#include "shared.hpp"
#include "exceptions.hpp"
#include "buffout.hpp"
#include "runtime.hpp"
#include "consensus.hpp"
#include <processsnapshot.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <wct.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>

namespace fs {
namespace { bool (*commitProbe)() = nullptr; bool (*pssProbe)() = nullptr; }
void setCommitProbeForTest(bool (*probe)()) { commitProbe = probe; }
void setPssProbeForTest(bool (*probe)()) { pssProbe = probe; }
std::filesystem::path reportRoot(bool vr) {
    PWSTR documents = nullptr;
    auto result = SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documents);
    if (FAILED(result)) throw std::runtime_error("Documents folder unavailable");
    std::filesystem::path root(documents);
    CoTaskMemFree(documents);
    return root / "My Games" / (vr ? "Fallout4VR" : "Fallout4") / "F4SE" / "FreezeSentryF4";
}
namespace {
constexpr DWORD64 MIN_COMMIT_BYTES_FOR_VA_CLONE = 2ULL * 1024 * 1024 * 1024; // 2 GiB
constexpr DWORD CLONE_TERMINATION_WAIT_MS = 5000;
// Test-only injection point: lets the regression tests force the low-commit and
// clone-failure paths without exhausting real commit. Declared above so the
// setter can live in the public namespace.
// PssFreeSnapshot returns before the clone process fully exits, so a 0 ms
// liveness check cannot tell a slow reaping from a real leak. Only terminate
// when the clone survives this grace period.
constexpr DWORD CLONE_EXIT_GRACE_MS = 500;
bool commitAvailableForClone() {
    if (commitProbe) return commitProbe();
    MEMORYSTATUSEX system{}; system.dwLength = sizeof(system);
    if (!GlobalMemoryStatusEx(&system)) return true; // Fail open; the capture attempt reports its own error.
    return system.ullAvailPageFile >= MIN_COMMIT_BYTES_FOR_VA_CLONE;
}
struct Snapshot {
    HPSS value = nullptr;
    HANDLE cloneBackstop = nullptr; // Duplicated clone handle. Verifies PssFreeSnapshot killed the clone.
    std::ostream* log = nullptr; // Optional; receives cleanup evidence. Never owns the stream.
    ~Snapshot() {
        if (cloneBackstop && cloneBackstop != INVALID_HANDLE_VALUE) {
            // Order matters: PssFreeSnapshot is documented to terminate the VA clone.
            // The handle check below only fires if that cleanup failed silently.
            DWORD freeError = PssFreeSnapshot(GetCurrentProcess(), value);
            value = nullptr;
            if (freeError && log) *log << "snapshot_free_error=" << freeError << '\n';
            if (WaitForSingleObject(cloneBackstop, 0) == WAIT_TIMEOUT) {
                if (log) *log << "clone_alive_after_free; waiting " << CLONE_EXIT_GRACE_MS << "ms for normal reaping\n";
                if (WaitForSingleObject(cloneBackstop, CLONE_EXIT_GRACE_MS) == WAIT_OBJECT_0) {
                    if (log) *log << "retained_clone_cleanup=reaped-after-free\n";
                } else {
                    if (log) *log << "snapshot_clone_survived_free; terminating retained clone\n";
                    TerminateProcess(cloneBackstop, 1);
                    DWORD wait = WaitForSingleObject(cloneBackstop, CLONE_TERMINATION_WAIT_MS);
                    if (log) *log << "retained_clone_cleanup=" << (wait == WAIT_OBJECT_0 ? "terminated" : "STILL_ALIVE") << '\n';
                }
            }
            CloseHandle(cloneBackstop);
            cloneBackstop = nullptr;
            return;
        }
        if (value) {
            DWORD freeError = PssFreeSnapshot(GetCurrentProcess(), value);
            value = nullptr;
            if (freeError && log) *log << "snapshot_free_error=" << freeError << '\n';
        }
    }
    Snapshot() = default;
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;
    // Remembers the VA clone of a successful capture so the destructor can verify
    // no clone process survives. Returns false when no clone handle could be tracked;
    // the caller must then abort the capture (the destructor still frees the snapshot).
    bool trackClone() {
        PSS_VA_CLONE_INFORMATION clone{};
        DWORD error = PssQuerySnapshot(value, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone));
        if (error || !clone.VaCloneHandle) {
            if (log) *log << "clone_query_error=" << error << '\n';
            return false;
        }
        HANDLE duplicated = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), clone.VaCloneHandle, GetCurrentProcess(), &duplicated,
                             SYNCHRONIZE | PROCESS_TERMINATE, FALSE, 0)) {
            if (log) *log << "clone_handle_error=" << GetLastError() << '\n';
            return false;
        }
        cloneBackstop = duplicated;
        return true;
    }
};
struct Marker {
    HPSSWALK value = nullptr;
    ~Marker() { if (value) PssWalkMarkerFree(value); }
};
struct Module { DWORD64 base; DWORD size; std::filesystem::path path; };
struct Observation {
    LONG64 created = 0, cpu = 0, firstCPU = 0;
    DWORD64 ip = 0;
    unsigned samples = 0;
    RipSequence ripSequence;
};
const Module* moduleContaining(DWORD64 address, const std::vector<Module>& modules) {
    for (const auto& module : modules)
        if (address >= module.base && address - module.base < module.size) return &module;
    return nullptr;
}
std::string location(DWORD64 address, const std::vector<Module>& modules) {
    std::ostringstream out;
    if (const auto* m = moduleContaining(address, modules)) {
        out << diagnosticPath(m->path.filename()) << "+0x" << std::hex << address - m->base;
        return out.str();
    }
    out << "0x" << std::hex << address;
    return out.str();
}
BOOL CALLBACK dumpCallback(PVOID, const PMINIDUMP_CALLBACK_INPUT input, PMINIDUMP_CALLBACK_OUTPUT output) {
    if (input->CallbackType == IsProcessSnapshotCallback) output->Status = S_FALSE;
    return TRUE;
}
std::string sha256(const std::filesystem::path& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) return "unavailable";
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return "unavailable";
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); return "unavailable";
    }
    std::array<UCHAR, 65536> bytes{}; DWORD count = 0; bool ok = true;
    for (;;) {
        if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) { ok = false; break; }
        if (!count) break;
        if (BCryptHashData(hash, bytes.data(), count, 0) < 0) { ok = false; break; }
    }
    std::array<UCHAR, 32> digest{};
    ok = ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    std::ostringstream out;
    if (!ok) return "unavailable";
    for (auto b : digest) out << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(b);
    return out.str();
}
std::string version(const std::filesystem::path& path) {
    DWORD ignored = 0, size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    std::vector<std::byte> data(size);
    VS_FIXEDFILEINFO* info = nullptr; UINT length = 0;
    if (!size || !GetFileVersionInfoW(path.c_str(), 0, size, data.data()) ||
        !VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length) || length < sizeof(*info)) return "unavailable";
    return std::to_string(HIWORD(info->dwFileVersionMS)) + '.' + std::to_string(LOWORD(info->dwFileVersionMS)) + '.' +
           std::to_string(HIWORD(info->dwFileVersionLS)) + '.' + std::to_string(LOWORD(info->dwFileVersionLS));
}
const char* waitType(WCT_OBJECT_TYPE type) {
    switch (type) {
    case WctCriticalSectionType: return "critical-section";
    case WctMutexType: return "mutex";
    case WctThreadType: return "thread";
    case WctThreadWaitType: return "thread-wait";
    case WctProcessWaitType: return "process-wait";
    case WctSendMessageType: return "SendMessage";
    case WctAlpcType: return "ALPC";
    case WctComType: return "COM";
    default: return "other";
    }
}
std::string waitChains(const std::vector<DWORD>& ids) {
    // WCT's synchronous API may block. A single bounded collector retains its
    // own context until it returns; it never holds or suspends a game thread.
    static std::atomic<bool> busy = false;
    if (busy.exchange(true)) return "previous WCT query still pending; skipped\n";
    struct Result { Handle done{CreateEventW(nullptr, TRUE, FALSE, nullptr)}; std::mutex mutex; std::string text; };
    auto result = std::make_shared<Result>();
    if (!result->done.value) { busy = false; return "WCT event unavailable\n"; }
    std::thread([result, ids] {
        try {
        std::ostringstream out;
        HWCT session = OpenThreadWaitChainSession(0, nullptr);
        struct CloseSession { HWCT h; ~CloseSession() { if (h) CloseThreadWaitChainSession(h); } } cleanup{session};
        if (!session) out << "WCT session error=" << GetLastError() << '\n';
        else {
            auto deadline = now() + 1500;
            for (DWORD id : ids) {
                std::array<WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT> nodes{};
                DWORD count = static_cast<DWORD>(nodes.size()); BOOL cycle = FALSE;
                BOOL ok = GetThreadWaitChain(session, 0, WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_CS_FLAG,
                                             id, &count, nodes.data(), &cycle);
                DWORD error = ok ? 0 : GetLastError();
                out << "thread=" << id << " deadlock_cycle=" << cycle << " error=" << error << '\n';
                if (ok || error == ERROR_MORE_DATA || error == ERROR_TOO_MANY_THREADS) {
                    for (DWORD i = 0; i < std::min<DWORD>(count, static_cast<DWORD>(nodes.size())); ++i) {
                        const auto& n = nodes[i];
                        out << "  node=" << i << " type=" << waitType(n.ObjectType) << " status=" << n.ObjectStatus;
                        if (n.ObjectType == WctThreadType)
                            out << " PID=" << n.ThreadObject.ProcessId << " TID=" << n.ThreadObject.ThreadId
                                << " wait_ms=" << n.ThreadObject.WaitTime << " switches=" << n.ThreadObject.ContextSwitches;
                        else {
                            size_t length = wcsnlen(n.LockObject.ObjectName, WCT_OBJNAME_LENGTH);
                            out << " object=" << diagnosticUtf8(std::wstring_view(n.LockObject.ObjectName, length));
                        }
                        out << '\n';
                    }
                }
                { std::lock_guard lock(result->mutex); result->text += out.str(); }
                out.str({}); out.clear();
                if (now() >= deadline) { out << "WCT time budget exhausted\n"; break; }
            }
        }
        { std::lock_guard lock(result->mutex); result->text += out.str(); }
        } catch (...) {
            std::lock_guard lock(result->mutex); result->text += "WCT collection exception; result incomplete\n";
        }
        SetEvent(result->done);
        busy = false;
    }).detach();
    bool completed = WaitForSingleObject(result->done, 2000) == WAIT_OBJECT_0;
    std::lock_guard lock(result->mutex);
    if (!completed) return result->text + "WCT query timed out; other evidence remains available\n";
    return result->text;
}
template<class T> bool remote(HANDLE process, DWORD64 address, T& value) {
    SIZE_T size = 0;
    if (ReadProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(value), &size) && size == sizeof(value)) {
        captureRpm().record(size);
        return true;
    }
    captureRpm().fail();
    return false;
}
std::string rtti(HANDLE process, DWORD64 address, const std::vector<Module>& modules) {
    DWORD64 table = 0, locator = 0;
    if (!remote(process, address, table) || table < 8 || !remote(process, table - 8, locator)) return {};
    for (const auto& m : modules) if (table >= m.base && table - m.base < m.size && locator >= m.base && locator - m.base < m.size) {
        struct Locator { DWORD signature, offset, constructorOffset, typeRVA, hierarchyRVA, selfRVA; } col{};
        if (!remote(process, locator, col) || col.signature != 1 || col.typeRVA >= m.size || col.selfRVA != locator - m.base) return {};
        std::array<char, 160> name{};
        if (!remote(process, m.base + col.typeRVA + 16, name) || name[0] != '.' || name[1] != '?') return {};
        name.back() = 0;
        return std::string(name.data());
    }
    return {};
}
}
std::string diskSHA256(const std::filesystem::path& path) { return sha256(path); }
// Writes once-per-folder setup notes for WER LocalDumps so a later incident
// still captures a dump after our own capture failed. Returns true when written.
bool writeWerFallbackHint(const std::filesystem::path& folder, const std::filesystem::path& gameImage) {
    std::error_code ignored;
    auto path = folder / "WER_LocalDumps_Hint.txt";
    if (std::filesystem::exists(path, ignored)) return false;
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    auto executable = gameImage.filename().wstring();
    if (executable.empty()) executable = L"Fallout4.exe";
    const std::string executableUtf8 = diagnosticUtf8(executable);
    const std::string registrySubkey = "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" + executableUtf8;
    out << "FreezeSentryF4 could not write a minidump for an incident (see snapshot_error= or minidump=FAILED\n"
           "in the incident log). These are separate recovery options:\n\n"
           "For a process that is still frozen, open Task Manager > Details, right-click " << executableUtf8
        << ", then choose Create dump file. This captures the live hang state.\n\n"
           "For future process crashes only, Windows Error Reporting LocalDumps can write a dump. Run as administrator,\n"
           "replacing the dump folder as needed:\n"
        << "  reg add \"" << registrySubkey << "\" /v DumpFolder /t REG_EXPAND_SZ /d \"%USERPROFILE%\\Documents\\CrashDumps\" /f\n"
        << "  reg add \"" << registrySubkey << "\" /v DumpCount /t REG_DWORD /d 5 /f\n"
        << "  reg add \"" << registrySubkey << "\" /v DumpType /t REG_DWORD /d 2 /f\n\n"
           "DumpType 2 is a full crash dump. LocalDumps does not capture a still-running hang.\n"
           "This file is never removed by retention; delete it to regenerate it.\n";
    out.flush();
    return static_cast<bool>(out);
}
// Lowercase basename of the module containing address, or empty.
std::string moduleBaseName(DWORD64 address, const std::vector<Module>& modules) {
    for (const auto& m : modules)
        if (address >= m.base && address - m.base < m.size)
            return buffout::lower(diagnosticPath(m.path.filename()));
    return {};
}
struct ExternalCrash {
    BuffoutCrashInfo info;
    std::string path;
    bool candidate = false;
    bool corroborated = false;
    std::uint64_t ageMs = 0;
    std::string correlation;
};
std::uint64_t fileTimeValue(FILETIME value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}
std::filesystem::path processImage(HANDLE process) {
    std::array<wchar_t, 32768> path{};
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &length) || !length) return {};
    return std::filesystem::path(std::wstring_view(path.data(), length));
}
std::string oneLine(std::string value) {
    for (char& c : value) if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
    return value;
}
// Selects a recent metadata-compatible candidate, then requires a matching
// exception and loaded image from this process before incident corroboration.
ExternalCrash findExternalCrashLog(const std::filesystem::path& gameImage, Shared* state,
                                  const std::vector<CrashModuleIdentity>& modules) {
    ExternalCrash newestCorroborated, newestCandidate, newestContext;
    std::uint64_t newestCorroboratedTime = 0, newestCandidateTime = 0, newestContextTime = 0;
    auto gameName = buffout::lower(diagnosticPath(gameImage.filename()));
    auto edition = gameName == "fallout4vr.exe" ? BuffoutCrashInfo::Edition::Fallout4VR :
                   gameName == "fallout4.exe" ? BuffoutCrashInfo::Edition::Fallout4 :
                   BuffoutCrashInfo::Edition::Unknown;
    PWSTR documents = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documents))) return {};
    std::filesystem::path root(documents);
    CoTaskMemFree(documents);
    if (edition == BuffoutCrashInfo::Edition::Unknown) return {};
    FILETIME observed{}; GetSystemTimeAsFileTime(&observed);
    CrashLogSession session;
    session.edition = edition;
    session.gameVersion = version(gameImage);
    session.processStartedFileTime = state ? static_cast<std::uint64_t>(read(state->processCreated)) : 0;
    session.observedFileTime = fileTimeValue(observed);
    CrashLogCorrelator correlator(std::move(session));
    ExceptionJournal journal(state);
    std::vector<ProcessExceptionIdentity> exceptions;
    for (const auto& fault : journal.recent())
        exceptions.push_back({fault.code, fault.ip, fault.fileTime});
    CrashIncidentCorrelator incidentCorrelator;
    const wchar_t* gameFolder = edition == BuffoutCrashInfo::Edition::Fallout4VR ? L"Fallout4VR" : L"Fallout4";
    std::error_code error;
    auto iterator = std::filesystem::directory_iterator(root / "My Games" / gameFolder / "F4SE", error);
    const auto end = std::filesystem::directory_iterator{};
    for (; !error && iterator != end; iterator.increment(error)) {
        auto path = iterator->path();
        auto extension = path.extension().wstring();
        for (wchar_t& c : extension) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        if (extension != L".log") continue;
        auto stem = path.stem().wstring();
        for (wchar_t& c : stem) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        if (!stem.starts_with(L"crash") && stem.find(L"buffout") == std::wstring::npos) continue;
        auto size = iterator->file_size(error);
        if (error || size > 4 * 1024 * 1024) { error.clear(); continue; }
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes)) continue;
        std::uint64_t written = fileTimeValue(attributes.ftLastWriteTime);
        std::ifstream in(path, std::ios::binary);
        if (!in) continue;
        std::string text(static_cast<std::size_t>(size), '\0');
        in.read(text.data(), static_cast<std::streamsize>(text.size()));
        text.resize(static_cast<std::size_t>(in.gcount()));
        BuffoutCrashInfo info = parseBuffoutCrashLog(text, diagnosticPath(path));
        if (!info.found) continue;
        CrashLogMatch match = correlator.assess(info, written);
        auto incident = match.candidate ? incidentCorrelator.assess(info, written, exceptions, modules) : CrashIncidentMatch{};
        ExternalCrash candidate{std::move(info), diagnosticPath(path), match.candidate,
                                incident.corroborated, match.ageMs,
                                incident.corroborated ? incident.reason : match.reason};
        if (candidate.corroborated && written >= newestCorroboratedTime) {
            newestCorroboratedTime = written;
            newestCorroborated = std::move(candidate);
        } else if (candidate.candidate && written >= newestCandidateTime) {
            newestCandidateTime = written;
            newestCandidate = std::move(candidate);
        } else if (!candidate.candidate && written >= newestContextTime) {
            newestContextTime = written;
            newestContext = std::move(candidate);
        }
    }
    if (newestCorroborated.corroborated) return newestCorroborated;
    return newestCandidate.candidate ? newestCandidate : newestContext;
}
std::string externalCrashReport(const ExternalCrash& external) {
    std::ostringstream out;
    if (external.path.empty()) {
        out << "EXTERNAL_CRASH_CORRELATION status=none; no parseable crash log found for this game edition\n";
        return out.str();
    }
    const char* status = external.corroborated ? "process-exception-corroborated" :
                         external.candidate ? "recent-candidate" : "context-only";
    out << "EXTERNAL_CRASH_CORRELATION status=" << status
        << " correlation=" << external.correlation << " age_ms=" << external.ageMs
        << " file=" << oneLine(external.path) << '\n';
    if (!external.corroborated) {
        if (external.candidate) {
            out << "candidate_game_version=" << external.info.gameVersion << " exception=" << external.info.exceptionName
                << " code=0x" << std::hex << external.info.exceptionCode << std::dec << " fault="
                << (external.info.faultModule.empty() ? "unknown-module" : external.info.faultModule)
                << (external.info.faultOffset.empty() ? "" : "+" + external.info.faultOffset) << '\n';
            out << "Metadata and time are not process identity; this candidate was not used for attribution.\n";
        } else out << "external crash log was not used for current-incident attribution\n";
        return out.str();
    }
    out << "external_game_version=" << external.info.gameVersion
        << " exception=" << external.info.exceptionName << " code=0x" << std::hex
        << external.info.exceptionCode << std::dec << " fault="
        << (external.info.faultModule.empty() ? "unknown-module" : external.info.faultModule)
        << (external.info.faultOffset.empty() ? "" : "+" + external.info.faultOffset) << '\n';
    if (!external.info.stackModules.empty()) out << "external_top_frame=" << external.info.stackModules.front() << '\n';
    out << "The fault matches this process's exception and loaded module; this corroborates the incident but does not prove which overlapping same-version process wrote the log or establish its cause.\n";
    return out.str();
}
std::string externalCrashEvidence(const std::filesystem::path& gameImage, Shared* state,
                                  const std::vector<CrashModuleIdentity>& modules) {
    return externalCrashReport(findExternalCrashLog(gameImage, state, modules));
}
std::string profile(HANDLE target, bool stacks, Shared* state, bool reset) {
    struct CPU { LONG64 created, cpu; };
    static thread_local std::map<DWORD, CPU> baseline;
    if (reset) { baseline.clear(); return {}; }
    std::ostringstream out;
    auto began = now();
    out << "\nPROFILE tick=" << now() << " early_stack=" << stacks << '\n';
    auto collect = [&] {
        Snapshot snapshot;
        snapshot.log = &out;
        if (stacks && !commitAvailableForClone()) {
            out << "profile_clone_deferred_low_commit\n";
            return;
        }
        auto flags = static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT |
                        (stacks ? PSS_CAPTURE_VA_CLONE : 0));
        auto captureBegan = now();
        DWORD error = PssCaptureSnapshot(target, flags, CONTEXT_ALL, &snapshot.value);
        if (error) { out << "profile_snapshot_error=" << error << '\n'; return; }
        out << "snapshot_capture_ms=" << now() - captureBegan << '\n';
        PSS_VA_CLONE_INFORMATION clone{};
        if (stacks && (error = PssQuerySnapshot(snapshot.value, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone)))) {
            out << "profile_clone_error=" << error << '\n'; return;
        }
        if (stacks && !snapshot.trackClone()) {
            out << "profile_clone_untracked; capture aborted\n";
            return;
        }
        HANDLE reader = stacks ? clone.VaCloneHandle : target;
        std::array<HMODULE, 2048> handles{}; DWORD needed = 0;
        std::vector<Module> modules;
        if (EnumProcessModulesEx(reader, handles.data(), sizeof(handles), &needed, LIST_MODULES_64BIT)) {
            for (size_t i = 0; i < std::min<size_t>(needed / sizeof(HMODULE), handles.size()); ++i) {
                MODULEINFO info{}; std::array<wchar_t, 32768> path{};
                if (GetModuleInformation(reader, handles[i], &info, sizeof(info)) &&
                    GetModuleFileNameExW(reader, handles[i], path.data(), static_cast<DWORD>(path.size())))
                    modules.push_back({reinterpret_cast<DWORD64>(info.lpBaseOfDll), info.SizeOfImage, path.data()});
            }
        }
        struct Row { DWORD id; LONG64 delta; CONTEXT context; bool valid; };
        std::vector<Row> rows;
        std::map<DWORD, CPU> next;
        Marker marker;
        error = PssWalkMarkerCreate(nullptr, &marker.value);
        if (error) { out << "profile_marker_error=" << error << '\n'; return; }
        PSS_THREAD_ENTRY entry{};
        while (rows.size() < 4096 && PssWalkSnapshot(snapshot.value, PSS_WALK_THREADS, marker.value, &entry, sizeof(entry)) == ERROR_SUCCESS) {
            auto cpu = filetime(entry.UserTime) + filetime(entry.KernelTime), created = filetime(entry.CreateTime);
            auto old = baseline.find(entry.ThreadId);
            auto delta = old != baseline.end() && old->second.created == created && cpu >= old->second.cpu ? cpu - old->second.cpu : 0;
            next[entry.ThreadId] = {created, cpu};
            bool valid = entry.ContextRecord && entry.SizeOfContextRecord >= sizeof(CONTEXT);
            rows.push_back({entry.ThreadId, delta, valid ? *entry.ContextRecord : CONTEXT{}, valid});
        }
        baseline = std::move(next);
        const std::array<DWORD, 3> priorityIds{
            state ? static_cast<DWORD>(read(state->thread[0])) : 0,
            state ? static_cast<DWORD>(read(state->thread[1])) : 0,
            state ? static_cast<DWORD>(read(state->frameThread)) : 0};
        auto isPriority = [&priorityIds](DWORD id) {
            return id && std::find(priorityIds.begin(), priorityIds.end(), id) != priorityIds.end();
        };
        std::sort(rows.begin(), rows.end(), [&isPriority](const Row& a, const Row& b) {
            bool priorityA = isPriority(a.id), priorityB = isPriority(b.id);
            if (priorityA != priorityB) return priorityA;
            return a.delta > b.delta;
        });
        bool symbols = false;
        if (stacks) {
            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
            symbols = SymInitializeW(reader, L"", FALSE) != FALSE;
            if (symbols) for (const auto& module : modules)
                SymLoadModuleExW(reader, nullptr, module.path.c_str(), nullptr, module.base, module.size, nullptr, 0);
        }
        struct Symbols { HANDLE process; bool ready; ~Symbols() { if (ready) SymCleanup(process); } } cleanup{reader, symbols};
        out << "CPU deltas belong to threads; sampled RIP modules do not establish DLL CPU ownership.\n";
        unsigned limit = stacks ? 16 : 64;
        for (unsigned i = 0; i < std::min<size_t>(rows.size(), limit); ++i) {
            const auto& row = rows[i];
            out << "thread=" << row.id << " cpu_delta_100ns=" << row.delta << " sampled_RIP="
                << (row.valid ? location(row.context.Rip, modules) : "unavailable") << '\n';
            if (!stacks || !row.valid || !symbols) continue;
            CONTEXT context = row.context; STACKFRAME64 frame{};
            frame.AddrPC = {context.Rip, 0, AddrModeFlat}; frame.AddrStack = {context.Rsp, 0, AddrModeFlat}; frame.AddrFrame = {context.Rbp, 0, AddrModeFlat};
            DWORD64 pc = 0, sp = 0;
            for (unsigned depth = 0; depth < 16; ++depth) {
                if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, reader, nullptr, &frame, &context, nullptr,
                                 SymFunctionTableAccess64, SymGetModuleBase64, nullptr) || !frame.AddrPC.Offset ||
                    (frame.AddrPC.Offset == pc && frame.AddrStack.Offset == sp)) break;
                pc = frame.AddrPC.Offset; sp = frame.AddrStack.Offset;
                out << "  early#" << depth << ' ' << location(pc, modules);
                alignas(SYMBOL_INFO) std::array<std::byte, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> storage{};
                auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
                symbol->SizeOfStruct = sizeof(SYMBOL_INFO); symbol->MaxNameLen = MAX_SYM_NAME; DWORD64 offset = 0;
                if (SymFromAddr(reader, pc, &offset, symbol)) out << ' ' << symbol->Name << "+0x" << std::hex << offset << std::dec;
                out << '\n';
            }
        }
        out << "profile_threads=" << rows.size() << " listed=" << std::min<size_t>(rows.size(), limit) << '\n';
    };
    collect(); // Snapshot, marker, and symbol cleanup finish before elapsed time is written.
    out << "profile_elapsed_ms=" << now() - began << '\n';
    return out.str();
}
bool capture(HANDLE target, DWORD pid, const std::filesystem::path& folder,
             const std::string& reason, Shared* state, bool dump, const std::string& history, bool quick) {
    ExceptionJournal exceptionJournal(state);
    const auto gameImage = processImage(target);
    SYSTEMTIME utc{}; GetSystemTime(&utc);
    std::ostringstream stem;
    // Manual snapshots use their own name class so per-category retention caps
    // (MaxFreezeReports/MaxManualReports) can keep each class independently.
    const char* prefix = reason == "manual-capture" ? "manual-" : reason == "fatal-exception" ? "crash-" : "freeze-";
    stem << prefix << std::setfill('0') << std::setw(4) << utc.wYear << std::setw(2) << utc.wMonth
         << std::setw(2) << utc.wDay << '-' << std::setw(2) << utc.wHour << std::setw(2) << utc.wMinute
         << std::setw(2) << utc.wSecond << '-' << std::setw(3) << utc.wMilliseconds << '-' << pid;
    auto logPath = folder / (stem.str() + ".log");
    std::ofstream log(logPath, std::ios::out | std::ios::trunc);
    if (!log) return false;
    log << "FreezeSentryF4 " << toolVersion << "\nUTC=" << utc.wYear << '-' << utc.wMonth << '-' << utc.wDay << ' '
        << utc.wHour << ':' << utc.wMinute << ':' << utc.wSecond << "\nPID=" << pid
        << " reason=" << reason << " tick=" << now() << '\n';
    log << "Observed task silence is a suspected stall. Long work can produce the same signal.\n"
           "A module appearing on a stack is not proof that it caused the stall.\n";
    if (state) {
        log << "runtime_packed=" << state->runtime << " f4se_packed=" << state->extender << '\n';
        log << "task_monitoring=" << state->taskMonitoring << '\n';
        for (int c = 0; c < 2; ++c)
            log << (c ? "ui" : "normal") << "_queue thread=" << read(state->thread[c])
                << " last_tick=" << read(state->pulse[c]) << " count=" << read(state->sequence[c])
                << " pending=" << read(state->pending[c]) << '\n';
        log << "last_F4SE_event=" << read(state->event) << " event_tick=" << read(state->eventTime)
            << " loading_or_saving=" << read(state->phase) << '\n';
        if (reason == "fatal-exception")
            log << "crash_code=0x" << std::hex << state->crashCode << std::dec
                << " crash_thread=" << state->crashThread << " crash_address=0x" << std::hex
                << state->crashAddress << std::dec << " capture=single-snapshot\n";
    }
    PROCESS_MEMORY_COUNTERS_EX memory{}; memory.cb = sizeof(memory);
    if (GetProcessMemoryInfo(target, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory)))
        log << "working_set_bytes=" << memory.WorkingSetSize << " private_bytes=" << memory.PrivateUsage << '\n';
    else log << "memory_query_error=" << GetLastError() << '\n';
    MEMORYSTATUSEX system{}; system.dwLength = sizeof(system);
    if (GlobalMemoryStatusEx(&system)) log << "system_available_physical=" << system.ullAvailPhys
        << " system_available_commit=" << system.ullAvailPageFile << '\n';
    log.flush(); // Even snapshot failure or collection interruption leaves incident evidence.
    exceptionJournal.write(log);
    log << eventHistory(state) << history;
    if (state) log << "frame_source=" << read(state->frameSource) << " frame_source_expired=" << read(state->frameSourceExpired)
        << " frame_status=" << read(state->frameStatus)
        << " present_count=" << read(state->frameCount) << " present_tick=" << read(state->frameTick)
        << " present_thread=" << read(state->frameThread) << '\n';
    log.flush();
    std::map<DWORD, Observation> observations;
    std::map<std::wstring, Module> identities;
    std::vector<Module> lastModules;
    std::vector<DWORD> threadIDs;
    bool sampled = false;
    const unsigned sampleCount = quick ? 1u : 3u;
    for (unsigned sample = 0; sample < sampleCount; ++sample) {
    if (sample) Sleep(1000);
    log << "\nSAMPLE " << sample + 1 << '/' << sampleCount << " tick=" << now() << '\n';
    Snapshot snapshot;
    snapshot.log = &log;
    bool cloneMode = commitAvailableForClone();
    if (!cloneMode) log << "snapshot_clone_deferred_low_commit; attempting thread-only fallback\n";
    auto captureBegan = now();
    DWORD error = ERROR_NOT_SUPPORTED;
    if (pssProbe && !pssProbe()) {
        log << "pss_capture_disabled_by_test_probe; using Toolhelp thread inventory\n";
    } else {
        auto flags = cloneMode
            ? static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT)
            : static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT);
        error = PssCaptureSnapshot(target, flags, CONTEXT_ALL, &snapshot.value);
        if (error != ERROR_SUCCESS && cloneMode) {
            log << "snapshot_error=" << error << " clone_mode=1; attempting thread-only fallback\n";
            cloneMode = false;
            captureBegan = now();
            flags = static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT);
            error = PssCaptureSnapshot(target, flags, CONTEXT_ALL, &snapshot.value);
        }
    }
    if (error != ERROR_SUCCESS) {
        // Last resort: thread identities and wait reasons without any snapshot.
        log << "snapshot_error=" << error << " clone_mode=0; using Toolhelp thread inventory\n";
        log << "capture_method=toolhelp-thread-inventory omitted=contexts,stacks,modules,symbols,minidump\n";
        log << "minidump=skipped (PSS unavailable; no snapshot)\n";
        MEMORYSTATUSEX systemMemory{}; systemMemory.dwLength = sizeof(systemMemory);
        if (GlobalMemoryStatusEx(&systemMemory))
            log << "system_available_physical=" << systemMemory.ullAvailPhys
                << " system_available_commit=" << systemMemory.ullAvailPageFile << '\n';
        HANDLE toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        unsigned count = 0;
        if (toolhelp != INVALID_HANDLE_VALUE) {
            THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
            if (Thread32First(toolhelp, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != pid) continue;
                    log << "thread=" << entry.th32ThreadID << " toolhelp_base_priority=" << entry.tpBasePri << '\n';
                    if (!sample) threadIDs.push_back(entry.th32ThreadID);
                    ++count;
                } while (Thread32Next(toolhelp, &entry));
            }
            CloseHandle(toolhelp);
        } else log << "toolhelp_error=" << GetLastError() << '\n';
        log << "thread_count=" << count << " capture_method=toolhelp\n";
        sampled |= count > 0;
        if (writeWerFallbackHint(folder, gameImage)) log << "wer_fallback_hint=written\n";
        log.flush();
        continue;
    }
    log << "snapshot_capture_ms=" << now() - captureBegan << " dump_transport="
        << (cloneMode ? "pss-snapshot" : "pss-thread-only") << '\n';
    PSS_VA_CLONE_INFORMATION clone{};
    if (cloneMode) {
        if (!snapshot.trackClone()) {
            log << "clone_untracked; capture aborted, snapshot released\n";
            return false;
        }
        error = PssQuerySnapshot(snapshot.value, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone));
        if (error != ERROR_SUCCESS || !clone.VaCloneHandle) { log << "clone_query_error=" << error << '\n'; return false; }
        log << "capture_source=Windows PSS snapshot; game threads are not manually suspended\n";
    } else {
        // No VA clone: read the live target directly. Threads and contexts come
        // from the thread-only snapshot; stacks, modules and symbols are read
        // from the running process and are explicitly lower fidelity.
        clone.VaCloneHandle = target;
        log << "capture_method=pss-thread-only omitted=va-clone,minidump (low commit or clone failure)\n";
        log << "capture_source=Windows PSS thread-only snapshot; live memory reads are not an atomic clone\n";
    }
    log.flush();
    if (cloneMode && dump && sample == 0) {
        auto dumpPath = folder / (stem.str() + ".dmp");
        auto partial = dumpPath; partial += ".partial";
        Handle file(CreateFileW(partial.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        bool createdFile = file.value != INVALID_HANDLE_VALUE;
        MINIDUMP_CALLBACK_INFORMATION callback{dumpCallback, nullptr};
        auto dumpFlags = static_cast<MINIDUMP_TYPE>(MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules |
            MiniDumpWithFullMemoryInfo | MiniDumpWithIndirectlyReferencedMemory);
        if (state && state->fullDump) dumpFlags = static_cast<MINIDUMP_TYPE>(dumpFlags | MiniDumpWithFullMemory);
        bool success = file.value != INVALID_HANDLE_VALUE && MiniDumpWriteDump(reinterpret_cast<HANDLE>(snapshot.value),
            pid, file, dumpFlags, nullptr, nullptr, &callback);
        DWORD dumpError = success ? 0 : GetLastError();
        if (success && !FlushFileBuffers(file)) { success = false; dumpError = GetLastError(); }
        if (file.value != INVALID_HANDLE_VALUE) { CloseHandle(file.value); file.value = nullptr; }
        std::string validation;
        success = success && validateDump(partial, validation);
        if (success && !MoveFileExW(partial.c_str(), dumpPath.c_str(), MOVEFILE_WRITE_THROUGH)) {
            success = false; dumpError = GetLastError(); validation = "rename failed";
        }
        if (!success && createdFile) { std::error_code ignored; std::filesystem::remove(partial, ignored); }
        log << "minidump=" << (success ? diagnosticPath(dumpPath.filename()) : "FAILED")
            << " error=" << dumpError << " structural_validation=" << validation << '\n';
        if (!success && writeWerFallbackHint(folder, gameImage)) log << "wer_fallback_hint=written\n";
        log.flush();
    } else if (dump && sample == 0) {
        log << "minidump=skipped (thread-only fallback; no VA clone)\n";
        log.flush();
    }
    std::vector<Module> modules;
    std::array<HMODULE, 2048> handles{};
    DWORD needed = 0;
    if (EnumProcessModulesEx(clone.VaCloneHandle, handles.data(), sizeof(handles), &needed, LIST_MODULES_64BIT)) {
        log << "\nMODULES (snapshot, full paths may contain local user information)\n";
        auto count = std::min<size_t>(needed / sizeof(HMODULE), handles.size());
        for (size_t i = 0; i < count; ++i) {
            MODULEINFO info{}; std::array<wchar_t, 32768> path{};
            if (!GetModuleInformation(clone.VaCloneHandle, handles[i], &info, sizeof(info))) continue;
            GetModuleFileNameExW(clone.VaCloneHandle, handles[i], path.data(), static_cast<DWORD>(path.size()));
            Module m{reinterpret_cast<DWORD64>(info.lpBaseOfDll), info.SizeOfImage, path.data()};
            log << "base=0x" << std::hex << m.base << " size=0x" << m.size << std::dec << ' ' << diagnosticPath(m.path) << '\n';
            identities.insert_or_assign(m.path.wstring(), m);
            IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{};
            if (remote(clone.VaCloneHandle, m.base, dos) && dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 &&
                dos.e_lfanew < 1048576 && remote(clone.VaCloneHandle, m.base + dos.e_lfanew, nt) && nt.Signature == IMAGE_NT_SIGNATURE)
            {
                log << "  loaded_PE_timestamp=" << nt.FileHeader.TimeDateStamp << " checksum=" << nt.OptionalHeader.CheckSum << '\n';
                auto debug = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
                if (debug.VirtualAddress < m.size && debug.Size <= 64 * sizeof(IMAGE_DEBUG_DIRECTORY)) {
                    for (unsigned d = 0; d < debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++d) {
                        IMAGE_DEBUG_DIRECTORY record{};
                        if (!remote(clone.VaCloneHandle, m.base + debug.VirtualAddress + d * sizeof(record), record) ||
                            record.Type != IMAGE_DEBUG_TYPE_CODEVIEW || record.SizeOfData < 24 || record.AddressOfRawData >= m.size) continue;
                        struct CodeView { DWORD signature; GUID id; DWORD age; } cv{};
                        if (!remote(clone.VaCloneHandle, m.base + record.AddressOfRawData, cv) || cv.signature != 0x53445352) continue;
                        log << "  loaded_PDB_GUID=" << std::hex << cv.id.Data1 << '-' << cv.id.Data2 << '-' << cv.id.Data3 << '-';
                        for (auto byte : cv.id.Data4) log << std::setfill('0') << std::setw(2) << static_cast<unsigned>(byte);
                        log << std::dec << " age=" << cv.age << '\n';
                    }
                }
            }
            modules.push_back(std::move(m));
        }
        if (needed > sizeof(handles)) log << "module list truncated to 2048 entries\n";
    } else log << "module_enumeration_error=" << GetLastError() << '\n';
    // ponytail: local PDBs only; raw module+offset remains useful without symbols.
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    bool symbols = SymInitializeW(clone.VaCloneHandle, L"", FALSE) != FALSE;
    struct Symbols { HANDLE process; bool ready; ~Symbols() { if (ready) SymCleanup(process); } } cleanup{clone.VaCloneHandle, symbols};
    if (symbols) for (const auto& m : modules)
        SymLoadModuleExW(clone.VaCloneHandle, nullptr, m.path.c_str(), nullptr, m.base, m.size, nullptr, 0);
    if (symbols && sample == 0) for (const auto& m : modules) {
        IMAGEHLP_MODULEW64 info{}; info.SizeOfStruct = sizeof(info);
        if (SymGetModuleInfoW64(clone.VaCloneHandle, m.base, &info)) {
            const auto pdbLength = wcsnlen(info.LoadedPdbName, std::size(info.LoadedPdbName));
            log << "symbols module=" << diagnosticPath(m.path.filename()) << " type=" << info.SymType << " pdb="
                << diagnosticUtf8(std::wstring_view(info.LoadedPdbName, pdbLength))
                << " pdb_age=" << info.PdbAge << " pdb_signature=" << std::hex << info.PdbSig70.Data1 << '-' << info.PdbSig70.Data2
                << '-' << info.PdbSig70.Data3 << '-';
            for (auto byte : info.PdbSig70.Data4) log << std::setfill('0') << std::setw(2) << static_cast<unsigned>(byte);
            log << std::dec << " pdb_mismatch=" << info.PdbUnmatched << '\n';
        }
    }
    log << "\nTHREADS (64 frames maximum per thread; symbols from local files only)\n";
    Marker marker;
    error = PssWalkMarkerCreate(nullptr, &marker.value);
    if (error) { log << "thread_marker_error=" << error << '\n'; return false; }
    PSS_THREAD_ENTRY entry{};
    unsigned count = 0;
    while ((error = PssWalkSnapshot(snapshot.value, PSS_WALK_THREADS, marker.value, &entry, sizeof(entry))) == ERROR_SUCCESS) {
        if (!sample) threadIDs.push_back(entry.ThreadId);
        LONG64 cpu = filetime(entry.UserTime) + filetime(entry.KernelTime);
        auto& observation = observations[entry.ThreadId];
        if (!observation.samples || observation.created != filetime(entry.CreateTime)) {
            observation = {};
            observation.created = filetime(entry.CreateTime);
            observation.cpu = cpu;
            observation.firstCPU = cpu;
        }
        log << "thread=" << entry.ThreadId << " sample_cpu_delta_100ns=" << (observation.samples ? cpu - observation.cpu : 0) << '\n';
        observation.cpu = cpu;
        log << "\nthread=" << entry.ThreadId << " cpu_user_100ns=" << filetime(entry.UserTime)
            << " cpu_kernel_100ns=" << filetime(entry.KernelTime) << " suspend_count=" << entry.SuspendCount;
        if (state && entry.ThreadId == static_cast<DWORD>(read(state->thread[0]))) log << " NORMAL_TASK_CALLBACK";
        if (state && entry.ThreadId == static_cast<DWORD>(read(state->thread[1]))) log << " UI_TASK_CALLBACK";
        log << '\n';
        using Describe = HRESULT(WINAPI*)(HANDLE, PWSTR*);
        auto describe = reinterpret_cast<Describe>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription"));
        if (describe) {
            Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.ThreadId));
            PWSTR name = nullptr;
            if (thread.value && SUCCEEDED(describe(thread, &name)) && name) {
                log << "thread_name=" << diagnosticUtf8(name) << '\n'; LocalFree(name);
            }
        }
        if (!entry.ContextRecord || entry.SizeOfContextRecord < sizeof(CONTEXT)) { log << "context unavailable\n"; continue; }
        CONTEXT context = *entry.ContextRecord;
        const Module* sampleModule = moduleContaining(context.Rip, modules);
        std::wstring modulePath = sampleModule ? sampleModule->path.lexically_normal().wstring() : std::wstring{};
        observation.ripSequence.observe(context.Rip, sampleModule ? sampleModule->base : 0, modulePath);
        observation.ip = context.Rip;
        ++observation.samples;
        log << "RIP=" << location(context.Rip, modules) << " RSP=0x" << std::hex << context.Rsp << " RBP=0x" << context.Rbp
            << " RAX=0x" << context.Rax << " RBX=0x" << context.Rbx << " RCX=0x" << context.Rcx << " RDX=0x" << context.Rdx
            << " RSI=0x" << context.Rsi << " RDI=0x" << context.Rdi << " R8=0x" << context.R8 << " R9=0x" << context.R9
            << " R10=0x" << context.R10 << " R11=0x" << context.R11 << " R12=0x" << context.R12 << " R13=0x" << context.R13
            << " R14=0x" << context.R14 << " R15=0x" << context.R15 << " EFLAGS=0x" << context.EFlags << std::dec << '\n';
        std::array<UCHAR, 32> code{};
        if (remote(clone.VaCloneHandle, context.Rip, code)) {
            log << "instruction_bytes_at_RIP=";
            for (auto byte : code) log << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(byte) << ' ';
            log << std::dec << '\n';
        } else log << "instruction bytes unavailable\n";
        std::array<DWORD64, 32> stack{};
        if (remote(clone.VaCloneHandle, context.Rsp, stack)) {
            log << "RAW_STACK (values and RTTI are candidates, not validated game objects)\n";
            for (size_t index = 0; index < stack.size(); ++index) {
                log << "  RSP+0x" << std::hex << index * 8 << "=0x" << stack[index] << std::dec
                    << " " << location(stack[index], modules);
                auto type = rtti(clone.VaCloneHandle, stack[index], modules);
                if (!type.empty()) log << " RTTI_candidate=" << type;
                log << '\n';
            }
        }
        STACKFRAME64 frame{};
        frame.AddrPC = {context.Rip, 0, AddrModeFlat};
        frame.AddrStack = {context.Rsp, 0, AddrModeFlat};
        frame.AddrFrame = {context.Rbp, 0, AddrModeFlat};
        DWORD64 previous = 0, previousStack = 0;
        for (unsigned depth = 0; depth < 64 && frame.AddrPC.Offset; ++depth) {
            if (!symbols || !StackWalk64(IMAGE_FILE_MACHINE_AMD64, clone.VaCloneHandle, nullptr,
                &frame, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) break;
            DWORD64 pc = frame.AddrPC.Offset;
            if (!pc || (pc == previous && frame.AddrStack.Offset == previousStack)) break;
            log << "  #" << depth << ' ' << location(pc, modules);
            alignas(SYMBOL_INFO) std::array<std::byte, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> storage{};
            auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO); symbol->MaxNameLen = MAX_SYM_NAME;
            DWORD64 displacement = 0;
            if (symbols && SymFromAddr(clone.VaCloneHandle, pc, &displacement, symbol))
                log << " " << symbol->Name << "+0x" << std::hex << displacement << std::dec;
            IMAGEHLP_LINE64 line{}; line.SizeOfStruct = sizeof(line); DWORD lineOffset = 0;
            if (symbols && SymGetLineFromAddr64(clone.VaCloneHandle, pc, &lineOffset, &line))
                log << " source=" << line.FileName << ':' << line.LineNumber;
            log << '\n';
            previous = pc;
            previousStack = frame.AddrStack.Offset;
        }
        log.flush();
        ++count;
        if (count >= 4096) { log << "thread list truncated to 4096 entries\n"; break; }
    }
    log << "thread_count=" << count << " walk_result=" << error << '\n';
    if (count && !modules.empty()) lastModules = modules;
    sampled |= count > 0;
    }
    KeptFault kept = exceptionJournal.selected();
    log << "\nSELECTED_EXCEPTION (first-candidate rule; a handled exception is not automatically the cause)\n";
    if (kept.present) {
        log << "code=0x" << std::hex << kept.code << std::dec << " thread=" << kept.thread << " tick=" << kept.tick
            << " rule=" << kept.rule << " p0=0x" << std::hex << kept.parameters[0] << " p1=0x" << kept.parameters[1]
            << " p2=0x" << kept.parameters[2] << " p3=0x" << kept.parameters[3] << std::dec << '\n';
        if (kept.code == 0xE06D7363u)
            log << "cpp_throw_image_base=p3 (resolve against MODULES below; thrown-by is not proven cause)\n";
    } else {
        log << "no native breadcrumbs recorded\n";
    }
    log << "\nREPEATED_OBSERVATIONS (high CPU can be legitimate work; stable RIP can be an ordinary wait)\n";
    for (const auto& [id, o] : observations)
        log << "thread=" << id << " samples=" << o.samples << " unchanged_RIP_transitions=" << o.ripSequence.repeats()
            << " total_cpu_delta_100ns=" << o.cpu - o.firstCPU << '\n';
    log << "\nWAIT_CHAINS (live, after snapshots; unsupported locks and access failures are not proof of no deadlock)\n";
    if (state) for (int channel = 1; channel >= 0; --channel) {
        auto priority = std::find(threadIDs.begin(), threadIDs.end(), static_cast<DWORD>(read(state->thread[channel])));
        if (priority != threadIDs.end()) std::rotate(threadIDs.begin(), priority, priority + 1);
    }
    log << waitChains(threadIDs);
    log.flush();
    log << "\nCANDIDATE_CONSENSUS (agreement heuristic, not a verdict; confirm by isolation or reproduction)\n";
    std::vector<CrashModuleIdentity> crashModules;
    crashModules.reserve(lastModules.size());
    for (const auto& module : lastModules)
        crashModules.push_back({module.base, module.size,
                                buffout::lower(diagnosticPath(module.path.filename()))});
    ExternalCrash external = findExternalCrashLog(gameImage, state, crashModules);
    log << externalCrashReport(external);
    struct OwnCandidate { std::string module; DWORD thread = 0; unsigned repeats = 0; bool present = false; };
    OwnCandidate own;
    if (state)
        for (int channel = 0; channel < 2; ++channel) {
            DWORD id = static_cast<DWORD>(read(state->thread[channel]));
            auto found = observations.find(id);
            if (found == observations.end() || found->second.samples < 3 || !found->second.ripSequence.repeats()) continue;
            std::string module = moduleBaseName(found->second.ip, lastModules);
            if (!module.empty() && (!own.present || found->second.ripSequence.repeats() > own.repeats))
                own = {module, id, found->second.ripSequence.repeats(), true};
        }
    log << "own_candidate=" << (own.present ? own.module + " (callback thread RIP agreement)" : "none") << '\n';
    if (external.corroborated && external.info.found && own.present) {
        if (external.info.faultModule == own.module) {
            if (RuntimeModuleClassifier::isVictimLocation(own.module))
                log << "consensus=victim-location-caution " << own.module
                    << " (system/game/logger image is usually where corruption lands, not the cause)\n";
            else
                log << "consensus=process-exception-and-callback-agree " << own.module
                    << " (evidence agrees, but agreement does not prove cause)\n";
        } else {
            log << "consensus=disagree external=" << external.info.faultModule << " live=" << own.module
                << " (treat both as leads)\n";
        }
    } else if (external.corroborated && external.info.found) {
        log << "consensus=process-exception-and-module-match " << external.info.faultModule
            << " (process evidence corroborates the fault record, not its cause)\n";
    } else if (external.candidate) {
        log << "consensus=recent-external-candidate-only (not used for current-process attribution)\n";
    } else {
        log << "consensus=no-correlated-external-log\n";
    }
    std::vector<ConsensusThread> consensusThreads;
    if (state)
        for (const auto& [id, observation] : observations) {
            ConsensusThread thread;
            thread.id = id;
            thread.module = moduleBaseName(observation.ip, lastModules);
            thread.samples = observation.samples;
            thread.repeats = observation.ripSequence.repeats();
            thread.cpuDelta = observation.cpu >= observation.firstCPU
                ? static_cast<unsigned long long>(observation.cpu - observation.firstCPU)
                : 0;
            for (int channel = 0; channel < 2; ++channel)
                if (id == static_cast<DWORD>(read(state->thread[channel]))) thread.isCallback = true;
            consensusThreads.push_back(std::move(thread));
        }
    GroupConsensus group = threadGroupConsensus(consensusThreads, [](const std::string& module) {
        return RuntimeModuleClassifier::isVictimLocation(module);
    });
    if (group.present)
        log << "thread_group_consensus=" << group.module << " matching_threads=" << group.matching
            << " (synchronization stall likely; an OS lock cycle is not proven, see WAIT_CHAINS)\n";
    else
        log << "thread_group_consensus=none (no stable non-idle group; zero-CPU system waits excluded)\n";
    if (kept.present && kept.code == 0xE06D7363u) {
        std::string thrownBy;
        for (const auto& [path, identity] : identities)
            if (kept.parameters[3] >= identity.base && kept.parameters[3] - identity.base < identity.size) {
                thrownBy = buffout::lower(diagnosticPath(identity.path.filename()));
                break;
            }
        if (!thrownBy.empty())
            log << "cpp_thrown_by=" << thrownBy
                << (thrownBy == "buffout4.dll" ? " (thrown by the crash logger itself; ignore)" : "") << '\n';
    }
    log << "\nMODULE_FILE_IDENTITIES (on-disk files; compare to loaded PE/PDB identity above)\n";
    for (const auto& [path, m] : identities)
        log << diagnosticPath(m.path) << " version=" << version(m.path) << " disk_sha256=" << sha256(m.path) << '\n';
    log << "\ncollection complete\n";
    return sampled && log.good();
}
}
