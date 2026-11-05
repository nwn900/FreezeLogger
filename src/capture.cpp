#include "shared.hpp"
#include "exceptions.hpp"
#include "buffout.hpp"
#include "consensus.hpp"
#include <processsnapshot.h>
#include <dbghelp.h>
#include <psapi.h>
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
// PssFreeSnapshot returns before the clone process fully exits, so a 0 ms
// liveness check cannot tell a slow reaping from a real leak. Only terminate
// when the clone survives this grace period.
constexpr DWORD CLONE_EXIT_GRACE_MS = 500;
bool commitAvailableForClone() {
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
struct Observation { LONG64 created = 0, cpu = 0, firstCPU = 0; DWORD64 ip = 0; unsigned samples = 0, repeats = 0; };
std::string location(DWORD64 address, const std::vector<Module>& modules) {
    std::ostringstream out;
    for (const auto& m : modules) if (address >= m.base && address - m.base < m.size) {
        out << utf8(m.path.filename().wstring()) << "+0x" << std::hex << address - m.base;
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
                            out << " object=" << utf8(std::wstring_view(n.LockObject.ObjectName, length));
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
    return ReadProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(value), &size) && size == sizeof(value);
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
bool writeWerFallbackHint(const std::filesystem::path& folder) {
    std::error_code ignored;
    auto path = folder / "WER_LocalDumps_Hint.txt";
    if (std::filesystem::exists(path, ignored)) return false;
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    out << "FreezeSentryF4 could not write a minidump for an incident (see snapshot_error= or minidump=FAILED\n"
           "in the incident log). Windows Error Reporting can capture a dump instead:\n\n"
           "Run as administrator, replacing the dump folder as needed:\n"
           "  reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\Fallout4.exe\""
           " /v DumpFolder /t REG_EXPAND_SZ /d \"%USERPROFILE%\\Documents\\CrashDumps\" /f\n"
           "  reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\Fallout4.exe\""
           " /v DumpCount /t REG_DWORD /d 5 /f\n"
           "  reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\Fallout4.exe\""
           " /v DumpType /t REG_DWORD /d 2 /f\n\n"
           "DumpType 2 is a full dump. Reproduce the incident, then find Fallout4.exe.*.dmp in the dump folder.\n"
           "This file is never removed by retention; delete it to regenerate it.\n";
    out.flush();
    return static_cast<bool>(out);
}
// Lowercase basename of the module containing address, or empty.
std::string moduleBaseName(DWORD64 address, const std::vector<Module>& modules) {
    for (const auto& m : modules)
        if (address >= m.base && address - m.base < m.size)
            return buffout::lower(utf8(m.path.filename().wstring()));
    return {};
}
// Images where corruption is usually observed rather than caused: system and
// graphics libraries, the game and loader images, and crash loggers themselves.
bool isVictimLocationModule(const std::string& lowerBase) {
    static const char* victims[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll",
        "gdi32.dll", "gdi32full.dll", "combase.dll", "ole32.dll", "oleaut32.dll",
        "shell32.dll", "shcore.dll", "shlwapi.dll", "msvcrt.dll", "ucrtbase.dll",
        "msvcp_win.dll", "bcrypt.dll", "bcryptprimitives.dll", "rpcrt4.dll", "sechost.dll",
        "advapi32.dll", "imm32.dll", "crypt32.dll", "imagehlp.dll", "psapi.dll",
        "version.dll", "winmm.dll", "ws2_32.dll", "mswsock.dll", "setupapi.dll",
        "cfgmgr32.dll", "hid.dll", "kernel.appcore.dll", "powrprof.dll", "umpdc.dll",
        "d3d11.dll", "dxgi.dll", "dwmapi.dll", "uxtheme.dll", "msctf.dll",
        "fallout4.exe", "fallout4vr.exe", "f4se_1_10_163.dll", "f4se_steam_loader.dll",
        "steam_api64.dll", "steamclient64.dll", "tier0_s64.dll", "vstdlib_s64.dll",
        "gameoverlayrenderer64.dll", "buffout4.dll"};
    for (const char* victim : victims)
        if (lowerBase == victim) return true;
    return lowerBase.starts_with("d3dcompiler_") || lowerBase.starts_with("msvcp140") ||
           lowerBase.starts_with("vcruntime140") || lowerBase.starts_with("concrt140");
}
struct ExternalCrash {
    BuffoutCrashInfo info;
    std::string path;
};
// Newest parseable Buffout-style crash log under the game F4SE folders.
// Tolerates custom ReportDirectory: the game folders are resolved independently.
ExternalCrash findExternalCrashLog() {
    ExternalCrash result;
    PWSTR documents = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documents))) return result;
    std::filesystem::path root(documents);
    CoTaskMemFree(documents);
    std::filesystem::file_time_type newest = std::filesystem::file_time_type::min();
    for (const wchar_t* game : {L"Fallout4", L"Fallout4VR"}) {
        std::error_code error;
        auto iterator = std::filesystem::directory_iterator(root / "My Games" / game / "F4SE", error);
        const auto end = std::filesystem::directory_iterator{};
        for (; !error && iterator != end; iterator.increment(error)) {
            auto path = iterator->path();
            if (path.extension() != ".log") continue;
            std::string stem = buffout::lower(path.stem().string());
            if (!stem.starts_with("crash") && stem.find("buffout") == std::string::npos) continue;
            auto size = iterator->file_size(error);
            if (error || size > 4 * 1024 * 1024) { error.clear(); continue; }
            std::ifstream in(path, std::ios::binary);
            if (!in) continue;
            std::string text(static_cast<std::size_t>(size), '\0');
            in.read(text.data(), static_cast<std::streamsize>(text.size()));
            text.resize(static_cast<std::size_t>(in.gcount()));
            BuffoutCrashInfo info = parseBuffoutCrashLog(text, path.string());
            if (!info.found) continue;
            auto time = iterator->last_write_time(error);
            if (error) { error.clear(); continue; }
            if (result.path.empty() || time > newest) {
                newest = time;
                result.info = std::move(info);
                result.path = path.string();
            }
        }
    }
    return result;
}
std::string profile(HANDLE target, bool stacks, Shared* state, bool reset) {
    struct CPU { LONG64 created, cpu; };
    static thread_local std::map<DWORD, CPU> baseline;
    if (reset) { baseline.clear(); return {}; }
    std::ostringstream out;
    auto began = now();
    out << "\nPROFILE tick=" << now() << " early_stack=" << stacks << '\n';
    Snapshot snapshot;
    snapshot.log = &out;
    if (stacks && !commitAvailableForClone()) {
        out << "profile_clone_deferred_low_commit\n";
        return out.str();
    }
    auto flags = static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT |
                    (stacks ? PSS_CAPTURE_VA_CLONE : 0));
    auto captureBegan = now();
    DWORD error = PssCaptureSnapshot(target, flags, CONTEXT_ALL, &snapshot.value);
    if (error) { out << "profile_snapshot_error=" << error << '\n'; return out.str(); }
    out << "snapshot_capture_ms=" << now() - captureBegan << '\n';
    PSS_VA_CLONE_INFORMATION clone{};
    if (stacks && (error = PssQuerySnapshot(snapshot.value, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone)))) {
        out << "profile_clone_error=" << error << '\n'; return out.str();
    }
    if (stacks && !snapshot.trackClone()) {
        out << "profile_clone_untracked; capture aborted\n";
        return out.str();
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
    if (error) { out << "profile_marker_error=" << error << '\n'; return out.str(); }
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
    std::sort(rows.begin(), rows.end(), [state](const Row& a, const Row& b) {
        auto priority = [state](DWORD id) { return state && (id == static_cast<DWORD>(read(state->thread[0])) ||
            id == static_cast<DWORD>(read(state->thread[1])) || id == static_cast<DWORD>(read(state->frameThread))); };
        if (priority(a.id) != priority(b.id)) return priority(a.id);
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
    out << "profile_elapsed_ms=" << now() - began << '\n';
    return out.str();
}
bool capture(HANDLE target, DWORD pid, const std::filesystem::path& folder,
             const std::string& reason, Shared* state, bool dump, const std::string& history) {
    ExceptionJournal exceptionJournal(state);
    SYSTEMTIME utc{}; GetSystemTime(&utc);
    std::ostringstream stem;
    // Manual snapshots use their own name class so per-category retention caps
    // (MaxFreezeReports/MaxManualReports) can keep each class independently.
    stem << (reason == "manual-capture" ? "manual-" : "freeze-") << std::setfill('0') << std::setw(4) << utc.wYear << std::setw(2) << utc.wMonth
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
    if (state) log << "frame_source=" << read(state->frameSource) << " frame_status=" << read(state->frameStatus)
        << " present_count=" << read(state->frameCount) << " present_tick=" << read(state->frameTick)
        << " present_thread=" << read(state->frameThread) << '\n';
    log.flush();
    std::map<DWORD, Observation> observations;
    std::map<std::wstring, Module> identities;
    std::vector<Module> lastModules;
    std::vector<DWORD> threadIDs;
    bool sampled = false;
    for (unsigned sample = 0; sample < 3; ++sample) {
    if (sample) Sleep(1000);
    log << "\nSAMPLE " << sample + 1 << "/3 tick=" << now() << '\n';
    Snapshot snapshot;
    snapshot.log = &log;
    if (!commitAvailableForClone()) {
        log << "snapshot_deferred_low_commit; no thread snapshot or minidump available\n";
        if (writeWerFallbackHint(folder)) log << "wer_fallback_hint=written\n";
        return false;
    }
    auto flags = static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT);
    auto captureBegan = now();
    DWORD error = PssCaptureSnapshot(target, flags, CONTEXT_ALL, &snapshot.value);
    if (error != ERROR_SUCCESS) {
        log << "snapshot_error=" << error << "; no thread snapshot or minidump available\n";
        if (writeWerFallbackHint(folder)) log << "wer_fallback_hint=written\n";
        return false;
    }
    if (!snapshot.trackClone()) {
        log << "clone_untracked; capture aborted, snapshot released\n";
        return false;
    }
    log << "snapshot_capture_ms=" << now() - captureBegan << " dump_transport=pss-snapshot\n";
    PSS_VA_CLONE_INFORMATION clone{};
    error = PssQuerySnapshot(snapshot.value, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone));
    if (error != ERROR_SUCCESS || !clone.VaCloneHandle) { log << "clone_query_error=" << error << '\n'; return false; }
    log << "capture_source=Windows PSS snapshot; game threads are not manually suspended\n";
    log.flush();
    if (dump && sample == 0) {
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
        log << "minidump=" << (success ? dumpPath.filename().string() : "FAILED")
            << " error=" << dumpError << " structural_validation=" << validation << '\n';
        if (!success && writeWerFallbackHint(folder)) log << "wer_fallback_hint=written\n";
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
            log << "base=0x" << std::hex << m.base << " size=0x" << m.size << std::dec << ' ' << utf8(m.path.wstring()) << '\n';
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
        IMAGEHLP_MODULE64 info{}; info.SizeOfStruct = sizeof(info);
        if (SymGetModuleInfo64(clone.VaCloneHandle, m.base, &info)) {
            log << "symbols module=" << utf8(m.path.filename().wstring()) << " type=" << info.SymType << " pdb=" << info.LoadedPdbName
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
        if (!observation.samples || observation.created != filetime(entry.CreateTime)) observation = {filetime(entry.CreateTime), cpu, cpu, 0, 0, 0};
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
                log << "thread_name=" << utf8(name) << '\n'; LocalFree(name);
            }
        }
        if (!entry.ContextRecord || entry.SizeOfContextRecord < sizeof(CONTEXT)) { log << "context unavailable\n"; continue; }
        CONTEXT context = *entry.ContextRecord;
        if (observation.samples && observation.ip == context.Rip) ++observation.repeats;
        observation.ip = context.Rip; ++observation.samples;
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
        log << "thread=" << id << " samples=" << o.samples << " unchanged_RIP_transitions=" << o.repeats
            << " total_cpu_delta_100ns=" << o.cpu - o.firstCPU << '\n';
    log << "\nWAIT_CHAINS (live, after snapshots; unsupported locks and access failures are not proof of no deadlock)\n";
    if (state) for (int channel = 1; channel >= 0; --channel) {
        auto priority = std::find(threadIDs.begin(), threadIDs.end(), static_cast<DWORD>(read(state->thread[channel])));
        if (priority != threadIDs.end()) std::rotate(threadIDs.begin(), priority, priority + 1);
    }
    log << waitChains(threadIDs);
    log.flush();
    log << "\nCANDIDATE_CONSENSUS (agreement heuristic, not a verdict; confirm by isolation or reproduction)\n";
    ExternalCrash external = findExternalCrashLog();
    log << "external_crash_log=" << (external.path.empty() ? "none" : external.path) << '\n';
    if (external.info.found) {
        log << "external_fault=" << (external.info.faultModule.empty() ? "unknown-module" : external.info.faultModule)
            << (external.info.faultOffset.empty() ? "" : "+" + external.info.faultOffset) << " code=0x" << std::hex
            << external.info.exceptionCode << std::dec << '\n';
        if (!external.info.stackModules.empty())
            log << "external_top_frame=" << external.info.stackModules.front() << '\n';
    }
    struct OwnCandidate { std::string module; DWORD thread = 0; unsigned repeats = 0; bool present = false; };
    OwnCandidate own;
    if (state)
        for (int channel = 0; channel < 2; ++channel) {
            DWORD id = static_cast<DWORD>(read(state->thread[channel]));
            auto found = observations.find(id);
            if (found == observations.end() || found->second.samples < 2) continue;
            std::string module = moduleBaseName(found->second.ip, lastModules);
            if (!module.empty() && (!own.present || found->second.repeats > own.repeats))
                own = {module, id, found->second.repeats, true};
        }
    log << "own_candidate=" << (own.present ? own.module + " (callback thread RIP agreement)" : "none") << '\n';
    if (external.info.found && own.present) {
        if (external.info.faultModule == own.module) {
            if (isVictimLocationModule(own.module))
                log << "consensus=victim-location-caution " << own.module
                    << " (system/game/logger image is usually where corruption lands, not the cause)\n";
            else
                log << "consensus=agree-strong " << own.module
                    << " (external log and live callback stacks agree; still confirm by isolation)\n";
        } else {
            log << "consensus=disagree external=" << external.info.faultModule << " live=" << own.module
                << " (treat both as leads)\n";
        }
    } else if (external.info.found) {
        log << "consensus=external-only " << external.info.faultModule << '\n';
    } else {
        log << "consensus=no-external-log\n";
    }
    std::vector<ConsensusThread> consensusThreads;
    if (state)
        for (const auto& [id, observation] : observations) {
            ConsensusThread thread;
            thread.id = id;
            thread.module = moduleBaseName(observation.ip, lastModules);
            thread.samples = observation.samples;
            thread.repeats = observation.repeats;
            thread.cpuDelta = observation.cpu >= observation.firstCPU
                ? static_cast<unsigned long long>(observation.cpu - observation.firstCPU)
                : 0;
            for (int channel = 0; channel < 2; ++channel)
                if (id == static_cast<DWORD>(read(state->thread[channel]))) thread.isCallback = true;
            consensusThreads.push_back(std::move(thread));
        }
    GroupConsensus group = threadGroupConsensus(consensusThreads, isVictimLocationModule);
    if (group.present)
        log << "thread_group_consensus=" << group.module << " matching_threads=" << group.matching
            << " (synchronization stall likely; an OS lock cycle is not proven, see WAIT_CHAINS)\n";
    else
        log << "thread_group_consensus=none (no stable non-idle group; zero-CPU system waits excluded)\n";
    if (kept.present && kept.code == 0xE06D7363u) {
        std::string thrownBy;
        for (const auto& [path, identity] : identities)
            if (kept.parameters[3] >= identity.base && kept.parameters[3] - identity.base < identity.size) {
                thrownBy = buffout::lower(utf8(identity.path.filename().wstring()));
                break;
            }
        if (!thrownBy.empty())
            log << "cpp_thrown_by=" << thrownBy
                << (thrownBy == "buffout4.dll" ? " (thrown by the crash logger itself; ignore)" : "") << '\n';
    }
    log << "\nMODULE_FILE_IDENTITIES (on-disk files; compare to loaded PE/PDB identity above)\n";
    for (const auto& [path, m] : identities)
        log << utf8(m.path.wstring()) << " version=" << version(m.path) << " disk_sha256=" << sha256(m.path) << '\n';
    log << "\ncollection complete\n";
    return sampled && log.good();
}
}
