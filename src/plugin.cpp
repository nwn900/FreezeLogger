#include "api.hpp"
#include "shared.hpp"
#include "exceptions.hpp"
#include <process.h>
#include <array>
#include <fstream>
#include <new>
#include <vector>
#include <algorithm>

namespace {
fs::Shared* state = nullptr;
fs::Tasks* tasks = nullptr;
HANDLE mapping = nullptr;
HANDLE companion = nullptr;
std::filesystem::path dllFolder;
fs::ExceptionJournal exceptionJournal;
HHOOK closeHook = nullptr;
LRESULT CALLBACK noteClose(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && state) {
        auto* message = reinterpret_cast<CWPSTRUCT*>(lParam);
        if (message && (message->message == WM_CLOSE ||
            (message->message == WM_SYSCOMMAND && (message->wParam & 0xFFF0) == SC_CLOSE)))
            InterlockedExchange(&state->userClose, 1);
    }
    return CallNextHookEx(closeHook, code, wParam, lParam);
}
struct PreserveError { DWORD value = GetLastError(); ~PreserveError() { SetLastError(value); } };
bool record(const fs::EventData& data) {
    if (!state || fs::read(state->ready) < 0) return false;
    if (InterlockedCompareExchange(&state->eventWriting, 1, 0)) {
        InterlockedIncrement(&state->eventsDropped); return false;
    }
    auto id = fs::read(state->eventCount) + 1;
    auto& slot = state->events[(id - 1) % 128];
    InterlockedIncrement(&slot.sequence);
    slot.data = {fs::now(), id, GetCurrentThreadId(), data};
    InterlockedIncrement(&slot.sequence);
    InterlockedExchange64(&state->eventCount, id);
    InterlockedExchange(&state->eventWriting, 0);
    return true;
}
bool movieCreated(void* view, void*) {
    PreserveError preserve;
    fs::EventData entry;
    strcpy_s(entry.source, "F4SE.Scaleform"); strcpy_s(entry.name, "movie-created (menu name unavailable)");
    entry.value = reinterpret_cast<ULONG_PTR>(view);
    record(entry);
    return true;
}
template<size_t N> void clean(char (&text)[N]) {
    text[N - 1] = 0;
    for (char& c : text) if (static_cast<unsigned char>(c) < 32 || c == 127) c = c ? ' ' : 0;
}
void startupLog(const std::string& text) {
    // One startup/error write only; task callbacks never perform file I/O.
    std::ofstream out(dllFolder / "FreezeSentryF4-startup.log", std::ios::app);
    out << text << '\n';
}
DWORD setting(const std::filesystem::path& ini, const wchar_t* key, DWORD fallback, DWORD low, DWORD high) {
    wchar_t buffer[64]{};
    auto defaultValue = std::to_wstring(fallback);
    GetPrivateProfileStringW(L"FreezeSentryF4", key, defaultValue.c_str(), buffer, 64, ini.c_str());
    wchar_t* end = nullptr;
    auto n = wcstoull(buffer, &end, 10);
    return end == buffer || *end || n < low || n > high ? fallback : static_cast<DWORD>(n);
}
struct Probe final : fs::Task {
    int channel;
    explicit Probe(int c) : channel(c) {}
    void Run() override {
        InterlockedExchange(&state->thread[channel], static_cast<LONG>(GetCurrentThreadId()));
        InterlockedIncrement64(&state->sequence[channel]);
        InterlockedExchange64(&state->pulse[channel], fs::now());
    }
    ~Probe() override { InterlockedExchange(&state->pending[channel], 0); }
};
unsigned __stdcall pump(void*) {
    for (;;) {
        if (fs::read(state->ready) < 0) return 0;
        if (companion && WaitForSingleObject(companion, 0) == WAIT_OBJECT_0) {
            InterlockedExchange(&state->ready, -1);
            DWORD exitCode = 0; GetExitCodeProcess(companion, &exitCode);
            try { startupLog("Companion stopped, exit_code=" + std::to_string(exitCode) + "; monitoring disabled for this session"); }
            catch (...) {}
            return 0;
        }
        for (int c = 0; c < 2; ++c) {
            if (InterlockedCompareExchange(&state->pending[c], 1, 0) == 0) {
                auto* probe = new (std::nothrow) Probe(c);
                if (probe) (c ? tasks->addUI : tasks->add)(probe);
                else InterlockedExchange(&state->pending[c], 0);
            }
        }
        Sleep(state->probeMs);
    }
}
void message(fs::Message* event) {
    PreserveError preserve;
    if (!event) return;
    fs::EventData entry; entry.kind = fs::EventKind::F4SE; entry.value = event->type;
    strcpy_s(entry.source, "F4SE");
    if ((event->type == 2 || event->type == 4 || event->type == 5 || event->type == 6) && event->data && event->length) {
        SIZE_T bytes = 0;
        ReadProcessMemory(GetCurrentProcess(), event->data, entry.name,
                          std::min<size_t>(event->length, sizeof(entry.name) - 1), &bytes);
        clean(entry.name);
    }
    if (event->type == 3 || event->type == 10) entry.flags = event->data ? 1 : 0;
    record(entry);
    InterlockedExchange(&state->event, static_cast<LONG>(event->type));
    InterlockedExchange64(&state->eventTime, fs::now());
    // F4SE enum: PreLoad=2, PostLoad=3, PreSave=4, PostSave=5,
    // GameLoaded=9, GameDataReady=10. Do not dereference game pointers.
    if (event->type == 2 || event->type == 4) InterlockedExchange(&state->phase, 1);
    else if (event->type == 3 || event->type == 5 || event->type == 9)
        InterlockedExchange(&state->phase, 0);
    else if (event->type == 10)
        InterlockedExchange(&state->phase, event->data ? 0 : 1);
}
bool launchWatch() {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes, PAGE_READWRITE, 0, sizeof(fs::Shared), nullptr);
    if (!mapping) return false;
    state = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!state) { CloseHandle(mapping); mapping = nullptr; return false; }
    new (state) fs::Shared;
    return true;
}
bool startHelper() {
    auto exe = dllFolder / "FreezeSentryF4Watch.exe";
    auto command = L"\"" + exe.wstring() + L"\" --watch " + std::to_wstring(reinterpret_cast<ULONG_PTR>(mapping));
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (!bytes) return false;
    std::vector<std::byte> buffer(bytes);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) return false;
    bool updated = UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                            &mapping, sizeof(mapping), nullptr, nullptr) != FALSE;
    PROCESS_INFORMATION process{};
    bool created = updated && CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, dllFolder.c_str(), &startup.StartupInfo, &process);
    DWORD error = GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    SetHandleInformation(mapping, HANDLE_FLAG_INHERIT, 0);
    if (created) {
        CloseHandle(process.hThread);
        auto deadline = fs::now() + 5000;
        while (!fs::read(state->monitorPulse) && fs::now() < deadline &&
               WaitForSingleObject(process.hProcess, 50) == WAIT_TIMEOUT) {}
        created = fs::read(state->monitorPulse) != 0;
        if (!created) {
            InterlockedExchange(&state->ready, -1);
            startupLog("Companion did not initialize; check its permissions and ReportDirectory");
        }
        if (created) companion = process.hProcess;
        else CloseHandle(process.hProcess);
    }
    else startupLog("Cannot launch companion, Windows error=" + std::to_string(error));
    return created;
}
bool load(const fs::Host* host) {
    if (state) return false; // Repeated registration cannot start a second companion/pump.
    if (!host || host->isEditor || !host->query || !host->handle) return false;
    tasks = static_cast<fs::Tasks*>(host->query(fs::taskID));
    auto* messaging = static_cast<fs::Messaging*>(host->query(fs::messagingID));
    // Task v1 contains only AddTask. AddUITask is a v2 extension.
    if (!tasks || tasks->version < 2 || !tasks->add || !tasks->addUI) tasks = nullptr;
    if (!messaging || messaging->version < 1 || !messaging->listen) return false;
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&load), &module)) return false;
    std::array<wchar_t, 32768> path{};
    DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return false;
    dllFolder = std::filesystem::path(path.data()).parent_path();
    if (!launchWatch()) { startupLog("Shared memory unavailable"); return false; }
    struct PendingMapping {
        bool keep = false;
        ~PendingMapping() {
            if (!keep && state) {
                if (state->crashEvent) {
                    CloseHandle(reinterpret_cast<HANDLE>(state->crashEvent));
                    state->crashEvent = 0;
                }
                InterlockedExchange(&state->ready, -1);
                UnmapViewOfFile(state); CloseHandle(mapping); state = nullptr; mapping = nullptr;
                if (companion) { CloseHandle(companion); companion = nullptr; }
            }
        }
    } pendingMapping;
    state->pid = GetCurrentProcessId();
    state->runtime = host->runtimeVersion; state->extender = host->extenderVersion;
    state->taskMonitoring = tasks ? 1 : 0;
    state->started = fs::now();
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) return false;
    state->processCreated = fs::filetime(creation);
    auto ini = dllFolder / "FreezeSentryF4.ini";
    state->timeoutMs = setting(ini, L"TimeoutSeconds", 15, 2, 3600) * 1000;
    state->loadingMs = setting(ini, L"LoadingTimeoutSeconds", 120, 2, 3600) * 1000;
    state->startupMs = setting(ini, L"StartupTimeoutSeconds", 180, 2, 3600) * 1000;
    state->probeMs = setting(ini, L"ProbeMilliseconds", 250, 50, 5000);
    state->maxReports = setting(ini, L"MaxReports", 10, 1, 100);
    // Older INIs exposed only MaxReports. Category-specific limits override
    // that compatibility default when present.
    state->maxFreezeReports = setting(ini, L"MaxFreezeReports", state->maxReports, 1, 100);
    state->maxManualReports = setting(ini, L"MaxManualReports", state->maxReports, 1, 100);
    state->suppressBackground = setting(ini, L"SuppressBackgroundHang", 1, 0, 1);
    state->foregroundGraceSec = setting(ini, L"ForegroundGraceSeconds", 10, 0, 300);
    // Minidumps are opt-in: text/thread evidence is the default incident payload.
    state->writeDump = setting(ini, L"WriteMinidump", 0, 0, 1);
    state->fullDump = setting(ini, L"FullMemoryDump", 0, 0, 1);
    state->earlyMs = setting(ini, L"EarlyWarningSeconds", 3, 0, 60) * 1000;
    state->profileMs = setting(ini, L"ProfileMilliseconds", 2000, 500, 10000);
    state->historyMs = setting(ini, L"HistorySeconds", 60, 10, 120) * 1000;
    state->storageMB = setting(ini, L"MaxStorageMB", 1024, 0, 65536);
    state->frameMonitoring = setting(ini, L"FrameMonitoring", 1, 0, 1);
    state->captureMs = setting(ini, L"CaptureTimeoutSeconds", 120, 15, 900) * 1000;
    state->contextMonitoring = setting(ini, L"ContextMonitoring", 1, 0, 1);
    state->crashCapture = setting(ini, L"CrashCapture", 1, 0, 1);
    if (HANDLE crashEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr))
        state->crashEvent = reinterpret_cast<ULONG_PTR>(crashEvent);
    state->manualKey = setting(ini, L"ManualKey", VK_PAUSE, 0, 255);
    GetPrivateProfileStringW(L"FreezeSentryF4", L"ReportDirectory", L"", state->outputDirectory, 1024, ini.c_str());
    if (!startHelper()) return false;
    // Keep callback code alive for process lifetime, including initialization failures.
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&load), &module)) {
        InterlockedExchange(&state->ready, -1); return false;
    }
    // Once a callback may have been retained by F4SE, its shared view must remain alive.
    pendingMapping.keep = true;
    if (!messaging->listen(host->handle(), "F4SE", message)) {
        InterlockedExchange(&state->ready, -1);
        startupLog("Messaging registration failed"); return false;
    }
    auto* scaleform = static_cast<fs::Scaleform*>(host->query(fs::scaleformID));
    if (scaleform && scaleform->version >= 1 && scaleform->registerCallback) {
        if (!scaleform->registerCallback("FreezeSentryF4", movieCreated)) startupLog("Scaleform creation events unavailable");
    }
    if (tasks) {
        HANDLE worker = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, pump, nullptr, 0, nullptr));
        if (!worker) {
            state->taskMonitoring = 0;
            startupLog("Probe thread unavailable; using Windows window monitoring");
        } else CloseHandle(worker);
    }
    InterlockedExchange(&state->ready, 1);
    if (!exceptionJournal.install(state)) startupLog("Native exception breadcrumbs unavailable");
    else startupLog("Native exception observer installed (first VEH position requested; pass-through; fatal codes request a live dump)");
    closeHook = SetWindowsHookExW(WH_CALLWNDPROC, noteClose, module, GetCurrentThreadId());
    struct CloseWindow { DWORD pid; DWORD thread = 0; };
    CloseWindow game{GetCurrentProcessId()};
    EnumWindows([](HWND window, LPARAM parameter) -> BOOL {
        auto& game = *reinterpret_cast<CloseWindow*>(parameter);
        DWORD pid = 0;
        DWORD thread = GetWindowThreadProcessId(window, &pid);
        if (pid == game.pid && IsWindowVisible(window) && !GetWindow(window, GW_OWNER)) {
            game.thread = thread; return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&game));
    if (game.thread && game.thread != GetCurrentThreadId())
        SetWindowsHookExW(WH_CALLWNDPROC, noteClose, module, game.thread);
    startupLog("Loaded, runtime=" + std::to_string(state->runtime) + ", PID=" + std::to_string(state->pid) +
               ", task_monitoring=" + std::to_string(state->taskMonitoring));
    return true;
}
}
extern "C" {
// F4SE's address-independent bit also covers having no addresses at all.
__declspec(dllexport) fs::Version F4SEPlugin_Version{1, 3, "FreezeSentryF4", "", 1, 1, {}, 0, 0, 0, {}};
__declspec(dllexport) bool FreezeSentryF4_RecordEvent(const fs::EventData* input) {
    PreserveError preserve;
    fs::EventData value; SIZE_T bytes = 0;
    if (!input || !ReadProcessMemory(GetCurrentProcess(), input, &value, sizeof(value), &bytes) || bytes != sizeof(value) ||
        value.size != sizeof(value) || value.version != 1 || value.kind < fs::EventKind::Cell || value.kind > fs::EventKind::Marker ||
        !value.source[0] || value.source[95] || value.name[159] || value.plugin[95]) return false;
    clean(value.source); clean(value.name); clean(value.plugin);
    return record(value);
}
__declspec(dllexport) bool FreezeSentryF4_FramePulse() {
    PreserveError preserve;
    if (!state || fs::read(state->ready) != 1) return false;
    auto tick = fs::now();
    return state->nativeFrames.publish(tick, tick, GetCurrentThreadId());
}
__declspec(dllexport) bool F4SEPlugin_Query(const fs::Host* host, fs::Info* info) {
    if (!info) return false;
    *info = {1, "FreezeSentryF4", 3};
    return host && !host->isEditor && host->query && host->handle;
}
__declspec(dllexport) bool F4SEPlugin_Load(const fs::Host* host) {
    try { return load(host); } catch (...) { return false; }
}
}
