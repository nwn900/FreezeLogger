#include "../src/api.hpp"
#include "../src/shared.hpp"
#include <dbghelp.h>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <vector>
#include <thread>
#include <atomic>

namespace {
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
std::mutex mutex;
std::vector<fs::Task*> queue[2];
void add(fs::Task* t) { std::lock_guard lock(mutex); queue[0].push_back(t); }
void addUI(fs::Task* t) { std::lock_guard lock(mutex); queue[1].push_back(t); }
fs::Tasks taskAPI{2, add, addUI};
void (*listener)(fs::Message*) = nullptr;
bool listen(std::uint32_t, const char*, void (*callback)(fs::Message*)) { listener = callback; return true; }
fs::Messaging messagingAPI{1, listen};
bool (*movieCallback)(void*, void*) = nullptr;
bool registerMovie(const char*, bool (*callback)(void*, void*)) { movieCallback = callback; return true; }
fs::Scaleform scaleformAPI{1, registerMovie};
void* query(std::uint32_t id) { return id == fs::taskID ? static_cast<void*>(&taskAPI) : id == fs::messagingID ? static_cast<void*>(&messagingAPI) :
    id == fs::scaleformID ? static_cast<void*>(&scaleformAPI) : nullptr; }
std::uint32_t handle() { return 1; }
void drain(int channel) {
    std::vector<fs::Task*> copy;
    { std::lock_guard lock(mutex); copy.swap(queue[channel]); }
    for (auto* t : copy) { t->Run(); delete t; }
}
std::string contents(const std::filesystem::path& file) {
    std::ifstream in(file); return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
std::vector<std::filesystem::path> reports(const std::filesystem::path& folder) {
    std::vector<std::filesystem::path> result;
    if (!std::filesystem::exists(folder)) return result;
    for (const auto& file : std::filesystem::directory_iterator(folder)) {
        auto name = file.path().filename().string();
        if (file.path().extension() == ".log" && (name.starts_with("freeze-") || name.starts_with("manual-"))) result.push_back(file.path());
    }
    return result;
}
void ticks(DWORD duration, bool normal = true, bool ui = true) {
    auto end = GetTickCount64() + duration;
    while (GetTickCount64() < end) { if (normal) drain(0); if (ui) drain(1); Sleep(20); }
}
std::atomic<bool> spin = true;
__declspec(noinline) void busyLoop() { while (spin.load(std::memory_order_relaxed)) {} }
void deadlockFixture() {
    auto prefix = L"Local\\FreezeLogger-test-" + std::to_wstring(GetCurrentProcessId());
    HANDLE a = CreateMutexW(nullptr, FALSE, (prefix + L"-A").c_str());
    HANDLE b = CreateMutexW(nullptr, FALSE, (prefix + L"-B").c_str());
    HANDLE readyA = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE readyB = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(a && b && readyA && readyB, "deadlock fixture handles");
    std::thread([=] { WaitForSingleObject(a, INFINITE); SetEvent(readyA); WaitForSingleObject(readyB, INFINITE); WaitForSingleObject(b, INFINITE); }).detach();
    std::thread([=] { WaitForSingleObject(b, INFINITE); SetEvent(readyB); WaitForSingleObject(readyA, INFINITE); WaitForSingleObject(a, INFINITE); }).detach();
    check(WaitForSingleObject(readyA, 2000) == WAIT_OBJECT_0 && WaitForSingleObject(readyB, 2000) == WAIT_OBJECT_0,
          "two known mutex owners established");
}
void handledExceptionFixture() {
    constexpr ULONG_PTR firstParameter = 0x1234;
    constexpr ULONG_PTR exceptionCount = static_cast<ULONG_PTR>(fs::faultCapacity) + 5;
    for (ULONG_PTR index = 0; index < exceptionCount; ++index) {
        ULONG_PTR parameters[]{0, firstParameter + index};
        __try { RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 2, parameters); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}
}
int wmain(int argc, wchar_t** argv) {
    check(argc == 3 || (argc == 4 && std::wstring(argv[3]) == L"--fallback"), "DLL and watcher paths required");
    bool fallback = argc == 4;
    fs::StallGate gate;
    check(!gate.sample(1000, 0, 900, 900, 2000, 5000), "healthy queues");
    check(gate.sample(3000, 0, 900, 900, 2000, 5000), "stall detected");
    check(!gate.sample(4000, 0, 900, 3900, 2000, 5000), "one report per incident");
    check(!gate.sample(6000, 0, 1000, 5900, 2000, 5000), "old partial progress cannot rearm");
    check(!gate.sample(6100, 0, 6000, 6000, 2000, 5000) && !gate.reported, "fresh queues rearm");
    check(gate.sample(9000, 0, 6000, 6000, 2000, 5000), "second incident");
    fs::StallGate startup;
    check(!startup.sample(4999, 0, 0, 0, 2000, 5000), "startup grace");
    check(startup.sample(5000, 0, 0, 0, 2000, 5000), "startup deadline");
    auto build = std::filesystem::path(argv[1]).parent_path();
    auto evidence = build / ("test-evidence-" + std::to_string(GetCurrentProcessId()));
    auto staging = evidence / "F4SE" / "Plugins";
    auto output = evidence / "reports";
    std::filesystem::create_directories(staging);
    std::filesystem::create_directories(output);
    auto dll = staging / "FreezeLogger.dll";
    std::filesystem::copy_file(argv[1], dll);
    std::filesystem::copy_file(argv[2], staging / "FreezeLoggerWatch.exe");
    std::ofstream ini(staging / "FreezeLogger.ini");
    ini << "[FreezeLogger]\nTimeoutSeconds=2\nLoadingTimeoutSeconds=5\nStartupTimeoutSeconds=5\n"
           "EarlyWarningSeconds=1\nProfileMilliseconds=500\nFrameMonitoring=0\n"
           "WriteMinidump=1\nFullMemoryDump=1\nMaxReports=10\nReportDirectory=" << output.string() << '\n';
    ini.close();
    // The watcher reads an optional layout override file from its own folder.
    // This row targets a runtime the fixture never reports, so it exercises the
    // read path without changing which layout the adapter resolves.
    { std::ofstream layout(staging / "FreezeLogger.layout.ini");
      layout << "[Layout.010C0000]\nPlayerRva=0x1111\nUiRva=0x2222\n"
                "PlayerCellOffset=0xB8\nCellFormIdOffset=0x14\nCellTypeOffset=0x1A\n"
                "UiStackOffset=0x190\nUiTableOffset=0x1B0\nUiTableEntriesOffset=0x20\n"
                "MenuStride=0x28\nMenuNameOffset=0x08\nMenuInstanceOffset=0x10\nMenuNextOffset=0x20\n"; }
    HMODULE plugin = LoadLibraryW(dll.c_str());
    check(plugin != nullptr, "load actual DLL");
    auto* version = reinterpret_cast<fs::Version*>(GetProcAddress(plugin, "F4SEPlugin_Version"));
    check(version && version->dataVersion == 1 && version->addressIndependence == 1 && version->structureIndependence == 1,
          "modern F4SE version-independent export");
    auto legacy = reinterpret_cast<bool(*)(const fs::Host*, fs::Info*)>(GetProcAddress(plugin, "F4SEPlugin_Query"));
    auto load = reinterpret_cast<bool(*)(const fs::Host*)>(GetProcAddress(plugin, "F4SEPlugin_Load"));
    check(legacy && load, "legacy and modern entry points");
    fs::Host host{0x000600E0, 0x010A0A30, 0, 0, query, handle};
    fs::Info info{};
    for (auto runtime : {0x010A0A30u, 0x010A3D80u, 0x010BF000u, 0x01020480u, 0xFFFFFFFFu}) {
        host.runtimeVersion = runtime;
        check(legacy(&host, &info), "no runtime whitelist in legacy query");
    }
    host.isEditor = 1;
    check(!legacy(&host, &info) && !load(&host), "editor rejected");
    host.isEditor = 0; host.runtimeVersion = 0x010A0A30;
    auto originalQuery = host.query;
    host.query = nullptr;
    check(!load(&host), "missing host API rejected");
    host.query = originalQuery;
    taskAPI.version = 2;
    if (fallback) taskAPI.version = 0;
    check(load(&host), "actual DLL load using F4SE ABI fixture");
    check(!load(&host), "duplicate DLL initialization rejected without second helper");
    check(listener != nullptr, "messaging callback registered");
    check(movieCallback && movieCallback(reinterpret_cast<void*>(0x1234), nullptr), "Scaleform movie creation observed without game layouts");
    auto recordEvent = reinterpret_cast<fs::RecordEvent>(GetProcAddress(plugin, "FreezeLogger_RecordEvent"));
    auto framePulse = reinterpret_cast<fs::FramePulse>(GetProcAddress(plugin, "FreezeLogger_FramePulse"));
    check(recordEvent && framePulse, "native telemetry exports");
    SetLastError(0x123456);
    check(framePulse(), "native frame provider publishes progress without game offsets");
    check(GetLastError() == 0x123456, "frame callback preserves LastError");
    check(!recordEvent(nullptr), "invalid event pointer rejected");
    fs::EventData adapter; strcpy_s(adapter.source, "fixture-provider");
    adapter.kind = fs::EventKind::Cell; adapter.form = 0xfe123456;
    strcpy_s(adapter.name, "fixture-cell"); strcpy_s(adapter.plugin, "Fixture.esl");
    check(recordEvent(&adapter), "optional adapter event accepted");
    check(GetLastError() == 0x123456, "event callback preserves LastError");
    adapter.version = 999; check(!recordEvent(&adapter), "unknown event version rejected");
    adapter.version = 1; memset(adapter.source, 'x', sizeof(adapter.source));
    check(!recordEvent(&adapter), "unterminated event field rejected");
    if (fallback) {
        HWND window = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"STATIC", L"FreezeSentry fixture",
            WS_POPUP | WS_VISIBLE, -32000, -32000, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        check(window != nullptr, "fixture window created outside visible desktop");
        auto deadline = GetTickCount64() + 1500;
        while (GetTickCount64() < deadline) {
            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
            Sleep(10);
        }
        check(reports(output).empty(), "healthy oldest-F4SE window");
        Sleep(7200); // Deliberately stop this fixture's Windows message pump.
        auto logs = reports(output);
        check(logs.size() == 1 && contents(logs[0]).find("window-not-responding") != std::string::npos,
              "oldest F4SE without tasks still captures a real unresponsive window");
        check(contents(logs[0]).find("collection complete") != std::string::npos, "fallback snapshot completed");
        DestroyWindow(window);
        std::cout << "PASS: oldest-F4SE window fallback and external snapshot\nEvidence: " << evidence.string() << '\n';
        ExitProcess(0);
    }
    ticks(1800);
    check(reports(output).empty(), "healthy host produces no incident");
    FILETIME creation{}, exit{}, kernel{}, user{};
    GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user);
    const auto session = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(fs::filetime(creation));
    auto sessionLog = output / (L"session-" + session + L".log");
    check(contents(sessionLog).find("layout_overrides=1") != std::string::npos,
          "watcher reads the layout override file");
    std::string save = "FixtureSave.fos";
    fs::Message preLoad{"F4SE", 2, static_cast<std::uint32_t>(save.size()), save.data()}; listener(&preLoad);
    fs::Message begin{"F4SE", 2, 0, nullptr}; listener(&begin);
    ticks(3000, false, false);
    check(reports(output).empty(), "loading timeout honored");
    ticks(1800);
    fs::Message end{"F4SE", 3, 0, nullptr}; listener(&end);
    handledExceptionFixture();
    deadlockFixture();
    std::thread(busyLoop).detach();
    ticks(7200, false, false);
    auto incident = reports(output);
    check(incident.size() == 1, "external watcher catches deliberate host queue stall");
    ticks(2000, false, false);
    check(reports(output).size() == 1, "stall does not flood reports");
    auto text = contents(incident.front());
    spin.store(false);
    check(text.find("both-task-queues-stalled") != std::string::npos, "automatic incident reason");
    check(text.find("collection complete") != std::string::npos, "snapshot collection completed");
    check(text.find("SAMPLE 3/3") != std::string::npos && text.find("REPEATED_OBSERVATIONS") != std::string::npos,
          "three independent snapshots and CPU deltas");
    check(text.find("early_stack=1") != std::string::npos && text.find("early#") != std::string::npos &&
          text.find("PREINCIDENT_HISTORY") != std::string::npos, "early stacks preserved before final incident");
    check(text.find("FixtureSave.fos") != std::string::npos && text.find("Fixture.esl") != std::string::npos &&
          text.find("fixture-cell") != std::string::npos, "load filename and source-labelled optional cell/mod context preserved");
    check(text.find("movie-created") != std::string::npos && text.find("frame_source=2") != std::string::npos,
          "movie creation and native frame provider propagated to external monitor");
    check(text.find("disk_sha256=") != std::string::npos && text.find("instruction_bytes_at_RIP=") != std::string::npos &&
          text.find("WAIT_CHAINS") != std::string::npos && text.find("R15=0x") != std::string::npos,
          "repair-oriented module identity, instruction bytes, wait chain and register evidence");
    check(text.find("deadlock_cycle=1") != std::string::npos && text.find("FreezeLogger-test-") != std::string::npos,
          "WCT identifies the known real mutex deadlock and its object names");
    check(text.find("busyLoop") != std::string::npos, "local symbols identify known busy loop");
    check(text.find("test.cpp:") != std::string::npos, "local PDB provides source file and line for repair");
    check(text.find("observed_count=517") != std::string::npos &&
          text.find("retained_window_count=512") != std::string::npos &&
          text.find("ring_capacity=512") != std::string::npos,
          "native exception journal retains a bounded 512-entry window after wrap");
    check(text.find("code=0xc0000005") != std::string::npos &&
          text.find("p1=0x1239") != std::string::npos && text.find("p1=0x1438") != std::string::npos &&
          text.find("p1=0x1234") == std::string::npos,
          "native fault breadcrumbs preserve the wrapped chronological range without suppressing handled exceptions");
    check(text.find("NORMAL_TASK_CALLBACK") != std::string::npos && text.find("THREADS") != std::string::npos,
          "actual target thread contexts and attribution");
    check(text.find("FreezeLoggerTests.exe+") != std::string::npos, "module-relative stack data");
    auto dump = incident.front(); dump.replace_extension(".dmp");
    check(std::filesystem::exists(dump) && std::filesystem::file_size(dump) > 4096, "minidump written externally");
    std::string validation;
    check(fs::validateDump(dump, validation), "real emitted dump passes structural validation");
    auto damaged = dump; damaged.replace_extension(".damaged");
    std::filesystem::copy_file(dump, damaged);
    std::filesystem::resize_file(damaged, 100);
    check(!fs::validateDump(damaged, validation), "truncated real dump rejected");
    std::filesystem::copy_file(dump, damaged, std::filesystem::copy_options::overwrite_existing);
    {
        std::fstream edit(damaged, std::ios::in | std::ios::out | std::ios::binary);
        MINIDUMP_HEADER header{}; edit.read(reinterpret_cast<char*>(&header), sizeof(header));
        header.NumberOfStreams = UINT_MAX; edit.seekp(0); edit.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }
    check(!fs::validateDump(damaged, validation), "overflow stream count rejected");
    std::filesystem::copy_file(dump, damaged, std::filesystem::copy_options::overwrite_existing);
    {
        std::fstream edit(damaged, std::ios::in | std::ios::out | std::ios::binary);
        MINIDUMP_HEADER header{}; edit.read(reinterpret_cast<char*>(&header), sizeof(header));
        for (ULONG i = 0; i < header.NumberOfStreams; ++i) {
            edit.seekg(header.StreamDirectoryRva + i * sizeof(MINIDUMP_DIRECTORY));
            MINIDUMP_DIRECTORY directory{}; edit.read(reinterpret_cast<char*>(&directory), sizeof(directory));
            if (directory.StreamType == Memory64ListStream) {
                ULONG64 huge = ULLONG_MAX;
                edit.seekp(directory.Location.Rva + 16 + offsetof(MINIDUMP_MEMORY_DESCRIPTOR64, DataSize));
                edit.write(reinterpret_cast<const char*>(&huge), sizeof(huge)); break;
            }
        }
    }
    check(!fs::validateDump(damaged, validation), "overflow memory payload rejected");
    auto partial = dump; partial += ".partial";
    check(!std::filesystem::exists(partial), "successful dump atomically committed from partial");
    {
        fs::Handle file(CreateFileW(dump.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        fs::Handle map(CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr));
        void* data = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
        check(data != nullptr, "map emitted dump");
        PMINIDUMP_DIRECTORY directory = nullptr; PVOID stream = nullptr; ULONG size = 0;
        check(MiniDumpReadDumpStream(data, ThreadListStream, &directory, &stream, &size) != FALSE && size > 4,
              "minidump contains parseable thread stream");
        check(MiniDumpReadDumpStream(data, Memory64ListStream, &directory, &stream, &size) != FALSE && size > 16,
              "opt-in full dump includes committed memory for object analysis");
        UnmapViewOfFile(data);
    }
    { std::lock_guard lock(mutex); check(queue[0].size() <= 1 && queue[1].size() <= 1, "bounded pending probes"); }
    ticks(1800);
    ticks(7200, true, false);
    ticks(1500, true, false);
    incident = reports(output);
    check(incident.size() == 2, "recovery followed by independent UI stall detected");
    bool uiReason = false;
    for (const auto& path : incident) uiReason |= contents(path).find("ui-task-queue-stalled") != std::string::npos;
    check(uiReason, "queue-specific incident reason");
    auto other = output / "user-notes.log"; { std::ofstream out(other); out << "preserve"; }
    fs::retain(output, 1, 1);
    check(reports(output).size() == 1 && std::filesystem::exists(other), "retention preserves unrelated files");
    auto latest = reports(output).front(); latest.replace_extension(".dmp");
    check(std::filesystem::exists(latest), "retention preserves paired newest dump");
    ticks(500);
    std::cout << "PASS: real DLL, F4SE ABI fixture, external process snapshots/minidumps, lifecycle, two queue stalls, recovery, bounds and retention\n"
              << "Evidence: " << evidence.string() << '\n';
    // The real DLL pins itself and owns a process-lifetime pump. Do not unload it.
    ExitProcess(0);
}
