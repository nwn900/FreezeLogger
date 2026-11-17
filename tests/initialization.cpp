#include "../src/api.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {
void check(bool ok, const char* message) { if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); } }
bool listen(std::uint32_t, const char*, void (*)(fs::Message*)) { return true; }
fs::Messaging messaging{1, listen};
void* query(std::uint32_t id) { return id == fs::messagingID ? &messaging : nullptr; }
std::uint32_t handle() { return 1; }
}
int wmain(int argc, wchar_t** argv) {
    check(argc == 3, "DLL/helper arguments");
    auto directory = std::filesystem::path(argv[1]).parent_path() / ("init-evidence-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    auto dll = directory / "FreezeLogger.dll"; std::filesystem::copy_file(argv[1], dll);
    HMODULE module = LoadLibraryW(dll.c_str()); check(module != nullptr, "load init fixture DLL");
    auto load = reinterpret_cast<bool(*)(const fs::Host*)>(GetProcAddress(module, "F4SEPlugin_Load"));
    check(load != nullptr, "initialization entry point");
    fs::Host host{0, 0x010A0A30, 0, 0, query, handle};
    DWORD before = 0, after = 0; GetProcessHandleCount(GetCurrentProcess(), &before);
    check(!load(&host), "missing helper fails initialization");
    // First CreateProcess/profile API calls may initialize persistent OS/CRT handles.
    // Repeated failures after that warm-up must not accumulate mapping/process handles.
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (unsigned i = 0; i < 5; ++i) check(!load(&host), "missing helper retry rejected");
    GetProcessHandleCount(GetCurrentProcess(), &after);
    std::cout << "failure_retry_handles before=" << before << " after=" << after << '\n';
    check(after == before, "missing-helper retries release mapping handles");
    std::filesystem::copy_file(argv[2], directory / "FreezeLoggerWatch.exe");
    auto blocked = directory / "not-a-directory"; { std::ofstream file(blocked); file << "fixture"; }
    auto writeIni = [&](const std::filesystem::path& output) {
        std::ofstream ini(directory / "FreezeLogger.ini");
        ini << "[FreezeLogger]\nFrameMonitoring=0\nContextMonitoring=0\nMaxReports=1\nReportDirectory=" << output.string() << '\n';
    };
    writeIni(blocked);
    check(!load(&host), "unwritable report directory fails before readiness handshake");
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (unsigned i = 0; i < 5; ++i) check(!load(&host), "failed handshake can retry");
    GetProcessHandleCount(GetCurrentProcess(), &after);
    std::cout << "handshake_retry_handles before=" << before << " after=" << after << '\n';
    check(after == before, "failed-handshake retries release handles");
    const auto reportDirectory = directory / "reports";
    writeIni(reportDirectory);
    check(load(&host), "corrected initialization can retry after pre-registration failures");
    check(!load(&host), "registered plugin cannot start another monitor");
    FILETIME creation{}, exit{}, kernel{}, user{};
    GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user);
    const auto created = (static_cast<long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    auto preflight = reportDirectory / (L"preflight-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                        std::to_wstring(created) + L".json");
    auto deadline = GetTickCount64() + 5000;
    while (!std::filesystem::exists(preflight) && GetTickCount64() < deadline) Sleep(50);
    std::ifstream receipt(preflight);
    std::string contents{std::istreambuf_iterator<char>(receipt), std::istreambuf_iterator<char>()};
    check(contents.find("\"max_reports_legacy\": 1") != std::string::npos &&
          contents.find("\"max_freeze_reports\": 1") != std::string::npos &&
          contents.find("\"max_manual_reports\": 1") != std::string::npos,
          "legacy MaxReports sets both category limits when overrides are absent");
    std::cout << "PASS: absent helper, unwritable directory, resource cleanup and corrected retry\n";
    ExitProcess(0); // The successfully registered plugin is pinned until this fixture exits.
}
