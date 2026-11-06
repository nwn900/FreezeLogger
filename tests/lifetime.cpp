#include "../src/lifetime.hpp"
#include <array>
#include <iostream>

namespace {
void check(bool ok, const char* message) { if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); } }
}
int wmain(int argc, wchar_t** argv) {
    fs::AwakeDeadline awakeDeadline;
    awakeDeadline.budget(5000, 30000);
    check(!awakeDeadline.expired(5000), "awake-time deadline starts unexpired");
    // An hour of wall-clock sleep does not advance the value supplied to this
    // deadline. It expires only after the configured awake interval elapses.
    check(!awakeDeadline.expired(6000), "sleep-inclusive wall time cannot expire collector budget");
    check(awakeDeadline.expired(35000), "collector budget expires after awake duration");
    if (argc == 2 && std::wstring(argv[1]) == L"--deadline") {
        fs::Lifetime guard(GetCurrentProcess(), 700);
        Sleep(INFINITE); return 1;
    }
    if (argc == 3 && std::wstring(argv[1]) == L"--parent-exit") {
        fs::Handle target(OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(wcstoul(argv[2], nullptr, 10))));
        check(target.value != nullptr, "open owned fixture target");
        fs::Lifetime guard(target, 30000); Sleep(INFINITE); return 1;
    }
    if (argc == 2 && std::wstring(argv[1]) == L"--short-target") { Sleep(1500); return 0; }
    std::array<wchar_t, 32768> path{}; GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    auto spawn = [&](const std::wstring& arguments, PROCESS_INFORMATION& process) {
        std::wstring command = L"\"" + std::wstring(path.data()) + L"\" " + arguments;
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        check(CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != 0, "launch guard fixture");
        CloseHandle(process.hThread);
    };
    PROCESS_INFORMATION child{};
    spawn(L"--deadline", child); fs::Handle first(child.hProcess);
    check(WaitForSingleObject(first, 5000) == WAIT_OBJECT_0, "blocked operation bounded");
    DWORD exit = 0; GetExitCodeProcess(first, &exit); check(exit == 124, "deadline has distinct exit code");
    spawn(L"--short-target", child); fs::Handle target(child.hProcess); DWORD pid = child.dwProcessId;
    spawn(L"--parent-exit " + std::to_wstring(pid), child); fs::Handle observer(child.hProcess);
    check(WaitForSingleObject(observer, 9000) == WAIT_OBJECT_0, "blocked cleanup bounded after original target exits");
    GetExitCodeProcess(observer, &exit); check(exit == 125, "target-exit cleanup has distinct exit code");
    check(WaitForSingleObject(target, 0) == WAIT_OBJECT_0, "fixture target exited normally");
    {
        fs::Lifetime healthy(GetCurrentProcess(), 3000); Sleep(200); healthy.budget(3000);
    }
    std::cout << "PASS: blocked collector deadline, target-exit cleanup and healthy guard shutdown\n";
}
