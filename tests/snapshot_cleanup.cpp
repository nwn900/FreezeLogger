// Regression test for retained PSS VA-clone processes (zombie game children).
// Captures VA-clone snapshots of this test process itself through the public
// fs::profile path and asserts no child process survives each capture.
// Exit 77 requests a ctest skip when this environment cannot snapshot
// (e.g. ERROR_COMMITMENT_LIMIT under memory pressure).
#include "../src/shared.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <string>

namespace {
void fail(const char* message) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
unsigned childProcesses() {
    DWORD self = GetCurrentProcessId();
    unsigned count = 0;
    fs::Handle list(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!list.value || list.value == INVALID_HANDLE_VALUE) fail("process enumeration unavailable");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(list, &entry)) fail("process enumeration failed");
    do {
        if (entry.th32ParentProcessID == self && entry.th32ProcessID != self) ++count;
    } while (Process32NextW(list, &entry));
    return count;
}
} // namespace

int wmain() {
    unsigned before = childProcesses();
    for (unsigned sample = 0; sample < 3; ++sample) {
        std::string report = fs::profile(GetCurrentProcess(), true, nullptr);
        if (report.find("profile_threads=") == std::string::npos) {
            std::cout << "SKIP: self snapshot unavailable in this environment\n" << report << '\n';
            return 77;
        }
        // Grace-period reaping or backstop termination are both acceptable; only
        // a clone surviving everything is a leak.
        if (report.find("STILL_ALIVE") != std::string::npos) fail("a clone survived free, grace and termination");
    }
    Sleep(1000); // Let verified clone terminations settle before counting.
    unsigned after = childProcesses();
    if (after != before) {
        std::cerr << "FAIL: child processes before=" << before << " after=" << after << '\n';
        return 1;
    }
    std::cout << "PASS: 3 self VA-clone snapshots left no surviving child processes\n";
    return 0;
}
