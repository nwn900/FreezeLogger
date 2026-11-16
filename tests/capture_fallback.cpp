// Regression test for the low-commit / clone-failure capture fallback: a
// bounded, clearly limited report must still carry thread evidence, must state
// what it omitted, and must never claim a minidump it did not write.
#include "../src/shared.hpp"
#include <iostream>
#include <fstream>
#include <string>

namespace {
void fail(const char* message) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
std::string contents(const std::filesystem::path& path) {
    std::ifstream in(path); return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
bool lowCommit() { return false; }
}

int wmain() {
    auto folder = std::filesystem::current_path() / ("capture-fallback-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(folder);
    fs::setCommitProbeForTest(lowCommit);
    bool complete = fs::capture(GetCurrentProcess(), GetCurrentProcessId(), folder, "fallback-test", nullptr, true, "", true);
    fs::setCommitProbeForTest(nullptr);
    std::filesystem::path log;
    for (const auto& entry : std::filesystem::directory_iterator(folder))
        if (entry.path().extension() == ".log") log = entry.path();
    if (log.empty()) fail("fallback capture wrote no report");
    auto text = contents(log);
    if (text.find("snapshot_clone_deferred_low_commit") == std::string::npos)
        fail("low-commit path was not reported");
    if (text.find("capture_method=pss-thread-only") == std::string::npos &&
        text.find("capture_method=toolhelp") == std::string::npos)
        fail("fallback method was not reported");
    if (text.find("minidump=skipped") == std::string::npos)
        fail("fallback must not claim a minidump");
    if (text.find("thread_count=") == std::string::npos)
        fail("fallback lost thread evidence");
    if (text.find("omitted=") == std::string::npos)
        fail("fallback must state omitted capabilities");
    if (!complete) fail("fallback report should still be complete for its declared scope");
    std::cout << "PASS: low-commit capture fallback produced a limited report with thread evidence\n";
    return 0;
}
