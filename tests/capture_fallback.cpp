// Regression test for the low-commit and forced-Toolhelp capture fallbacks: a
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
bool noPss() { return false; }
struct Capture { std::string text; fs::CaptureResult result; };
Capture runCapture(const std::filesystem::path& folder, const char* reason) {
    std::filesystem::create_directories(folder);
    fs::CaptureResult result;
    bool complete = fs::capture(GetCurrentProcess(), GetCurrentProcessId(), folder, reason, nullptr, true, "", true, &result);
    std::filesystem::path log;
    for (const auto& entry : std::filesystem::directory_iterator(folder))
        if (entry.path().extension() == ".log") log = entry.path();
    if (log.empty()) fail("capture wrote no report");
    auto text = contents(log);
    if (!complete && text.find("toolhelp_error=") == std::string::npos)
        fail("capture reported incomplete without a toolhelp error");
    return {text, result};
}
}

int wmain() {
    auto root = std::filesystem::current_path() / ("capture-fallback-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(root);

    fs::setCommitProbeForTest(lowCommit);
    auto threadOnly = runCapture(root / "low-commit", "fallback-test");
    fs::setCommitProbeForTest(nullptr);
    if (threadOnly.text.find("snapshot_clone_deferred_low_commit") == std::string::npos)
        fail("low-commit path was not reported");
    if (threadOnly.text.find("capture_method=pss-thread-only") == std::string::npos &&
        threadOnly.text.find("capture_method=toolhelp") == std::string::npos)
        fail("fallback method was not reported");
    if (threadOnly.text.find("minidump=skipped") == std::string::npos)
        fail("fallback must not claim a minidump");
    if (threadOnly.text.find("thread_count=") == std::string::npos)
        fail("fallback lost thread evidence");
    if (threadOnly.text.find("omitted=") == std::string::npos)
        fail("fallback must state omitted capabilities");
    if (!threadOnly.result.textComplete) fail("low-commit capture did not complete its text report");
    if (!threadOnly.result.snapshotCaptured) fail("low-commit capture lost its snapshot evidence");
    if (!threadOnly.result.dumpRequested) fail("low-commit capture did not record the dump request");
    if (threadOnly.result.dumpValidated) fail("low-commit capture must not claim a validated dump");

    fs::setPssProbeForTest(noPss);
    auto toolhelp = runCapture(root / "toolhelp", "toolhelp-test");
    fs::setPssProbeForTest(nullptr);
    if (toolhelp.text.find("capture_method=toolhelp-thread-inventory") == std::string::npos)
        fail("forced Toolhelp path was not reported");
    if (toolhelp.text.find("minidump=skipped (PSS unavailable") == std::string::npos)
        fail("Toolhelp path must record the skipped minidump");
    if (toolhelp.text.find("omitted=contexts,stacks,modules,symbols,minidump") == std::string::npos)
        fail("Toolhelp path must state its omitted capabilities");
    if (toolhelp.text.find("thread_count=") == std::string::npos)
        fail("Toolhelp path lost thread evidence");
    if (toolhelp.result.dumpValidated) fail("Toolhelp capture must not claim a validated dump");

    std::cout << "PASS: low-commit and forced Toolhelp capture fallbacks produced limited reports\n";
    return 0;
}
