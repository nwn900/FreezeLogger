// Regression test for capture capability truthfulness: a Toolhelp inventory is
// not a PSS snapshot, a text report is not a dump, and completion is only
// claimed after the final text is flushed and verified on disk.
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
int failAtCreation() { return 1; }
int failAtFinalWrite() { return 2; }
struct Capture { std::string text; fs::CaptureResult result; bool complete; };
Capture runCapture(const std::filesystem::path& folder, const char* reason) {
    std::filesystem::create_directories(folder);
    fs::CaptureResult result;
    bool complete = fs::capture(GetCurrentProcess(), GetCurrentProcessId(), folder, reason, nullptr, true, "", true, &result);
    std::filesystem::path log;
    for (const auto& entry : std::filesystem::directory_iterator(folder))
        if (entry.path().extension() == ".log") log = entry.path();
    return {log.empty() ? std::string{} : contents(log), result, complete};
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
    if (threadOnly.text.find("capture_method=pss-thread-only") == std::string::npos)
        fail("thread-only PSS method was not reported");
    if (threadOnly.text.find("minidump=skipped") == std::string::npos)
        fail("thread-only capture must not claim a minidump");
    if (threadOnly.text.find("thread_count=") == std::string::npos)
        fail("thread-only capture lost thread evidence");
    if (!threadOnly.result.textComplete) fail("thread-only capture did not complete its text report");
    if (!threadOnly.result.anyThreadEvidence) fail("thread-only capture lost thread evidence flag");
    if (!threadOnly.result.pssSnapshotCaptured) fail("thread-only capture must report a PSS snapshot");
    if (!threadOnly.result.threadContextsAvailable) fail("thread-only capture must report thread contexts");
    if (threadOnly.result.vaCloneCaptured) fail("thread-only capture must not claim a VA clone");
    if (!threadOnly.result.dumpRequested) fail("thread-only capture did not record the dump request");
    if (threadOnly.result.dumpValidated) fail("thread-only capture must not claim a validated dump");

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
    if (toolhelp.result.pssSnapshotCaptured) fail("Toolhelp inventory must not claim a PSS snapshot");
    if (toolhelp.result.vaCloneCaptured) fail("Toolhelp inventory must not claim a VA clone");
    if (toolhelp.result.dumpValidated) fail("Toolhelp capture must not claim a validated dump");
    if (toolhelp.text.find("toolhelp_error=") == std::string::npos) {
        if (!toolhelp.result.anyThreadEvidence) fail("Toolhelp inventory reported no thread evidence");
        if (!toolhelp.result.textComplete) fail("Toolhelp inventory did not complete its text report");
    }

    auto normal = runCapture(root / "normal", "normal-test");
    if (!normal.result.textComplete) fail("normal capture did not complete its text report");
    if (!normal.result.pssSnapshotCaptured) fail("normal capture must report a PSS snapshot");
    if (!normal.result.vaCloneCaptured) fail("normal capture must report a VA clone");
    if (!normal.result.threadContextsAvailable) fail("normal capture must report thread contexts");
    if (!normal.result.dumpValidated) fail("normal capture must validate its dump");

    fs::setCaptureLogFailureForTest(failAtCreation);
    auto creation = runCapture(root / "log-creation", "log-creation-test");
    fs::setCaptureLogFailureForTest(nullptr);
    if (creation.complete || creation.result.textComplete) fail("a failed log creation must not claim completion");
    if (!creation.text.empty()) fail("a failed log creation must not leave a report");
    if (!creation.result.dumpRequested) fail("the dump request must be recorded before an early failure");
    if (creation.result.dumpValidated) fail("an early failure cannot validate a dump");

    fs::setCaptureLogFailureForTest(failAtFinalWrite);
    auto finalWrite = runCapture(root / "log-final", "log-final-test");
    fs::setCaptureLogFailureForTest(nullptr);
    if (finalWrite.complete || finalWrite.result.textComplete)
        fail("a failed final write must not claim completion");
    if (finalWrite.text.empty()) fail("a failed final write must preserve partial evidence");
    if (finalWrite.text.find("collection complete") != std::string::npos)
        fail("a failed final write must not contain the completion marker");
    if (!finalWrite.result.dumpValidated)
        fail("a validated dump must survive a failed text write");
    bool dumpFound = false;
    for (const auto& entry : std::filesystem::directory_iterator(root / "log-final"))
        if (entry.path().extension() == ".dmp") dumpFound = true;
    if (!dumpFound) fail("the validated dump file is missing");

    std::cout << "PASS: capture capabilities and text persistence are reported truthfully\n";
    return 0;
}
