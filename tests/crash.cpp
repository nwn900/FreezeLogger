#include "../src/crash.hpp"
#include <iostream>

namespace {
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
}

int wmain() {
    check(fs::isFatalExceptionCode(EXCEPTION_ACCESS_VIOLATION), "access violation is a fatal capture");
    check(fs::isFatalExceptionCode(0xC0000374u), "heap corruption is a fatal capture");
    check(!fs::isFatalExceptionCode(0xE06D7363u), "a C++ throw is not fatal at first chance");
    check(!fs::isFatalExceptionCode(EXCEPTION_BREAKPOINT), "a breakpoint is not fatal at first chance");
    check(fs::isIgnoredUnhandledCode(EXCEPTION_SINGLE_STEP), "single step stays out of the unhandled crash record");
    check(!fs::isIgnoredUnhandledCode(0xE06D7363u), "an unhandled C++ exception can be recorded");

    fs::LoadingStats empty;
    check(empty.thresholdMs(120000) == 120000, "no loading samples keep the configured timeout");
    fs::LoadingStats fast;
    fast.addSeconds(30); fast.addSeconds(30); fast.addSeconds(30);
    check(fast.thresholdMs(120000) == 120000, "a fast load does not lower the configured timeout");
    fs::LoadingStats heavy;
    for (int i = 0; i < 10; ++i) heavy.addSeconds(600);
    check(heavy.thresholdMs(120000) == 900000, "heavy loads raise the hang threshold to p90 plus half");

    std::cout << "PASS: fatal exception classification and adaptive loading threshold\n";
    return 0;
}
