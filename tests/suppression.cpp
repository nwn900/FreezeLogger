// Unit tests for the owned background-hang suppression policy.
#include "../src/suppress.hpp"
#include <windows.h>
#include <iostream>

namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
}

int wmain() {
    fs::HangSuppressionPolicy disabled;
    check(!disabled.evaluate(false, false, false, true, 10000, 1000, 10).suppress,
          "disabled suppression never fires");

    fs::HangSuppressionPolicy background;
    auto suppressed = background.evaluate(true, false, false, true, 10000, 1000, 10);
    check(suppressed.suppress && suppressed.reason == fs::HangSuppressionReason::NotForeground,
          "responsive background stall is temporarily suppressed");
    check(!background.evaluate(true, false, false, false, 11000, 1000, 10).suppress,
          "unresponsive background window still reports");

    fs::HangSuppressionPolicy foreground;
    check(!foreground.evaluate(true, true, false, true, 20000, 1000, 10).suppress,
          "foreground stall without prior suppression reports");

    fs::HangSuppressionPolicy progress;
    progress.evaluate(true, false, false, true, 30000, 1000, 10);
    check(!progress.evaluate(true, true, false, true, 32000, 2000, 10).suppress,
          "queue progress since suppression resets state");

    // Zero is a valid startup pulse, whether one callback has not run or both
    // have not run. Explicit active state must still grant foreground grace.
    fs::HangSuppressionPolicy zeroPulse;
    check(zeroPulse.evaluate(true, false, false, true, 40000, 0, 10).suppress,
          "startup stall with a zero pulse is suppressed in background");
    auto firstForeground = zeroPulse.evaluate(true, true, false, true, 40001, 0, 10);
    check(firstForeground.suppress && firstForeground.reason == fs::HangSuppressionReason::ForegroundGrace,
          "zero startup pulse receives foreground grace");
    check(!zeroPulse.evaluate(true, true, false, true, 50001, 0, 10).suppress,
          "responsive window cannot suppress a stalled queue after finite grace");

    fs::HangSuppressionPolicy noGrace;
    noGrace.evaluate(true, false, false, true, 60000, 6000, 0);
    check(!noGrace.evaluate(true, true, false, true, 61000, 6000, 0).suppress,
          "zero grace disables foreground suppression");

    fs::HangSuppressionPolicy loading;
    loading.evaluate(true, false, false, true, 70000, 7000, 10);
    check(!loading.evaluate(true, true, true, true, 71000, 7000, 10).suppress,
          "loading does not extend the foreground grace indefinitely");
    std::cout << "PASS: finite background grace, zero startup pulses and recovery\n";
    return 0;
}
