// Unit tests for background-hang suppression (src/suppress.hpp).
#include "../src/suppress.hpp"
#include <windows.h>
#include <iostream>

namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
} // namespace

int wmain() {
    fs::HangSuppressionState state;
    check(!fs::EvaluateHangSuppression(state, false, false, false, true, 10000, 1000, 10).suppress,
          "disabled suppression never fires");
    auto background = fs::EvaluateHangSuppression(state, true, false, false, true, 10000, 1000, 10);
    check(background.suppress && background.reason == fs::HangSuppressionReason::NotForeground,
          "responsive background stall suppressed");
    check(state.suppressedPulse == 1000, "suppression remembers pulse");
    fs::HangSuppressionState loud;
    check(!fs::EvaluateHangSuppression(loud, true, false, false, false, 10000, 1000, 10).suppress,
          "unresponsive background window still reports");
    fs::HangSuppressionState fresh;
    check(!fs::EvaluateHangSuppression(fresh, true, true, false, true, 20000, 1000, 10).suppress,
          "foreground stall without prior suppression reports");
    check(!fs::EvaluateHangSuppression(state, true, true, false, true, 20000, 2000, 10).suppress &&
          state.suppressedPulse == 0,
          "queue progress since suppression resets state");
    fs::EvaluateHangSuppression(state, true, false, false, true, 30000, 3000, 10);
    auto grace = fs::EvaluateHangSuppression(state, true, true, false, true, 32000, 3000, 10);
    check(grace.suppress && grace.reason == fs::HangSuppressionReason::ForegroundGrace, "foreground grace suppresses");
    auto settled = fs::EvaluateHangSuppression(state, true, true, false, true, 45000, 3000, 10);
    check(settled.suppress && settled.reason == fs::HangSuppressionReason::ForegroundResponsive,
          "responsive foreground stall after grace stays suppressed");
    check(!fs::EvaluateHangSuppression(state, true, true, true, true, 45000, 3000, 10).suppress,
          "loading after grace reports");
    check(!fs::EvaluateHangSuppression(state, true, true, false, false, 45000, 3000, 10).suppress,
          "unresponsive foreground after grace reports");
    fs::HangSuppressionState noGrace;
    fs::EvaluateHangSuppression(noGrace, true, false, false, true, 50000, 5000, 0);
    check(!fs::EvaluateHangSuppression(noGrace, true, true, false, true, 51000, 5000, 0).suppress,
          "zero grace disables foreground suppression");
    std::cout << "PASS: background, grace and responsive hang suppression\n";
    return 0;
}
