// Hang suppression for background (likely Alt-Tab) pauses.
//
// A queue stall while the game window is backgrounded but responsive is usually
// an OS pause, not a freeze. An unresponsive background window still reports:
// the user may have tabbed away from an already frozen game.
// Pure logic, no OS calls; the caller supplies foreground/responsiveness facts.
#pragma once
#include <cstdint>

namespace fs {
using Tick = int64_t; // Milliseconds on the same clock as Shared pulse fields.
struct HangSuppressionState {
    Tick suppressedPulse = 0; // Callback pulse when background suppression started.
    Tick foregroundResumeTick = 0; // First foreground tick after suppression started.
};
enum class HangSuppressionReason : unsigned char { None = 0, NotForeground, ForegroundGrace, ForegroundResponsive };
struct HangSuppressionResult {
    bool suppress = false;
    HangSuppressionReason reason = HangSuppressionReason::None;
};
inline void ResetHangSuppression(HangSuppressionState& state) { state = HangSuppressionState{}; }
// pulseTick is the newest main/UI callback tick; the caller passes the older of the two.
inline HangSuppressionResult EvaluateHangSuppression(HangSuppressionState& state, bool enabled, bool isForeground,
                                                     bool isLoading, bool isWindowResponsive, Tick nowTick,
                                                     Tick pulseTick, unsigned graceSec) {
    if (!enabled) return {};
    if (!isForeground) {
        if (!isWindowResponsive) return {}; // Frozen behind Alt-Tab is still a real freeze.
        state.suppressedPulse = pulseTick;
        state.foregroundResumeTick = 0;
        return {true, HangSuppressionReason::NotForeground};
    }
    if (!state.suppressedPulse) return {};
    if (pulseTick > state.suppressedPulse) {
        ResetHangSuppression(state); // Queues advanced since suppression started; genuine activity.
        return {};
    }
    if (!graceSec) return {};
    if (!state.foregroundResumeTick) state.foregroundResumeTick = nowTick;
    Tick elapsed = nowTick > state.foregroundResumeTick ? nowTick - state.foregroundResumeTick : 0;
    if (elapsed < static_cast<Tick>(graceSec) * 1000) return {true, HangSuppressionReason::ForegroundGrace};
    if (!isLoading && isWindowResponsive) return {true, HangSuppressionReason::ForegroundResponsive};
    return {};
}
inline const char* suppressionReasonName(HangSuppressionReason reason) {
    switch (reason) {
    case HangSuppressionReason::NotForeground: return "background-responsive";
    case HangSuppressionReason::ForegroundGrace: return "foreground-grace";
    case HangSuppressionReason::ForegroundResponsive: return "foreground-responsive";
    default: return "none";
    }
}
} // namespace fs
