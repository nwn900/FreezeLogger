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
    bool active = false;
    bool foregroundResumeStarted = false;
    Tick suppressedPulse = 0; // Callback pulse when background suppression started.
    Tick foregroundResumeTick = 0; // First foreground tick after suppression started.
};
enum class HangSuppressionReason : unsigned char { None = 0, NotForeground, ForegroundGrace };
struct HangSuppressionResult {
    bool suppress = false;
    HangSuppressionReason reason = HangSuppressionReason::None;
};
class HangSuppressionPolicy final {
public:
    void reset() noexcept { state_ = {}; }

    // pulseTick is the oldest normal/UI callback tick. A zero startup pulse is valid.
    HangSuppressionResult evaluate(bool enabled, bool isForeground, bool isLoading,
                                  bool isWindowResponsive, Tick nowTick, Tick pulseTick,
                                  unsigned graceSec) noexcept {
        if (!enabled) return {};
        if (!isForeground) {
            if (!isWindowResponsive) return {}; // Frozen behind Alt-Tab is still a real freeze.
            state_.active = true;
            state_.suppressedPulse = pulseTick;
            state_.foregroundResumeStarted = false;
            state_.foregroundResumeTick = 0;
            return {true, HangSuppressionReason::NotForeground};
        }
        if (!state_.active) return {};
        if (pulseTick > state_.suppressedPulse) {
            reset(); // Queues advanced since suppression started; genuine activity.
            return {};
        }
        if (!graceSec) return {};
        if (!state_.foregroundResumeStarted) {
            state_.foregroundResumeStarted = true;
            state_.foregroundResumeTick = nowTick;
        }
        Tick elapsed = nowTick > state_.foregroundResumeTick ? nowTick - state_.foregroundResumeTick : 0;
        if (!isLoading && elapsed < static_cast<Tick>(graceSec) * 1000)
            return {true, HangSuppressionReason::ForegroundGrace};
        // Foreground suppression is deliberately finite. If callback pulses did
        // not advance by the end of grace, report the continuing queue stall.
        return {};
    }
private:
    HangSuppressionState state_;
};
inline const char* suppressionReasonName(HangSuppressionReason reason) {
    switch (reason) {
    case HangSuppressionReason::NotForeground: return "background-responsive";
    case HangSuppressionReason::ForegroundGrace: return "foreground-grace";
    default: return "none";
    }
}
} // namespace fs
