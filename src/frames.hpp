#pragma once
#include "shared.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <thread>
#include <array>
#include <map>

namespace fs {
struct FrameSelection {
    FrameSnapshot sample;
    LONG source = 0; // 2=native provider, 1=ETW, 0=unavailable.
    bool nativeExpired = false; // native was seen but is stale; ETW fallback in use.
    bool usable = false;        // the sample meets the gate's observation threshold.
};
class FrameProviderSelector final {
public:
    // A native source that stops publishing must not mask a healthy ETW source
    // forever. After this silence the selector falls back to ETW; native
    // resumes precedence as soon as it publishes again.
    static constexpr LONG64 nativeFreshnessMs = 2000;
    // The gate needs this many observed frames before it can judge silence.
    // A fallback below this threshold is not eligible: handing an armed native
    // gate to it would reset the gate and lose the stall.
    static constexpr LONG64 minimumFrames = 10;

    FrameSelection select(const FrameReadResult& native, const FrameReadResult& etw,
                          bool etwAvailable, LONG64 decisionTick) noexcept {
        if (native.status == FrameReadStatus::Coherent && native.sample.present) {
            native_ = {native.sample, 2};
            hasNative_ = true;
            // Freshness is the publisher's own receive time, not the moment this
            // selector happened to read the cached record.
            nativeSeen_ = native.sample.receivedTick;
        }
        if (etw.status == FrameReadStatus::Coherent && etw.sample.present) {
            etw_ = {etw.sample, 1};
            hasEtw_ = true;
        }
        const bool nativeFresh = hasNative_ && decisionTick - nativeSeen_ <= nativeFreshnessMs;
        // "ETW has ever published" is not the same as "ETW is eligible as a
        // fallback": a 1-9 frame ETW sample cannot satisfy the gate.
        const bool etwUsable = etwAvailable && hasEtw_ && etw_.sample.count >= minimumFrames;
        auto qualified = [](FrameSelection selection) {
            selection.usable = selection.sample.count >= minimumFrames;
            return selection;
        };
        if (native.status == FrameReadStatus::Busy) {
            if (nativeFresh) return qualified(native_);
            // A busy first read is unknown, not absent: do not fall back before
            // a native source has ever published.
            if (hasNative_) {
                if (etwUsable) { FrameSelection result = etw_; result.nativeExpired = true; return qualified(result); }
                // ETW is unavailable or not eligible. Keep the last native
                // sample as stalled evidence instead of discarding the only
                // qualified frame signal.
                FrameSelection result = native_; result.nativeExpired = true; return qualified(result);
            }
            return {};
        }
        if (nativeFresh) return qualified(native_);
        if (hasNative_) {
            if (etwUsable) { FrameSelection result = etw_; result.nativeExpired = true; return qualified(result); }
            FrameSelection result = native_; result.nativeExpired = true; return qualified(result);
        }
        if (!etwAvailable) return {};
        if (etw.status == FrameReadStatus::Busy) return hasEtw_ ? qualified(etw_) : FrameSelection{};
        if (hasEtw_) return qualified(etw_);
        return {};
    }
private:
    FrameSelection native_, etw_;
    bool hasNative_ = false, hasEtw_ = false;
    LONG64 nativeSeen_ = 0;
};
inline bool frameTickFromQpc(std::uint64_t eventQpc, std::uint64_t receiveQpc,
                             std::uint64_t frequency, LONG64 receiveTick,
                             LONG64& eventTick) noexcept {
    if (!eventQpc || !frequency || receiveQpc < eventQpc || receiveTick < 0) return false;
    const std::uint64_t elapsed = receiveQpc - eventQpc;
    const std::uint64_t wholeSeconds = elapsed / frequency;
    const std::uint64_t remainder = elapsed % frequency;
    if (wholeSeconds > (std::numeric_limits<std::uint64_t>::max)() / 1000ULL ||
        remainder > (std::numeric_limits<std::uint64_t>::max)() / 1000ULL) return false;
    const std::uint64_t ageMs = wholeSeconds * 1000ULL + (remainder * 1000ULL) / frequency;
    eventTick = ageMs >= static_cast<std::uint64_t>(receiveTick)
        ? 0 : receiveTick - static_cast<LONG64>(ageMs);
    return true;
}
class FrameGate final {
public:
    bool sample(LONG64 now, const FrameSelection& selection, bool foreground, bool loading, DWORD timeout) {
        const auto& sample = selection.sample;
        bool eligible = selection.source && sample.present &&
                        sample.count >= FrameProviderSelector::minimumFrames && foreground && !loading;
        if (!eligible) { reset(); return false; }
        if (sample.tick > now) return false;
        const bool sourceChanged = active_ && source_ != selection.source;
        if (!active_ || (sample.count < lastCount_ && !sourceChanged)) {
            // First eligibility or a same-source counter restart: pre-eligibility
            // buffered ticks are not evidence of post-eligibility progress.
            active_ = true;
            source_ = selection.source;
            eligibleSince_ = lastProgress_ = now;
            lastCount_ = sample.count;
            gate_.rearm();
            return false;
        }
        if (sourceChanged) {
            // Handover: preserve the most recent trustworthy progress across
            // providers. A fallback whose newest buffered tick is old must not
            // backdate progress that was already observed, and an old-source
            // selection must not clear an incident's recovery requirement.
            source_ = selection.source;
            const LONG64 observed = sample.tick > 0 && sample.tick <= now ? sample.tick : now;
            if (observed > lastProgress_) lastProgress_ = observed;
            lastCount_ = sample.count;
            return false;
        }
        if (sample.count > lastCount_) {
            lastCount_ = sample.count;
            if (sample.tick > eligibleSince_ && sample.tick <= now && sample.tick > lastProgress_)
                lastProgress_ = sample.tick;
        }
        return gate_.sample(now, eligibleSince_, lastProgress_, lastProgress_, timeout, timeout);
    }
    void reset() noexcept {
        active_ = false;
        source_ = 0;
        gate_.rearm();
    }
private:
    StallGate gate_;
    bool active_ = false;
    LONG source_ = 0;
    LONG64 eligibleSince_ = 0, lastProgress_ = 0, lastCount_ = 0;
};
class FrameObserver {
    Shared* state;
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread worker;
    std::wstring name;
    std::map<DWORD, DWORD> pending;
    LARGE_INTEGER qpcFrequency{};
    DWORD lastLossPoll = 0;
    FrameProviderSelector selector;
    alignas(EVENT_TRACE_PROPERTIES) std::array<std::byte, sizeof(EVENT_TRACE_PROPERTIES) + 512> buffer{};
    static void WINAPI receive(EVENT_RECORD* event);
    static ULONG WINAPI buffers(EVENT_TRACE_LOGFILEW* log);
    bool lossCountersClear();
public:
    explicit FrameObserver(Shared* shared) : state(shared) {}
    ~FrameObserver();
    ULONG start();
    void accept(const EVENT_RECORD& event);
    FrameSelection current() noexcept;
};
}
