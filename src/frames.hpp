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
};
class FrameProviderSelector final {
public:
    FrameSelection select(const FrameReadResult& native, const FrameReadResult& etw,
                          bool etwAvailable) noexcept {
        if (native.status == FrameReadStatus::Coherent && native.sample.present) {
            native_ = {native.sample, 2};
            hasNative_ = true;
        }
        if (etw.status == FrameReadStatus::Coherent && etw.sample.present) {
            etw_ = {etw.sample, 1};
            hasEtw_ = true;
        }
        if (native.status == FrameReadStatus::Busy)
            return hasNative_ ? native_ : FrameSelection{};
        if (native.status == FrameReadStatus::Coherent && native.sample.present)
            return native_;
        if (hasNative_) return native_;
        if (!etwAvailable) return {};
        if (etw.status == FrameReadStatus::Busy) return hasEtw_ ? etw_ : FrameSelection{};
        return hasEtw_ ? etw_ : FrameSelection{};
    }
private:
    FrameSelection native_, etw_;
    bool hasNative_ = false, hasEtw_ = false;
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
        bool eligible = selection.source && sample.present && sample.count >= 10 && foreground && !loading;
        if (!eligible) { reset(); return false; }
        if (sample.tick > now) return false;
        if (!active_ || source_ != selection.source || sample.count < lastCount_) {
            active_ = true;
            source_ = selection.source;
            eligibleSince_ = lastProgress_ = now;
            lastCount_ = sample.count;
            gate_.rearm();
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
