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
inline FrameSelection selectFrameProvider(const FrameSnapshot& native,
                                          const FrameSnapshot& etw,
                                          bool etwAvailable) noexcept {
    if (native.present) return {native, 2};
    if (etwAvailable && etw.present) return {etw, 1};
    return {};
}
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
struct FrameGate {
    StallGate gate;
    bool active = false;
    LONG64 resumeCount = 0;
    bool sample(LONG64 t, LONG64 tick, LONG64 count, bool available, bool foreground, bool loading, DWORD timeout) {
        bool eligible = available && foreground && !loading && count >= 10;
        if (!eligible) { active = false; gate.reported = false; return false; }
        if (!active) { active = true; resumeCount = count; return false; }
        if (count <= resumeCount) return false;
        return gate.sample(t, t, tick, tick, timeout, timeout);
    }
};
class FrameObserver {
    Shared* state;
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread worker;
    std::wstring name;
    std::map<DWORD, DWORD> pending;
    LARGE_INTEGER qpcFrequency{};
    DWORD lastLossPoll = 0;
    alignas(EVENT_TRACE_PROPERTIES) std::array<std::byte, sizeof(EVENT_TRACE_PROPERTIES) + 512> buffer{};
    static void WINAPI receive(EVENT_RECORD* event);
    static ULONG WINAPI buffers(EVENT_TRACE_LOGFILEW* log);
    bool lossCountersClear();
public:
    explicit FrameObserver(Shared* shared) : state(shared) {}
    ~FrameObserver();
    ULONG start();
    void accept(const EVENT_RECORD& event);
    FrameSelection current() const noexcept;
};
}
