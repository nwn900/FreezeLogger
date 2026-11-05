#pragma once
#include "shared.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <thread>
#include <array>
#include <map>

namespace fs {
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
    alignas(EVENT_TRACE_PROPERTIES) std::array<std::byte, sizeof(EVENT_TRACE_PROPERTIES) + 512> buffer{};
    static void WINAPI receive(EVENT_RECORD* event);
    static ULONG WINAPI buffers(EVENT_TRACE_LOGFILEW* log);
public:
    explicit FrameObserver(Shared* shared) : state(shared) {}
    ~FrameObserver();
    ULONG start();
    void accept(const EVENT_RECORD& event);
};
}
