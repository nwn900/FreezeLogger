#include "lifetime.hpp"
#include <stdexcept>
#include <evntrace.h>
#include <array>

namespace fs {
Lifetime::Lifetime(HANDLE process, DWORD idleMs, std::wstring ownedTraceName)
    : stop(CreateEventW(nullptr, TRUE, FALSE, nullptr)), traceName(std::move(ownedTraceName)) {
    if (!stop.value || !DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &target.value,
                                        SYNCHRONIZE, FALSE, 0)) throw std::runtime_error("lifetime guard unavailable");
    budget(idleMs);
    worker = std::thread([this] {
        HANDLE handles[]{stop.value, target.value};
        LONG64 exitedAt = 0;
        for (;;) {
            DWORD wait = WaitForMultipleObjects(exitedAt ? 1 : 2, handles, FALSE, 200);
            if (wait == WAIT_OBJECT_0) return;
            if (wait == WAIT_OBJECT_0 + 1 && !exitedAt) exitedAt = now();
            if (wait == WAIT_FAILED || now() >= read(deadline) || (exitedAt && now() - exitedAt >= 5000)) {
                // Bypass DLL shutdown callbacks that might themselves be blocked.
                // Incomplete evidence remains on disk; no target process is altered.
                auto code = exitedAt ? 125u : 124u;
                if (!traceName.empty()) {
                    // ETW sessions survive controller death. Attempt to stop only
                    // our exact PID/creation-time session, with an independent kill
                    // deadline even if ControlTrace itself stalls.
                    try {
                        std::thread([code] { Sleep(1000); TerminateProcess(GetCurrentProcess(), code); }).detach();
                        alignas(EVENT_TRACE_PROPERTIES) std::array<BYTE, sizeof(EVENT_TRACE_PROPERTIES) + 1024> data{};
                        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(data.data());
                        properties->Wnode.BufferSize = static_cast<ULONG>(data.size());
                        ControlTraceW(0, traceName.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
                    } catch (...) {}
                }
                TerminateProcess(GetCurrentProcess(), code);
                return;
            }
        }
    });
}
Lifetime::~Lifetime() { SetEvent(stop); if (worker.joinable()) worker.join(); }
}
