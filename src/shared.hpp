#pragma once
#include <windows.h>
#include <filesystem>
#include <ostream>
#include <string>
#include <string_view>
#include "telemetry.hpp"

namespace fs {
inline std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}
inline constexpr LONG magic = 0x46534634;
inline constexpr LONG faultCapacity = 512;
inline constexpr char toolVersion[] = "0.3.1";
struct FaultData {
    LONG64 tick = 0;
    DWORD code = 0, thread = 0, flags = 0, parameterCount = 0;
    DWORD64 ip = 0, parameters[4]{}, registers[16]{};
    DWORD64 stackWords[32]{};
    DWORD stackBytes = 0;
};
struct Fault { volatile LONG sequence = 0; FaultData data; };
struct EventRecord { LONG64 tick = 0, id = 0; DWORD thread = 0; EventData data; };
struct EventSlot { volatile LONG sequence = 0; EventRecord data; };
struct alignas(8) Shared {
    LONG signature = magic, version = 5;
    DWORD pid = 0, runtime = 0, extender = 0;
    DWORD timeoutMs = 15000, loadingMs = 120000, startupMs = 180000, probeMs = 250;
    DWORD maxReports = 10, writeDump = 1, manualKey = VK_PAUSE;
    DWORD suppressBackground = 1, foregroundGraceSec = 10;
    DWORD maxFreezeReports = 10, maxManualReports = 10;
    DWORD taskMonitoring = 1;
    DWORD fullDump = 0;
    DWORD earlyMs = 3000, historyMs = 60000, profileMs = 2000, storageMB = 1024;
    DWORD frameMonitoring = 1;
    DWORD captureMs = 120000, contextMonitoring = 1;
    wchar_t outputDirectory[1024]{};
    alignas(8) volatile LONG64 started = 0, processCreated = 0;
    volatile LONG64 pulse[2]{}, sequence[2]{};
    volatile LONG thread[2]{}, pending[2]{};
    volatile LONG event = -1, phase = 0, ready = 0;
    volatile LONG64 eventTime = 0, monitorPulse = 0;
    volatile LONG faultCount = 0, faultWriting = 0, faultsDropped = 0;
    Fault faults[faultCapacity];
    volatile LONG eventWriting = 0, eventsDropped = 0;
    volatile LONG64 eventCount = 0, frameTick = 0, frameCount = 0;
    volatile LONG frameSource = 0, frameStatus = 0, frameThread = 0;
    EventSlot events[128];
};
inline LONG64 read(volatile LONG64& value) { return InterlockedCompareExchange64(&value, 0, 0); }
inline LONG read(volatile LONG& value) { return InterlockedCompareExchange(&value, 0, 0); }
inline LONG64 now() { return static_cast<LONG64>(GetTickCount64()); }
inline LONG64 filetime(FILETIME t) { return (static_cast<LONG64>(t.dwHighDateTime) << 32) | t.dwLowDateTime; }
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE h = nullptr) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    operator HANDLE() const { return value; }
};
struct StallGate {
    bool reported = false;
    LONG64 previous[2]{};
    bool sample(LONG64 t, LONG64 start, LONG64 main, LONG64 ui, DWORD timeout, DWORD startup) {
        if (reported && main > previous[0] && ui > previous[1] &&
            t - main < timeout && t - ui < timeout) reported = false;
        bool stale = (!main || !ui) ? t - start >= startup :
            t - main >= timeout || t - ui >= timeout;
        if (stale && !reported) { reported = true; previous[0] = main; previous[1] = ui; return true; }
        return false;
    }
    // Re-arm after a suppressed report so recovery and a later genuine stall
    // are still observed. The next stale poll fires again for re-evaluation.
    void rearm() { reported = false; }
};
std::filesystem::path reportRoot(bool vr);
bool capture(HANDLE target, DWORD pid, const std::filesystem::path& folder,
             const std::string& reason, Shared* state, bool dump, const std::string& history = {});
void retain(const std::filesystem::path& folder, unsigned freezeLimit, unsigned manualLimit, unsigned storageMB = 0,
            const std::filesystem::path& protectedFile = {});
std::string eventHistory(Shared* state, LONG64 after = 0);
bool validateDump(const std::filesystem::path& path, std::string& reason);
std::string profile(HANDLE target, bool stacks, Shared* state, bool reset = false);
}
