#pragma once
#include <windows.h>
#include <atomic>
#include <filesystem>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>
#include <limits>
#include <stdexcept>
#include <system_error>
#include "crash_identity.hpp"
#include "telemetry.hpp"

namespace fs {
inline std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw std::length_error("path is too long for UTF-8 conversion");
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "UTF-8 conversion failed");
    std::string result(size, '\0');
    int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    if (written != size) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "UTF-8 conversion failed");
    return result;
}
inline std::string diagnosticUtf8(std::wstring_view value) {
    try { return utf8(value); }
    catch (...) { return "<text-encoding-error>"; }
}
inline std::string diagnosticPath(const std::filesystem::path& value) {
    try {
        auto text = utf8(value.wstring());
        return text;
    } catch (...) { return "<path-encoding-error>"; }
}
inline std::string jsonEscape(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string escaped;
    escaped.reserve(value.size());
    for (unsigned char c : value) {
        switch (c) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (c < 0x20) {
                escaped += "\\u00";
                escaped += hex[c >> 4];
                escaped += hex[c & 0x0f];
            } else escaped += static_cast<char>(c);
        }
    }
    return escaped;
}
inline constexpr LONG magic = 0x46534634;
inline constexpr LONG faultCapacity = 512;
inline constexpr char toolVersion[] = "0.3.6";
struct FaultData {
    LONG64 ordinal = 0, tick = 0;
    std::uint64_t fileTime = 0;
    DWORD code = 0, thread = 0, flags = 0, parameterCount = 0;
    DWORD64 ip = 0, parameters[4]{}, registers[16]{};
    DWORD64 stackWords[32]{};
    DWORD stackBytes = 0;
};
struct Fault { volatile LONG sequence = 0; FaultData data; };
struct EventRecord { LONG64 tick = 0, id = 0; DWORD thread = 0; EventData data; };
struct EventSlot { volatile LONG sequence = 0; EventRecord data; };
struct FrameSnapshot {
    LONG64 tick = 0, receivedTick = 0, count = 0;
    DWORD thread = 0;
    bool present = false;
};
enum class FrameReadStatus : unsigned char { NeverPublished, Coherent, Busy };
struct FrameReadResult {
    FrameSnapshot sample;
    FrameReadStatus status = FrameReadStatus::NeverPublished;
};
// One writer-owned frame source. Keeping ETW and native publication in separate
// records prevents a delayed callback from replacing a newer authoritative source.
class FrameSignal final {
public:
    bool publish(LONG64 tick, LONG64 receivedTick, DWORD thread) noexcept {
        if (InterlockedCompareExchange(&writer_, 1, 0) != 0) {
            InterlockedIncrement(&dropped_);
            return false;
        }
        LONG64 next = InterlockedCompareExchange64(&count_, 0, 0) + 1;
        InterlockedIncrement(&sequence_);
        InterlockedExchange64(&tick_, tick);
        InterlockedExchange64(&receivedTick_, receivedTick);
        InterlockedExchange(&thread_, static_cast<LONG>(thread));
        InterlockedExchange64(&count_, next);
        MemoryBarrier();
        InterlockedIncrement(&sequence_);
        InterlockedExchange(&writer_, 0);
        return true;
    }
    FrameReadResult snapshot() const noexcept {
        for (unsigned attempt = 0; attempt < 4; ++attempt) {
            LONG before = InterlockedCompareExchange(const_cast<volatile LONG*>(&sequence_), 0, 0);
            if (!before) return {};
            if (before & 1) continue;
            FrameSnapshot result;
            result.tick = InterlockedCompareExchange64(const_cast<volatile LONG64*>(&tick_), 0, 0);
            result.receivedTick = InterlockedCompareExchange64(const_cast<volatile LONG64*>(&receivedTick_), 0, 0);
            result.thread = static_cast<DWORD>(InterlockedCompareExchange(const_cast<volatile LONG*>(&thread_), 0, 0));
            result.count = InterlockedCompareExchange64(const_cast<volatile LONG64*>(&count_), 0, 0);
            MemoryBarrier();
            LONG after = InterlockedCompareExchange(const_cast<volatile LONG*>(&sequence_), 0, 0);
            if (before == after && !(after & 1)) {
                result.present = result.count != 0;
                return {result, FrameReadStatus::Coherent};
            }
        }
        return {{}, FrameReadStatus::Busy};
    }
private:
    alignas(8) volatile LONG sequence_ = 0;
    volatile LONG writer_ = 0, thread_ = 0, dropped_ = 0;
    alignas(8) volatile LONG64 tick_ = 0, receivedTick_ = 0, count_ = 0;
};
struct alignas(8) Shared {
    LONG signature = magic, version = 10;
    DWORD pid = 0, runtime = 0, extender = 0;
    DWORD timeoutMs = 15000, loadingMs = 120000, startupMs = 180000, probeMs = 250;
    DWORD maxReports = 10, writeDump = 0, manualKey = VK_PAUSE;
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
    alignas(8) volatile LONG64 faultCount = 0;
    volatile LONG faultWriting = 0, faultsDropped = 0;
    Fault faults[faultCapacity];
    volatile LONG eventWriting = 0, eventsDropped = 0;
    volatile LONG64 eventCount = 0, frameTick = 0, frameCount = 0;
    volatile LONG frameSource = 0, frameStatus = 0, frameThread = 0, frameSourceExpired = 0, frameSourceUsable = 0;
    FrameSignal nativeFrames, etwFrames;
    EventSlot events[128];
    // One live crash incident. Sequence 0 = none, 1 = writing, 2 = published.
    volatile LONG crashSequence = 0, crashAck = 0, userClose = 0;
    DWORD crashCapture = 1, crashCode = 0, crashThread = 0;
    DWORD64 crashAddress = 0;
    ULONG_PTR crashEvent = 0;
    // Terminal crash capture state: 0 = none, 1 = observed, 2 = capture
    // attempted, 3 = text report complete, 4 = dump validated, -1 = failed.
    // "Captured" is reserved for a completed report or validated dump.
    volatile LONG crashCaptureState = 0;
    // Provisional first-chance observations: fatal-looking codes that SEH may
    // still handle. They never consume the terminal capture slot.
    volatile LONG provisionalWriting = 0, provisionalCount = 0;
    volatile LONG64 provisionalGeneration = 0, provisionalTick = 0;
    DWORD provisionalCode = 0, provisionalThread = 0;
    DWORD64 provisionalAddress = 0;
};
inline LONG64 read(volatile LONG64& value) { return InterlockedCompareExchange64(&value, 0, 0); }
inline LONG read(volatile LONG& value) { return InterlockedCompareExchange(&value, 0, 0); }
inline LONG64 now() { return static_cast<LONG64>(GetTickCount64()); }
// ReadProcessMemory accounting for the overhead budget. The context reader and
// the capture collector are counted separately so a log field cannot be read as
// "all process reads" when it only covers one instrumented path.
struct RpmCounter {
    std::atomic<unsigned long long> calls{0}, failures{0}, bytes{0};
    void record(unsigned long long count) {
        calls.fetch_add(1, std::memory_order_relaxed);
        bytes.fetch_add(count, std::memory_order_relaxed);
    }
    void fail() {
        calls.fetch_add(1, std::memory_order_relaxed);
        failures.fetch_add(1, std::memory_order_relaxed);
    }
    void reset() { calls = 0; failures = 0; bytes = 0; }
};
inline RpmCounter& contextRpm() { static RpmCounter value; return value; }
inline RpmCounter& captureRpm() { static RpmCounter value; return value; }
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
// Test-only injection points for the capture availability checks.
void setCommitProbeForTest(bool (*probe)());
void setPssProbeForTest(bool (*probe)());
void setCaptureLogFailureForTest(int (*probe)());
// What a capture actually produced. Capabilities are independent: a Toolhelp
// thread inventory is not a PSS snapshot, and a text report is not a dump.
struct CaptureResult {
    bool textComplete = false;
    bool anyThreadEvidence = false;
    bool pssSnapshotCaptured = false;
    bool threadContextsAvailable = false;
    bool vaCloneCaptured = false;
    bool dumpRequested = false;
    bool dumpValidated = false;
};
bool capture(HANDLE target, DWORD pid, const std::filesystem::path& folder,
             const std::string& reason, Shared* state, bool dump, const std::string& history = {},
             bool quick = false, CaptureResult* result = nullptr);
void retain(const std::filesystem::path& folder, unsigned freezeLimit, unsigned manualLimit, unsigned storageMB = 0,
            const std::filesystem::path& protectedFile = {});
std::string eventHistory(Shared* state, LONG64 after = 0);
bool validateDump(const std::filesystem::path& path, std::string& reason);
std::string profile(HANDLE target, bool stacks, Shared* state, bool reset = false);
std::string externalCrashEvidence(const std::filesystem::path& gameImage, Shared* state,
                                  const std::vector<CrashModuleIdentity>& modules);
}
