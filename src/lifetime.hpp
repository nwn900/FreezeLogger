#pragma once
#include "shared.hpp"
#include <thread>

namespace fs {
inline LONG64 awakeNow() noexcept {
    ULONGLONG intervals = 0;
    if (!QueryUnbiasedInterruptTime(&intervals)) return now();
    return static_cast<LONG64>(intervals / 10000ULL);
}

class AwakeDeadline final {
public:
    void budget(LONG64 awakeTick, DWORD milliseconds) noexcept {
        LONG64 duration = static_cast<LONG64>(milliseconds);
        InterlockedExchange64(&deadline_, awakeTick > (std::numeric_limits<LONG64>::max)() - duration
            ? (std::numeric_limits<LONG64>::max)() : awakeTick + duration);
    }
    bool expired(LONG64 awakeTick) const noexcept {
        auto deadline = InterlockedCompareExchange64(const_cast<volatile LONG64*>(&deadline_), 0, 0);
        return awakeTick >= deadline;
    }
private:
    alignas(8) volatile LONG64 deadline_ = 0;
};

// Terminates only this collector if local collection/cleanup stops making progress.
// The original target handle remains valid even if Windows later reuses its PID.
class Lifetime {
    Handle target, stop;
    AwakeDeadline deadline;
    const std::wstring traceName;
    std::thread worker;
public:
    explicit Lifetime(HANDLE process, DWORD idleMs = 30000, std::wstring ownedTraceName = {});
    ~Lifetime();
    void budget(DWORD milliseconds) { deadline.budget(awakeNow(), milliseconds); }
    Lifetime(const Lifetime&) = delete;
    Lifetime& operator=(const Lifetime&) = delete;
};
}
