#pragma once
#include "shared.hpp"
#include <thread>

namespace fs {
// Terminates only this collector if local collection/cleanup stops making progress.
// The original target handle remains valid even if Windows later reuses its PID.
class Lifetime {
    Handle target, stop;
    alignas(8) volatile LONG64 deadline = 0;
    const std::wstring traceName;
    std::thread worker;
public:
    explicit Lifetime(HANDLE process, DWORD idleMs = 30000, std::wstring ownedTraceName = {});
    ~Lifetime();
    void budget(DWORD milliseconds) { InterlockedExchange64(&deadline, now() + milliseconds); }
    Lifetime(const Lifetime&) = delete;
    Lifetime& operator=(const Lifetime&) = delete;
};
}
