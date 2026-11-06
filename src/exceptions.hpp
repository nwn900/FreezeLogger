#pragma once
#include "shared.hpp"
#include <algorithm>
#include <ostream>
#include <vector>

namespace fs {
struct KeptFault {
    bool present = false;
    DWORD code = 0, thread = 0;
    LONG64 tick = 0;
    DWORD64 parameters[4]{};
    const char* rule = "none";
};

// Owns exception observation and interpretation for this process. The shared
// Fault array stays a plain, versioned cross-process data structure.
class ExceptionJournal final {
public:
    explicit ExceptionJournal(Shared* state = nullptr) noexcept : state_(state) {}
    ~ExceptionJournal() {
        if (handler_) RemoveVectoredExceptionHandler(handler_);
        if (active_ == this) active_ = nullptr;
    }
    ExceptionJournal(const ExceptionJournal&) = delete;
    ExceptionJournal& operator=(const ExceptionJournal&) = delete;
    ExceptionJournal(ExceptionJournal&&) = delete;
    ExceptionJournal& operator=(ExceptionJournal&&) = delete;

    bool install(Shared* state) noexcept {
        if (!state) return false;
        if (handler_) return state_ == state;
        if (active_ && active_ != this) return false;
        state_ = state;
        active_ = this;
        // First requests the head of the VEH chain. A later component can
        // still insert ahead of us. The callback always continues search.
        handler_ = AddVectoredExceptionHandler(1, dispatch);
        if (!handler_) {
            active_ = nullptr;
            state_ = nullptr;
            return false;
        }
        return true;
    }

    std::vector<FaultData> recent() const {
        std::vector<FaultData> faults;
        if (!state_) return faults;
        LONG64 count = read(state_->faultCount);
        LONG64 begin = std::max<LONG64>(0, count - faultCapacity);
        faults.reserve(static_cast<size_t>(count - begin));
        for (LONG64 n = begin; n < count; ++n) {
            auto& slot = state_->faults[static_cast<ULONG>(n) % static_cast<ULONG>(faultCapacity)];
            LONG sequence = read(slot.sequence);
            if (sequence & 1) continue;
            FaultData fault = slot.data;
            MemoryBarrier();
            if (sequence != read(slot.sequence) || fault.ordinal != n + 1) continue;
            faults.push_back(fault);
        }
        return faults;
    }

    void write(std::ostream& log) const {
        if (!state_) return;
        log << "\nRECENT_NATIVE_EXCEPTIONS (first chance; may have been handled; not proof of a crash cause)\n";
        LONG64 count = read(state_->faultCount);
        LONG64 begin = std::max<LONG64>(0, count - faultCapacity);
        log << "observed_count=" << count
            << " retained_window_count=" << count - begin
            << " ring_capacity=" << faultCapacity
            << " dropped_concurrent=" << read(state_->faultsDropped) << '\n';
        const char* names[]{"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
        LONG64 emitted = 0, skipped = 0;
        for (LONG64 n = begin; n < count; ++n) {
            auto& slot = state_->faults[static_cast<ULONG>(n) % static_cast<ULONG>(faultCapacity)];
            LONG sequence = read(slot.sequence);
            if (sequence & 1) { ++skipped; continue; }
            FaultData fault = slot.data;
            MemoryBarrier();
            if (sequence != read(slot.sequence) || fault.ordinal != n + 1) { ++skipped; continue; }
            log << "ordinal=" << fault.ordinal << " tick=" << fault.tick << " filetime=" << fault.fileTime
                << " thread=" << fault.thread << " code=0x" << std::hex << fault.code
                << " IP=0x" << fault.ip << " flags=0x" << fault.flags << std::dec << " parameters=" << fault.parameterCount;
            for (unsigned i = 0; i < std::min<unsigned>(4, fault.parameterCount); ++i)
                log << " p" << i << "=0x" << std::hex << fault.parameters[i] << std::dec;
            log << '\n';
            for (unsigned i = 0; i < 16; ++i) log << names[i] << "=0x" << std::hex << fault.registers[i] << ' ';
            log << std::dec << '\n';
            log << "exception_time_raw_stack bytes=" << fault.stackBytes << '\n';
            for (unsigned i = 0; i < std::min<unsigned>(32, fault.stackBytes / 8); ++i)
                log << "  exception_RSP+0x" << std::hex << i * 8 << "=0x" << fault.stackWords[i] << std::dec << '\n';
            ++emitted;
        }
        log << "emitted_count=" << emitted << " unstable_slots_skipped=" << skipped << '\n';
    }

    KeptFault selected() const {
        KeptFault kept;
        if (!state_) return kept;
        auto faults = recent();
        auto consider = [&](const FaultData& fault, const char* rule) {
            if (!kept.present || fault.tick < kept.tick) {
                kept.present = true;
                kept.code = fault.code;
                kept.thread = fault.thread;
                kept.tick = fault.tick;
                kept.rule = rule;
                for (unsigned i = 0; i < 4; ++i) kept.parameters[i] = fault.parameters[i];
            }
        };
        // Breakpoint/assert candidates outrank C++ throws; otherwise keep the
        // earliest first-chance observation. None proves the eventual cause.
        for (const auto& fault : faults)
            if (fault.code == EXCEPTION_BREAKPOINT) consider(fault, "breakpoint-assert-keeps-priority");
        if (kept.present) return kept;
        for (const auto& fault : faults)
            if (fault.code == 0xE06D7363u) consider(fault, "first-cpp-throw");
        if (kept.present) return kept;
        for (const auto& fault : faults) consider(fault, "earliest-first-chance-fault");
        return kept;
    }

private:
    struct LastErrorGuard {
        DWORD value = GetLastError();
        ~LastErrorGuard() { SetLastError(value); }
    };

    static LONG CALLBACK dispatch(EXCEPTION_POINTERS* exception) noexcept {
        return active_ ? active_->record(exception) : EXCEPTION_CONTINUE_SEARCH;
    }

    LONG record(EXCEPTION_POINTERS* exception) noexcept {
        LastErrorGuard preserve;
        if (!state_ || !exception || !exception->ExceptionRecord || !exception->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;
        const auto& record = *exception->ExceptionRecord;
        DWORD code = record.ExceptionCode;
        if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_BREAKPOINT &&
            code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
            code != EXCEPTION_STACK_OVERFLOW && code != 0xC0000374 && code != 0xE06D7363)
            return EXCEPTION_CONTINUE_SEARCH;
        if (InterlockedCompareExchange(&state_->faultWriting, 1, 0) != 0) {
            InterlockedIncrement(&state_->faultsDropped);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        LONG64 ordinal = read(state_->faultCount) + 1;
        ULONG index = static_cast<ULONG>(ordinal - 1) % static_cast<ULONG>(faultCapacity);
        auto& slot = state_->faults[index];
        InterlockedIncrement(&slot.sequence);
        const auto& context = *exception->ContextRecord;
        slot.data.ordinal = ordinal;
        slot.data.tick = now();
        FILETIME observed{};
        GetSystemTimeAsFileTime(&observed);
        slot.data.fileTime = static_cast<std::uint64_t>(filetime(observed));
        slot.data.code = code;
        slot.data.thread = GetCurrentThreadId();
        slot.data.flags = record.ExceptionFlags;
        slot.data.ip = reinterpret_cast<DWORD64>(record.ExceptionAddress);
        slot.data.parameterCount = record.NumberParameters;
        for (unsigned i = 0; i < 4; ++i)
            slot.data.parameters[i] = i < record.NumberParameters ? record.ExceptionInformation[i] : 0;
        DWORD64 registers[]{context.Rax, context.Rbx, context.Rcx, context.Rdx, context.Rsi, context.Rdi, context.Rbp, context.Rsp,
                            context.R8, context.R9, context.R10, context.R11, context.R12, context.R13, context.R14, context.R15};
        for (unsigned i = 0; i < 16; ++i) slot.data.registers[i] = registers[i];
        SIZE_T bytes = 0;
        ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(context.Rsp), slot.data.stackWords,
                          sizeof(slot.data.stackWords), &bytes);
        slot.data.stackBytes = static_cast<DWORD>(bytes);
        InterlockedIncrement(&slot.sequence);
        InterlockedExchange64(&state_->faultCount, ordinal);
        InterlockedExchange(&state_->faultWriting, 0);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    inline static ExceptionJournal* active_ = nullptr;
    Shared* state_ = nullptr;
    PVOID handler_ = nullptr;
};
}
