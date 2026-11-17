#pragma once
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include "shared.hpp"

namespace fs {
// Fatal codes match Tullius crash-hook mode 1: record them at first chance.
// Handled C++ throws, breakpoints, and debug strings stay out of that path.
inline bool isBenignExceptionCode(DWORD code) noexcept {
    switch (code) {
    case 0xE06D7363u: // C++ exception
    case 0x406D1388u: // legacy thread name
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP:
    case 0x40010006u: // OutputDebugStringA
    case 0x4001000Au: // OutputDebugStringW
        return true;
    default:
        return false;
    }
}
inline bool isFatalExceptionCode(DWORD code) noexcept {
    if (isBenignExceptionCode(code)) return false;
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_INVALID_DISPOSITION:
    case 0xC0000374u: // STATUS_HEAP_CORRUPTION
    case 0xC0000409u: // STATUS_STACK_BUFFER_OVERRUN
        return true;
    default:
        return false;
    }
}
// Codes the first-chance journal records: every terminal-classifiable code plus
// the diagnostic events that are useful before a terminal fault (C++ throws and
// breakpoints). Noisy benign events (single-step, debug strings) stay out.
inline bool isJournalExceptionCode(DWORD code) noexcept {
    if (isFatalExceptionCode(code)) return true;
    switch (code) {
    case 0xE06D7363u: // C++ exception
    case EXCEPTION_BREAKPOINT:
        return true;
    default:
        return false;
    }
}
// Map a capture result to the terminal capture state. "Incomplete" requires
// actual durable evidence; a requested dump alone is not evidence.
inline LONG captureStateFromResult(bool textComplete, bool dumpValidated, bool anyThreadEvidence) noexcept {
    if (dumpValidated) return textComplete ? 4 : 5; // 5 = dump-only
    if (textComplete) return 3;
    if (anyThreadEvidence) return 2;
    return -1;
}
// Exit classification from observed evidence. "Captured" is reserved for a
// completed text report or a validated dump; an observed-but-unfinished capture
// is never labelled captured. Existing evidence is described even when the exit
// code could not be queried.
inline const char* classifyExit(bool exitCodeKnown, DWORD exitCode, LONG crashSequence,
                                LONG captureState, bool userClose) noexcept {
    if (captureState == 5) return "fatal-exception-captured-dump-only";
    if (captureState == 4) return "fatal-exception-captured-with-dump";
    if (captureState == 3) return "fatal-exception-captured-text-only";
    if (captureState == 2) return "fatal-exception-capture-incomplete";
    if (captureState == -1) return "fatal-exception-capture-failed";
    if (!exitCodeKnown) return "unknown_exit_status";
    if ((crashSequence & ~1L) && !(crashSequence & 1L)) return "fatal-exception-observed-not-captured";
    if (userClose && exitCode == 0) return "user-close";
    if (exitCode) return "nonzero_exit_unclassified";
    return "zero_exit";
}
// Codes that reach the unhandled filter but are still not a crash record.
inline bool isIgnoredUnhandledCode(DWORD code) noexcept {
    switch (code) {
    case 0x406D1388u:
    case EXCEPTION_SINGLE_STEP:
    case 0x40010006u:
    case 0x4001000Au:
        return true;
    default:
        return false;
    }
}

// Session loading durations. Threshold is p90 + max(30s, p90/2), never below
// the configured loading timeout and never above one hour.
class LoadingStats {
public:
    void addSeconds(std::uint32_t seconds) noexcept {
        if (!seconds || seconds > 3600) return;
        if (count_ < samples_.size()) samples_[count_++] = seconds;
        else {
            for (std::size_t i = 1; i < samples_.size(); ++i) samples_[i - 1] = samples_[i];
            samples_.back() = seconds;
        }
    }
    std::uint32_t thresholdMs(std::uint32_t configuredMs) const {
        if (!count_) return configuredMs;
        std::array<std::uint32_t, 10> sorted{};
        for (std::size_t i = 0; i < count_; ++i) sorted[i] = samples_[i];
        std::sort(sorted.begin(), sorted.begin() + static_cast<std::ptrdiff_t>(count_));
        const double index = static_cast<double>(count_ - 1) * 0.90;
        const auto rank = static_cast<std::size_t>(index + 0.5);
        const std::uint32_t p90 = sorted[std::min(rank, count_ - 1)];
        const std::uint32_t extra = std::max<std::uint32_t>(30, p90 / 2);
        std::uint32_t seconds = p90 + extra;
        const std::uint32_t configuredSec = std::max<std::uint32_t>(1, configuredMs / 1000);
        if (seconds < configuredSec) seconds = configuredSec;
        if (seconds > 3600) seconds = 3600;
        return seconds * 1000;
    }
private:
    std::array<std::uint32_t, 10> samples_{};
    std::size_t count_ = 0;
};
}
