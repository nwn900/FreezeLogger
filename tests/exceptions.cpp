#include "../src/exceptions.hpp"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <thread>

namespace {
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
void handledAccessViolations(int count) {
    for (int i = 0; i < count; ++i) {
        ULONG_PTR parameters[]{0, static_cast<ULONG_PTR>(i)};
        __try { RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 2, parameters); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}
void handledCppThrow() {
    __try { RaiseException(0xE06D7363u, 0, 0, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
}

int wmain() {
    {
        fs::Shared shared{};
        shared.faultCount = 2;
        auto& overwritten = shared.faults[0];
        overwritten.sequence = 2;
        overwritten.data.ordinal = 513; // Slot zero was reused after the reader captured count=2.
        overwritten.data.tick = 10;
        overwritten.data.code = EXCEPTION_ACCESS_VIOLATION;
        auto& current = shared.faults[1];
        current.sequence = 2;
        current.data.ordinal = 2;
        current.data.tick = 20;
        current.data.code = EXCEPTION_ILLEGAL_INSTRUCTION;

        fs::ExceptionJournal journal(&shared);
        std::ostringstream output;
        journal.write(output);
        check(output.str().find("ordinal=513") == std::string::npos,
              "overwritten exception outside captured sequence window is skipped");
        check(output.str().find("unstable_slots_skipped=1") != std::string::npos,
              "overwritten exception increments skipped count");
        auto selected = journal.selected();
        check(selected.present && selected.code == EXCEPTION_ILLEGAL_INSTRUCTION && selected.tick == 20,
              "fault selection accepts only the captured logical ordinal");
    }

    // A handled first-chance fault is a provisional breadcrumb, never a terminal
    // crash: it must not consume the one-shot live-capture slot.
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for provisional test");
        handledAccessViolations(3);
        check(fs::read(shared.crashSequence) == 0,
              "handled access violations do not consume the terminal capture slot");
        check(fs::read(shared.provisionalCount) >= 1,
              "handled access violations leave provisional breadcrumbs");
        check(shared.provisionalCode == EXCEPTION_ACCESS_VIOLATION,
              "provisional breadcrumb records the observed code");
        check(fs::read(shared.faultCount) == 3,
              "handled access violations remain in the exception ring");
    }

    // The unhandled filter is the terminal classifier: it publishes once, and a
    // later distinct terminal code cannot overwrite the first incident.
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for terminal test");
        EXCEPTION_RECORD record{};
        record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        record.ExceptionAddress = reinterpret_cast<void*>(0x1234);
        CONTEXT context{};
        EXCEPTION_POINTERS pointers{&record, &context};
        fs::ExceptionJournal::unhandled(&pointers);
        check(fs::read(shared.crashSequence) == 2 && shared.crashCode == EXCEPTION_ACCESS_VIOLATION,
              "unhandled filter publishes the terminal crash");
        EXCEPTION_RECORD second{};
        second.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        second.ExceptionAddress = reinterpret_cast<void*>(0x5678);
        EXCEPTION_POINTERS secondPointers{&second, &context};
        fs::ExceptionJournal::unhandled(&secondPointers);
        check(shared.crashCode == EXCEPTION_ACCESS_VIOLATION,
              "terminal capture slot is one-shot");
    }

    // A handled throw followed by an abort on the same thread is one coherent
    // observation; the same sequence across threads must not be combined.
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for same-thread abort test");
        handledCppThrow();
        fs::ExceptionJournal::abortSignal(SIGABRT);
        check(fs::read(shared.crashSequence) == 2 && shared.crashCode == 0xE06D7363u,
              "same-thread handled throw plus abort publishes one terminal record");
    }
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for cross-thread abort test");
        std::thread thrower(handledCppThrow);
        thrower.join();
        fs::ExceptionJournal::abortSignal(SIGABRT);
        check(fs::read(shared.crashSequence) == 0,
              "a throw on another thread cannot be combined with this thread's abort");
    }

    std::cout << "PASS: exception ring, provisional/terminal split and coherent throw record\n";
    return 0;
}
