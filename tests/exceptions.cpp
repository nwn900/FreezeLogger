#include "../src/exceptions.hpp"
#include <windows.h>
#include <array>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
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
void handledCoverageFaults() {
    for (DWORD code : {EXCEPTION_IN_PAGE_ERROR, EXCEPTION_FLT_DIVIDE_BY_ZERO,
                       EXCEPTION_INT_OVERFLOW, EXCEPTION_PRIV_INSTRUCTION}) {
        __try { RaiseException(code, 0, 0, nullptr); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// Child-process terminal fixture: a second, well-behaved crash handler is
// registered either before or after the journal, and both orders must still
// publish exactly one terminal incident while chaining to the other handler.
LPTOP_LEVEL_EXCEPTION_FILTER previousDummy = nullptr;
std::wstring markerPath;
LONG WINAPI dummyFilter(EXCEPTION_POINTERS* exception) {
    HANDLE marker = CreateFileW(markerPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (marker != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(marker, "called", 6, &written, nullptr);
        CloseHandle(marker);
    }
    return previousDummy ? previousDummy(exception) : EXCEPTION_CONTINUE_SEARCH;
}

int terminalChild(const wchar_t* mappingName, const wchar_t* marker, const wchar_t* order) {
    markerPath = marker;
    fs::Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName));
    if (!mapping.value) return 2;
    auto* shared = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!shared) return 3;
    fs::ExceptionJournal journal(shared);
    if (std::wstring(order) == L"dummy-first") {
        SetUnhandledExceptionFilter(dummyFilter);
        if (!journal.install(shared)) return 4;
    } else {
        if (!journal.install(shared)) return 4;
        previousDummy = SetUnhandledExceptionFilter(dummyFilter);
    }
    RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr); // unhandled: terminal
    return 5; // not reached
}

void noopAbort(int) {}
std::wstring abortMarkerPath;
void customAbort(int) {
    HANDLE marker = CreateFileW(abortMarkerPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (marker != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(marker, "called", 6, &written, nullptr);
        CloseHandle(marker);
    }
}

int abortChild(const wchar_t* mappingName, const wchar_t* mode, const wchar_t* marker) {
    abortMarkerPath = marker;
    fs::Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName));
    if (!mapping.value) return 2;
    auto* shared = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!shared) return 3;
    std::wstring disposition(mode);
    if (disposition == L"ignore") std::signal(SIGABRT, SIG_IGN);
    else if (disposition == L"custom") std::signal(SIGABRT, customAbort);
    fs::ExceptionJournal journal(shared);
    if (!journal.install(shared)) return 4;
    if (disposition == L"throw-abort") {
        handledCppThrow();
        std::abort();
    }
    if (disposition == L"abort") std::abort();
    std::raise(SIGABRT);
    return 0; // reached only for an ignored or custom disposition
}

bool runAbortChild(const wchar_t* mode, DWORD expectedExit, bool expectCrash) {
    auto name = L"Local\\FSF4-abort-" + std::to_wstring(GetCurrentProcessId()) + L"-" + mode;
    auto marker = std::filesystem::current_path() / (std::wstring(L"abort-marker-") + mode + L".txt");
    std::error_code ignored; std::filesystem::remove(marker, ignored);
    fs::Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(fs::Shared), name.c_str()));
    if (!mapping.value) return false;
    auto* shared = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!shared) return false;
    new (shared) fs::Shared;
    std::array<wchar_t, 32768> exe{};
    DWORD length = GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size()));
    if (!length || length >= exe.size()) return false;
    std::wstring command = L"\"" + std::wstring(exe.data(), length) + L"\" --abort-child \"" + name +
        L"\" " + mode + L" \"" + marker.wstring() + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    bool started = CreateProcessW(exe.data(), command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &process) != FALSE;
    if (!started) return false;
    WaitForSingleObject(process.hProcess, 15000);
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    bool crash = fs::read(shared->crashSequence) == 2;
    bool markerWritten = std::filesystem::exists(marker);
    UnmapViewOfFile(shared);
    if (exitCode != expectedExit || crash != expectCrash) return false;
    if (std::wstring(mode) == L"custom" && !markerWritten) return false;
    return true;
}

std::atomic<int> hookInside{0}, hookMax{0};
void throwHook() {
    int now = hookInside.fetch_add(1) + 1;
    int previous = hookMax.load();
    while (now > previous && !hookMax.compare_exchange_weak(previous, now)) {}
    Sleep(1);
    hookInside.fetch_sub(1);
}

bool runTerminalChild(const wchar_t* order) {
    auto name = L"Local\\FSF4-terminal-" + std::to_wstring(GetCurrentProcessId()) + L"-" + order;
    auto marker = std::filesystem::current_path() / (std::wstring(L"terminal-marker-") + order + L".txt");
    std::error_code ignored; std::filesystem::remove(marker, ignored);
    fs::Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(fs::Shared), name.c_str()));
    if (!mapping.value) return false;
    auto* shared = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!shared) return false;
    new (shared) fs::Shared;
    std::array<wchar_t, 32768> exe{};
    DWORD length = GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size()));
    if (!length || length >= exe.size()) return false;
    std::wstring command = L"\"" + std::wstring(exe.data(), length) + L"\" --terminal-child \"" + name +
        L"\" \"" + marker.wstring() + L"\" " + order;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    bool started = CreateProcessW(exe.data(), command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &process) != FALSE;
    if (!started) return false;
    WaitForSingleObject(process.hProcess, 15000);
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    bool published = fs::read(shared->crashSequence) == 2 && shared->crashCode == EXCEPTION_ACCESS_VIOLATION;
    bool chained = std::filesystem::exists(marker);
    UnmapViewOfFile(shared);
    return exitCode == EXCEPTION_ACCESS_VIOLATION && published && chained;
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 5 && std::wstring(argv[1]) == L"--terminal-child")
        return terminalChild(argv[2], argv[3], argv[4]);
    if (argc == 5 && std::wstring(argv[1]) == L"--abort-child")
        return abortChild(argv[2], argv[3], argv[4]);
    // Direct abortSignal tests must not terminate the test process: install a
    // no-op handler before the first journal captures the disposition.
    std::signal(SIGABRT, noopAbort);

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

    // The first-chance journal covers every terminal-classifiable code, not a
    // hand-picked subset, and handled faults never consume the terminal slot.
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for coverage test");
        handledCoverageFaults();
        check(fs::read(shared.faultCount) == 4, "journal records every terminal-classifiable code");
        check(fs::read(shared.crashSequence) == 0, "handled coverage faults do not consume the terminal slot");
    }

    // Exit classification must match the evidence, never an optimistic label.
    check(std::string(fs::classifyExit(true, 0xC0000005, 2, 4, false)) == "fatal-exception-captured-with-dump",
          "validated dump is labelled captured-with-dump");
    check(std::string(fs::classifyExit(true, 0xC0000005, 2, 3, false)) == "fatal-exception-captured-text-only",
          "text-only capture is labelled text-only");
    check(std::string(fs::classifyExit(true, 0xC0000005, 2, 2, false)) == "fatal-exception-capture-incomplete",
          "an attempted but unfinished capture is not labelled captured");
    check(std::string(fs::classifyExit(true, 0xC0000005, 2, -1, false)) == "fatal-exception-capture-failed",
          "a failed capture is labelled failed");
    check(std::string(fs::classifyExit(true, 0xC0000005, 2, 0, false)) == "fatal-exception-observed-not-captured",
          "an observed terminal fault without a capture is labelled not-captured");
    check(std::string(fs::classifyExit(true, 0, 0, 0, true)) == "user-close", "user close is classified");
    check(std::string(fs::classifyExit(true, 1, 0, 0, false)) == "nonzero_exit_unclassified",
          "nonzero exit without evidence is unclassified");
    check(std::string(fs::classifyExit(false, 0, 0, 0, false)) == "unknown_exit_status",
          "unknown exit status is explicit");

    // Reinstallation must not chain the unhandled filter to itself.
    {
        fs::Shared shared{};
        {
            fs::ExceptionJournal first(&shared);
            check(first.install(&shared), "first journal installs");
        }
        fs::ExceptionJournal second(&shared);
        check(second.install(&shared), "second journal installs after the first is destroyed");
        EXCEPTION_RECORD record{};
        record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        record.ExceptionAddress = reinterpret_cast<void*>(0x1234);
        CONTEXT context{};
        EXCEPTION_POINTERS pointers{&record, &context};
        fs::ExceptionJournal::unhandled(&pointers);
        check(fs::read(shared.crashSequence) == 2,
              "reinstalled journal publishes one terminal record without recursion");
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

    // Concurrent writers: the throw record is single-writer. The test hook
    // widens the publication window, so at most one writer may be inside it and
    // an abort on another thread must never combine fields from two throws.
    {
        fs::Shared shared{};
        fs::ExceptionJournal journal(&shared);
        check(journal.install(&shared), "journal installs for concurrency test");
        hookInside = 0; hookMax = 0;
        fs::cppThrowTestHook = throwHook;
        std::thread aborter([&] {
            for (int i = 0; i < 200; ++i) { fs::ExceptionJournal::abortSignal(SIGABRT); Sleep(1); }
        });
        std::vector<std::thread> throwers;
        for (int i = 0; i < 4; ++i) throwers.emplace_back(handledCppThrow);
        for (auto& thread : throwers) thread.join();
        aborter.join();
        fs::cppThrowTestHook = nullptr;
        check(hookMax.load() == 1, "throw-record publication is single-writer under contention");
        check(fs::read(shared.crashSequence) == 0,
              "a concurrent throw on another thread cannot be combined with this thread's abort");
    }

    // SIGABRT semantics: the observer must not consume the default fatal path.
    check(runAbortChild(L"default", 3, false), "raise(SIGABRT) with SIG_DFL still terminates");
    check(runAbortChild(L"ignore", 0, false), "an ignored SIGABRT stays ignored");
    check(runAbortChild(L"custom", 0, false), "a custom SIGABRT handler is called and may return");
    check(runAbortChild(L"abort", 3, false), "abort() still terminates");
    check(runAbortChild(L"throw-abort", 3, true), "abort after a handled throw publishes and terminates");

    // A real unhandled fault in a controlled child process still produces one
    // terminal incident, in both crash-handler registration orders.
    check(runTerminalChild(L"dummy-first"), "terminal child with a pre-registered handler publishes and chains");
    check(runTerminalChild(L"journal-first"), "terminal child with a later handler publishes through the chain");

    std::cout << "PASS: exception ring, provisional/terminal split, coherent throw record and child terminal capture\n";
    return 0;
}
