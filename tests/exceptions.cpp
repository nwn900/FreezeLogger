#include "../src/exceptions.hpp"
#include <windows.h>
#include <array>
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

    // A real unhandled fault in a controlled child process still produces one
    // terminal incident, in both crash-handler registration orders.
    check(runTerminalChild(L"dummy-first"), "terminal child with a pre-registered handler publishes and chains");
    check(runTerminalChild(L"journal-first"), "terminal child with a later handler publishes through the chain");

    std::cout << "PASS: exception ring, provisional/terminal split, coherent throw record and child terminal capture\n";
    return 0;
}
