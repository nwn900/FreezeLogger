#include "../src/exceptions.hpp"
#include <windows.h>
#include <iostream>
#include <sstream>

namespace {
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
}

int wmain() {
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
    std::cout << "PASS: exception ring logical ordinals reject overwritten records\n";
    return 0;
}
