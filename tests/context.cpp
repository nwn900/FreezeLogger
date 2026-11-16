#include "../src/context.hpp"
#include <psapi.h>
#include <array>
#include <cstring>
#include <iostream>

namespace {
void check(bool ok, const char* message) { if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); } }
template<class T, size_t N> void put(std::array<BYTE, N>& memory, size_t offset, T value) {
    memcpy(memory.data() + offset, &value, sizeof(value));
}
template<class T> ULONG64 pointer(T& value) { return reinterpret_cast<ULONG64>(&value); }
}
int main() {
    // Layout table: exact runtime match, independent player/menu capabilities.
    const auto* modern = fs::resolveLayout(0x010A0A30);
    check(modern && fs::hasPlayer(*modern) && fs::hasMenus(*modern), "1.10.163 layout carries both halves");
    const auto* next = fs::resolveLayout(0x010B0DD0);
    check(next && fs::hasPlayer(*next) && fs::hasMenus(*next), "1.11.221 layout carries both halves");
    check(!fs::resolveLayout(0xFFFFFFFF) && !fs::resolveLayout(0), "unknown runtime resolves to no layout");
    check(modern->playerRva != next->playerRva, "player global is per-runtime, not shared");
    // Table hygiene: unique runtimes, every row usable, offsets inside a plausible object.
    for (std::size_t i = 0; i < std::size(fs::layouts); ++i) {
        check(fs::layouts[i].runtime != 0, "layout row has a runtime key");
        check(fs::hasPlayer(fs::layouts[i]) || fs::hasMenus(fs::layouts[i]), "layout row carries at least one half");
        for (std::size_t j = i + 1; j < std::size(fs::layouts); ++j)
            check(fs::layouts[i].runtime != fs::layouts[j].runtime, "layout runtimes are unique");
        for (auto offset : {fs::layouts[i].playerCellOffset, fs::layouts[i].cellFormIdOffset,
                            fs::layouts[i].cellTypeOffset, fs::layouts[i].cellNameOffset,
                            fs::layouts[i].cellSourceOffset, fs::layouts[i].uiStackOffset,
                            fs::layouts[i].uiTableOffset})
            check(offset < 0x1000, "layout offset stays inside a plausible object");
    }

    // Runtime overrides: a derived row can be added without a rebuild.
    fs::LayoutOverrides overrides;
    const char* ini =
        "; derived elsewhere\n"
        "[Layout.010C0000]\n"
        "PlayerRva=0x1111\n"
        "UiRva=0x2222\n"
        "PlayerCellOffset=0xB8\n"
        "CellFormIdOffset=0x14\n"
        "CellTypeOffset=0x1A\n"
        "UiStackOffset=0x190\n"
        "UiTableOffset=0x1B0\n"
        "UiTableEntriesOffset=0x20\n"
        "MenuStride=0x28\n"
        "MenuNameOffset=0x08\n"
        "MenuInstanceOffset=0x10\n"
        "MenuNextOffset=0x20\n"
        "UnknownKey=0x99\n";
    check(fs::parseLayoutOverrides(ini, overrides) == 1, "one override row parsed");
    const auto* custom = fs::resolveLayout(0x010C0000, &overrides);
    check(custom && custom->playerRva == 0x1111 && custom->uiRva == 0x2222, "override row is used");
    check(fs::hasPlayer(*custom) && fs::hasMenus(*custom), "override row carries both halves");
    check(fs::resolveLayout(0x010A0A30, &overrides) == modern, "built-in rows still resolve with overrides present");
    check(!fs::resolveLayout(0x010C0000), "override does not leak without the table");
    fs::LayoutOverrides empty;
    check(fs::parseLayoutOverrides("[Layout.zzzz]\nPlayerRva=1\n", empty) == 0, "malformed runtime key rejected");
    check(fs::parseLayoutOverrides("[Other]\nPlayerRva=1\n", empty) == 0, "non-layout section ignored");
    fs::LayoutOverrides hollow;
    check(fs::parseLayoutOverrides("[Layout.010A0A30]\nUnknownKey=1\n", hollow) == 0,
          "empty override is dropped so it cannot shadow a built-in row");
    check(fs::resolveLayout(0x010A0A30, &hollow) == modern, "built-in row survives an empty override");

    // Invalid values are rejected instead of wrapping or truncating silently.
    fs::LayoutOverrides overflow;
    fs::LayoutParseReport overflowReport;
    check(fs::parseLayoutOverrides("[Layout.010C0000]\nPlayerRva=0x10000000000000000\n", overflow, &overflowReport) == 0 &&
          overflowReport.invalidValues == 1 && overflowReport.firstError[0],
          "over-64-bit hex value is rejected with a diagnostic");
    fs::LayoutOverrides wide;
    fs::LayoutParseReport wideReport;
    check(fs::parseLayoutOverrides("[Layout.010C0000]\nPlayerCellOffset=0x1000000B8\n", wide, &wideReport) == 0 &&
          wideReport.invalidValues == 1,
          "over-32-bit offset is rejected instead of truncating to 0xB8");
    fs::LayoutOverrides stride;
    fs::LayoutParseReport strideReport;
    check(fs::parseLayoutOverrides("[Layout.010C0000]\nMenuStride=0x400\n", stride, &strideReport) == 0 &&
          strideReport.invalidValues == 1,
          "out-of-range menu stride is rejected");

    // A partial override cannot shadow a working built-in row.
    fs::LayoutOverrides partialOverride;
    fs::LayoutParseReport partialReport;
    check(fs::parseLayoutOverrides("[Layout.010A0A30]\nPlayerRva=0x1111\n", partialOverride, &partialReport) == 0 &&
          partialReport.rejected == 1,
          "partial override that cannot decode either half is rejected");
    check(fs::resolveLayout(0x010A0A30, &partialOverride) == modern,
          "rejected partial override leaves the built-in row active");

    // A complete override for a built-in runtime with one invalid recognized
    // field is rejected as a whole and cannot shadow the built-in row.
    fs::LayoutOverrides invalidCell;
    fs::LayoutParseReport invalidCellReport;
    check(fs::parseLayoutOverrides(
              "[Layout.010A0A30]\nPlayerRva=0x1111\nUiRva=0x2222\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\nCellNameOffset=0x1000000B8\n",
              invalidCell, &invalidCellReport) == 0 && invalidCellReport.rejected >= 1,
          "complete override with one invalid recognized cell field is rejected as a whole");
    check(fs::resolveLayout(0x010A0A30, &invalidCell) == modern,
          "invalid complete override cannot shadow the built-in row");
    fs::LayoutOverrides invalidMenu;
    fs::LayoutParseReport invalidMenuReport;
    check(fs::parseLayoutOverrides(
              "[Layout.010A0A30]\nPlayerRva=0x1111\nUiRva=0x2222\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\nUiStackOffset=0x190\nUiTableOffset=0x1B0\n"
              "UiTableEntriesOffset=0x20\nMenuStride=0x28\nMenuNameOffset=0x1000000B8\n"
              "MenuInstanceOffset=0x10\nMenuNextOffset=0x20\n",
              invalidMenu, &invalidMenuReport) == 0 && invalidMenuReport.rejected >= 1,
          "invalid menu name offset rejects the whole row");
    check(fs::resolveLayout(0x010A0A30, &invalidMenu) == modern,
          "invalid menu override cannot shadow the built-in row");

    // A deliberately partial but valid row stays supported.
    fs::LayoutOverrides playerOnly;
    fs::LayoutParseReport playerOnlyReport;
    check(fs::parseLayoutOverrides(
              "[Layout.010C0000]\nPlayerRva=0x1111\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\n",
              playerOnly, &playerOnlyReport) == 1 && fs::hasPlayer(playerOnly.rows[0]) &&
          !fs::hasMenus(playerOnly.rows[0]),
          "deliberately partial valid row is still accepted");

    // Duplicate sections are rejected and counted.
    fs::LayoutOverrides duplicate;
    fs::LayoutParseReport duplicateReport;
    check(fs::parseLayoutOverrides(
              "[Layout.010C0000]\nPlayerRva=0x1111\nUiRva=0x2222\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\n"
              "[Layout.010C0000]\nPlayerRva=0x3333\nUiRva=0x4444\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\n",
              duplicate, &duplicateReport) == 1 &&
          duplicateReport.duplicateSections == 1 && duplicate.rows[0].playerRva == 0x1111,
          "duplicate runtime section is rejected and the first row is kept");

    // Unknown keys stay forward compatible but are counted.
    fs::LayoutOverrides unknown;
    fs::LayoutParseReport unknownReport;
    check(fs::parseLayoutOverrides(
              "[Layout.010C0000]\nPlayerRva=0x1111\nUiRva=0x2222\nPlayerCellOffset=0xB8\n"
              "CellFormIdOffset=0x14\nCellTypeOffset=0x1A\nFutureKey=0x1\n",
              unknown, &unknownReport) == 1 && unknownReport.unknownKeys == 1,
          "unknown keys are ignored but counted");

    HMODULE image = GetModuleHandleW(nullptr); MODULEINFO info{};
    check(GetModuleInformation(GetCurrentProcess(), image, &info, sizeof(info)) != 0, "fixture image");
    auto base = reinterpret_cast<ULONG64>(image);
    std::array<BYTE, 0xC0> player{};
    std::array<BYTE, 0x48> cell{};
    std::array<BYTE, 0x1E0> ui{};
    std::array<BYTE, 0x380> file{};
    std::array<BYTE, 0x18 + 256> cellName{}, menuName{};
    std::array<BYTE, 0x28> menu{};
    ULONG64 playerGlobal = pointer(player), uiGlobal = pointer(ui), filePtr = pointer(file);
    ULONG64 active = 0x123400;
    struct Sources { ULONG64 entries, count; } sources{pointer(filePtr), 1};
    put(player, 0, base); put(player, 0xB8, pointer(cell)); put(cell, 0, base);
    put(cell, 8, pointer(sources)); put(cell, 0x14, DWORD{0x05123456}); put(cell, 0x1A, BYTE{63});
    put(cell, 0x28, pointer(cellName)); strcpy_s(reinterpret_cast<char*>(cellName.data() + 0x18), 256, "Fixture cell");
    strcpy_s(reinterpret_cast<char*>(file.data() + 0x70), 260, "Fixture.esp"); put(file, 0x370, BYTE{5});
    put(ui, 0, base); put(ui, 0x190, pointer(active)); put(ui, 0x198, DWORD{1}); put(ui, 0x1A0, DWORD{1});
    put(ui, 0x1B4, DWORD{1}); put(ui, 0x1D0, pointer(menu));
    put(menu, 0, pointer(menuName)); put(menu, 8, active); put(menu, 0x20, ULONG64{1});
    strcpy_s(reinterpret_cast<char*>(menuName.data() + 0x18), 256, "LoadingMenu");
    auto sample = [&] { return fs::readContext(GetCurrentProcess(), *modern, pointer(playerGlobal), pointer(uiGlobal), base, info.SizeOfImage); };
    auto frame = sample();
    check(frame.cellValid && frame.cell == 0x05123456 && frame.cellName == "Fixture cell" && frame.origin == "Fixture.esp", "real RPM cell/name/standard origin");
    check(frame.menusValid && frame.loading(), "menu-stack name and loading phase");

    // The 1.11.221 row uses a different table and entry shape. The decoder must
    // follow the row rather than a fixed struct, so build that shape and check
    // it decodes to the same answer.
    std::array<BYTE, 0x1E0> ui2{};
    std::array<BYTE, 0x28> menu2{};
    std::array<BYTE, 0x18 + 256> menuName2{};
    ULONG64 active2 = 0x567800;
    put(ui2, 0, base);
    put(ui2, 0x190, pointer(active2)); put(ui2, 0x198, DWORD{1}); put(ui2, 0x1A0, DWORD{1});
    put(ui2, 0x1B4, DWORD{1}); put(ui2, 0x1D0, pointer(menu2));
    put(menu2, 8, pointer(menuName2)); put(menu2, 0x10, active2); put(menu2, 0x20, ULONG64{1});
    strcpy_s(reinterpret_cast<char*>(menuName2.data() + 0x18), 256, "LoadingMenu");
    ULONG64 uiGlobal2 = pointer(ui2);
    auto nextFrame = fs::readContext(GetCurrentProcess(), *next, pointer(playerGlobal), pointer(uiGlobal2), base, info.SizeOfImage);
    check(nextFrame.menusValid && nextFrame.loading(), "1.11.221 table and entry shapes decode through the row");
    put(menu2, 0x10, ULONG64{0x9999});
    auto nextMiss = fs::readContext(GetCurrentProcess(), *next, pointer(playerGlobal), pointer(uiGlobal2), base, info.SizeOfImage);
    check(!nextMiss.menusValid, "1.11.221 instance mismatch is rejected, not guessed");

    // A row with addresses but no usable entry shape must not index an empty
    // buffer or read past an entry.
    auto noStride = *next; noStride.menuStride = 0;
    auto noStrideFrame = fs::readContext(GetCurrentProcess(), noStride, pointer(playerGlobal), pointer(uiGlobal2), base, info.SizeOfImage);
    check(!noStrideFrame.menusValid, "zero stride is refused instead of indexed");
    auto badField = *next; badField.menuNameOffset = 0x30;
    auto badFieldFrame = fs::readContext(GetCurrentProcess(), badField, pointer(playerGlobal), pointer(uiGlobal2), base, info.SizeOfImage);
    check(!badFieldFrame.menusValid, "field offset outside the stride is refused");
    put(cell, 0x14, DWORD{0xFE123456}); put(file, 0x334, DWORD{0x200}); put(file, 0x372, WORD{0x123});
    strcpy_s(reinterpret_cast<char*>(file.data() + 0x70), 260, "Fixture.esl");
    frame = sample(); check(frame.cellValid && frame.origin == "Fixture.esl", "ESL partial-index origin");
    put(ui, 0x1A0, DWORD{0});
    frame = sample(); check(frame.menusValid && frame.menus.empty() && !frame.loading(), "cached instance outside stack is closed");
    put(ui, 0x1A0, DWORD{1}); put(menu, 0x20, ULONG64{0});
    check(!sample().menusValid, "free hash entry not treated as named active menu");
    put(menu, 0x20, ULONG64{1}); put(ui, 0x1B4, DWORD{4096});
    check(!sample().menusValid, "unbounded hash rejected"); put(ui, 0x1B4, DWORD{1});
    put(cellName, 8, DWORD{0x4000}); put(cellName, 0x10, pointer(cellName));
    auto cycle = sample();
    check(cycle.cellValid && cycle.cellName.empty(), "external string cycle rejected, identity kept");
    put(cellName, 8, DWORD{0});
    playerGlobal = ~ULONG64{0}; check(!sample().cellValid, "unreadable player pointer rejected");
    playerGlobal = pointer(player); put(cell, 0x1A, BYTE{65});
    check(!sample().cellValid, "wrong cell type rejected");
    put(cell, 0x1A, BYTE{63});

    // Name and file association are best effort; identity is type plus FormID.
    put(cell, 0x28, ULONG64{0xDEADBEEF});
    auto unnamed = sample();
    check(unnamed.cellValid && unnamed.cell == 0xFE123456 && unnamed.cellName.empty(),
          "unreadable name keeps the cell identity");
    put(cell, 0x28, pointer(cellName));
    put(cell, 8, ULONG64{0xDEADBEEF});
    auto unsourced = sample();
    check(unsourced.cellValid && unsourced.files.find("unavailable") != std::string::npos,
          "unreadable association keeps the cell identity");
    put(cell, 8, pointer(sources));

    // A partial layout must still deliver the half it has and stay silent on the other.
    auto partial = *next;
    auto partialFrame = fs::readContext(GetCurrentProcess(), partial, pointer(playerGlobal), 0, base, info.SizeOfImage);
    check(partialFrame.cellValid && partialFrame.cell == 0xFE123456, "player-only layout still reads the cell");
    check(!partialFrame.menusValid && partialFrame.menus.empty(), "player-only layout never invents menus");
    auto noPlayer = *modern; noPlayer.playerRva = 0;
    auto menuOnly = fs::readContext(GetCurrentProcess(), noPlayer, 0, pointer(uiGlobal), base, info.SizeOfImage);
    check(!menuOnly.cellValid && menuOnly.menusValid, "menu-only layout reads menus without a player global");

    fs::ContextObserver unsupported(GetCurrentProcess(), 0xFFFFFFFF, true);
    check(!unsupported.sample().cellValid && !unsupported.sample().menusValid, "unknown runtime has no engine reads");
    check(unsupported.qualification().find("no engine layout") != std::string::npos, "unknown runtime explains itself");
    fs::ContextObserver wrongImage(GetCurrentProcess(), 0x010A0A30, true);
    check(!wrongImage.sample().cellValid, "runtime alone cannot enable offsets in fixture executable");
    fs::ContextObserver disabled(GetCurrentProcess(), 0x010A0A30, false);
    check(!disabled.sample().cellValid, "ContextMonitoring=0 disables the adapter");
    std::cout << "PASS: layout table, per-half degradation, external cell/menu decoder, ESP/ESL origins, bounds, string cycles, identity gating\n";
}
