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
    auto sample = [&] { return fs::readContext163(GetCurrentProcess(), pointer(playerGlobal), pointer(uiGlobal), base, info.SizeOfImage); };
    auto frame = sample();
    check(frame.cellValid && frame.cell == 0x05123456 && frame.cellName == "Fixture cell" && frame.origin == "Fixture.esp", "real RPM cell/name/standard origin");
    check(frame.menusValid && frame.loading(), "menu-stack name and loading phase");
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
    check(!sample().cellValid, "external string cycle rejected"); put(cellName, 8, DWORD{0});
    playerGlobal = ~ULONG64{0}; check(!sample().cellValid, "unreadable player pointer rejected");
    playerGlobal = pointer(player); put(cell, 0x1A, BYTE{65});
    check(!sample().cellValid, "wrong cell type rejected");
    fs::ContextObserver unsupported(GetCurrentProcess(), 0xFFFFFFFF, true);
    check(!unsupported.sample().cellValid && !unsupported.sample().menusValid, "unknown runtime has no engine reads");
    fs::ContextObserver wrongImage(GetCurrentProcess(), 0x010A0A30, true);
    check(!wrongImage.sample().cellValid, "runtime alone cannot enable offsets in fixture executable");
    std::cout << "PASS: external cell/menu decoder, ESP/ESL origins, bounds, string cycles, identity gating\n";
}
