// Unit tests for the Buffout 4 crash-log parser (src/buffout.hpp).
#include "../src/buffout.hpp"
#include <windows.h>
#include <iostream>

namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
} // namespace

int wmain() {
    {
        fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog(
            "Buffout 4 v1.28.6\n"
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x7FF6A1B23456 CoolMod.dll+0x12345\n"
            "PROBABLE CALL STACK:\n"
            "\t[0] 0x7FF6A1B23456 (CoolMod.dll+0x12345)\n"
            "\t[1] 0x7FF7B2C30000 (Fallout4.exe+0x9999)\n"
            "\t[2] 0x7FF8C1D40000 (KERNELBASE.dll+0x1)\n");
        check(info.found, "direct fault recognized");
        check(info.exceptionCode == 0xC0000005u, "access violation code");
        check(info.faultAddress == 0x7FF6A1B23456u, "fault address");
        check(info.faultModule == "coolmod.dll", "fault module lowercased");
        check(info.faultOffset == "0x12345", "fault offset");
        check(info.stackModules.size() == 3 && info.stackModules[0] == "coolmod.dll" &&
                  info.stackModules[2] == "kernelbase.dll",
              "stack modules top-first");
    }
    {
        fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog(
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x7FF8C1D40000 ntdll.dll+0xABC\n"
            "PROBABLE CALL STACK:\n"
            "[0] 0x7FF8C1D40000 (ntdll.dll+0xABC)\n");
        check(info.found && info.faultModule == "ntdll.dll", "system module victim parsed");
        check(info.stackModules.size() == 1, "single frame");
    }
    {
        fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog(
            "Unhandled exception \"E06D7363\" at 0x7FFD00001234 Thrower.dll+0x10\n");
        check(info.found && info.exceptionCode == 0xE06D7363u, "C++ throw code");
        check(info.stackModules.empty(), "absent stack section is not an error");
    }
    {
        fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog("not a crash log\njust notes\n");
        check(!info.found, "garbage rejected");
        fs::BuffoutCrashInfo empty = fs::parseBuffoutCrashLog({});
        check(!empty.found, "empty input rejected");
    }
    {
        // Hostile shapes: unterminated quote, huge address, path-qualified module.
        fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog(
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION at 0xFFFFFFFFFFFFFFFFFF "
            "C:\\Games\\Fallout 4\\Data\\F4SE\\Plugins\\Deep\\NestedMod.dll+0x1\n");
        check(!info.found || info.faultAddress <= 0xFFFFFFFFFFFFFFFFu, "overflow address contained");
        fs::BuffoutCrashInfo pathed = fs::parseBuffoutCrashLog(
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x1000 "
            "E:\\SteamLibrary\\steamapps\\common\\Fallout 4\\Data\\F4SE\\Plugins\\NestedMod.dll+0x2\n");
        check(pathed.found && pathed.faultModule == "nestedmod.dll", "path stripped to basename");
    }
    std::cout << "PASS: Buffout fault/stack parsing, victim cases, hostile input\n";
    return 0;
}
