// Unit tests for the Buffout 4 crash-log parser (src/buffout.hpp).
#include "../src/buffout.hpp"
#include <windows.h>
#include <iostream>
#include <limits>

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
            "Fallout 4 v1.10.163\nBuffout 4 v1.28.6\n"
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x7FF64B7552D6 Fallout4.exe+1C152D6\n"
            "PROBABLE CALL STACK:\n[ 0] 0x7FF64B7552D6 Fallout4.exe+1C152D6 -> 1523267+0x2D6\n");
        check(info.found && info.edition == fs::BuffoutCrashInfo::Edition::Fallout4 &&
              info.gameVersion == "1.10.163" && info.faultModule == "fallout4.exe" &&
              info.faultOffset == "0x1c152d6", "real Fallout 4 Buffout header and fault line parse");
    }
    {
        fs::BuffoutCrashInfo vr = fs::parseBuffoutCrashLog(
            "Fallout 4 VR v1.2.72\nUnhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 Fallout4VR.exe+0x2\n");
        check(vr.found && vr.edition == fs::BuffoutCrashInfo::Edition::Fallout4VR && vr.gameVersion == "1.2.72",
              "VR edition header parse");
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
    {
        fs::BuffoutCrashInfo space = fs::parseBuffoutCrashLog(
            "Fallout 4 v1.10.163\nUnhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 "
            "C:\\Games\\Fallout 4\\Data\\F4SE\\Plugins\\My Plugin.dll+0x2\n");
        check(space.found && space.faultModule == "my plugin.dll", "spaces in module paths preserve the full basename");
        fs::BuffoutCrashInfo bare = fs::parseBuffoutCrashLog(
            "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 Fallout 4.exe+0x2\n");
        check(bare.found && bare.faultModule == "fallout 4.exe", "spaces in bare image names are retained");
    }
    {
        std::size_t cursor = 0;
        std::uint64_t value = 7;
        check(fs::buffout::parseHex("FFFFFFFFFFFFFFFF", cursor, value) &&
              cursor == 16 && value == (std::numeric_limits<std::uint64_t>::max)(), "sixteen-digit hex maximum accepted");
        cursor = 0; value = 7;
        check(!fs::buffout::parseHex("FFFFFFFFFFFFFFFFF", cursor, value) && cursor == 0 && value == 7,
              "17-digit hex overflow rejected without changing parser state");
    }
    {
        auto crash = fs::parseBuffoutCrashLog(
            "Fallout 4 v1.10.163\nUnhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 Fallout4.exe+0x2\n");
        constexpr std::uint64_t started = 1'000'000'000ULL;
        constexpr std::uint64_t written = started + 10'000'000ULL;
        fs::CrashLogSession session{fs::BuffoutCrashInfo::Edition::Fallout4, "1.10.163",
                                    started, written + 600'000'000ULL};
        fs::CrashLogCorrelator correlator(session);
        auto match = correlator.assess(crash, written);
        check(match.matched && match.ageMs == 60000, "same game edition/version and recent current process correlates");
        crash.edition = fs::BuffoutCrashInfo::Edition::Fallout4VR;
        check(correlator.assess(crash, written).reason == "game-edition-mismatch", "other game edition is context only");
        crash.edition = fs::BuffoutCrashInfo::Edition::Fallout4;
        crash.gameVersion = "1.10.980";
        check(correlator.assess(crash, written).reason == "game-version-mismatch", "different game version is context only");
        crash.gameVersion = "1.10.163";
        check(correlator.assess(crash, started - 1).reason == "before-process-start", "old process log is context only");
        auto staleSession = session;
        staleSession.observedFileTime = written + 3'010'000'000ULL;
        check(fs::CrashLogCorrelator(staleSession).assess(crash, written).reason == "outside-session-correlation-window",
              "stale crash log is context only");
        crash.gameVersion.clear();
        check(correlator.assess(crash, written).reason == "game-version-unknown", "unknown log version is context only");
    }
    std::cout << "PASS: Buffout fault/stack parsing, victim cases, hostile input\n";
    return 0;
}
