#pragma once
#include <array>
#include <string_view>

namespace fs {
// Classifies modules whose stack locations are normally observation surfaces
// rather than direct evidence of the code that caused a fault.
class RuntimeModuleClassifier final {
public:
    static bool isF4seRuntime(std::string_view lowerBase) noexcept {
        return versioned(lowerBase, "f4se_") || versioned(lowerBase, "f4sevr_");
    }

    static bool isVictimLocation(std::string_view lowerBase) noexcept {
        static constexpr std::array<std::string_view, 47> modules{
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll",
            "gdi32.dll", "gdi32full.dll", "combase.dll", "ole32.dll", "oleaut32.dll",
            "shell32.dll", "shcore.dll", "shlwapi.dll", "msvcrt.dll", "ucrtbase.dll",
            "msvcp_win.dll", "bcrypt.dll", "bcryptprimitives.dll", "rpcrt4.dll", "sechost.dll",
            "advapi32.dll", "imm32.dll", "crypt32.dll", "imagehlp.dll", "psapi.dll",
            "version.dll", "winmm.dll", "ws2_32.dll", "mswsock.dll", "setupapi.dll",
            "cfgmgr32.dll", "hid.dll", "kernel.appcore.dll", "powrprof.dll", "umpdc.dll",
            "d3d11.dll", "dxgi.dll", "dwmapi.dll", "uxtheme.dll", "msctf.dll",
            "fallout4.exe", "fallout4vr.exe", "f4se.dll", "f4sevr.dll", "f4se_steam_loader.dll",
            "steam_api64.dll", "steamclient64.dll"};
        for (auto module : modules)
            if (lowerBase == module) return true;
        return isF4seRuntime(lowerBase) || lowerBase == "tier0_s64.dll" || lowerBase == "vstdlib_s64.dll" ||
               lowerBase == "gameoverlayrenderer64.dll" || lowerBase == "buffout4.dll" ||
               lowerBase.starts_with("d3dcompiler_") || lowerBase.starts_with("msvcp140") ||
               lowerBase.starts_with("vcruntime140") || lowerBase.starts_with("concrt140");
    }

private:
    static bool versioned(std::string_view module, std::string_view prefix) noexcept {
        constexpr std::string_view suffix = ".dll";
        if (!module.starts_with(prefix) || !module.ends_with(suffix)) return false;
        auto version = module.substr(prefix.size(), module.size() - prefix.size() - suffix.size());
        if (version.empty()) return false;
        bool needDigit = true;
        for (char c : version) {
            if (c >= '0' && c <= '9') needDigit = false;
            else if (c == '_' && !needDigit) needDigit = true;
            else return false;
        }
        return !needDigit;
    }
};
} // namespace fs
