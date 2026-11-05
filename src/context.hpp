#pragma once
#include "shared.hpp"
#include <vector>

namespace fs {
struct EngineContext {
    bool cellValid = false, menusValid = false;
    DWORD cell = 0;
    std::string cellName, origin, files, status;
    std::vector<std::string> menus;
    bool operator==(const EngineContext&) const = default;
    bool loading() const;
    std::string text() const;
};
// Read-only decoder. Production callers must first qualify the image identity.
EngineContext readContext163(HANDLE target, ULONG64 playerGlobal, ULONG64 uiGlobal, ULONG64 base, DWORD imageSize);
class ContextObserver {
    HANDLE target;
    ULONG64 base = 0;
    DWORD size = 0;
    std::string status;
public:
    ContextObserver(HANDLE target, DWORD runtime, bool enabled);
    EngineContext sample() const;
    const std::string& qualification() const { return status; }
};
std::string diskSHA256(const std::filesystem::path& path);
}
