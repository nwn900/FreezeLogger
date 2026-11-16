#pragma once
#include "shared.hpp"
#include "layout.hpp"
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
// Read-only decoder driven entirely by a resolved layout. A zero global address
// disables that half; the caller never supplies a guessed address.
EngineContext readContext(HANDLE target, const EngineLayout& layout, ULONG64 playerGlobal,
                          ULONG64 uiGlobal, ULONG64 base, DWORD imageSize);
class ContextObserver {
    HANDLE target;
    const EngineLayout* layout = nullptr;
    ULONG64 base = 0;
    DWORD size = 0;
    std::string status;
    const char* hashState_ = "none";
public:
    ContextObserver(HANDLE target, DWORD runtime, bool enabled, const LayoutOverrides* overrides = nullptr);
    EngineContext sample() const;
    const std::string& qualification() const { return status; }
    // "match", "differs", "not-declared" (override row) or "none" (no layout).
    const char* hashState() const { return hashState_; }
    bool enabled() const { return base && layout; }
};
std::string diskSHA256(const std::filesystem::path& path);
}
