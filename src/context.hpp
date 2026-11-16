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
public:
    ContextObserver(HANDLE target, DWORD runtime, bool enabled, const LayoutOverrides* overrides = nullptr);
    EngineContext sample() const;
    const std::string& qualification() const { return status; }
};
// Scans a code buffer for the player-global pattern: a RIP-relative load whose
// destination is then dereferenced at the parentCell offset. Returns the RVA of
// the most-referenced candidate, or 0 when the result is not decisive. This is
// what lets the player half work on a runtime with no layout row, because the
// loaded image is decrypted even when the file on disk is not.
std::uint64_t scanPlayerGlobal(const BYTE* code, std::size_t size, std::uint64_t codeRva,
                               std::uint32_t cellOffset);
std::string diskSHA256(const std::filesystem::path& path);
}
