// Per-runtime engine layout for the read-only context adapter.
//
// The adapter is the only part of FreezeSentryF4 that touches engine memory, so
// it is the only part that needs per-version knowledge. That knowledge lives
// here as data rather than being compiled into the decoder: adding a runtime is
// a table row, not a code change.
//
// Every address is an RVA from the module base. Every offset is a byte
// displacement inside the object named by the field. A zero means "not derived
// for this runtime"; the adapter then reports that field as unavailable instead
// of reading a guessed address.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace fs {

struct EngineLayout {
    std::uint32_t runtime;            // F4SE packed runtime version
    std::uint64_t playerRva;          // global holding PlayerCharacter*
    std::uint64_t uiRva;              // global holding UI*
    std::uint32_t playerCellOffset;   // PlayerCharacter -> parentCell
    std::uint32_t cellFormIdOffset;   // TESObjectCELL -> FormID
    std::uint32_t cellTypeOffset;     // TESForm -> formType
    std::uint32_t cellNameOffset;     // TESObjectCELL -> full name
    std::uint32_t cellSourceOffset;   // TESObjectCELL -> file association
    std::uint32_t uiStackOffset;      // UI -> active menu stack
    std::uint32_t uiTableOffset;      // UI -> menu table
    // The stack is an Array: entries pointer at +0, capacity at +8, count at
    // +0x10. The table and its entries moved between versions, so their field
    // positions are data too.
    std::uint32_t uiTableEntriesOffset; // menu table -> entries pointer
    std::uint32_t uiTableSizeOffset;    // menu table -> entry count
    std::uint32_t menuStride;           // menu table entry size
    std::uint32_t menuNameOffset;       // entry -> name
    std::uint32_t menuInstanceOffset;   // entry -> menu instance
    std::uint32_t menuNextOffset;       // entry -> chain link
    const char* expectedSha256;       // informational only; never a gate
    const char* evidence;             // how this row was derived
};

inline constexpr std::uint32_t cellFormType = 63;
inline constexpr std::uint32_t stackCapacityOffset = 0x08;
inline constexpr std::uint32_t stackCountOffset = 0x10;

// Rows are matched exactly on the packed runtime version. A row may be partial:
// the player half and the menu half are independent capabilities.
inline constexpr EngineLayout layouts[] = {
    { 0x010A0A30u, 0x05AA4388u, 0x058D0898u, 0xB8, 0x14, 0x1A, 0x28, 0x08, 0x190, 0x1A8,
      0x28, 0x0C, 0x28, 0x00, 0x08, 0x20,
      "55f57947db9e05575122fae1088f0b0247442f11e566b56036caa0ac93329c36",
      "1.10.163: F4SE v0.6.23 layout declarations, checked against the local executable" },
    { 0x010B0DD0u, 0x032D22E0u, 0x030DD8B0u, 0xB8, 0x14, 0x1A, 0x28, 0x08, 0x190, 0x1B0,
      0x20, 0x04, 0x28, 0x08, 0x10, 0x20,
      "428f9996cc4248e26c0f62f9fdd3eaf0e5eb305834b67ee5996538e593218b61",
      "1.11.221: player global from the parentCell/FormID chain; UI singleton via RTTI .?AVUI@@ -> vtable 0x27159E8; stack +0x190 confirmed, table +0x1B0 and entry shape inferred from the member constructors" },
};

// Runtime overrides let a derived row be added without a rebuild. The file is
// optional and every row still goes through the same structural validation, so
// a wrong row fails closed instead of reading a guessed address.
struct LayoutOverrides {
    static constexpr std::size_t capacity = 4;
    EngineLayout rows[capacity]{};
    std::size_t count = 0;

    const EngineLayout* find(std::uint32_t runtime) const noexcept {
        for (std::size_t i = 0; i < count; ++i)
            if (rows[i].runtime == runtime) return &rows[i];
        return nullptr;
    }
};

namespace detail {
inline bool parseHex(std::string_view text, std::uint64_t& value) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) text.remove_suffix(1);
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text.remove_prefix(2);
    if (text.empty()) return false;
    std::uint64_t result = 0;
    for (char c : text) {
        unsigned digit = c >= '0' && c <= '9' ? static_cast<unsigned>(c - '0')
            : c >= 'a' && c <= 'f' ? static_cast<unsigned>(c - 'a' + 10)
            : c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10) : 256u;
        if (digit > 15) return false;
        result = result * 16 + digit;
    }
    value = result;
    return true;
}
inline std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) text.remove_suffix(1);
    return text;
}
}

// Parses [Layout.<runtime-hex>] sections. Unknown keys are ignored so a newer
// file still loads on an older build. Returns the number of rows accepted.
inline std::size_t parseLayoutOverrides(std::string_view text, LayoutOverrides& out) noexcept {
    out.count = 0;
    EngineLayout* current = nullptr;
    while (!text.empty()) {
        auto end = text.find('\n');
        auto line = detail::trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (line.empty() || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            current = nullptr;
            auto close = line.find(']');
            if (close == std::string_view::npos) continue;
            auto name = line.substr(1, close - 1);
            constexpr std::string_view prefix = "Layout.";
            if (name.size() <= prefix.size() || name.substr(0, prefix.size()) != prefix) continue;
            std::uint64_t runtime = 0;
            if (!detail::parseHex(name.substr(prefix.size()), runtime) || !runtime) continue;
            if (out.count >= LayoutOverrides::capacity) continue;
            current = &out.rows[out.count];
            *current = EngineLayout{};
            current->runtime = static_cast<std::uint32_t>(runtime);
            current->evidence = "runtime override from FreezeSentryF4.layout.ini";
            ++out.count;
            continue;
        }
        if (!current) continue;
        auto equals = line.find('=');
        if (equals == std::string_view::npos) continue;
        auto key = detail::trim(line.substr(0, equals));
        std::uint64_t value = 0;
        if (!detail::parseHex(line.substr(equals + 1), value)) continue;
        auto field = [&](std::string_view name, std::uint32_t& target) {
            if (key == name) { target = static_cast<std::uint32_t>(value); return true; }
            return false;
        };
        auto wide = [&](std::string_view name, std::uint64_t& target) {
            if (key == name) { target = value; return true; }
            return false;
        };
        if (wide("PlayerRva", current->playerRva)) continue;
        if (wide("UiRva", current->uiRva)) continue;
        if (field("PlayerCellOffset", current->playerCellOffset)) continue;
        if (field("CellFormIdOffset", current->cellFormIdOffset)) continue;
        if (field("CellTypeOffset", current->cellTypeOffset)) continue;
        if (field("CellNameOffset", current->cellNameOffset)) continue;
        if (field("CellSourceOffset", current->cellSourceOffset)) continue;
        if (field("UiStackOffset", current->uiStackOffset)) continue;
        if (field("UiTableOffset", current->uiTableOffset)) continue;
        if (field("UiTableEntriesOffset", current->uiTableEntriesOffset)) continue;
        if (field("UiTableSizeOffset", current->uiTableSizeOffset)) continue;
        if (field("MenuStride", current->menuStride)) continue;
        if (field("MenuNameOffset", current->menuNameOffset)) continue;
        if (field("MenuInstanceOffset", current->menuInstanceOffset)) continue;
        if (field("MenuNextOffset", current->menuNextOffset)) continue;
    }
    // Drop sections that carried no usable field. An empty override must not
    // shadow a built-in row for the same runtime.
    std::size_t kept = 0;
    for (std::size_t i = 0; i < out.count; ++i) {
        const auto& row = out.rows[i];
        if (row.playerRva || row.uiRva || row.playerCellOffset || row.uiStackOffset || row.uiTableOffset)
            out.rows[kept++] = row;
    }
    out.count = kept;
    return out.count;
}

inline const EngineLayout* resolveLayout(std::uint32_t runtime, const LayoutOverrides* overrides = nullptr) noexcept {
    if (overrides)
        if (const auto* row = overrides->find(runtime)) return row;
    for (const auto& layout : layouts)
        if (layout.runtime == runtime) return &layout;
    return nullptr;
}

// The player half needs the global plus the three offsets the decoder reads
// before it can produce a cell sample.
inline bool hasPlayer(const EngineLayout& layout) noexcept {
    return layout.playerRva && layout.playerCellOffset && layout.cellFormIdOffset && layout.cellTypeOffset;
}

// The menu half needs the global, both container offsets and a usable entry
// shape. A row that knows the addresses but not the shapes stays unavailable.
inline bool hasMenus(const EngineLayout& layout) noexcept {
    return layout.uiRva && layout.uiStackOffset && layout.uiTableOffset &&
           layout.uiTableEntriesOffset && layout.menuStride && layout.menuNameOffset != 0xFFFFFFFF &&
           layout.menuInstanceOffset != 0xFFFFFFFF && layout.menuNextOffset != 0xFFFFFFFF;
}
} // namespace fs