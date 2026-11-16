#include "context.hpp"
#include <psapi.h>
#include <array>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <set>

namespace fs {
namespace {
struct Reader {
    HANDLE process;
    ULONG64 base;
    DWORD size;
    bool bytes(ULONG64 address, void* output, size_t count) const {
        SIZE_T got = 0;
        RpmStats::calls().fetch_add(1, std::memory_order_relaxed);
        bool ok = address >= 0x10000 && address <= 0x00007fffffff0000ULL && count <= 1024 * 1024 &&
            count <= 0x00007fffffff0000ULL - address &&
            ReadProcessMemory(process, reinterpret_cast<void*>(address), output, count, &got) && got == count;
        if (ok) RpmStats::bytes().fetch_add(count, std::memory_order_relaxed);
        else RpmStats::failures().fetch_add(1, std::memory_order_relaxed);
        return ok;
    }
    template<class T> bool get(ULONG64 address, T& output) const { return bytes(address, &output, sizeof(output)); }
    bool object(ULONG64 address) const {
        ULONG64 vtable = 0;
        return get(address, vtable) && vtable >= base && vtable - base < size;
    }
    bool fixed(ULONG64 entry, std::string& result) const {
        if (!entry) { result.clear(); return true; }
        std::set<ULONG64> seen;
        for (unsigned i = 0; i < 8; ++i) {
            struct Header { ULONG64 next; DWORD flags, length; ULONG64 external; } header{};
            if (!seen.insert(entry).second || !get(entry, header)) return false;
            if (header.flags & 0x4000) { entry = header.external; continue; }
            if ((header.flags & 0x8000) || header.length > 1024) return false;
            // Validate termination without assuming whether length includes the terminator.
            result.clear();
            for (unsigned n = 0; n < 256;) {
                std::array<char, 32> chunk{};
                auto address = entry + 0x18 + n;
                auto count = std::min<size_t>({chunk.size(), 256 - n, 4096 - (address & 4095)});
                if (!bytes(address, chunk.data(), count)) return false;
                for (size_t part = 0; part < count; ++part) {
                    auto c = chunk[part];
                    if (!c) return true;
                    result += static_cast<unsigned char>(c) < 32 || c == 127 ? ' ' : c;
                }
                n += static_cast<unsigned>(count);
            }
            return false;
        }
        return false;
    }
};
// The stack, table and entry shapes used to be fixed structs here. They are now
// fields in EngineLayout, because the three moved independently between 1.10.163
// and 1.11.221 and a compiled-in layout cannot describe both.
EngineContext once(const Reader& read, const EngineLayout& layout, ULONG64 playerGlobal, ULONG64 uiGlobal) {
    EngineContext result;
    ULONG64 player = 0, cell = 0, ui = 0;
    if (playerGlobal && read.get(playerGlobal, player) &&
        (!player || (read.object(player) && read.get(player + layout.playerCellOffset, cell)))) {
        if (!cell) { result.cellValid = true; }
        else {
            BYTE type = 0; ULONG64 name = 0, source = 0;
            // Identity is the object, its form type and its FormID. The name and
            // the file association are best effort: a layout whose name offset is
            // wrong should still report the cell instead of dropping the sample.
            if (read.object(cell) && read.get(cell + layout.cellTypeOffset, type) && type == cellFormType &&
                read.get(cell + layout.cellFormIdOffset, result.cell)) {
                result.cellValid = true;
                result.origin = (result.cell >> 24) == 0xFF ? "dynamic form" : "not resolved";
                if (!read.get(cell + layout.cellNameOffset, name) || !read.fixed(name, result.cellName))
                    result.cellName.clear();
                struct Sources { ULONG64 entries, count; } sources{};
                if (read.get(cell + layout.cellSourceOffset, source) && source &&
                    read.get(source, sources) && sources.count <= 64) {
                    std::ostringstream files;
                    for (ULONG64 i = 0; i < sources.count; ++i) {
                        ULONG64 file = 0; std::array<char, 260> nameBytes{}; DWORD flags = 0; BYTE index = 0; WORD light = 0;
                        if (!read.get(sources.entries + i * 8, file) || !read.bytes(file + 0x70, nameBytes.data(), nameBytes.size()) ||
                            !read.get(file + 0x334, flags) || !read.get(file + 0x370, index) || !read.get(file + 0x372, light) ||
                            !memchr(nameBytes.data(), 0, nameBytes.size())) { files << "[unreadable association] "; continue; }
                        std::string fileName(nameBytes.data());
                        for (auto& c : fileName) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
                        files << '[' << fileName << "] ";
                        bool matches = flags & 0x200 ? (result.cell >> 24) == 0xFE && ((result.cell >> 12) & 0xFFF) == light :
                                                      (result.cell >> 24) < 0xFE && (result.cell >> 24) == index;
                        if (matches) result.origin = fileName;
                    }
                    result.files = files.str();
                } else if (source) result.files = "unavailable (association count/read failed)";
            }
        }
    }
    if (uiGlobal && read.get(uiGlobal, ui)) {
        if (!ui) result.menusValid = true;
        else if (read.object(ui)) {
            // Every field position comes from the layout row. The stack and the
            // table moved independently between versions, and so did the entry
            // shape, so nothing here assumes a fixed struct.
            ULONG64 stackEntries = 0, tableEntries = 0;
            DWORD stackCapacity = 0, stackCount = 0, tableSize = 0;
            // A row can carry addresses without a usable entry shape. Guard the
            // stride and the field offsets so a bad row cannot index an empty
            // buffer or read past the end of the last entry.
            const bool shapeUsable = layout.menuStride >= 8 && layout.menuStride <= 0x100 &&
                layout.menuNameOffset + 8 <= layout.menuStride &&
                layout.menuInstanceOffset + 8 <= layout.menuStride &&
                layout.menuNextOffset + 8 <= layout.menuStride;
            if (shapeUsable &&
                read.get(ui + layout.uiStackOffset, stackEntries) &&
                read.get(ui + layout.uiStackOffset + stackCapacityOffset, stackCapacity) &&
                read.get(ui + layout.uiStackOffset + stackCountOffset, stackCount) &&
                read.get(ui + layout.uiTableOffset + layout.uiTableEntriesOffset, tableEntries) &&
                read.get(ui + layout.uiTableOffset + layout.uiTableSizeOffset, tableSize) &&
                stackCount <= stackCapacity && stackCount <= 128 && tableSize <= 2048) {
                std::vector<ULONG64> active(stackCount);
                std::vector<BYTE> entries(static_cast<size_t>(tableSize) * layout.menuStride);
                if ((!stackCount || read.bytes(stackEntries, active.data(), active.size() * 8)) &&
                    (!tableSize || read.bytes(tableEntries, entries.data(), entries.size()))) {
                    result.menusValid = true;
                    for (auto instance : active) {
                        bool matched = false;
                        for (DWORD i = 0; i < tableSize; ++i) {
                            const BYTE* entry = entries.data() + static_cast<size_t>(i) * layout.menuStride;
                            ULONG64 next = 0, entryInstance = 0, name = 0;
                            memcpy(&next, entry + layout.menuNextOffset, 8);
                            memcpy(&entryInstance, entry + layout.menuInstanceOffset, 8);
                            memcpy(&name, entry + layout.menuNameOffset, 8);
                            if (!next || !instance || entryInstance != instance) continue;
                            std::string text;
                            if (!read.fixed(name, text) || text.empty()) { result.menusValid = false; break; }
                            result.menus.push_back(text);
                            matched = true;
                            break;
                        }
                        if (!matched) { result.menusValid = false; break; }
                    }
                }
            }
        }
    }
    result.status = result.cellValid && result.menusValid ? "sample readable" : "context partially unavailable; no transition inferred for missing fields";
    return result;
}
std::string hex(std::uint64_t value) {
    std::ostringstream out; out << "0x" << std::hex << value; return out.str();
}
}
bool EngineContext::loading() const {
    return menusValid && std::find(menus.begin(), menus.end(), "LoadingMenu") != menus.end();
}
std::string EngineContext::text() const {
    std::ostringstream out;
    out << "ENGINE_CONTEXT (external read-only observation; sampled transitions can miss short events)\n"
        << "status=" << status << " cell_valid=" << cellValid << " menus_valid=" << menusValid << '\n';
    if (cellValid) out << "cell_FormID=0x" << std::hex << cell << std::dec << " cell_name=[" << cellName << "] form_origin=[" << origin
        << "]\ncell_associated_files=" << files << " (association only; not winning override or blame)\n";
    if (menusValid) {
        out << "open_menu_stack=";
        for (const auto& name : menus) out << '[' << name << "] ";
        out << "\nloading_menu_observed=" << loading() << " (loading cause/fast travel not inferred)\n";
    }
    return out.str();
}
EngineContext readContext(HANDLE target, const EngineLayout& layout, ULONG64 playerGlobal,
                          ULONG64 uiGlobal, ULONG64 base, DWORD imageSize) {
    Reader reader{target, base, imageSize};
    auto first = once(reader, layout, playerGlobal, uiGlobal), second = once(reader, layout, playerGlobal, uiGlobal);
    if (first == second) return second;
    EngineContext unavailable; unavailable.status = "changed during two reads; sample discarded"; return unavailable;
}
ContextObserver::ContextObserver(HANDLE process, DWORD runtime, bool enabled, const LayoutOverrides* overrides)
    : target(process) {
    status = "disabled or unsupported runtime/image; generic F4SE history remains available";
    if (!enabled) return;
    layout = resolveLayout(runtime, overrides);
    if (!layout) {
        status = "no engine layout for runtime " + hex(runtime) + "; generic F4SE history remains available";
        return;
    }
    if (!hasPlayer(*layout) && !hasMenus(*layout)) {
        status = "layout for runtime " + hex(runtime) + " has no derived addresses; adapter disabled";
        return;
    }
    std::array<wchar_t, 32768> path{}; DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(target, 0, path.data(), &length) ||
        _wcsicmp(std::filesystem::path(path.data()).filename().c_str(), L"Fallout4.exe")) {
        status = "layout for runtime " + hex(runtime) + " exists but the image is not Fallout4.exe; adapter disabled";
        return;
    }
    HMODULE image = nullptr; DWORD needed = 0; MODULEINFO info{};
    if (!EnumProcessModulesEx(target, &image, sizeof(image), &needed, LIST_MODULES_64BIT) ||
        !GetModuleInformation(target, image, &info, sizeof(info))) return;
    auto imageBase = reinterpret_cast<ULONG64>(info.lpBaseOfDll);
    Reader reader{target, imageBase, info.SizeOfImage};
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{};
    if (!reader.get(imageBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 64 || dos.e_lfanew > 4096 ||
        !reader.get(imageBase + dos.e_lfanew, nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage != info.SizeOfImage ||
        !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > 96) return;
    auto inData = [&](ULONG64 rva) {
        for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER section{};
            if (!reader.get(imageBase + dos.e_lfanew + 24 + nt.FileHeader.SizeOfOptionalHeader + i * sizeof(section), section)) return false;
            if (rva >= section.VirtualAddress && rva + 8 <= static_cast<ULONG64>(section.VirtualAddress) + section.Misc.VirtualSize)
                return (section.Characteristics & IMAGE_SCN_MEM_READ) && !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        }
        return false;
    };
    // Every derived address must land in readable, non-executable image data.
    // This is the structural replacement for the old exact-hash gate: it holds
    // for any build whose layout row is correct, and fails closed otherwise.
    if ((layout->playerRva && !inData(layout->playerRva)) || (layout->uiRva && !inData(layout->uiRva))) {
        status = "layout for runtime " + hex(runtime) + " does not match this image's data sections; adapter disabled";
        return;
    }
    // Built-in rows are qualified by their on-disk fingerprint. A mismatch is
    // unqualified: the adapter stays disabled rather than reading plausible but
    // wrong offsets from a different build of the same runtime. Override rows
    // carry no fingerprint and are structural-only by design.
    if (layout->expectedSha256 && *layout->expectedSha256) {
        auto actual = diskSHA256(path.data());
        if (actual != layout->expectedSha256) {
            hashState_ = "differs";
            status = "layout for runtime " + hex(runtime) + " exists but the image hash differs (unqualified); adapter disabled";
            return;
        }
        hashState_ = "match";
    } else {
        hashState_ = "not-declared";
    }
    base = imageBase; size = info.SizeOfImage;
    std::ostringstream qualified;
    qualified << "runtime " << hex(runtime) << " layout enabled; player="
              << (hasPlayer(*layout) ? hex(layout->playerRva) : "unavailable")
              << " menus=" << (hasMenus(*layout) ? hex(layout->uiRva) : "unavailable")
              << "; image_hash=" << hashState_;
    status = qualified.str();
}
EngineContext ContextObserver::sample() const {
    if (base && layout) {
        // A row may know an address without knowing the member offsets that make
        // it decodable. Gate on the capability, not on the address being non-zero.
        auto playerGlobal = hasPlayer(*layout) ? base + layout->playerRva : 0;
        auto uiGlobal = hasMenus(*layout) ? base + layout->uiRva : 0;
        return readContext(target, *layout, playerGlobal, uiGlobal, base, size);
    }
    EngineContext result; result.status = status; return result;
}
} // namespace fs
