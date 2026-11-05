#include "context.hpp"
#include <psapi.h>
#include <array>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <set>

namespace fs {
namespace {
constexpr ULONG64 playerRva = 0x05AA4388, uiRva = 0x058D0898;
constexpr char qualifiedSHA[] = "55f57947db9e05575122fae1088f0b0247442f11e566b56036caa0ac93329c36";
struct Reader {
    HANDLE process;
    ULONG64 base;
    DWORD size;
    bool bytes(ULONG64 address, void* output, size_t count) const {
        SIZE_T got = 0;
        return address >= 0x10000 && address <= 0x00007fffffff0000ULL && count <= 1024 * 1024 &&
            count <= 0x00007fffffff0000ULL - address &&
            ReadProcessMemory(process, reinterpret_cast<void*>(address), output, count, &got) && got == count;
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
struct Array { ULONG64 entries; DWORD capacity, padding, count, padding2; };
struct Table { ULONG64 unknown; DWORD unknown2, size, free, freeOffset; ULONG64 sentinel, unknown3, entries; };
struct Menu { ULONG64 name, instance, constructor, unknown, next; };
static_assert(sizeof(Array) == 0x18 && sizeof(Table) == 0x30 && sizeof(Menu) == 0x28);
EngineContext once(const Reader& read, ULONG64 playerGlobal, ULONG64 uiGlobal) {
    EngineContext result;
    ULONG64 player = 0, cell = 0, ui = 0;
    if (read.get(playerGlobal, player) && (!player || (read.object(player) && read.get(player + 0xB8, cell)))) {
        if (!cell) { result.cellValid = true; }
        else {
            BYTE type = 0; ULONG64 name = 0, source = 0;
            if (read.object(cell) && read.get(cell + 0x1A, type) && type == 63 &&
                read.get(cell + 0x14, result.cell) && read.get(cell + 0x28, name) && read.fixed(name, result.cellName) &&
                read.get(cell + 8, source)) {
                result.cellValid = true;
                result.origin = (result.cell >> 24) == 0xFF ? "dynamic form" : "not resolved";
                struct Sources { ULONG64 entries, count; } sources{};
                if (source && read.get(source, sources) && sources.count <= 64) {
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
    if (read.get(uiGlobal, ui)) {
        if (!ui) result.menusValid = true;
        else if (read.object(ui)) {
            Array stack{}; Table table{};
            if (read.get(ui + 0x190, stack) && read.get(ui + 0x1A8, table) && stack.count <= stack.capacity &&
                stack.count <= 128 && table.size <= 2048 && table.free <= table.size) {
                std::vector<ULONG64> active(stack.count);
                std::vector<Menu> entries(table.size);
                if ((!stack.count || read.bytes(stack.entries, active.data(), active.size() * 8)) &&
                    (!table.size || read.bytes(table.entries, entries.data(), entries.size() * sizeof(Menu)))) {
                    result.menusValid = true;
                    for (auto instance : active) {
                        auto found = std::find_if(entries.begin(), entries.end(), [instance](const Menu& menu) {
                            return menu.next && instance && menu.instance == instance;
                        });
                        std::string name;
                        if (found == entries.end() || !read.fixed(found->name, name) || name.empty()) { result.menusValid = false; break; }
                        result.menus.push_back(name);
                    }
                }
            }
        }
    }
    result.status = result.cellValid && result.menusValid ? "sample readable" : "context partially unavailable; no transition inferred for missing fields";
    return result;
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
EngineContext readContext163(HANDLE target, ULONG64 playerGlobal, ULONG64 uiGlobal, ULONG64 base, DWORD imageSize) {
    Reader reader{target, base, imageSize};
    auto first = once(reader, playerGlobal, uiGlobal), second = once(reader, playerGlobal, uiGlobal);
    if (first == second) return second;
    EngineContext unavailable; unavailable.status = "changed during two reads; sample discarded"; return unavailable;
}
ContextObserver::ContextObserver(HANDLE process, DWORD runtime, bool enabled) : target(process) {
    status = "disabled or unsupported runtime/image; generic F4SE history remains available";
    if (!enabled || runtime != 0x010A0A30) return;
    std::array<wchar_t, 32768> path{}; DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(target, 0, path.data(), &length) ||
        _wcsicmp(std::filesystem::path(path.data()).filename().c_str(), L"Fallout4.exe") || diskSHA256(path.data()) != qualifiedSHA) return;
    HMODULE image = nullptr; DWORD needed = 0; MODULEINFO info{};
    if (!EnumProcessModulesEx(target, &image, sizeof(image), &needed, LIST_MODULES_64BIT) ||
        !GetModuleInformation(target, image, &info, sizeof(info))) return;
    auto imageBase = reinterpret_cast<ULONG64>(info.lpBaseOfDll);
    Reader reader{target, imageBase, info.SizeOfImage};
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{};
    if (!reader.get(imageBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 64 || dos.e_lfanew > 4096 ||
        !reader.get(imageBase + dos.e_lfanew, nt) || nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt.OptionalHeader.SizeOfImage != info.SizeOfImage ||
        nt.FileHeader.TimeDateStamp != 0x5DDC40FA || info.SizeOfImage != 0x06CE6000 ||
        info.SizeOfImage < playerRva + 8 || !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > 96) return;
    auto inData = [&](ULONG64 rva) {
        for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER section{};
            if (!reader.get(imageBase + dos.e_lfanew + 24 + nt.FileHeader.SizeOfOptionalHeader + i * sizeof(section), section)) return false;
            if (rva >= section.VirtualAddress && rva + 8 <= static_cast<ULONG64>(section.VirtualAddress) + section.Misc.VirtualSize)
                return (section.Characteristics & IMAGE_SCN_MEM_READ) && !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        }
        return false;
    };
    if (!inData(playerRva) || !inData(uiRva)) return;
    base = imageBase; size = info.SizeOfImage;
    status = "Fallout4 1.10.163 read-only adapter enabled; exact on-disk SHA256 matched; loaded PE/data globals validated";
}
EngineContext ContextObserver::sample() const {
    if (base) return readContext163(target, base + playerRva, base + uiRva, base, size);
    EngineContext result; result.status = status; return result;
}
}
