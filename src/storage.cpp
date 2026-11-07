#include "shared.hpp"
#include <dbghelp.h>
#include <algorithm>
#include <vector>
#include <regex>
#include <cstring>
#include <set>
#include <map>

namespace fs {
bool validateDump(const std::filesystem::path& path, std::string& reason) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    LARGE_INTEGER size{};
    if (file.value == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) || size.QuadPart < sizeof(MINIDUMP_HEADER)) {
        reason = "missing/truncated header"; return false;
    }
    Handle mapping(CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr));
    auto* data = static_cast<const BYTE*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!data) { reason = "mapping unavailable"; return false; }
    struct Unmap { const void* p; ~Unmap() { UnmapViewOfFile(p); } } unmap{data};
    auto bound = [size](ULONG64 offset, ULONG64 bytes) {
        return offset <= static_cast<ULONG64>(size.QuadPart) && bytes <= static_cast<ULONG64>(size.QuadPart) - offset;
    };
    auto location = [&bound](MINIDUMP_LOCATION_DESCRIPTOR value) { return bound(value.Rva, value.DataSize); };
    MINIDUMP_HEADER header{}; memcpy(&header, data, sizeof(header));
    if (header.Signature != MINIDUMP_SIGNATURE || (header.Version & 0xffff) != MINIDUMP_VERSION ||
        !header.NumberOfStreams || header.NumberOfStreams > 4096 ||
        !bound(header.StreamDirectoryRva, static_cast<ULONG64>(header.NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY))) {
        reason = "invalid header/directory"; return false;
    }
    bool threads = false, modules = false, system = false, memory64 = false;
    for (ULONG i = 0; i < header.NumberOfStreams; ++i) {
        MINIDUMP_DIRECTORY directory{};
        memcpy(&directory, data + header.StreamDirectoryRva + i * sizeof(directory), sizeof(directory));
        auto loc = directory.Location;
        if (!location(loc)) { reason = "stream outside file"; return false; }
        if (directory.StreamType == ThreadListStream || directory.StreamType == ModuleListStream || directory.StreamType == MemoryListStream) {
            ULONG count = 0;
            if (loc.DataSize < sizeof(count)) { reason = "missing list count"; return false; }
            memcpy(&count, data + loc.Rva, sizeof(count));
            size_t stride = directory.StreamType == ThreadListStream ? sizeof(MINIDUMP_THREAD) :
                directory.StreamType == ModuleListStream ? sizeof(MINIDUMP_MODULE) : sizeof(MINIDUMP_MEMORY_DESCRIPTOR);
            if (count > 65536 || static_cast<ULONG64>(count) * stride > loc.DataSize - sizeof(count)) {
                reason = "truncated list"; return false;
            }
            if (directory.StreamType == ThreadListStream) {
                if (threads || !count) { reason = "empty/duplicate threads"; return false; }
                threads = true;
                for (ULONG n = 0; n < count; ++n) {
                    MINIDUMP_THREAD thread{}; memcpy(&thread, data + loc.Rva + sizeof(count) + n * stride, sizeof(thread));
                    if (!location(thread.ThreadContext) || thread.ThreadContext.DataSize < sizeof(CONTEXT) ||
                        !location(thread.Stack.Memory)) { reason = "thread context/stack outside file"; return false; }
                    DWORD flags = 0;
                    memcpy(&flags, data + thread.ThreadContext.Rva + offsetof(CONTEXT, ContextFlags), sizeof(flags));
                    if ((flags & CONTEXT_CONTROL) != CONTEXT_CONTROL) { reason = "thread control context absent"; return false; }
                }
            } else if (directory.StreamType == ModuleListStream) {
                if (modules || !count) { reason = "empty/duplicate modules"; return false; }
                modules = true;
                for (ULONG n = 0; n < count; ++n) {
                    MINIDUMP_MODULE module{}; memcpy(&module, data + loc.Rva + sizeof(count) + n * stride, sizeof(module));
                    if (!location(module.CvRecord) || !location(module.MiscRecord) || !bound(module.ModuleNameRva, 4)) {
                        reason = "module metadata outside file"; return false;
                    }
                    ULONG bytes = 0; memcpy(&bytes, data + module.ModuleNameRva, 4);
                    if ((bytes & 1) || !bound(static_cast<ULONG64>(module.ModuleNameRva) + 4, bytes)) {
                        reason = "invalid module name"; return false;
                    }
                }
            } else for (ULONG n = 0; n < count; ++n) {
                MINIDUMP_MEMORY_DESCRIPTOR memory{}; memcpy(&memory, data + loc.Rva + sizeof(count) + n * stride, sizeof(memory));
                if (!location(memory.Memory)) { reason = "memory outside file"; return false; }
            }
        } else if (directory.StreamType == SystemInfoStream) {
            if (system || loc.DataSize < sizeof(MINIDUMP_SYSTEM_INFO)) { reason = "invalid system info"; return false; }
            MINIDUMP_SYSTEM_INFO info{}; memcpy(&info, data + loc.Rva, sizeof(info));
            if (info.ProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) { reason = "unexpected architecture"; return false; }
            system = true;
        } else if (directory.StreamType == Memory64ListStream) {
            if (memory64) { reason = "duplicate memory64 stream"; return false; }
            memory64 = true;
            if (loc.DataSize < 16) { reason = "truncated memory64 header"; return false; }
            ULONG64 count = 0, offset = 0;
            memcpy(&count, data + loc.Rva, 8); memcpy(&offset, data + loc.Rva + 8, 8);
            if (count > (loc.DataSize - 16) / sizeof(MINIDUMP_MEMORY_DESCRIPTOR64) || !bound(offset, 0)) {
                reason = "invalid memory64 list"; return false;
            }
            for (ULONG64 n = 0; n < count; ++n) {
                MINIDUMP_MEMORY_DESCRIPTOR64 memory{};
                memcpy(&memory, data + loc.Rva + 16 + n * sizeof(memory), sizeof(memory));
                if (!bound(offset, memory.DataSize)) { reason = "memory64 payload outside file"; return false; }
                offset += memory.DataSize;
            }
        }
    }
    if (!threads || !modules || !system) { reason = "required streams absent"; return false; }
    if ((header.Flags & MiniDumpWithFullMemory) && !memory64) { reason = "full memory stream absent"; return false; }
    reason = "header, directories, thread contexts/stacks, modules and memory bounds valid";
    return true;
}
void retain(const std::filesystem::path& folder, unsigned freezeLimit, unsigned manualLimit, unsigned storageMB,
            const std::filesystem::path& protectedFile) {
    DWORD attributes = GetFileAttributesW(folder.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return;
    struct File { std::filesystem::path path; std::uintmax_t size; std::filesystem::file_time_type time; bool dump; };
    std::vector<File> files;
    static const std::wregex owned(LR"(((freeze|manual|crash)-[0-9]{8}-[0-9]{6}-[0-9]{3}-[0-9]+\.(log|dmp|dmp\.partial)|(session|exit-evidence|prehang)-[0-9]+\.log|prehang-[0-9]+\.log\.partial|preflight-[0-9]+\.json))");
    std::error_code error;
    auto iterator = std::filesystem::directory_iterator(folder, error);
    const auto iteratorEnd = std::filesystem::directory_iterator{};
    for (; !error && iterator != iteratorEnd; iterator.increment(error)) {
        const auto& file = *iterator;
        auto path = file.path(); DWORD attr = GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
            !std::regex_match(path.filename().wstring(), owned)) continue;
        auto size = file.file_size(error); if (error) { error.clear(); continue; }
        auto time = file.last_write_time(error); if (error) { error.clear(); continue; }
        files.push_back({path, size, time, path.extension() == L".dmp" || path.extension() == L".partial"});
    }
    std::sort(files.begin(), files.end(), [](const File& a, const File& b) { return a.time < b.time; });
    std::vector<std::filesystem::path> freezeLogs, manualLogs;
    for (const auto& file : files)
        if (file.path.extension() == L".log") {
            auto name = file.path.filename().wstring();
            if (name.starts_with(L"freeze-") || name.starts_with(L"crash-")) freezeLogs.push_back(file.path);
            else if (name.starts_with(L"manual-")) manualLogs.push_back(file.path);
        }
    auto current = protectedFile.stem().wstring();
    auto pid = current.starts_with(L"session-") ? current.substr(8) : std::wstring{};
    // A live collector holds its session without FILE_SHARE_DELETE. Preserve all
    // its evidence, including captures, while another collector runs retention.
    std::set<std::wstring> activePids;
    for (const auto& file : files) {
        auto name = file.path.filename().wstring();
        if (!name.starts_with(L"session-")) continue;
        Handle deletionProbe(CreateFileW(file.path.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        auto code = GetLastError();
        if (deletionProbe.value == INVALID_HANDLE_VALUE && (code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED))
            activePids.insert(file.path.stem().wstring().substr(8));
    }
    struct LiveIncident { std::filesystem::file_time_type time; std::filesystem::path path; };
    std::map<std::wstring, LiveIncident> liveNewest;
    for (const auto& file : files) {
        auto name = file.path.filename().wstring();
        for (const auto& active : activePids) {
            if (!name.starts_with(L"freeze-") && !name.starts_with(L"manual-") && !name.starts_with(L"crash-")) continue;
            if (!name.ends_with(L"-" + active + L".log")) continue;
            auto found = liveNewest.find(active);
            if (found == liveNewest.end() || file.time > found->second.time)
                liveNewest[active] = {file.time, file.path};
        }
    }
    auto newestFreeze = freezeLogs.empty() ? std::filesystem::path{} : freezeLogs.back();
    auto newestManual = manualLogs.empty() ? std::filesystem::path{} : manualLogs.back();
    auto belongsToActiveCollector = [&](const std::filesystem::path& path) {
        const auto name = path.filename().wstring();
        for (const auto& active : activePids)
            if (name.ends_with(L"-" + active + L".log")) return true;
        return false;
    };
    auto protectedPath = [&](const std::filesystem::path& path) {
        auto name = path.filename().wstring();
        for (const auto& active : activePids) {
            if (name == L"session-" + active + L".log" || name == L"prehang-" + active + L".log" ||
                name == L"prehang-" + active + L".log.partial" || name == L"exit-evidence-" + active + L".log" ||
                name == L"preflight-" + active + L".json") return true;
            auto latest = liveNewest.find(active);
            if (latest != liveNewest.end()) {
                auto incident = latest->second.path;
                auto dump = incident; dump.replace_extension(".dmp");
                auto partial = dump; partial += ".partial";
                if (path == incident || path == dump || path == partial) return true;
            }
        }
        // A live session's newest incident is selected across both categories
        // above. Do not additionally pin an older manual log just because it is
        // the newest manual entry when a newer freeze report exists.
        bool categoryNewest = path == newestFreeze || path == newestManual;
        if (categoryNewest && belongsToActiveCollector(path)) {
            bool selectedForLiveSession = false;
            for (const auto& active : activePids) {
                auto latest = liveNewest.find(active);
                if (latest != liveNewest.end() && latest->second.path == path) {
                    selectedForLiveSession = true;
                    break;
                }
            }
            if (!selectedForLiveSession) categoryNewest = false;
        }
        return path == protectedFile || (!pid.empty() && (name == L"prehang-" + pid + L".log" ||
            name == L"prehang-" + pid + L".log.partial" || name == L"exit-evidence-" + pid + L".log" ||
            name == L"preflight-" + pid + L".json")) || categoryNewest;
    };
    auto pruneCategory = [&](std::vector<std::filesystem::path>& category, unsigned limit) {
        if (!limit) return;
        while (category.size() > limit) {
            auto dump = category.front();
            dump.replace_extension(".dmp");
            for (auto& file : files)
                if ((file.path == category.front() || file.path == dump) && !protectedPath(file.path)) {
                    if (std::filesystem::remove(file.path, error)) file.size = 0;
                }
            category.erase(category.begin());
        }
    };
    pruneCategory(freezeLogs, freezeLimit);
    pruneCategory(manualLogs, manualLimit);
    auto now = std::filesystem::file_time_type::clock::now();
    for (auto& file : files) if (file.path.extension() == L".partial" && !protectedPath(file.path) && now - file.time > std::chrono::hours(1)) {
        if (std::filesystem::remove(file.path, error)) file.size = 0;
    }
    std::uintmax_t total = 0; for (const auto& file : files) total += file.size;
    auto cap = static_cast<std::uintmax_t>(storageMB) * 1024 * 1024;
    if (!cap) return;
    for (bool dumps : {true, false}) for (auto& file : files) {
        if (total <= cap) return;
        if (file.dump != dumps || !file.size || protectedPath(file.path)) continue;
        if (std::filesystem::remove(file.path, error)) { total -= file.size; file.size = 0; }
    }
}
}
