// Tolerant parser for Buffout 4 crash logs (FO4: Documents/My Games/Fallout4/F4SE).
//
// Supported stable markers (anything else is ignored):
//   Unhandled exception "NAME" at 0xADDR Module.dll+0xOFF
//   PROBABLE CALL STACK: followed by [N] 0xADDR Module.dll+0xOFF lines
// All module basenames are lowercased for comparison. Never throws on hostile
// input; designed to be fuzzed. Pure C++ (no OS headers) so libFuzzer and unit
// tests share this exact code.
#pragma once
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "crash_identity.hpp"

namespace fs {
struct BuffoutCrashInfo {
    bool found = false; // A fault line was recognized.
    enum class Edition : unsigned char { Unknown, Fallout4, Fallout4VR };
    Edition edition = Edition::Unknown;
    std::string gameVersion;
    std::string exceptionName;
    std::uint32_t exceptionCode = 0;
    std::uint64_t faultAddress = 0;
    std::string faultModule; // Lowercase basename, may be empty when unparseable.
    std::string faultOffset;
    std::vector<std::string> stackModules; // Lowercase basenames, top frame first.
    std::string sourcePath;
};
namespace buffout {
inline std::string lower(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
inline std::string trim(const std::string& line) {
    std::size_t first = 0, last = line.size();
    while (first < last && (line[first] == ' ' || line[first] == '\t' || line[first] == '\r')) ++first;
    while (last > first && (line[last - 1] == ' ' || line[last - 1] == '\t' || line[last - 1] == '\r')) --last;
    return line.substr(first, last - first);
}
// Parses up to 16 hex digits; returns false on empty/invalid input or overflow.
inline bool parseHex(const std::string& text, std::size_t& at, std::uint64_t& value) {
    std::uint64_t result = 0;
    std::size_t cursor = at;
    std::size_t digits = 0;
    while (cursor < text.size() && digits < 16) {
        char c = text[cursor];
        unsigned digit = c >= '0' && c <= '9' ? static_cast<unsigned>(c - '0')
            : c >= 'a' && c <= 'f' ? static_cast<unsigned>(c - 'a' + 10)
            : c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10)
            : 256u;
        if (digit > 15) break;
        result = result * 16 + digit;
        ++cursor;
        ++digits;
    }
    if (!digits) return false;
    if (cursor < text.size()) {
        char c = text[cursor];
        bool extraHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (extraHex) return false;
    }
    at = cursor;
    value = result;
    return true;
}
struct ModuleField {
    std::string basename;
    std::string offset;
};
inline ModuleField moduleFieldAfter(const std::string& line, std::size_t from) {
    static const char* extensions[] = {".dll", ".exe", ".asi"};
    while (from < line.size() && (line[from] == ' ' || line[from] == '\t' || line[from] == '(' ||
                                   line[from] == '[' || line[from] == '"' || line[from] == '\'')) ++from;
    std::size_t limit = line.size();
    while (limit > from && (line[limit - 1] == ' ' || line[limit - 1] == '\t' || line[limit - 1] == ')' ||
                            line[limit - 1] == ']' || line[limit - 1] == '"' || line[limit - 1] == '\'')) --limit;
    ModuleField result;
    std::size_t moduleEnd = 0;
    std::size_t offsetStart = 0;
    std::size_t offsetEnd = 0;
    for (std::size_t i = from; i < line.size(); ++i) {
        for (const char* extension : extensions) {
            std::size_t length = 4;
            if (i + length > line.size()) continue;
            bool match = true;
            for (std::size_t k = 0; k < length; ++k)
                if (std::tolower(static_cast<unsigned char>(line[i + k])) != extension[k]) { match = false; break; }
            if (!match) continue;
            std::size_t end = i + length;
            std::size_t suffix = end;
            while (suffix < limit && (line[suffix] == ' ' || line[suffix] == '\t')) ++suffix;
            std::size_t candidateOffsetStart = 0, candidateOffsetEnd = 0;
            if (suffix < limit && line[suffix] == '+') {
                candidateOffsetStart = suffix + 1;
                if (line.compare(candidateOffsetStart, 2, "0x") == 0 || line.compare(candidateOffsetStart, 2, "0X") == 0)
                    candidateOffsetStart += 2;
                std::size_t cursor = candidateOffsetStart;
                std::uint64_t ignored = 0;
                if (!parseHex(line, cursor, ignored)) continue;
                if (cursor < limit && line[cursor] != ' ' && line[cursor] != '\t' && line[cursor] != ')' &&
                    line[cursor] != ']' && line[cursor] != '"' && line[cursor] != '\'') continue;
                candidateOffsetEnd = cursor;
            } else if (suffix != limit) {
                continue;
            }
            std::size_t begin = from;
            for (std::size_t cursor = from; cursor < i; ++cursor)
                if (line[cursor] == '\\' || line[cursor] == '/') begin = cursor + 1;
            while (begin < i && (line[begin] == ' ' || line[begin] == '\t' || line[begin] == '"' ||
                                 line[begin] == '\'' || line[begin] == '(' || line[begin] == '[')) ++begin;
            if (begin >= end) continue;
            moduleEnd = end;
            offsetStart = candidateOffsetStart;
            offsetEnd = candidateOffsetEnd;
            result.basename = lower(line.substr(begin, moduleEnd - begin));
        }
    }
    if (result.basename.empty()) return {};
    if (offsetEnd > offsetStart) {
        std::size_t cursor = offsetStart;
        std::uint64_t value = 0;
        if (parseHex(line, cursor, value) && cursor == offsetEnd) {
            std::ostringstream formatted;
            formatted << "0x" << std::hex << value;
            result.offset = formatted.str();
        }
    }
    return result;
}
inline std::string imageAfter(const std::string& line, std::size_t from) {
    return moduleFieldAfter(line, from).basename;
}
inline std::string normalizeVersion(std::string value) {
    value = trim(value);
    while (value.size() > 1 && value.ends_with(".0")) value.resize(value.size() - 2);
    return value;
}
inline std::uint32_t exceptionCodeFor(const std::string& name) {
    std::string upper = name;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (upper == "EXCEPTION_ACCESS_VIOLATION") return 0xC0000005u;
    if (upper == "EXCEPTION_ILLEGAL_INSTRUCTION") return 0xC000001Du;
    if (upper == "EXCEPTION_INT_DIVIDE_BY_ZERO") return 0xC0000094u;
    if (upper == "EXCEPTION_STACK_OVERFLOW") return 0xC00000FDu;
    if (upper == "STATUS_BREAKPOINT" || upper == "EXCEPTION_BREAKPOINT") return 0x80000003u;
    if (upper == "CPP_EXCEPTION" || upper == "EXCEPTION_CPP" || upper == "E06D7363") return 0xE06D7363u;
    return 0;
}
} // namespace buffout

inline BuffoutCrashInfo parseBuffoutCrashLog(const std::string& text, const std::string& sourcePath = {}) {
    BuffoutCrashInfo info;
    bool inStack = false;
    std::size_t at = 0;
    while (at <= text.size()) {
        std::size_t end = text.find('\n', at);
        if (end == std::string::npos) end = text.size();
        std::string line = buffout::trim(text.substr(at, end - at));
        at = end + 1;
        if (line.size() > 4096) continue; // Hostile line; markers never need more.
        std::string lowerLine = buffout::lower(line);
        const std::pair<const char*, BuffoutCrashInfo::Edition> editions[]{
            {"fallout 4 vr v", BuffoutCrashInfo::Edition::Fallout4VR},
            {"fallout4vr v", BuffoutCrashInfo::Edition::Fallout4VR},
            {"fallout 4 v", BuffoutCrashInfo::Edition::Fallout4},
            {"fallout4 v", BuffoutCrashInfo::Edition::Fallout4},
        };
        for (const auto& [prefix, edition] : editions) {
            std::size_t prefixSize = std::char_traits<char>::length(prefix);
            if (lowerLine.starts_with(prefix)) {
                info.edition = edition;
                info.gameVersion = buffout::trim(line.substr(prefixSize));
                break;
            }
        }
        if (!info.found) {
            std::size_t marker = line.find("Unhandled exception");
            if (marker != std::string::npos) {
                std::size_t open = line.find('"', marker);
                std::size_t close = open == std::string::npos ? open : line.find('"', open + 1);
                if (open != std::string::npos && close != std::string::npos && close > open + 1) {
                    info.exceptionName = line.substr(open + 1, close - open - 1);
                    info.exceptionCode = buffout::exceptionCodeFor(info.exceptionName);
                }
                std::size_t address = line.find("0x", close == std::string::npos ? marker : close);
                if (address == std::string::npos) address = line.find("0X", close == std::string::npos ? marker : close);
                if (address != std::string::npos) {
                    std::size_t digits = address + 2;
                    if (buffout::parseHex(line, digits, info.faultAddress)) {
                        auto module = buffout::moduleFieldAfter(line, digits);
                        info.faultModule = std::move(module.basename);
                        info.faultOffset = std::move(module.offset);
                    }
                } else if (close != std::string::npos) {
                    info.faultModule = buffout::imageAfter(line, close + 1);
                }
                if (!info.exceptionName.empty() || info.faultAddress || !info.faultModule.empty()) info.found = true;
                continue;
            }
        }
        if (line == "PROBABLE CALL STACK:") { inStack = true; continue; }
        if (inStack) {
            if (line.empty() || line[0] != '[') {
                if (!info.stackModules.empty()) inStack = false;
                continue;
            }
            std::size_t address = line.find("0x");
            if (address == std::string::npos) address = line.find("0X");
            std::size_t moduleStart = address == std::string::npos ? line.size() : address + 2;
            std::uint64_t ignoredAddress = 0;
            if (address != std::string::npos && !buffout::parseHex(line, moduleStart, ignoredAddress)) continue;
            std::string module = address == std::string::npos ? std::string{} : buffout::imageAfter(line, moduleStart);
            if (!module.empty() && info.stackModules.size() < 16) info.stackModules.push_back(module);
            if (info.stackModules.size() >= 16) inStack = false;
        }
    }
    if (!info.found) return BuffoutCrashInfo{};
    info.sourcePath = sourcePath;
    return info;
}

struct CrashLogSession {
    BuffoutCrashInfo::Edition edition = BuffoutCrashInfo::Edition::Unknown;
    std::string gameVersion;
    std::uint64_t processStartedFileTime = 0;
    std::uint64_t observedFileTime = 0;
    std::uint64_t maximumAgeMs = 5 * 60 * 1000;
};
struct CrashLogMatch {
    bool candidate = false;
    std::uint64_t ageMs = 0;
    std::string reason;
};

// Filters crash-log candidates by metadata and age. It cannot establish which
// process wrote the file, so a candidate alone never counts as a process match.
class CrashLogCorrelator final {
public:
    explicit CrashLogCorrelator(CrashLogSession session) : session_(std::move(session)) {}

    CrashLogMatch assess(const BuffoutCrashInfo& crash, std::uint64_t writtenFileTime) const {
        if (!crash.found) return {false, 0, "not-a-crash-log"};
        if (session_.edition == BuffoutCrashInfo::Edition::Unknown ||
            crash.edition == BuffoutCrashInfo::Edition::Unknown) return {false, 0, "game-edition-unknown"};
        if (crash.edition != session_.edition) return {false, 0, "game-edition-mismatch"};
        if (session_.gameVersion.empty() || session_.gameVersion == "unavailable" || crash.gameVersion.empty())
            return {false, 0, "game-version-unknown"};
        if (buffout::normalizeVersion(crash.gameVersion) != buffout::normalizeVersion(session_.gameVersion))
            return {false, 0, "game-version-mismatch"};
        if (!session_.processStartedFileTime || writtenFileTime < session_.processStartedFileTime)
            return {false, 0, "before-process-start"};
        constexpr std::uint64_t futureSkew = 30ULL * 10000000ULL;
        if (writtenFileTime > session_.observedFileTime && writtenFileTime - session_.observedFileTime > futureSkew)
            return {false, 0, "future-file-time"};
        std::uint64_t age = session_.observedFileTime > writtenFileTime
            ? (session_.observedFileTime - writtenFileTime) / 10000ULL : 0;
        if (age > session_.maximumAgeMs) return {false, age, "outside-session-correlation-window"};
        return {true, age, "same-edition-version-and-time-candidate"};
    }
private:
    CrashLogSession session_;
};

struct CrashIncidentMatch {
    bool corroborated = false;
    std::uint64_t deltaMs = 0;
    std::string reason;
};

// Requires an exact first-chance exception and a loaded image identity from
// this process before a time-compatible log can support incident attribution.
class CrashIncidentCorrelator final {
public:
    CrashIncidentMatch assess(const BuffoutCrashInfo& crash, std::uint64_t logFileTime,
                              const std::vector<ProcessExceptionIdentity>& exceptions,
                              const std::vector<CrashModuleIdentity>& modules) const {
        if (!crash.found || !crash.exceptionCode || !crash.faultAddress || crash.faultModule.empty() ||
            crash.faultOffset.empty()) return {false, 0, "crash-identity-incomplete"};
        std::size_t cursor = crash.faultOffset.starts_with("0x") || crash.faultOffset.starts_with("0X") ? 2 : 0;
        std::uint64_t expectedOffset = 0;
        if (!buffout::parseHex(crash.faultOffset, cursor, expectedOffset) || cursor != crash.faultOffset.size())
            return {false, 0, "crash-offset-invalid"};
        constexpr std::uint64_t maximumDelta100ns = 5ULL * 60ULL * 1000ULL * 10000ULL;
        for (const auto& exception : exceptions) {
            if (exception.code != crash.exceptionCode || exception.address != crash.faultAddress || !exception.fileTime)
                continue;
            const auto delta = logFileTime >= exception.fileTime
                ? logFileTime - exception.fileTime : exception.fileTime - logFileTime;
            if (delta > maximumDelta100ns) continue;
            for (const auto& module : modules) {
                if (exception.address < module.base || exception.address - module.base >= module.size ||
                    buffout::lower(module.basename) != crash.faultModule ||
                    exception.address - module.base != expectedOffset) continue;
                return {true, delta / 10000ULL, "exact-current-process-exception-and-loaded-module"};
            }
        }
        return {false, 0, "no-matching-current-process-exception-and-loaded-module"};
    }
};
} // namespace fs
