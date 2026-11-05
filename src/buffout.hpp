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
#include <vector>

namespace fs {
struct BuffoutCrashInfo {
    bool found = false; // A fault line was recognized.
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
    std::size_t digits = 0;
    while (at < text.size() && digits < 16) {
        char c = text[at];
        unsigned digit = c >= '0' && c <= '9' ? static_cast<unsigned>(c - '0')
            : c >= 'a' && c <= 'f' ? static_cast<unsigned>(c - 'a' + 10)
            : c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10)
            : 256u;
        if (digit > 15) break;
        result = result * 16 + digit;
        ++at;
        ++digits;
    }
    if (!digits) return false;
    value = result;
    return true;
}
// Finds the first image token (.dll/.exe/.asi, any case) at or after `from`
// and returns its lowercase basename. Empty when absent.
inline std::string imageAfter(const std::string& line, std::size_t from) {
    static const char* extensions[] = {".dll", ".exe", ".asi"};
    for (std::size_t i = from; i < line.size(); ++i) {
        for (const char* extension : extensions) {
            std::size_t length = 4;
            if (i + length > line.size()) continue;
            bool match = true;
            for (std::size_t k = 0; k < length; ++k)
                if (std::tolower(static_cast<unsigned char>(line[i + k])) != extension[k]) { match = false; break; }
            if (!match) continue;
            std::size_t end = i;
            while (end > 0) {
                char c = line[end - 1];
                if (c == '\\' || c == '/' || c == ':' || c == '"' || c == '\'' || c == ' ' || c == '\t' ||
                    c == '(' || c == '[' || c == '<' || c == '|') break;
                --end;
            }
            if (end >= i) continue;
            return lower(line.substr(end, i - end + length));
        }
    }
    return {};
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
                        info.faultModule = buffout::imageAfter(line, digits);
                        std::size_t plus = line.find('+', digits);
                        if (plus != std::string::npos) {
                            std::size_t offset = plus + 1;
                            if (line.compare(offset, 2, "0x") == 0 || line.compare(offset, 2, "0X") == 0) offset += 2;
                            std::uint64_t value = 0;
                            if (buffout::parseHex(line, offset, value)) {
                                std::ostringstream out;
                                out << "0x" << std::hex << value;
                                info.faultOffset = out.str();
                            }
                        }
                    }
                } else {
                    info.faultModule = buffout::imageAfter(line, marker);
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
            std::string module = buffout::imageAfter(line, 0);
            if (!module.empty() && info.stackModules.size() < 16) info.stackModules.push_back(module);
            if (info.stackModules.size() >= 16) inStack = false;
        }
    }
    if (!info.found) return BuffoutCrashInfo{};
    info.sourcePath = sourcePath;
    return info;
}
} // namespace fs
