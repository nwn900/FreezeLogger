// Fuzz entry for the Buffout 4 crash-log parser (src/buffout.hpp).
//
// libFuzzer mode (Clang -fsanitize=fuzzer): defines FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION.
// Standalone mode (any compiler, default): runs embedded hostile cases plus every
// file in an optional corpus directory argument. Both modes share the parser.
#include "../src/buffout.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {
int runOne(const std::string& text) {
    volatile fs::BuffoutCrashInfo info = fs::parseBuffoutCrashLog(text);
    (void)info;
    return 0;
}
} // namespace

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return runOne(std::string(reinterpret_cast<const char*>(data), size));
}
#else
#include <filesystem>
#include <iostream>
int main(int argc, char** argv) {
    std::vector<std::string> cases = {
        {},
        "Unhandled exception",
        "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION",
        "Unhandled exception \"\" at 0x DLL.dll+0x",
        std::string(100000, 'A'),
        std::string("Unhandled exception \"X\" at 0x") + std::string(64, 'F') + " M.dll+0x1\n",
        "PROBABLE CALL STACK:\n[0] 0x1 (A.dll+0x1)\n[1] 0x2 (B.DLL+0X2)\n[bad line\n[2] 0x3\n",
        std::string([] {
            static constexpr char embedded[] = "x\0y\nUnhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 Z.dll+0x1\n";
            return embedded;
        }(), sizeof("x\0y\nUnhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 Z.dll+0x1\n") - 1),
        std::string("Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0xFFFFFFFFFFFFFFFFF Overflow.dll+0x1\n"),
        std::string("Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 My Plugin.dll+0x2\n"),
        "Unhandled exception \"EXCEPTION_ACCESS_VIOLATION\" at 0x10 C:\\P\\Q.dll+0x1\r\n"
        "PROBABLE CALL STACK:\r\n[0] 0x10 (Q.dll+0x1)\r\n",
    };
    if (argc > 1) {
        std::error_code error;
        for (const auto& file : std::filesystem::directory_iterator(argv[1], error)) {
            if (error || !file.is_regular_file()) continue;
            std::error_code sizeError;
            auto size = file.file_size(sizeError);
            if (sizeError || size > 4 * 1024 * 1024) continue;
            FILE* handle = nullptr;
            if (_wfopen_s(&handle, file.path().c_str(), L"rb") != 0 || !handle) continue;
            std::string text(static_cast<std::size_t>(size), '\0');
            std::size_t read = fread(text.data(), 1, text.size(), handle);
            fclose(handle);
            text.resize(read);
            cases.push_back(std::move(text));
        }
    }
    for (const auto& text : cases) runOne(text);
    std::cout << "PASS: buffout parser fuzz smoke (" << cases.size() << " cases, no crash)\n";
    return 0;
}
#endif
