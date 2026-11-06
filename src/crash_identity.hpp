#pragma once
#include <cstdint>
#include <string>

namespace fs {
struct CrashModuleIdentity {
    std::uint64_t base = 0, size = 0;
    std::string basename;
};
struct ProcessExceptionIdentity {
    std::uint32_t code = 0;
    std::uint64_t address = 0, fileTime = 0;
};
}
