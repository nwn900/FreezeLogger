#pragma once
#include <cstddef>
#include <cstdint>

// Public F4SE ABI prefix only. No Bethesda classes, functions or addresses.
namespace fs {
struct Host {
    std::uint32_t extenderVersion, runtimeVersion, editorVersion, isEditor;
    void* (*query)(std::uint32_t);
    std::uint32_t (*handle)();
};
struct Info { std::uint32_t version; const char* name; std::uint32_t pluginVersion; };
struct Message { const char* sender; std::uint32_t type, length; void* data; };
struct Messaging {
    std::uint32_t version;
    bool (*listen)(std::uint32_t, const char*, void (*)(Message*));
};
struct Scaleform {
    std::uint32_t version;
    bool (*registerCallback)(const char*, bool (*)(void*, void*));
};
struct Task { virtual ~Task() = default; virtual void Run() = 0; };
struct Tasks {
    std::uint32_t version;
    void (*add)(Task*);
    void (*addUI)(Task*);
};
struct Version {
    std::uint32_t dataVersion, pluginVersion;
    char name[256], author[256];
    std::uint32_t addressIndependence, structureIndependence;
    std::uint32_t compatibleVersions[16], requiredExtender, reservedNonBreaking, reservedBreaking;
    std::uint8_t reserved[512];
};
static_assert(offsetof(Host, query) == 16 && offsetof(Tasks, add) == 8);
static_assert(sizeof(Version) == 1116 && offsetof(Version, compatibleVersions) == 528);
inline constexpr std::uint32_t messagingID = 1, scaleformID = 2, taskID = 5;
}
