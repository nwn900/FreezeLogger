#pragma once
#include <cstdint>

// Optional native adapters copy values while their own runtime contracts are valid.
// UTF-8 fields are inline, bounded, and must be terminated. No engine pointers.
namespace fs {
enum class EventKind : std::uint32_t { Cell = 1, MenuOpen, MenuClose, TravelBegin, TravelEnd, LoadBegin, LoadEnd, SaveBegin, SaveEnd, Marker, F4SE = 100 };
struct EventData {
    std::uint32_t size = sizeof(EventData), version = 1;
    EventKind kind = EventKind::Marker;
    std::uint32_t form = 0, relatedForm = 0, flags = 0;
    std::uint64_t value = 0;
    char source[96]{}, name[160]{}, plugin[96]{};
};
using RecordEvent = bool (*)(const EventData*);
using FramePulse = bool (*)();
static_assert(sizeof(EventData) == 384);
}
