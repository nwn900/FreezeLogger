#include "history.hpp"
#include <sstream>
#include <algorithm>
namespace fs {
void History::add(std::string text) {
    if (text.size() > 65536) { text.resize(65536); text += "\nsample truncated\n"; }
    bytes += text.size(); samples.push_back({now(), std::move(text)});
    while (!samples.empty() && (samples.front().tick < now() - window || bytes > 2 * 1024 * 1024)) {
        bytes -= samples.front().text.size(); samples.pop_front();
    }
}
std::string History::text() const {
    std::ostringstream out;
    out << "\nPREINCIDENT_HISTORY window_ms=" << window << " samples=" << samples.size() << '\n';
    for (const auto& entry : samples) if (entry.tick >= now() - window) out << entry.text;
    return out.str();
}
std::string eventHistory(Shared* state, LONG64 after) {
    if (!state) return {};
    std::ostringstream out;
    auto count = read(state->eventCount);
    out << "\nEVENT_HISTORY published=" << count << " dropped_concurrent=" << read(state->eventsDropped)
        << " oldest_retained_id=" << std::max<LONG64>(1, count - 127) << '\n';
    const char* names[]{"PostLoad", "PostPostLoad", "PreLoadGame", "PostLoadGame", "PreSaveGame", "PostSaveGame",
        "DeleteGame", "InputLoaded", "NewGame", "GameLoaded", "GameDataReady"};
    for (auto id = std::max<LONG64>(after + 1, std::max<LONG64>(1, count - 127)); id <= count; ++id) {
        auto& slot = state->events[(id - 1) % 128]; auto sequence = read(slot.sequence);
        if (sequence & 1) continue;
        auto entry = slot.data; MemoryBarrier();
        if (sequence != read(slot.sequence) || entry.id != id) { out << "event_overwritten id=" << id << '\n'; continue; }
        entry.data.source[95] = 0; entry.data.name[159] = 0; entry.data.plugin[95] = 0;
        const auto& data = entry.data;
        out << "event_id=" << id << " tick=" << entry.tick << " thread=" << entry.thread
            << " source=" << data.source << " kind=" << static_cast<DWORD>(data.kind);
        if (data.kind == EventKind::F4SE && data.value < 11) out << " operation=" << names[data.value];
        out << " form=0x" << std::hex << data.form << " related_form=0x" << data.relatedForm << std::dec
            << " value=" << data.value << " flags=" << data.flags << " name=" << data.name << " plugin=" << data.plugin << '\n';
    }
    out << "Cell/menu/mod fields from optional adapters are provider observations; presence does not prove causality.\n";
    return out.str();
}
}
