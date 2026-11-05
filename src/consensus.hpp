// Pure thread-group consensus rule for freeze reports.
//
// A stable-RIP group (3+ samples with repeats, 4+ threads including a callback
// thread) suggests a synchronization stall. Threads parked with zero CPU inside
// system images are OS idle surface, not evidence, and are excluded; a zero-CPU
// wait inside a non-system image still counts. Pure C++ for unit tests.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fs {
struct ConsensusThread {
    std::uint32_t id = 0;
    std::string module; // Lowercase basename of the stable sampled RIP module.
    unsigned samples = 0;
    unsigned repeats = 0; // Unchanged-RIP transitions across samples.
    unsigned long long cpuDelta = 0; // Total thread CPU across the sampled window.
    bool isCallback = false;
};
struct GroupConsensus {
    bool present = false;
    std::string module;
    unsigned matching = 0;
};
inline GroupConsensus threadGroupConsensus(const std::vector<ConsensusThread>& threads,
                                           bool (*isSystemImage)(const std::string&)) {
    std::map<std::string, std::pair<unsigned, bool>> groups;
    for (const auto& thread : threads) {
        if (thread.module.empty() || thread.samples < 3 || !thread.repeats) continue;
        if (!thread.cpuDelta && isSystemImage(thread.module)) continue;
        auto& group = groups[thread.module];
        ++group.first;
        group.second = group.second || thread.isCallback;
    }
    GroupConsensus best;
    for (const auto& [module, group] : groups)
        if (group.first >= 4 && group.second && group.first > best.matching) best = {true, module, group.first};
    return best;
}
} // namespace fs
