// Unit tests for the thread-group consensus rule (src/consensus.hpp).
#include "../src/consensus.hpp"
#include <windows.h>
#include <iostream>

namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
bool systemImage(const std::string& module) { return module == "ntdll.dll" || module == "kernelbase.dll"; }
fs::ConsensusThread thread(std::uint32_t id, const char* module, unsigned long long cpu, bool callback) {
    fs::ConsensusThread thread;
    thread.id = id;
    thread.module = module;
    thread.samples = 3;
    thread.repeats = 2;
    thread.cpuDelta = cpu;
    thread.isCallback = callback;
    return thread;
}
} // namespace

int wmain() {
    {
        // The live 16:44 case: 174 threads parked with zero CPU in ntdll.
        std::vector<fs::ConsensusThread> parked;
        for (std::uint32_t id = 1; id <= 174; ++id) parked.push_back(thread(id, "ntdll.dll", 0, id == 7));
        fs::GroupConsensus consensus = fs::threadGroupConsensus(parked, systemImage);
        check(!consensus.present, "zero-CPU system parkers abstain");
    }
    {
        // Deadlock-style waits inside a mod DLL count even with zero CPU.
        std::vector<fs::ConsensusThread> stuck;
        for (std::uint32_t id = 1; id <= 5; ++id) stuck.push_back(thread(id, "coolmod.dll", 0, id == 1));
        fs::GroupConsensus consensus = fs::threadGroupConsensus(stuck, systemImage);
        check(consensus.present && consensus.module == "coolmod.dll" && consensus.matching == 5,
              "zero-CPU non-system waits form consensus");
    }
    {
        std::vector<fs::ConsensusThread> leaderless;
        for (std::uint32_t id = 1; id <= 6; ++id) leaderless.push_back(thread(id, "coolmod.dll", 100, false));
        check(!fs::threadGroupConsensus(leaderless, systemImage).present, "group without callback thread abstains");
    }
    {
        std::vector<fs::ConsensusThread> small;
        for (std::uint32_t id = 1; id <= 3; ++id) small.push_back(thread(id, "coolmod.dll", 100, id == 1));
        check(!fs::threadGroupConsensus(small, systemImage).present, "fewer than four threads abstains");
    }
    {
        std::vector<fs::ConsensusThread> mixed;
        for (std::uint32_t id = 1; id <= 5; ++id) mixed.push_back(thread(id, "ntdll.dll", 0, false));
        for (std::uint32_t id = 6; id <= 9; ++id) mixed.push_back(thread(id, "render.dll", 50, id == 6));
        fs::ConsensusThread unstable = thread(10, "render.dll", 50, false);
        unstable.repeats = 0;
        mixed.push_back(unstable);
        fs::GroupConsensus consensus = fs::threadGroupConsensus(mixed, systemImage);
        check(consensus.present && consensus.module == "render.dll" && consensus.matching == 4,
              "parked system threads ignored, unstable threads excluded");
    }
    {
        std::vector<fs::ConsensusThread> busy;
        for (std::uint32_t id = 1; id <= 4; ++id) busy.push_back(thread(id, "kernelbase.dll", 300, id == 2));
        fs::GroupConsensus consensus = fs::threadGroupConsensus(busy, systemImage);
        check(consensus.present && consensus.module == "kernelbase.dll",
              "system image with real CPU still counts");
    }
    std::cout << "PASS: parked-system exclusion, deadlock groups, quorum rules\n";
    return 0;
}
