# FreezeSentryF4

Build an original Windows x64 F4SE freeze logger. Scope includes every Fallout 4
runtime for which a matching F4SE provides Messaging v1, including VR,
legacy, next-gen and Anniversary. Windows Store/console versions have no F4SE.
One DLL and a companion executable; C++20 and Windows SDK only.

The DLL uses two bounded F4SE Task v2 probes (normal and UI queues), records the
actual callback thread IDs and monotonic times, and publishes F4SE lifecycle
events to an inherited unnamed shared memory handle. It uses no game addresses,
game structures, Address Library, executable patches or copied Skyrim code.
Only one pending task per queue is permitted, including while the game hangs.
Older F4SE uses Windows window monitoring without reading absent task fields.

The companion process monitors those signals independently, records prolonged
silence as a suspected stall, and collects a Windows process snapshot, thread
contexts, module-relative stacks, CPU/memory data and a minidump. Reporting and
DbgHelp run outside the game. Snapshot failure must still leave a useful log.
It records recovery and rearms after progress. Loading/saving affects thresholds.
Background/scheduling pauses can cause suspected stalls. A manual capture key
handles apparent freezes that still advance the monitored queues.

All output is local. No game termination, forced thread resumption, recovery
patches, save edits, network symbol server, telemetry or automatic deployment.
Logs distinguish observed queue progress from inferred game state and never
label a module on a stack as the proven cause. GPU-only stalls and scheduler
progress without visible gameplay remain detection limits.

Additional user requirement: collect actionable repair evidence, including three
samples, CPU deltas, wait-chain ownership/deadlocks, module/PDB identities,
instruction bytes, complete registers, RTTI candidates, optional full memory
and non-suppressing exception breadcrumbs with post-exit preservation.

Phases: implement/build both binaries and an INI; validate queue ownership,
loading/startup deadlines, one incident per stall, rearming, cross-process
diagnostics and old/current/VR F4SE ABI; package DLL/EXE/INI/PDB/source notices;
perform a controlled in-game test on available runtimes. Offline tests cannot
prove runtime compatibility across absent game versions.

Current prerequisite: user approved direct execution with no subagents on
2026-10-08 after the configured Astra/Flash doctor failed. The active root is
gpt-6.1-sol; router and model settings will not be changed.

Sources: official F4SE repository, head 4692e9bba0f87d8b8d1a0b79110bf212f2b2ada7
(v0.7.9); v0.6.23 ea143b59b14346d941f5efe42d97769cac83fa38;
PluginAPI.h, GameThreads.h, Hooks_Threads.cpp and PluginManager.cpp.
https://f4se.silverlock.org/
https://github.com/ianpatt/f4se
https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot
Skyrim FreezeLogger README was consulted only for product context; its
implementation, algorithms, report templates and assets were not copied.

## 0.2.0 implementation, 2026-10-08

User requested direct implementation of the five discussed diagnostic ideas.
Implementation remains solo. Public F4SE lifecycle/file and Scaleform creation
history plus optional provider ingestion; bounded early-stack/thread-CPU history;
optional DXGI ETW/native frame heartbeat; partial dump validation/commit; soft
storage quota and owned-file retention. Engine-specific named cell/menu/travel
sources require an optional runtime-qualified adapter and are not guessed in
this core. Real DXGI ETW is blocked by access denied; tests mark it skipped.
The existing local install can receive the tested update by targeted file copy
with rollback backups under deployments. No public publication or game test.

## 0.3.0 readiness work, 2026-10-08

The active objective is a mature plugin ready for game tests. The five
diagnostic additions are retained. The collector now includes a read-only
1.10.163 context adapter gated by exact executable hash and loaded PE/data
identity, with bounded double reads. It observes cell/FormID/name, ESP/ESL
associations, menu stack changes and LoadingMenu; full fast-travel hooks and
winning-override attribution are not inferred. The generic DLL stays independent
of game layouts on all supported F4SE API versions.

Collector lifetime has independent deadlines for a blocked capture, observer
operation and cleanup after the original process handle signals exit. Only
the collector may be terminated. Active session/history/latest incident pairs
are protected during concurrent retention. Initialization failures release
unregistered mappings and can retry; registered callbacks keep pinned storage.

Acceptance: clean local build; executable queue/dump/WCT/retention, context,
lifetime and failed-initialization tests; explicit ETW skip if Windows denies
access; disk qualification receipt; verified local binary/source package and
game checklist. Deployment and live game proof are separate. No public release,
router change, subagents or game modification is part of readiness work.
