# FreezeSentryF4

Original Fallout 4 F4SE freeze logger: a small DLL plus a separate Windows
collector. The DLL uses public F4SE interfaces; no Address Library, CommonLib
or game memory patches. A separately gated collector adapter reads engine
context only from a qualified 1.10.163 executable.

Version 0.3.6 adds a live crash minidump on fatal exceptions and raises the
loading hang threshold from observed
load times. Version 0.3.5 closes crash-log chronology (exception must precede log write within
limits), samples the frame provider immediately before the frame stall decision, verifies
matching PDB identities in diagnostic packages, and retains the 0.3.3 frame,
parser, and packaging fixes. Edition, version, and time identify candidates;
matching exception and loaded-module evidence only corroborate a log and do not
prove which overlapping same-version process wrote it. See
[validation](docs/VALIDATION.md) for evidence and limits.

## Install

Install the package through Vortex/MO2, or copy its `F4SE/Plugins` folder into
the game's `Data` directory. Keep the DLL, EXE and INI together. Launch with the
F4SE matching the runtime. Windows 10/11 x64 and the current Microsoft Visual C++
x64 Redistributable are required. Keep the supplied PDBs beside the binaries.
No ESP or save changes are needed. Disable/remove the mod while the game is
closed to uninstall it.

Reports: `Documents/My Games/Fallout4/F4SE/FreezeSentryF4` (or `Fallout4VR`).
The optional absolute `ReportDirectory` in the INI supports custom save/profile
locations. A startup/error log is also written beside the DLL. The collector
has no visible window and exits when the game exits.

## Collected evidence

Each incident contains three independent process snapshots and, by default,
a snapshot minidump. Collection pauses one second between passes and records
each actual sample time; dump writing and symbol processing can lengthen the
interval, particularly with full-memory dumps.

- All captured thread stacks, exact module offsets, full x64 general-purpose
  registers, instruction bytes at RIP and raw stack words.
- Per-thread CPU deltas, repeated instruction observations and callback thread
  IDs, counters and bounded queue state.
- Windows wait chains, lock ownership and detected deadlock cycles. WCT has a
  time budget and can fail because of privileges or unsupported lock types.
- Module paths/base/size, loaded PE identity, PDB GUID/age, local symbols and
  source file/line when the matching PDB provides them,
  on-disk file versions and SHA-256 hashes.
- Candidate C++ RTTI names from stack pointers, without guessed Bethesda
  structure layouts. Candidates are not validated forms.
- Latest F4SE lifecycle event, memory/commit figures and recent native exception
  breadcrumbs with code, address, parameters and registers.
- A 60-second ring of thread CPU deltas and sampled module-relative instruction
  addresses, plus early stacks after three seconds of queue silence. The interval
  defaults to two seconds; early passes use one second, up to twelve per stall.
  CPU time belongs to the thread, not necessarily the DLL at the sampled RIP.
- A bounded 128-event history, including F4SE save/load/delete filenames and
  success flags, and Scaleform movie creation without reading engine layouts.
  Optional providers can publish cell/FormID/plugin/menu/travel context.

The profiler pauses during F4SE-observed loading/saving or a qualified adapter's
observed LoadingMenu and resets CPU baselines
after loading or observer scheduling gaps. `HistorySeconds`, `ProfileMilliseconds`
and `EarlyWarningSeconds` control the ring; zero early warning disables early
stacks. The ring uses at most 2 MiB and is also preserved atomically in
`prehang-PID.log` before a full incident. Profiling has measurable overhead;
each sample records its actual elapsed milliseconds.

`FrameMonitoring=1` attempts a private real-time DXGI ETW session filtered to
the target PID. Successful non-test Present calls provide a separate heartbeat.
Presentation submission is not proof a frame reached the display, and this is
not a GPU diagnosis. The provider must emit supported events and Windows must
permit ETW access. Denied access or lost events disable this detection source;
queue monitoring and manual capture remain available. No elevation is requested.
Frame detection requires observed progress, foreground focus and no F4SE-observed
loading/saving; after returning to foreground it requires fresh presentations.
VR/compositor paths that do not emit DXGI Present need a native frame provider.

Only local PDBs are used. No symbol server or telemetry is contacted. Module
offsets remain usable with the exact matching DLL/PDB or executable mapping.
An appearance on a stack is not by itself proof that a plugin caused the stall.

Default detection thresholds: 15 seconds without a task callback, 120 seconds
for F4SE-observed save/load operations and 180 seconds for startup. Change them
in the INI. Long legitimate operations can exceed them. Fast-travel loading is
not always represented by an F4SE save/load message. On the qualified 1.10.163
image, LoadingMenu observation also extends the loading deadline.

Pause/Break captures a manual report while the game has focus, including when
task queues keep advancing during an apparent hang. `ManualKey=0` disables it.
Detection rearms after queue recovery. `MaxFreezeReports`/`MaxManualReports`
cap each incident class independently (manual snapshots use `manual-*` names);
session, exit and preflight evidence remain. A background-but-responsive stall
is suppressed as a likely Alt-Tab pause (`SuppressBackgroundHang=0` disables);
an unresponsive background window still reports. Each session writes a
machine-readable `preflight-<PID>.json` beside the session log. When a dump
cannot be written, a `WER_LocalDumps_Hint.txt` explains the Windows fallback.
Incident logs add `SELECTED_EXCEPTION` (first-candidate native fault rule) and
`CANDIDATE_CONSENSUS` (comparison of process-corroborated crash evidence with
callback-thread stacks and stable thread groups). A metadata/time-only Buffout
candidate is labeled separately and is not attributed to the current process;
even corroborated agreement is evidence, not a cause verdict.

Dumps first write to `.dmp.partial`. Only a flushed file with valid x64 header,
required streams, thread contexts, stack and memory bounds is renamed `.dmp`.
Validation cannot guarantee meaningful unwinding or causal attribution. Stale
owned partials older than one hour are cleaned outside captures. `MaxStorageMB`
sets a soft cap (default 1024 MiB, zero disables it), deleting old dumps before
old owned text. Active session/history/exit evidence and newest incident text are
protected, including the latest incident pair of other live collectors, so
the cap/count can be exceeded. Reparse points and unrelated files are
excluded. Session text rotates at 8 MiB. Keep externally archived evidence when
it must survive these limits.

## Optional native context providers

The DLL exports `FreezeSentryF4_RecordEvent(const fs::EventData*)` and
`FreezeSentryF4_FramePulse()`. The standalone header is `src/telemetry.hpp` (also
packaged under `FreezeSentryF4/include`). Resolve the exports from the loaded
logger DLL; a false return means unsupported/malformed input or concurrent-event
drop. Events are copied immediately into the shared ring; callbacks do no disk
I/O. Inline UTF-8 fields must be terminated, with version=1 and size=384.

An adapter must identify its source and copy validated FormIDs, cell/menu names
and plugin filenames under its own runtime/lifetime contract. The logger does
not infer a winning override from a FormID prefix. The collector bundles a
read-only adapter for an exactly qualified 1.10.163 image; other runtimes retain
public F4SE/provider history. Scaleform creation reports an opaque movie address,
not a named menu or its lifetime. `FramePulse` is for a validated per-frame source,
not a timer; it takes precedence over ETW. `FrameMonitoring=0` disables automatic
frame-silence reports. Adapter events supplement evidence, not a culprit verdict.

`ContextMonitoring=1` polls current cell/FormID/name, associated ESP/ESL files
and the active menu stack about every 500 ms. The adapter requires the exact
on-disk executable hash, matching loaded PE identity and readable data globals;
unknown versions/images are skipped. Two equal reads, bounded arrays/strings,
vtable/type checks and ReadProcessMemory failures discard unreadable samples.
This is not an atomic snapshot: short transitions can be missed. Last readable
fields retain their independent timestamps when current context is unavailable.
LoadingMenu means observed loading, not confirmed fast travel. The associated
file list is not a winning override or culprit verdict. See
[adapter qualification](docs/CONTEXT-163.md).

`CaptureTimeoutSeconds=120` limits a full collector operation (15..900 seconds).
Raise it explicitly for very large full dumps. A separate thread limits blocked
cleanup to five seconds after the original game process exits and stalled normal
monitoring operations to 30 seconds. Expiry terminates only the collector;
incident sections and `.partial` files remain. Session text records collection
start/deadline; exit 124 means a collector deadline, 125 means blocked cleanup
after target exit. The guard attempts to stop its exact owned ETW session, with
an additional one-second bound for that cleanup. It never terminates the game.

`FullMemoryDump=1` includes committed memory for heap/object/lock inspection.
It can produce tens of GB on heavily modded games. The default dump includes
threads, stacks and indirectly referenced memory instead.

## Crashes and repair

A fatal exception (access violation, heap corruption, stack overflow, and the
other codes Tullius treats as fatal) publishes one crash incident. The watcher
wakes on that event and writes a single `crash-*.dmp` plus report while the
process is still alive. It does not swallow the exception. An unhandled C++
exception, or `abort()` within 500 ms of a C++ throw on that thread, uses the
same one-shot path. `CrashCapture=0` leaves the journal in place and skips the
dump. Completed loads can raise `LoadingTimeoutSeconds` using the 90th
percentile plus half that time, at least 30 seconds of margin, and never above
one hour. Alt+F4 / window close sets `user-close` on a zero exit.

The exception journal records up to 512 selected first-chance native/C++
exceptions and always returns `EXCEPTION_CONTINUE_SEARCH`. It requests the first
position in the vectored-handler chain so it can observe faults before handlers
that were already registered; another component can later request an earlier
position. The journal does not replace crash handlers or suppress exceptions.
First-chance exceptions can be handled and are not automatically the crash
cause. On a nonzero exit or when exceptions were observed, the collector writes
the exit status and retained exception history to `exit-evidence-PID.log`.
It cannot snapshot an already terminated process. Keep Buffout or another crash
logger for exception-time crash dumps.

Start freeze analysis with the callback threads and compare their three stacks,
CPU deltas and WCT owner chains. Follow a blocked owner's stack, rather than
blaming a waiting caller. A reported mutex cycle identifies its participants;
high CPU in repeated plugin frames is a lead for a loop/long operation.

For repair, open the dump in WinDbg/Visual Studio, load the exact identified
DLL/PDB, select the relevant thread and inspect registers, instruction bytes and
matching source/disassembly. Full dumps additionally allow heap inspection.
Confirm suspected components with a reversible, one-variable reproduction.
The logger supplies evidence, not a guaranteed verdict for every failure.

## Compatibility and evidence limits

One x64 DLL exports legacy Query/Load and modern version-independent metadata.
The DLL has no game-address/layout dependencies. The collector's optional
engine adapter is independently identity gated. F4SE Task v2 supplies normal/UI
probes; older F4SE uses Windows window-response monitoring. That fallback can
miss a stall behind a responsive message pump; manual capture remains available.

ABI declarations compile against 71 official SDKs: every archived F4SE 0.1.0
through 0.6.23, VR 0.6.21 and 0.7.0 through 0.7.9. This verifies API/loader
contracts for legacy, next-gen, Anniversary and VR, including 1.10.163, 1.10.984,
1.11.240 and VR 1.2.72. Each runtime needs its matching F4SE; Windows Store and
console editions have no F4SE support. ABI/host tests do not constitute live
qualification of all game executables. See [validation](docs/VALIDATION.md).

## Build

From an x64 MSVC developer shell with CMake/Ninja:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DFSF4_SYMBOLS_MODE=required
cmake --build build
ctest --test-dir build --output-on-failure `
  --output-junit "$((Get-Location).Path)\build\validation-0.3.6.xml"
python scripts/package.py --build build --config RelWithDebInfo --symbols-mode required `
  --stage build/package-0.3.6-release --artifacts artifacts/release-0.3.6 `
  --test-report build/validation-0.3.6.xml
python scripts/verify_release.py --build build --config RelWithDebInfo --symbols-mode required `
  --package build/package-0.3.6-release
```

The default diagnostic package requires both compiler PDBs and checks their
GUID/age against the packaged DLL and watcher. A deliberate symbols-free package
must configure CMake with `-DFSF4_SYMBOLS_MODE=none` and pass
`--symbols-mode none` to the packager and verifier; that mode rejects any PDB in
the package.

The ABI verifier uses Python/7-Zip and downloads public SDK evidence into
`build/sdk-evidence`; those headers are not linked or redistributed. Tests stage
their own DLL/EXE/INI and output under `build/test-evidence-PID`. Deliberate
deadlocks exist only in test processes; tests do not install into a game.

See [origin](docs/ORIGIN.md) for independent implementation provenance.
The [game test checklist](docs/GAME-TESTS.md) records the remaining live checks.
Product context: [Skyrim FreezeLogger](https://github.com/GoAhead-at/FreezeLogger).
Primary API sources: [F4SE](https://github.com/ianpatt/f4se),
[official releases](https://f4se.silverlock.org/),
[Windows snapshot dumps](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/proc_snap/export-a-process-snapshot-to-a-file),
and [WCT](https://learn.microsoft.com/en-us/windows/win32/debug/wait-chain-traversal).
