# Validation history

## Freeze Logger 0.3.6 Tullius capture paths, 2026-11-07

Live fatal-exception dumps and an adaptive
loading threshold follow the capture behavior of Tullius CTD Logger. The WinUI
viewer, dump analyzer, resource hooks, and Address Library game hooks are not
part of this port. Shared memory is version 8.

## Freeze Logger 0.3.5 audit follow-up, 2026-11-07

[GitHub issue #1](https://github.com/nwn900/FreezeLogger/issues/1) third-audit
follow-up: incident corroboration now rejects a log written a full minute
before the matching in-process exception (only a small last-write skew toward a
later exception remains for FAT-style timestamp quantization). The watcher takes
the latest frame snapshot immediately before the frame-stall decision so the
gate's decision clock cannot lag an interleaved fresh Present. Release packaging
still requires both matching PDBs by default; symbols-free mode remains explicit.

## Freeze Logger 0.3.4 audit follow-up, 2026-11-06

The third audit found three gaps. Crash-log corroboration now requires the
matching current-process exception to precede the log's last-write timestamp,
allowing at most two seconds of future skew for coarse filesystem timestamp
granularity; the earlier five-minute maximum delay still applies. Corroboration
is explicitly described as evidence, not proof of which overlapping process
wrote the log or of crash cause. The frame watcher now takes its monotonic
decision time after reading the latest frame snapshot, and a future-dated
snapshot is deferred without consuming its progress count. Release packaging
requires both matching PDBs by default and checks their CodeView GUID/age
against their binaries. A symbols-free package must explicitly select
`--symbols-mode none`.

The MSVC `RelWithDebInfo` build succeeded (`Visual Studio 18 2026`, `-A x64`,
`build-vs/`). All 14 registered CTest cases are accounted for: 13 passed and
`real-dxgi-etw` skipped because ETW startup returned status 5. This is not ETW
qualification. Fresh-built `FreezeLogger.dll`, `FreezeLoggerWatch.exe`, and
matching PDBs are copied to `deployments/2026-11-07-pre-0.3.5-local/` (ignored
by git) for handoff into a mod or `Data\F4SE\Plugins` tree. Packaging was not
run in this session; run `scripts/package.py` after a full JUnit receipt when you
need a release ZIP.

## Freeze Logger 0.3.3 review follow-up, 2026-11-06

The original November 5 crash report is in the Fallout 4 `F4SE` folder. Its
header reports an access violation at `Fallout4.exe+1C152D6`. The 0.3.1
collector's exit report recorded a nonzero game exit and first-chance exception
history, but omitted the Buffout report because external-log correlation was
only called during hang capture. Version 0.3.2 added the exit-path lookup.

This follow-up closes the remaining review findings: ETW frame generation and
receipt times stay distinct; foreground eligibility rejects buffered
pre-resume frames; a busy native read retains native authority and its last
coherent sample; provider handover rebases frame counts; and crash metadata/time
is only a candidate until an exact in-process exception and loaded-module
identity match. The parser accepts full module fields with dotted path segments,
spaces and `C++` directories. The release verifier requires each file at its
canonical ZIP root. Stateful frame selection, stall gating and crash
corroboration are owned by focused objects.

The MSVC `RelWithDebInfo` build passed. All 14 registered CTest cases are
accounted for: 13 passed and `real-dxgi-etw` was skipped because Windows
returned status 5. The release package and source archive passed the package
gate, canonical ZIP verifier, and independent source-archive build. The Buffout
parser regression uses the actual crash header and confirms exact exception,
module and offset matching; a nearby but different process exception is
rejected. This is a controlled fixture, not a reproduced game crash.

The new DLL, watcher, PDBs and INI were deployed to the requested Vortex folder
and the Fallout 4 `Data/F4SE/Plugins` paths. Both locations match the release
payload by SHA-256, with the pre-update copies preserved under
`deployments/2026-11-06-pre-0.3.3-update`.

A direct `f4se_loader.exe` launch loaded the deployed DLL and watcher, wrote
preflight data, and passed the qualified 1.10.163 context adapter. ETW remains
unavailable (`status=5`). A SHA-256-verified copied test-save pair was prepared
in the top-level save folder, but desktop capture timed out twice before the
save could be selected. No save was loaded or written, and no gameplay or live
crash-capture claim is made. Keep the GitHub issue open for the copied-save
gameplay check and native ETW qualification.

## Freeze Logger 0.3.2 crash correlation and audit, 2026-11-06

The November 5 Buffout log records an access violation at `Fallout4.exe+1C152D6`
and repeated stack frames at `Fallout4.exe+1B99DCC`. FreezeSentry's prior
`exit-evidence-12392.log` already recorded PID 12392's nonzero exit and 436
first-chance access violations, but it did not read/correlate the Buffout log
when writing exit evidence. The handler had been wired only into freeze capture,
so the exit report stopped at a generic nonzero exit; the first-chance records
were not enough to prove the Buffout fault's cause.

Version 0.3.2 now attaches a Buffout record to exit evidence only when its game
edition and executable version match, its file timestamp follows that process's
start, and it is within five minutes of observation. Nonmatching records remain
explicitly `context-only`. Parser bounds, filenames with spaces, UTF-8/JSON
paths, frame-source priority and ETW QPC timestamps, ETW loss queries, fault-ring
ordinals, F4SE runtime names, awake-time deadlines, finite foreground grace,
and active-session retention all have regression coverage. Packaging derives
its test gate from CTest's inventory, includes the fuzz source, and validates the
INI inside the package. Small service/policy objects own the suppression,
correlation, frame publication, runtime classification, and lifetime rules.

The `RelWithDebInfo` build completed. CTest passed 12 of 13 tests; only
`real-dxgi-etw` skipped because ETW startup returned status 5. The real ETW
provider test is therefore not qualified on this machine. Both the package
directory and Windows ZIP passed `scripts/verify_release.py`; the source ZIP
contains `fuzz/`.

A direct `f4se_loader.exe` launch from the installed Fallout 4 directory loaded
the deployed 0.3.2 DLL, created a matching watcher/session/preflight, and enabled
the qualified read-only 1.10.163 context adapter. The game was closed from the
main menu without loading a save. The resulting exit report recorded exit code
0 and labeled the November 5 crash log `context-only` / `before-process-start`.
This verifies startup and exit-report wiring, not gameplay, save integrity, or
live crash reproduction. The DLL, watcher, PDBs and INI in the requested Vortex
mod folder match the installed `Data/F4SE/Plugins` hardlinks by SHA-256. The
predeployment files are backed up at
`deployments/2026-11-06-pre-0.3.2-vortex`.

## Freeze Logger 0.3.1 crash-capture update, 2026-11-05

The plugin and collector configured and built in `RelWithDebInfo` with Visual
Studio 2022 Build Tools, MSVC 19.44.35229.0 and Windows SDK 10.0.26100. The
full build completed. CTest passed 11 of 12 cases in 46.43 seconds; the
`real-dxgi-etw` case was skipped because ETW was unavailable (the live session
reported `DXGI_ETW_status=5`). The diagnostics fixture raises 517 handled
access violations, verifies the 512-entry ring wrap and chronological retained
range, and confirms the exceptions remain handled. The full suite was rerun
after this regression check was added.

A live startup smoke test launched `f4se_loader.exe` directly. FreezeSentry
loaded in PID 35120 with `task_monitoring=1`; watcher PID 34168 created
`session-35120.log`, and the 1.10.163 context adapter passed its exact image and
loaded-data checks. The game exited normally with code 0 and the watcher
stopped. No save interaction or gameplay test was performed. Desktop screenshot
capture timed out twice, so menu state was not visually verified.

The DLL, collector and matching PDBs were copied into the requested Vortex mod
folder after the prior game process exited. The Vortex files are hard-linked to
Fallout 4's deployed `Data` paths; hashes match at both locations. The INI was
preserved. This is compile/link, host-test and startup-smoke evidence, not
gameplay or crash-reproduction qualification.

The previous `build` directory has a stale CMake compiler path from an older
Visual Studio 18 installation. The 0.3.1 build used a separate directory at
`build/audit-0.3.1-vs2022`; it did not overwrite the older binaries or receipts.

## Freeze Logger 0.3.0 candidate, 2026-10-08

Built locally with MSVC x64/C++20. No commit, push or public release. The
0.1.0/0.2.0 packages are preserved. Tests run only in isolated host processes;
Fallout 4 was not launched for 0.3.0 qualification. The deployed logger remains
the earlier 0.1.0 version; 0.3.0 is packaged locally for game tests.

## Executable evidence

CTest has seven cases: history-storage, real-dxgi-etw, engine-context,
collector-lifetime, initialization-failures, diagnostics and oldest-f4se-fallback.
Six execute successfully; the final full run took 43.86 seconds. Real DXGI ETW is explicitly
SKIPPED (StartTrace returns error 5, access denied); this is not a passed frame
capture test. No elevation or permission changes are performed.

After a final DLL error-path handle cleanup change, initialization-failures,
diagnostics and oldest-f4se-fallback were rerun on the final DLL and passed.
Their latest receipt is build/changed-dll-0.3.0.xml. Collector/context binaries
were unchanged from the full suite.

The real DLL and external collector verify:
- Healthy/loading queues, separate normal/UI stalls, bounded pending tasks,
  recovery/rearming, and the oldest-F4SE window fallback.
- Three PSS process snapshots, full-memory fixture dump, local symbols/source
  lines, registers, instruction bytes, module/PDB identities and file SHA-256.
- A real two-mutex deadlock and its owner cycle, plus a real CPU busy loop.
- Early PSS stacks and thread CPU/RIP samples retained before the full incident.
- F4SE load filename, Scaleform movie-creation observation and explicitly labelled
  fixture cell/FormID/ESL events via the exported optional-provider API.
- Native FramePulse propagation into the external report. It is a synthetic
  provider signal, not an actual Fallout 4 frame.
- Input version/termination/null-pointer rejection and LastError preservation.
- Real minidump structural validation and absence of a committed partial file;
  truncated dumps, overflowing stream counts and overflowing memory payloads
  are rejected.
- 2 MiB ring bounds, dump-first quota cleanup, active/unrelated-file protection,
  incident-count retention and stale owned partial cleanup. Symlink exclusion
  is exercised only if the host permits creating the test symlink.
- External context decoder using real ReadProcessMemory in a fixture: named
  cell, standard/ESL origin, active menu/LoadingMenu, closed cached instances,
  bounds, wrong types, bad pointers, cyclic external strings and identity refusal.
- Actual subprocess watchdog expiry (exit 124), original target exit followed
  by blocked cleanup (exit 125), and healthy guard shutdown.
- Repeated absent-helper and unwritable-output initialization failures without
  accumulating handles after OS/CRT warm-up; corrected retry and duplicate-load
  rejection. Early failures release the mapping before callbacks are registered.
- Other live collector history/latest incident pair survives both count and
  quota cleanup, including when its incident is older than this collector's.

FrameGate checks source availability, prior observed progress, gameplay/focus
conditions, loading suppression, fresh progress after foreground resume,
one report per stall, recovery and a second incident. These are detection logic
checks, not live DXGI or game rendering proof.

Evidence directories and actual durations are recorded in
build/Testing/Temporary/LastTest.log, build/validation-0.3.0.xml and isolated
build/feature-evidence-PID, test-evidence-PID and init-evidence-PID directories.
The original 0.1.0 validation is retained under build/baseline-0.1.0/docs.

## F4SE API evidence

All 71 official SDK ABI compilations passed in the preceding 0.2.0 audit after adding the optional Scaleform
prefix: all 60 archived standard SDKs 0.1.0 through 0.6.23, VR 0.6.21 and ten
0.7.x tags through 0.7.9. Absent historical Scaleform interfaces remain optional.
Results and header hashes are in build/sdk-evidence/abi-results.json. The
public api.hpp prefix is unchanged in 0.3.0; this audit was not rerun needlessly.

The DLL has no Bethesda layout/address dependencies. No Address Library,
CommonLib, engine patches or third-party implementations are linked. Only the
collector's optional 1.10.163 read-only adapter contains independently declared
field offsets. SDK compilation is not live proof on every runtime.

## Scope and current limits

Automatic generic history uses public F4SE lifecycle/file messages and Scaleform
movie-creation callbacks. The bundled collector adapter additionally polls
cell/FormID/name, associated files and active menu stack on the exactly qualified
1.10.163 image. It observes transitions and LoadingMenu; short events can be
missed and the cause of loading/fast travel is not inferred. Other runtimes can
use src/telemetry.hpp providers. Fixture transport/decoder tests do not prove
live engine reads, winning override ownership or causality.

The installed 1.10.163 executable's exact hash, timestamp/image size and global
data-section bounds were verified without launching it. The receipt includes
source header hashes. See CONTEXT-163.md/context-image-evidence.json. A live
pointer, cell/menu lifetime and overhead test remains mandatory before claiming
game-qualified context support.

The DXGI ETW implementation and native frame-provider interface are built. ETW
access was denied on this host; no real DXGI event or in-game frame capture is
claimed. Successful Present submission is not proof of display/GPU progress.
VR/compositor paths may not emit the selected provider events.

Profiling adds overhead; samples report actual duration. F4SE loading and a
readable qualified LoadingMenu pause it; every loading path is not covered.
Thread CPU deltas and sampled DLL instruction addresses do not establish DLL
CPU ownership or identify an upstream memory corruptor.

Dump validation checks structure and bounds; it cannot guarantee successful
unwinding, relevant heap coverage or causality. The quota is soft because active
text/newest incident text are protected. Full dumps can exceed it temporarily.
No real-game freeze, gameplay/save-load integrity test or broader-runtime
startup qualification of the 0.3.0 binaries has been performed. GAME-TESTS.md
contains the live acceptance checks.

The independent lifetime guard caps normal blocked observer operations at 30
seconds, capture operations at CaptureTimeoutSeconds (120 default), and blocked
cleanup five seconds after the original process exits. It stops only its own
collector. Owned ETW cleanup has a one-second termination fallback; actual
ETW start/cleanup remains untested because access is denied here. A forced
collector exit can leave partial evidence; a successful guard test does not
prove every external Windows/driver call is interruptible.
