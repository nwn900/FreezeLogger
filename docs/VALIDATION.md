# Validation history

## FreezeSentryF4 0.3.1 crash-capture update, 2026-11-05

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

## FreezeSentryF4 0.3.0 candidate, 2026-10-08

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
