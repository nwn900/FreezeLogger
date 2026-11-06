# 0.3.2 candidate: live game checks

The direct F4SE startup smoke test completed on 2026-11-06 with Fallout 4
1.10.163 and F4SE 0.6.23. The 0.3.2 plugin loaded, wrote `shared_version=6`
preflight data, started its watcher, and passed the qualified 1.10.163 context
adapter. The game closed from the main menu with exit code 0; the watcher wrote
exit evidence and stopped normally. It saw the November 5 Buffout log as
`context-only` with `before-process-start`, which is correct for this separate
process. DXGI ETW remained unavailable (`status=5`). No save was loaded, no real
crash/freeze was reproduced, and no save-integrity claim is made.

## Remaining copied-save checks

Use the available 1.10.163/F4SE 0.6.23 instance. Preserve the five currently
installed logger files and INI before a targeted Data/F4SE/Plugins update.
Keep the ordinary crash logger enabled. Use a copied save/profile for play tests.

1. Load the copied save. Verify cell FormID/name against a known cell and check
   origin/associated files without treating them as winning overrides. Open/close
   a named menu; confirm sampled transitions. Do not expect very short events.
2. Observe LoadingMenu during a cell transition/fast travel. Check profiling
   pause/resume and no short-threshold false report. Record its real duration.
3. Play for ten minutes across interiors/exteriors and menus. Check session
   profiler durations, memory/CPU overhead, log growth and unexpected incidents.
   Repeat with ContextMonitoring=0 if context overhead or reads look suspicious.
4. With the game in foreground press Pause once. Verify one three-sample report,
   a validated committed dump and the matching supplied PDB identities. Confirm
   the game remains responsive and resumes normal monitoring afterward.
5. Reproduce a known freeze only on the copied baseline. Preserve the entire
   report/dump, prehang/session/exit logs and the exact module versions. Compare
   callback-thread samples, CPU deltas and WCT owners. Test one suspected cause
   reversibly; stack appearances alone do not identify the upstream culprit.
6. Restore baseline files/config if instability appears. If Vortex owns the old
   files, its next deployment can restore them; update/rollback must account for
   its staging winner as well as the direct game copy.

The Buffout correlation unit tests exercise the recorded crash-log header and
fault format, including same-session acceptance and rejection of stale,
cross-edition, cross-version and pre-process logs. The game smoke test confirms
exit-report wiring and safe rejection of an unrelated old log; it does not
simulate a Fallout 4 crash.

Other Fallout 4 runtimes/VR need their own startup/gameplay checks. The native
context adapter is intentionally unavailable on unqualified images; this must
not prevent generic queue/manual diagnostics from working.
