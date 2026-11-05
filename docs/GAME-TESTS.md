# 0.3.1 candidate: live game checks

The direct F4SE startup smoke test is complete. It confirmed plugin load,
collector startup, `task_monitoring=1`, the qualified 1.10.163 context adapter,
and normal watcher shutdown. DXGI ETW was unavailable (`status=5`). No save
selection or gameplay interaction occurred; no freeze/crash was reproduced,
and no save-integrity claim is made. Host/ABI/disk tests do not establish
gameplay behavior.

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

The actual crash observer has only been exercised by a synthetic, handled
exception in the isolated diagnostics process; no Fallout 4 crash was triggered.
The UI screenshot service timed out twice during the smoke test, so the menu
state was not visually checked.

Other Fallout 4 runtimes/VR need their own startup/gameplay checks. The native
context adapter is intentionally unavailable on unqualified images; this must
not prevent generic queue/manual diagnostics from working.
