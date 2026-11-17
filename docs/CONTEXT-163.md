# Read-only context adapter: layout table

The file name is historical. The adapter is no longer tied to one executable.

The DLL remains independent of Bethesda addresses and layouts. Only the external
collector contains this optional, read-only decoder. ContextMonitoring=0
disables it.

## How a runtime is supported

Per-version knowledge lives in src/layout.hpp as data, not in the decoder.
Each row carries the packed F4SE runtime version, the two singleton RVAs, the
object offsets the decoder reads, an informational executable hash and a note
saying how the row was derived. Adding a runtime is a table row.

A row may be partial. The player half (cell FormID, name, file association) and
the menu half (open menu stack, LoadingMenu) are independent capabilities, and
hasPlayer/hasMenus gate them separately. A runtime with only the player half
still reports cells and never invents menus.

| Runtime | Player half | Menu half | Evidence |
|---|---|---|---|
| 1.10.163 (0x010A0A30) | yes | yes | F4SE v0.6.23 layout declarations, checked against the local executable |
| 1.11.221 (0x010B0DD0) | yes | no | player global derived from the parentCell/FormID access chain; cell offsets confirmed; UI layout not derived |

## What replaced the exact-hash gate

The old adapter refused to run unless the on-disk SHA-256, PE timestamp and
image size matched one build. That made it a single-version special case.

The gate is now structural and version-agnostic:

- the runtime must resolve to a layout row;
- the image must be Fallout4.exe (VR keeps its own layout);
- the loaded PE must be AMD64 with a consistent SizeOfImage and a bounded
  section count;
- every non-zero derived RVA must land in a readable, non-executable section.

The executable hash is still computed and reported as image_hash=match or
image_hash=differs(...), but it never decides whether the adapter runs. A
modified build of a supported version therefore keeps working, and a build whose
layout row is wrong fails closed instead of reading a guessed address.

## Adding a runtime without a rebuild

FreezeLogger.layout.ini next to the plugin can carry extra rows. Each section
is [Layout.<runtime-hex>] with the same field names as the struct:

    [Layout.010C0000]
    PlayerRva=0x1111
    UiRva=0x2222
    PlayerCellOffset=0xB8
    CellFormIdOffset=0x14
    CellTypeOffset=0x1A
    UiStackOffset=0x190
    UiTableOffset=0x1B0
    UiTableEntriesOffset=0x20
    MenuStride=0x28
    MenuNameOffset=0x08
    MenuInstanceOffset=0x10
    MenuNextOffset=0x20

Unknown keys are ignored so a newer file still loads on an older build. Every
override row goes through the same structural validation as a built-in row, so a
wrong row fails closed rather than reading a guessed address. The watcher logs
layout_overrides=<n> at startup so the receipt shows whether a file was read.

Three guards keep a bad file from doing damage. A row whose entry stride is zero
or whose name, instance or chain offset does not fit inside the stride is
refused rather than indexed, so it cannot read past an entry or walk an empty
buffer. A section that carries no usable field is dropped, so an empty override
cannot shadow a built-in row for the same runtime. The file read is bounded to
64 KiB.

The read path is covered end to end: the diagnostics fixture drops a
FreezeLogger.layout.ini next to the plugin and asserts the watcher logs
layout_overrides=1, so the wiring between the file and the parser is tested and
not just the parser itself.

## Deriving a new row

The 1.11.221 row was produced without launching the game:

1. The 1.10.163 executable is Steam-CEG encrypted (.text entropy 8.000, no
   function prologues), so it cannot be analysed statically. The 1.11.221
   executable is plaintext (entropy 6.226).
2. Disassemble .text, find every mov reg, [rip+disp] global load, and track
   register provenance forward. The player singleton is the unique global whose
   value is dereferenced at +0xB8 and then at +0x14 or +0x1A.
3. Confirm the offsets independently: +0xB8 appears 193 times on the player
   pointer, and mov al, [reg+0x1A] followed by cmp al, 63 appears 12 times,
   which fixes formType at +0x1A for this build too.
4. The UI half was not derived. No global in 1.11.221 is accessed at both
   +0x190 and +0x1A8, so the UI layout changed and the row leaves it zero.

The derivation is reproducible. tools/derive_layout.py takes a plaintext
executable, refuses encrypted images, and prints the row. It reports a player
global only when exactly one candidate survives. It also walks RTTI for
.?AVUI@@ through the CompleteObjectLocator to the vtable, finds the constructor
that writes that vtable, and reports the global every call site stores into. It
then finds the vtable method that walks the active menu stack and reports the
stack offset, and matches the member constructor that reads a pointer at +0x20
and a count at +4 to report the table offset. It stops there: the entry shape
comes from the table's free loop, which fixes the stride, name and chain offsets
but not the instance, because the instance is not freed. Provenance is
invalidated only by instructions that actually write a register, and cleared
across calls; treating test/cmp as writes drops every chain at the first null
check, and ignoring calls lets a stale register produce a false candidate.

Every shipped row is checked against its executable by
tests/verify_context_image.py, which asserts the on-disk digest and that each
derived RVA lands in readable, non-executable data. Both rows pass: 1.10.163
g_player 0x05AA4388 and g_ui 0x058D0898 in .data, 1.11.221 g_player 0x032D22E0
and g_ui 0x030DD8B0 in .data.

tests/verify_layout_rows.py runs that check automatically. It parses the rows
out of src/layout.hpp, hashes every Fallout4* image it can find, and validates
the RVAs of any row whose digest matches. It is registered as the layout-rows
ctest and skips when no image matches, so it guards the shipped data on a
developer machine without failing on a build agent.

## UI half: singleton located, layout still open

The 1.11.221 UI singleton is 0x030DD8B0. It was found through RTTI, which lives
in .data rather than .rdata:

1. The .?AVUI@@ type descriptor is at 0x030A6058, so the descriptor base is
   0x030A6048.
2. The only CompleteObjectLocator whose typeRVA points at it is 0x02AB4720.
3. The only vtable whose [-1] slot holds that locator is 0x027159E8.
4. The constructor that writes that vtable is 0x01A7F720.
5. All 102 call sites of that constructor store the result to 0x030DD8B0.

The row records the address but leaves both menu offsets zero, because the
member shapes changed. What is now known about the 1.11.221 UI object:

- Menu stack at +0x190, and its shape is identical to 1.10.163. The vtable
  method at 0x01A82EF0 reads the count from [this+0x1A0] and the entries pointer
  from [this+0x190], then indexes entries[count-1]. The member constructor at
  0x01A83B50 reads [rcx] and [rcx+0x10], the same entries/count pair.
- Menu table at +0x1B0, but its shape differs. The member constructor at
  0x01A83610 reads the entries pointer from [rcx+0x20] and the count from
  [rcx+4]. The 1.10.163 Table has entries at +0x28 and size at +0xC.
- Table entries are 0x28 bytes. The destructor path shows the name pointer at
  entry+8 and the chain link at entry+0x20. The 1.10.163 entry has the name at
  +0 and the instance at +8, so the instance field has not been located yet.
- The IMenu vtable is 0x271C168 and its constructor is 0x01B18D70. That
  constructor writes the vtable at +0, a second vtable at +0x10, a byte at
  +0x18, and zeroes +0x20, +0x28, +0x40 and +0x58. Because +0x40 starts null and
  is only filled later, it is not the menu name; the refcount bump at +0x5c
  belongs to whatever object is stored there. The LoadingMenu constructor at
  0x01065B93 likewise writes only vtables and its own members, so the name is
  not on the instance at construction time. That points back at the table.

The table and entry shapes are now fields in the layout row, so the decoder
follows the row instead of a fixed struct. The 1.11.221 row is enabled with the
stack at +0x190, the table at +0x1B0, entries at +0x20, count at +4, entry
stride 0x28, name at +8, instance at +0x10 and chain link at +0x20.

The instance offset is inferred rather than observed. The entry gained a field
at +0, which shifts the 1.10.163 name/instance/constructor triple from
0/+8/+0x10 to +8/+0x10/+0x18. If that inference is wrong the decoder finds no
matching entry and reports the menu half unavailable, so the failure mode is
silence rather than a wrong name.

Earlier approaches that did not work, kept here so they are not repeated:

- RTTI searched only in .rdata. The descriptors are in .data, so that search
  finds nothing.
- Menu name strings. LoadingMenu has no code reference and no pointer-table
  entry. PipboyMenu and DialogueMenu resolve to a BSFixedString constructor.
- Offset pairs. Union-of-offsets views suggest pairs such as 0x194/0x1AC and
  0x190/0x198/0x1A0, but no single site accesses both members on one register.
- Menu-adjacent globals. The strongest candidate, 0x03E5C6D8, is a TLS index.
- Array push. 0x03E47B70 has an Array at 0x1A0 with an in-place count increment
  at 0x1B0, but no menu Table follows it.

## Decoder limits

The decoder uses ReadProcessMemory, never engine calls or game locks. It caps
menus at 128, table slots at 2048, file associations at 64 and strings at 255
bytes, follows at most eight external string links and rejects cycles, wide
strings, unreadable memory, invalid counts, non-image vtables and non-CELL types.
Two equal complete reads are required. Equality is a consistency check, not an
atomic snapshot or a guarantee against an ABA change between reads.

Only instances in the active menu stack are named. Cached menu instances alone
do not prove that a menu is open. Missing or inconsistent fields cannot generate
synthetic open/close/cell transitions. Last readable fields have independent
timestamps and are labelled historical when current reads fail.

Matching a file's normal/light index to the FormID labels form origin. The
engine-provided association list is recorded separately. Neither is a claim
about the winning override, runtime corruption source or guilty mod. Dynamic
forms and unavailable associations remain unresolved. LoadingMenu suppresses
short loading-time alarms; it does not identify why loading started or prove
fast travel. Polling can miss short events.

Tests exercise the layouts in an isolated process with real ReadProcessMemory,
including ESP/ESL origins, inactive instances, invalid counts/types/pointers,
external-string cycles, per-half degradation and unknown-runtime refusal. A
real-game observation is still required before promoting any row to
live-qualified support.
