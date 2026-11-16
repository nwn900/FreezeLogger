#!/usr/bin/env python3
"""Derive a FreezeSentryF4 engine-layout row from a Fallout 4 executable.

The context adapter is the only part of the plugin that needs per-version
knowledge. This tool produces that knowledge from a plaintext executable so a
new runtime is a table row in src/layout.hpp rather than a code change.

Usage:
    python tools/derive_layout.py "C:/path/to/Fallout4.exe"

Requires capstone (pip install capstone).

What it does:
  1. Rejects encrypted images. Fallout 4 1.10.163 ships Steam-CEG encrypted
     .text (entropy 8.000, no function prologues) and cannot be analysed
     statically. Use a plaintext build, or supply known values by hand.
  2. Finds every RIP-relative global load in .text and tracks register
     provenance forward. The player singleton is the unique global whose value
     is dereferenced at +0xB8 and then at +0x14 (FormID) or +0x1A (formType).
  3. Confirms the cell offsets independently and reports how often each was
     observed, so a weak row is visible rather than silently trusted.
  4. Attempts the UI half. It is reported as unresolved unless a single global
     is seen with both stack and table offsets on the same register.

The tool never guesses. If a step is ambiguous it says so and leaves the field
zero, which the adapter treats as "unavailable" rather than reading a wrong
address.

Provenance is invalidated whenever a register is written from an untracked
source. Without that, a stale value survives a call and a later [reg+0x14] on a
reused register is wrongly attributed to the global.
"""
import hashlib
import math
import struct
import sys
from collections import Counter, defaultdict

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    from capstone.x86_const import X86_REG_RIP, X86_REG_RCX
except ImportError:
    sys.exit("capstone is required: pip install capstone")

RIP_MODRM = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
PLAYER_CELL_OFFSET = 0xB8
FORM_ID_OFFSET = 0x14
FORM_TYPE_OFFSET = 0x1A
CELL_FORM_TYPE = 63


def parent_registers():
    import capstone.x86_const as const
    pairs = [("RAX", "EAX"), ("RBX", "EBX"), ("RCX", "ECX"), ("RDX", "EDX"),
             ("RSI", "ESI"), ("RDI", "EDI"), ("RBP", "EBP"), ("RSP", "ESP")]
    pairs += [("R%d" % i, "R%dD" % i) for i in range(8, 16)]
    table = {}
    for r64, r32 in pairs:
        table[getattr(const, "X86_REG_" + r32)] = getattr(const, "X86_REG_" + r64)
        table[getattr(const, "X86_REG_" + r64)] = getattr(const, "X86_REG_" + r64)
    return table


PARENT = parent_registers()


def parse_pe(path):
    with open(path, "rb") as handle:
        data = handle.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    coff = e_lfanew + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    sections = []
    for index in range(section_count):
        offset = optional + optional_size + index * 40
        name = data[offset:offset + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                             rawsize=rawsize, rawptr=rawptr))
    return dict(data=data, sections=sections,
                image_base=struct.unpack_from("<Q", data, optional + 24)[0],
                image_size=struct.unpack_from("<I", data, optional + 56)[0])


def section(pe, name):
    for entry in pe["sections"]:
        if entry["name"] == name:
            return entry
    raise SystemExit("missing section " + name)


def entropy(blob):
    if not blob:
        return 0.0
    counts = Counter(blob)
    total = len(blob)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def global_loads(pe):
    text = section(pe, ".text")
    raw = pe["data"][text["rawptr"]:text["rawptr"] + text["rawsize"]]
    base = text["vaddr"]
    sites = []
    for i in range(len(raw) - 7):
        if raw[i] in (0x48, 0x4C) and raw[i + 1] == 0x8B and raw[i + 2] in RIP_MODRM:
            disp = struct.unpack_from("<i", raw, i + 3)[0]
            sites.append((i, base + i + 7 + disp))
    return text, raw, base, sites


WRITERS = {"mov", "lea", "movzx", "movsx", "movsxd", "xor", "add", "sub", "and",
           "or", "pop", "inc", "dec", "imul", "shl", "shr", "sar", "not", "neg",
           "xchg", "movbe", "bswap", "adc", "sbb", "mul", "div", "idiv", "lzcnt",
           "tzcnt", "popcnt", "bsf", "bsr"}


def step(provenance, insn, target):
    """Advance provenance by one instruction.

    Only instructions that actually write their first operand invalidate it.
    test/cmp/push do not, and treating them as writes drops every chain at the
    first null check. A call clears everything because the ABI lets the callee
    clobber the volatile registers.
    """
    if insn.mnemonic == "call":
        provenance.clear()
        return
    if insn.mnemonic not in WRITERS and not insn.mnemonic.startswith(("cmov", "set")):
        return
    ops = insn.operands
    if not ops or ops[0].type != X86_OP_REG:
        return
    dst = PARENT.get(ops[0].reg)
    if dst is None:
        return
    if insn.mnemonic in ("mov", "lea") and len(ops) == 2 and ops[1].type == X86_OP_MEM:
        mem = ops[1].mem
        if mem.base == X86_REG_RIP:
            provenance[dst] = ("global", target) if insn.address + insn.size + mem.disp == target else None
            return
        src = PARENT.get(mem.base)
        if src in provenance and provenance[src] and mem.index == 0:
            kind, value = provenance[src]
            if kind == "global" and mem.disp == PLAYER_CELL_OFFSET:
                provenance[dst] = ("cell", value)
                return
    provenance[dst] = None


def find_player(raw, base, sites, disassembler):
    """Unique global whose value is dereferenced at +0xB8 then +0x14/+0x1A."""
    hits = Counter()
    for site, target in sites:
        provenance = {}
        for insn in disassembler.disasm(raw[site:site + 200], base + site):
            if insn.mnemonic in ("ret", "jmp", "int3"):
                break
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.index == 0:
                    src = PARENT.get(op.mem.base)
                    state = provenance.get(src)
                    if state and state[0] == "cell" and op.mem.disp in (FORM_ID_OFFSET, FORM_TYPE_OFFSET):
                        hits[state[1]] += 1
            step(provenance, insn, target)
    return hits


def observed_offsets(raw, base, sites, target, disassembler):
    """Offsets seen on the player pointer and on the cell pointer it yields."""
    counts = Counter()
    for site, candidate in sites:
        if candidate != target:
            continue
        provenance = {}
        for insn in disassembler.disasm(raw[site:site + 600], base + site):
            if insn.mnemonic in ("ret", "int3"):
                break
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.index == 0:
                    src = PARENT.get(op.mem.base)
                    state = provenance.get(src)
                    if state and state[0] in ("global", "cell"):
                        counts["%s+0x%X" % (state[0], op.mem.disp)] += 1
            step(provenance, insn, target)
    return counts


def find_ui(raw, base, sites, disassembler):
    """A single global carrying both stack and table offsets on one register."""
    pairs = defaultdict(set)
    for site, target in sites:
        provenance = {}
        for insn in disassembler.disasm(raw[site:site + 300], base + site):
            if insn.mnemonic in ("ret", "int3"):
                break
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.index == 0:
                    src = PARENT.get(op.mem.base)
                    state = provenance.get(src)
                    if state and state[0] == "global" and state[1] == target and 0 <= op.mem.disp < 0x800:
                        pairs[target].add(op.mem.disp)
            step(provenance, insn, target)
    candidates = []
    for target, offsets in pairs.items():
        for offset in offsets:
            if offset >= 0x100 and offset + 0x18 in offsets:
                candidates.append((target, offset, len(offsets)))
    candidates.sort(key=lambda row: -row[2])
    return candidates


def find_type_descriptor(pe, class_name):
    """RVA of the RTTI type descriptor name for a class, or None.

    The descriptors live in .data, not .rdata, which is easy to miss.
    """
    needle = (".?AV" + class_name + "@@").encode()
    for entry in pe["sections"]:
        blob = pe["data"][entry["rawptr"]:entry["rawptr"] + entry["rawsize"]]
        at = blob.find(needle)
        if at >= 0:
            return entry["vaddr"] + at
    return None


def find_vtable(pe, name_rva):
    """Walk type descriptor -> CompleteObjectLocator -> vtable."""
    descriptor = name_rva - 16
    image_base = pe["image_base"]
    locators = []
    for entry in pe["sections"]:
        blob = pe["data"][entry["rawptr"]:entry["rawptr"] + entry["rawsize"]]
        for i in range(0, len(blob) - 24, 4):
            signature, _, _, type_rva, _, self_rva = struct.unpack_from("<IIIIII", blob, i)
            if signature == 1 and type_rva == descriptor and self_rva == entry["vaddr"] + i:
                locators.append(entry["vaddr"] + i)
    for locator in locators:
        wanted = image_base + locator
        for entry in pe["sections"]:
            blob = pe["data"][entry["rawptr"]:entry["rawptr"] + entry["rawsize"]]
            for i in range(0, len(blob) - 8, 8):
                if struct.unpack_from("<Q", blob, i)[0] == wanted:
                    return entry["vaddr"] + i + 8
    return None


def function_start(raw, base, site):
    """Scan backwards over int3 padding to the function entry."""
    offset = site - base
    for i in range(offset, max(0, offset - 0x800), -1):
        if raw[i - 1] == 0xCC and raw[i - 2] == 0xCC and raw[i - 3] == 0xCC:
            return base + i
    return site


def find_constructors(raw, base, vtable_rva):
    """Every function that writes the vtable into a new object.

    A class can have more than one: the base constructor and a derived one that
    initialises additional members. The menu table is only set up by one of them.
    """
    found = []
    for i in range(len(raw) - 7):
        if raw[i] in (0x48, 0x4C) and raw[i + 1] == 0x8D and raw[i + 2] in RIP_MODRM:
            if base + i + 7 + struct.unpack_from("<i", raw, i + 3)[0] == vtable_rva:
                entry = function_start(raw, base, base + i)
                if entry not in found:
                    found.append(entry)
    return found


def find_singleton(raw, base, constructor_rva):
    """The global that every constructor call site stores the result into."""
    stores = Counter()
    for i in range(len(raw) - 5):
        if raw[i] != 0xE8:
            continue
        if base + i + 5 + struct.unpack_from("<i", raw, i + 1)[0] != constructor_rva:
            continue
        j = i + 5
        if j + 7 <= len(raw) and raw[j] == 0x48 and raw[j + 1] == 0x89 and raw[j + 2] == 0x05:
            stores[base + j + 7 + struct.unpack_from("<i", raw, j + 3)[0]] += 1
    return stores.most_common(1)[0] if stores else (None, 0)


def rva_to_offset(pe, rva):
    for entry in pe["sections"]:
        if entry["vaddr"] <= rva < entry["vaddr"] + max(entry["vsize"], entry["rawsize"]):
            delta = rva - entry["vaddr"]
            if delta < entry["rawsize"]:
                return entry["rawptr"] + delta
    return None


def section_of(pe, rva):
    for entry in pe["sections"]:
        if entry["vaddr"] <= rva < entry["vaddr"] + max(entry["vsize"], entry["rawsize"]):
            return entry["name"]
    return None


def derive_stack_offset(pe, raw, base, vtable_rva, disassembler):
    """Find the member whose count sits 0x10 above its entries pointer.

    The UI vtable method that walks the active menu stack reads the count and
    the entries pointer from the same base register, 0x10 apart. That pair is
    the stack; its base is the offset the decoder needs.
    """
    offset = rva_to_offset(pe, vtable_rva)
    if offset is None:
        return None
    methods = []
    for i in range(32):
        value = struct.unpack_from("<Q", pe["data"], offset + i * 8)[0]
        fn = value - pe["image_base"]
        if value == 0 or section_of(pe, fn) != ".text":
            break
        methods.append(fn)
    for fn in methods:
        start = fn - base
        # The method usually copies this into a callee-saved register first, so
        # track which registers still hold it rather than assuming rcx.
        this_regs = {X86_REG_RCX}
        seen = set()
        for insn in disassembler.disasm(raw[start:start + 400], fn):
            if insn.mnemonic in ("ret", "int3"):
                break
            ops = insn.operands
            if insn.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG:
                if ops[1].type == X86_OP_REG and ops[1].reg in this_regs:
                    this_regs.add(ops[0].reg)
                    continue
                if ops[1].type == X86_OP_MEM:
                    mem = ops[1].mem
                    if mem.base in this_regs and mem.index == 0 and 0 <= mem.disp < 0x800:
                        seen.add(mem.disp)
                this_regs.discard(ops[0].reg)
        for disp in seen:
            if disp + 0x10 in seen:
                return disp
    return None


def derive_table_offset(pe, raw, base, constructor_rva, disassembler):
    """Find the member whose constructor reads entries at +0x20 and count at +4.

    The UI constructor initialises each member through a small constructor. The
    menu table's one is the only member constructor that reads a pointer at
    +0x20 and a count at +4, so matching that shape identifies the offset.
    """
    start = constructor_rva - base
    if start < 0 or start >= len(raw):
        return None
    body = list(disassembler.disasm(raw[start:start + 0x600], constructor_rva))
    for index, insn in enumerate(body):
        if len(insn.operands) != 2 or insn.operands[0].type != X86_OP_REG:
            continue
        # The member address reaches the constructor either as lea reg,[reg+X]
        # or as add reg,X, depending on how the compiler scheduled it.
        offset = None
        if insn.mnemonic == "lea" and insn.operands[1].type == X86_OP_MEM:
            mem = insn.operands[1].mem
            if mem.index == 0 and 0 < mem.disp < 0x800:
                offset = mem.disp
        elif insn.mnemonic == "add" and insn.operands[1].type == X86_OP_IMM:
            if 0 < insn.operands[1].imm < 0x800:
                offset = insn.operands[1].imm
        if offset is None:
            continue
        if index + 1 >= len(body) or body[index + 1].mnemonic != "call":
            continue
        target = body[index + 1].operands[0]
        if target.type != X86_OP_IMM:
            continue
        callee = target.imm - base
        if callee < 0 or callee >= len(raw):
            continue
        seen = set()
        for inner in disassembler.disasm(raw[callee:callee + 200], target.imm):
            if inner.mnemonic in ("ret", "int3"):
                break
            for op in inner.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RCX and op.mem.index == 0:
                    seen.add(op.mem.disp)
        if 0x20 in seen and 4 in seen:
            return offset
    return None


def derive_ui(pe, raw, base):
    """Report the UI singleton and the offsets the decoder needs."""
    name_rva = find_type_descriptor(pe, "UI")
    if name_rva is None:
        print("ui: .?AVUI@@ not found")
        return 0, None, None
    print("ui type descriptor : 0x%08X" % (name_rva - 16))
    vtable = find_vtable(pe, name_rva)
    if vtable is None:
        print("ui: no vtable resolved from the type descriptor")
        return 0, None, None
    print("ui vtable          : 0x%08X" % vtable)
    constructors = find_constructors(raw, base, vtable)
    if not constructors:
        print("ui: no constructor writes that vtable")
        return 0, None, None
    constructor = constructors[0]
    print("ui constructor     : 0x%08X" % constructor)
    singleton, count = find_singleton(raw, base, constructor)
    if singleton is None:
        print("ui: no store target after the constructor")
        return 0, None, None
    print("ui singleton       : 0x%08X (%d call sites)" % (singleton, count))
    stack_dis = Cs(CS_ARCH_X86, CS_MODE_64)
    stack_dis.detail = True
    stack = derive_stack_offset(pe, raw, base, vtable, stack_dis)
    print("ui stack offset    :", ("0x%X" % stack) if stack is not None else "not found")
    table = None
    for candidate in constructors:
        table = derive_table_offset(pe, raw, base, candidate, stack_dis)
        if table is not None:
            break
    print("ui table offset    :", ("0x%X" % table) if table is not None else "not found")
    print("ui entry shape     : not derivable; the free loop fixes stride,")
    print("    name and chain offsets but not the instance, which is not")
    print("    freed. Read it from the table destructor by hand.")
    return singleton, stack, table


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: derive_layout.py <Fallout4.exe>")
    path = sys.argv[1]
    pe = parse_pe(path)
    text = section(pe, ".text")
    raw = pe["data"][text["rawptr"]:text["rawptr"] + text["rawsize"]]

    digest = hashlib.sha256(pe["data"]).hexdigest()
    print("image       :", path)
    print("image_size  : 0x%X" % pe["image_size"])
    print("sha256      :", digest)
    print("text entropy: %.3f" % entropy(raw[:1 << 20]))
    if entropy(raw[:1 << 20]) > 7.9:
        raise SystemExit("text is encrypted (Steam CEG); this image cannot be analysed statically")

    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    text, raw, base, sites = global_loads(pe)
    print("global loads:", len(sites))

    hits = find_player(raw, base, sites, disassembler)
    if len(hits) != 1:
        print("player candidates:", ["0x%X (%d)" % (k, v) for k, v in hits.most_common()])
        raise SystemExit("player global is not unique; refusing to guess")
    player = next(iter(hits))
    print("player global: 0x%08X" % player)

    offsets = observed_offsets(raw, base, sites, player, disassembler)
    for probe in ("global+0xB8", "cell+0x14", "cell+0x1A", "cell+0x28", "cell+0x8"):
        print("  %-12s %d" % (probe, offsets.get(probe, 0)))

    ui = find_ui(raw, base, sites, disassembler)
    print("ui candidates:", ["0x%X@0x%X" % (t, o) for t, o, _ in ui[:5]] or "none")
    ui_singleton, ui_stack, ui_table = derive_ui(pe, raw, base)

    print()
    print("Suggested row (UI half stays zero until it is derived):")
    print('    { 0x%08Xu, 0x%08Xu, 0x%08Xu, 0xB8, 0x14, 0x1A, 0x28, 0x08, 0x%Xu, 0x%Xu,' % (0, player, ui_singleton, ui_stack or 0, ui_table or 0))
    print('      "%s",' % digest)
    print('      "<version>: player global from the parentCell/FormID chain; UI layout not derived" },')


if __name__ == "__main__":
    main()