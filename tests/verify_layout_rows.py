"""Validate every shipped layout row against the executables on this machine.

Parses src/layout.hpp, hashes each Fallout4*.exe it can find, and for every row
whose expected digest matches a file, checks that each derived RVA lands in a
readable, non-executable section of that image.

Exits 77 (ctest SKIP) when no matching executable is present, so the test is
useful on a developer machine and harmless on a build agent.
"""
from pathlib import Path
import hashlib
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "src" / "layout.hpp"
SEARCH = [
    Path(r"E:\SteamLibrary\steamapps\common\Fallout 4"),
    Path(r"C:\Program Files (x86)\Steam\steamapps\common\Fallout 4"),
]

ROW = re.compile(
    r"\{\s*(0x[0-9A-Fa-f]+)u,\s*(0x[0-9A-Fa-f]+)u,\s*(0x[0-9A-Fa-f]+)u,\s*"
    r"(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*"
    r"(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*"
    r"(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*"
    r"(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*"
    r"(0x[0-9A-Fa-f]+),\s*\"([0-9a-f]{64})\"",
    re.S,
)


def declared_rows():
    """Count the initialisers in the layouts array, independent of the regex."""
    text = HEADER.read_text(encoding="utf-8")
    start = text.index("layouts[] = {")
    end = text.index("};", start)
    return text[start:end].count("{ 0x")


def rows():
    text = HEADER.read_text(encoding="utf-8")
    out = []
    for m in ROW.finditer(text):
        values = [int(m.group(i), 16) for i in range(1, 17)]
        out.append(dict(runtime=values[0], player=values[1], ui=values[2],
                        stack=values[8], table=values[9], digest=m.group(17)))
    return out


def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e + 4
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional = struct.unpack_from("<H", data, coff + 16)[0]
    base = coff + 20 + optional
    out = []
    for i in range(count):
        o = base + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr = struct.unpack_from("<II", data, o + 8)
        flags = struct.unpack_from("<I", data, o + 36)[0]
        out.append((name, vaddr, vsize, flags))
    return out


def check_rva(data, secs, rva, label):
    for name, vaddr, vsize, flags in secs:
        if vaddr <= rva < vaddr + vsize:
            assert flags & 0x40000000, f"{label} 0x{rva:X} is not readable"
            assert not flags & 0x20000000, f"{label} 0x{rva:X} is executable"
            return name
    raise AssertionError(f"{label} 0x{rva:X} is outside every section")


def main():
    table = rows()
    declared = declared_rows()
    if not table:
        print("no layout rows parsed from src/layout.hpp")
        return 1
    # A format change must not silently shrink coverage: the regex has to see
    # every initialiser the array declares.
    assert len(table) == declared, f"parsed {len(table)} of {declared} declared rows"
    print(f"parsed {len(table)} layout rows")
    images = []
    for folder in SEARCH:
        if folder.is_dir():
            # Backups are often named Fallout4.exe_backup, so match the stem
            # and filter on the PE signature rather than the extension.
            for candidate in folder.glob("Fallout4*"):
                if not candidate.is_file():
                    continue
                try:
                    with candidate.open("rb") as handle:
                        if handle.read(2) != b"MZ":
                            continue
                except OSError:
                    continue
                images.append(candidate)
    if not images:
        print("SKIP: no Fallout 4 executable found")
        return 77
    matched = 0
    for image in images:
        data = image.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        for row in table:
            if row["digest"] != digest:
                continue
            matched += 1
            secs = sections(data)
            for label, rva in (("player", row["player"]), ("ui", row["ui"])):
                if not rva:
                    continue
                where = check_rva(data, secs, rva, label)
                print(f"  runtime 0x{row['runtime']:08X} {label} 0x{rva:X} in {where}")
            print(f"  runtime 0x{row['runtime']:08X} matched {image.name}")
    if not matched:
        print("SKIP: no executable matches a shipped row digest")
        return 77
    print(f"PASS: {matched} row(s) validated against real images")
    return 0


if __name__ == "__main__":
    sys.exit(main())
