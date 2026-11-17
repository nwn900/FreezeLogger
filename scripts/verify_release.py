#!/usr/bin/env python3
"""Verify that a release directory or ZIP contains the built binaries and INI."""
import argparse
import hashlib
import re
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath


REQUIRED = (
    "F4SE/Plugins/FreezeLogger.dll",
    "F4SE/Plugins/FreezeLoggerWatch.exe",
    "F4SE/Plugins/FreezeLogger.ini",
)
PDB_TO_BINARY = {
    "F4SE/Plugins/FreezeLogger.pdb": "F4SE/Plugins/FreezeLogger.dll",
    "F4SE/Plugins/FreezeLoggerWatch.pdb": "F4SE/Plugins/FreezeLoggerWatch.exe",
}
BUILD_BINARIES = {
    "F4SE/Plugins/FreezeLogger.dll": "FreezeLogger.dll",
    "F4SE/Plugins/FreezeLoggerWatch.exe": "FreezeLoggerWatch.exe",
}
MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"


@dataclass(frozen=True)
class PdbIdentity:
    guid: bytes
    age: int


class BinaryCodeViewReader:
    def __init__(self, data: bytes):
        self.data = data

    def _u16(self, offset: int, field: str) -> int:
        if offset < 0 or offset + 2 > len(self.data):
            raise ValueError(f"truncated PE {field}")
        return struct.unpack_from("<H", self.data, offset)[0]

    def _u32(self, offset: int, field: str) -> int:
        if offset < 0 or offset + 4 > len(self.data):
            raise ValueError(f"truncated PE {field}")
        return struct.unpack_from("<I", self.data, offset)[0]

    def _rva_to_offset(self, rva: int, size: int, sections: list[tuple[int, int, int, int]],
                       size_of_headers: int) -> int:
        if rva < size_of_headers and rva + size <= size_of_headers:
            return rva
        for virtual_address, virtual_size, raw_offset, raw_size in sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva and rva + size <= virtual_address + span:
                delta = rva - virtual_address
                if delta + size > raw_size:
                    raise ValueError("PE debug directory extends beyond raw section data")
                return raw_offset + delta
        raise ValueError("PE debug directory RVA is outside file-backed sections")

    def read(self) -> PdbIdentity:
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ValueError("built binary has no valid DOS header")
        pe_offset = self._u32(0x3C, "PE offset")
        if self.data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError("built binary has no valid PE signature")
        coff = pe_offset + 4
        section_count = self._u16(coff + 2, "section count")
        optional_size = self._u16(coff + 16, "optional-header size")
        optional = coff + 20
        optional_end = optional + optional_size
        if optional_end > len(self.data) or not section_count or section_count > 96:
            raise ValueError("invalid PE optional header or section count")
        magic = self._u16(optional, "optional-header magic")
        if magic == 0x10B:
            number_of_directories_offset, directories_offset = 92, 96
        elif magic == 0x20B:
            number_of_directories_offset, directories_offset = 108, 112
        else:
            raise ValueError("unsupported PE optional-header format")
        if optional_size < directories_offset + 7 * 8:
            raise ValueError("PE optional header has no complete debug data directory")
        if self._u32(optional + number_of_directories_offset, "data-directory count") <= 6:
            raise ValueError("built binary has no PE debug data directory")
        debug_rva, debug_size = struct.unpack_from("<II", self.data, optional + directories_offset + 6 * 8)
        if not debug_rva or debug_size < 28 or debug_size % 28:
            raise ValueError("built binary has no valid PE debug directory")
        size_of_headers = self._u32(optional + 60, "header size")
        section_table = optional_end
        sections = []
        for index in range(section_count):
            header = section_table + index * 40
            if header + 40 > len(self.data):
                raise ValueError("truncated PE section table")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", self.data, header + 8)
            sections.append((virtual_address, virtual_size, raw_offset, raw_size))
        debug_offset = self._rva_to_offset(debug_rva, debug_size, sections, size_of_headers)
        if debug_offset + debug_size > len(self.data):
            raise ValueError("truncated PE debug directory")
        for index in range(debug_size // 28):
            entry = debug_offset + index * 28
            entry_type = self._u32(entry + 12, "debug entry type")
            if entry_type != 2:
                continue
            size_of_data = self._u32(entry + 16, "CodeView data size")
            data_offset = self._u32(entry + 24, "CodeView data offset")
            if size_of_data < 24 or data_offset + size_of_data > len(self.data):
                raise ValueError("invalid PE CodeView data range")
            if self.data[data_offset:data_offset + 4] != b"RSDS":
                continue
            guid = self.data[data_offset + 4:data_offset + 20]
            age = self._u32(data_offset + 20, "CodeView age")
            return PdbIdentity(guid, age)
        raise ValueError("built binary has no RSDS CodeView identity")


class MsfPdbIdentityReader:
    def __init__(self, data: bytes):
        self.data = data

    def _u32(self, offset: int, field: str) -> int:
        if offset < 0 or offset + 4 > len(self.data):
            raise ValueError(f"truncated PDB {field}")
        return struct.unpack_from("<I", self.data, offset)[0]

    def read(self) -> PdbIdentity:
        if len(self.data) < 56 or self.data[:32] != MSF7_MAGIC:
            raise ValueError("PDB is not an MSF 7.0 file")
        block_size = self._u32(32, "block size")
        block_count = self._u32(40, "block count")
        directory_size = self._u32(44, "directory size")
        block_map_address = self._u32(52, "block-map address")
        if block_size < 512 or block_size & (block_size - 1) or block_count * block_size > len(self.data):
            raise ValueError("invalid PDB MSF block layout")
        if not directory_size or directory_size > block_count * block_size or block_map_address >= block_count:
            raise ValueError("invalid PDB MSF directory layout")
        directory_block_count = (directory_size + block_size - 1) // block_size
        block_map_size = directory_block_count * 4
        block_map_offset = block_map_address * block_size
        if block_map_offset + block_map_size > len(self.data):
            raise ValueError("truncated PDB MSF block map")
        directory_blocks = [self._u32(block_map_offset + index * 4, "directory block")
                            for index in range(directory_block_count)]
        if any(block >= block_count for block in directory_blocks):
            raise ValueError("PDB MSF directory references an invalid block")
        directory = b"".join(
            self.data[block * block_size:(block + 1) * block_size] for block in directory_blocks
        )[:directory_size]
        if len(directory) < 4:
            raise ValueError("truncated PDB MSF stream directory")
        stream_count = struct.unpack_from("<I", directory, 0)[0]
        sizes_end = 4 + stream_count * 4
        if stream_count < 2 or sizes_end > len(directory):
            raise ValueError("PDB MSF directory has no information stream")
        stream_sizes = struct.unpack_from(f"<{stream_count}I", directory, 4)
        cursor = sizes_end
        info_size = stream_sizes[1]
        if info_size == 0xFFFFFFFF:
            raise ValueError("PDB information stream is absent")
        info_block_count = (info_size + block_size - 1) // block_size
        info_blocks = None
        for index, stream_size in enumerate(stream_sizes):
            blocks_needed = 0 if stream_size == 0xFFFFFFFF else (stream_size + block_size - 1) // block_size
            next_cursor = cursor + blocks_needed * 4
            if next_cursor > len(directory):
                raise ValueError("truncated PDB MSF stream block list")
            if index == 1:
                info_blocks = [struct.unpack_from("<I", directory, cursor + block * 4)[0]
                               for block in range(info_block_count)]
            cursor = next_cursor
        if info_blocks is None or any(block >= block_count for block in info_blocks):
            raise ValueError("PDB information stream references an invalid block")
        info = b"".join(
            self.data[block * block_size:(block + 1) * block_size] for block in info_blocks
        )[:info_size]
        if len(info) < 28:
            raise ValueError("PDB information stream is too short for GUID and age")
        age = struct.unpack_from("<I", info, 8)[0]
        return PdbIdentity(info[12:28], age)


class PackageReader:
    def __init__(self, package: Path):
        self.package = package
        self.archive = None
        if package.is_dir():
            self.names = [path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file()]
        elif package.is_file() and zipfile.is_zipfile(package):
            self.archive = zipfile.ZipFile(package)
            self.names = [entry.filename for entry in self.archive.infolist() if not entry.is_dir()]
        else:
            raise FileNotFoundError(f"package is not a directory or ZIP: {package}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.archive is not None:
            self.archive.close()

    def read(self, name: str) -> bytes:
        if self.archive is None:
            return (self.package / Path(*name.split("/"))).read_bytes()
        matches = [entry for entry in self.names if entry == name]
        if len(matches) != 1:
            raise FileNotFoundError(f"expected one canonical packaged entry {name}, found {len(matches)}")
        return self.archive.read(matches[0])

    def exists(self, name: str) -> bool:
        if self.archive is None:
            return (self.package / Path(*name.split("/"))).is_file()
        return self.names.count(name) == 1

    def contains_pdbs(self) -> bool:
        return any(PurePosixPath(name.replace("\\", "/")).suffix.lower() == ".pdb" for name in self.names)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_file(build: Path, name: str, config: str) -> Path:
    for candidate in (build / name, build / config / name):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"missing build output: {name} under {build}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True, type=Path, help="CMake build directory")
    parser.add_argument("--package", required=True, type=Path, help="Package directory or ZIP")
    parser.add_argument("--config", default="RelWithDebInfo", help="CMake configuration")
    parser.add_argument("--symbols-mode", choices=("required", "none"), default="required",
                        help="require matching PDBs or explicitly verify a symbols-free package")
    parser.add_argument("--src", default=Path(__file__).resolve().parent.parent,
                        type=Path, help="Repository root")
    args = parser.parse_args()
    failures = []
    package = args.package.resolve()
    build = args.build.resolve()
    source = args.src.resolve()
    plugin = source / "src/plugin.cpp"
    dist_ini = source / "dist/F4SE/Plugins/FreezeLogger.ini"
    packaged_ini_name = "F4SE/Plugins/FreezeLogger.ini"
    with PackageReader(package) as reader:
        for name in REQUIRED:
            if not reader.exists(name):
                failures.append(f"missing required file: {name}")

        for packaged_name, build_name in BUILD_BINARIES.items():
            try:
                built = build_file(build, build_name, args.config).read_bytes()
                if reader.exists(packaged_name) and sha256(reader.read(packaged_name)) != sha256(built):
                    failures.append(f"stale binary: {packaged_name} differs from build output")
            except FileNotFoundError as error:
                failures.append(str(error))

        if args.symbols_mode == "required":
            for pdb_name, binary_name in PDB_TO_BINARY.items():
                if not reader.exists(pdb_name):
                    failures.append(f"missing required debug symbols: {pdb_name}")
                    continue
                try:
                    packaged_pdb = reader.read(pdb_name)
                    built_pdb = build_file(build, Path(pdb_name).name, args.config).read_bytes()
                    if sha256(packaged_pdb) != sha256(built_pdb):
                        failures.append(f"stale PDB: {pdb_name} differs from build output")
                    binary = reader.read(binary_name)
                    binary_identity = BinaryCodeViewReader(binary).read()
                    pdb_identity = MsfPdbIdentityReader(packaged_pdb).read()
                    if pdb_identity != binary_identity:
                        failures.append(f"PDB identity does not match packaged binary: {pdb_name}")
                except FileNotFoundError as error:
                    failures.append(str(error))
                except ValueError as error:
                    failures.append(f"cannot verify PDB identity for {pdb_name}: {error}")
        elif reader.contains_pdbs():
            failures.append("symbols-mode none requires a package with no PDB files")

        if plugin.is_file() and dist_ini.is_file() and reader.exists(packaged_ini_name):
            packaged_ini = reader.read(packaged_ini_name)
            expected_ini = dist_ini.read_bytes()
            if packaged_ini != expected_ini:
                failures.append("packaged INI differs from canonical dist INI")
            try:
                ini_text = packaged_ini.decode("utf-8-sig")
            except UnicodeDecodeError:
                failures.append("packaged INI is not valid UTF-8")
                ini_text = ""
            keys = set(re.findall(r'setting\s*\(\s*ini\s*,\s*L"([^"]+)"',
                                  plugin.read_text(encoding="utf-8")))
            documented = set(re.findall(r"^([A-Za-z0-9]+)\s*=", ini_text, re.M))
            for key in sorted(keys - documented):
                failures.append(f"INI key read by plugin.cpp but absent from packaged INI: {key}")
        else:
            failures.append("cannot verify the packaged INI against code and canonical dist INI")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    symbols = "both matching PDB identities verified" if args.symbols_mode == "required" else "explicit symbols-free mode"
    print(f"PASS: release gate ({len(REQUIRED)} packaged files, {symbols}, build hashes and packaged INI verified)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
