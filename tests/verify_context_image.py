"""Read-only disk qualification receipt; never starts or changes Fallout 4."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

parser = argparse.ArgumentParser()
parser.add_argument('exe', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
data = args.exe.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '55f57947db9e05575122fae1088f0b0247442f11e566b56036caa0ac93329c36', 'unsupported executable hash'
assert data[:2] == b'MZ'
offset = struct.unpack_from('<I', data, 60)[0]
assert data[offset:offset + 4] == b'PE\0\0'
machine, sections, timestamp = struct.unpack_from('<HHI', data, offset + 4)
optional_size = struct.unpack_from('<H', data, offset + 20)[0]
image_size = struct.unpack_from('<I', data, offset + 80)[0]
assert machine == 0x8664 and timestamp == 0x5ddc40fa and image_size == 0x6ce6000
qualified = []
for name, rva in [('g_player', 0x5aa4388), ('g_ui', 0x58d0898)]:
    for i in range(sections):
        entry = offset + 24 + optional_size + i * 40
        section_name, virtual_size, address = struct.unpack_from('<8sII', data, entry)
        flags = struct.unpack_from('<I', data, entry + 36)[0]
        if address <= rva and rva + 8 <= address + virtual_size:
            assert flags & 0x40000000 and not flags & 0x20000000
            qualified.append({'name': name, 'rva': hex(rva), 'section': section_name.rstrip(b'\0').decode('ascii')})
            break
    else:
        raise AssertionError(f'{name} outside readable nonexecutable data')
root = Path(__file__).resolve().parents[1]
sdk = root / 'build/context-sdk'
headers = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sdk.glob('*')) if p.is_file()}
receipt = {
    'executable': str(args.exe.resolve()), 'sha256': digest, 'timestamp': hex(timestamp),
    'image_size': hex(image_size), 'data_globals': qualified,
    'sdk_tag': 'ianpatt/f4se v0.6.23', 'sdk_file_sha256': headers,
    'evidence': 'disk PE identity/data bounds and public SDK declarations; not live pointer or gameplay proof',
}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(json.dumps(receipt, indent=2))
