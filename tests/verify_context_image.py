"""Read-only disk qualification receipt for one engine-layout row.

Never starts or changes Fallout 4. Given an executable and the values from a
src/layout.hpp row, it checks that the image identity matches and that every
derived RVA lands in readable, non-executable data. Without those arguments it
only reports the image identity, which is still useful when adding a row.

Examples:
    python tests/verify_context_image.py "Fallout4.exe" \
        --sha256 55f57947... --player-rva 0x5aa4388 --ui-rva 0x58d0898 \
        --output build/context-image-evidence.json

    python tests/verify_context_image.py "Fallout4.exe_backup" \
        --sha256 428f9996... --player-rva 0x32d22e0 \
        --output build/context-image-evidence-1.11.221.json
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

parser = argparse.ArgumentParser()
parser.add_argument('exe', type=Path)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--sha256', help='expected on-disk digest; asserted when given')
parser.add_argument('--player-rva', type=lambda v: int(v, 0), help='g_player RVA from the layout row')
parser.add_argument('--ui-rva', type=lambda v: int(v, 0), help='g_ui RVA from the layout row')
args = parser.parse_args()

data = args.exe.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if args.sha256:
    assert digest == args.sha256.lower(), 'executable hash does not match the layout row'
assert data[:2] == b'MZ', 'not a PE image'
offset = struct.unpack_from('<I', data, 60)[0]
assert data[offset:offset + 4] == b'PE\0\0', 'missing PE signature'
machine, sections, timestamp = struct.unpack_from('<HHI', data, offset + 4)
optional_size = struct.unpack_from('<H', data, offset + 20)[0]
image_size = struct.unpack_from('<I', data, offset + 80)[0]
assert machine == 0x8664, 'not an AMD64 image'

qualified = []
for name, rva in [('g_player', args.player_rva), ('g_ui', args.ui_rva)]:
    if rva is None:
        continue
    for i in range(sections):
        entry = offset + 24 + optional_size + i * 40
        section_name, virtual_size, address = struct.unpack_from('<8sII', data, entry)
        flags = struct.unpack_from('<I', data, entry + 36)[0]
        if address <= rva and rva + 8 <= address + virtual_size:
            assert flags & 0x40000000 and not flags & 0x20000000, f'{name} is not readable non-executable data'
            qualified.append({'name': name, 'rva': hex(rva),
                              'section': section_name.rstrip(b'\0').decode('ascii')})
            break
    else:
        raise AssertionError(f'{name} outside every section')

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
