"""Package an already validated local build without publishing or deploying."""
from pathlib import Path
import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zipfile

root = Path(__file__).resolve().parents[1]
version = re.search(r'project\(FreezeSentryF4 VERSION ([0-9.]+)', (root / 'CMakeLists.txt').read_text()).group(1)
stage = root / f'build/package-{version}'
artifacts = root / 'artifacts'
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
suite = ET.parse(root / f'build/validation-{version}.xml').getroot()
tests = suite.findall('testcase')
assert tests and not suite.findall('.//failure') and not suite.findall('.//error'), 'test suite failed'
assert int(suite.attrib['failures']) == 0
assert {test.attrib['name'] for test in tests} == {
    'history-storage', 'real-dxgi-etw', 'engine-context', 'collector-lifetime',
    'initialization-failures', 'diagnostics', 'oldest-f4se-fallback',
}
skipped = [{
    'test': test.attrib['name'], 'evidence': test.findtext('system-out', '').strip(),
} for test in tests if test.find('skipped') is not None]
assert all(entry['test'] == 'real-dxgi-etw' for entry in skipped), 'required tests were skipped'
rerun = ET.parse(root / f'build/changed-dll-{version}.xml').getroot()
assert int(rerun.attrib['failures']) == 0 and not rerun.findall('.//failure') and not rerun.findall('.//skipped')
assert {test.attrib['name'] for test in rerun.findall('testcase')} == {'initialization-failures', 'diagnostics', 'oldest-f4se-fallback'}
abi = json.loads((root / 'build/sdk-evidence/abi-results.json').read_text())
assert len(abi) == 71 and all(entry['abi_compile'] == 'passed' for entry in abi)
with zipfile.ZipFile(artifacts / 'FreezeSentryF4-0.2.0-source.zip') as previous:
    assert previous.read('src/api.hpp') == (root / 'src/api.hpp').read_bytes(), 'ABI prefix changed since compiled audit'
for name in ['FreezeSentryF4.dll', 'FreezeSentryF4Watch.exe', 'FreezeSentryF4.pdb', 'FreezeSentryF4Watch.pdb']:
    assert (stage / 'F4SE/Plugins' / name).read_bytes() == (root / 'build' / name).read_bytes(), f'stale staged {name}'
assert (stage / 'F4SE/Plugins/FreezeSentryF4.ini').read_bytes() == (root / 'dist/F4SE/Plugins/FreezeSentryF4.ini').read_bytes()
manifest = stage / 'FreezeSentryF4/SHA256SUMS.txt'
payload = sorted(path for path in stage.rglob('*') if path.is_file() and path != manifest)
manifest.write_text(''.join(f'{digest(path)}  {path.relative_to(stage).as_posix()}\n' for path in payload), encoding='utf-8')
binary = artifacts / f'FreezeSentryF4-{version}-windows-x64.zip'
source = artifacts / f'FreezeSentryF4-{version}-source.zip'
with zipfile.ZipFile(binary, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(stage.rglob('*')):
        if path.is_file(): archive.write(path, path.relative_to(stage).as_posix())
sources = [root / name for name in ['.gitignore', 'CMakeLists.txt', 'README.md', 'LICENSE']]
private_work = root / 'docs' / 'agent-work'
for directory in ['src', 'tests', 'docs', 'dist', 'scripts']:
    sources += [
        path for path in (root / directory).rglob('*')
        if path.is_file() and '__pycache__' not in path.parts
        and not (directory == 'docs' and private_work in path.parents)
    ]
with zipfile.ZipFile(source, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(sources): archive.write(path, path.relative_to(root).as_posix())
for artifact in [binary, source]:
    with zipfile.ZipFile(artifact) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            assert archive.read(name) == ((stage if artifact == binary else root) / name).read_bytes(), name
with zipfile.ZipFile(binary) as archive:
    for line in archive.read('FreezeSentryF4/SHA256SUMS.txt').decode('utf-8').splitlines():
        expected, name = line.split('  ', 1)
        assert hashlib.sha256(archive.read(name)).hexdigest() == expected, name
(artifacts / f'SHA256SUMS-{version}.txt').write_text(''.join(f'{digest(path)}  {path.name}\n' for path in [binary, source]), encoding='utf-8')
receipt = {
    'version': version, 'readiness': 'local game-test candidate',
    'tests_passed': len(tests) - len(skipped), 'tests_skipped': skipped,
    'after_final_dll_cleanup_change': 'initialization, diagnostics and oldest-F4SE fallback passed again',
    'official_sdk_abi_passed': len(abi), 'abi_audit_reused_from': '0.2.0; unchanged api.hpp',
    'api_prefix_sha256': digest(root / 'src/api.hpp'),
    'game_startup_qualified': False, 'deployed': False,
    'named_engine_context_adapter_bundled': 'read-only; exact qualified 1.10.163 hash/PE only',
    'context_evidence': 'disk/source plus isolated RPM fixtures; no live game pointer claim',
    'payloads': [{'file': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path)} for path in [binary, source]],
}
(artifacts / f'validation-{version}.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(json.dumps(receipt, indent=2))
