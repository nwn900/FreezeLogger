"""Compile our ABI prefixes against official historical, VR and current SDKs.

Run in an x64 MSVC developer shell. Downloads are public SDK evidence under
build/sdk-evidence, never dependencies linked into the plugin or shipped in it.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--all', action='store_true', help='check every official archived release')
parser.add_argument('--sevenzip', default=r'C:\Program Files\7-Zip\7z.exe')
args = parser.parse_args()
evidence = ROOT / 'build/sdk-evidence'
evidence.mkdir(parents=True, exist_ok=True)
archives = ['f4se_0_01_00.7z', 'f4se_0_06_23.7z']
if args.all:
    listing = urllib.request.urlopen('https://f4se.silverlock.org/archive/', timeout=30).read().decode()
    archives = sorted(set(re.findall(r'href="(f4se_[0-9_]+\.7z)"', listing)))
results = []

def download(url, path):
    if not path.exists():
        with urllib.request.urlopen(url, timeout=30) as response:
            path.write_bytes(response.read())

def compile_prefix(folder, label):
    header = folder / 'PluginAPI.h'
    original = header.read_text(encoding='utf-8-sig')
    source = '''#include <windows.h>
#include <cstddef>
#include <cstdint>
using UInt8=std::uint8_t; using UInt16=std::uint16_t; using UInt32=std::uint32_t; using UInt64=std::uint64_t;
#include "PluginAPI.h"
#include "../../../src/api.hpp"
static_assert(offsetof(fs::Host,query)==offsetof(F4SEInterface,QueryInterface));
static_assert(offsetof(fs::Host,handle)==offsetof(F4SEInterface,GetPluginHandle));
static_assert(offsetof(fs::Messaging,listen)==offsetof(F4SEMessagingInterface,RegisterListener));
static_assert(sizeof(fs::Message)==sizeof(F4SEMessagingInterface::Message));
static_assert(offsetof(fs::Message,data)==offsetof(F4SEMessagingInterface::Message,data));
static_assert(fs::messagingID==kInterface_Messaging);
'''
    # Absolute include keeps the evidence folder layout independent of SDK label.
    source = source.replace('../../../src/api.hpp', (ROOT / 'src/api.hpp').as_posix())
    if 'struct F4SEScaleformInterface' in original:
        source += '''static_assert(fs::scaleformID==kInterface_Scaleform);
static_assert(offsetof(fs::Scaleform,registerCallback)==offsetof(F4SEScaleformInterface,Register));
'''
    task = 'struct F4SETaskInterface' in original
    if task:
        source += '''static_assert(fs::taskID==kInterface_Task);
static_assert(offsetof(fs::Tasks,add)==offsetof(F4SETaskInterface,AddTask));
'''
        if 'AddUITask' in original:
            source += 'static_assert(offsetof(fs::Tasks,addUI)==offsetof(F4SETaskInterface,AddUITask));\n'
        else:
            task = False
        game_threads = (folder / 'GameThreads.h').read_text(encoding='utf-8-sig')
        contract = re.search(r'class ITaskDelegate\s*\{(.*?)\};', game_threads, re.S).group(1)
        assert contract.index('~ITaskDelegate') < contract.index('Run()'), label
    if 'struct F4SEPluginVersionData' in original:
        source += '''static_assert(sizeof(fs::Version)==sizeof(F4SEPluginVersionData));
static_assert(offsetof(fs::Version,addressIndependence)==offsetof(F4SEPluginVersionData,addressIndependence));
static_assert(offsetof(fs::Version,compatibleVersions)==offsetof(F4SEPluginVersionData,compatibleVersions));
'''
    (folder / 'check.cpp').write_text(source)
    command = ['cl', '/nologo', '/std:c++20', '/c', '/EHsc', 'check.cpp', '/Focheck.obj']
    run = subprocess.run(command, cwd=folder, capture_output=True)
    if run.returncode:
        raise RuntimeError(label + ': ' + run.stdout.decode(errors='replace') + run.stderr.decode(errors='replace'))
    results.append({'sdk': label, 'task_monitor': task, 'abi_compile': 'passed',
                    'header_sha256': hashlib.sha256(header.read_bytes()).hexdigest()})
    print(f'PASS {label}: ' + ('task probes' if task else 'Windows window fallback'), flush=True)

for archive in archives + ['f4sevr_0_6_21.7z']:
    path = evidence / archive
    base = 'beta' if archive.startswith('f4sevr') else 'archive'
    download(f'https://f4se.silverlock.org/{base}/{archive}', path)
    folder = evidence / archive.removesuffix('.7z')
    folder.mkdir(exist_ok=True)
    run = subprocess.run([args.sevenzip, 'e', str(path), f'-o{folder}', '-ir!PluginAPI.h',
                          '-ir!GameThreads.h', '-ir!f4se_version.h', '-y'], capture_output=True)
    if run.returncode:
        raise RuntimeError(f'Cannot extract SDK {archive}')
    compile_prefix(folder, archive)

for tag in ['v0.7.0', 'v0.7.1', 'v0.7.2', 'v0.7.3', 'v0.7.4', 'v0.7.5', 'v0.7.6', 'v0.7.7', 'v0.7.8', 'v0.7.9']:
    folder = evidence / tag
    folder.mkdir(exist_ok=True)
    for name in ['PluginAPI.h', 'GameThreads.h']:
        download(f'https://raw.githubusercontent.com/ianpatt/f4se/{tag}/f4se/{name}', folder / name)
    compile_prefix(folder, tag)
(evidence / 'abi-results.json').write_text(json.dumps(results, indent=2) + '\n')
print(f'PASS: {len(results)} official SDK ABI compilations', flush=True)
