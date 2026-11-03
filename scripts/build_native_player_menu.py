#!/usr/bin/env python3
"""Build a resident private-menu ABI prototype for emulation only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from analyze_native_sections import NativeImage, EXPECTED

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / 'native/player-menu'
BUILD = ROOT / 'staging/native-player-menu'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    if result.stderr.strip(): raise RuntimeError(result.stderr)
    return result.stdout

def main():
    NativeImage()  # Refuse any target image except the verified exact MAIN.
    BUILD.mkdir(parents=True, exist_ok=True)
    compiler = 'arm-linux-gnueabi-gcc'
    elf = BUILD / 'player-menu-armv6.elf'
    flags = ['-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft', '-Os',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pie',
        '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
        '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror']
    command = [compiler, *flags, '-nostdlib', '-static', '-no-pie',
        '-Wl,--build-id=none,-Map=' + str(BUILD / 'player-menu.map'),
        '-Wl,-T,' + str(LOCAL / 'emulation.ld'), str(LOCAL / 'player_menu.c'),
        '-lgcc', '-o', str(elf)]
    run(command)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Unresolved symbols: ' + undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = {'address': int(fields[0], 16), 'type': fields[1]}
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attributes or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected ISA or runtime dependency')
    flat = BUILD / 'player-menu-armv6.bin'
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    files = [LOCAL / 'player_menu.c', LOCAL / 'emulation.ld', Path(__file__).resolve(),
             ROOT / 'scripts/analyze_native_sections.py']
    info = {'updated_utc': datetime.now(timezone.utc).isoformat(),
        'MAIN_sha256': EXPECTED, 'target': 'Taiwan nuvi2565RT HWID1352 SW8.00',
        'compiler': run([compiler, '--version']).splitlines()[0], 'command': command,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
        'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
        'flat_binary_bytes': flat.stat().st_size, 'attributes': attributes,
        'segments': segments, 'symbols': symbols, 'undefined_symbols': [],
        'synthetic_link_base': '0x09080000', 'device_io': False,
        'device_files_modified': False, 'native_App_on_device': False,
        'limitations': 'Exact private HWID1352 SW8.00 ABI experiment, not a Garmin SDK. '
            'Synthetic address is not known free device RAM. No package, accepted loading, '
            'rendered icon, UI lifecycle or direct Bluetooth audio is established.'}
    manifest = BUILD / 'build.json'
    manifest.write_text(json.dumps(info, indent=2) + '\n')
    print(json.dumps({'build': str(manifest.relative_to(ROOT)),
        'flat_binary_bytes': info['flat_binary_bytes'], 'elf_sha256': sha(elf),
        'device_io': False}))

if __name__ == '__main__': main()
