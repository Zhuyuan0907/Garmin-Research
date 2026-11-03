#!/usr/bin/env python3
"""Build a freestanding ARM1176 decoder for emulation, never for flashing."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'sources/deep-research/sbc-2.1'
LOCAL = ROOT / 'native/sbc-prototype'
BUILD = ROOT / 'staging/native-sbc'
ARCHIVE_SHA256 = '426633cabd7c798236443516dfa8335b47e004b0ef37ff107e0c7ead3299fcc2'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    try:
        return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.output) from error


def main():
    archive = ROOT / 'sources/deep-research/sbc-2.1.tar.xz'
    if sha(archive) != ARCHIVE_SHA256:
        raise ValueError('Unexpected upstream archive hash')
    # Check the source used by this build, not just the downloaded archive.
    upstream_files = [SOURCE / 'sbc/sbc.c', *sorted((SOURCE / 'sbc').glob('*.h'))]
    with tarfile.open(archive, 'r:xz') as package:
        for source in upstream_files:
            member = 'sbc-2.1/' + source.relative_to(SOURCE).as_posix()
            original = package.extractfile(member)
            if original is None or original.read() != source.read_bytes():
                raise ValueError('Upstream source differs from archive: ' + member)
    BUILD.mkdir(parents=True, exist_ok=True)
    compiler = 'arm-linux-gnueabi-gcc'
    flags = ['-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft', '-Os',
             '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
             '-fno-pie', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
             '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra',
             '-I' + str(SOURCE / 'sbc'), '-I' + str(LOCAL)]
    objects, commands = [], []
    sources = [SOURCE / 'sbc/sbc.c', LOCAL / 'decoder.c', LOCAL / 'runtime.c']
    for source in sources:
        obj = BUILD / (source.stem + '.o')
        cmd = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        output = run(cmd)
        if output: print(output)
        objects.append(str(obj))
        commands.append(cmd)
    elf = BUILD / 'decoder-armv6.elf'
    cmd = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
           '-nostdlib', '-static', '-no-pie',
           '-Wl,--gc-sections,--build-id=none,-Map=' + str(BUILD / 'decoder.map'),
           '-Wl,-T,' + str(LOCAL / 'emulation.ld'),
           '-Wl,--undefined=garmin_sbc_decode_frame', *objects, '-lgcc', '-o', str(elf)]
    output = run(cmd)
    if output: print(output)
    commands.append(cmd)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Unresolved runtime symbols: ' + undefined)
    symbols_text = run(['arm-linux-gnueabi-nm', '-n', str(elf)])
    symbols = {}
    for line in symbols_text.splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = {'address': int(fields[0], 16), 'type': fields[1]}
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attributes or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected ISA or dynamic runtime requirement')
    flat = BUILD / 'decoder-armv6.bin'
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    for license_file in ('COPYING', 'COPYING.LIB'):
        shutil.copyfile(SOURCE / license_file, BUILD / license_file)
    info = {'compiler': run([compiler, '--version']).splitlines()[0],
            'upstream': {'version': '2.1', 'archive': str(archive.relative_to(ROOT)),
                         'url': 'https://www.kernel.org/pub/linux/bluetooth/sbc-2.1.tar.xz',
                         'archive_sha256': ARCHIVE_SHA256,
                         'license': 'LGPL-2.1-or-later', 'sbc_c_modified': False,
                         'source_and_headers_verified_against_archive': True},
            'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                              [*sources, LOCAL / 'decoder.h', LOCAL / 'emulation.ld',
                               *sorted((SOURCE / 'sbc').glob('*.h'))]},
            'commands': commands, 'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
            'flat_binary_bytes': flat.stat().st_size, 'flat_binary_sha256': sha(flat),
            'attributes': attributes, 'segments': segments, 'symbols': symbols,
            'undefined_symbols': [], 'device_io': False, 'firmware_patch': False,
            'garmin_abi_identified': False, 'native_on_device_verified': False,
            'synthetic_link_base': '0x08000000',
            'limitations': 'Single-context SBC decoder only. No Garmin loader, UI, A2DP transport or speaker ABI. ELF/flat addresses are emulator mappings, not known free Garmin RAM. Preserve upstream source/licenses and relinkable objects for any future distribution.'}
    (BUILD / 'manifest.json').write_text(json.dumps(info, indent=2) + '\n')
    print(json.dumps({'manifest': str(BUILD / 'manifest.json'),
                      'flat_binary_bytes': info['flat_binary_bytes'],
                      'elf_sha256': info['elf_sha256'], 'device_io': False}))


if __name__ == '__main__':
    main()
