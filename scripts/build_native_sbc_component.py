#!/usr/bin/env python3
"""Build the native decoder as an emulator-only stock component experiment."""
import hashlib
import argparse
import json
import shutil
import struct
from pathlib import Path

from build_native_sbc import ROOT, LOCAL, SOURCE, ARCHIVE_SHA256, run, sha

BUILD = ROOT / 'staging/native-sbc-component-emulation'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audio-route', action='store_true',
                        help='Separate emulator-only PCM callback experiment')
    args = parser.parse_args()
    global BUILD
    if args.audio_route:
        BUILD = ROOT / 'staging/native-sbc-pcm-emulation'
    base = json.loads((ROOT / 'staging/native-sbc/manifest.json').read_text())
    if sha(ROOT / base['upstream']['archive']) != ARCHIVE_SHA256:
        raise ValueError('Unexpected upstream package')
    for path, expected in base['source_sha256'].items():
        if sha(ROOT / path) != expected:
            raise ValueError('Rebuild/verify the baseline after source change: ' + path)
    BUILD.mkdir(parents=True, exist_ok=True)
    compiler = base['commands'][0][0]
    flags = base['commands'][0][1:-4]
    sources = [SOURCE / 'sbc/sbc.c', LOCAL / 'decoder.c', LOCAL / 'runtime.c',
               LOCAL / ('component_audio.c' if args.audio_route else 'component.c'),
               LOCAL / 'component_header.S']
    commands, objects = [], []
    for source in sources:
        obj = BUILD / (source.stem + '.o')
        cmd = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        output = run(cmd)
        if output: print(output)
        commands.append(cmd)
        objects.append(str(obj))
    elf = BUILD / 'component-emulation.elf'
    cmd = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
           '-nostdlib', '-static', '-no-pie',
           '-Wl,--gc-sections,--build-id=none,-Map=' + str(BUILD / 'component.map'),
           '-Wl,-T,' + str(LOCAL / 'component_emulation.ld'),
           *objects, '-lgcc', '-o', str(elf)]
    output = run(cmd)
    if output: print(output)
    commands.append(cmd)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Unresolved component symbols: ' + undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = {'address': int(fields[0], 16), 'type': fields[1]}
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attributes or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected component ISA/runtime')
    flat = BUILD / 'component-emulation.bin'
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    header = struct.unpack_from('<2I', flat.read_bytes())
    ram_bytes = symbols['__component_ram_bytes']['address']
    if header[1] != ram_bytes or not flat.stat().st_size < ram_bytes <= 0x300000:
        raise ValueError('Component footprint header differs from linked memory')
    if symbols['garmin_component_start']['address'] != 0x2d4bb74:
        raise ValueError('Wrong fixed loader entry')
    for name in ('COPYING', 'COPYING.LIB'):
        shutil.copyfile(SOURCE / name, BUILD / name)
    manifest = {'compiler': base['compiler'], 'upstream': base['upstream'],
                'baseline_manifest': 'staging/native-sbc/manifest.json',
                'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                                  [*sources, LOCAL / 'component_emulation.ld', LOCAL / 'decoder.h']},
                'commands': commands, 'symbols': symbols, 'attributes': attributes,
                'segments': segments, 'undefined_symbols': [],
                'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
                'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
                'flat_binary_bytes': flat.stat().st_size, 'ram_bytes': ram_bytes,
                'bss_start': symbols['__component_bss_start']['address'],
                'bss_bytes': symbols['__component_bss_end']['address'] - symbols['__component_bss_start']['address'],
                'exports': ['garmin_sbc_reset', 'garmin_sbc_decode_frame'] +
                           (['garmin_sbc_submit_frame'] if args.audio_route else []),
                'preserves_original_component_api': False,
                'device_install_candidate': False, 'device_io': False,
                'native_pcm_callback_experiment': args.audio_route,
                'limitations': 'Emulator-only native loader experiment. Experimental exports do not preserve the original 40 TTS APIs. The optional audio variant submits only 16 kHz mono PCM through host slot 0; resampling, native UI, A2DP, physical speaker/sample clock and real loading/recovery remain unverified. It must not be installed as dllimg.bin.'}
    (BUILD / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'manifest': str(BUILD / 'manifest.json'),
                      'binary_bytes': manifest['flat_binary_bytes'], 'ram_bytes': ram_bytes,
                      'bss_bytes': manifest['bss_bytes'], 'device_install_candidate': False}))


if __name__ == '__main__':
    main()
