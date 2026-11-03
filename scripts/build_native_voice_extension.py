#!/usr/bin/env python3
"""Append a decoder after original TTS RAM; produce emulator-only binaries.

This retains original bytes except the entry branch and two size words. It
does NOT write a VPM, modify a SIG, or install anything on the navigator.
"""
import argparse
import json
import shutil
import struct
from pathlib import Path

from build_native_sbc import ROOT, LOCAL, SOURCE, ARCHIVE_SHA256, run, sha
from analyze_native_loader import IMAGE

OUT = ROOT / 'staging/native-voice-extension-emulation'


def build(record, baseline, media=False, convert=False):
    original_path = ROOT / record['module']['extracted_binary']
    original = original_path.read_bytes()
    original_sha = record['files']['DLLIMG.BIN']['sha256']
    if sha(original_path) != original_sha: raise ValueError('Original TTS image changed')
    stem = Path(record['file']).stem
    destination = (ROOT/'staging/native-voice-convert-extension-emulation' if convert else
                   ROOT/'staging/native-voice-media-extension-emulation' if media else OUT) / stem
    destination.mkdir(parents=True, exist_ok=True)
    original_ram = record['module']['image_header_ram_bytes']
    extension_offset = (original_ram+31) & ~31
    extension_base = IMAGE + extension_offset
    original_entry = IMAGE + record['module']['first_branch_offset']
    entry = 'voice_convert_entry' if convert else 'voice_extension_entry'
    linker = destination/'extension.ld'
    linker.write_text(f'''/* Emulator-only, no device installation. */
ENTRY({entry})
PHDRS {{ code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }}
original_tts_entry = {original_entry:#x};
SECTIONS {{
    . = {extension_base:#x};
    .entry : {{ KEEP(*(.text.{entry})) }} :code
    .text : {{ *(.text*) }} :code
    .rodata : {{ KEEP(*(.extension_exports)) *(.rodata*) }} :code
    . = ALIGN(32);
    .data : {{ *(.data*) }} :data
    . = ALIGN(32);
    .bss (NOLOAD) : {{
        __extension_bss_start = .;
        *(.bss*) *(COMMON)
        __extension_bss_end = .;
    }} :data
    __extension_end = .;
    __combined_ram_bytes = . - {IMAGE:#x};
    ASSERT(__combined_ram_bytes <= 0x300000, "Exceeds original loader capacity")
    /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    compiler = baseline['commands'][0][0]
    flags = baseline['commands'][0][1:-4]
    sources = [SOURCE/'sbc/sbc.c', LOCAL/'decoder.c', LOCAL/'runtime.c',
               LOCAL/'voice_extension.c']
    if media: sources.append(LOCAL/'voice_media.c')
    additional_sources = []
    if convert:
        converter = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
        for path, expected in converter['source_sha256'].items():
            if sha(ROOT/path) != expected: raise ValueError('Converter source changed: '+path)
        sources.extend([LOCAL/'pcm_converter.c', LOCAL/'voice_convert_extension.c'])
        additional_sources.extend([LOCAL/'pcm_converter.h', ROOT/converter['generated_header'],
                                   ROOT/converter['coefficient_table']])
    objects, commands = [], []
    for source in sources:
        obj = destination/(source.stem+'.o')
        extra = []
        if convert:
            extra.append('-I'+str((ROOT/converter['generated_header']).parent))
            if source.name == 'voice_media.c':
                extra.extend(['-DVOICE_MEDIA_CONVERT=1',
                              '-Dvoice_extension_submit_frame=voice_convert_submit_frame'])
        command = [compiler, *flags, *extra, '-c', str(source), '-o', str(obj)]
        run(command)
        objects.append(str(obj)); commands.append(command)
    elf = destination/'extension-emulation.elf'
    command = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
               '-nostdlib', '-static', '-no-pie',
               '-Wl,--gc-sections,--build-id=none,-Map='+str(destination/'extension.map'),
               '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(command); commands.append(command)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Unresolved extension symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    # Calls from a future in-module integration need these symbols retained.
    for name in ('garmin_sbc_reset', 'garmin_sbc_decode_frame'):
        if name not in symbols: raise ValueError('Decoder API was removed by linker: '+name)
    if symbols[entry]['address'] != extension_base:
        raise ValueError('Extension entry differs from the appended offset')
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attributes or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected extension ISA/runtime')
    flat = destination/'extension-emulation.bin'
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    extension = flat.read_bytes()
    combined = bytearray(original)
    combined.extend(bytes(extension_offset-len(original)))
    combined.extend(extension)
    combined_ram = symbols['__combined_ram_bytes']['address']
    displacement = extension_base - (IMAGE+8)
    if displacement % 4 or not -(1 << 25) <= displacement < 1 << 25:
        raise ValueError('Entry outside ARM branch range')
    struct.pack_into('<3I', combined, 0,
                     0xea000000 | ((displacement//4) & 0xffffff), combined_ram, len(combined))
    if combined[12:len(original)] != original[12:]:
        raise ValueError('Original code/data changed outside allowed header words')
    if not len(combined) < combined_ram <= 0x300000:
        raise ValueError('Combined image footprint is invalid')
    combined_path = destination/'voice-extension-emulation.bin'
    combined_path.write_bytes(combined)
    for name in ('COPYING', 'COPYING.LIB'): shutil.copyfile(SOURCE/name, destination/name)
    manifest = {
        'voice_package': record['file'], 'original_binary': str(original_path.relative_to(ROOT)),
        'original_binary_sha256': original_sha, 'original_file_bytes': len(original),
        'original_ram_bytes': original_ram, 'original_arm_entry': original_entry,
        'extension_offset': extension_offset, 'extension_base': extension_base,
        'extension_bytes': len(extension), 'original_header_words': list(struct.unpack_from('<3I', original)),
        'combined_header_words': list(struct.unpack_from('<3I', combined)),
        'header_mutation_offsets': [0, 4, 8], 'original_bytes_after_header_unchanged': True,
        'combined_binary': str(combined_path.relative_to(ROOT)), 'combined_sha256': sha(combined_path),
        'combined_file_bytes': len(combined), 'combined_ram_bytes': combined_ram,
        'extension_elf': str(elf.relative_to(ROOT)), 'extension_elf_sha256': sha(elf),
        'extension_flat': str(flat.relative_to(ROOT)), 'extension_flat_sha256': sha(flat),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                         [*sources, LOCAL/'decoder.h', linker, *additional_sources]},
        'symbols': symbols, 'commands': commands, 'attributes': attributes, 'segments': segments,
        'undefined_symbols': [], 'upstream': baseline['upstream'],
        'registers_replacement_tts_exports': False, 'device_io': False,
        'includes_media_callback': media,
        'includes_pcm_conversion': convert, 'entry_symbol': entry,
        'decoder_api_table': 'voice_convert_decoder_api' if convert else 'voice_extension_decoder_api',
        'registers_real_bluetooth_endpoint': False,
        'device_install_candidate': False, 'modified_vpm_generated': False,
        'signature_modified': False, 'signature_acceptance_verified': False,
        'limitations': 'Offline extension/coexistence experiment only. The original bootstrap registers its own 40 APIs, and decoder calls use appended local symbols. Bootstrap/export preservation must be tested in emulation; speech synthesis is not verified. VPM mount/SIG acceptance, actual loading, UI/A2DP integration and hardware are unverified. Never install this binary.'}
    path = destination/'manifest.json'
    path.write_text(json.dumps(manifest, indent=2)+'\n')
    return {'manifest': str(path.relative_to(ROOT)), 'voice': stem,
            'combined_file_bytes': len(combined), 'combined_ram_bytes': combined_ram}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--voice', default='Chinese_Big5_MeiLing',
                        help='Original voice package stem, or all')
    parser.add_argument('--media', action='store_true',
                        help='Append offline RTP/SBC callback; does not register a real SEP')
    parser.add_argument('--convert', action='store_true',
                        help='With --media, link validated stereo/FIR conversion to mono16k')
    args = parser.parse_args()
    if args.convert and not args.media: parser.error('--convert requires --media')
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    if sha(ROOT/baseline['upstream']['archive']) != ARCHIVE_SHA256:
        raise ValueError('Unexpected upstream SBC archive')
    for path, expected in baseline['source_sha256'].items():
        if sha(ROOT/path) != expected: raise ValueError('Baseline source changed: '+path)
    containers = json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())
    rows = [r for r in containers['containers'] if r['native_module_container']
            and (args.voice == 'all' or Path(r['file']).stem == args.voice)]
    if not rows: raise ValueError('Original voice package not found')
    result = [build(row, baseline, args.media, args.convert) for row in rows]
    print(json.dumps({'built': result, 'device_io': False, 'device_install_candidate': False}))


if __name__ == '__main__':
    main()
