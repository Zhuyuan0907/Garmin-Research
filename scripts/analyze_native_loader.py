#!/usr/bin/env python3
"""Describe the stock dllimg component loader, without touching the device."""
import array
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from analyze_native_sections import NativeImage, ROOT, BASE, EXPECTED
from analyze_sdp_activation import trace

INIT = 0x23c3c4
TRAMPOLINES = 0x3b3268
READ = 0x3b3294
EXECUTE = 0x3b331a
DESCRIPTOR = 0x304bb74
IMAGE = 0x2d4bb74
STUBS = 0x2d4b994


def scan_calls(image, targets):
    hits = {hex(target): [] for target in targets}
    words = array.array('H', image.read(BASE, 0xcb179c-BASE))
    for n in range(len(words)-1):
        a, b = words[n], words[n+1]
        if a & 0xf800 == 0xf000 and b & 0xf800 == 0xf800:
            offset = ((a & 0x7ff) << 12) | ((b & 0x7ff) << 1)
            if offset & 0x400000: offset -= 0x800000
            address = BASE + n*2
            target = address+4+offset
            if target in targets:
                ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
                if ins and ins.mnemonic == 'bl': hits[hex(target)].append(hex(address))
    return hits


def main():
    image = NativeImage()
    entries = [INIT, TRAMPOLINES, READ, EXECUTE, 0x38a398, 0x240498,
               0x43424c, 0x40c0ec, 0x2356bc, 0x1fb304]
    functions = {hex(start): trace(image, start, 600) for start in entries}
    imports = struct.unpack('<40I', image.read(image.runtime_to_load(0xf092c4, 160), 160))
    if imports[-1] != 0xf092c0: raise ValueError('Unexpected import slot list')
    trampoline_words = (image.word(0x3b334c), image.word(0x3b3350))
    if trampoline_words != (0xe59fc000, 0xe12fff1c):
        raise ValueError('Unexpected ARM trampoline encoding')
    if image.read(0x23c4e8, 11) != b'dllimg.bin\0': raise ValueError('Name mismatch')
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    cache = [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
             for i in arm.disasm(image.read(0x6f0360, 0x34), 0x6f0360)]
    backup = ROOT / 'backups/20261002T154458Z/files'
    vpm_path = ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json'
    vpm = json.loads(vpm_path.read_text()) if vpm_path.exists() else None
    output = {'stock_sha256': EXPECTED, 'initializer': hex(INIT),
              'descriptor_runtime': hex(DESCRIPTOR),
              'descriptor_fields': {'0': 'Initialized to 0x50000; decremented on return code 5 retry',
                                    '4': '11 bytes dllimg.bin plus terminator copied here',
                                    '24': 'Loaded image/entry base 0x2d4bb74',
                                    '28': 'Maximum bytes 0x300000',
                                    '32': 'ARM trampoline base 0x2d4b994',
                                    '36': 'Unassigned pointer 0xf09364',
                                    '40': 'Initialized to 99; decremented on one retry boundary',
                                    '44': 'Thumb export-registration callback 0x2356bd',
                                    '48': 'Initialized to zero'},
              'import_slots_runtime': '0xf092c4', 'import_count': 40,
              'import_pointer_storage': [hex(v) for v in imports],
              'trampolines': {'builder': hex(TRAMPOLINES), 'base': hex(STUBS),
                              'stride': 12, 'count': 40,
                              'code_words': [hex(v) for v in trampoline_words],
                              'instructions': ['ldr ip, [pc]', 'bx ip'],
                              'target_word_offset': 8,
                              'target_word_initialized_by_builder': False},
              'file_reader': {'entry': hex(READ), 'filename_field_offset': 4,
                              'callback_order': ['close', 'open', 'read', 'seek', 'tell'],
                              'file_size_exceeds_limit_return': 4,
                              'header_word_4_exceeds_limit_return': 9,
                              'success_return': 11,
                              'image_postprocess': {'entry': '0x38a398', 'body': 'movs r0, #11; bx lr',
                                                    'observed_relocation_or_signature_check': False},
                              'read_return_value_checked': False},
              'executor': {'entry': hex(EXECUTE), 'invalid_name_comparison': 'Invalid',
                           'call_instruction': '0x3b3332 blx r1',
                           'entry_register_source': 'ldr r1, [r4, #0x18]',
                           'argument_r0': 'descriptor pointer',
                           'first_attempt_return_code_6_maps_to_11': True,
                           'retry_return_code_6_is_returned_unchanged': True},
              'export_registration': {'entry': '0x2356bc',
                                       'argument_r0': 'loader descriptor',
                                       'argument_r1': 'module descriptor',
                                       'module_descriptor_fields': {'0': 'version word',
                                                                    '12': 'export pointer array',
                                                                    '20': 'export count'},
                                       'accepted_version_high_words': [3, 4, 5],
                                       'matching_low_word_return': 11,
                                       'different_low_word_return': 6,
                                       'unsupported_high_word_return': 5,
                                       'target_write': 'loader[32] + export_index*12 + 8',
                                       'export_role_names_identified': False,
                                       'limitations': 'Numeric version/return behavior verified from instructions; semantic names and the exact 40 original API signatures are unknown.'},
              'cache_sync': {'wrapper': '0x221d2c', 'arm_veneer': '0x33e674',
                             'routine': '0x6f0360', 'instructions': cache},
              'conditional_caller': {'entry': '0x240498', 'call': '0x2404c2',
                                     'requires': ['Nonzero halfword written by 0x2741f4',
                                                  'Nonzero return from 0x2747cc'],
                                     'real_world_trigger_identified': False},
              'direct_thumb_bl_candidates': scan_calls(image, {INIT, TRAMPOLINES, READ, EXECUTE}),
              'backup_dllimg_files': [str(p.relative_to(backup)) for p in backup.rglob('*')
                                      if p.is_file() and p.name.lower() == 'dllimg.bin'],
              'component_location': {'internal_member': 'DLLIMG.BIN',
                                     'container_type': 'DSKIMG TTS VPM',
                                     'usb_container_directory': 'Voice',
                                     'containers_in_backup': [r['file'] for r in vpm['containers']
                                                              if r['native_module_container']] if vpm else [],
                                     'file_open_wrapper': '0x1fb304',
                                     'open_prefix': 'Integer internal drive number followed by colon',
                                     'drive_number_source': '0xfe648(active byte at 0xf09658+8)',
                                     'backup_evidence': 'evidence/firmware-analysis/tts-vpm-containers.json',
                                     'signature_files_present': bool(vpm),
                                     'signature_algorithm_or_enforcement_verified': False,
                                     'modified_container_acceptance_verified': False},
              'functions': functions,
              'device_io': False, 'native_application_running': False,
              'limitations': 'Stock component loader and matching original TTS VPM members are identified, not a generic application installation interface. Exact voice-selection/mount conditions, SIG enforcement and 40 original API signatures remain unverified. RAM ranges are stock loader addresses, not verified free RAM. Import targets are not initialized by the trampoline builder; a trivial returning image would leave required APIs invalid. No device file or firmware change is prepared.'}
    path = ROOT / 'evidence/firmware-analysis/native-component-loader.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'import_count': len(imports),
                      'component_file': 'dllimg.bin', 'entry_base': hex(IMAGE),
                      'generic_install_interface': False, 'device_io': False}))


if __name__ == '__main__':
    main()
