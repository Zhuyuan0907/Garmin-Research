#!/usr/bin/env python3
"""Execute the stock Discover handler with synthetic RAM on the Pi.

Unicorn executes the exact backed-up Thumb instructions. The L2CAP send call
is replaced by a capture hook; this script has no device/Bluetooth I/O.
"""
import hashlib
import json
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR)

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace

HANDLER = 0x5747b4
SEND = 0x5a7794
STATE = 0x3a88ef0
DESCRIPTORS = 0x3a89058
RETURN = 0x10000


def run(image, slots, sdp_sink_enabled=False):
    emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emulator.ctl_set_cpu_model(UC_CPU_ARM_1176)
    emulator.mem_map(0x574000, 0x2000)
    emulator.mem_write(0x574000, image.read(0x574000, 0x2000))
    emulator.mem_map(SEND & ~0xfff, 0x1000)
    emulator.mem_write(SEND, b'\x70\x47')  # Stub BX LR after capture.
    emulator.mem_map(0x3a88000, 0x2000)
    emulator.mem_map(0x3a7c000, 0x1000)
    emulator.mem_map(0x02000000, 0x10000)
    emulator.mem_map(RETURN, 0x1000)
    emulator.mem_write(0x3a88f50, struct.pack('<H', 0x1234))
    if sdp_sink_enabled:
        emulator.mem_write(0x3a7c108+7*12+4, struct.pack('<H', 1))
    for index, slot in enumerate(slots):
        if not 0 <= index < 3:
            raise ValueError('Only three observed endpoint slots')
        emulator.mem_write(STATE+index*32+0x12, bytes([slot.get('state', 0)]))
        emulator.mem_write(STATE+index*32+0x13, bytes([slot.get('pending', 0)]))
        emulator.mem_write(DESCRIPTORS+index*12+5, bytes([slot.get('media_type', 0)]))
        emulator.mem_write(DESCRIPTORS+index*12+8, bytes([slot.get('sink', 0)]))
    captured, visited = [], []

    def hook(uc, address, size, user_data):
        visited.append(address)
        if address == SEND:
            channel = uc.reg_read(UC_ARM_REG_R0)
            length = uc.reg_read(UC_ARM_REG_R1)
            buffer = uc.reg_read(UC_ARM_REG_R2)
            if not 6 <= length <= 12:
                raise ValueError('Unexpected Discover buffer length')
            raw = bytes(uc.mem_read(buffer, length))
            captured.append({'channel': channel, 'buffer_length': length,
                             'reserved_prefix_hex': raw[:4].hex(),
                             'avdtp_frame_hex': raw[4:].hex()})
            uc.reg_write(UC_ARM_REG_R0, 0)
        if address == RETURN:
            uc.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, hook)
    emulator.reg_write(UC_ARM_REG_SP, 0x0200f000)
    emulator.reg_write(UC_ARM_REG_LR, RETURN | 1)
    emulator.reg_write(UC_ARM_REG_R0, 0)  # Signalling channel index.
    emulator.reg_write(UC_ARM_REG_R1, 1)  # Signal identifier (unused by handler).
    emulator.reg_write(UC_ARM_REG_R2, 1)  # Transaction label.
    emulator.emu_start(HANDLER | 1, RETURN+2, timeout=1000000, count=2000)
    if not visited or visited[-1] != RETURN or len(captured) != 1:
        raise ValueError('Handler did not return cleanly after one captured send')
    return {'slots': slots, 'synthetic_sdp_sink_enabled': sdp_sink_enabled,
            'send': captured[0], 'instructions_executed': len(visited)}


def main():
    image = NativeImage()
    scenarios = [
        ('all_slots_inactive', [{}, {}, {}], False, '1201'),
        ('sdp_enabled_without_sep', [{}, {}, {}], True, '1201'),
        ('first_audio_sink_available', [{'state': 1, 'sink': 1}, {}, {}], False, '12010408'),
        ('first_audio_sink_in_use', [{'state': 2, 'sink': 1}, {}, {}], False, '12010608'),
        ('third_audio_sink_available', [{}, {}, {'state': 1, 'sink': 1}], False, '12010c08'),
        ('three_slots_media_and_use_bits', [{'state': 1}, {'state': 2, 'sink': 1},
                                           {'state': 1, 'media_type': 1, 'sink': 1}], False, '120104000a080c18'),
    ]
    results = []
    for name, slots, sdp, expected in scenarios:
        result = run(image, slots, sdp)
        result.update(name=name, expected_frame_hex=expected)
        result['passed'] = result['send']['avdtp_frame_hex'] == expected
        if not result['passed']:
            raise ValueError(f'Unexpected emulated Discover frame in {name}: {result}')
        results.append(result)
    dispatch = struct.unpack('<10I', image.read(0xba6f6c, 40))
    if dispatch[0] != HANDLER | 1:
        raise ValueError('Discover dispatch pointer mismatch')
    output = {'stock_sha256': EXPECTED, 'emulator': 'Unicorn', 'module_version': unicorn.__version__,
              'cpu_model': 'ARM1176', 'discover_handler': hex(HANDLER),
              'handler_code_sha256': hashlib.sha256(image.read(HANDLER, 0x574854-HANDLER)).hexdigest(),
              'dispatch_table': hex(0xba6f6c), 'signal_1_pointer': hex(dispatch[0]),
              'state_table': {'base': hex(STATE), 'slots': 3, 'stride': 32,
                              'state_offset': 0x12, 'pending_use_offset': 0x13,
                              'initial_state': 'Zeroed by 0x4ccc3c AVDTP initialization'},
              'descriptor_table': {'base': hex(DESCRIPTORS), 'stride': 12,
                                   'media_type_offset': 5, 'source_sink_offset': 8},
              'l2cap_send_hook': hex(SEND), 'device_io': False, 'firmware_modified': False,
              'cases': results, 'all_passed': all(r['passed'] for r in results),
              'handler_instructions': trace(image, HANDLER, 400),
              'dispatcher_instructions': trace(image, 0x5247fc, 700),
              'sources': ['https://www.bluetooth.org/docman/handlers/DownloadDoc.ashx?doc_id=8241'],
              'limitations': 'Synthetic RAM and intercepted L2CAP only. Reproducing an empty frame in emulation does not prove live RAM contents or that a functional endpoint can be registered. Synthetic Sink descriptors do not provide codecs, stream callbacks, decoding or speaker playback.'}
    path = ROOT/'evidence/firmware-analysis/avdtp-discover-emulation.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'cases_passed': len(results),
                      'frames': {r['name']: r['send']['avdtp_frame_hex'] for r in results},
                      'device_io': False}))


if __name__ == '__main__':
    main()
