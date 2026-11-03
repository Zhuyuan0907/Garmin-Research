#!/usr/bin/env python3
"""Execute the exact stock touch-line handler on synthetic GUI events.

This is an offline ABI experiment for a future native projection receiver.
The actual input driver, page creation, redraw scheduler and phone transport
are NOT exercised. No stock instructions or device files are changed.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace

ENTRY = 0x5c1072
VTABLE = 0xc0d45c
OBJECT = 0x08002020
EVENT = 0x08004020
BUFFER = 0x08005020
STACK = 0x0800f000
RETURN = 0x10000
OBJECT_BYTES = 0x1000
EVENT_BYTES = 64
BUFFER_BYTES = 24*8
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def sha(blob): return hashlib.sha256(blob).hexdigest()
def require(test, reason):
    if not test: raise ValueError(reason)


def run(stock, kind, action, x, y, expected_append):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
    for section in stock.copies:
        start = section['runtime_start'] & ~4095
        end = (section['runtime_end']+4095) & ~4095
        uc.mem_map(start, end-start)
        uc.mem_write(section['runtime_start'],
                     stock.read(section['load_start'], section['size']))
    uc.mem_map(0x08000000, 0x10000)
    uc.mem_map(RETURN, 4096)
    for address, length in [(OBJECT, OBJECT_BYTES), (EVENT, EVENT_BYTES),
                            (BUFFER, BUFFER_BYTES)]:
        uc.mem_write(address-32, b'\xa5'*(length+64))
        uc.mem_write(address, bytes(length))
    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value & 0xffffffff))
    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]
    image = RuntimeImage(stock)
    require(image.word(VTABLE+4*4) == ENTRY+1, 'Stock event vslot differs')
    require(image.word(VTABLE+17*4) == 0x3775b5, 'Stock redraw vslot differs')
    put(OBJECT, VTABLE)
    # Actual getter3766C4 reads the rectangle at object+20 and zeroes XY.
    uc.mem_write(OBJECT+0x20, struct.pack('<4I', 0, 0, 480, 272))
    put(OBJECT+0x70c, BUFFER)
    put(OBJECT+0x710, BUFFER)
    put(OBJECT+0x714, BUFFER+BUFFER_BYTES)
    put(EVENT+0x10, x)
    put(EVENT+0x14, y)
    put(EVENT+0x20, 12345)
    put(EVENT+0x24, 67890)
    uc.mem_write(EVENT+0x28, bytes([action]))
    event_before = bytes(uc.mem_read(EVENT, EVENT_BYTES))
    visits, fixtures = Counter(), []
    returned = False
    code_start, code_end = ENTRY, 0x5c1304
    before = bytes(uc.mem_read(code_start, code_end-code_start))
    def observe(cpu, address, size, unused):
        nonlocal returned
        if address == RETURN:
            returned = True
            cpu.emu_stop()
            return
        visits[address] += 1
        values = [cpu.reg_read(reg) for reg in REGS]
        lr = cpu.reg_read(UC_ARM_REG_LR)
        if address == 0x279f34:
            require(lr == 0x5c1111, 'Unexpected diagnostic call path')
            text = bytes(cpu.mem_read(values[0], 96)).split(b'\0', 1)[0].decode()
            fixtures.append({'boundary': 'diagnostic_output', 'format': text,
                             'counter': values[1], 'time': values[2],
                             'x': values[3], 'y': word(cpu.reg_read(UC_ARM_REG_SP))})
        elif address == 0x3775b4:
            require(lr == 0x5c12f9 and values == [OBJECT, 0, 0, 480],
                    'Unexpected redraw request')
            sp = cpu.reg_read(UC_ARM_REG_SP)
            require([word(sp), word(sp+4)] == [272, 1], 'Redraw stack arguments differ')
            fixtures.append({'boundary': 'redraw_scheduler',
                             'rectangle': [0, 0, 480, 272], 'flag': 1})
        else:
            return
        cpu.reg_write(UC_ARM_REG_R0, 0)
        cpu.reg_write(UC_ARM_REG_PC, lr)
    uc.hook_add(UC_HOOK_CODE, observe)
    uc.reg_write(UC_ARM_REG_R0, OBJECT)
    uc.reg_write(UC_ARM_REG_R1, EVENT)
    uc.reg_write(UC_ARM_REG_SP, STACK)
    uc.reg_write(UC_ARM_REG_LR, RETURN+1)
    uc.emu_start(ENTRY+1, 0, timeout=10_000_000, count=100_000)
    require(returned, 'Handler did not complete')
    result = uc.reg_read(UC_ARM_REG_R0)
    require(result == 0, 'Expected native base handler result0 with no child listeners')
    added = (word(OBJECT+0x710)-BUFFER)//24
    require(added == int(expected_append), 'Unexpected event-record count')
    require(word(OBJECT+0x71c) == added, 'Original diagnostic counter differs')
    require(visits[0x3766c4] == 1 and visits[0x376bf6] == 1,
            'Actual rectangle/base handlers were bypassed')
    records = []
    if expected_append:
        require(visits[0x3819d4] == 1 and visits[0x6173a6] == 0,
                'Test must use original placement constructor, not vector growth')
        a, b, c, d, sequence = struct.unpack('<5I', uc.mem_read(BUFFER, 20))
        native_action = bytes(uc.mem_read(BUFFER+20, 1))[0]
        require([a,b,c,d,sequence,native_action] ==
                [x & 0xffffffff,y & 0xffffffff,12345,67890,0,action],
                'Original event copy differs')
        require(len(fixtures) == 2 and
                ('PRESSED' if action == 0 else 'DRAG') in fixtures[0]['format'],
                'Native diagnostic action differs')
        records.append({'x': x, 'y': y, 'fields20_24': [c,d],
                        'sequence': sequence, 'action': native_action})
    else:
        require(len(fixtures) == 1 and not visits[0x3819d4], 'Ignored event appended data')
    for address, length in [(OBJECT, OBJECT_BYTES), (EVENT, EVENT_BYTES),
                            (BUFFER, BUFFER_BYTES)]:
        require(bytes(uc.mem_read(address-32, 32)) == b'\xa5'*32 and
                bytes(uc.mem_read(address+length, 32)) == b'\xa5'*32,
                'Synthetic object/event/record canary changed')
    require(bytes(uc.mem_read(EVENT, EVENT_BYTES)) == event_before,
            'Input event mutated')
    require(bytes(uc.mem_read(code_start, code_end-code_start)) == before,
            'Original handler instructions changed')
    return {'kind': kind, 'action': action, 'input_xy': [x,y],
            'status': result, 'records_appended': added, 'records': records,
            'boundary_fixtures': fixtures, 'all_passed': True,
            'native_entry': hex(ENTRY), 'native_vtable': hex(VTABLE),
            'original_code_sha256_before_after': sha(before),
            'native_functions_executed': {hex(a): visits[a] for a in
                (ENTRY, 0x3766c4, 0x376bf6, 0x3819d4, 0x6173a6)},
            'temporary_buffer_guards_intact': True,
            'real_input_driver_or_registered_App_exercised': False}


def main():
    stock = NativeImage()
    cases = [run(stock,*args) for args in [
        ('press_at_origin',0,0,0,True),
        ('drag_at_center',3,240,136,True),
        ('drag_at_last_screen_pixel',3,479,271,True),
        ('press_outside_synthetic_screen_not_clamped',0,-3,700,True),
        ('action2_ignored',2,100,100,False),
        ('unknown_action_ignored',254,100,100,False)]]
    funcs = {hex(a):trace(RuntimeImage(stock),a,2500)
             for a in [ENTRY,0x3766c4,0x376bf6,0x3819d4]}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in funcs.values()), 'Unresolved bounded function CFG')
    paths = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
             ROOT/'scripts/analyze_native_voice_acceptance.py',
             ROOT/'scripts/analyze_sdp_activation.py',
             ROOT/'evidence/firmware-analysis/main_02bd.bin']
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name and Path(name).resolve().parent == ROOT/'scripts' and name.endswith('.py'):
            paths.append(Path(name).resolve())
    result = {'updated_utc':datetime.now(timezone.utc).isoformat(),
        'stock_sha256': EXPECTED, 'all_passed':True, 'cases':cases,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in paths},
        'static_functions':funcs, 'device_io':False,
        'release_action1_static_branch_identified_but_not_executed':True,
        'scope':'Stock diagnostic page event consumer with a synthetic existing page, preallocated vector and events. Native geometry getter, placement constructor and base handler execute; diagnostic output and redraw scheduling are fixtures. No page construction, input driver, release handling, vector growth, new native UI registration, scaling, AA framing/TLS, real phone or display output is tested.',
        'native_Android_Auto_running':False, 'device_install_candidate':False}
    output=ROOT/'evidence/firmware-analysis/native-projection-touch-emulation.json'
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(output.relative_to(ROOT)), 'cases':len(cases),
                      'all_passed':True, 'device_io':False}))


if __name__ == '__main__': main()
