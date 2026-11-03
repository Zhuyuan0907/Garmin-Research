#!/usr/bin/env python3
"""Execute stock cable-state debouncing and callback-table initialization offline.

Channel registrations, policy, task handle, memory and controller registers are
synthetic. Queue publication, notification and logging are explicit boundaries.
No physical USB, ADC, VBUS, phone, firmware modification or installation.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from emulate_native_projection_io import Probe, USB, require

RECORD = 0x02cea2c4
CONTROL = 0x00f07100
PROFILES = 0x014a882c
PROFILE_BYTES, CHANNEL_STRIDE, TYPE_STRIDE = 0x4b40, 0x12d0, 0x158
DRIVER_VECTOR = 0x02cf4330


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


class TransitionProbe(Probe):
    def __init__(self, stock, queue_result=1):
        super().__init__(stock)
        self.queue_result = queue_result
        self.events = []

    def observe(self, uc, address, size, user):
        if address in (0x37bce4, 0x3cc594, 0x32303e):
            lr = uc.reg_read(UC_ARM_REG_LR)
            if address == 0x37bce4:
                require(lr == 0x322ef3, 'Unexpected queue-publication caller')
                handle, pointer = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
                require(handle == 0x12345678, 'Wrong synthetic task handle')
                row = {'boundary': 'queue_publication', 'message_hex': self.data(pointer, 6).hex(),
                       'fixture_return': self.queue_result, 'caller_LR': hex(lr)}
                result = self.queue_result
            elif address == 0x3cc594:
                require(lr == 0x33229d and uc.reg_read(UC_ARM_REG_R0) == 0x2cea324,
                        'Unexpected state notification')
                row = {'boundary': 'state_notification',
                       'message_hex': self.data(uc.reg_read(UC_ARM_REG_R1), 3).hex(),
                       'caller_LR': hex(lr)}
                result = 0
            else:
                require(lr == 0x3238df, 'Unexpected callback initializer logger')
                row = {'boundary': 'diagnostic_logging', 'caller_LR': hex(lr)}
                result = 0
            self.events.append(row)
            self.fixtures.append({'function': hex(address), **row})
            self.visits[address] += 1
            uc.reg_write(UC_ARM_REG_R0, result)
            uc.reg_write(UC_ARM_REG_PC, lr)
            return
        super().observe(uc, address, size, user)


def record_fixture(p, old=13, policy=0, handle=0x12345678, enabled=1):
    p.uc.mem_map(RECORD & ~4095, 4096)
    p.guarded(RECORD, 24)
    data = bytearray(24)
    data[:4] = bytes((0, old, 14, 14))
    struct.pack_into('<4I', data, 4, 3290, 0x8dcd8c, 0x8dcd40, 0x8dcdfc)
    data[20] = 11
    p.uc.mem_write(RECORD, bytes(data))
    p.uc.mem_write(0xf08ac0, bytes((policy,)))
    p.guarded(CONTROL, 8)
    control = bytes((0, enabled, 0, 0)) + struct.pack('<I', handle)
    p.uc.mem_write(CONTROL, control)
    return control


def transition(stock, name, candidates, *, old=13, policy=0,
               handle=0x12345678, enabled=1, queue_result=1, channel=0,
               expected_final, expected_queue, expected_notify, expected_counters):
    p = TransitionProbe(stock, queue_result)
    control = record_fixture(p, old, policy, handle, enabled)
    original_record = p.data(RECORD, 24)
    snapshots = []
    for candidate in candidates:
        p.call(0x332216, channel, candidate)
        p.guard_ok(RECORD, 24)
        p.guard_ok(CONTROL, 8)
        require(p.data(CONTROL, 8) == control, 'Task gate/handle modified')
        data = p.data(RECORD, 24)
        require(all(data[n] == original_record[n] for n in range(24) if n not in (1,2,3,21)),
                'Transition changed registered channel metadata')
        snapshots.append({'candidate_input': candidate, 'old_type_field': data[2],
                          'current_type_field': data[1], 'candidate_field': data[3],
                          'debounce_counter': data[21]})
    queues = [e['message_hex'] for e in p.events if e['boundary'] == 'queue_publication']
    notices = [e['message_hex'] for e in p.events if e['boundary'] == 'state_notification']
    require(snapshots[-1]['current_type_field'] == expected_final, 'Final cable type differs')
    require([s['debounce_counter'] for s in snapshots] == expected_counters, 'Debounce differs')
    require(queues == expected_queue and notices == expected_notify, 'Message/state flow differs')
    require(set(e['boundary'] for e in p.events) <= {'queue_publication', 'state_notification'},
            'Unexpected execution boundary')
    return {'name': name, 'fixtures': {'channel': channel, 'old_type': old, 'policy': policy,
        'task_handle': hex(handle), 'queue_enabled': enabled, 'queue_return': queue_result},
        'snapshots': snapshots, 'events': p.events, 'all_passed': True,
        'native_transition_calls': p.visits[0x332216],
        'native_message_builder_calls': p.visits[0x322f0e],
        'native_publication_gate_calls': p.visits[0x322edc],
        'record_and_control_guards_intact': True, 'function_fixtures': p.fixtures,
        'immutable_channel_registration_fields_unchanged': True,
        'actual_queue_worker_ADC_USB_role_or_VBUS_executed': False}


def callbacks(stock):
    p = TransitionProbe(stock)
    start, end = PROFILES & ~4095, (PROFILES + PROFILE_BYTES + 32 + 4095) & ~4095
    p.uc.mem_map(start, end-start)
    p.guarded(PROFILES, PROFILE_BYTES)
    before_control = p.data(CONTROL, 8)
    p.call(0x323818)
    p.guard_ok(PROFILES, PROFILE_BYTES)
    require(p.visits[0x35b4f4] == 1, 'Native ARM clear skipped')
    require(p.data(CONTROL+1, 1) == b'\x01', 'Initializer did not enable publication')
    after_control = p.data(CONTROL, 8)
    require(after_control[:1] == before_control[:1] and after_control[2:] == before_control[2:],
            'Callback initializer changed another task-control field')
    expected = {
        1: (0x323593,0x323595), 3: (0x32358f,0x323591),
        4: (0x32338d,0x32341f), 7: (0x323551,0x323569),
        9: (0x323551,0x323569), 10: (0x322de1,0x322dd7),
        11: (0x32338d,0x32341f), 12: (0x322e89,0x322e77),
        13: (0x322ec7,0x322e93),
    }
    records = []
    for channel in range(4):
        for cable_type in range(14):
            address = PROFILES + channel*CHANNEL_STRIDE + cable_type*TYPE_STRIDE
            raw = p.data(address, TYPE_STRIDE)
            close, opened = struct.unpack_from('<2I', raw, 4)
            require(raw[0] == channel, 'Wrong initialized channel')
            require((close, opened) == expected.get(cable_type, (0x3230ff,0x3230fd)),
                    'Original callback table differs')
            # Outside the channel byte and two pointers, all fields remain zero.
            require(raw[1:4] == bytes(3) and raw[12:] == bytes(TYPE_STRIDE-12),
                    'Unexpected callback profile data')
            records.append({'channel': channel, 'type': cable_type,
                            'close_callback': hex(close), 'open_callback': hex(opened)})
    p.call(0x3230fc)
    p.call(0x3230fe)
    require(all(e['boundary'] == 'diagnostic_logging' for e in p.events), 'Unexpected init boundary')
    return {'original_initializer': '0x323818', 'original_ARM_clear': '0x35b4f4',
        'profile_bytes': PROFILE_BYTES, 'channel_stride': CHANNEL_STRIDE,
        'type_stride': TYPE_STRIDE, 'records': records, 'all_passed': True,
        'guard_intact': True, 'default_callbacks_executed_and_returned': True,
        'default_callbacks_exact_body': 'BX LR', 'function_fixtures': p.fixtures,
        'other_task_control_bytes_unchanged': True,
        'nondefault_callbacks_or_hardware_not_executed': True}


def driver_selector(stock, selector):
    p = TransitionProbe(stock)
    p.uc.mem_map(DRIVER_VECTOR & ~4095, 4096)
    p.guarded(DRIVER_VECTOR, 0x70)
    p.call(0x21289c, selector)
    p.guard_ok(DRIVER_VECTOR, 0x70)
    branch = 0x212740 if selector == 3 else 0x21279c
    slots = {offset: hex(p.word(DRIVER_VECTOR+offset)) for offset in range(0,0x70,4)}
    require(p.visits[branch] == 1 and p.visits[0x35b4f4] == 1 and not p.fixtures,
            'Original board-control vector selection bypassed')
    if selector == 3:
        require(slots[0x28] == slots[0x2c] == slots[0x30] == '0x122b29', 'First board vector differs')
    else:
        require([slots[o] for o in (0x28,0x2c,0x30)] == ['0x1551a1','0x1551b1','0x155213'],
                'Second board vector differs')
    return {'synthetic_selector': selector, 'selected_initializer': hex(branch), 'slots': slots,
        'all_passed': True, 'guard_intact': True, 'function_fixtures': [],
        'board_selector_actual_value_or_target_functions_executed': False,
        'not_claimed_as_USB_host_driver_vector': True}


def softconnect(stock, initial, argument):
    p = TransitionProbe(stock)
    p.uc.mem_write(USB, b'\xa5'*32)
    p.uc.mem_write(USB+1, bytes((initial,)))
    before = p.data(USB, 32)
    p.call(0x332012, argument)
    expected = initial | 0x40 if argument else initial & 0xbf
    after = p.data(USB, 32)
    require(after[1] == expected and after[:1] == before[:1] and after[2:] == before[2:],
            'Original register toggle changed another field')
    require(not p.fixtures, 'Register toggle reached an unexpected function')
    return {'synthetic_POWER_byte_before': initial, 'argument': argument, 'after': expected,
        'original_function': '0x332012', 'register_address': hex(USB+1),
        'all_passed': True, 'adjacent_register_bytes_unchanged': True, 'function_fixtures': [],
        'real_softconnect_VBUS_or_host_session_not_executed': True}


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    require(image.read(0x3230fc,4) == bytes.fromhex('70477047'), 'Default callbacks not BX LR')
    cases = [
        transition(stock, 'TypeB_to_TypeA', [0,0,0], expected_final=0,
                   expected_queue=['01000d000100'], expected_notify=['00000d'], expected_counters=[1,2,3]),
        transition(stock, 'TypeA_to_TypeB', [13,13,13], old=0, expected_final=13,
                   expected_queue=['0100000d0001'], expected_notify=['000d00'], expected_counters=[1,2,3]),
        transition(stock, 'missing_task_handle', [0,0,0], handle=0, expected_final=13,
                   expected_queue=[], expected_notify=['000d0e'], expected_counters=[1,2,3]),
        transition(stock, 'disabled_publication', [0,0,0], enabled=0, expected_final=13,
                   expected_queue=[], expected_notify=['000d0e'], expected_counters=[1,2,3]),
        transition(stock, 'publication_return_zero_is_ignored_by_wrapper', [0,0,0], queue_result=0,
                   expected_final=0, expected_queue=['01000d000100'], expected_notify=['00000d'],
                   expected_counters=[1,2,3]),
        transition(stock, 'policy11_bypasses_publication', [0,0,0], policy=11, handle=0,
                   expected_final=0, expected_queue=[], expected_notify=['00000d'], expected_counters=[1,2,3]),
        transition(stock, 'candidate_churn_restarts_debounce', [0,13,0,0,0], expected_final=0,
                   expected_queue=['01000d000100'], expected_notify=['00000d'], expected_counters=[1,1,1,2,3]),
        transition(stock, 'unknown_channel_ignored', [0,0,0], channel=4, expected_final=13,
                   expected_queue=[], expected_notify=[], expected_counters=[0,0,0]),
    ]
    cb = callbacks(stock)
    selectors = [driver_selector(stock,s) for s in (0,3,5)]
    registers = [softconnect(stock,b,arg) for b,arg in ((0xa5,1),(0xe5,0),(0,1),(0xff,0))]
    deps = {Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for module in list(sys.modules.values()):
        filename = getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent == ROOT/'scripts' and filename.endswith('.py'):
            deps.add(Path(filename).resolve())
    output = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': {'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256': {str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'transition_cases':cases, 'original_callback_initializer':cb,
        'board_control_selector_cases':selectors, 'synthetic_softconnect_cases':registers,
        'all_passed':True, 'stock_code_mappings_write_protected':True,
        'device_io':False, 'firmware_modified':False, 'device_install_candidate':False,
        'USB_host_AOA_VBUS_or_phone_session_verified':False,
        'verification_history':{
            'initial_callback_table_expectation_rejected':True,
            'cause':'Harness initially reversed the two default close/open BX-LR pointers; '
                'original stores put3230FF at+4 and3230FD at+8. Expected mapping corrected, '
                'then all cases rerun from fresh VMs. Stock bytes were never changed.',
            'complete_fresh_run_after_correction':True},
        'scope':'Original state debounce, six-byte transition messages, task/enable gate, four-channel '
            '14-type callback initialization and two board-control vector constructors execute offline. '
            'Queue publication, state notification and initializer logging are explicit fixtures. '
            'Original register bit0x40 toggle only uses synthetic10200001 RAM. Actual queue scheduling, '
            'nondefault callbacks, board I/O, ADC, VBUS, host transfers, phone and installed App are untested.'}
    name = ROOT/'evidence/firmware-analysis/native-usb-transition-emulation.json'
    name.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'output':str(name.relative_to(ROOT)),'all_passed':True,
        'transition_cases':len(cases),'profiles':len(cb['records']),
        'board_selector_cases':len(selectors),'synthetic_register_cases':len(registers),
        'source_dependencies':len(deps)}))


if __name__ == '__main__':
    main()
