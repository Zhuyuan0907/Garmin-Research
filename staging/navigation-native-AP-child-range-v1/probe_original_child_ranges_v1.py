#!/usr/bin/env python3
"""New bounded child-range consumer and two level-4 address plans.

Execute only the original successful-parent-reader continuation, with sealed
observed reader outputs as explicit inputs. Then execute the original reader
entry for two previously unprobed child IDs, stopping before any bit/file read.
Neither run represents a complete address/UI query.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

DIR, CTX, FILE, OUT, RET, STACK = 0x09002000, 0x09000000, 0x09001000, 0x09003000, 0x09004000, 0x09010000
FRAGMENT, FRAGMENT_STOP = 0x00173C3E, 0x00173C54
READER, READER_STOP = 0x044B10E4, 0x0448EB90


def dependency(relative, expected):
    path = ROOT / relative
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != expected:
        raise ValueError('Frozen dependency mismatch: ' + relative)
    return json.loads(raw), dict(path=relative, sha256=sha, old_probe_not_replayed=True)


def main():
    recorded, recorded_dep = dependency(
        'staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json',
        'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53')
    consumer, consumer_dep = dependency(
        'staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
        '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60')
    image = NativeImage()

    def rd(address, size):
        try:
            address = image.runtime_to_load(address, size)
        except ValueError:
            pass
        return image.read(address, size)

    signature = '04984007400f28620398a861069903984018401ee861'
    if rd(FRAGMENT, FRAGMENT_STOP - FRAGMENT).hex() != signature:
        raise ValueError('Original child-range continuation changed')
    if rd(READER, 8).hex() != 'ffb500208fb00590' or rd(READER_STOP, 8).hex() != '04f01fe54b783000':
        raise ValueError('Original reader/veneer signature changed')

    def machine(pages):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        receipts = []
        for page in pages:
            raw = rd(page, 4096)
            u.mem_map(page, 4096)
            u.mem_write(page, raw)
            u.mem_protect(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
            try:
                load = image.runtime_to_load(page, 4096)
            except ValueError:
                load = page
            receipts.append(dict(runtime=hex(page), load=hex(load), sha256=hashlib.sha256(raw).hexdigest()))
        u.mem_map(CTX, 0x4000)
        u.mem_map(STACK, 0x4000)
        u.mem_map(RET, 4096)
        u.mem_write(RET, b'\x70\x47')
        u.mem_protect(RET, 4096, UC_PROT_READ | UC_PROT_EXEC)
        u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        u.reg_write(UC_ARM_REG_SP, STACK + 0x3000)
        u.reg_write(UC_ARM_REG_LR, RET | 1)
        return u, receipts

    ranges = []
    for source in recorded['cases']:
        u, receipts = machine([0x00173000])
        raw = bytes.fromhex(source['native_32byte_output_hex'])
        sp = u.reg_read(UC_ARM_REG_SP)
        # Actual caller r5 is the directory-object range state at +0x140.
        state = DIR + 0x140
        u.mem_write(sp + 0xc, raw)
        u.reg_write(UC_ARM_REG_R5, state)
        trace = []
        stopped = []

        def observe_fragment(uc, pc, size, unused):
            if pc == FRAGMENT_STOP:
                stopped.append(True)
                uc.emu_stop()
                return
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))

        u.hook_add(UC_HOOK_CODE, observe_fragment)
        u.emu_start(FRAGMENT | 1, RET + 2, count=100, timeout=100000)
        if stopped != [True] or len(trace) != 11:
            raise ValueError('Original continuation did not reach bounded stop')
        first, last, level = struct.unpack('<3I', u.mem_read(state + 0x18, 12))
        source_fields = source['native_unnamed_fields']
        expected = (source_fields['+00'], source_fields['+00'] + source_fields['+0c'] - 1, source_fields['+04'] & 7)
        if (first, last, level) != expected:
            raise ValueError('Original child-state result mismatch')
        ranges.append(dict(parent_explicit_level=source['explicit_level'], parent_lowID=source['explicit_low28_ID'],
            source_logical_key=source['source_logical_key_witness'], frozen_observed_raw_output_hex=raw.hex(),
            original_child_first_ID=first, original_child_last_ID_inclusive=last, original_child_level=level,
            original_child_count=last-first+1, original_state_directory_offsets={'+158': first, '+15c': last, '+160': level},
            original_instructions_executed=len(trace), original_instruction_trace=trace, original_RX_pages=receipts,
            synthetic_fragment_inputs=True, complete_parent_reader_or_query_not_executed=True))

    street = next(row for row in ranges if row['parent_explicit_level'] == 3)
    directory_observation = consumer['cases'][0]
    directory = bytes.fromhex(directory_observation['output_hex'])
    plans = []
    for name, record in [('selected_street_child_first', street['original_child_first_ID']),
                         ('selected_street_child_last', street['original_child_last_ID_inclusive'])]:
        level = street['original_child_level']
        u, receipts = machine([0x044B1000, 0x0448E000])
        u.mem_write(DIR, directory)
        u.mem_write(DIR + 0x154, struct.pack('<I', CTX))
        u.mem_write(CTX + 0x20, struct.pack('<2I', FILE, 0))
        for reg, value in [(UC_ARM_REG_R0, DIR), (UC_ARM_REG_R1, record),
                           (UC_ARM_REG_R2, level), (UC_ARM_REG_R3, OUT)]:
            u.reg_write(reg, value)
        trace, callee = [], []

        def observe_reader(uc, pc, size, unused):
            if pc == READER_STOP:
                callee.append(dict(original_callee_veneer=hex(pc), original_callee='0x0030784a',
                    r0_file_pointer=hex(uc.reg_read(UC_ARM_REG_R0)), r1_file_kind=uc.reg_read(UC_ARM_REG_R1),
                    r2_MDR_relative_byte_offset=uc.reg_read(UC_ARM_REG_R2),
                    r3_initial_bit_offset=uc.reg_read(UC_ARM_REG_R3),
                    original_callee_not_executed=True))
                uc.emu_stop()
                return
            if pc == RET:
                raise ValueError('Unexpected reader guard failure')
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))

        u.hook_add(UC_HOOK_CODE, observe_reader)
        u.emu_start(READER | 1, RET + 2, count=3000, timeout=100000)
        if len(callee) != 1:
            raise ValueError('Reader did not reach real bit-reader veneer')
        item = directory_observation['decoded_records'][level-1]
        bits = (record-1) * item['third_scalar']
        expected_byte = item['span_start'] + bits // 8
        if (callee[0]['r2_MDR_relative_byte_offset'], callee[0]['r3_initial_bit_offset']) != (expected_byte, bits % 8):
            raise ValueError('Original child read-plan mismatch')
        plans.append(dict(name=name, explicit_level=level, explicit_low28_ID=record,
            original_planned_read=callee[0], original_directory_ordinal_zero_based=level-1,
            actual_record_stride_bits=item['third_scalar'], original_span_start=item['span_start'],
            original_span_bytes=item['span_bytes'], required_body_bytes=(bits % 8 + item['third_scalar'] + 7)//8,
            original_instructions_executed=len(trace), original_instruction_trace=trace, original_RX_pages=receipts,
            body_bytes_read=0, filesystem_or_result_or_policy_hooks=[]))

    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    instruction_ranges = []
    for address, size, purpose in [(0x00173C26, 0x46, 'descriptor reader and child-range continuation'),
                                  (0x044B203A, 0x20, 'forward child iterator range bound and reader'),
                                  (0x044B2072, 0x20, 'reverse child iterator range bound and reader')]:
        raw = rd(address, size)
        instruction_ranges.append(dict(start=hex(address), size=size, purpose=purpose, raw_hex=raw.hex(),
            instructions=[dict(pc=hex(i.address), bytes=i.bytes.hex(), instruction=i.mnemonic + ' ' + i.op_str)
                          for i in cs.disasm(raw, address)]))
    veneers = []
    for address, expected_target in [(0x002E382C, 0x044B10E5), (0x002E383C, 0x044B1EEB)]:
        raw = rd(address, 8)
        if raw[:4].hex() != '04f01fe5' or struct.unpack('<I', raw[4:])[0] != expected_target:
            raise ValueError('Caller veneer target changed')
        veneers.append(dict(address=hex(address), raw_hex=raw.hex(), literal_thumb_target=hex(expected_target)))
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), stock_MAIN_sha256=EXPECTED,
        dependencies=[recorded_dep, consumer_dep], all_cases_passed=True,
        original_consumer_fragment_entry=hex(FRAGMENT), original_fragment_stop=hex(FRAGMENT_STOP),
        actual_fragment_cases=ranges, newly_executed_child_reader_plans=plans,
        source_instruction_ranges=instruction_ranges, source_original_veneers=veneers,
        proven_field_semantics={'+00': 'first record ID in selected child table',
            '+0c': 'child record count; last inclusive is +00 + +0c - 1',
            '+04 low3bits': 'selected child table level'},
        still_unnamed_fields=['+04 upper bits', '+10', '+1c', 'contents/semantics of child level4 records'],
        raw_children_not_named_houses=True, fullquery_executed=False, physical_query_verified=False,
        device_IO=False, new_IMG_payload_bytes_read=0, query_or_result_or_policy_hooks=[],
        limits=['The successful-reader continuation is executed inside the original function, with frozen decoded outputs explicitly supplied as synthetic stack input.',
                'Two original reader entries plan fresh level4 requests and stop before bit/file reads; no child record has been decoded here.',
                'The first/count/level semantics are grounded in original child-read and forward/reverse iterator uses, but level4 records are not yet confirmed as house records.',
                'No complete SQL/UI query, native provider initialization, new address record or index writer is exercised.'])
    path = HERE / 'original-child-range-and-level4-plans-proof-v1.json'
    if path.exists():
        raise ValueError('Refuse overwrite proof')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(output=str(path), all_passed=True, fragment_cases=len(ranges),
        child_range={key: street[key] for key in ['original_child_level', 'original_child_first_ID', 'original_child_last_ID_inclusive', 'original_child_count']},
        plans=[dict(level=p['explicit_level'], ID=p['explicit_low28_ID'],
                    byte=p['original_planned_read']['r2_MDR_relative_byte_offset'],
                    bit=p['original_planned_read']['r3_initial_bit_offset'], bytes=p['required_body_bytes']) for p in plans],
        new_IMG_payload_bytes_read=0, physical_query_verified=False)))


if __name__ == '__main__':
    main()
