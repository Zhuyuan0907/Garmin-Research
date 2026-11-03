#!/usr/bin/env python3
"""Exactly three new original-CPU record-prefix/partial-suffix cases.

Case inputs: original stock184 bytes, fresh street-point payload, and fresh
house184-point payload. One underlying filesystem mapping supplies each frozen
16-byte fixture. No metadata/result/sort policy is hooked. Original reader
prefix stops before registry/metadata; the source-backed shift suffix is an
independent inside-function fragment with explicit instance/frame inputs.
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
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

DIR, CTX, FILE, OUT, RET, BUF, OBJECT, STACK = (
    0x09002000, 0x09000000, 0x09001000, 0x09003000, 0x09004000, 0x09006000, 0x09008000, 0x09010000)
ENTRY, PREFIX_STOP = 0x044B10E4, 0x0448F740


def dependency(relative, expected):
    path = ROOT/relative
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != expected:
        raise ValueError('Frozen dependency mismatch: '+relative)
    return json.loads(raw), dict(path=relative, sha256=sha, old_scope_not_replayed=True)


def main():
    dependencies = []
    def load(relative, sha):
        obj, receipt = dependency(relative, sha)
        dependencies.append(receipt)
        return obj
    consumer = load('staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
        '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60')
    stock = load('staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json',
        '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774')
    street = load('staging/navigation-native-record-writer-v1/modern-Minquan-street-point-prototype-v1.json',
        '01b793bd8ea6268529c05bd1769f586458dcb93283888fe640369362e1bc4cb7')
    house = load('staging/navigation-native-record-house184-prototype-v1/modern-source-native-house184-point-prototype-v1.json',
        'dcb61e8798cf9562f6ecdb7d0da1441ff8c193d96db37df22ff2db4a8dde66fa')
    street_seal = load('staging/navigation-native-record-writer-v1/native-record-writer-file-seal-v1.json',
        'a69e3b666c8be1843a8d85839eed5116bc4979637d191c6e5eb2459860a1e19c')
    house_seal = load('staging/navigation-native-record-house184-prototype-v1/house184-prototype-file-seal-v1.json',
        '6ce7c4d7932aa3859ee964d68a12ac31650575b32aa71b5cabe68cd0941ab6bc')
    tre_loop = load('staging/navigation-native-AP-TRE-level-loop-v1/original-TRE-level-loop-proof-v1.json',
        '3643721fca5a1195d042d9309d8ce33b7e948aa6636870ebf20fc3a60ea51b73')
    if stock['strict_184_match_count'] != 1:
        raise ValueError('Original184 witness is not unique')
    witness = stock['strict_184_matches'][0]
    if (witness['lowID'], witness['primary_reference'], witness['label']) != (904780, 808, '184號'):
        raise ValueError('Original184 source identity witness changed')
    directory_observation = consumer['cases'][0]
    directory = bytes.fromhex(directory_observation['output_hex'])
    original_expected = bytes().join(struct.pack('<I', witness['host_fields'][f'+{offset:02x}']) for offset in range(0, 32, 4))
    inputs = [dict(name='original_stock_house184_new_selected_case', level=4, ID=witness['lowID'],
        offset=witness['MDR_relative_offset'], initial=0, raw=bytes.fromhex(witness['record_hex']),
        expected=original_expected, expected_source='separate original-source host witness', original_stock=True,
        source_payload_sha256=witness['record_sha256']),
        dict(name='fresh_modern_street_point_payload', original_stock=False, prototype=street),
        dict(name='fresh_modern_house184_point_payload', original_stock=False, prototype=house)]
    for case in inputs[1:]:
        prototype = case['prototype']
        path = ROOT/prototype['payload']
        raw = path.read_bytes()
        if len(raw) != 16 or hashlib.sha256(raw).hexdigest() != prototype['payload_sha256'] or raw.hex() != prototype['payload_hex']:
            raise ValueError('Frozen prototype binary payload mismatch')
        if prototype['installable'] or prototype.get('independent_original_native_reader_executed', False) or prototype.get('independent_original_native_reader_new_payload_executed', False):
            raise ValueError('Unexpected prior prototype/installability claim')
        case.update(level=prototype['explicit_reader_level'], ID=prototype['explicit_one_based_lowID_fixture'],
            offset=prototype['MDR_relative_offset_fixture'], initial=prototype['initial_bit_offset'], raw=raw,
            expected=bytes.fromhex(prototype['expected_native_output_32bytes_hex']),
            expected_source='fresh producer projection, independently crosschecked against original CPU and direct bit extraction',
            source_payload_sha256=prototype['payload_sha256'], payload_path=prototype['payload'])
    if [case['raw'].hex() for case in inputs] != [
        'ffff8f32000000000000022b112ed055', '4067000838375440a060252206ba0a00', 'ffff8f32000000000000052b1131d055']:
        raise ValueError('Scope is limited to exactly the three assigned new payloads')
    minimum = tre_loop['cases'][0]['original_object_u8_at68']
    source_field = tre_loop['cases'][0]['original_object_u8_at56_plus_minimum']
    if (minimum, source_field) != (0, 24):
        raise ValueError('Source-backed TRE instance fields changed')
    image = NativeImage()
    def rd(a, n):
        try:
            a = image.runtime_to_load(a, n)
        except ValueError:
            pass
        return image.read(a, n)
    if rd(ENTRY, 8).hex() != 'ffb500208fb00590' or rd(0x00307930, 4).hex() != 'b3773000':
        raise ValueError('Original reader/bitreader callback changed')
    if rd(0x044B1354, 22).hex() != '79690f2080010818406b6821095c40184030807d0390':
        raise ValueError('Original source-field accessor changed')
    if rd(0x044B1372, 18).hex() != '039a20206169801a81406161a1698140a161':
        raise ValueError('Original rescale suffix changed')

    def machine(code_pages):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        receipts = []
        for page in code_pages:
            raw = rd(page, 4096)
            u.mem_map(page, 4096)
            u.mem_write(page, raw)
            u.mem_protect(page, 4096, UC_PROT_READ|UC_PROT_EXEC)
            try:
                load_address = image.runtime_to_load(page, 4096)
            except ValueError:
                load_address = page
            receipts.append(dict(runtime=hex(page), load=hex(load_address), sha256=hashlib.sha256(raw).hexdigest()))
        u.mem_map(CTX, 0x4000)
        u.mem_map(STACK, 0x4000)
        u.mem_map(RET, 4096)
        u.mem_map(BUF, 4096)
        u.mem_map(OBJECT, 4096)
        u.mem_write(RET, b'\x70\x47')
        u.mem_protect(RET, 4096, UC_PROT_READ|UC_PROT_EXEC)
        u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        u.reg_write(UC_ARM_REG_SP, STACK+0x3000)
        u.reg_write(UC_ARM_REG_LR, RET|1)
        return u, receipts

    cases = []
    for case in inputs:
        level, ID, offset, initial, raw = (case[key] for key in ['level', 'ID', 'offset', 'initial', 'raw'])
        if hashlib.sha256(raw).hexdigest() != case['source_payload_sha256']:
            raise ValueError('Assigned source slice hash mismatch')
        item = directory_observation['decoded_records'][level-1]
        widths = item['six_bit_values_at_record_offsets_10_to_17']
        flags = item['flags_at_record_offsets_18_19']
        if widths[6:] != [0, 0]:
            raise ValueError('Unexpected nonzero extra fields')
        expected_bits = (ID-1)*item['third_scalar']
        if (offset, initial) != (item['span_start']+expected_bits//8, expected_bits%8):
            raise ValueError('Assigned fixture address disagrees with frozen directory')
        sequence = [('+08', 8, widths[4], True), ('+1c', 28, widths[3], bool(flags[1])),
                    ('+10', 16, widths[3], bool(flags[0])), ('+00', 0, widths[0], bool(widths[0])),
                    ('+0c', 12, widths[5], bool(widths[5])), ('+04', 4, widths[1], bool(widths[1])),
                    ('+14', 20, widths[2], bool(widths[2])), ('+18', 24, widths[2], bool(widths[2]))]
        bits, cursor, model, projection = int.from_bytes(raw, 'little'), initial, {}, []
        for label, outoffset, width, enabled in sequence:
            wire = (bits>>cursor)&((1<<width)-1) if enabled else None
            value = wire if enabled else (0xffffffff if outoffset in [16, 28] else 0)
            if enabled and outoffset in [16, 28] and wire == (1<<width)-1:
                value = 0xffffffff
            if enabled:
                cursor += width
            model[outoffset] = value
            projection.append(dict(output_offset=label, width=width, enabled=enabled, raw_wire_value=wire,
                projected_native_value=value, cumulative_record_bits_consumed=cursor-initial))
        model_bytes = b''.join(struct.pack('<I', model[k]) for k in range(0, 32, 4))
        if cursor-initial != item['third_scalar'] or model_bytes != case['expected']:
            raise ValueError('Independent direct-bit extraction differs from assigned source/producer projection')
        u, pages = machine([0x044B1000, 0x0448E000, 0x0448F000, 0x00307000,
                            0x001C8000, 0x00112000, 0x00427000, 0x00373000])
        u.mem_write(BUF, raw)
        u.mem_protect(BUF, 4096, UC_PROT_READ)
        u.mem_write(DIR, directory)
        u.mem_write(DIR+0x154, struct.pack('<I', CTX))
        u.mem_write(CTX+0x20, struct.pack('<2I', FILE, 0))
        u.mem_write(FILE+0xc, struct.pack('<2I', 92653600, 0))
        for reg, value in [(UC_ARM_REG_R0, DIR), (UC_ARM_REG_R1, ID), (UC_ARM_REG_R2, level), (UC_ARM_REG_R3, OUT)]:
            u.reg_write(reg, value)
        trace, mappings, progress, actual_calls = [], [], [], []
        stopped = []
        boundaries = {0x044B1190:'+08', 0x044B11DE:'+1c', 0x044B122E:'+10', 0x044B1268:'+00',
                      0x044B12A4:'+0c', 0x044B12DE:'+04', 0x044B1314:'+14', 0x044B1344:'+18'}
        def word(address):
            return struct.unpack('<I', u.mem_read(address, 4))[0]
        def observe(uc, pc, size, unused):
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex(),
                thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
            if pc == 0x00112194:
                fp, outpointer, mode = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)
                actual_cursor = word(FILE+0x10)
                if fp != FILE or actual_cursor != offset or mode != 0 or mappings:
                    raise ValueError('Filesystem fixture request exceeds assigned sealed range')
                uc.mem_write(outpointer, struct.pack('<I', BUF))
                uc.reg_write(UC_ARM_REG_R0, 16)
                mappings.append(dict(callee='0x00112194', original_FILE_cursor_MDRrelative=actual_cursor,
                    output_buffer_pointer_address=hex(outpointer), mode=mode, returned_mapped_bytecount=16,
                    source_payload_sha256=hashlib.sha256(raw).hexdigest(), explicit_filesystem_fixture_only=True))
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            elif pc in boundaries:
                reader = uc.reg_read(UC_ARM_REG_SP)+0x10
                consumed = (word(reader+8)-offset)*8-word(reader)-initial
                progress.append(dict(original_pc=hex(pc), output_offset=boundaries[pc], original_record_bits_consumed=consumed))
            elif pc in [0x0030784A, 0x003077B2, 0x001C8802, 0x001C8882, 0x00307348]:
                actual_calls.append(dict(pc=hex(pc), r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                    r1=hex(uc.reg_read(UC_ARM_REG_R1)), r2=uc.reg_read(UC_ARM_REG_R2), r3=uc.reg_read(UC_ARM_REG_R3)))
            elif pc == PREFIX_STOP:
                stopped.append(True)
                uc.emu_stop()
            elif pc == RET:
                raise ValueError('Unexpected complete reader return')
        u.hook_add(UC_HOOK_CODE, observe)
        try:
            u.emu_start(ENTRY|1, RET+2, count=30000, timeout=1000000)
        except Exception as exc:
            failure_path = HERE/'new-record-prefix-failure-v1.json'
            if not failure_path.exists():
                failure_path.write_text(json.dumps(dict(case=case['name'], exception=repr(exc),
                    last_pc=hex(u.reg_read(UC_ARM_REG_PC)), trace_tail=trace[-40:], mappings=mappings), indent=2)+'\n')
            raise
        output = bytes(u.mem_read(OUT, 32))
        if stopped != [True] or len(mappings) != 1 or output != case['expected'] or len(progress) != 8:
            raise ValueError('Original prefix output does not match independent assigned projection')
        for native, direct in zip(progress, projection):
            if (native['output_offset'], native['original_record_bits_consumed']) != (direct['output_offset'], direct['cumulative_record_bits_consumed']):
                raise ValueError('Native conditional bit progress mismatch')
        if bytes(u.mem_read(BUF, 16)) != raw:
            raise ValueError('Original readonly fixture bytes changed')
        # This is a separate post-metadata suffix, not continuation of a
        # fabricated successful registry call. Both phases use explicit input.
        v, suffix_pages = machine([0x044B1000])
        suffix_sp = v.reg_read(UC_ARM_REG_SP)
        v.mem_write(DIR+0x154, struct.pack('<I', CTX))
        v.mem_write(CTX+0x3f4, struct.pack('<I', OBJECT))
        v.mem_write(OBJECT+0x68, bytes([minimum]))
        v.mem_write(OBJECT+0x56+minimum, bytes([source_field]))
        v.reg_write(UC_ARM_REG_R7, DIR+0x140)
        field_trace, field_stop = [], []
        def observe_field(uc, pc, size, unused):
            if pc == 0x044B136A:
                field_stop.append(True)
                uc.emu_stop()
                return
            field_trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))
        field_hook = v.hook_add(UC_HOOK_CODE, observe_field)
        v.emu_start(0x044B1355, 0x044B136E, count=100, timeout=100000)
        v.hook_del(field_hook)
        parameter = struct.unpack('<I', v.mem_read(suffix_sp+0xc, 4))[0]
        if field_stop != [True] or parameter != 24:
            raise ValueError('Source-backed original instance-field accessor mismatch')
        v.mem_write(OUT, output)
        v.reg_write(UC_ARM_REG_R4, OUT)
        suffix_trace, suffix_stopped = [], []
        def observe_suffix(uc, pc, size, unused):
            if pc == 0x044B1384:
                suffix_stopped.append(True)
                uc.emu_stop()
                return
            suffix_trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))
        v.hook_add(UC_HOOK_CODE, observe_suffix)
        v.emu_start(0x044B1373, 0x044B1388, count=100, timeout=100000)
        rescaled = bytes(v.mem_read(OUT, 32))
        expected_scaled = list(struct.unpack('<8I', output))
        expected_scaled[5] = (expected_scaled[5]<<8)&0xffffffff
        expected_scaled[6] = (expected_scaled[6]<<8)&0xffffffff
        if suffix_stopped != [True] or struct.unpack('<8I', rescaled) != tuple(expected_scaled):
            raise ValueError('Original source-backed rescale suffix mismatch')
        cases.append(dict(name=case['name'], original_stock_bytes=case['original_stock'], explicit_level=level,
            explicit_one_based_lowID_fixture=ID, MDR_relative_offset_fixture=offset, initial_bit_offset=initial,
            frozen_payload_hex=raw.hex(), payload_sha256=hashlib.sha256(raw).hexdigest(),
            fixture_meaning='Original stock selected record' if case['original_stock'] else 'Fresh producer bytes at explicit synthetic reader fixture address; not installed data',
            actual_original_prefix_output_hex=output.hex(), actual_original_prefix_fields={f'+{k:02x}':model[k]for k in range(0, 32, 4)},
            independent_direct_bit_projection=projection, expected_projection_source=case['expected_source'],
            actual_original_consumption_progress=progress, actual_original_callee_observations=actual_calls,
            original_instructions_executed_before_metadata=len(trace)-1,
            original_prefix_trace_sha256=hashlib.sha256(json.dumps(trace, sort_keys=True).encode()).hexdigest(),
            underlying_filesystem_fixture=mappings[0], original_RX_pages=pages,
            independently_supplied_source_backed_suffix=dict(original_field_accessor_trace=field_trace,
                source_instance_fields={'object+68':minimum, 'object+56+minimum':source_field},
                resulting_original_shift_parameter=parameter, original_rescale_trace=suffix_trace,
                actual_original_rescaled_output_hex=rescaled.hex(), original_RX_pages=suffix_pages,
                mapregistry_or_metadata_or_cleanup_not_executed=True, explicit_synthetic_instance_and_frame_input=True),
            complete_reader_or_registry_or_query_executed=False))
    original, modern_street, modern_house = cases
    original_fields = original['actual_original_prefix_fields']
    modern_fields = modern_house['actual_original_prefix_fields']
    house_delta = [modern_fields[k]-original_fields[k] for k in ['+14', '+18']]
    if house_delta != [3, 3] or any(original_fields[k] != modern_fields[k] for k in ['+00', '+04', '+08', '+0c', '+10', '+1c']):
        raise ValueError('Fresh house184 case altered fields beyond assigned +3/+3 raw24 change')
    if [modern_street['actual_original_prefix_fields'][k] for k in ['+14', '+18']] != [1125125, 5623857]:
        raise ValueError('Fresh street point does not decode assigned modern point')
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), stock_MAIN_sha256=EXPECTED,
        dependencies=dependencies, exact_new_case_count=3, all_assigned_case_checks_passed=True, cases=cases,
        original_selected184_reference_witness=dict(mapordinal=1, primary_reference=808, label_from_frozen_source='184號',
            original_reference_proved_by_new_prefix=True, actual_original_LBL_text_decoder_executed_here=False),
        actual_house184_raw24_delta=house_delta, fresh_house_retained_other_6_fields=True,
        fresh_street_is_representative_point_only=True,
        source_backed_rescale_used=True, only_function_hook='underlying FS mapping 0x00112194 supplies frozen sixteen-byte fixture',
        original_prefix_stop_before_metadata='0x0448f740',
        result_or_metadata_success_or_sort_or_policy_hooks=[], old3_or2_case_suites_replayed=False,
        writer_module_imported_or_run=False, new_IMG_or_DB_reads=0, device_IO=False,
        complete_reader_return_or_SQL_or_UI_or_registry_executed=False, physical_navigation_verified_here=False,
        native2026_address_database_or_IMG_updated=False, installable=False,
        limits=['Exactly the three newly assigned payload cases; no original city/district/street/boundary suite rerun.',
                'The original reader prefix and real 30784A/307348 bitreader execute with one explicit FS mapping fixture; stop before metadata lookup.',
                'Postmetadata field accessor and rescale are separate original fragments with source-backed instance fields explicitly supplied. No registry/getter result is forced to succeed.',
                'The house retains the source-backed184號 primary reference, but text decoding is a separate peer proof; no full native selected UI query is executed here.',
                'Fresh payloads validate the bounded serializer format only; bare sixteen bytes are not a map, DB update, installer or route acceptance result.',
                'Matching name and nearby modern OSM node do not prove the OSM source and stock record have identical geographic identity.'])
    path = HERE/'new-selected184-and-writer-payloads-partial-CPU-proof-v1.json'
    if path.exists():
        raise ValueError('Refuse overwrite proof')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(output=str(path), all_passed=True, exact_new_cases=3,
        raw24=[dict(case=c['name'], fields=[c['actual_original_prefix_fields'][k]for k in ['+14', '+18']])for c in cases],
        original_house_reference=original_fields['+10'], house_raw24_delta=house_delta,
        complete_reader_or_query_executed=False, installable=False)))


if __name__ == '__main__':
    main()
