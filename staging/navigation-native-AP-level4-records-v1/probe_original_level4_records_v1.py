#!/usr/bin/env python3
"""Two new level-4 boundary records through original packed-reader prefix.

Only one underlying filesystem mapping supplies the already sealed 16 bytes
per case. Original SEEK/bit readers execute; stop before metadata lookup.
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

DIR, CTX, FILE, OUT, RET, BUF, STACK = 0x09002000, 0x09000000, 0x09001000, 0x09003000, 0x09004000, 0x09006000, 0x09010000
ENTRY, STOP = 0x044B10E4, 0x0448F740


def dependency(relative, expected):
    path = ROOT/relative
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != expected:
        raise ValueError('Frozen dependency mismatch: '+relative)
    return json.loads(raw), dict(path=relative, sha256=sha, old_probe_not_replayed=True)


def main():
    consumer, consumer_dep = dependency(
        'staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
        '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60')
    body, body_dep = dependency(
        'staging/navigation-AP-level4-boundary-bytes-v1/level4-boundary-bytes-evidence.json',
        'b3c524ffae00e211f1622084625913ab6ad8e13d6ef3c9de22e5be045d63fae0')
    directory = bytes.fromhex(consumer['cases'][0]['output_hex'])
    item = consumer['cases'][0]['decoded_records'][3]
    widths = item['six_bit_values_at_record_offsets_10_to_17']
    flags = item['flags_at_record_offsets_18_19']
    if item['third_scalar'] != 128 or widths[6:] != [0, 0]:
        raise ValueError('Unexpected boundary record layout')
    image = NativeImage()
    def rd(a, n):
        try:
            a = image.runtime_to_load(a, n)
        except ValueError:
            pass
        return image.read(a, n)
    if rd(ENTRY, 8).hex() != 'ffb500208fb00590' or rd(0x00307930, 4).hex() != 'b3773000':
        raise ValueError('Original packed-reader signature mismatch')
    cases = []
    for source in body['cases']:
        level, record, offset = source['explicit_level'], source['explicit_low28_ID'], source['MDRrelative_byte_offset']
        raw = bytes.fromhex(source['hex'])
        initial = source['initial_bit_offset']
        if (level, record) not in [(4, 904706), (4, 904789)] or len(raw) != 16 or initial != 0 or source['bytes'] != 16:
            raise ValueError('Unexpected source range')
        if hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('Source raw hash mismatch')
        seq = [('+08', 8, widths[4], True), ('+1c', 28, widths[3], bool(flags[1])),
               ('+10', 16, widths[3], bool(flags[0])), ('+00', 0, widths[0], bool(widths[0])),
               ('+0c', 12, widths[5], bool(widths[5])), ('+04', 4, widths[1], bool(widths[1])),
               ('+14', 20, widths[2], bool(widths[2])), ('+18', 24, widths[2], bool(widths[2]))]
        bits, cursor, expected, host = int.from_bytes(raw, 'little'), initial, {}, []
        for label, outoffset, width, enabled in seq:
            value = (bits>>cursor)&((1<<width)-1) if enabled else (0xffffffff if outoffset in [16, 28] else 0)
            if enabled:
                cursor += width
            expected[outoffset] = value
            host.append(dict(output_offset=label, width=width, conditional_enabled=enabled, value=value,
                cumulative_record_bits_consumed=cursor-initial))
        if cursor-initial != 128:
            raise ValueError('Boundary record bit consumption mismatch')
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages = []
        for page in [0x044B1000, 0x0448E000, 0x0448F000, 0x00307000, 0x001C8000, 0x00112000, 0x00427000, 0x00373000]:
            codebytes = rd(page, 4096)
            u.mem_map(page, 4096)
            u.mem_write(page, codebytes)
            u.mem_protect(page, 4096, UC_PROT_READ|UC_PROT_EXEC)
            try:
                load = image.runtime_to_load(page, 4096)
            except ValueError:
                load = page
            pages.append(dict(runtime=hex(page), load=hex(load), sha256=hashlib.sha256(codebytes).hexdigest()))
        u.mem_map(CTX, 0x4000)
        u.mem_map(STACK, 0x4000)
        u.mem_map(RET, 4096)
        u.mem_map(BUF, 4096)
        u.mem_write(RET, b'\x70\x47')
        u.mem_protect(RET, 4096, UC_PROT_READ|UC_PROT_EXEC)
        u.mem_write(BUF, raw)
        u.mem_protect(BUF, 4096, UC_PROT_READ)
        u.mem_write(DIR, directory)
        u.mem_write(DIR+0x154, struct.pack('<I', CTX))
        u.mem_write(CTX+0x20, struct.pack('<2I', FILE, 0))
        u.mem_write(FILE+0xc, struct.pack('<2I', 92653600, 0))
        for reg, value in [(UC_ARM_REG_CPSR, 0x3f), (UC_ARM_REG_SP, STACK+0x3000), (UC_ARM_REG_LR, RET|1),
                           (UC_ARM_REG_R0, DIR), (UC_ARM_REG_R1, record), (UC_ARM_REG_R2, level), (UC_ARM_REG_R3, OUT)]:
            u.reg_write(reg, value)
        trace, mappings, progress = [], [], []
        stopped = []
        boundaries = {0x044B1190:'+08', 0x044B11DE:'+1c', 0x044B122E:'+10', 0x044B1268:'+00',
                      0x044B12A4:'+0c', 0x044B12DE:'+04', 0x044B1314:'+14', 0x044B1344:'+18'}
        def word(address):
            return struct.unpack('<I', u.mem_read(address, 4))[0]
        def observe(uc, pc, size, unused):
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex(),
                thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
            if pc == 0x00112194:
                fp, pointer, mode = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)
                actual_cursor = word(FILE+0x10)
                if fp != FILE or actual_cursor != offset or mode != 0 or mappings:
                    raise ValueError('Mapping outside exact sealed source range')
                uc.mem_write(pointer, struct.pack('<I', BUF))
                uc.reg_write(UC_ARM_REG_R0, 16)
                mappings.append(dict(original_FS_mapping_callee='0x00112194', original_FILE_cursor_MDRrelative=actual_cursor,
                    output_buffer_pointer_address=hex(pointer), mode=mode, returned_bytecount=16,
                    supplied_bytes=16, source_payload_sha256=hashlib.sha256(raw).hexdigest()))
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            elif pc in boundaries:
                reader = uc.reg_read(UC_ARM_REG_SP)+0x10
                consumed = (word(reader+8)-offset)*8-word(reader)
                progress.append(dict(original_pc=hex(pc), completed_output_offset=boundaries[pc],
                    original_record_bits_consumed=consumed-initial))
            elif pc == STOP:
                stopped.append(True)
                uc.emu_stop()
            elif pc == RET:
                raise ValueError('Unexpected early original return')
        u.hook_add(UC_HOOK_CODE, observe)
        try:
            u.emu_start(ENTRY|1, RET+2, count=30000, timeout=1000000)
        except Exception as exc:
            path = HERE/'level4-reader-failure-v1.json'
            if not path.exists():
                path.write_text(json.dumps(dict(case=source['name'], exception=repr(exc),
                    last_pc=hex(u.reg_read(UC_ARM_REG_PC)), trace_tail=trace[-40:], mappings=mappings), indent=2)+'\n')
            raise
        output = bytes(u.mem_read(OUT, 32))
        values = {k:struct.unpack_from('<I', output, k)[0] for k in range(0, 32, 4)}
        if stopped != [True] or len(mappings) != 1 or values != expected or len(progress) != 8:
            raise ValueError('Original boundary decode mismatch')
        for native, model in zip(progress, host):
            if (native['completed_output_offset'], native['original_record_bits_consumed']) != (model['output_offset'], model['cumulative_record_bits_consumed']):
                raise ValueError('Original bit progress mismatch')
        cases.append(dict(name=source['name'], explicit_level=level, explicit_low28_ID=record,
            MDRrelative_byte_offset=offset, initial_bit_offset=initial, original_readonly_payload_hex=raw.hex(),
            native_32byte_output_hex=output.hex(), native_fields={f'+{k:02x}':v for k,v in values.items()},
            known_child_range_fields=dict(first_child_ID=values[0], child_count=values[12], child_level=values[4]&7),
            conditional_read_sequence=host, actual_original_bit_progress=progress,
            underlying_filesystem_mapping_hook=mappings[0], original_RX_pages=pages,
            original_instructions_executed=len(trace)-1,
            original_instruction_trace_sha256=hashlib.sha256(json.dumps(trace, sort_keys=True).encode()).hexdigest(),
            mapmetadata_lookup_not_executed=True, synthetic_directory_context_registers=True))
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), stock_MAIN_sha256=EXPECTED,
        dependencies=[consumer_dep, body_dep], all_cases_passed=True, cases=cases,
        original_reader_entry=hex(ENTRY), original_stop_before_metadata=hex(STOP),
        original_bitreader='0x0030784a', only_underlying_FS_mapping_hook='0x00112194',
        result_or_sort_or_query_or_metadata_hooks=[], no_new_IMG_reads_here=True,
        intervening_child_records_read=0, full_reader_or_query_executed=False,
        physical_query_verified=False, device_IO=False, level4_records_named_houses=False,
        actual_label_text_decoded=False,
        limits=['Two fresh boundary slices only; sealed source bytes copied by one underlying filesystem mapping hook, with original seek/bitreader instructions executing.',
                'Stop before original mapmetadata lookup; raw 24-bit fields remain unscaled and no final coordinate claim is made.',
                'The first/count/level output fields have a separate native consumer proof; this does not establish the semantic name of level4 or its children.',
                'Text-reference values are observed but native text getter has not been executed; no house number 184 lookup or new-address writer is proved.'])
    path = HERE/'original-level4-boundary-records-proof-v1.json'
    if path.exists():
        raise ValueError('Refuse overwrite proof')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(output=str(path), all_passed=True, cases=len(cases),
        fields=[dict(ID=c['explicit_low28_ID'], fields=c['native_fields']) for c in cases],
        actual_label_text_decoded=False, full_reader_or_query_executed=False)))


if __name__ == '__main__':
    main()
