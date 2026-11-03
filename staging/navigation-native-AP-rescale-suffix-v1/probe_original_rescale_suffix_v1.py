#!/usr/bin/env python3
"""Two original post-metadata fragments with source-backed explicit input.

No mapregistry/getter return is faked. The metadata callee and cleanup are not
entered. This verifies the local field access and shift, not a full reader.
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

CTX, DIR, OUT, OBJECT, STACK = 0x09000000, 0x09002000, 0x09003000, 0x09004000, 0x09010000


def dependency(relative, expected):
    path = ROOT/relative
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != expected:
        raise ValueError('Frozen dependency mismatch: '+relative)
    return json.loads(raw), dict(path=relative, sha256=sha, old_probe_not_replayed=True)


def main():
    loop, loop_dep = dependency(
        'staging/navigation-native-AP-TRE-level-loop-v1/original-TRE-level-loop-proof-v1.json',
        '3643721fca5a1195d042d9309d8ce33b7e948aa6636870ebf20fc3a60ea51b73')
    records, records_dep = dependency(
        'staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json',
        'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53')
    observed = loop['cases'][0]
    source_minimum = observed['original_object_u8_at68']
    source_field = observed['original_object_u8_at56_plus_minimum']
    if source_minimum != 0 or source_field != 24 or not loop['actual_original_loop_stores_obj56_24_obj68_0_verified']:
        raise ValueError('Source-backed TRE field mismatch')
    image = NativeImage()
    def rd(address, size):
        return image.read(image.runtime_to_load(address, size), size)
    field_entry, field_stop = 0x044B1354, 0x044B136A
    shift_entry, shift_stop = 0x044B1372, 0x044B1384
    if rd(field_entry, field_stop-field_entry).hex() != '79690f2080010818406b6821095c40184030807d0390':
        raise ValueError('Original metadata-field consumer signature mismatch')
    if rd(shift_entry, shift_stop-shift_entry).hex() != '039a20206169801a81406161a1698140a161':
        raise ValueError('Original shift suffix signature mismatch')

    def machine():
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        raw = rd(0x044B1000, 4096)
        u.mem_map(0x044B1000, 4096)
        u.mem_write(0x044B1000, raw)
        u.mem_protect(0x044B1000, 4096, UC_PROT_READ|UC_PROT_EXEC)
        u.mem_map(CTX, 0x6000)
        u.mem_map(STACK, 0x4000)
        sp = STACK+0x3000
        u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        u.reg_write(UC_ARM_REG_SP, sp)
        return u, sp, raw

    # Field-access fragment starts after the metadata branch, with the two
    # actual original TRE-loop stores supplied as explicit instance fields.
    u, sp, rawcode = machine()
    u.mem_write(DIR+0x154, struct.pack('<I', CTX))
    u.mem_write(CTX+0x3f4, struct.pack('<I', OBJECT))
    u.mem_write(OBJECT+0x68, bytes([source_minimum]))
    u.mem_write(OBJECT+0x56+source_minimum, bytes([source_field]))
    u.reg_write(UC_ARM_REG_R7, DIR+0x140)
    field_trace, field_stopped = [], []
    def field_observe(uc, pc, size, unused):
        if pc == field_stop:
            field_stopped.append(True)
            uc.emu_stop()
            return
        field_trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))
    u.hook_add(UC_HOOK_CODE, field_observe)
    u.emu_start(field_entry|1, field_stop+4, count=100, timeout=100000)
    shift_parameter = struct.unpack('<I', u.mem_read(sp+0xc, 4))[0]
    if field_stopped != [True] or shift_parameter != 24:
        raise ValueError('Original field accessor fragment mismatch')
    cases = []
    for source in records['cases']:
        v, sp, rawcode = machine()
        raw = bytes.fromhex(source['native_32byte_output_hex'])
        v.mem_write(OUT, raw)
        v.mem_write(sp+0xc, struct.pack('<I', shift_parameter))
        v.reg_write(UC_ARM_REG_R4, OUT)
        trace, stopped = [], []
        def observe(uc, pc, size, unused):
            if pc == shift_stop:
                stopped.append(True)
                uc.emu_stop()
                return
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))
        v.hook_add(UC_HOOK_CODE, observe)
        v.emu_start(shift_entry|1, shift_stop+4, count=100, timeout=100000)
        output = bytes(v.mem_read(OUT, 32))
        original_values = struct.unpack('<8I', raw)
        actual_values = struct.unpack('<8I', output)
        expected = list(original_values)
        expected[5] = (expected[5] << (32-shift_parameter)) & 0xffffffff
        expected[6] = (expected[6] << (32-shift_parameter)) & 0xffffffff
        if stopped != [True] or tuple(expected) != actual_values:
            raise ValueError('Original rescale suffix mismatch')
        cases.append(dict(parent_explicit_level=source['explicit_level'], parent_lowID=source['explicit_low28_ID'],
            frozen_raw_input_hex=raw.hex(), original_rescaled_output_hex=output.hex(), shift_parameter=shift_parameter,
            actual_left_shift_bits=32-shift_parameter, original_rescaled_unnamed_fields={'+14': actual_values[5], '+18': actual_values[6]},
            original_instruction_trace=trace, original_instructions_executed=len(trace), synthetic_frame_inputs=True))
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), stock_MAIN_sha256=EXPECTED,
        dependencies=[loop_dep, records_dep], all_cases_passed=True,
        original_source_backed_field_fragment=dict(entry=hex(field_entry), stop=hex(field_stop),
            original_trace=field_trace, original_instructions_executed=len(field_trace),
            explicit_source_fields={'object+68': source_minimum, 'object+56+minimum': source_field},
            resulting_stack_shift_parameter=shift_parameter, synthetic_object_context_and_frame=True),
        actual_original_rescale_suffix_cases=cases, original_suffix_entry=hex(shift_entry), original_suffix_stop=hex(shift_stop),
        original_RX_page_sha256=hashlib.sha256(rawcode).hexdigest(),
        registry_or_getter_or_result_or_policy_hooks=[], original_mapmetadata_getter_executed=False,
        original_mapmetadata_cleanup_executed=False, complete_reader_or_query_executed=False,
        physical_query_verified=False, device_IO=False, new_IMG_payload_bytes_read=0,
        final_coordinate_or_route_semantics_proven=False,
        limits=['Two original inside-function fragments are executed independently with explicit source-backed instance/frame input; the native metadata callee is never entered or forced to succeed.',
                'The true TRE-loop stores supply minimum level0 and field24; original accessor retrieves24 and rescale shifts each observed raw24bit field left8.',
                'No complete reader return, registry/load sequence, current device instance, final coordinate interpretation or routing lookup is verified.',
                'Only frozen three original records are inputs; their old bit-reader probes are not replayed.'])
    path = HERE/'original-source-backed-rescale-suffix-proof-v1.json'
    if path.exists():
        raise ValueError('Refuse overwrite proof')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(output=str(path), all_passed=True, field_parameter=shift_parameter,
        cases=len(cases), shifted_fields=[c['original_rescaled_unnamed_fields']for c in cases],
        complete_reader_or_query_executed=False)))


if __name__ == '__main__':
    main()
