#!/usr/bin/env python3
"""Execute only the original TRE levels-table loop using frozen true bytes."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R7

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-native-AP-TRE-level-loop-v1'
METADATA = ROOT / 'staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json'
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
ENTRY, STOP = 0x2D08CC, 0x2D09EA


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def run_case(code, table, padding):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x2D0000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    uc.mem_write(ENTRY, code)
    uc.mem_protect(0x2D0000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    stack_page, object_page = 0x09000000, 0x09100000
    uc.mem_map(stack_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(object_page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    sp, obj = stack_page + 0x800, object_page + 0x800
    before = bytearray(b'\xCC' * 256)
    # Explicit synthetic predecessor state, matching static initialization;
    # this is not complete TRE loader execution or a live metadata instance.
    struct.pack_into('<H', before, 0x40, 0)
    struct.pack_into('<H', before, 0x42, 0xffff)
    before[0x44:0x56] = bytes(0x12)
    before[0x68:0x6A] = bytes([8, 0])
    uc.mem_write(obj, bytes(before))
    uc.mem_write(sp + 0x138, table + bytes([padding]) * 4)
    uc.mem_write(sp + 0x15C, struct.pack('<I', len(table) // 4))
    uc.mem_write(sp + 0x178, struct.pack('<I', obj + 0x40))
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_R4, obj)
    uc.reg_write(UC_ARM_REG_R5, obj + 0x60)
    uc.reg_write(UC_ARM_REG_R7, sp + 0x138)
    uc.reg_write(UC_ARM_REG_CPSR, 0x33)
    trace = []
    def observe(machine, address, size, _):
        need(ENTRY <= address < STOP, 'Original loop escaped bounded code range')
        trace.append(address)
    uc.hook_add(UC_HOOK_CODE, observe)
    uc.emu_start(ENTRY | 1, STOP, timeout=1_000_000, count=10000)
    from unicorn.arm_const import UC_ARM_REG_PC
    need(uc.reg_read(UC_ARM_REG_PC) == STOP, 'Original loop did not reach expected exit')
    after = bytes(uc.mem_read(obj, 256))
    expected_levels = {int(raw[0] & 127): int(raw[1]) for raw in
                       [table[p:p + 4] for p in range(0, len(table), 4)]}
    levels = {str(level): after[0x56 + level] for level in sorted(expected_levels)}
    need(levels == {str(k): v for k, v in sorted(expected_levels.items())}, 'Original second-byte stores differ')
    minimum, maximum = after[0x68], after[0x69]
    need(minimum == min(expected_levels) and maximum == max(expected_levels), 'Original level selectors differ')
    getter_value = after[0x56 + minimum]
    need(getter_value == 24, 'Original stored source-backed getter input differs')
    changed = [i for i in range(256) if before[i] != after[i]]
    allowed = set(range(0x40, 0x56)) | set(range(0x56, 0x5B)) | set(range(0x5F, 0x64)) | {0x68, 0x69}
    need(set(changed) <= allowed, 'Unexpected object byte changed')
    need(after[:0x40] == before[:0x40] and after[0x6A:] == before[0x6A:], 'Object canary changed')
    need(bytes(uc.mem_read(sp + 0x138, len(table) + 4)) == table + bytes([padding]) * 4,
         'Frozen table or controlled trailing bytes changed')
    return {'name': 'original_table_trailing_' + hex(padding), 'synthetic_trailing_padding_byte': padding,
        'original_entry': hex(ENTRY), 'original_stop': hex(STOP), 'stop_reached': True,
        'executed_instruction_count': len(trace), 'instruction_PC_trace': [hex(p) for p in trace],
        'original_object_u8_at68': minimum, 'original_object_u8_at69': maximum,
        'original_object_u8_at56': after[0x56], 'original_object_u8_at56_plus_minimum': getter_value,
        'second_bytes_by_low7level': levels, 'changed_object_offsets': [hex(p) for p in changed],
        'original_object40_6A_hex': after[0x40:0x6A].hex(), 'canaries_and_table_unchanged': True,
        'result_or_registry_or_getter_or_policy_hooks': [], 'all_case_checks_passed': True}


def main():
    target = OUT / 'original-TRE-level-loop-proof-v1.json'
    need(not target.exists(), 'Refusing to overwrite proof')
    need(ref(METADATA)['sha256'] == '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753',
         'Frozen actual metadata proof changed')
    metadata = json.loads(METADATA.read_text())
    table = bytes.fromhex(metadata['TRE_level_table']['hex'])
    need(len(table) == 20 and sha(table) == metadata['TRE_level_table']['sha256'], 'True table bytes changed')
    fragment = next(f for f in metadata['static_original_code_fragments'] if f['runtime_address'] == 0x2D0850)
    frozen = bytes.fromhex(fragment['hex'])
    need(sha(frozen) == fragment['sha256'], 'Frozen original code fragment changed')
    suffix_start = fragment['runtime_address'] + len(frozen)
    need(suffix_start == 0x2D09DA, 'Unexpected frozen code end')
    before = stat(MAIN)
    with MAIN.open('rb') as f:
        f.seek(suffix_start - 0x50000)
        suffix = f.read(STOP - suffix_start)
    need(len(suffix) == 16 and stat(MAIN) == before, 'Short suffix or original MAIN changed')
    code = frozen[ENTRY - fragment['runtime_address']:] + suffix
    need(len(code) == STOP - ENTRY, 'Original loop source incomplete')
    cases = [run_case(code, table, pad) for pad in (0, 0xA5)]
    need(cases[0]['original_object40_6A_hex'] == cases[1]['original_object40_6A_hex'],
         'Outputs depend on bytes after actual table')
    proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
        'dependencies': [ref(METADATA)], 'source_MAIN': {
            'path': str(MAIN.relative_to(ROOT)), 'bytes': before[2],
            'verified_sha256_reference': metadata['original_MAIN']['verified_sha256_reference'],
            'whole_MAIN_digest_repeated': False, 'stat_unchanged': True},
        'source_backed_table': {'path': str(METADATA.relative_to(ROOT)), 'json_key': 'TRE_level_table',
            'GMP_logical_offset': metadata['TRE_level_table']['logical_offset'],
            'bytes': len(table), 'sha256': sha(table), 'hex': table.hex()},
        'original_loop_code': {'runtime_start': ENTRY, 'runtime_stop_exclusive': STOP,
            'bytes': len(code), 'sha256': sha(code), 'hex': code.hex(),
            'previously_frozen_fragment_bytes_reused': len(code) - len(suffix),
            'new_MAIN_suffix_bytes_read': len(suffix), 'new_suffix_MAIN_file_offset': suffix_start - 0x50000,
            'new_suffix_hex': suffix.hex(), 'new_suffix_sha256': sha(suffix)},
        'explicit_synthetic_predecessor_state': {
            'object_u16_at40': 0, 'object_u16_at42': 65535, 'object44_56_memzero_bytes': 18,
            'object_u8_at68': 8, 'object_u8_at69': 0,
            'stack_table_copy_from_actual_source': True, 'stack_count': 5,
            'r4_object_r5_object_plus60_r7_stack_table_SP': True},
        'cases': cases, 'all_cases_passed': True,
        'actual_original_loop_stores_obj56_24_obj68_0_verified': True,
        'table_trailing_bytes_variation_outputs_identical': True,
        'metadata_getter_or_complete_loader_executed': False, 'reader_rescale_executed_here': False,
        'partial_loop_only_not_complete_function': True, 'new_IMG_payload_bytes_read': 0,
        'runtime_copy_live_flag_verified': False, 'device_IO': False,
        'full_query_or_route_executed': False, 'live_metadata_instance_or_hardware_verified': False,
        'limitations': ['Predecessor object and stack state are explicit synthetic inputs; only the original no-call table loop is executed.',
            'Two padding controls prove these outputs do not depend on the four synthetic bytes after the original 20-byte table.',
            'No mapregistry, metadata getter, whole TRE loader, reader continuation, UI query or hardware navigation is executed.']}
    with target.open('x') as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
        'sha256': sha(target.read_bytes()), 'all_cases_passed': True,
        'original_obj56': cases[0]['original_object_u8_at56'], 'original_obj68': cases[0]['original_object_u8_at68'],
        'new_MAIN_suffix_bytes_read': len(suffix), 'new_IMG_payload_bytes_read': 0,
        'instruction_counts': [c['executed_instruction_count'] for c in cases]}))


if __name__ == '__main__':
    main()
