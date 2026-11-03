#!/usr/bin/env python3
"""Independent file-only partial journal replay, including original bank bytes."""
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
import hashlib
import json
import re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import ROOT, NativeImage

BASE = 'staging/native-player-settings-scope/'
RUNTIME = BASE + 'runtime/'
OUT = BASE + 'runtime/independent-partial-journals.json'


def read(path):
    return json.loads((ROOT / path).read_text())


@lru_cache(None)
def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    assert not (ROOT / OUT).exists(), 'Preserve independent partial proof'
    meta = read(RUNTIME + 'terminal-metadata.json')
    probe = read(meta['probe'])
    assert meta['authoritative_terminal_result_received_from_exec']
    assert meta['cold_prefix_full_guards_passed'] and probe['callback_entry_seen']
    for path, digest in meta['source_sha256'].items():
        assert sha(path) == digest, path
    for key in ('runner', 'runner_snapshot', 'inputs', 'probe', 'FP_helper', 'GUI_observer', 'sealer', 'cold_prefix', 'terminal_tool_receipt'):
        assert sha(meta[key]) == meta[key + '_sha256'], key
    stock = NativeImage()
    companion_path = read('staging/controller-gir-prep-stock-v2/verification.json')['flat_binary']
    companion = (ROOT / companion_path).read_bytes()
    disassemblers = {False: Cs(CS_ARCH_ARM, CS_MODE_ARM), True: Cs(CS_ARCH_ARM, CS_MODE_THUMB)}
    decoded = {}
    counts = {'original_MAIN': 0, 'frozen_ARM_companion': 0}

    def original_store(row):
        pc = int(row['PC'], 16)
        opcode = bytes.fromhex(row.get('opcode_hex', row.get('original_opcode_hex', '')))
        thumb = row['Thumb']
        assert isinstance(thumb, bool) and opcode
        if row.get('writer_kind') == 'frozen_ARM_companion':
            offset = pc - 0xEA10000
            assert offset >= 0 and companion[offset:offset + len(opcode)] == opcode
            counts['frozen_ARM_companion'] += 1
        else:
            load = int(row['load_PC'], 16) if 'load_PC' in row else (
                stock.runtime_to_load(pc, len(opcode))
                if any(r['runtime_start'] <= pc and pc + len(opcode) <= r['runtime_end'] for r in stock.copies) else pc)
            assert stock.read(load, len(opcode)) == opcode, row['PC']
            counts['original_MAIN'] += 1
        key = (pc, thumb, opcode)
        if key not in decoded:
            instructions = list(disassemblers[thumb].disasm(opcode, pc, count=1))
            assert len(instructions) == 1 and instructions[0].size == len(opcode)
            instruction = instructions[0]
            assert instruction.mnemonic.startswith(('str', 'stm', 'swp', 'push', 'vstr', 'vstm'))
            decoded[key] = instruction.mnemonic + ' ' + instruction.op_str
        assert re.sub(r'\s+', '', decoded[key]) == re.sub(r'\s+', '', row['original_instruction']), row['PC']

    def replay(zone, before_hex=None):
        expected = bytearray.fromhex(before_hex if before_hex is not None else zone['before_hex'])
        start = int(zone['start'], 16)
        assert len(expected) == zone['bytes']
        if 'before_sha256' in zone:
            assert hashlib.sha256(expected).hexdigest() == zone['before_sha256']
        for row in zone['stores']:
            original_store(row)
            offset, size = int(row['address'], 16) - start, row['size']
            assert size in (1, 2, 4, 8) and 0 <= offset and offset + size <= len(expected)
            assert expected[offset:offset + size].hex() == row['before_hex']
            expected[offset:offset + size] = row['value'].to_bytes(size, 'little')
        digest = hashlib.sha256(expected).hexdigest()
        assert digest == zone['after_sha256'], zone['start']
        return dict(start=zone['start'], bytes=len(expected), events=len(zone['stores']),
            independent_replay_sha256=digest, equals_recorded_actual_after_sha256=True)

    body = probe['partial_body_zone_verification']
    floating = probe['partial_FP_zone_verification']
    inherited = probe['partial_inherited_zone_verification']
    assert len(body) == 7 and len(floating) == 8 and len(inherited) == 22
    body_replay = [replay(zone) for zone in body]
    fp_replay = [replay(zone) for zone in floating]
    inherited_replay = [replay(zone) for zone in inherited]
    bank = probe['partial_initialized_bank_verification']
    bank_replay = replay(bank, probe['mutable_bank_initial_before_hex'])
    assert bank['whole_bank_matches_original_CPU_write_history'] and not bank['host_unrecorded_mutation']
    assert bank_replay['bytes'] == 467532
    assert len(probe['original_lazy_handler_rows']) == 1
    first = probe['original_lazy_handler_rows'][0]
    assert first['save_complete'] and not first['restore_complete'] and first['original_opcode_retry_reached']
    paths = [str(Path(__file__).resolve().relative_to(ROOT)), RUNTIME + 'terminal-metadata.json', meta['probe'], companion_path]
    paths += [BASE + 'partial-verifier-v1-failure/source-at-verification.py', BASE + 'partial-verifier-v1-failure/failure.json']
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        source_sha256={path: sha(path) for path in paths},
        verified_runtime_dependencies=meta['source_sha256'],
        session_id=meta['session_id'], original_guest_terminal_exit_code=meta['terminal_exit_code'],
        original_guest_terminal_error=meta['error'],
        body_whole_zone_replays=body_replay, FP_whole_zone_replays=fp_replay,
        inherited_whole_zone_replays=inherited_replay, initialized_bank_replay=bank_replay,
        original_instruction_mode_combinations_verified=len(decoded), CPU_store_event_counts=counts,
        counts_include_overlapping_zone_observations=True,
        inherited_contains_frozen_companion_stores=True,
        initial_bank_bytes_present=True, independent_file_only_bank_replay_verified=True,
        first_C_to_D_save_only=True, complete_multiowner_exchange_verified=False,
        callback_return_seen=probe['callback_return_seen'],
        complete_body_guards_verified=meta['body_full_guards_passed'],
        foreground_or_device_App_verified=False, guest_execution_by_verifier=False,
        guest_VM_instantiated_by_verifier=False, device_io=False, sounds_emitted=False,
        scope='Partial histories through recorded terminal boundary; complete bank initial bytes now allow independent replay. Native GUI, hardware, scheduler integration and physical App are not proven.')
    with (ROOT / OUT).open('x') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(all_passed=True, body_zones=7, FP_zones=8, inherited_zones=22,
        independent_bank_bytes=bank_replay['bytes'], CPU_events=counts,
        original_guest_terminal_exit_code=meta['terminal_exit_code'])))


if __name__ == '__main__':
    main()
