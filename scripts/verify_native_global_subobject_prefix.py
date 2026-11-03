#!/usr/bin/env python3
"""Prove the observed caller-stack and first global store, keeping failure scope."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys
from analyze_native_sections import ROOT, NativeImage

BASE = 'staging/native-player-global-subobject/'
RUNTIME = BASE + 'runtime-v2/'
OUT = BASE + 'global-object-observed-prefix.json'


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    digest = hashlib.sha256()
    with (ROOT / path).open('rb') as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    assert not (ROOT / OUT).exists(), 'Preserve positive prefix evidence'
    meta = read(RUNTIME + 'terminal-metadata.json')
    probe = read(meta['probe'])
    partial_path = RUNTIME + 'independent-partial-journals.json'
    partial = read(partial_path)
    assert meta['session_id'] == partial['session_id'] == 30399
    assert meta['actual_exec_chunk'] == '6ed1b9' and meta['terminal_exit_code'] == 1
    assert partial['all_passed'] and partial['independent_file_only_bank_replay_verified']
    assert probe['cold_prefix_full_guards_passed'] and probe['callback_entry_seen']
    assert not probe['callback_return_seen'] and not probe['body_full_guards_passed']
    assert sha(meta['probe']) == meta['probe_sha256']
    observer = probe['body_actor_observations']
    g = observer['global_subobject_observer']
    s = observer['settings_actor_observer']
    assert len(g['stores']) == 1 and not g['three_store_prefix_complete']
    assert g['base_native_return'] is None and g['derived_native_return'] is None
    assert not s['raw_ops'] and not s['defaults'] and not s['zero_calls']
    first = g['stores'][0]
    assert (first['PC'], first['load_PC'], first['address'], first['value'], first['size']) == (
        '0x26de42', '0x26de42', '0x3aaf844', 0xC035F8, 4)
    assert first['Thumb'] and first['opcode_hex'] == '2060' and first['before_hex'] == '00000000'
    stock = NativeImage()
    assert stock.read(0x26DE42, 2) == bytes.fromhex('2060')
    assert stock.word(0x26E100) == 0xC035F8 and stock.word(0x114688) == 0x3AAF844
    page = next(z for z in probe['partial_body_zone_verification'] if z['start'] == '0x3aaf000')
    initial = bytearray.fromhex(page['before_hex'])
    assert len(initial) == 4096
    for event in page['stores']:
        address = int(event['address'], 16)
        size = event['size']
        offset = address - 0x3AAF000
        assert initial[offset:offset + size].hex() == event['before_hex']
        op = bytes.fromhex(event['opcode_hex'])
        assert stock.read(int(event['load_PC'], 16), len(op)) == op
        initial[offset:offset + size] = event['value'].to_bytes(size, 'little')
    assert hashlib.sha256(initial).hexdigest() == page['after_sha256']
    object_after = bytes(initial[0x844:0x84C])
    assert object_after == bytes.fromhex('f835c00000000000')
    assert len(g['once_calls']) == 2
    once = []
    for row, pointer in zip(g['once_calls'], ['0xf701fc', '0xf701f8']):
        assert row['pointer'] == pointer and row['actual_return_seen'] and row['actual_return_r0'] == 1
        event = row['original_CPU_store']
        assert event['PC'] == '0x385450' and event['address'] == pointer
        assert event['value'] == 1 and event['size'] == 4 and event['before_hex'] == '00000000'
        assert event['running_task'] == '0x8804fb8'
        assert event in probe['partial_initialized_bank_verification']['stores']
        assert stock.read(0x385450, 2) == bytes.fromhex(event['original_opcode_hex'])
        once.append(dict(pointer=pointer, original_zero_to_one_verified=True, actual_native_return_verified=True))
    frame = g['frame_history'][0]
    assert frame['entry'] == '0x114612' and frame['SP'] == 0x8804100
    stack_input = frame['native_caller_stack_input']
    assert stack_input['start'] == '0x8804194' and stack_input['bytes'] == 8
    assert stack_input['input_is_caller_stack'] and not stack_input['raw_heap_input_required']
    assert stock.read(0x115204, 2) == bytes.fromhex('25ad')
    assert stock.read(0x1152CA, 2) == bytes.fromhex('2900')
    writes = stack_input['original_currentD_CPU_writes']
    assert writes[-2]['PC'] == '0x4501088' and writes[-2]['load_PC'] == '0xe24c54'
    assert writes[-1]['PC'] == '0x450108e' and writes[-1]['load_PC'] == '0xe24c5a'
    stack = next(z for z in probe['partial_body_zone_verification'] if z['start'] == '0x8801024')
    before = bytearray.fromhex(stack['before_hex'])
    expected = bytes(before[0x3170:0x3178])
    for event in writes:
        assert event in stack['stores'] and event['running_task'] == '0x8804fb8'
        offset = int(event['address'], 16) - 0x8804194
        size = event['size']
        assert expected[offset:offset + size].hex() == event['before_hex']
        assert stock.read(int(event['load_PC'], 16), len(bytes.fromhex(event['opcode_hex']))) == bytes.fromhex(event['opcode_hex'])
        value = bytearray(expected)
        value[offset:offset + size] = event['value'].to_bytes(size, 'little')
        expected = bytes(value)
    assert expected.hex() == stack_input['before_native_getter_hex'] == 'a040820820418208'
    assert s['unknown_boundaries'][0]['PC'] == '0x44f76d0'
    assert s['unknown_boundaries'][0]['actual_target'] == '0x3aaf81c'
    paths = [str(Path(__file__).resolve().relative_to(ROOT)), RUNTIME + 'terminal-metadata.json',
             meta['probe'], partial_path, meta['runner'], meta['GUI_observer'],
             BASE + 'gui-static/global-subobject-observer-v2-contract.json',
             'evidence/firmware-analysis/main_02bd.bin']
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        source_sha256={path: sha(path) for path in paths},
        session_id=30399, original_guest_terminal_exit_code=1,
        first_original_global_store_verified=True, actual_global_stores=1, required_full_sequence_stores=3,
        observed_once_transitions=once, caller_stack_input_hex=expected.hex(),
        caller_stack_is_original_CPU_generated=True, whole_page_history_replayed=True,
        global_object_after_hex=object_after.hex(), next_unreviewed_writer='0x44f76d0',
        next_target='0x3aaf81c', settings_raw_operations=0, defaults_observed=0,
        native_memzero_calls_completed=0, constructor_return_verified=False,
        full_Dispatcher_body_or_foreground_verified=False, physical_App_verified=False,
        guest_execution_by_verifier=False, VM_instantiation_by_verifier=False, device_io=False,
        scope='Observed first global vtable store, native once transitions and original caller-stack input only. '
              'The terminal boundary and unexecuted later stores/returns/settings are preserved; no full constructor or App claim.')
    with (ROOT / OUT).open('x') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(all_passed=True, original_global_stores=1, once_transitions=2,
                         original_caller_stack_input=True, terminal_exit_code=1)))


if __name__ == '__main__':
    main()
