#!/usr/bin/env python3
"""File-only review of the original clock call, frames, and terminal boundary."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
from analyze_native_sections import ROOT, NativeImage

BASE = 'staging/native-player-clock-caller/'
OUT = BASE + 'clock-caller-observed-prefix.json'


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    h = hashlib.sha256()
    with (ROOT / path).open('rb') as handle:
        while block := handle.read(8 * 1024 * 1024):
            h.update(block)
    return h.hexdigest()


def main():
    assert not (ROOT / OUT).exists(), 'Preserve the successful review'
    metadata_path = BASE + 'runtime/terminal-metadata.json'
    meta = read(metadata_path)
    probe = read(meta['probe'])
    partial_path = BASE + 'runtime/independent-partial-journals.json'
    partial = read(partial_path)
    assert meta['session_id'] == 5264 and meta['terminal_exit_code'] == 1
    assert meta['actual_exec_chunk'] == '3bd84b'
    assert meta['authoritative_terminal_result_received_from_exec']
    assert partial['all_passed'] and partial['independent_file_only_bank_replay_verified']
    assert partial['source_sha256'][meta['probe']] == meta['probe_sha256'] == sha(meta['probe'])
    state = probe['body_actor_observations']['clock_caller_observer']
    assert state['clock_prefix_complete'] and state['pending'] is None
    assert not state['clock_write_attempts']
    assert not state['whole_395520_function_complete']
    assert not state['full_dispatcher_body_or_foreground_verified']
    assert not probe['callback_return_seen'] and not meta['body_full_guards_passed']
    stock = NativeImage()
    clock = 0xF09098
    bank = probe['partial_initialized_bank_verification']
    before = bytearray.fromhex(probe['mutable_bank_initial_before_hex'])
    assert len(before) == bank['bytes'] == 467532
    assert hashlib.sha256(before).hexdigest() == bank['before_sha256']
    offset = clock - int(bank['start'], 16)
    assert before[offset:offset + 4] == bytes(4)
    assert stock.runtime_to_load(clock, 4) == 0xCBAA18
    assert stock.word(0xCBAA18) == 0
    for event in bank['stores']:
        address, size = int(event['address'], 16), event['size']
        assert not (address < clock + 4 and clock < address + size)
    assert state['inputs']['before_hex'] == '00000000'
    assert not state['inputs']['host_clock_seeded_or_reset']
    assert not state['inputs']['initialized_data_bank_provenance']['new_mapping_or_BSS_zero_assumption']
    stack = next(z for z in probe['partial_body_zone_verification'] if z['start'] == '0x8801024')
    corresponding = next(z for z in partial['body_whole_zone_replays'] if z['start'] == stack['start'])
    assert corresponding['independent_replay_sha256'] == stack['after_sha256']
    stack_events = stack['stores']
    verified_pushes = []
    for name, entry, expected_count, expected_SP, expected_LR, opcode in (
        ('wrapper', 0x39578E, 6, 0x8804048, 0x26DD61, 'f8b5'),
        ('constructor', 0x395520, 9, 0x8804030, 0x3957B7, 'ffb5'),
    ):
        row = state[name]
        assert row['SP'] == expected_SP and row['LR'] == expected_LR
        assert row['native_push_complete'] and not row['frame_host_seeded']
        assert stock.read(entry, 2).hex() == opcode == row['original_entry_opcode']
        events = row['push_events']
        assert len(events) == expected_count
        index = row['whole_stack_event_index']
        assert stack_events[index:index + expected_count] == events
        image = bytearray.fromhex(row['push_before_hex'])
        base = int(row['push_start'], 16)
        for i, event in enumerate(events):
            assert event['PC'] == hex(entry) and event['opcode_hex'] == opcode
            assert event['running_task'] == '0x8804fb8' and event['processor_mode'] == 31 and event['Thumb']
            assert (int(event['address'], 16), event['size'], event['value']) == (base + 4 * i, 4, row['actual_push_values'][i])
            assert image[4 * i:4 * i + 4].hex() == event['before_hex']
            image[4 * i:4 * i + 4] = event['value'].to_bytes(4, 'little')
        assert image.hex() == row['push_after_hex']
        assert row['actual_after_push_SP'] == hex(base)
        call = row['source_call']
        assert stock.read(int(call['call'], 16), len(bytes.fromhex(call['opcode_hex']))).hex() == call['opcode_hex']
        verified_pushes.append(dict(frame=name, stores=expected_count, actual_SP=hex(expected_SP), push_after_hex=image.hex()))
    ctor = state['constructor']
    assert ctor['local_SUB_seen'] and stock.read(0x395522, 2).hex() == '97b0'
    assert ctor['native_stack_fifth_input'] == 1
    fifth = ctor['native_fifth_input_store']
    assert fifth in stack_events and fifth['PC'] == '0x3957b0'
    assert fifth['opcode_hex'] == stock.read(0x3957B0, 2).hex() == '0097'
    assert len(state['clock_reads']) == len(state['result_stores']) == 1
    getter = state['clock_reads'][0]
    assert getter['instructions_seen'] == [0x353A9C, 0x353A9E, 0x353AA0]
    assert stock.read(0x353A9C, 6).hex() == '014908687047'
    assert stock.word(0x353AA4) == clock
    assert getter['source_call']['call'] == '0x395528'
    assert stock.read(0x395528, 4).hex() == getter['source_call']['opcode_hex'] == 'bef7b8fa'
    assert getter['entry_SP'] == 0x8803FB0 and getter['LR'] == 0x39552D
    assert getter['original_return_branch_seen'] and getter['actual_return_seen']
    assert getter['actual_return_SP'] == '0x8803fb0'
    assert getter['actual_return_arguments'] == ['0x0', '0xf09098', '0x8804058', '0xea60']
    assert not getter['host_return_supplied'] and not getter['guest_context_restored_by_host']
    store = getter['result_store']
    assert store == state['result_stores'][0]
    assert (store['PC'], store['address'], store['size'], store['value']) == ('0x39552c', '0x8803fec', 4, 0)
    assert stock.read(0x39552C, 2).hex() == store['opcode_hex'] == '0f90'
    assert any(all(event[k] == value for k, value in store.items()) for event in stack_events)
    assert len(state['unreviewed_allocator_boundaries']) == 1
    stop = state['unreviewed_allocator_boundaries'][0]
    assert (stop['entry'], stop['native_caller'], stop['SP'], stop['requested_bytes']) == ('0x3954cc', '0x395534', '0x8803fb0', 48)
    assert not stop['host_allocator_return_allowed'] and not stop['admitted']
    assert probe['registers']['pc'] == stop['entry'] and probe['registers']['lr'] == '0x395535'
    paths = [str(Path(__file__).resolve().relative_to(ROOT)), metadata_path, meta['probe'], partial_path,
             meta['terminal_tool_receipt'], meta['GUI_observer'], BASE + 'gui-static/clock-caller-observer-v2-contract.json',
             'scripts/analyze_native_sections.py', 'evidence/firmware-analysis/main_02bd.bin']
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        source_sha256={p: sha(p) for p in paths}, actual_guest_session=5264,
        actual_guest_terminal_exit_code=1, actual_guest_terminal_chunk='3bd84b',
        actual_original_frame_pushes=verified_pushes, actual_native_push_CPU_stores=15,
        actual_original_clock_instructions=3, clock_value=0, clock_is_original_initialized_data=True,
        host_clock_seeded_or_reset=False, native_clock_actual_return_and_result_store_verified=True,
        original_result_store=store, next_unadmitted_allocator=stop,
        actual_native_allocator_executed=False, containing_constructor_return_verified=False,
        callback_return_or_foreground_or_physical_App_verified=False,
        independent_whole_stack_and_bank_replay_referenced=partial_path,
        guest_execution_by_verifier=False, VM_instantiated=False, device_io=False, sounds_emitted=False)
    with (ROOT / OUT).open('x') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(all_passed=True, actual_original_clock_instructions=3,
        actual_native_push_CPU_stores=15, native_clock_return_and_stack_store=True,
        original_allocator_executed=False, constructor_return_verified=False)))


if __name__ == '__main__':
    main()
