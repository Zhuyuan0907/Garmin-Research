#!/usr/bin/env python3
"""File-only replay of the actual bounded settings branch, not physical NV."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
from analyze_native_sections import ROOT, NativeImage

BASE = 'staging/native-player-inline-fields/'
OUT = BASE + 'settings-observed-prefix-v2.json'


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    h = hashlib.sha256()
    with (ROOT / path).open('rb') as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    assert not (ROOT / OUT).exists()
    meta = read(BASE + 'runtime/terminal-metadata.json')
    probe = read(meta['probe'])
    partial_path = BASE + 'runtime/independent-partial-journals.json'
    partial = read(partial_path)
    assert meta['authoritative_terminal_result_received_from_exec'] and meta['session_id'] == 35110
    assert sha(meta['probe']) == meta['probe_sha256']
    assert partial['all_passed'] and partial['independent_file_only_bank_replay_verified']
    settings = probe['body_actor_observations']['settings_actor_observer']
    stock = NativeImage()
    replayed = []
    actual_containers = probe['partial_body_zone_verification'] + probe['partial_inherited_zone_verification']
    def whole_replay(zone):
        raw = bytearray.fromhex(zone['before_hex'])
        start = int(zone['start'], 16)
        for event in zone['stores']:
            op = bytes.fromhex(event['opcode_hex'])
            assert stock.read(int(event['load_PC'], 16), len(op)) == op
            offset, n = int(event['address'], 16) - start, event['size']
            assert raw[offset:offset+n].hex() == event['before_hex']
            raw[offset:offset+n] = event['value'].to_bytes(n, 'little')
        assert hashlib.sha256(raw).hexdigest() == zone['after_sha256']
        return raw
    for zone in settings['zones'].values():
        raw = bytearray.fromhex(zone['before_hex'])
        start = int(zone['start'], 16)
        assert len(raw) == zone['bytes']
        for event in zone['stores']:
            pc = int(event['PC'], 16)
            opcode = bytes.fromhex(event['opcode_hex'])
            assert stock.read(int(event['load_PC'], 16), len(opcode)) == opcode
            assert event['running_task'] == '0x8804fb8' and event['Thumb'] in (True, False)
            offset, n = int(event['address'], 16) - start, event['size']
            assert n in (1, 2, 4) and 0 <= offset and offset + n <= len(raw)
            assert raw[offset:offset + n].hex() == event['before_hex']
            raw[offset:offset + n] = event['value'].to_bytes(n, 'little')
        digest = hashlib.sha256(raw).hexdigest()
        container = next(x for x in actual_containers if int(x['start'],16) <= start and start+len(raw) <= int(x['start'],16)+x['bytes'])
        complete = whole_replay(container)
        offset = start-int(container['start'],16)
        assert bytes(raw) == complete[offset:offset+len(raw)]
        replayed.append(dict(start=zone['start'], bytes=len(raw), stores=len(zone['stores']), after_sha256=digest, actual_after_source=container['start'], actual_container_after_sha256=container['after_sha256']))
    assert len(replayed) == 2
    operations = settings['raw_ops']
    assert len(operations) == 2 and not settings['raw_returns_pending']
    for row, entry, caller, operation in zip(operations, ('0x3009a0', '0x3008b0'),
            ('0x2cabfa', '0x2cac08'), ('lock', 'unlock')):
        assert (row['original_entry'], row['native_caller'], row['operation']) == (entry, caller, operation)
        assert row['pointer'] == '0x148e6cc' and row['running_task'] == '0x8804fb8'
        assert row['entry_SP'] == row['actual_return_SP'] == '0x8804018'
        assert row['native_body_returned'] and row['actual_caller_continuation_seen']
        assert row['original_return_branch_reached'] and row['semaphore_fields_written_by_original_only']
        assert not row['host_CPU_context_restore']
        assert row['before_words'][4] == row['after_words'][4] == '0x2cbf6c'
    assert operations[0]['native_lock_acquired_by_originating_task']
    assert operations[0]['after_words'][2] == '0x8804fb8' and operations[1]['after_words'][2] == '0x0'
    assert operations[0]['after_words'] == operations[1]['before_words']
    # Unlocked backend links retain history; zero is not a release requirement.
    assert operations[1]['after_words'][:2] == ['0x8810718', '0x8804fd8']
    zeros = settings['zero_calls']
    assert len(zeros) == 1 and settings['zero_call'] is None
    zero = zeros[0]
    assert zero['start'] == 0x3aaed08 and zero['bytes'] == 0xb10 and zero['page_zero_events'] == 518
    assert zero['original_return_seen'] and not zero['host_zeroed_memory']
    assert zero['LR'] == 0x26dd27 and zero['actual_return_SP'] == '0x8804048'
    witness, lower = settings['source_id_witness'], settings['lower_queries']
    assert witness['PC'] == '0x26dd2c' and witness['literal'] == '0x26e0bc' and witness['value'] == 0x100d
    assert stock.word(0x26e0bc) == 0x100d and len(lower) == 1
    assert lower[0]['actual_absent_return_seen'] and lower[0]['inherited_lower_inventory_fixture_preserved']
    assert not lower[0]['host_return_supplied_by_this_observer']
    defaults = settings['defaults']
    assert len(defaults) == 1 and defaults[0]['native_wrapper_return'] == 0xffffffff
    assert defaults[0]['source_setting_id'] == 0x100d and defaults[0]['store_seen']
    assert defaults[0]['actual_continuation'] == '0x26dd38' and defaults[0]['target'] == '0x3aaf838'
    page = settings['zones'][str(0x3aaf000)]
    stores = [x for x in page['stores'] if x['PC'] == '0x26dd3c']
    assert len(stores) == 1 and stores[0]['address'] == '0x3aaf838' and stores[0]['value'] == 0
    assert stores[0]['opcode_hex'] == '3e63' and stores[0]['original_instruction'] == 'str r6, [r7, #0x30]'
    assert stock.read(0x26dd3c, 2).hex() == '3e63'
    paths = [str(Path(__file__).resolve().relative_to(ROOT)), BASE + 'runtime/terminal-metadata.json', meta['probe'], partial_path,
        'staging/native-player-settings-scope/gui-static/settings_actor_observer.py', 'evidence/firmware-analysis/main_02bd.bin',
        BASE+'settings-verifier-v1-failure/source-at-run.py', BASE+'settings-verifier-v1-failure/failure.json']
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        source_sha256={p: sha(p) for p in paths}, actual_guest_session=35110, original_guest_terminal_exit_code=1,
        actual_raw_operations=2, actual_memzero_returns=1, original_clear_bytes=2832, page_memzero_store_events=518,
        actual_default_stores=1, settings_id='0x100d', original_R6_zero_not_R0_minus1_store=True,
        raw_lock_acquire_and_release_native_return_verified=True, released_links_preserved=True,
        whole_zones_independently_replayed=replayed, lower_missing_record_is_declared_inherited_fixture=True,
        actual_physical_NV_settings_read_verified=False, SFS_constructor_return_verified=False,
        callback_return_verified=False, complete_body_guards_verified=False,
        guest_execution_by_verifier=False, device_io=False, sounds_emitted=False)
    assert not probe['callback_return_seen'] and not meta['body_full_guards_passed']
    with (ROOT / OUT).open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps(dict(all_passed=True, native_raw_operations=2, memzero_bytes=2832,
        page_zero_stores=518, default_stores=1, actual_physical_NV_settings_read_verified=False)))


if __name__ == '__main__':
    main()
