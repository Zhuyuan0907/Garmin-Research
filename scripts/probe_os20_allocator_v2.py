#!/usr/bin/env python3
"""Retain the two completed v1 scopes; rerun ONLY its unfinalized control.

The one-page private extent is rejected during original extent validation,
before the page-pop site initially predicted. Preserve the failed prediction.
"""
import sys
sys.dont_write_bytecode = True
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
from probe_os20_allocator_v1 import (
    ROOT, NativeImage, HeapCase, PRIVATE, PUBLIC, REGS, UC_ARM_REG_PC,
    UC_ARM_REG_SP, UC_ARM_REG_LR, sha, save, compressed)

OUT = ROOT / 'staging/native-os20-allocator-v2'


def main():
    assert not OUT.exists()
    OUT.mkdir()
    old_base = ROOT / 'staging/native-os20-allocator-v1'
    receipt = json.loads((old_base / 'terminal-tool-receipt.json').read_text())
    assert receipt['terminal'] and receipt['actual_terminal_result']['exit_code'] == 1
    assert 'session_id' not in receipt['actual_terminal_result']
    inputs = json.loads((old_base / 'inputs-at-run.json').read_text())
    assert all(sha(ROOT / path) == h for path, h in inputs['source_sha256'].items())
    rows = []
    import gzip
    for name in ('native_OS20_two_allocation_prefix', 'no_public_extent_hits_original_diagnostic'):
        path = old_base / (name + '.json.gz')
        data = json.load(gzip.open(path, 'rt'))
        assert data['all_passed'] and data['name'] == name
        rows.append(dict(name=name, path=str(path.relative_to(ROOT)), sha256=sha(path),
                         original_guest_terminal_exit=1, completed_prefix_scope=True,
                         CPU_stores=len(data['CPU_stores']), instructions=len(data['original_instruction_trace']),
                         native_full_returns=len(data['native_full_returns']), boundary=data['boundary']['kind'],
                         guest_rerun=False))
    n = NativeImage()
    m = HeapCase(n, 'private_prefix_only_rejected_during_extent_validation', 4096, 65536)
    try:
        m.call('original_exit_list_constructor', 0x3cc57c, [0x02d226b4])
        assert m.done
        m.call('new_original_heap_constructor', 0x388b6c, [0x09030000, 1, 0x09030010, 1])
        assert not m.done and m.boundary and m.boundary['PC'] == 0x23d6e8
        assert m.boundary['state']['GP16'][14] == 0x388c65
        assert m.boundary['state']['GP16'][1] == 3
        assert m.boundary['state']['GP16'][4] == m.boundary['state']['GP16'][7] == 0
        assert m.trace[-1]['PC'] == 0x388c60 and m.trace[-1]['opcode_hex'] == 'b4f642fd'
        final = {r['name']: bytes(m.u.mem_read(r['start'], r['size'])).hex() for r in m.zones}
        for row in m.zones:
            expected = bytearray.fromhex(m.before[row['name']])
            for store in m.stores:
                if store['zone'] != row['name']:
                    continue
                offset, length = store['address'] - row['start'], store['size']
                assert expected[offset:offset + length].hex() == store['before_hex']
                expected[offset:offset + length] = store['value'].to_bytes(length, 'little')
            assert expected.hex() == final[row['name']]
        for base, size in ((PRIVATE, 4096), (PUBLIC, 65536)):
            assert bytes(m.u.mem_read(base - 4096, 4096)) == b'\xa5' * 4096
            assert bytes(m.u.mem_read(base + size, 4096)) == b'\xa5' * 4096
        assert hashlib.sha256(bytes(m.u.mem_read(0x50000, m.rom_size))).hexdigest() == m.rx_sha
        data = dict(all_passed=True, name=m.name, input_private_bytes=4096, input_public_bytes=65536,
                    declared_synthetic_current_TCB=0x09040000, current_TCB_not_constructed_by_kernel=True,
                    model_SCTLR=m.sctlr, MMU_translation_disabled=True,
                    table_bytes_not_captured_from_hardware=True,
                    original_constructor_calls=m.host_calls, native_full_returns=m.native_calls,
                    unreturned_native_frames=m.open_calls, boundary=m.boundary, payloads=None,
                    zones=m.zones, whole_zones_before=m.before, whole_zones_after=final,
                    CPU_stores=m.stores, original_instruction_trace=m.trace,
                    unchanged_original_RX_sha256=m.rx_sha, no_WORK_or_free_page_heads_seeded=True,
                    original_code_or_functions_not_replaced=True,
                    actual_task_created_or_callback_or_physical_heap_verified=False, device_IO=False)
        path = OUT / (m.name + '.json.gz')
        compressed(path, data)
        rows.append(dict(name=m.name, path=str(path.relative_to(ROOT)), sha256=sha(path),
                         original_guest_terminal_exit=0, completed_prefix_scope=False,
                         CPU_stores=len(m.stores), instructions=len(m.trace),
                         native_full_returns=len(m.native_calls), boundary=m.boundary['kind']))
        sources = dict(inputs['source_sha256'])
        for path in (Path(__file__).resolve(), old_base / 'inputs-at-run.json',
                     old_base / 'terminal-tool-receipt.json', old_base / 'terminal-failure.json.gz'):
            sources[str(path.relative_to(ROOT))] = sha(path)
        save(OUT / 'guest-proof.json', dict(
            all_passed=True, cases=rows, source_sha256=sources, case_count=3,
            two_completed_EXIT1_prefix_scopes_preserved_not_rerun=True,
            corrected_failed_control_only_new_execution=True,
            original_v1_wrong_diagnostic_site_prediction_preserved=True,
            actual_task_created_or_physical_heap_verified=False, device_IO=False,
            updated_utc=datetime.now(timezone.utc).isoformat()))
        print(json.dumps(dict(all_passed=True, completed_prefix_cases=2,
                              corrected_new_control_cases=1, cases=rows)), flush=True)
    except BaseException as error:
        import traceback
        compressed(OUT / 'terminal-failure.json.gz', dict(
            error=str(error), traceback=traceback.format_exc(), state=m.snap(),
            CPU_stores=m.stores, trace=m.trace, boundary=m.boundary, device_IO=False))
        raise


if __name__ == '__main__':
    main()
