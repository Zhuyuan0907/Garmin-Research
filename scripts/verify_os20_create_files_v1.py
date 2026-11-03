#!/usr/bin/env python3
"""Verify completed create continuations from source bytes and saved traces.

No VM rerun. Validate all native stores, declared new inputs, TCB/name/queue
semantics and native ABI returns. Not a full nonstore interpreter or hardware
MMU/kernel inventory verification.
"""
import sys
sys.dont_write_bytecode = True
import gzip
import hashlib
import json
import struct
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from analyze_native_sections import NativeImage
from verify_os20_allocator_files_v1 import stores_for
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-os20-create-file-v1'
CASES = ['staging/native-os20-create-continuation-v3/', 'staging/native-os20-create-finish-v2/']


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(p):
    if str(p).endswith('.gz'):
        return json.load(gzip.open(p, 'rt'))
    return json.loads(p.read_text())


def zone_bytes(d, name, after=True):
    z = next(z for z in d['zones'] if z['name'] == name)
    return z['start'], bytes.fromhex(d['whole_zones_after' if after else 'whole_zones_before'][name])


def u32(d, address, after=True):
    z = next(z for z in d['zones'] if z['start'] <= address and address + 4 <= z['start'] + z['size'])
    b = bytes.fromhex(d['whole_zones_after' if after else 'whole_zones_before'][z['name']])
    return struct.unpack_from('<I', b, address - z['start'])[0]


def main():
    assert not OUT.exists()
    OUT.mkdir()
    n = NativeImage()
    decoders = {False: Cs(CS_ARCH_ARM, CS_MODE_ARM), True: Cs(CS_ARCH_ARM, CS_MODE_THUMB)}
    for md in decoders.values():
        md.detail = True
    sources, totals, completed = {}, Counter(), []
    data = []
    try:
        for base in CASES:
            guest = load(ROOT / base / 'guest-proof.json')
            result = load(ROOT / base / 'terminal-tool-receipt.json')['actual_terminal_result']
            assert result['exit_code'] == 0 and 'session_id' not in result
            assert guest['all_passed']
            for p, expected in guest['source_sha256'].items():
                assert sha(ROOT / p) == expected, p
                assert p not in sources or sources[p] == expected
                sources[p] = expected
            row = guest['case']
            path = ROOT / row['path']
            assert sha(path) == row['sha256']
            d = load(path)
            assert d['all_passed'] and not d['device_IO']
            parent = load(ROOT / d['parent_checkpoint'])
            assert sha(ROOT / d['parent_checkpoint']) == d['parent_checkpoint_sha256']
            by_name = {z['name']: z for z in d['zones']}
            before = {name: bytearray.fromhex(value) for name, value in d['whole_zones_before'].items()}
            if len(data) == 0:
                # Restore the complete allocation endpoint, then apply only
                # the two explicitly declared caller-input changes.
                reconstructed = {name: bytearray.fromhex(value) for name, value in parent['whole_zones_after'].items()}
                for name, z in by_name.items():
                    if name in reconstructed:
                        continue
                    assert z['original_startup_zero']
                    assert any(r['runtime_start'] <= z['start'] and z['start'] + z['size'] <= r['runtime_end'] for r in n.zeros)
                    reconstructed[name] = bytearray(z['size'])
                assert len(d['explicit_new_name_fixture_writes']) == 2
                for w in d['explicit_new_name_fixture_writes']:
                    payload = bytes.fromhex(w['after_hex'])
                    z = next(z for z in d['zones'] if z['start'] <= w['address'] and w['address'] + len(payload) <= z['start'] + z['size'])
                    off = w['address'] - z['start']
                    assert reconstructed[z['name']][off:off + len(payload)].hex() == w['before_hex']
                    reconstructed[z['name']][off:off + len(payload)] = payload
                assert reconstructed == before
                tail = parent['original_instruction_trace'][-2:]
                assert [x['PC'] for x in tail] == [0x521e8c, 0x521e8e]
                assert not any(s['PC'] in {0x521e8c, 0x521e8e} for s in parent['CPU_stores'])
                first = d['original_instruction_trace'][0]
                assert first['PC'] == 0x521e8c
                assert first['GP16'] == tail[0]['GP16'] and first['CPSR'] == tail[0]['CPSR']
                assert d['parent_allocations_not_replayed']
            else:
                assert d['whole_zones_before'] == parent['whole_zones_after']
                assert not d['allocation_or_TCB_scope_replayed']
                assert d['suffix_before'] == parent['boundary']['state']
            journals, count, states = d['CPU_stores'], 0, []
            for t in d['original_instruction_trace']:
                raw = bytes.fromhex(t['opcode_hex'])
                assert n.read(t['PC'], len(raw)) == raw
                i = next(decoders[bool(t['CPSR'] & 32)].disasm(raw, t['PC'], count=1))
                assert i.size == t['size'] and i.bytes == raw
                states.append((t['PC'], t['GP16'], t['CPSR']))
                for address, size, value in stores_for(i, t):
                    s = journals[count]
                    assert (s['PC'], s['address'], s['size'], s['value']) == (t['PC'], address, size, value)
                    assert s['GP16'] == t['GP16'] and s['CPSR'] == t['CPSR']
                    assert s['opcode_hex'] == raw.hex() and s['phase'] == t['phase']
                    z = by_name[s['zone']]
                    off = address - z['start']
                    assert 0 <= off and off + size <= z['size']
                    assert before[z['name']][off:off + size].hex() == s['before_hex']
                    before[z['name']][off:off + size] = value.to_bytes(size, 'little')
                    count += 1
            assert count == len(journals)
            assert {name: b.hex() for name, b in before.items()} == d['whole_zones_after']
            endpoint = d['boundary']['state'] if len(data) == 0 else d['original_create_return_after']
            states.append((endpoint['GP16'][15], endpoint['GP16'], endpoint['CPSR']))
            for call in d['native_full_returns']:
                b, a = call['before'], call['after']
                assert call['full_ABI_return']
                assert (call['entry'], b['GP16'], b['CPSR']) in states
                assert (call['return_PC'], a['GP16'], a['CPSR']) in states
                assert b['GP16'][4:12] == a['GP16'][4:12] and b['GP16'][13] == a['GP16'][13]
                assert (b['CPSR'] ^ a['CPSR']) & 0xdf == 0
            for p in (row['path'], base + 'guest-proof.json', base + 'terminal-tool-receipt.json'):
                sources[p] = sha(ROOT / p)
            totals.update(CPU_stores=count, store_effective_addresses=count,
                          whole_zones=len(before), instructions=len(states) - 1,
                          native_full_returns=len(d['native_full_returns']))
            completed.append(dict(name=d['name'], passed=True, exact_store_EA_values=True,
                whole_zone_replay=True, original_full_ABI_returns_checked=True, guest_rerun=False))
            data.append(d)
        created, posted = data
        desc, task = created['descriptor'], created['original_new_TCB']
        start, public = zone_bytes(created, 'public_extent_and_guards')
        name = public[desc + 60 - start:desc + 100 - start]
        expected = 'Garmin Music\0'.encode('utf-16le')
        assert name == expected + bytes(40 - len(expected))
        assert created['name_output40_hex'] == name.hex()
        assert task == (created['workspace'] + created['workspace_bytes'] - 108) & ~7
        frame = u32(created, task + 12)
        assert frame == task - 52
        words = struct.unpack_from('<13I', public, frame - start)
        assert words == (0x3f, 0x521e45, *([0] * 9), task, 0x358fa5)
        assert public[task + 16 - start:task + 18 - start] == b'\xf0\xf0'
        assert public[task + 22 - start] == 2
        assert u32(created, 0xf071cc) == u32(created, 0xf071d0) == 1
        assert u32(created, 0x014b3ad0) == desc
        assert [c['entry'] for c in created['native_full_returns']] == [0x2fc9bc, 0x2fccce, 0x2fcd0a, 0x358bf8, 0x2fbbbe, 0x521d7c]
        irq = [t for t in created['original_instruction_trace'] if t['PC'] in {0x21b6cc, 0x21b6dc}]
        assert len(irq) == 2 and irq[0]['PC'] == 0x21b6cc and irq[1]['PC'] == 0x21b6dc
        assert irq[1]['GP16'][0] == irq[0]['CPSR']
        assert posted['original_create_complete_ABI_return'] and posted['original_POST_complete_return']
        b, a = posted['original_create_entry_before'], posted['original_create_return_after']
        assert b['GP16'][4:12] == a['GP16'][4:12] and b['GP16'][13] == a['GP16'][13]
        assert (b['CPSR'] ^ a['CPSR']) & 0xdf == 0
        assert a['GP16'][0] == created['adapter_record']
        start, public_after = zone_bytes(posted, 'public_extent_and_guards')
        assert public_after[task + 22 - start] == 1
        assert u32(posted, 0x09040000) == task and u32(posted, task) == 0
        assert u32(posted, 0xf09090) == 0x09040000
        assert not any(t['PC'] in {0x521e44, 0x358ec4} for t in posted['original_instruction_trace'])
        assert totals == dict(CPU_stores=1676, store_effective_addresses=1676, whole_zones=24,
                              instructions=3403, native_full_returns=7)
        for p in (Path(__file__), ROOT / 'scripts/verify_os20_allocator_files_v1.py'):
            sources[str(p.relative_to(ROOT))] = sha(p)
        proof = dict(all_passed=True, cases=completed, totals=dict(totals), source_sha256=sources,
            actual_original_name_converter_produced_UTF16LE=True,
            original_name_source_codepage=1252, observed_name_capacity40_bytes=True,
            original_task_control_block_and_compact_frame_created=True,
            original_descriptor_and_OS20_adapter_registered=True,
            original_POST_inserted_new_task_after_synthetic_current=True,
            original_create_function_complete_ABI_return=True,
            fixture_name_changes_explicit_and_parent_allocation_not_replayed=True,
            original_IRQ_pair_state_argument_verified=True,
            null_name_failure_not_original_firmware_bug=True,
            original_root_or_user_callback_not_executed=True,
            actual_kernel_boot_current_TCB_physical_heap_or_App_verified=False,
            full_nonstore_semantic_interpreter=False, new_independent_agent_review=False,
            device_IO=False, updated_utc=datetime.now(timezone.utc).isoformat())
        with (OUT / 'ROOT_FILE-proof-v1.json').open('x') as f:
            json.dump(proof, f, indent=2); f.write('\n')
        print(json.dumps(dict(all_passed=True, totals=dict(totals), cases=2,
            original_create_complete_return=True, original_callback_executed=False)), flush=True)
    except BaseException as error:
        with (OUT / 'terminal-failure.json').open('x') as f:
            json.dump(dict(all_passed=False, error=str(error), traceback=traceback.format_exc(),
                completed_cases=completed, partial_totals=dict(totals), guest_rerun=False), f, indent=2)
            f.write('\n')
        raise


if __name__ == '__main__':
    main()
