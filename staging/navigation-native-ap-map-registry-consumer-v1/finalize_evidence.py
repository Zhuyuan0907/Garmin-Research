#!/usr/bin/env python3
"""Audit this scope's captured bytes and completed guest receipts; no guest rerun.

MAIN is stat-only. IMG files are never opened. Capture names were discovery
hypotheses; the interpreted witnesses and explicit errata below are authoritative.
"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent


def sha(b):
    return hashlib.sha256(b).hexdigest()


def save(name, obj):
    (HERE / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')


def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    ledger = json.loads((HERE / 'read-ledger.json').read_bytes())
    assert ledger['bytes'] == 17134 and ledger['bytes'] <= 65536
    assert stat(ROOT / 'evidence/firmware-analysis/main_02bd.bin') == ledger['MAIN_stat']
    captures = []
    windows = []
    revisions = {}
    for n in ['capture_windows_initial.py', 'capture_windows.py']:
        b = (HERE / n).read_bytes()
        revisions[sha(b)] = n
    for row in ledger['batches']:
        b = (ROOT / row['path']).read_bytes()
        assert sha(b) == row['sha256']
        d = json.loads(b)
        assert d['source_sha256'] in revisions
        assert d['MAIN_stat_before'] == d['MAIN_stat_after'] == ledger['MAIN_stat']
        assert d['handles_closed'] and not d['CPU_executed']
        for w in d['windows']:
            raw = bytes.fromhex(w['raw_hex'])
            assert len(raw) == w['bytes'] and sha(raw) == w['sha256']
        captures.append(dict(path=row['path'], sha256=sha(b),
                             bytes=d['explicit_read_bytes'],
                             operations=d['explicit_read_operations'],
                             capture_source_sha256=d['source_sha256']))
        windows.extend(d['windows'])
    assert sum(r['bytes'] for r in captures) == ledger['bytes']
    assert sum(r['operations'] for r in captures) == ledger['operations']

    def raw(a, n):
        out = [bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'], 16):a-int(w['runtime_start'], 16)+n]
               for w in windows if int(w['runtime_start'], 16) <= a and
               a+n <= int(w['runtime_start'], 16)+w['bytes']]
        assert out and all(x == out[0] for x in out), (hex(a), n)
        return out[0]

    def rows(lo, hi):
        out = {}
        for w in windows:
            for i in w['instructions']:
                a = int(i['address'], 16)
                if lo <= a < hi:
                    assert a not in out or out[a] == i
                    out[a] = i
        assert out
        return [out[a] for a in sorted(out)]

    def frag(a, n):
        return dict(start=hex(a), bytes=n, raw_hex=raw(a, n).hex(),
                    instructions=rows(a, a+n))

    inventory = raw(0xf00114, 99)
    assert inventory.index(0x4d) == 2 and inventory.index(0x31) == 1
    entries = raw(0x8dd22c, 272)
    assert entries[5*8:6*8] == bytes.fromhex('4d00000000000000')
    assert entries[27*8] == 0xff
    ops = list(struct.unpack('<9I', raw(0x8dd208, 36)))
    assert ops[2:5] == [0xfb589, 0xfb599, 0xfb5b7]
    assert raw(0x89e1fd, 3) == bytes.fromhex('104d01')
    witnesses = [
        dict(id='AP_selector_classification_in_actual_Map_load', entry='0x10fef8',
             observations=['0x1101FC/0x110208 call FE648 with selectors 31/4D and compare the returned inventory ordinal to the active ordinal.',
                           'The exact initialized inventory maps selector 4D to ordinal 2 and selector 31 to ordinal 1. Live inventory is unknown.'],
             fragments=[frag(0x1101fc, 38)],
             startup_inventory=inventory.hex(), registry_base='0x1286bcc',
             registry_stride=24,
             does_not_prove='AP filename opening, overlay priority, actual live inventory or renderer admission'),
        dict(id='Map_registry_retain_or_clear_branch',
             observations=['The linked record+6 u16 minimum is stored at SP+60; SP+6C is compared without a proven semantic name.',
                           'BHI at 110FF4 retains this ordinal. Otherwise the caller reads record+8/+C, calls unknown 10CC8E, then calls actual clear primitive 10DF5A.',
                           'The original CPU cases stop before 10CC8E or at the retain branch; they do not fake that callee.'],
             fragments=[frag(0x110f9e, 30), frag(0x110fee, 34)],
             unknown_fields=['record+6 meaning', 'SP+6C origin/meaning', 'record+8/+C object identity', '10CC8E effect'],
             does_not_prove='that v3 takes this branch, priority, checksum, physical offset guard or complete caller success'),
        dict(id='AP_filebacked_resource_dispatch_and_size_clamp',
             observations=['FB558 registers descriptor 02D144B4 in resource slot 3: entries 8DD22C, ops 8DD208, source RAM F08BC4.',
                           'Exact entry 8DD254 contains selector 4D. Ops+8 is FB589: it clears both output values and returns 11, an unsupported direct-view API.',
                           'Ops+0C FB599 calls 2D3380 with the selector and file-relative arguments. Ops+10 FB5B7 calls 2D30C4 and clamps a 64-bit size to FFFFFFFF.',
                           'This is a file-backed resource adapter; it is not the physical filename opener.'],
             fragments=[frag(0xfb558, 26), frag(0x26a2d0, 48),
                        frag(0xfb588, 12), frag(0xfb598, 30), frag(0xfb5b6, 44)],
             ops_words=[hex(x) for x in ops],
             selector_entry=dict(address='0x8dd254', raw_hex=entries[40:48].hex()),
             does_not_prove='live F08BC4 file handle binding, physical storage window or AP renderer acceptance'),
        dict(id='Actual_file_change_callback_to_mount_and_Map_reload_frontier',
             observations=['2DDD4C is an actual file-change callback entry. The generic selector path calls FE648 then FEA50 with argument 1.',
                           'The forced-selector-31 branch calls the same mount path and then 10CE3C, an unresolved Map reload frontier.',
                           'The generic path posts event 1<<17 through original 2FCF44. No callback registration/live delivery or 10CE3C-to-10FEF8 runtime execution is claimed.',
                           'The exact inventory entry at 89E1FD is 10 4D 01; the first/third byte meaning and physical filename construction are not closed.'],
             fragments=[frag(0x2dddd0, 30), frag(0x2ddeb2, 38), frag(0x2da6f2, 20)],
             selector_metadata=dict(address='0x89e1fd', raw_hex='104d01'),
             does_not_prove='complete AP opener, actual overlay decisions or runtime callback linkage'),
        dict(id='Original_Map_registry_clear_primitive',
             observations=['10DF5A clears three linked heads, registry+0C u16/+0E byte, two parallel pointer arrays and node first eight bytes.',
                           'The standalone original-instruction case verifies these writes and preserves node tail/other registry bytes.',
                           'It is tested as an independent call, not as an invented result of the unresolved preceding caller.'],
             fragments=[frag(0x10df5a, 94), frag(0x10dfb8, 4)],
             registry='0x1286bcc', parallel_arrays=['0x1287a3c', '0x1287bc8'],
             does_not_prove='a real AP registry deletion or its semantic policy')
    ]
    save('actual-call-chain-witnesses.json', dict(schema='bounded-original-ap-map-registry-witnesses/v1',
         witnesses=witnesses, witness_count=len(witnesses),
         all_instruction_bytes_from_this_scope_actual_MAIN_windows=True,
         startup_copy_mapping_used=True, complete_runtime_call_chain_executed=False))

    cpu_b = (HERE / 'registry-guard-pending-cpu-proof.json').read_bytes()
    cpu = json.loads(cpu_b)
    assert sha((HERE / 'run_registry_guard_pending_cases.py').read_bytes()) == cpu['source_sha256']
    assert cpu['case_count'] == 3 and cpu['all_passed'] and cpu['IMG_reads'] == 0
    assert sum(c['instruction_count'] for c in cpu['cases']) == 73
    assert cpu['semantic_hooks'] == []
    failure = json.loads((HERE / 'initial-guest-failure.json').read_bytes())
    initial = (HERE / 'run_registry_guards_initial_failure.py').read_bytes()
    assert sha(initial) == failure['source_sha256']
    assert initial == (HERE / 'run_registry_guards.py').read_bytes()
    for c in cpu['captures']:
        assert sha((ROOT / c['path']).read_bytes()) == c['sha256']

    receipts = dict(schema='actual-bounded-ap-map-registry-tool-receipts/v1',
        capture_tools=[dict(tag=tag, tool_chunk=chunk, exit_code=0) for tag, chunk in
            [('seeds','723a34'),('registry','055fc3'),('opener','07d749'),
             ('selectors','adf7f6'),('registrations','f0284f'),('driverdata','28b8dc'),
             ('apdescriptor','8557a6'),('exacttables','313efe'),('mapbind','19e22d'),
             ('filechange','96f037'),('physicalbind','485efb'),('cpuguard','23e62c'),
             ('exactguards','f945df')]],
        capture_source_revision_note='Initial helper restored byte for byte from its later source by reverting DATA support; SHA exactly matches each earlier capture. The original MAIN windows were not reread.',
        initial_guest=dict(tool_chunk='f04ace', exit_code=1, source_sha256=sha(initial),
            receipt='initial-guest-failure.json', guest_error='UC_ERR_READ_UNMAPPED',
            prior_four_classifier_assertions='partial only; per-case traces not durably saved; not replayed',
            last_guest_PC_or_fault_address='not recorded; exact missing fixture address is not claimed',
            IMG_opened=False),
        completed_pending_guest=dict(tool_chunk='2e629c', exit_code=0,
            source_sha256=cpu['source_sha256'], proof_sha256=sha(cpu_b),
            durable_cases=3, original_executed_instructions=73, IMG_reads=0,
            semantic_hooks=[], replayed_initial_classifier_cases=False),
        original_MAIN_reads=dict(bytes=ledger['bytes'], operations=ledger['operations'],
            whole_file_read_or_hash=False, stat_before=ledger['MAIN_stat'],
            stat_after=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin'),
            inherited_SHA='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'),
        IMG_reads=dict(v2=0, v3_8K=0, expanded4K_disabled=0),
        no_device_operations=True, old_reader15_and_mount3_cases_not_rerun=True,
        all_scope_handles_closed=True)
    save('actual-tool-receipts.json', receipts)
    proof = dict(schema='bounded-ap-map-registry-consumer-review/v1',
        scope='NEW readonly original Map registry/resource adapter windows and finite guards',
        source_sha256=sha(Path(__file__).read_bytes()), captures=captures,
        witness_sha256=sha((HERE/'actual-call-chain-witnesses.json').read_bytes()),
        guest_proof_sha256=sha(cpu_b), receipts_sha256=sha((HERE/'actual-tool-receipts.json').read_bytes()),
        assigned_bounded_checks_passed=True, durable_original_guest_cases=3,
        original_guest_instructions=73, source_stats_stable=True,
        limits=dict(MAIN_read_limit=65536, actual_MAIN_reads=17134,
                    each_IMG_metadata_limit=131072, actual_IMG_reads=0),
        fixtures=['synthetic guest stack threshold/minimum/ordinal',
                  'synthetic three-head linked registry and record+8/+C payload values',
                  'exact file-backed initialized inventory bytes; live inventory unknown',
                  'observer stops before unknown 10CC8E, retain destination or independent return sentinel'],
        new_partial_failure_preserved=True,
        claim_corrections=[
            'Capture name AP_filename_selector_resolver at 26A2D0 was a hypothesis. It is actual resource direct-view dispatch, not a filename resolver.',
            'Capture name AP_selector_file_driver_initializer starts at FB572, a BX LR no-op. Actual registration is FB558 reached through FB594.',
            'Capture name file_slot_state_activation at 2DA6F2 is not established file activation: original code forwards mode 1/2 and selector to unknown 214AF6.',
            'Capture name file_slot_pointer_provider at 2DAAF4 does not establish a file pointer provider.',
            'Guest case name registry_drop_guard means only the drop-side branch reaches the stop before 10CC8E; it does not complete the caller or delete registry entries.',
            'Four initial classifier assertions are partial results without durable traces, not additional completed proof cases.'
        ],
        physical_128MiB_hypothesis=dict(status='unresolved',
            verified_size_guard='FB5CE..FB5D8 clamps a 64-bit result to FFFFFFFF, not a demonstrated 08000000 window.',
            registry_guard_operands='u16 record+6-derived minimum and unbound SP+6C; not physical component offsets.',
            absence_of_guard_not_claimed=True,
            lower_storage_cache_mount_or_resource_window_not_excluded=True),
        remaining_blockers=[
            'Actual AP physical filename constructor/caller into generic 2D3166 is unbound.',
            'Live F08BC4 file-handle construction, callback delivery and live volume inventory are unobserved.',
            'Unknown 10CC8E and 10E328, record+6 semantics and SP+6C origin prevent semantic admission-policy interpretation.',
            '10CE3C is a bounded Map reload frontier; downstream actual overlay/display policy is not closed.',
            'Neither v3 nor expanded4K failing physical component position is bound to a real failing guard.'
        ],
        minimal_next_entries=[
            dict(entry='0x10cc8e', caller='0x111004', bytes='fbf743fe',
                 arguments='r0=record+8, r1=record+0C, r2=0; real object semantics remain unknown'),
            dict(entry='0x10e328', caller='0x110fd4', bytes='fdf7a8f9',
                 purpose='matched metadata consumer affects SP+60'),
            dict(entry='0x10ce3c', caller='0x2ddde8', bytes='2ff628f8',
                 purpose='actual file-change-to-Map-reload frontier; not a claimed full call-chain')],
        AP_physical_opener_proved=False, real_overlay_policy_proved=False,
        v3_road_regression_rootcause_proved=False, renderer_or_device_success=False,
        shared_or_sealed_inputs_modified=False, install_candidate_created=False,
        full_address_update_completed=False, all_scope_handles_closed=True)
    save('proof.json', proof)
    print(json.dumps(dict(bounded_audit_passed=True, MAIN_bytes=ledger['bytes'],
        MAIN_operations=ledger['operations'], IMG_bytes=0, durable_guest_cases=3,
        original_guest_instructions=73, witnesses=len(witnesses), handles_closed=True)))


if __name__ == '__main__':
    main()
