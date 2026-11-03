#!/usr/bin/env python3
"""Finite static lineage audit. Opens only pinned small evidence files, never IMG/MAIN."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def save(n, d):
    p = HERE / n
    assert not p.exists(), n
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n')

def main():
    pins = json.loads((HERE / 'input-bindings.json').read_bytes())
    additions = [
        'staging/navigation-native-ap-sector-reader-matrix-v1/sealed-files.json',
        'staging/navigation-native-ap-sector-reader-matrix-v1/windows-lower.json',
        'staging/navigation-native-ap-sector-reader-matrix-v1/windows-ops.json',
        'staging/navigation-native-ap-sector-reader-matrix-v1/windows-callbacks.json',
    ]
    extra = []
    for n in additions:
        p = ROOT / n
        before = stat(p)
        b = p.read_bytes()
        assert stat(p) == before
        extra.append(dict(path=n, bytes=len(b), sha256=sha(b), stat=before, mode=oct(p.stat().st_mode & 0o777)))
    save('additional-input-bindings.json', dict(schema='reused-sealed-static-matrix-windows/v1',
         files=extra, old_probe_or_suite_executed=False, source_only=True))
    rows = pins['files'] + extra
    checked = []
    documents = {}
    for row in rows:
        p = ROOT / row['path']
        assert stat(p) == row['stat'], row['path']
        b = p.read_bytes()
        assert len(b) == row['bytes'] and sha(b) == row['sha256'], row['path']
        assert stat(p) == row['stat']
        checked.append(row['path'])
        if p.name.startswith('windows-') or p.name == 'reused-primary-functions.json':
            documents[row['path']] = json.loads(b)
    ledger = json.loads((HERE / 'read-ledger.json').read_bytes())
    mainpath = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
    assert stat(mainpath) == ledger['MAIN_stat']  # stat only, no MAIN open
    for batch in ledger['batches']:
        b = (ROOT / batch['path']).read_bytes()
        assert sha(b) == batch['sha256']
        documents[batch['path']] = json.loads(b)
    assert ledger['bytes'] == 2260 and ledger['bytes'] <= 24576
    assert sum(d['explicit_read_bytes'] for p, d in documents.items() if p.startswith(str(HERE.relative_to(ROOT)))) == ledger['bytes']
    assert sum(d['explicit_read_operations'] for p, d in documents.items() if p.startswith(str(HERE.relative_to(ROOT)))) == ledger['operations']

    def inst(suffix, address):
        matches = []
        for name, d in documents.items():
            if not name.endswith(suffix):
                continue
            for w in d.get('windows', []):
                for i in w['instructions']:
                    if int(i['address'], 16) == address:
                        raw = bytes.fromhex(w['raw_hex'])
                        off = address - int(w['runtime_start'], 16)
                        ib = bytes.fromhex(i['bytes'])
                        assert raw[off:off + len(ib)] == ib
                        matches.append(dict(source_path=name, source_window=w['name'], instruction=i))
            for f in d.get('functions', {}).values():
                for i in f['instructions']:
                    if int(i['address'], 16) == address:
                        matches.append(dict(source_path=name, inherited_original_instruction=i))
        assert len(matches) == 1, (suffix, hex(address), len(matches))
        return matches[0]

    def get(suffix, addresses):
        return [inst(suffix, a) for a in addresses]

    witnesses = []
    def witness(n, meaning, parts, caveat):
        witnesses.append(dict(number=n, meaning=meaning, exact_instructions=parts, limit=caveat))

    table = next(w for w in documents['staging/navigation-native-ap-map-registry-consumer-v1/windows-cpuguard.json']['windows']
                 if w['runtime_start'] == '0xf00114')
    assert bytes.fromhex(table['raw_hex'])[:4] == bytes.fromhex('03314d15')
    witness(1, 'True selector 4D metadata caller, followed by selector-to-slot lookup: startup slot 2 contains 4D.',
      get('ap-mount-registry-binding-v1/windows-targets.json', [0x167272, 0x167274, 0x167276, 0x16727a]) +
      get('ap-mount-registry-binding-v1/windows-parser.json', [0x167152, 0x167154]) +
      get('ap-mount-registry-binding-v1/windows-dependencies.json', [0x1188c2, 0x1188c4, 0x1188c8, 0x1188ca]) +
      get('ap-map-registry-consumer-v1/windows-seeds.json', [0xfe668, 0xfe66a, 0xfe66c, 0xfe66e, 0xfe670]),
      'Startup initialized bytes are evidence, not a live registry snapshot. Selector 4D, query slot 2, embedded IMG volume ordinal and storage partition ordinal are separate domains.')
    witnesses[-1]['data'] = dict(source_path='staging/navigation-native-ap-map-registry-consumer-v1/windows-cpuguard.json',
         runtime='0xf00114', startup_load='0xcb1a94', startup_file_offset='0xc61a94', first_four_bytes='03314d15',
         mode='DATA', slot2_selector='0x4d')

    witness(2, 'Actual selector/slot reader reverses slot lookup before calling mapped-region reader; resource driver independently supplies entry byte 4D.',
      get('ap-mount-registry-binding-v1/windows-mountmem.json', [0x1186bc, 0x1186d6, 0x1186d8, 0x1186da, 0x1186de]) +
      get('ap-mount-registry-binding-v1/windows-consumer.json', [0xfe8ec, 0xfe8f0, 0xfe8f4, 0xfe8f6, 0xfe966, 0xfe968, 0xfe96a, 0xfe96c, 0xfe96e]) +
      get('ap-map-registry-consumer-v1/windows-registrations.json', [0xfb59a, 0xfb5a0, 0xfb5a4, 0xfb5a6]),
      'For unchanged startup table, AP slot 2 uses region 4D, not old matrix fixture region 63. This scope reruns none of that matrix. Resource descriptor registration does not itself identify the physical filename/drive.')
    witnesses[-1]['resource_entry_data'] = dict(source_path='staging/navigation-native-ap-map-registry-consumer-v1/windows-exacttables.json',
         runtime='0x8dd254', bytes='4d00000000000000')

    witness(3, 'Mapped region reads inventory+1C FILE handle; generic producer takes incoming filename and writes this output slot.',
      get('ap-sector-reader-matrix-v1/windows-lower.json', [0x2d3384, 0x2d3386, 0x2d3388, 0x2d3390, 0x2d3394, 0x2d3396, 0x2d3398, 0x2d339a, 0x2d339c, 0x2d33b0, 0x2d33d8, 0x2d33da, 0x2d33ec, 0x2d33f0]) +
      get('ap-map-registry-consumer-v1/windows-physicalbind.json', [0x2d3166, 0x2d316a, 0x2d316e, 0x2d3174, 0x2d3176, 0x2d31bc, 0x2d31ca, 0x2d31d2, 0x2d31d4, 0x2d31d6, 0x2d31d8]),
      'Inventory index J is byte1 of 105E424[2*region]; 36-byte inventory at105E624 is not the 64-byte drive array. No actual AP filename caller to 2D3166 has been recovered in these pinned windows; no global absence claim.')
    witnesses[-1]['ABI'] = dict(generic_producer='r0 flags; r1 mapped-region selector; r2 incoming UTF16 filename',
         open='31D09A(r0 filename, r1 flags23/21, r2 &inventory[J]+1C)',
         AP_incoming_filename=None, AP_inventory_J=None)

    witness(4, 'Generic FILE opener parses a path ordinal, selects real drive array and passes drive to fileops open; type1 constructs child+2C with that drive. FILE reads dispatch through child+2C then drive+18/fileops+8.',
      get('ap-mount-registry-binding-v1/windows-dependencies.json', [0x31d0a6, 0x31d0c4, 0x31d0c8, 0x31d0ca, 0x31d0cc, 0x31d0ce, 0x31d0dc]) +
      get('AP-opener-drive-lineage-v1/windows-FILEdrive.json', [0x31d06e, 0x31d072, 0x31d076, 0x31d084, 0x31d088, 0x31d090, 0x31d092, 0x31d094, 0x1fdc16, 0x1fdc1a, 0x1fdcb0, 0x1fdcb4, 0x1fdcb8]) +
      get('AP-opener-drive-lineage-v1/windows-drivegetter.json', [0x24e790, 0x24e792, 0x24e794, 0x24e796, 0x24e79c, 0x24e79e, 0x24e7a0]) +
      get('ap-mount-registry-binding-v1/windows-type1read.json', [0x3a0e32, 0x3a0ece, 0x3a0ed2]) +
      get('ap-sector-reader-matrix-v1/windows-ops.json', [0x31cf50, 0x31cf52, 0x31cf54, 0x31cf56]) +
      get('ap-sector-reader-matrix-v1/windows-callbacks.json', [0x1fde78, 0x1fde7c, 0x1fde80, 0x1fde82, 0x1fde86]),
      'The true AP incoming path and returned drive ordinal/type are missing. Path helpers282564/2734DA are not executed here. The conditional type1 opener and read ABI are actual code, not a live AP FILE binding.')
    witnesses[-1]['fileops_data'] = dict(source_path='staging/navigation-native-ap-mount-registry-binding-v1/windows-targets.json',
         runtime='0x86df84', bytes='2d133a00', little_endian_function_pointer='0x3a132d')

    witness(5, 'Previously sealed production registration uses the same F001A8 drive array: drive+20 receives supplied lowerops; storage producer supplies context+64 and lowerops+8 becomes3FEA37.',
      get('production-block-read-binding-v1/reused-primary-functions.json', [0x24e83e, 0x24e8a0, 0x3fe82e, 0x3fe830]) +
      get('production-block-read-binding-v1/windows-callbacks.json', [0x3feb40]) +
      get('ap-mount-registry-binding-v1/windows-type1read.json', [0x3a1456, 0x3a1464, 0x3a1472, 0x3a1474, 0x3a1476, 0x3a1478, 0x3a147e]),
      'This is a conditional shared-drive bridge only. AP is not proven to choose this live drive, partition ordinal or callback.3FEA36 is not proven to be the physical AP path. No board/MMIO/DMA or original callback result is executed or fabricated.')
    assert len(witnesses) == 5
    # Verify data claims against raw bytes instead of labels or linear DATA disassembly.
    for claim in [witnesses[1]['resource_entry_data'], witnesses[3]['fileops_data']]:
        d = documents[claim['source_path']]
        a = int(claim['runtime'], 16)
        good = []
        for w in d['windows']:
            start = int(w['runtime_start'], 16)
            raw = bytes.fromhex(w['raw_hex'])
            if start <= a and a + len(bytes.fromhex(claim['bytes'])) <= start + len(raw):
                good.append(raw[a-start:a-start+len(bytes.fromhex(claim['bytes']))].hex() == claim['bytes'])
        assert good and all(good), claim
    save('five-exact-witnesses.json', dict(schema='static-AP-opener-FILE-drive-lineage-witnesses/v1', witnesses=witnesses,
         CPU_executed=False, comments_do_not_change_original_bytes=True))
    graph = dict(schema='static-AP-to-production-drive-lineage/v1',
      exact_static_chain=['167272 selector4D ->16727A/16713A ->1188B6 ->FE648 ->startup slot2',
       '1186B8 slot ->FE8E8 startup selector4D ->2D3380',
       '2D3380 ->mapped pair105E424[2*4D] ->J ->inventory105E624+36*J ->FILE at+1C',
       'generic2D3166 incoming filename ->31D09A ->31D032 path ordinal ->1FDC0C ->24E790 F001A8 drive array',
       'type1 open child+2C=drive; read1FDE12 ->drive+18 fileops+8 ->conditional3A132D',
       'registered production drive+20=context+64; lowerops+8=3FEA37'],
      missing_edges=[dict(from_node='true physical AP gmapprom1.img filename/volume opener', to_node='2D3166 or other actual mapping producer',
        missing='actual caller/setup showing selector4D with exact original AP UTF16 path'),
       dict(from_node='AP inventory FILE', to_node='specific live F001A8 drive entry',
        missing='AP actual path ordinal, drive type, initialized mount registration and current lowerops pointer'),
       dict(from_node='shared drive array', to_node='AP production partition/storage context',
        missing='live partition/storage mapping and callback selection; no slot/ordinal identity assumption')],
      domain_separation=['selector0x4D','query slot2','mapped inventory indexJ','embedded IMG volume ordinal','FILE path drive ordinal','storage partition ordinal','physical storage ID'],
      AP_opener_to_production_storage_closed=False,
      minimum_next_step='Find the real AP filename builder/caller to mapped-region installation, with register setup showing selector4D and exact UTF16 path. Then bind returned drive ordinal through24E790; do not infer it from query slot2. No generic driver case is needed again.')
    save('source-lineage.json', graph)
    errata = [
      dict(affected='new windows-APinventory.json heuristic names', correction='2D40FC is table comparator/index search, not FILE constructor.11215E calls111E0A notification wrapper, not filename resource provider. The original raw windows remain preserved.'),
      dict(affected='new windows-APsource.json heuristic literal_AP_selector_resource_consumer', correction='111E0A packages notification/event arguments and calls3CC594; it does not produce an AP filename. Not used as opener evidence.'),
      dict(affected='intermediate startup-table transcription', correction='Actual first bytes are03 31 4D 15; any33 wording is erroneous. Slot2=4D unchanged.'),
      dict(affected='prior matrix linkage inference', correction='Old matrix explicitly supplies region63; current static AP startup route reverses slot2 to region4D. Old finite matrix result remains valid within its synthetic region63 fixture; it is not live physical AP lineage.'),
      dict(affected='linear saved disassembly and function labels', correction='Only selected raw-backed instructions/data above support claims. Captures extending into next functions/literal pools do not establish reachable calls.')]
    save('errata.json', dict(schema='current-finite-static-lineage-errata/v1', entries=errata, prior_sealed_evidence_modified=False))
    save('audit.json', dict(schema='finite-static-source-audit/v1', all_assigned_static_checks_passed=True,
      input_files_verified=len(rows), verified_files=checked,
      exact_witness_count=len(witnesses), raw_backed_instruction_count=sum(len(w['exact_instructions']) for w in witnesses),
      startup_copy_used_for_DATA=True, source_stat_stable=True, MAIN_stat_only_after_capture=True,
      capture_batches=len(ledger['batches']), new_MAIN_bytes=ledger['bytes'], new_MAIN_operations=ledger['operations'],
      new_MAIN_limit=24576, IMG_read_bytes=0, CPU_cases=0, all_handles_closed=True,
      no_old_suite_execution=True, no_whole_MAIN_or_IMG_hash=True))
    save('proof.json', dict(schema='finite-AP-opener-drive-lineage-summary/v1', all_assigned_checks_passed=True,
      result='partial static FILE/drive ABI recovered; actual AP filename-to-live-drive edge remains unbound',
      actual_lineage_closed=False, five_witnesses_sha256=sha((HERE/'five-exact-witnesses.json').read_bytes()),
      source_lineage_sha256=sha((HERE/'source-lineage.json').read_bytes()), audit_sha256=sha((HERE/'audit.json').read_bytes()),
      new_MAIN_read_bytes=ledger['bytes'], new_MAIN_read_operations=ledger['operations'], new_MAIN_max=24576,
      IMG_read_bytes=0, CPU_cases=0, old_suite_reruns=0,
      startup_selector2='0x4d', AP_live_FILE_drive_binding=None,
      physical_AP_read_callback_proven=False, live_policy_proven=False,
      v3_regression_root_cause_proven=False, real_128MiB_guard_proven=False,
      renderer_or_admission_success=False, fixed_or_installable=False,
      metadata_or_IMG_or_MAIN_mutations=False, shared_sealed_inputs_modified=False,
      device_or_audio_or_license_token_access=False, handles_closed=True,
      limits=graph['missing_edges'], errata_file='errata.json'))
    (HERE/'HANDOFF.txt').write_text('Finite static AP opener / production drive lineage, no CPU or IMG reads.\n\n'
      'Five raw-backed witnesses recover AP selector4D -> startup slot2 -> reader selector4D -> mapped inventory FILE+1C.\n'
      'Generic FILE path parsing then uses an independent path drive ordinal,24E790 selects F001A8+4 base + ordinal*64,\n'
      'and type1 opener stores the passed drive at child+2C. Reads reach drive+18/fileops+8.\n'
      'Previously sealed production registration writes lowerops at drive+20 in the same drive array.\n\n'
      'Missing: exact AP filename caller/setup creating this mapped FILE and selecting a live drive/type/partition.\n'
      'Therefore3FEA36 is not proven to be physical AP. AP slot2 does not imply partition ordinal2 or<2.\n'
      'Old matrix region63 was explicit fixture; startup AP slot2 reverses to region4D. No old case rerun.\n'
      '2D40FC comparator and11215E/111E0A notifier are excluded opener hypotheses; see preserved raw captures/errata.\n\n'
      'Fresh MAIN2260 B /24KiB maximum; IMG0; CPU0. No full hashes, shared evidence/device/report changes.\n'
      'Next smallest entry: exact AP UTF16 path producer/caller into2D3166 (or another actual installer) and\n'
      'register setup containing selector4D; then bind returned path ordinal through24E790. Live policy remains unknown.\n'
      'No renderer/admission success,128MiB root cause,v3 fix or installability is claimed. Handles closed.\n')
    print(json.dumps(dict(result='PASS finite static audit with explicit missing AP edge', witnesses=5,
      input_files=len(rows), MAIN_bytes=ledger['bytes'], IMG_bytes=0, CPU_cases=0,
      proof_sha256=sha((HERE/'proof.json').read_bytes()), handles_closed=True)))

if __name__ == '__main__':
    main()
