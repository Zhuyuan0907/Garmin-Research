#!/usr/bin/env python3
"""Audit finite original AP metadata/path fragments without any guest or IMG access."""
from pathlib import Path
import hashlib
import json

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def save(n, d):
    assert not (HERE/n).exists(), n
    (HERE/n).write_text(json.dumps(d, ensure_ascii=False, indent=2)+'\n')

def main():
    pins = json.loads((HERE/'input-bindings.json').read_bytes())
    docs = {}
    for row in pins['files']:
        p = ROOT/row['path']
        assert stat(p) == row['stat']
        b = p.read_bytes()
        assert sha(b) == row['sha256'] and len(b) == row['bytes']
        assert stat(p) == row['stat']
        docs[row['path']] = json.loads(b)
    ledger = json.loads((HERE/'read-ledger.json').read_bytes())
    assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin') == ledger['MAIN_stat']
    assert ledger['bytes'] == 5434 and ledger['bytes'] <= 24576
    windows = []
    for row in ledger['batches']:
        p = ROOT/row['path']
        b = p.read_bytes()
        assert sha(b) == row['sha256']
        d = json.loads(b)
        assert d['handles_closed'] and not d['CPU_executed'] and not d['device_or_IMG_access']
        docs[row['path']] = d
        for w in d['windows']:
            raw = bytes.fromhex(w['raw_hex'])
            assert len(raw) == w['bytes'] and sha(raw) == w['sha256']
            windows.append((row['path'], w))
    assert sum(d['explicit_read_bytes'] for n,d in docs.items() if n.startswith(str(HERE.relative_to(ROOT))+'/windows-')) == ledger['bytes']

    def inst(a):
        matches = []
        for p,w in windows:
            for i in w['instructions']:
                if int(i['address'],16) == a:
                    raw = bytes.fromhex(w['raw_hex'])
                    ib = bytes.fromhex(i['bytes'])
                    off = a-int(w['runtime_start'],16)
                    assert raw[off:off+len(ib)] == ib
                    matches.append(dict(source_path=p, original_instruction=i))
        # APliteral and APpathliteral overlap on52 bytes; these bytes must agree.
        assert matches, hex(a)
        assert len(set(m['original_instruction']['bytes'] for m in matches)) == 1
        return matches[0]

    def get(addresses):
        return [inst(a) for a in addresses]

    def data(a,n,expected):
        matches = []
        for p,w in windows:
            start = int(w['runtime_start'],16)
            raw = bytes.fromhex(w['raw_hex'])
            if start <= a and a+n <= start+len(raw):
                b = raw[a-start:a-start+n]
                assert b == expected
                matches.append(dict(source_path=p, runtime=hex(a), bytes=b.hex(), interpret_as='DATA'))
        assert matches, hex(a)
        return matches[0]

    aptext = 'gmapprom1.img\0'.encode('utf-16le')
    apname = data(0x3a77f0,len(aptext),aptext)
    base = data(0x3a671c,20,'/.System/\0'.encode('utf-16le'))
    fmt = data(0x3a6244,6,'%s\0'.encode('utf-16le'))
    producer = get([0x1d8514,0x1d8518,0x1d851a,0x1d851e,0x1d8520,0x1d8522,0x1d8524,0x1d8526,0x1d8528])
    # New actual bytes independently agree with two old bounded original captures.
    oldpaths = ['staging/native-player-settings-vfp-context/acceptance-static/bounded-functions.json',
                'staging/native-player-heap-settings-boot/package-static/bounded-functions.json']
    equality = []
    for path in oldpaths:
        old = {int(i['address'],16):i for i in docs[path]['functions']['0x1d8514']['instructions']}
        for claim in producer:
            i = claim['original_instruction']
            assert old[int(i['address'],16)]['bytes'] == i['bytes']
        equality.append(dict(path=path, selected_original_byte_anchors_equal=len(producer)))

    # These are only20 calculated stride positions inside a small copied-data window.
    # No original descriptor declares20 records; do not extend array semantics beyond known bytes.
    table = next(w for p,w in windows if w['name']=='startup_small_filename_selector_inventory_DATA')
    raw = bytes.fromhex(table['raw_hex'])
    probe_bytes = [raw[i*42+40] for i in range(20)]
    assert probe_bytes[0] == 0x13 and 0x4d not in probe_bytes
    save('bounded-selector-observation.json', dict(schema='small-stride-candidate-position-observation/v1',
      runtime_start='0xf09638', startup_copy_mapping=True,
      count_is_probe_positions_not_declared_record_count=20, stride_from_original_code=42,
      selector_relative_offset=40, first_position_selector='0x13',
      AP_selector4D_positions=[], original_array_extent_unknown=True,
      other_positions_not_interpreted_as_valid_records=True,
      no_claim_about_live_mutated_inventory=True, no_non_map_names_or_private_data_decoded=True))

    inherited = docs['staging/navigation-native-AP-opener-drive-lineage-v1/five-exact-witnesses.json']
    old_mapping = next(w for w in inherited['witnesses'] if w['number']==3)
    wanted = {0x2d31d2,0x2d31d4,0x2d31d6,0x2d31d8}
    mapping = [r for r in old_mapping['exact_instructions'] if int(r.get('instruction',{}).get('address','0'),16) in wanted]
    assert len(mapping) == 4
    witnesses = [
      dict(number=1, finding='A real generic direct filename-mapping caller exists:1D8528 ->2D3166.',
        exact_instructions=producer,
        ABI='incoming r0 filename ->r2; incoming r1 index ->F09638+index*42+0x28 selector ->r1; flags r0=0',
        limit='No actual AP index/live selector4D setup in this caller is established. Startup candidate byte0=13 is not AP. This is not a physical AP witness by itself.'),
      dict(number=2, finding='A true selector4D branch supplies the original AP basename and system-directory text to3A5F3E.',
        exact_instructions=get([0x3a7436,0x3a7438,0x3a743a,0x3a743e,0x3a7442,0x3a7444,
          0x3a7446,0x3a7448,0x3a744a,0x3a744c,0x3a744e,0x3a7450,0x3a7452,0x3a7454,0x3a7456]),
        general_path_data=[apname,base],
        limit='3A743E metadata helper is a stop boundary. Its authorization-related internals are not analyzed or executed. This actual branch does not call2D3166 or open a FILE.'),
      dict(number=3, finding='3A5F3E emits base-text and AP basename separately through1D5248; it does not assemble a mounted AP FILE.',
        exact_instructions=get([0x3a5f3e,0x3a5f42,0x3a5f44,0x3a5f48,0x3a5f5c,0x3a5f5e,
          0x3a5f74,0x3a5f78,0x3a5fea,0x3a5fee,0x3a5ff2,0x3a5ff4,0x3a5ff6,0x3a5ff8,0x3a5ffa,0x3a5ffc,
          0x3a6004,0x3a6006,0x3a6008,0x3a600a,0x3a600c,0x3a600e,0x3a6018,0x3a601a]),
        string_format=fmt, named_field_codes=dict(base_text='0x09',basename='0x0b'),
        limit='Base text passes through3A5EFA before field09. Do not claim full drive-prefixed path or a particular XML schema/key name from numerical field codes.3A671C is text data, not a callback.'),
      dict(number=4, finding='The common field emitter1D5248 selects the field and formats supplied text into its context buffer.',
        exact_instructions=get([0x1d5248,0x1d524a,0x1d524e,0x1d5250,0x1d5256,0x1d5266,
          0x1d5272,0x1d5274,0x1d5276,0x1d527e,0x1d5280,0x1d5282,0x1d5284,0x1d5286,0x1d528a,0x1d528c,0x1d528e]),
        limit='Static1D51A6/387218/1D4F52 boundaries identify field/format/buffer path only. No2D3166/31D09A mapping operation is in this selected fragment. Downstream consumer and whole object format remain unbound.'),
      dict(number=5, finding='Real mapped-file setter passes incoming filename to31D09A output inventory+1C, unlike named-field emission.',
        inherited_exact_instructions=mapping,
        source_path='staging/navigation-native-AP-opener-drive-lineage-v1/five-exact-witnesses.json',
        limit='The actual generic1D8528 caller connects here. The actual AP basename/base-text metadata branch still has no recovered caller edge here. Slot2 is not drive/partition ordinal.')]
    assert len(witnesses) == 5
    save('five-exact-witnesses.json', dict(schema='bounded-static-AP-path-producer-witnesses/v1',
      witnesses=witnesses, CPU_not_executed=True, private_or_license_values_not_used=True))

    # Cache-only direct-call inventory, no broad MAIN scan. Capstone instruction metadata
    # is a candidate inventory; fresh code confirms1D8528, not every cached function.
    cached = []
    for path in oldpaths:
        for f, row in docs[path]['functions'].items():
            for i in row['instructions']:
                if i.get('direct_call') == '0x2d3166':
                    cached.append(dict(source_path=path,function=f,address=i['address'],bytes=i['bytes'],target='0x2d3166'))
    assert set(r['address'] for r in cached) == {'0x1d8528'}
    save('bounded-direct-caller-inventory.json', dict(schema='saved-small-source-direct-call-inventory/v1',
      searched_saved_files=oldpaths, actual_results=cached,
      fresh_original_caller_bytes_confirmed=True, instruction_anchor_equality=equality,
      fresh_named_AP_fragments_have_no_direct2D3166_edge=True,
      no_global_direct_or_indirect_caller_absence_claim=True, no_whole_MAIN_search=True,
      distinction='real mapper1D8528 confirmed; AP named-field emission separately confirmed; connection missing'))
    errata = [
      dict(affected='new window AP_named_object_callback_frontier',
        correction='3A671C raw bytes are UTF16 /.System/, not a function/callback. Its Thumb linear disassembly is excluded. Original capture retained unchanged.'),
      dict(affected='20-entry wording in progress message',
        correction='20 are calculated candidate stride positions in840 copied-data bytes; no original declared20-record extent is known. Onlyfirst selector13 and no4D at those positions are observed. Adjacent bytes may belong to other data.'),
      dict(affected='path producer vs physical opener',
        correction='Actual AP branch emits general base-directory text and basename in separate fields. No drive prefix, full concatenated AP path, FILE handle or mapped-volume producer is established.'),
      dict(affected='captured nearby code outside exact fragments',
        correction='Authorization-related metadata internals and incidental next functions/data are not analyzed, executed or used as witnesses. No token/UNL/device identifier is read or disclosed.')]
    save('errata.json', dict(schema='AP-path-static-interpretation-errata/v1',entries=errata,shared_seals_unchanged=True))
    missing = [
      'Actual AP path/selector4D mapping setup into2D3166 (or another true mapped FILE installer).',
      'An AP-specific caller supplying1D8514 index with actual selector4D, if this generic mapper is applicable at all.',
      'Consumer of named fields09/0B and exact general path-to-live drive/FILE handoff.',
      'Live inventory contents, drive ordinal/type, partition/storage context and lowerops choice.']
    save('proof.json', dict(schema='finite-static-AP-path-producer-summary/v1',all_assigned_checks_passed=True,
      result='AP general path text/basename field producer and real generic mapper identified separately; physical AP mapping edge missing',
      exact_witness_count=5, new_MAIN_read_bytes=ledger['bytes'], new_MAIN_read_operations=ledger['operations'],new_MAIN_max=24576,
      MAIN_identity_inherited='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8',
      MAIN_full_hash_recomputed=False,IMG_read_bytes=0,CPU_cases=0,old_suite_reruns=0,
      real_generic_mapper_caller='0x1d8528',actual_AP_general_basename='gmapprom1.img',actual_general_base_directory='/.System/',
      AP_UTF16_drive_prefixed_path_produced=False,AP_filename_to_mapping_caller_closed=False,
      AP_live_drive_or_partition_bound=False, root_cause_proven=False,
      renderer_admission_or_v3fix_proven=False,installable=False,
      license_token_or_UNL_research=False,device_id_or_unlock_data_used=False,
      input_files_stat_sha_stable=True,input_files_verified=len(pins['files']),
      windows_sha_raw_bytes_verified=True,handles_closed=True,shared_sealed_inputs_mutated=False,
      no_report_device_firmware_or_audio_access=True,
      five_witnesses_sha256=sha((HERE/'five-exact-witnesses.json').read_bytes()),
      direct_caller_inventory_sha256=sha((HERE/'bounded-direct-caller-inventory.json').read_bytes()),
      missing_edges=missing,
      minimal_next_entry='AP-specific general filename mapping registration caller/setup; current exact1D8528 caller has selector fromF09638+index*42+28, but no AP4D index/source. Named fields09/0B downstream consumer is a separate candidate, not proof of its use by AP mount. No generic CPU rerun or authorization path continuation is justified.'))
    (HERE/'HANDOFF.txt').write_text('Finite static AP path producer scope; no CPU / IMG / device work.\n\n'
      'Real generic caller1D8528->2D3166 is newly original-byte confirmed. It forwards filename r0->r2,\n'
      'flags0, and selector fromF09638+index*42+28. AP selector/index is not bound. Startup firstcandidate selector13;\n'
      '20 calculated positions in840 bytes have no4D, with actual array extent/live mutation unknown.\n\n'
      'Actual AP selector4D branch3A7436 ->3A7446 basename3A77F0 gmapprom1.img plus\n'
      '3A7448 data pointer3A671C /.System/ ->3A7456/3A5F3E. The latter emits base-text through\n'
      'field09 and basename throughfield0B to1D5248 with UTF16 format%s.3A671C is data, notcallback.\n'
      'This produces general filename metadata; no full drive-prefixed path, physical FILE or mapped-volume setup.\n'
      'The metadata helper3A72F2 and authorization-related internals are excluded stop points.\n\n'
      'Missing actual AP caller/setup into2D3166, actual index/selector4D if1D8514 applies,\n'
      'namedfield consumer-to-FILE connection and live drive/partition/lowerops. Slot2 is not a storage ordinal.\n'
      'Five exact witnesses; newMAIN5434B/24KiB maximum; IMG0; CPU0; oldcases0.\n'
      'No global xref absence claim, renderer/admission success,128MiB guard/rootcause,v3fix or installability.\n'
      'All handles closed; oldsealed sources/report/device untouched. Stop at this bounded gap.\n')
    print(json.dumps(dict(result='PASS finite static observations, physical AP edge remains missing',
      proof_sha256=sha((HERE/'proof.json').read_bytes()),MAIN_bytes=ledger['bytes'],
      new_MAIN_operations=ledger['operations'],IMG_bytes=0,CPU_cases=0,witnesses=5,handles_closed=True)))

if __name__ == '__main__':
    main()
