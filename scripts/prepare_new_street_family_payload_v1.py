"""Finite source-bound family payloads, not an MDR/IMG writer or installer.

Use current v3 L3 records, not stale stock street child ranges. The supplied
SQLite family is a partial sandbox; prefix/segments and full UI remain open.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-native-new-street-family-payload-v1'
PINS = {
    'staging/navigation-native-new-street-source-example-v1/candidate.json':
        'd26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c',
    'staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json':
        '929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6',
    'staging/navigation-country-native-lane-candidate-v3/actual-output-layout.json':
        '4abdc75c4af78dbfcdae421d68e838042e1756f978bff0f342c793bc4d411a9a',
    'staging/navigation-country-native-lane-cpu-v3/strict_ap8k_reader.py':
        'fe76a3b33b361d02518f7045b8437db9819b34dffeafd77a0bfb9058af1100ec',
    'staging/navigation-native-label-relocation-v1/relocate_lbl_pool.py':
        '11a4e9936ea74d2bd1bb7dcc7c9f5faa91dfeefc3f1a205244cf64cb15fa290d',
}
IMAGE_SHA = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
GMP_SHA = '92d4a1aa7cf84ff17b092d74302fb4d432691bd6cd563ba8da4d7ed51f8d73bd'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bind(name):
    path = ROOT / name
    need(path.stat().st_size <= 2_000_000, 'Explicit small input bound')
    raw = path.read_bytes()
    need(sha(raw) == PINS[name], 'Pinned prerequisite ' + name)
    return raw


def load(name, module_name):
    bind(name)
    spec = importlib.util.spec_from_file_location(module_name, ROOT / name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def save(name, value):
    raw = value if type(value) is bytes else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        need(stream.write(raw) == len(raw), 'Complete new artifact')
        stream.flush()
        os.fsync(stream.fileno())
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def fields(value, widths):
    result = []
    for width in widths:
        result.append(value & ((1 << width) - 1))
        value >>= width
    need(value == 0, 'No outside significant bits')
    return result


def pack(values, widths):
    result = offset = 0
    for value, width in zip(values, widths):
        need(type(value) is int and 0 <= value < 1 << width, 'Explicit finite packed field')
        result |= value << offset
        offset += width
    return result.to_bytes((offset + 7) // 8, 'little')


def main():
    need(not OUT.exists(), 'New payload namespace only')
    candidate = json.loads(bind('staging/navigation-native-new-street-source-example-v1/candidate.json'))
    snapshot = json.loads(bind('staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json'))
    layout = json.loads(bind('staging/navigation-country-native-lane-candidate-v3/actual-output-layout.json'))
    need(candidate['schema'] == 'garmin-source-backed-new-street-example/v1' and
         candidate['streettext'] == '敦富六街' and candidate['house_label'] == '368號' and
         candidate['source_ids'] == [8280986017] and candidate['raw24'] == [1127253, 5625400],
         'Exact concrete source example')
    need(candidate['original_JAI_exact_street_absent'] and
         candidate['geometry_gate']['sourcepoint_inside_full_city'] and
         candidate['geometry_gate']['exact_quantized_raw24_inside_same_full_city'] and
         not candidate['admissibility']['install_candidate'], 'Source geometry with explicit admission limits')
    need(snapshot['all_assigned_checks_passed'] and snapshot['selected_original_physical_L3_count'] == 441 and
         snapshot['actual_original_L2_fields']['one_based_ID'] == 74 and
         snapshot['selected_family_first'] == 0x3000327c, 'One exact original family')
    # Read only the prefix of the already verified experimental component;
    # restore its two original header words and bind the complete original GMP.
    with (ROOT / 'staging/navigation-native-label-relocation-v1/experimental-relocated.GMP').open('rb') as stream:
        gmp = bytearray(stream.read(3812824))
    need(len(gmp) == 3812824, 'Complete bounded original component prefix')
    struct.pack_into('<II', gmp, 874 + 21, 6566, 3805432)
    need(sha(gmp) == GMP_SHA, 'Reconstructed source component equals exact original GMP')
    relocate = load('staging/navigation-native-label-relocation-v1/relocate_lbl_pool.py', 'new_family_label_primitive')
    label_plan = relocate.relocate_pool(bytes(gmp), (candidate['streettext'], candidate['house_label']))
    street_ref, house_ref = [row['reference'] for row in label_plan.labels]
    need((street_ref, house_ref) == (475679, 2967) and
         label_plan.labels[1]['reused_existing'] and not label_plan.labels[0]['reused_existing'],
         'One new street label and exact original house reference')
    mapper = load('staging/navigation-country-native-lane-cpu-v3/strict_ap8k_reader.py', 'new_family_finite_AP8K')
    path = ROOT / 'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
    before = mapper.stat(path)
    seal = json.loads((ROOT / 'staging/navigation-country-native-lane-candidate-v3/sealed-files.json').read_text())
    pin = next(row for row in seal['files'] if row['path'].endswith('/gmapprom1.img'))
    need(pin['sha256'] == IMAGE_SHA and before[:4] == pin['stat_at_seal'][:4],
         'Exact completed current v3 dev/inode/size/mtime; capture fresh hardlink ctime')
    image = mapper.Candidate8K(path, layout, before)
    try:
        tables = {row['level']: row for row in layout['tables']}
        need(tables[3]['stride'] == 112 and tables[3]['count'] == 47870 and tables[4]['count'] == 4896236,
             'Exact current profile/counts')
        first = snapshot['selected_family_first'] & 0x0fffffff
        witness, clones = image.read('00004171.MDR', tables[3]['start'] + (first - 1) * 14,
                                     441 * 14, 'actual_current_v3_Beitun_full_family')
        for at in range(0, len(clones), 14):
            value = int.from_bytes(clones[at:at + 14], 'little')
            need(value & 1, 'Actual cloned street mapordinal')
            f, n, flags = (value >> 20) & 0x7fffff, (value >> 43) & 0xfff, (value >> 55) & 511
            level = flags & 7
            need(level in (4, 5, 6) and f >= 1 and n >= 1 and f + n - 1 <= tables[level]['count'],
                 'Every retained current street has a valid current child range')
        low, shift = divmod((74 - 1) * 122, 8)
        L2_witness, window = image.read('00004171.MDR', tables[2]['start'] + low,
                                       (shift + 122 + 7) // 8, 'actual_current_v3_L2_ID74')
        original_L2 = (int.from_bytes(window, 'little') >> shift) & ((1 << 122) - 1)
        widths = (1, 19, 19, 16, 10, 9, 24, 24)
        values = fields(original_L2, widths)
        need(values == [1, 24068, 24067, 12924, 441, 3, 1126994, 5624389], 'Original district record preserved in current v3')
        new_values = values.copy()
        new_values[3:5] = [47871, 442]
        patched_L2 = pack(new_values, widths)
        range_mask = ((1 << 26) - 1) << 39
        need((int.from_bytes(patched_L2, 'little') ^ original_L2) & ~range_mask == 0,
             'Only explicit L2 first/count may change')
        raw24 = candidate['raw24']
        new_house = pack([1, (1 << 19) - 1, house_ref, 0, 0, 0, *raw24],
                         (1, 19, 19, 22, 10, 9, 24, 24))
        new_street = pack([1, street_ref, tables[4]['count'] + 1, 1, 4, *raw24],
                          (1, 19, 23, 12, 9, 24, 24))
        append = clones + new_street
        need(len(append) == 442 * 14 and append[:441 * 14] == clones, 'Complete current family cloned verbatim')
        log = image.log
    finally:
        image.close()
    OUT.mkdir()
    artifacts = [save('L3-family-append.bin', append), save('L4-house-append.bin', new_house),
                 save('L2-patch-record.bin', patched_L2),
                 save('LBL-label-extension.bin', label_plan.component[label_plan.new_pool_offset + label_plan.original_pool_bytes:]),
                 save('LBL-header-pointer-size.bin', struct.pack('<II', label_plan.new_pool_offset, label_plan.new_pool_bytes))]
    proof = dict(schema='source-bound-current-family-payloads/v1',
                 created_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
                 source_script_sha256=sha(Path(__file__).read_bytes()), prerequisite_pins=PINS,
                 source_candidate_name=candidate['streettext'], source_candidate_house=candidate['house_label'],
                 source_ids=candidate['source_ids'], source_raw24=raw24,
                 source_alias_history_verified=False, district_polygon_verified=False,
                 current_v3_full_SHA_inherited=IMAGE_SHA, candidate_stat_before=before,
                 candidate_stat_unchanged=True, actual_current_family=witness, actual_L2=L2_witness,
                 actual_v3_reads=log, current_family_records_copied_verbatim=441,
                 new_family_first=47871, new_street_ID=48312, final_L3_count=48312,
                 L2_only_first_count_patch={'ID':74,'first':47871,'count':442,'raw_flags_retained':3,'initial_bit_shift':shift},
                 street_label_ref=street_ref, house_label_ref=house_ref,
                 new_street_L4_first=tables[4]['count'] + 1, new_L4_count=tables[4]['count'] + 1,
                 label_new_pool_start=label_plan.new_pool_offset, label_new_pool_bytes=label_plan.new_pool_bytes,
                 label_original_GMP_bytes_preserved_except_pointer_size=True, label_original_pool_preserved=True,
                 label_new_source_text_encoded=True, artifacts=artifacts,
                 original_branch_flags_or_existing_house_coords_modified=False,
                 whole_MDR_GMP_IMG_or_SQLite_update_produced=False,
                 new_native_CPU_executed=False, native_full_query_or_UI_verified=False,
                 phone_audio_or_device_IO=False, installable=False, full_Taiwan_update_complete=False,
                 limits=['Finite append payloads only; no MDR directory/header streaming, IMG allocation or rollback composition yet.',
                         'Current v3 family child pointers are retained, avoiding stale stock pointers after the previous address expansion.',
                         'L2 is a122-bit record patch with source shift2; never byte-overwrite the whole16-byte mixed source window.',
                         'New street point is explicitly the sole source house point, not a verified street centroid/entrance.',
                         'The source is literal-name/complete-city qualified but historical aliases, official street identity and district polygon remain held.',
                         'JAI partial FTS8 sandbox is separate; prefix/segment/frontend, full getter/query, container acceptance and real destination/route remain unverified.'])
    row = save('proof.json', proof)
    print(json.dumps(dict(all_passed=True, current_family_clones=441, new_street_ID=48312,
                         v3_actual_read_bytes=sum(x['bytes'] for x in log), artifacts=artifacts, proof=row), ensure_ascii=False))


if __name__ == '__main__':
    main()
