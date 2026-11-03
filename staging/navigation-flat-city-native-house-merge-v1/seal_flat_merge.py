#!/usr/bin/env python3
"""Seal actual preparation/readback receipts; no native output composition."""
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


class Reader:
    def __init__(self,file):self.file=file;self.count=0;self.digest=hashlib.sha256()
    def read(self,n=-1):
        raw=self.file.read(n);self.count+=len(raw);self.digest.update(raw);return raw


def main():
    assert not (HERE/'sealed-files.json').exists()
    producer=json.loads((HERE/'proof.json').read_text())
    metadata=json.loads((HERE/'preflight.json').read_text())
    readback=json.loads((HERE/'output-readback-proof.json').read_text())
    tests=json.loads((HERE/'new-policy-test-proof.json').read_text())
    assert producer['all_assigned_checks_passed'] and readback['all_assigned_new_readback_checks_passed'] and tests['all_new_policy_controls_passed']
    assert sha((HERE/'proof.json').read_bytes())==readback['producer_proof_sha256']
    assert sha((HERE/'verify_flat_append_readback.py').read_bytes())==readback['readback_script_sha256']
    assert sha((HERE/'flat_merge_policy.py').read_bytes())==tests['policy_sha256']
    for item in producer['source_code_bindings']:
        path=ROOT/item['path'];assert path.stat().st_size==item['bytes'] and sha(path.read_bytes())==item['sha256']
    immutable=[]
    for item in metadata['input_receipts']+producer['inputs']:
        current=stat(ROOT/item['path']);assert current==item['stat_after']==item['stat_before']
        immutable.append({'path':item['path'],'stat_at_seal':current,'bytes':item['bytes'],'completed_content_sha256':item['sha256'],
                          'unchanged_from_completed_pass':True})
    AP=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
    assert stat(AP)==producer['original_map_stat_before']==producer['original_map_stat_after'] \
        ==readback['additional_original_image_stat_before']==readback['additional_original_image_stat_after']
    auxiliary=[]
    for key in ('held','rejected_targets','read_log'):
        expected=producer['artifacts'][key];path=HERE/expected['path'];before=stat(path);plain=hashlib.sha256();count=0
        with path.open('rb') as file:
            reader=Reader(file)
            with gzip.GzipFile(fileobj=reader) as stream:
                for line in stream:
                    plain.update(line);row=json.loads(line);count+=1
                    if key=='held':assert row['district'] is None and row['native_district_verified'] is False and row['reason']=='unproved_original_parent_flags'
                    elif key=='rejected_targets':
                        assert row['district'] is None and row['native_district_verified'] is False
                        assert row['source_ids']==[i for m in row['source_members'] for i in m['source_ids']]
                        assert row['source_group_ids']==[m['group_id'] for m in row['source_members']]
                    else:assert row['bytes']>0
        assert reader.count==expected['bytes'] and reader.digest.hexdigest()==expected['sha256'] and plain.hexdigest()==expected['uncompressed_sha256']
        assert count==expected['rows'] and stat(path)==before
        auxiliary.append(dict(expected,gzip_EOF_validated=True,stat_before=before,stat_after=stat(path),
                              complete_rows_validated=count))
    receipt={'schema':'flat-native-city-merge-execution-receipts/v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'metadata':{'command':'python3 staging/navigation-flat-city-native-house-merge-v1/prepare_metadata.py','actual_exec_chunk_id':'440e98','actual_exit_code':0,
                    'preflight_sha256':sha((HERE/'preflight.json').read_bytes())},
        'new_policy_controls':{'command':'python3 staging/navigation-flat-city-native-house-merge-v1/test_flat_merge_policy.py','actual_exec_chunk_id':'34cf56','actual_exit_code':0,
                    'new_rejection_controls':tests['new_rejection_controls_count']},
        'actual_preparation':{'command':'python3 staging/navigation-flat-city-native-house-merge-v1/prepare_flat_city_house_merge.py',
                    'initial_exec_chunk_id':'bc55f6','session_id':82134,'terminal_write_stdin_chunk_id':'0c7768','actual_exit_code':0,
                    'started_utc':producer['started_utc'],'finished_utc':producer['finished_utc'],
                    'max_RSS_KiB':producer['max_RSS_KiB'],'original_map_bytes_read':producer['original_map_bytes_read'],
                    'ready_group_rows':159594,'ready_ledger_complete_content_passes_each':1,
                    'all_ready_compressed_plain_EOF_hashes_bound':True,'new_records':4500,
                    'append_bytes':sum(producer['artifacts'][f'level{i}']['bytes'] for i in (4,5,6))},
        'actual_output_readback':{'command':'python3 staging/navigation-flat-city-native-house-merge-v1/verify_flat_append_readback.py',
                    'initial_exec_chunk_id':'844526','session_id':69213,'terminal_write_stdin_chunk_id':'239d47','actual_exit_code':0,
                    'actual_new_records_decoded':4500,'old_records_retained_hash_and_order_checked':142146,
                    'selected_original_groups_actual_output_checked':889,'positive_unique_new_record_OSM_IDs':38261,
                    'additional_original_label_pool_bytes':3805432,'additional_original_image_bytes_read':readback['additional_original_image_bytes_read'],
                    'old_source_groups_or_address_ready_ledgers_reread':False},
        'auxiliary_output_readback':auxiliary,'source_immutability_at_seal':immutable,
        'original_IMG_stat_unchanged_at_seal':stat(AP),
        'all_actual_handles_terminal':True,'native_district_created_or_verified':False,
        'closed_suites_CPU_IMG_USB_canonical_ZIP':False,'full_Taiwan_update_complete':False}
    (HERE/'execution-receipts.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
    handoff="""Prepared native integer-house appends for four original city→street layouts

Actual sealed ready inputs were read once each, with full compressed/plain SHA,
gzip EOF, exact counts and immutable stats: L4 144,987, L5 14,537, L6 70 groups.
Native city/street must be unique in the complete original four-city roster.
The producer's global nativeStreet+house collision flags plus exact full-target
member count are checked; different declared source districts cannot coalesce.
All admitted members have positive unique IDs, identical Decimal coordinates,
reusable original GMP house refs, and source and exact quantized raw24 points
within the SAME literally declared source district. No first conflicting point
or inferred district is selected. The original native district remains null.

4,500 new records = L4 3,552 / L5 936 / L6 12, in 889 original streets.
142,146 original records are cloned unchanged; appends contain 146,646 records.
L4 138,912 records / 2,222,592 B; L5 7,720 / 121,590 B; L6 14 / 119 B.
Total 2,344,301 B. Each binary is a table-wide stream of stride 128/126/68 bits
starting at local bit zero. L4/L5/L6 have final padding 0/0/0; a future prefix
may end at a partial byte, so splice significant bits, never byte-concatenate.

107,387 existing exact integer targets retain original coordinates and bits.
47,478 non-integer/subnumber targets are deferred. Seven otherwise-new targets
fail declared source district containment and are rejected with full provenance.
18 street groups / 222 source groups with original parent flags outside4/5/6
are held; unknown raw13 semantics are not changed. Selected cloned children
include 8,263 nested records, raw flag8 7,299 and raw flag13 24 unchanged.

Index bases are sealed v1+KH: L4 3,642,683, L5 2,659,853, L6 1,984,052.
Under these exact pins, proposed counts are 3,781,595 / 2,667,573 / 1,984,066.
Root plans one prior v1 L4 outlier exclusion. Explicitly rebasing only L4 by−1
gives 3,781,594 / 2,667,573 / 1,984,066. Do not mutate this source seal or bins.
relative_new_first / relative_new_lowID and local appended_bit_offset retain
source-relative identity; new_first/new_lowID use the above old base pins.
Rebase formula: explicit_new_base[level] + relative_new_first/relative_new_lowID.
All final IDs fit the currently selected country L3 w0=23 profile; this is a
profile constraint, not a GarminOS hard limit. The final L6 total also fits21bits.

Selected range schema matches the other producers: nativeStreetID,
native_street_record, city, district:null, street, next_level, record_bits,
original_first/count/flags, new_first/count, appended_bit_offset/record_ordinal,
new_integer_house_count, original/new significant hashes and source window hash.
Additional annotations: index_base_count_pin, relative_new_first,
declared_source_districts, native_district_record:null/native_district_verified:false.
New ledger keeps core nativeStreetID/next_level/new_lowID/appended_bit_offset/
record_bits/payload/primary_ref/raw24/coordinate_strings/source_members fields.
It also retains complete source_ids/source_group_ids, raw addresses/floor-unit
metadata, source_city/source_district, per-member same-district decisions,
relative_new_lowID and the explicit base pin. source_merge may be flat_city_v1
when a composing builder labels its derived copy; no source ledger is modified.

Actual-output readback independently decoded all4,500 packed new records,
checked every original GMP text ref and exact Fraction raw24 rounding,
revalidated every source/native-grid district decision, checked all889 actual
merged numeric orders and all142,146 retained old significant hashes/order.
An extra bounded3.8MB label-pool read supports numeric/ref checks; old original
street windows and all source-ready ledgers were not reread. Held/rejected/read
logs also passed full gzip EOF/dual-hash readback. Execution receipts bind real
EXIT0 metadata440e98, new policy34cf56, preparation82134/0c7768 and output
readback69213/239d47. No prior closed suite or native CPU was run.

Preparation only: no IMG, JAI record, USB, canonical report or ZIP was written.
No native district exists or is validated for these cities. Source geometry and
host numeric insertion do not prove actual device search/UI/navigation or source
house authenticity. Upstream coordinate-review/name/ref/other source groups
remain unresolved; the full Taiwan native address update remains incomplete.
"""
    (HERE/'HANDOFF.txt').write_text(handoff)
    filenames=['prepare_metadata.py','native-flat-roster.json','preflight.json','flat_merge_policy.py',
        'test_flat_merge_policy.py','new-policy-test-proof.json','prepare_flat_city_house_merge.py',
        'appended-level4.bin','appended-level5.bin','appended-level6.bin','selected-street-ranges.json',
        'new-house-records.jsonl.gz','held-street-groups.jsonl.gz','rejected-new-house-targets.jsonl.gz',
        'original-map-read-log.jsonl.gz','proof.json','verify_flat_append_readback.py','output-readback-proof.json',
        'seal_flat_merge.py','execution-receipts.json','HANDOFF.txt']
    # Large artifacts were already fully read back or stream-verified. Use their
    # completed hashes and size+stat checks; do not do another full content pass.
    artifact_lookup={a['path']:a for a in producer['artifacts'].values()}
    files=[]
    for name in filenames:
        path=HERE/name
        if name in artifact_lookup:
            expected=artifact_lookup[name];assert path.stat().st_size==expected['bytes']
            files.append({'path':name,'bytes':expected['bytes'],'sha256':expected['sha256']})
        else:
            raw=path.read_bytes();files.append({'path':name,'bytes':len(raw),'sha256':sha(raw)})
    seal={'schema':'flat-native-city-house-merge-file-seal/v1','created_utc':receipt['created_utc'],
        'all_actual_handles_terminal':True,'all_preparation_new_policy_actual_output_checks_passed':True,
        'new_house_records':4500,'selected_streets':889,'native_district_record_created_or_verified':False,
        'base_counts_pinned':producer['starting_country_v1_plus_KH_counts'],'artifacts_are_locally_rebasable':True,
        'files':files,'file_count':len(files),'total_bytes':sum(r['bytes'] for r in files),
        'scope':'Four native flat-city appends only; root explicitly rebases derived composition; no new IMG/device/ZIP.',
        'full_Taiwan_update_complete':False}
    (HERE/'sealed-files.json').write_text(json.dumps(seal,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'scope_sealed':True,'new_records':4500,'selected_streets':889,
        'append_bytes':2344301,'seal_sha256':sha((HERE/'sealed-files.json').read_bytes()),
        'actual_output_readback_passed':True,'auxiliary_gzip_EOF_hashes_passed':True},ensure_ascii=False))


if __name__=='__main__':main()
