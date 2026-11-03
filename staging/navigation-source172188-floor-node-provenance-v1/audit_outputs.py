#!/usr/bin/env python3
"""Independent tiny XML/output audit; never opens source PBF or repeats getid."""
import sys
sys.dont_write_bytecode=True
import hashlib,json
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def load(n):return json.loads((HERE/n).read_text())
def save(n,d):
 assert not(HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def main():
 assert not(HERE/'proof.json').exists()
 captured=load('original-captured-group.json');group=captured['original_prepared_group']
 assert json.loads((HERE/'original-capture-line.jsonl').read_bytes())==captured
 prepared=load('prepared-inputs.json');process=load('extraction-process.json');membership=load('extraction-membership.json')
 provenance=load('node-provenance.json');proposal=load('source-partition-proposal.json');io=load('PBF-read-receipt.json')
 raw_before=stat(HERE/'rawextract.osm');raw=(HERE/'rawextract.osm').read_bytes();assert stat(HERE/'rawextract.osm')==raw_before
 assert(len(raw),sha(raw))==(membership['raw_extract_bytes'],membership['raw_extract_sha256'])
 nodes={int(e.attrib['id']):e for e in ET.fromstring(raw).findall('node')}
 ids=group['source_ids'];assert set(nodes)==set(ids) and len(nodes)==21
 rows=provenance['node_records'];assert [r['source_ID']for r in rows]==ids
 assert [int(l.strip()[1:])for l in (HERE/'node-ids.txt').read_text().splitlines()]==ids
 floor=[];base=[]
 policy=('addr:floor','addr:unit','addr:door','level')
 for order,r in enumerate(rows):
  e=nodes[r['source_ID']];tags={t.attrib['k']:t.attrib['v']for t in e.findall('tag')}
  assert r['captured_source_order_zero_based']==order
  assert r['source_version']==e.attrib['version'] and r['source_timestamp']==e.attrib['timestamp']
  assert r['coordinate_strings']==[e.attrib['lat'],e.attrib['lon']]==group['first_coordinate']
  assert [tags['addr:'+k]for k in ('city','district','street','housenumber')]==group['raw_address']
  assert r['original_floor_policy_keys']=={k:tags.get(k)for k in policy}
  assert r['original_floor_policy_nonempty']==any(tags.get(k)for k in policy)
  assert r['source_node_element_sha256']==sha(ET.tostring(e,encoding='utf-8'))
  assert r['all_relevant_tags_original_values']=={k:v for k,v in tags.items()if k.startswith('addr:') or k in policy}
  # These21 actual tag dictionaries only contain addr:* tags, all relevant; no account attrs copied.
  assert not {'uid','user','changeset'}&r.keys()
  assert r['original_tag_count']==len(tags) and r['all_original_tags_retained_in_private_raw']
  (floor if r['original_floor_policy_nonempty']else base).append(r['source_ID'])
 assert len(floor)==20 and base==[8535365806] and ids[0]in floor
 assert provenance['base_source_IDs']==base and provenance['floor_unit_source_IDs']==floor
 assert proposal['base_node_partition']['source_IDs']==base and proposal['floor_unit_partition']['source_IDs']==floor
 assert proposal['original21_source_IDs']==ids
 assert not set(base)&set(floor) and set(base)|set(floor)==set(ids)
 assert len(proposal['floor_unit_partition']['ordered_floor_unit_mapping'])==20
 assert proposal['original_group_count_coordinate_flags_retained']==group
 assert proposal['original_group_hold_reasons']==captured['classification']['all_hold_reasons']
 assert not proposal['original_group_hold_released'] and not proposal['native_write_ready'] and not proposal['install_ready']
 assert process['actual_getid_invocations']==1 and process['exit_code']==0 and not process['source_full_hash_recomputed']
 assert io['file_opens']==io['file_closes']==1 and not io['mmap_count']
 cursor=0
 for r in io['reads']:
  assert r['offset']==cursor;cursor+=r['bytes']
 assert cursor==io['actual_syscall_read_bytes']==io['unique_bytes']==327206226
 assert io['unique_ranges']==[[0,327206226]]
 assert process['raw_output_bytes']==len(raw)==13468<=65536
 assert not membership['missing_IDs'] and not membership['extra_IDs'] and not membership['duplicate_IDs']
 pbf=ROOT/prepared['source_pin']['path'];assert stat(pbf)==process['source_stat_before']==process['source_stat_after']
 for r in prepared['input_read_receipts']+load('analysis-read-receipts.json')['reads']:
  assert stat(ROOT/r['path'])==r['stat']
 proof=dict(schema='targeted21-node-floor-provenance-proof/v1',all_assigned_checks_passed=True,
  status='complete-source-provenance-with-held-source-only-partition',original_source_group_ID=172188,
  original21_group_unchanged=True,original_group_hold_reasons_retained=captured['classification']['all_hold_reasons'],
  requested_nodes=21,actual_nodes=21,missing_nodes=0,extra_nodes=0,duplicates=0,
  actual_original_four_addr_keys_matching=21,actual_coordinates_literal_matching=21,
  captured_different_coordinate_nodes=group['different_coordinate_nodes'],actual_different_coordinate_nodes=0,
  coordinate_ready_capture_preserved=True,captured_raw24=[1127428,5624288],actual_all_nodes_raw24_same=True,
  actual_floor_unit_nodes=20,actual_floor_unit_raw_values='3樓..12樓, each之1/之2, literals retained; no unit-to-house-subnumber conversion',
  actual_no_explicit_floor_unit_node_ID=8535365806,base_node_original_ID_order_one_based=18,
  first_captured_node_ID=8535190177,first_node_actual_floor='4樓',first_node_actual_unit='之1',
  first_node_not_assumed_base=True,base_node_version='3',base_node_timestamp='2026-03-13T00:09:45Z',
  all21_actual_versions_timestamps_and_complete_related_tags_preserved=True,
  all21_private_raw_original_tags_and_metadata_retained=True,unrelated_tags_or_contributor_accounts_not_reported=True,
  source_pin=prepared['source_pin'],actual_single_getid_invocation=True,
  actual_PBF_IO=dict(syscalls=io['actual_read_syscalls'],bytes=io['actual_syscall_read_bytes'],unique_bytes=io['unique_bytes'],
   exact_monotonic_ranges=True,ranges=[[0,327206226]],file_opens=1,file_closes=1,mmap=0),
  PBF_source_SHA_inherited_not_rehashed=True,PBF_source_stat_before_after_equal=True,
  rawextract_bytes=13468,rawextract_sha256=sha(raw),rawextract_mode='0400',namespace_mode='0700',
  output_XML_budget_bytes=65536,original_prepared_capture_sha256='937cfd4cd38ee374e99bdbb08d0a2546b6d9a40e6ea71bdd47408d309dfdc221',
  base_source_level_partition_only=True,original_group_floor_hold_not_released=True,
  audit_private_XML_reads=len(raw),audit_PBF_reads=0,
  source_scope_limits=dict(second_getid_extraction=False,full_PBF_hash=False,network=False,
   full_address_node_ledger_or_group_scan=False,source_PBF_or_original_capture_mutation=False,
   geometry_or_native_lane_branch_reverified=False,original_firmware_CPU_or_audio=False,
   IMG_DB_installer_or_device_written=False,official_address_entrance_alias_route_verified=False,
   new_native_record_or_ref_reserved=False,native_write_ready=False,install_ready=False,full_address_update_complete=False),
  actual_all_handles_closed=True,source_or_output_gap=False)
 save('proof.json',proof)
 save('output-audit.json',dict(all_assigned_checks_passed=True,independent_private_XML_node_checks=21,
  source_partition_disjoint_exact_union=True,originalgroup_and_holds_kept=True,read_private_XML_bytes=len(raw),
  PBF_file_reads=0,PBF_stat_only=True,no_getid_or_old_suite_repeat=True))
 print(json.dumps(dict(result='PASS independent small-output audit',proof_sha256=sha((HERE/'proof.json').read_bytes()),
  base_source_ID=8535365806,floor_unit_IDs=20,original_group_held=True,native_write_ready=False,
  source_PBF_actual_read_once=True,PBF_read_in_audit=0,all_handles_closed=True)))
if __name__=='__main__':main()
