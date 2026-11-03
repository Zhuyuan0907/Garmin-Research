#!/usr/bin/env python3
"""Complete relevant per-node provenance; source-only partition, original group held."""
import sys
sys.dont_write_bytecode=True
import ast,hashlib,json,re
from pathlib import Path
from decimal import Decimal,ROUND_HALF_UP
from collections import Counter
from datetime import datetime
import xml.etree.ElementTree as ET
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;READS=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p,pin=None):
 before=stat(p);b=p.read_bytes();assert stat(p)==before
 if pin:assert(len(b),sha(b))==pin
 READS.append(dict(path=str(p.relative_to(ROOT)),byte_range=[0,len(b)],bytes=len(b),sha256=sha(b),stat=before))
 return b
def load(n):return json.loads(read(HERE/n))
def save(n,d):
 assert not(HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def relevant(k):
 # Complete address/location/floor/unit metadata; unrelated contact/account data stays private raw only.
 if any(s in k.lower() for s in ('phone','email','contact','website','operator','contributor')):return False
 if k.startswith('addr:'):return True
 return k in {'level','floor','unit','door','entrance','indoor','repeat_on','building:levels','building:min_level','building:flats','room','apartment'}
def main():
 assert not(HERE/'node-provenance.json').exists()
 inputs=load('prepared-inputs.json');captured=load('original-captured-group.json');group=captured['original_prepared_group']
 process=load('extraction-process.json');membership=load('extraction-membership.json');io=load('PBF-read-receipt.json')
 assert process['actual_getid_invocations']==1 and process['exit_code']==0
 assert process['source_stat_unchanged'] and not process['output_overflow'] and not process['timed_out']
 assert membership['all_nodes_exact_requested'] and not membership['missing_IDs'] and not membership['extra_IDs']
 assert io['actual_syscall_read_bytes']==327206226 and io['file_opens']==io['file_closes']==1 and not io['mmap_count']
 raw=read(HERE/'rawextract.osm',(membership['raw_extract_bytes'],membership['raw_extract_sha256']))
 assert len(raw)<=65536 and (HERE/'rawextract.osm').stat().st_mode&0o777==0o400
 xml=ET.fromstring(raw);nodes={int(e.attrib['id']):e for e in xml.findall('node')}
 ids=group['source_ids'];assert set(nodes)==set(ids) and len(nodes)==21
 policy_path=ROOT/'staging/navigation-taiwan-address-ingestion-v1/prepare_taiwan_address_ingestion.py'
 policy=read(policy_path,(26444,'bf597ea4d04ca9585dfbeac1cc8aa7285cd98a8f7d6a09d446799f46099ddf4b'))
 tree=ast.parse(policy);tuples=set()
 for n in ast.walk(tree):
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='any' and len(n.args)==1 and isinstance(n.args[0],ast.GeneratorExp):
   gen=n.args[0]
   if not (isinstance(gen.elt,ast.Call) and isinstance(gen.elt.func,ast.Attribute) and isinstance(gen.elt.func.value,ast.Name) and gen.elt.func.value.id=='tags' and gen.elt.func.attr=='get'):continue
   if len(gen.generators)==1 and isinstance(gen.generators[0].iter,ast.Tuple):
    vals=tuple(ast.literal_eval(gen.generators[0].iter))
    if vals==('addr:floor','addr:unit','addr:door','level'):tuples.add(vals)
 assert len(tuples)==1;floor_keys=next(iter(tuples))
 rows=[];Q=Decimal(360)/Decimal(1<<24);ambiguous=[]
 for order,node_id in enumerate(ids):
  element=nodes[node_id];taglist=[(e.attrib['k'],e.attrib['v'])for e in element.findall('tag')]
  assert len(taglist)==len({k for k,v in taglist});tags=dict(taglist)
  addr={k:tags.get(k)for k in ('addr:city','addr:district','addr:street','addr:housenumber')}
  original_addr=list(addr.values());point=[element.attrib.get('lat'),element.attrib.get('lon')]
  assert original_addr==group['raw_address']
  assert point==group['first_coordinate']
  numerical_equal=all(Decimal(a)==Decimal(b)for a,b in zip(point,group['first_coordinate']));assert numerical_equal
  native=[int((Decimal(v)/Q).to_integral_value(rounding=ROUND_HALF_UP))for v in point]
  assert native==captured['classification']['point']['native24']
  assert element.attrib.get('version') and element.attrib.get('timestamp')
  assert int(element.attrib['version'])>0;datetime.fromisoformat(element.attrib['timestamp'].replace('Z','+00:00'))
  original_flags={k:tags.get(k)for k in floor_keys};flag=any(original_flags.values())
  related={k:v for k,v in taglist if relevant(k)}
  additional={k:v for k,v in related.items() if k not in floor_keys and
    (re.search(r'(^|:)(floor|unit|door|level|room|apartment)(:|$)',k) or k=='repeat_on') and v}
  full=tags.get('addr:full');assert full
  base_full_without_floor=not re.search(r'(樓|層|室|\bfloor\b|\bunit\b|\bapartment\b)',full,re.I)
  if flag:
   explicit=bool(re.fullmatch(r'(?:[3-9]|1[0-2])樓',tags.get('addr:floor','')) and tags.get('addr:unit')in('之1','之2'))
   status='explicit_source_floor_and_unit' if explicit and not additional else 'ambiguous_floor_unit_held'
  else:status='source_address_without_explicit_floor_unit' if not additional and base_full_without_floor else 'ambiguous_floor_unit_held'
  if status=='ambiguous_floor_unit_held':ambiguous.append(node_id)
  row=dict(source_type='node',source_ID=node_id,captured_source_order_zero_based=order,
   source_version=element.attrib['version'],source_timestamp=element.attrib['timestamp'],
   coordinate_strings=point,raw24_lat_lon=native,raw24_quantization_policy=captured['classification']['point']['quantization_policy'],
   original_four_addr_keys=addr,all_relevant_tags_original_values=related,related_metadata_selection_rule='all addr:* except unrelated contact/account keys, plus level/floor/unit/door/entrance/indoor/repeat_on/building levels/flats/room/apartment',
   original_tag_count=len(tags),all_original_tags_retained_in_private_raw=True,
   original_floor_policy_keys=original_flags,original_floor_policy_nonempty=flag,
   additional_floor_related_nonempty=additional,addr_full_without_floor_or_unit_words=base_full_without_floor,
   floor_source_status=status,original_raw_address_exact_match=True,original_firstpoint_literal_match=True,
   original_firstpoint_numerical_match=True,source_node_element_sha256=sha(ET.tostring(element,encoding='utf-8')),
   contributor_account_attributes_not_copied=True,unrelated_tags_not_reported=True,
   official_address_entrance_or_native_branch_verified=False)
  rows.append(row)
 floor=[r for r in rows if r['original_floor_policy_nonempty']];base=[r for r in rows if r['floor_source_status']=='source_address_without_explicit_floor_unit']
 assert len(floor)==group['separate_floor_unit_nodes']==20 and len(base)==1 and not ambiguous
 assert base[0]['source_ID']==8535365806 and base[0]['captured_source_order_zero_based']==17
 assert rows[0]['source_ID']==captured['original_first_node_ID'] and rows[0]['original_floor_policy_nonempty']
 pair_counts=Counter((r['all_relevant_tags_original_values']['addr:floor'],r['all_relevant_tags_original_values']['addr:unit'])for r in floor)
 assert set(pair_counts)=={(str(n)+'樓',u)for n in range(3,13)for u in ['之1','之2']} and set(pair_counts.values())=={1}
 provenance=dict(schema='exact21-OSM-node-floor-provenance/v1',original_group_ID=172188,
  original_capture_file=inputs['input_read_receipts'][2]['path'],original_capture_line=inputs['capture_line'],
  original_capture_group_path='original-captured-group.json',source_pin=inputs['source_pin'],
  targeted_extraction_membership='extraction-membership.json',targeted_private_XML='rawextract.osm',
  rawextract_sha256=sha(raw),rawextract_bytes=len(raw),source_ID_order=ids,
  metadata_complete_for_actual_extracted21_nodes=True,node_records=rows,
  count_same_original_four_addr_keys=21,count_exact_original_firstpoint=21,count_same_raw24=21,
  actual_original_floor_policy_node_count=20,actual_no_explicit_floor_unit_count=1,
  base_source_IDs=[r['source_ID']for r in base],floor_unit_source_IDs=[r['source_ID']for r in floor],
  ambiguous_source_IDs=ambiguous,original_first_node_is_floor_unit=True,
  node_versions=dict(Counter(r['source_version']for r in rows)),
  node_timestamps=dict(Counter(r['source_timestamp']for r in rows)),
  original_group_still_held=True,all_original_group_holds=captured['classification']['all_hold_reasons'],
  formal_address_alias_route_native_branch_or_install_acceptance=False)
 save('node-provenance.json',provenance)
 proposal=dict(schema='held-source-only-base-floor-partition-proposal/v1',parent_source_group_ID=172188,
  proposal_ID='source172188/per-node-floor-provenance',original_group_unchanged_path='original-captured-group.json',
  original21_source_IDs=ids,original_group_hold_reasons=captured['classification']['all_hold_reasons'],
  original_group_count_coordinate_flags_retained=group,
  base_node_partition=dict(source_IDs=[r['source_ID']for r in base],complete_node_provenance=base,
   original_raw_address_unchanged=group['raw_address'],raw_house_literal='39號',
   separate_floor_unit_metadata_absent=True,data_point_equal_to_original_group=True,
   base_selected_by_actual_tags_not_count_or_firstpoint=True,
   source_level_partition_proposed=True,address_or_native_leaf_created=False),
  floor_unit_partition=dict(source_IDs=[r['source_ID']for r in floor],node_count=20,
   ordered_floor_unit_mapping=[dict(source_ID=r['source_ID'],floor=r['all_relevant_tags_original_values']['addr:floor'],
    unit=r['all_relevant_tags_original_values']['addr:unit'])for r in floor],
   all_floor_and_unit_literals_retained=True,hold='explicit floor/unit source nodes remain excluded from house-only materialization'),
  source_semantics=dict(no_floor_tags_removed_from_floor_nodes=True,no_addr_unit_converted_to_house_subnumber=True,
   no_flat_street_or_integer_lane_assignment=True,no_official_entrance_inferred=True,
   no_new_group_ID_native_record_or_ref_reserved=True),
  followup_requirements=['Actual existing native lane/alley path proof for literal昌平路二段50之6巷2弄.',
   'Retain original39號 house literal; exact native house/reference membership and supported house-format proof.',
   'Required source/raw24 geographic and alias relationship gates under a separate authorized scope.',
   'Explicit planner policy approval for this source-only partition; original21-group hold not removed.'],
  original_group_hold_released=False,native_write_ready=False,install_ready=False)
 save('source-partition-proposal.json',proposal)
 save('analysis-read-receipts.json',dict(reads=READS,PBF_read_in_this_analysis=0,full_ledger_group_scan=False,
  private_XML_reads_only_small13468_bytes=True,source_handles_closed=True))
 for r in READS:assert stat(ROOT/r['path'])==r['stat']
 print(json.dumps(dict(result='exact21-node provenance and held partition prepared',base_source_IDs=provenance['base_source_IDs'],
  explicit_floor_unit_nodes=20,original_first_node_is_floor_unit=True,all_coordinate_and_raw_addr_matches=21,
  all_group_holds_retained=True,native_write_ready=False,unrelated_raw_tags_or_accounts_not_printed=True)))
if __name__=='__main__':main()
