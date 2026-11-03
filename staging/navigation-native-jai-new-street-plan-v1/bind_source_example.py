#!/usr/bin/env python3
"""Bind the separate sealed sole-house source example to the SQLite plan."""
from pathlib import Path
import json
import jai_scope as s

HERE=Path(__file__).resolve().parent
SOURCE=s.ROOT/'staging/navigation-native-new-street-source-example-v1'
PINS={'sealed-files.json':'a7f469ff3b4c9acc562ba92560f4645f77977ccc234a379fdb9f88b11d8c58d3',
 'candidate.json':'d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c',
 'proof.json':'c9033395961cf1d13abaeea76881d479070630abdc189e3580d8630d18db9c3d'}


def main():
    inputs=[];docs={}
    for name,pin in PINS.items():
        p=SOURCE/name;before=s.stat(p);raw=p.read_bytes();s.need(before[2]<=20000 and s.sha(raw)==pin and s.stat(p)==before,'Sealed small source candidate SHA/stat')
        docs[name]=json.loads(raw);inputs.append(dict(path=str(p.relative_to(s.ROOT)),bytes=len(raw),sha256=pin,stat_before=before,stat_after=s.stat(p)))
    c=docs['candidate.json'];sp=docs['proof.json'];s.need(sp['all_assigned_checks_passed'],'Separate sealed source checks')
    plan=json.loads((HERE/'one-family-new-street-plan.json').read_bytes());snapshot=json.loads((HERE/'original-family-snapshot.json').read_bytes())
    s.need(c['streettext']==plan['new_street']['label']=='敦富六街'and c['native_district']['record']==plan['parent_record'],'Exact source target and actual family')
    s.need(c['house_label']=='368號'and c['house_text_reference']['primary_ref']==2967 and c['raw24']==[1127253,5625400],'Exact separate sole-house reference/raw24')
    s.need(c['original_JAI_exact_street_absent']and c['geometry_gate']['sourcepoint_inside_full_city']and c['geometry_gate']['exact_quantized_raw24_inside_same_full_city'],'Separate source exactabsence and both citypoints checked')
    s.need(c['source_ids']==[8280986017]and c['source_group_ids']==[37506]and not c['admissibility']['install_candidate'],'Complete sole source IDs and held installstatus')
    oldbase=s.ROOT/'staging/navigation-country-native-lane-independent-review-v3/proof.json';before=s.stat(oldbase);base_raw=oldbase.read_bytes()
    s.need(s.sha(base_raw)=='9b2ba5d69d26939911fdfe2c311736d22244e80afc6850668716075ee8e5e01d'and s.stat(oldbase)==before,'Sealed actual v3 review metadata only, no IMG open/rerun')
    base=json.loads(base_raw);t=base['actual_tables'];s.need(base['all_assigned_checks_passed']and t['3']['count']==47870 and t['3']['stride']==112,'Bound currentv3 unchanged L3 count/first23 profile')
    inputs.append(dict(path=str(oldbase.relative_to(s.ROOT)),bytes=len(base_raw),sha256=s.sha(base_raw),stat_before=before,stat_after=s.stat(oldbase)))
    additions=(plan['new_physical_L3_count']*t['3']['stride'])//8+16
    result=dict(schema='source-backed-JAI-family-writer-slot-contract/v1',all_assigned_checks_passed=True,
        source_sha256=s.sha(Path(__file__).read_bytes()),inputs=inputs,candidate_status=c['status'],source_candidate=dict(path=str((SOURCE/'candidate.json').relative_to(s.ROOT)),sha256=PINS['candidate.json']),
        full_source_IDs=c['source_ids'],full_source_group_IDs=c['source_group_ids'],source_members=c['source_members'],raw_address=c['raw_address'],normalized_planning_key=c['normalized_planning_key'],
        coordinate_strings=c['coordinate_strings'],raw24=c['raw24'],geometry_gate_inherited=c['geometry_gate'],alias_authenticity_policy_held=c['conservative_name_screen'],
        actual_original_parent_fields=snapshot['actual_original_L2_fields'],new_street_ID=plan['new_street']['record']&0xfffffff,new_info_id=plan['new_street']['info_id'],
        planned_L2_patch=plan['required_L2_patch'],old_L3_entire_family_ID_map=plan['complete_old_physical_order_mapping'],
        required_future_current_profile_source=dict(candidate_sha256=base['candidate_sha256'],actual_original_L3_ID_range=[12924,13364],
            retain_all_current_first_count_rawflags_refs_mapordinal_raw24=True,copying_stock111_records_would_drop_prior_new_children=True),
        future_new_house_slot=dict(level=4,lowID=t['4']['count']+1,primary_ref=c['house_text_reference']['primary_ref'],house_label=c['house_label'],raw24=c['raw24'],
            new_street_first_child=t['4']['count']+1,new_street_child_count=1,new_street_first_width23=True),
        additional_MDR_byte_arithmetic_only=additions,new_L3_span_arithmetic_only=(t['3']['count']+plan['new_physical_L3_count'])*14,
        current_L2_first_width16_and_count_width10_unchanged=True,new_street_LBL_ref_not_allocated_by_this_scope=True,
        street_representative_point_policy_not_proved=True,newstreet_newbranch_rawflag_policy_not_automatically_inferred=True,
        original_DB_IMG_PBF_source_groups_ready_groups_geometry_or_CPU_not_rerun=True,
        complete_prefix_segment_serializer_absent=True,complete_frontend_UI_query_or_device_not_proved=True,
        native_write_ready=False,install_candidate=False,full_Taiwan_native_update_complete=False)
    artifact=s.save('source-candidate-binding.json',result)
    print(json.dumps(dict(all_assigned_checks_passed=True,source_full_IDs=c['source_ids'],new_street_ID=result['new_street_ID'],house_slot=result['future_new_house_slot'],additional_MDR_bytes=additions,binding=artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
