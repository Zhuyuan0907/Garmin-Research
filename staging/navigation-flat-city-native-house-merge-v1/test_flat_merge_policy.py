#!/usr/bin/env python3
"""New flat-city ambiguity and source provenance policy controls only."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')
sys.path.insert(0,str(HERE))
import flat_merge_policy as policy


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def main():
    assert not (HERE/'new-policy-test-proof.json').exists()
    validator=load(ROOT/'staging/navigation-flat-city-district-geometry-v1/source_district_membership.py','flat_policy_source_API').SourceDistrictMembership()
    base=load(ROOT/'staging/navigation-country-native-house-merge-v1/prepare_country_house_merge.py','flat_policy_existing_quantizer_only')
    controls=json.loads((ROOT/'staging/navigation-flat-city-district-geometry-v1/membership-test-proof.json').read_text())
    point=next(r['geometry_derived_control_point'] for r in controls['geometry_derived_positive_pair_controls']
               if r['source_city']=='臺北市' and r['district']=='中正區')
    native={'city':'台北市','district':None,'street':'測試街','record':(3<<28)|123,'low28_id':123,
            'first_child':1,'child_count':3,'child_level_and_flags':4,'next_level':4}
    row={'native_city':'台北市','native_district':None,'native_street':'測試街',
         'native_street_record':native['record'],'nativeStreetID':123,
         'old_child_first':1,'old_child_count':3,'old_child_level_and_flags':4,'old_next_level':4,
         'native_match_scope':'direct_city_street_district_unverified','district_verified':False,'native_merge_eligible':False,
         'house_label':'6號','primary_ref':23,'group_id':1,'source_ids':[10,11],'source_node_count':2,
         'raw_address':['臺北市','中正區','測試街','6號'],'coordinate_strings':point,
         'coordinate_status':'coordinate_ready_global_bounds','source_different_coordinate_nodes':0,
         'same_native_street_house_group_count':1,'same_native_street_house_collision_checked':True,
         'same_native_street_house_coordinate_collision':False,'same_native_street_house_unready_coordinate_members':0,
         'separate_floor_unit_source_nodes':2,'embedded_floor_unit_first_source_flag':False}
    assert policy.exact_native_witness(row,native)
    assert not policy.exact_native_witness(row,native,unique=False)
    label=lambda ref:'6號' if ref==23 else None
    def decide(members,ordinal=True):return policy.target_eligibility(members,native,validator,label,ordinal,base.quantize_point24)
    assert decide([row])['accepted']
    assert decide([row])['native_district_record'] is None and decide([row])['native_district_verified'] is False
    rejected=[]
    def reject(name,rows,reason,ordinal=True):
        actual=decide(rows,ordinal)
        assert actual['accepted'] is False and actual['reason']==reason,(name,actual)
        rejected.append({'control':name,'actual_reason':reason})
    for name,key,value,reason in [
        ('not_all_global_members','same_native_street_house_group_count',2,'global_native_street_house_collision_or_missing_members'),
        ('producer_coordinate_collision','same_native_street_house_coordinate_collision',True,'global_native_street_house_collision_or_missing_members'),
        ('unready_member','same_native_street_house_unready_coordinate_members',1,'global_native_street_house_collision_or_missing_members'),
        ('not_coordinate_ready','coordinate_status','source_conflict','source_coordinate_unready_or_conflict'),
        ('source_ID_not_positive','source_ids',[0,11],'source_node_ID_invalid_or_reused'),
        ('unproved_floor_metadata','separate_floor_unit_source_nodes',3,'source_floor_unit_metadata_invalid'),
        ('unproved_house_hyphen','raw_address',['臺北市','中正區','測試街','6-2號'],'source_raw_house_identity_unproved'),
        ('wrong_street','raw_address',['臺北市','中正區','別街','6號'],'source_literal_city_street_mismatch_under_existing_host_policy'),
        ('unverified_city_glyph','raw_address',['臺北巿','中正區','測試街','6號'],'source_literal_city_street_mismatch_under_existing_host_policy'),
        ('unverified_source_district_glyph','raw_address',['臺北市','中正区','測試街','6號'],'source_point_not_inside_declared_source_district'),
        ('wrong_reference','primary_ref',24,'original_label_ref_mismatch')]:
        altered=deepcopy(row);altered[key]=value;reject(name,[altered],reason)
    reject('original_mapordinal_unknown',[row],'original_mapordinal_not_one',False)
    a,b=deepcopy(row),deepcopy(row)
    a['same_native_street_house_group_count']=b['same_native_street_house_group_count']=2
    b['group_id']=2;b['source_ids']=[12,13]
    assert decide([a,b])['accepted']
    b['raw_address'][1]='大安區'
    reject('different_declared_district_even_same_coordinates',[a,b],'same_native_target_multiple_declared_source_districts')
    b=deepcopy(a);b['group_id']=2;b['source_ids']=[12,13]
    b['coordinate_strings']=[str(float(point[0])+0.0001),point[1]]
    reject('different_Decimal_points',[a,b],'same_native_target_conflicting_ref_or_Decimal_point')
    b=deepcopy(a);b['group_id']=2;b['source_ids']=[10,13]
    reject('reused_source_node_across_members',[a,b],'source_node_ID_invalid_or_reused')
    result={'schema':'flat-native-city-new-merge-policy-controls/v1','all_new_policy_controls_passed':True,
        'synthetic_native_street_and_source_ID_context':True,'synthetic_controls_are_address_or_native_acceptance_evidence':False,
        'positive_single_member':True,'positive_same_point_same_district_multiple_members':True,
        'unique_native_street_required':True,'native_district_record_remains_null':True,
        'new_rejection_controls':rejected,'new_rejection_controls_count':len(rejected),
        'policy_sha256':hashlib.sha256((HERE/'flat_merge_policy.py').read_bytes()).hexdigest(),
        'closed_existing_suites_rerun':False,'IMG_device_or_address_ledger_read':False}
    (HERE/'new-policy-test-proof.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_new_policy_controls_passed':True,'new_rejection_controls':len(rejected),'native_district_verified':False}))


if __name__=='__main__':main()
