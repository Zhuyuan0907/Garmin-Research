#!/usr/bin/env python3
"""Flat-city source eligibility: no invented native district or alias assignment."""
from decimal import Decimal, InvalidOperation
import re
import unicodedata

CITIES = {'台北市','基隆市','新竹市','嘉義市'}
INTEGER = re.compile(r'([1-9][0-9]*)號\Z')


def norm(value):
    return unicodedata.normalize('NFKC',value or '').strip().replace('臺','台')


def exact_native_witness(row,native,unique=True):
    pairs = [('native_street_record','record'),('nativeStreetID','low28_id'),
        ('native_city','city'),('native_district','district'),('native_street','street'),
        ('old_child_first','first_child'),('old_child_count','child_count'),
        ('old_child_level_and_flags','child_level_and_flags'),('old_next_level','next_level')]
    return unique and native is not None and native['city'] in CITIES and native['district'] is None \
        and row['native_match_scope']=='direct_city_street_district_unverified' \
        and row['district_verified'] is False and row['native_merge_eligible'] is False \
        and all(row[a]==native[b] for a,b in pairs)


def target_eligibility(members,native,validator,label,ordinal_one,quantize):
    """All source members must agree; never pick a conflicting point/district."""
    def reject(reason,**details):return {'accepted':False,'reason':reason,**details}
    if not members:return reject('no_source_members')
    house = members[0]['house_label']
    if not INTEGER.fullmatch(house):return reject('not_positive_integer_house')
    if any(row['house_label']!=house for row in members):return reject('target_house_identity_mismatch')
    if any(row['same_native_street_house_group_count']!=len(members) or
           row['same_native_street_house_collision_checked'] is not True or
           row['same_native_street_house_coordinate_collision'] is not False or
           row['same_native_street_house_unready_coordinate_members']!=0 for row in members):
        return reject('global_native_street_house_collision_or_missing_members')
    if any(row['coordinate_status']!='coordinate_ready_global_bounds' or row['coordinate_strings'] is None or
           row['source_different_coordinate_nodes']!=0 for row in members):
        return reject('source_coordinate_unready_or_conflict')
    groups,ids=set(),set()
    for row in members:
        group=row['group_id'];nodes=row['source_ids']
        if type(group)is not int or group<=0 or group in groups:return reject('source_group_ID_invalid_or_reused')
        if not isinstance(nodes,list) or len(nodes)!=row['source_node_count'] or not nodes \
                or any(type(i)is not int or i<=0 for i in nodes) or len(set(nodes))!=len(nodes) or ids.intersection(nodes):
            return reject('source_node_ID_invalid_or_reused')
        groups.add(group);ids.update(nodes)
        raw=row['raw_address']
        if not isinstance(raw,list) or len(raw)!=4 or any(not isinstance(x,str) for x in raw):
            return reject('source_raw_address_invalid')
        if norm(raw[0])!=norm(native['city']) or norm(raw[2])!=norm(native['street']):
            return reject('source_literal_city_street_mismatch_under_existing_host_policy')
        text=unicodedata.normalize('NFKC',raw[3]).strip()
        simple=re.fullmatch(r'([1-9][0-9]*)號?',text)
        unit=re.fullmatch(r'([1-9][0-9]*號)(.+(?:樓|室|F|f).*)',text)
        if not (simple and simple.group(1)+'號'==house) and not (
                unit and unit.group(1)==house and row['embedded_floor_unit_first_source_flag'] is True):
            return reject('source_raw_house_identity_unproved')
        if type(row['separate_floor_unit_source_nodes'])is not int or not 0<=row['separate_floor_unit_source_nodes']<=len(nodes) \
                or type(row['embedded_floor_unit_first_source_flag'])is not bool:
            return reject('source_floor_unit_metadata_invalid')
    district_names={row['raw_address'][1] for row in members}
    if len(district_names)!=1:return reject('same_native_target_multiple_declared_source_districts',source_districts=sorted(district_names))
    refs={row['primary_ref'] for row in members}
    try:
        points={tuple(map(Decimal,row['coordinate_strings'])) for row in members}
        if any(len(point)!=2 or not all(x.is_finite() for x in point) or not(-90<=point[0]<=90 and -180<=point[1]<180) for point in points):
            return reject('invalid_global_source_coordinate')
    except (ValueError,TypeError,InvalidOperation):return reject('invalid_source_coordinate')
    if len(refs)!=1 or len(points)!=1:return reject('same_native_target_conflicting_ref_or_Decimal_point')
    if any(type(ref)is not int or not 0<=ref<524287 for ref in refs) or label(members[0]['primary_ref'])!=house:
        return reject('original_label_ref_mismatch')
    if not ordinal_one:return reject('original_mapordinal_not_one')
    district=next(iter(district_names))
    source_decisions=[];pair_decisions=[];raw_points=[]
    for row in members:
        point=row['coordinate_strings']
        q=quantize(*point)
        raw24=[q['latitude']['wire_u24'],q['longitude']['wire_u24']]
        source=validator.assess(row['raw_address'][0],district,*point)
        pair=validator.assess_source_and_raw24(row['raw_address'][0],district,*point,raw24)
        if source['status']!='inside_declared_source_district':
            return reject('source_point_not_inside_declared_source_district',source_decision=source)
        if not pair['eligible'] or pair['status']!='source_and_raw24_inside_same_declared_source_district':
            return reject('raw24_point_not_inside_same_source_district',raw24=raw24,pair_decision=pair)
        if pair['native_city']!=native['city'] or pair['native_district_verified'] is not False or pair['native_district_record'] is not None:
            return reject('source_native_root_binding_mismatch')
        source_decisions.append(source);pair_decisions.append(pair);raw_points.append(raw24)
    if any(point!=raw_points[0] for point in raw_points):return reject('same_Decimal_point_encoded_inconsistently')
    return {'accepted':True,'reason':'all_members_source_and_raw24_inside_same_source_district',
        'source_district':district,'source_city':pair_decisions[0]['source_city'],
        'raw24':raw_points[0],'source_decisions':source_decisions,'pair_decisions':pair_decisions,
        'native_district_verified':False,'native_district_record':None}
