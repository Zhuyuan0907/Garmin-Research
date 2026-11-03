#!/usr/bin/env python3
"""Pinned one-district primary-source membership, no alias/admin assignment."""
import ast
from collections import defaultdict
from decimal import Decimal,InvalidOperation
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
ENGINE=ROOT/'staging/navigation-country-merge-independent-review-v1/review_country_merge.py'
PINS={
    'geometry.json':(144506,'c4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3'),
    'source-membership.json':(4204,'d624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84'),
    'proof.json':(9659,'7000011d0cc84272d0ceb4a23b23e8dc2097cf414b9b0b4fea7dd0bbd82cd4e1'),
}
ENGINE_PIN=(35417,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec')


def need(ok,message):
    if not ok:raise ValueError(message)


def pinned(path,pin):
    raw=path.read_bytes()
    need(len(raw)==pin[0] and hashlib.sha256(raw).hexdigest()==pin[1],'Unverified membership input '+str(path))
    return raw


class BeitunMembership:
    def __init__(self,directory=HERE,engine_path=ENGINE):
        directory=Path(directory)
        geometry=json.loads(pinned(directory/'geometry.json',PINS['geometry.json']))
        membership=json.loads(pinned(directory/'source-membership.json',PINS['source-membership.json']))
        proof=json.loads(pinned(directory/'proof.json',PINS['proof.json']))
        need(proof['all_assigned_geometry_preparation_checks_passed'] is True and
             proof['actual_source_parent_subarea_membership_verified'] is True,'Accepted preparation and actual parent membership')
        need((membership['source_city_relation_id'],membership['source_district_relation_id'])==(2921154,2959946) and
             (membership['city'],membership['source_city'],membership['district'])==('台中市','臺中市','北屯區'),
             'Exact source district and source city identity')
        need(membership['actual_source_parent_subarea_member']==dict(type='relation',ref=2959946,role='subarea') and
             membership['native_city']['record']==0x10000008 and membership['native_district']['record']==0x2000004a,
             'Known existing native city/district names and source subarea')
        need(membership['complete_reference_closed_geometry'] is True and
             membership['geometry']['sha256']==PINS['geometry.json'][1], 'Exact complete district geometry binding')
        tree=ast.parse(pinned(Path(engine_path),ENGINE_PIN))
        names={'WindingRing','WindingCity'}
        module=ast.Module(body=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in names],type_ignores=[])
        need({n.name for n in module.body}==names,'Exact existing pure membership classes')
        namespace=dict(Decimal=Decimal,defaultdict=defaultdict,need=need)
        exec(compile(module,str(engine_path),'exec'),namespace)
        self.engine=namespace['WindingCity'](geometry)
        self.metadata=dict(city='台中市',district='北屯區',source_city_relation_id=2921154,
                           source_district_relation_id=2959946,native_city_record=0x10000008,
                           native_district_record=0x2000004a,geometry_sha256=PINS['geometry.json'][1],
                           primary_source_geometry_only=True,official_street_alias_verified=False)

    def _context(self,city,district):
        if city!='台中市':return dict(eligible=False,status='unsupported_native_city')
        if district!='北屯區':return dict(eligible=False,status='unsupported_native_district')
        return None

    def assess_source_point(self,city,district,latitude,longitude):
        context=self._context(city,district)
        if context:return context
        if isinstance(latitude,bool) or isinstance(longitude,bool):return dict(eligible=False,status='invalid_source_coordinate')
        try:lat,lon=Decimal(str(latitude)),Decimal(str(longitude))
        except (InvalidOperation,ValueError,TypeError):return dict(eligible=False,status='invalid_source_coordinate')
        if not lat.is_finite() or not lon.is_finite() or not (-90<=lat<=90 and -180<=lon<180):
            return dict(eligible=False,status='invalid_global_source_coordinate')
        scaled=[v*10_000_000 for v in (lat,lon)]
        if any(v!=v.to_integral_value() for v in scaled):return dict(eligible=False,status='source_coordinate_exceeds_OSM_precision')
        inside=self.engine.covers(int(scaled[1]),int(scaled[0]))
        return dict(self.metadata,eligible=inside,status='inside_explicit_source_district' if inside else 'outside_explicit_source_district',
                    point_kind='original_OSM_decimal_strings')

    def assess_raw24(self,city,district,latitude_u24,longitude_u24):
        context=self._context(city,district)
        if context:return context
        if any(type(v)is not int or not 0<=v<=0xffffff for v in (latitude_u24,longitude_u24)):
            return dict(eligible=False,status='invalid_explicit_raw24_integers')
        signed=[v-(1<<24) if v&(1<<23) else v for v in (latitude_u24,longitude_u24)]
        if not -(1<<22)<=signed[0]<=(1<<22):return dict(eligible=False,status='invalid_global_raw24_latitude')
        inside=self.engine.covers(signed[1]*3515625,signed[0]*3515625,16384)
        return dict(self.metadata,eligible=inside,status='inside_explicit_source_district' if inside else 'outside_explicit_source_district',
                    point_kind='exact_native_raw24_rational_no_decimal_rounding',signed24=signed)
