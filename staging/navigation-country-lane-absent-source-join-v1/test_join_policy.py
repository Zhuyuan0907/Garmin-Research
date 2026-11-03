#!/usr/bin/env python3
"""New pure coalescence policy controls; no old main, geometry or CPU suites."""
import ast
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
source=HERE/'join_absent_lane_sources.py'
raw=source.read_bytes()
nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='eligibility']
assert len(nodes)==1
ns={'Decimal':Decimal,'INTEGER':re.compile(r'[1-9][0-9]*號\Z')}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),ns)
policy=ns['eligibility']
def member(point=('25.0000000','121.0000000'),ref=19,parent=1074000000,status='coordinate_ready_global_bounds'):
    return dict(coordinate_status=status,coordinate_strings=list(point) if point is not None else None,
                primary_ref=ref,native_parent={'record':parent,'rawflags':5})
passed=[]
def check(name,ok):
    assert ok,name;passed.append(name)
r,p=policy([member(),member(('25','121'))],'2號')
check('same exact Decimal point permitted despite string scale',not r and len(p)==1)
r,p=policy([member(),member(('25.0000001','121'))],'2號')
check('distinct exact Decimal point held','same_parent_house_exact_Decimal_point_collision' in r)
r,p=policy([member(),member(None,status='source_coordinate_conflict')],'2號')
check('unready member prevents any target point selection','source_coordinate_conflict_or_unavailable' in r)
check('subnumber deferred','noninteger_or_subnumber_house' in policy([member()],'2之1號')[0])
check('missing numeric textref held','missing_or_invalid_existing_numeric_label_ref' in policy([member(ref=None)],'2號')[0])
check('different textrefs held','same_parent_house_reference_collision' in policy([member(),member(ref=20)],'2號')[0])
check('different parent plans held','native_parent_path_or_old_range_collision' in policy([member(),member(parent=1074000001)],'2號')[0])
result={'all_new_policy_controls_passed':True,'controls':passed,'count':len(passed),
        'source_sha256':hashlib.sha256(raw).hexdigest(),'native_CPU_executed':False,
        'old_closed_tests_replayed':False,'source_groups_or_maps_read':False}
(HERE/'new-policy-controls-proof.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
