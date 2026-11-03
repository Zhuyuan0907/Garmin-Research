#!/usr/bin/env python3
"""Only new pure planning controls; no old main/suite or map/source data."""
from pathlib import Path
import importlib.util
import hashlib
import json

HERE=Path(__file__).resolve().parent
path=HERE/'plan_lane_tree_overlay.py'
spec=importlib.util.spec_from_file_location('new_overlay_policy_under_test',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
controls=[]


def check(name,condition):
    if not condition:raise AssertionError(name)
    controls.append(dict(name=name,passed=True))


def reject(name,callback):
    try:callback()
    except ValueError:controls.append(dict(name=name,passed=True));return
    raise AssertionError(name)


check('old parent remaps through actual inserted ordinal holes',m.old_to_current_ordinals(4,7,{0,3,6})==[1,2,4,5])
check('unselected child sequence maps verbatim',m.old_to_current_ordinals(3,3,set())==[0,1,2])
reject('missing kept ordinal cannot silently shift old parent',lambda:m.old_to_current_ordinals(4,7,{0,3}))
reject('out-of-group kept ordinal rejected',lambda:m.old_to_current_ordinals(2,3,{3}))
check('numeric interleave preserves nested and nonnumeric positions',
      m.numeric_positions(['2號','4巷','4之1號','未知','10號'],[1,3,6,12])=={1:0,3:2,6:6,12:8})
check('nonmonotone native numeric anchors held',m.numeric_positions(['10號','2號'],[3])is None)
check('no numeric anchor held',m.numeric_positions(['未分類'],[3])is None)
reject('duplicate source numeric target rejected',lambda:m.numeric_positions(['1號'],[3,3]))
check('same exact group is an alias',m.intervals_overlap((5,100,10),(5,100,10)))
check('partial same-table overlap detected',m.intervals_overlap((5,100,10),(5,109,3)))
check('adjacent groups do not alias',not m.intervals_overlap((5,100,10),(5,110,3)))
check('equal ordinal range in different tables does not alias',not m.intervals_overlap((5,100,10),(6,100,10)))
profile=dict(widths=[21,9,24,19,1,9,0,0],reference_flags=[1,1],stride=126)
raw=1|(122<<1)|(456<<20)|(100<<39)|(5<<60)|(13<<69)|(1124806<<78)|(5624212<<102)
decoded=m.decode(raw,profile)
check('raw13 branch fields decoded without flag conversion',
      (decoded['raw_flags'],decoded['next_level'],decoded['first_child'],decoded['child_count'])==(13,5,100,5))
check('unknown child coordinates and both references retained',
      (decoded['raw_location_a'],decoded['raw_location_b'],decoded['primary_ref'],decoded['secondary_ref'])==(1124806,5624212,456,122))
proof=dict(all_new_controls_passed=True,controls=controls,count=len(controls),tested_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
           actual_source_or_map_accessed=False,native_CPU_executed=False,closed_suites_replayed=False)
with(HERE/'new-planning-controls-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
print(json.dumps(proof))
