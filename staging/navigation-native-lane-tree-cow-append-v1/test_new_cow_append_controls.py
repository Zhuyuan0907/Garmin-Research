#!/usr/bin/env python3
"""New pure append carry/range-patch controls only; no task data or oldmain."""
from pathlib import Path
import importlib.util
import hashlib
import json
import tempfile

HERE=Path(__file__).resolve().parent
path=HERE/'prepare_lane_cow_appends.py'
spec=importlib.util.spec_from_file_location('new_cow_producer_control',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
helperpath=m.PLAN/'plan_lane_tree_overlay.py';need=lambda x,s:None if x else(_ for _ in()).throw(AssertionError(s))
need(hashlib.sha256(helperpath.read_bytes()).hexdigest()==m.HELPER_SHA,'Sealed pure decoder source')
spec2=importlib.util.spec_from_file_location('sealed_cow_control_decode',helperpath);h=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(h)
controls=[]


def check(name,value):need(value,name);controls.append(dict(name=name,passed=True))


def reject(name,fn):
    try:fn()
    except ValueError:controls.append(dict(name=name,passed=True));return
    raise AssertionError(name)


with tempfile.TemporaryDirectory(dir=HERE,prefix='new-small-controls-')as directory:
    for width,count in [(126,3),(68,5),(128,3)]:
        p=Path(directory)/('stream-'+str(width));values=[1|((i+1)<<(width-8))for i in range(count)]
        w=m.TightWriter(p,width)
        for value in values:w.add(value)
        receipt=w.close();raw=p.read_bytes();expected=sum(v<<(i*width)for i,v in enumerate(values)).to_bytes((count*width+7)//8,'little')
        check('tight cross-group carry and final padding stride'+str(width),raw==expected and receipt['bytes']==len(expected))
        check('independent actual bitreader preserves stride'+str(width),[h.extract(raw,i*width,width)for i in range(count)]==values)
    w=m.TightWriter(Path(directory)/'overflow',68);reject('record-width overflow rejected',lambda:w.add(1<<68));w.close()
table=dict(widths=[21,9,24,19,1,9,0,0],reference_flags=[1,1],stride=126)
value=1|(122<<1)|(456<<20)|(100<<39)|(5<<60)|(13<<69)|(1124806<<78)|(5624212<<102)
patched,mask=m.patch_range(value,table,2062754,17,5,13,h.decode);a=h.decode(patched,table)
check('explicit first/count patch preserves raw13 and every other significant bit',(patched^value)&~mask==0 and a['raw_flags']==13 and a['first_child']==2062754 and a['child_count']==17)
reject('unexpected raw flag rejected',lambda:m.patch_range(value,table,1,1,5,5,h.decode))
reject('next-level branch conversion rejected',lambda:m.patch_range(value,table,1,1,6,13,h.decode))
reject('first21 overflow rejected',lambda:m.patch_range(value,table,1<<21,1,5,13,h.decode))
reject('count9 overflow rejected',lambda:m.patch_range(value,table,1,512,5,13,h.decode))
check('copied old parent ordinal follows insertion shifts',m.old_to_new_ordinal(0,[0,1,3])==2 and m.old_to_new_ordinal(1,[0,1,3])==4)
proof=dict(all_new_controls_passed=True,controls=controls,count=len(controls),tested_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    PBF_source_ledgers_maps_geometry_or_native_CPU_accessed=False,historical_suite_replayed=False)
with(HERE/'new-controls-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
print(json.dumps(proof))
