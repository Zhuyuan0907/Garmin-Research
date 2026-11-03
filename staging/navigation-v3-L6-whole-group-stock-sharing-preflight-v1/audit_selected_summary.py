#!/usr/bin/env python3
"""Audit own finite summary only. Preserve actual universal-predicate counterexamples."""
import hashlib,json,zlib
from pathlib import Path
BASE=Path(__file__).resolve().parent;RAW_CAP=6291456;DEC_CAP=67108864
raw_count=4890625;dec_count=25656713
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 global raw_count,dec_count
 before=st(p);assert raw_count+before[2]<=RAW_CAP
 b=p.read_bytes();raw_count+=len(b);assert st(p)==before;return b,before
b,_=read(BASE/'proof.json');dec_count+=len(b);proof=json.loads(b);spec=proof['selected_summary']
p=BASE/'selected-L6-group-summary.jsonl.gz';compressed,before=read(p)
assert len(compressed)==spec['compressed_bytes'] and dec_count+spec['uncompressed_bytes']+1<=DEC_CAP
d=zlib.decompressobj(31);decoded=d.decompress(compressed,spec['uncompressed_bytes']+1)
dec_count+=len(decoded);assert d.eof and not d.unused_data and not d.unconsumed_tail
assert len(decoded)==spec['uncompressed_bytes'] and hashlib.sha256(decoded).hexdigest()==spec['uncompressed_SHA256']
rows=decoded.splitlines();assert len(rows)==4676
exceptions=[];total=0;mixed=0
for line in rows:
 r=json.loads(line);total+=r['new_count']
 if r['stockhit0_rows']==0:exceptions.append(r)
 else:mixed+=1
assert total==78705 and mixed==4674 and len(exceptions)==2
remaining_v3=sum(r['new_count'] for r in exceptions);loose_upper=10750+remaining_v3
result={'schema':'own-summary-audit-and-optimistic-complete-group-bound/v1','actual_universal_predicate_all_v3_groups_have_stockhit0':False,
 'actual_allstockmatched_groups':exceptions,'actual_allstockmatched_group_rows':remaining_v3,'mixed_groups':mixed,
 'wholegroup_optimistic_savings_bound':{'all_v2_poststock_rows_assumed_savable':10750,'all_counterexample_v3_group_rows_assumed_savable':remaining_v3,
  'sum':loose_upper,'required':71359,'insufficient':loose_upper<71359,'assumptions':'Sharing only complete emitted v3 L6 groups into identical originalstock ordered ranges; mixedgroups kept intact. Both counterexamples treated wholly reusable even though donor contiguity not proved. No partialgroups/inplace edits/newencoding or runtimeincoming proof.'},
 'selected_summary_actual_read_pin':{'path':str(p.relative_to(Path('/root/garmin'))),'bytes':len(compressed),'SHA256':hashlib.sha256(compressed).hexdigest(),
  'decoded_bytes':len(decoded),'decoded_SHA256':hashlib.sha256(decoded).hexdigest(),'stat_before':before,'stat_after':st(p)},
 'actual_post_audit_raw_artifact_read_bytes':raw_count,'actual_post_audit_decoded_artifact_bytes':dec_count,'raw_cap':RAW_CAP,'decoded_cap':DEC_CAP,
 'no_sourceledger_or_IMG_reread':True,'no_original_predicate_or_guard_changed':True,'immutable_counterexample_contiguity_and_external_runtime_refs_held':True}
(BASE/'own-summary-audit-and-bound.json').write_text(json.dumps(result,separators=(',',':'))+'\n')
print(json.dumps({'ownsummary_audit_completed':True,'counterexamples':[{k:r[k] for k in ['new_first','new_count','new_integer_leaf_count','stockhit0_rows']} for r in exceptions],
 'additional_v3_rows_optimistically_savable':remaining_v3,'loose_wholegroup_bound':loose_upper,'required':71359,
 'route_bound_insufficient_conditionally':loose_upper<71359,'actual_raw_artifact_read_bytes':raw_count,'actual_decoded_artifact_bytes':dec_count,'IMGread':0}),flush=True)
