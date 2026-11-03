#!/usr/bin/env python3
"""Output-only fresh finite audit. Does not open IMG/MAIN or replay CPU."""
import datetime,hashlib,json,re
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def key(s):
    m=re.fullmatch(r'([1-9][0-9]*)(?:之([1-9][0-9]*))?號',s)
    need(m is not None,'Finite strictly parsed house label')
    # Explicit independent model for these observed cases, not a global comparator replacement.
    return int(m[1]),(0,int(m[2])) if m[2] else (1,0)
def main():
    need(not (HERE/'output-audit.json').exists(),'Do not overwrite terminal output')
    raw=(HERE/'proof.json').read_bytes();p=json.loads(raw)
    need(sha(raw)=='9068f429268ed1cb843cec8629677f5f911384a635a61dbd86f3bd6cbb144a7d','Actual proof pin')
    need(p['all_assigned_checks_passed'] and p['actual_IMG_read_bytes']==164676 and len(p['new_original_prefix_cases'])==20 and len(p['numeric_comparisons'])==21,'Actual bounded totals')
    cases=p['new_original_prefix_cases'];seen=set()
    for c in cases:
        seen.add((c['level'],c['lowID']));shift=c['initial_bit_offset'];stride=c['record_bits']
        raw=bytes.fromhex(c['real_candidate_span_hex']);v=(int.from_bytes(raw,'little')>>shift)&((1<<stride)-1)
        need(v.to_bytes((stride+7)//8,'little').hex()==c['significant_wire_record_normalized_for_comparison_hex'],'Actual true packed slice normalization')
        need(len(bytes.fromhex(c['real_following_4byte_lookahead_hex']))==4 and c['filesystem_mapping']['record_fixture_realigned']==False and c['filesystem_mapping']['tail_at_unmapped_page'],'True spans/lookahead/guard')
        need(c['stop_before_metadata']=='0x0448F740' and not c['full_original_reader_return'],'Finite prefix boundary')
    need(len(seen)==20 and {x[0] for x in seen}=={4,5,6},'Twenty distinct original small samples')
    compares=[]
    for c in p['numeric_comparisons']:
        a=key(c['left']['label']);b=key(c['right']['label']);expect=1 if a<b else 2 if a>b else 0
        need(c['native_body_result']==expect,'Independent finite pair ordering disagreement')
        need(c['entry']=='0x044B19FC' and c['stop']=='0x044B1E9C' and not c['getter_executed'] and c['successful_getter_return_not_hooked'],'No full getter fabrication')
        need(bytes.fromhex(c['left']['raw_hex']).rstrip(b'\0').decode('cp950')==c['left']['label'] and bytes.fromhex(c['right']['raw_hex']).rstrip(b'\0').decode('cp950')==c['right']['label'],'Source-backed CP950 bytes')
        compares.append(dict(left=c['left']['label'],right=c['right']['label'],actual=c['native_body_result'],independent_finite_model=expect))
    r=p['raw13'];need(r['original_record']['ID']==1287044 and r['original_record']['fields']['+04']==13 and r['original_record']['label']['label']=='88巷','Actual stock raw13')
    need(r['actual_single_child']['ID']==1417151 and r['actual_single_child']['label']['label']=='+ 交叉路口 +' and r['actual_single_child']['fields']['+04']==6,'Actual bounded raw13 child witness')
    for dep in p['dependencies']:
        dp=ROOT/dep['path'];need(sha(dp.read_bytes())==dep['sha256'],'Frozen method/evidence pin');need(not dep['old_main_or_cases_executed'],'No old suite replay')
    result=dict(schema='garmin-native-stock-subnumber-output-audit/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),all_assigned_checks_passed=True,audit_source_sha256=sha(Path(__file__).read_bytes()),actual_proof_sha256=sha((HERE/'proof.json').read_bytes()),distinct_original_prefix_cases=20,independently_checked_pairs=compares,
                original_AP_MAIN_or_candidate_opened=False,CPU_replayed=False,device_IO=False,finite_model_not_global_comparator=True,full_query_verified=False)
    out=HERE/'output-audit.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(out.relative_to(ROOT)),sha256=sha(out.read_bytes()),all_assigned_checks_passed=True,new_CPU_or_IMG_reads=0)))
if __name__=='__main__':main()
