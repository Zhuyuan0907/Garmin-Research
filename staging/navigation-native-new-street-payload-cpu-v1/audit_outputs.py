#!/usr/bin/env python3
"""New output-only exact semantic/source binding audit, no CPU/map replay."""
import datetime,hashlib,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def main():
    out=HERE/'output-audit.json';need(not out.exists(),'New terminal audit only')
    raw=(HERE/'proof.json').read_bytes();need(sha(raw)=='ecd6fe017cbf1149a4c0420b3cb1c8a2bfba0abf86189a05f51d6167f34ed574','Actual proof pin');p=json.loads(raw)
    expected=[(2,74,47871,442,3,24067,24068,1126994,5624389),(3,48312,4896237,1,4,475679,0xffffffff,1127253,5625400),(4,4896237,0,0,0,2967,0xffffffff,1127253,5625400)]
    need(p['all_assigned_checks_passed'] and p['new_original_prefix_case_count']==3 and p['new_proposed_LBL_fragment_case_count']==1 and p['actual_candidate_IMG_bytes_read']==0 and not p['device_IO'],'Finite truthful scope totals')
    dirbytes=bytes.fromhex(p['proposed_native_directory_hex']);need(struct.unpack_from('<I',dirbytes)[0]==6 and len(dirbytes)==172,'Proposed native directory fixture')
    for c,e in zip(p['new_original_prefix_cases'],expected):
        f=c['actual_original_native_fields'];actual=(c['level'],c['lowID'],f['+00'],f['+0c'],f['+04'],f['+10'],f['+1c'],f['+14'],f['+18']);need(actual==e and f['+08']==1,'Independent bounded semantic contract')
        need(c['actual_original_native_fields']==c['independent_expected_native_fields'] and c['stop_before_metadata']=='0x0448F740' and not c['full_getter_or_query_return'],'Native prefix boundary')
        count,stride,start,span=struct.unpack_from('<4I',dirbytes,4+(c['level']-1)*28);bit=(c['lowID']-1)*stride
        need(1<=c['lowID']<=count and c['proposed_MDR_offset']==start+bit//8 and c['initial_bit_shift']==bit%8,'Independent proposed seek/bit arithmetic')
        need(c['FS_fixture']['source_is_proposed_payload'] and c['FS_fixture']['readonly_fixture_tail_at_unmapped_page'] and c['FS_fixture']['four_following_bytes_are_explicit_canaries'],'Explicit proposed input/guard/following bytes')
        need(len(bytes.fromhex(c['four_explicit_following_canary_bytes_hex']))==4,'Four explicit canaries')
    t=p['new_proposed_LBL_address_and_bytecopy'];need(t['actual_GMP_offset']==3812824+475679*8==7618256 and t['host_CP950_display_of_actual_native_output']=='敦富六街' and t['actual_byte_copy_and_termination_passed'],'One new proposed LBL contract')
    need(bytes.fromhex(t['actual_original_output_hex'])=='敦富六街'.encode('cp950')+b'\0\0','Source-bound new CP950 text')
    mixed=p['L2_mixed_bits'];old=int.from_bytes(bytes.fromhex(mixed['original_window_hex']),'little');new=int.from_bytes(bytes.fromhex(mixed['proposed_window_hex']),'little');mask=((1<<122)-1)<<2
    need((old^new)&~mask==0 and mixed['initial_shift']==2,'Independent mixed-window neighbor bit preservation')
    for d in p['dependencies']:need(sha((ROOT/d['path']).read_bytes())==d['sha256'] and not d['old_main_or_cases_executed'],'Pinned small source or function binding')
    result=dict(schema='garmin-proposed-new-street-output-audit/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_sha256=sha(Path(__file__).read_bytes()),actual_proof_sha256=sha(raw),all_assigned_checks_passed=True,new_CPU_map_or_MAIN_reads=0,three_independent_semantic_contracts_verified=True,new_label_CP950_bytes_verified=True,L2_neighbor_bits_verified=True,actual_candidate_or_device_not_opened=True,full_query_verified=False)
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(output=str(out.relative_to(ROOT)),sha256=sha(out.read_bytes()),all_assigned_checks_passed=True,new_CPU_or_IMG_reads=0)))
if __name__=='__main__':main()
