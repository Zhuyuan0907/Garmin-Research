#!/usr/bin/env python3
"""File-only V1 partial scopes; missing inherited actual-after capture retained."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json
from file_verifier_common import *
OUT=BASE+'verification/native-public-heap-partial-journals.json'

def main():
    meta,probe,prefix=seal_inputs();r=Replay()
    require(probe['callback_entry_seen']and not probe['callback_return_seen'],'Actual bounded Dispatcher body attempt status')
    require(probe['partial_inherited_zone_verification']=={'passed':False,'error':'First/same native FP owner differs'},
      'V1 inherited terminal scope failure must remain explicit')
    body=probe['partial_body_zone_verification'];fp=probe['partial_FP_zone_verification']
    require(isinstance(body,list)and len(body)==7 and isinstance(fp,list)and len(fp)==8,'Actual7body/8FP after scopes required')
    bodyproof=[r.replay(z)[1]for z in body];fpproof=[r.replay(z)[1]for z in fp]
    bank=probe['partial_initialized_bank_verification'];_,bankproof=r.replay(bank,probe['mutable_bank_initial_before_hex'])
    require(bank['whole_bank_matches_original_CPU_write_history']and not bank['host_unrecorded_mutation']and bankproof['bytes']==467532,
      'Actual whole initialized-data bank47x replay')
    guards=probe['terminal_native_public_heap_guards'];require(guards['all_passed'],'Actual new public terminal net guards absent')
    public=[]
    for entry in guards['whole_zones']:
        z=probe['journal_zones'][str(int(entry['start'],16))]
        public.append(r.replay(z,after_sha256=entry['after_sha256'])[1])
    require(len(public)==2,'Two newpublic whole terminal zones')
    # Replaying before+stores alone is not an actual final-memory witness. V1
    # lost the computed inherited return value when its later owner check raised.
    unsealed=[]
    for z in probe['journal_zones'].values():
        _,v=r.replay(z,require_actual=False);unsealed.append(v)
    require(len(unsealed)==24 and all(not e['recorded_actual_after_SHA_available']for e in unsealed),
      'Do not retroactively synthesize V1 inherited terminal actual-after hashes')
    s=probe['body_actor_observations']['native_allocation_observer'];a=s['pending']
    require(len(s['allocations'])==1 and a==s['allocations'][0]and len(s['raw_ops'])==0,
      'V1 actual single intercepted allocation attempt, zero native raw scopes')
    require(not any(a[k]for k in ['lower_return_seen','query_return_seen','actual_original_caller_return_seen','prefix_store_seen']),
      'V1 must not claim native malloc/query/prefix success')
    require(a['native_handle']is None and a['native_pointer']is None and not a['heap_stores']and not a['TCB_stores'],
      'No native allocation descriptor/payload/TCB stores were observed')
    require(probe['registers']=={'r0':'0x88246a0','r1':'0xf09098','r2':'0x8804058','r3':'0xea60',
      'lr':'0x395535','pc':'0x395534','sp':'0x8803fb0'},'Actual inherited provider return/current guard boundary')
    # There is no claimed all-zone or all-parent mutation reconstruction. Only
    # the sealed scopes above have a recorded actual after SHA to compare.
    here=str(Path(__file__).resolve().relative_to(ROOT))
    doc=dict(all_passed=True,source_sha256=sources(meta,here,r.companion_path),verified_runtime_dependencies=meta['source_sha256'],**fields(meta),
      actual_body_whole_zone_replays=bodyproof,actual_FP_whole_zone_replays=fpproof,
      actual_initialized_bank_replay=bankproof,actual_newpublic_whole_zone_replays=public,
      inherited_terminal_scope_passed=False,actual_inherited_terminal_scope_failure=probe['partial_inherited_zone_verification'],
      inherited_terminal_actual_after_snapshots_missing=True,full_inherited_terminal_whole_zone_replay_verified=False,
      inherited_before_plus_CPU_history_only=unsealed,
      computed_history_hashes_are_not_actual_terminal_memory_SHA=True,
      CPU_store_event_counts=r.counts,counts_include_overlapping_zone_observations=True,
      actual_allocation_attempts=1,actual_native_malloc_raw_operations=0,actual_native_48_8_return_verified=False,
      actual_host_allocator_return_pointer='0x88246a0',inherited_host_provider_was_used=True,
      actual_allocator_guard_boundary=probe['registers'],host_substitution_local_false_is_not_wholepipeline_verified=False,
      scope='Independent7body/8FP/467532bank/new2public recorded actual final SHA checks pass. All24 inherited CPU histories are reproducible but their terminal actual-after snapshots are absent because V1 later virtual FP owner check failed; no full inherited terminal net-memory claim. Original native malloc48/8 did not execute.')
    dump(OUT,doc);print(json.dumps(dict(all_passed=True,body_zones=7,FP_zones=8,bank_bytes=467532,newpublic_zones=2,
      inherited_actual_after_scope=False,native48_8_return_verified=False)))
if __name__=='__main__':main()
