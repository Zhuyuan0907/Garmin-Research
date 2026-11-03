#!/usr/bin/env python3
"""Seal static stop contract and exact existing compiled-gate limitations."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def write(p,obj):
 assert not p.exists(),'New outputs only'
 p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def main():
 proof=HERE/'original-mixer-stop-cleanup-next-contract.json'
 receipt=HERE/'original-mixer-stop-static-terminal-tool-receipt.json'
 supplement=HERE/'existing-compiled-stop-gates-and-link-contract.json'
 ledger=HERE/'original-mixer-stop-static-source-output-ledger.json'
 seal=HERE/'original-mixer-stop-static-seal.json'
 p=json.loads(proof.read_text());r=json.loads(receipt.read_text())
 assert p['all_passed']and p['scope']['static_only']and not p['scope']['guest_executed']
 assert r['actual_tool_result']['exit_code']==0
 emitted=json.loads(r['actual_tool_result']['output'])
 assert emitted['proof']==rel(proof)and emitted['proof_sha256']==sha(proof)
 sources=dict(p['source_sha256'])
 sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
 gate='staging/native-player-mixer-sync/music_session_guard_sync_v1.c'
 driver='staging/native-player-mixer-handoff/audio_session_driver_v4.c'
 owner='staging/native-player-mixer-sync/build-v2/source-snapshot/12-memory_output_session_owner_v4.c'
 build='staging/native-player-mixer-sync/build-v2.json'
 for name in [gate,driver,owner,build]:sources[name]=sha(ROOT/name)
 g=(ROOT/gate).read_text();d=(ROOT/driver).read_text();o=(ROOT/owner).read_text()
 assert 'int mcs_mutation_begin('in g and 'actor(g)!=g->owner || !normal(g)'in g
 assert 'else if(g->borrow || g->native_mutation)result=UMC_PENDING;'in g
 assert 'else g->native_mutation=1;'in g
 assert 'g->control->status.state!=UMC_STOPPED' in g
 assert 'int memory_output_release_session(uint32_t session)'in o
 assert '!g->held || !g->native_mutation || !g->registration_ticket' in o
 assert 'umc_request_stop(&aas_control,&aas_generation)'in d
 assert 'if(r==UMC_PENDING)(void)media_queue_stop();'in d
 b=json.loads((ROOT/build).read_text());symbol_names=['mcs_mutation_begin','mcs_mutation_end',
       'memory_output_release_session','mcs_release_scoped','continuous_media_cancel_ready']
 presence={name:name in b['symbols']for name in symbol_names}
 assert presence==dict(mcs_mutation_begin=False,mcs_mutation_end=False,
          memory_output_release_session=True,mcs_release_scoped=False,continuous_media_cancel_ready=False)
 for name,h in sources.items():assert sha(ROOT/name)==h,name
 write(supplement,dict(all_passed=True,static_only=True,guest_execution=False,
   source_sha256={name:sources[name]for name in [gate,driver,owner,build]},
   existing_source_API={'mcs_mutation_begin':'existingSource owner/normal/held guard; rejects borrow/pendingmutation, marksnative_mutation1',
       'mcs_mutation_end':'Sourceowner releasesmarker aftercompletecleanup transaction',
       'memory_output_release_session':'requiresoldretainedsession/epoch/selectedidentity+held+native_mutation+registrationseed andzero borrowedreaders; checksactualnative provider/method/listidle beforeclear',
       'mcs_release_scoped':'requiresUMC_STOPPED andall private/inflight/providerleases0; nativeboundedMixerFIFO retirement cannotmanufacturethisstate'},
   build_v2_ELF_symbol_presence=presence,
   next_build_requirement='NEW compiled Source calls mustretain/link neededmutation/cancel APIs from existing source. Their names inC source are notcallableentrypoints in frozenbuild-v2 ELF ifGCremoved.',
   completion_distinction={'aas_stop':'requestStop closesnew PLAY/queueadmission butreturnsUMC_PENDING',
       'ordered15_19_20_ACK_and277674':'canproveboundednativeMixer/provider/listretirement afteractualreturns',
       'UMC_native_STOP_DONE':'absent currentadapter path; staySTOP_PENDING/retain scopedguard ownership/module',
       'hardware_or_all_future_callbacks_drained':False},
   no_gate_generation_or_owner_host_seed=True,no_fake_STOP_DONE=True))
 outputs={rel(proof):sha(proof),rel(receipt):sha(receipt),rel(supplement):sha(supplement)}
 stamp=datetime.now(timezone.utc).isoformat()
 write(ledger,dict(all_passed=True,updated_utc=stamp,source_sha256=dict(sorted(sources.items())),
   output_sha256=outputs,actual_file_analysis_chunk='92cd58',actual_file_analysis_exit_code=0,
   guest_execution=False,proof_kind=p['proof_kind']))
 outputs[rel(ledger)]=sha(ledger)
 write(seal,dict(all_passed=True,updated_utc=stamp,source_sha256=dict(sorted(sources.items())),
   output_sha256=outputs,static_analysis_only=True,complete_native_stop_runtime_suite_verified=False,
   guest_execution=False,device_io=False,canonical_writes=False,actual_file_analysis_receipt=rel(receipt),
   actual_file_analysis_exit_code=0,immutable_prior_sources_or_proofs_modified=False))
 for name,h in sources.items():assert sha(ROOT/name)==h,name
 for name,h in outputs.items():assert sha(ROOT/name)==h,name
 for q in [proof,receipt,supplement,ledger,seal,Path(__file__).resolve(),HERE/'analyze_original_stop_cleanup_contract.py']:q.chmod(0o444)
 print(json.dumps(dict(all_passed=True,proof=rel(proof),proof_sha256=sha(proof),
   seal=rel(seal),seal_sha256=sha(seal),ledger_sha256=sha(ledger),
   supplement_sha256=sha(supplement),source_count=len(sources),guest_execution=False)))
if __name__=='__main__':main()
