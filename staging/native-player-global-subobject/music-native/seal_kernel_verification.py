#!/usr/bin/env python3
"""Pure file-only replay/seal; no VM, compiler or guest rerun."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,struct,difflib,ast
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB

def sha(p):
    h=hashlib.sha256()
    with p.open('rb')as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(d):
    for p,h in d.items():assert sha(ROOT/p)==h,p
def read(p):return json.loads(p.read_text())
def newjson(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
def main():
    assert not (OUT/'verification.json').exists()
    pre=read(OUT/'preflight-v2.json');probe=read(OUT/'kernel-v3/terminal-probe.json');receipt=read(OUT/'kernel-v3/terminal-tool-receipt.json')
    assert receipt['actual_exec_result']['exit_code']==0 and receipt['actual_exec_result']['chunk_id']=='5f5dd2'
    assert probe['completed'] and not probe['error'] and probe['case_count']==7 and len(probe['runs'])==2
    assert len(probe['cases'])==7 and all(c['passed'] for c in probe['cases'])
    check(pre['source_sha256']);check(pre['artifacts_sha256']);check(probe['source_sha256'])
    registry=ROOT/pre['protected_registry'];protected=read(registry)['protected_sources'];assert len(protected)==1274;check(protected)
    assert sha(registry)==pre['protected_registry_sha256']
    runner=OUT/'run_native_owner_kernel_v3.py';snapshot=OUT/'kernel-v3/runner-at-run.py'
    assert sha(runner)==sha(snapshot)==probe['source_sha256'][rel(runner)]
    previous=read(OUT/'kernel-v2/terminal-probe.json');previous_receipt=read(OUT/'kernel-v2/terminal-tool-receipt.json')
    assert not previous['completed'] and previous['case_count']==0 and previous_receipt['actual_exec_result']['exit_code']==1
    assert previous_receipt['actual_exec_result']['chunk_id']=='7f3f61'
    assert previous['error']['message']=='Fetch from non-executable memory (UC_ERR_FETCH_PROT)'
    assert sha(OUT/'run_native_owner_kernel_v2.py')==sha(OUT/'kernel-v2/runner-at-run.py')
    delta=''.join(difflib.unified_diff((OUT/'run_native_owner_kernel_v2.py').read_text().splitlines(True),runner.read_text().splitlines(True),fromfile='frozen kernel-v2 runner',tofile='frozen kernel-v3 runner'))
    # Pure source review binds absence of host CPU-context restoration/native
    # return hooks; declared RAM fixture writes are intentionally present.
    calls={n.func.attr for n in ast.walk(ast.parse(runner.read_text()))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)}
    assert 'context_restore' not in calls and 'context_save' not in calls
    assert 'ret' not in calls
    assert 'self.uc.mem_protect(CODE,4096,unicorn.UC_PROT_ALL)' in runner.read_text()
    assert 'self.uc.mem_protect(RETURN,4096,unicorn.UC_PROT_ALL)' in runner.read_text()
    im=NativeImage();m=read(ROOT/pre['frozen_image_manifest'])
    specpath=ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py'
    import importlib.util
    spec=importlib.util.spec_from_file_location('frozen_ELF_reader',specpath);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    elf=mod.ELF32(ROOT/pre['frozen_image_elf']);publisher=mod.ELF32(ROOT/pre['new_ARM_ET_EXEC'])
    images=[elf,publisher];disasm={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    checks=[];total_cpu=total_fixtures=total_zones=0
    for run in probe['runs']:
        assert run['source']['entered']==1 and not run['source']['finished_on_stack'] and not run['source']['cancel_requested']
        assert run['trace']['service_calls']==run['trace']['publication_observations']==0
        for event in run['kernel_events']:
            pc=int(event['PC'],16);op=bytes.fromhex(event['opcode_hex']);assert im.read(pc,len(op))==op
        for event in run['actor_calls']:
            assert int(event['current'],16)==event['source']['tcb']==run['source']['tcb']
            assert elf.symbol('__source_stack_start')['value']<=int(event['SP'],16)<elf.symbol('__source_stack_end')['value']
        for row in run['whole_RW_zones']:
            before=bytearray.fromhex(row['before_hex']);assert len(before)==row['bytes']
            low=row['start'];events=[e for e in run['journal']if low<=e['address'] and e['address']+e['size']<=low+row['bytes']]
            for event in events:
                o=event['address']-low;n=event['size'];assert before[o:o+n].hex()==event['before_hex']
                before[o:o+n]=bytes.fromhex(event['after_hex'])
                if event['kind']=='CPU':
                    pc=int(event['PC'],16);op=bytes.fromhex(event['opcode_hex']);found=None
                    for image in images:
                        try:found=image.at(pc,len(op))[0];break
                        except AssertionError:pass
                    if found is None:found=im.read(pc,len(op))
                    assert found==op
                    i=next(disasm[event['Thumb']].disasm(op,pc,count=1));assert i.mnemonic+' '+i.op_str==event['instruction']
                    total_cpu+=1
                else:
                    assert event['kind']=='explicit_host_RAM_fixture' and event['reason'];total_fixtures+=1
            assert hashlib.sha256(before).hexdigest()==row['after_sha256'];assert row['whole_replay'];total_zones+=1
        for pc,h in run['immutable_MAIN_pages'].items():assert hashlib.sha256(im.read(int(pc,16),4096)).hexdigest()==h
        assert {0x2fcf44,0x2fd034,0x358ec4,0xf5030,0xf6f26,0x2fbbbe,0x358f08}.issubset({int(e['PC'],16)for e in run['kernel_events']})
        assert all(r['actual_return_r0']==-100 for r in run['control_returns']+run['after_returns'])
        assert all(r['source_at_return']['cancel_requested']==1 for r in run['cancel_returns'])
        checks.append(dict(priority=run['priority'],instructions=run['instructions'],guest_mapped_bytes=run['guest_mapped_bytes'],
            persistent_source_TCB=hex(run['source']['tcb']),source_entry_count=run['source']['entered'],
            original_kernel_opcode_events_verified=len(run['kernel_events']),whole_zones=len(run['whole_RW_zones']),
            compiled_lifecycle_owner_stack_observations=len(run['actor_calls']),actual_cancel_returns=[r['actual_return_r0']for r in run['cancel_returns']],
            attached_adapter_service_calls=run['trace']['service_calls'],file_only_replay_passed=True))
    deps=dict(protected);deps.update(probe['source_sha256']);deps[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
    for p in [OUT/'preflight-v2.json',ROOT/pre['frozen_image_manifest'],ROOT/pre['frozen_image_elf'],ROOT/pre['new_ARM_ET_EXEC'],specpath,ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']:
        deps[rel(p)]=sha(p)
    for p in OUT.glob('*.py'):deps[rel(p)]=sha(p)
    for p in OUT.glob('*.c'):deps[rel(p)]=sha(p)
    artifacts={rel(p):sha(p)for p in OUT.rglob('*')if p.is_file()}
    # Already streamed protected+runtime dependencies above; new sources are
    # local small files and are checked once more immediately before sealing.
    for p in OUT.glob('*.py'):assert sha(p)==deps[rel(p)]
    proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
      scope='bounded_original_kernel_executes_frozen_persistent_music_owner_loop_with_missing_adapter',
      exact_target=pre['exact_target'],source_sha256=deps,artifacts_sha256=artifacts,
      protected_registry=dict(path=rel(registry),sha256=sha(registry),count=1274,streaming_hashes=True,unchanged=True),
      compile_preflight=rel(OUT/'preflight-v2.json'),compile_preflight_sha256=sha(OUT/'preflight-v2.json'),
      actual_tool_receipt=dict(path=rel(OUT/'kernel-v3/terminal-tool-receipt.json'),sha256=sha(OUT/'kernel-v3/terminal-tool-receipt.json'),exit_code=0,chunk_id='5f5dd2',
          wrapper_store_undefined_failed_after_nested_exec=True,warning=receipt['qualification']),
      runtime_proof=rel(OUT/'kernel-v3/terminal-probe.json'),runtime_proof_sha256=sha(OUT/'kernel-v3/terminal-probe.json'),
      native_kernel_groups=probe['cases'],native_kernel_group_count=7,native_instances=2,file_only_replay=checks,
      CPU_store_events_replayed=total_cpu,explicit_fixture_mutations_replayed=total_fixtures,whole_RW_zone_instances_replayed=total_zones,
      failed_history=dict(compile_v1='preserved exact source/command/error; one excess header path parent',
          kernel_v2=dict(actual_exit_code=1,actual_chunk_id='7f3f61',error='UC_ERR_FETCH_PROT',exact_old_fault_PC_captured=False,
              source_and_snapshot_unchanged=True,declared_endpoint_permissions_inference_only=True),
          v3_source_delta=delta,v3_change='Only declared synthetic CODE/RETURN executable permissions, unique output namespace and retained partial constructor object for failure capture'),
      positive_boundaries=dict(original_TCB_ctor_and_F5030_F6F26_bookkeeping_unpatched=True,original_descriptor_registry=True,
          original_irq_metadata_save_restore=True,original_normal_context_post_wait_priority_insertion_context_restore=True,
          source_entry_only_reached_through_original_native_scheduler=True,persistent_entry_once_then_resumed=True,
          compiled_owner_loop_and_coordinator_cancel_and_queue_stop=True,actual_cancel_return_precedes_private_flag_clear_and_after_boundary=True,
          priority3_actual_preemption_restores_compiled_publisher_and_cancel_request_caller=True),
      missing_bindings_and_limits=dict(adapter_attached=False,all_observed_control_and_after_returns=-100,
          producer_busy_pause_release_is_explicit_host_private_RAM_fixture=True,original_DSP_or_live_producer_cancel_success=False,
          declared_channel8_idle_state_not_exclusive_reservation=True,native_ownership_snapshot_and_prepare_session_missing=True,
          real_lease_generation_and_GUI_start_stop_controls_not_integrated=True,STOP_DONE=False,
          native_register_head_source_publication_cleanup_remove_release_and_FIFO_audio_not_executed=True,
          source8_decoder_radio_HFP_boot_not_integrated=True,source9_binding_missing=True,
          initialized_ELF_BSS_is_fixture_and_not_new_single_bootstrap_loader_proof=True,
          no_MAIN_code_patches_no_host_context_restore_no_ABI_spies=True,hardware_IRQ_clock_or_live_task_inventory=False,
          VPM_SIG_or_device_candidate=False,physical_App_icon_touch_A2DP_speaker=False,
          no_unload_or_free_all_stacks_pinned=True,no_device_BT_USB_service_or_sound=True,goal_active=True),
      next_action=dict(native_owner_event_and_cancel_return_preflight_is_now_executed=True,
          required_next_binding='Original native channel8/session reservation and future borrower exclusion must be traced/bound before attached actor START may proceed',
          smaller_offline_next_boundary='Reuse unchanged source loop/kernel fixture with actual existing AV mutex construction/radio profile inventory and decoder/source runtime boot; do not treat idle record or TCB identity as exclusive witness',
          physical_modified_code_acceptance='Native SIG requester/enforcement and accepted modified VPM remain separate unknown gates'))
    newjson(OUT/'verification.json',proof)
    print(json.dumps(dict(verification=rel(OUT/'verification.json'),sha256=sha(OUT/'verification.json'),native_kernel_groups=7,protected=1274,source_count=len(deps),artifact_count=len(artifacts),CPU_stores=total_cpu,fixture_events=total_fixtures,whole_zones=total_zones)))
if __name__=='__main__':main()
