#!/usr/bin/env python3
"""Finish ABI/end-state review, retaining v1's completed store/prefix checks.

The v1 review checked every store, whole-zone replay and context destinations,
then failed because stopped host-return sentinels have no next instruction.
Do not rerun those completed checks. Validate the captured host endpoints as
well as instruction endpoints, and finish the remaining semantic scope.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct,traceback
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
G='staging/native-os20-scheduled-decoder-v1/'
V1='staging/native-os20-scheduled-decoder-file-v1/'
OUT=ROOT/'staging/native-os20-scheduled-decoder-file-v2'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.load(gzip.open(p,'rt')) if str(p).endswith('.gz') else json.loads(p.read_text())

def main():
    assert not OUT.exists();OUT.mkdir()
    guest=load(ROOT/G/'guest-proof.json')
    failed=load(ROOT/V1/'terminal-failure.json')
    terminal=load(ROOT/V1/'terminal-tool-receipt.json')['actual_terminal_result']
    assert terminal['exit_code']==1 and 'session_id'not in terminal
    assert 'returned[\'return_PC\']'in terminal['output']
    assert failed['stores_checked']==12085 and len(failed['completed_prefixes'])==2
    assert not failed['guest_rerun']
    assert 'line 141' in failed['traceback']
    source=(ROOT/'scripts/verify_os20_scheduled_decoder_files_v1.py').read_text()
    assert source.splitlines()[140].strip()=="assert (returned['return_PC'],a['GP16'],a['CPSR'],task)in before_states"
    # Source and terminal route prove the store/prefix/context assertions
    # before that line completed. Only return-sentinel admission was missing.
    assert "assert count==len(d['CPU_stores'])"in source
    assert "assert len(destinations)==4"in source
    sources=dict(guest['source_sha256'])
    for p,h in sources.items():assert sha(ROOT/p)==h,p
    for c in guest['cases']:
        assert sha(ROOT/c['path'])==c['sha256'];sources[c['path']]=c['sha256']
    d=load(ROOT/guest['cases'][-1]['path'])
    trace=d['original_and_compiled_instruction_trace']
    before_states=[(t['PC'],t['GP16'],t['CPSR'],t['running_task'])for t in trace]
    endpoints=[]
    for call in d['host_calls']:
        if not call['full_return']:continue
        task=0 if call['stage']in {'native_controller_constructor','native_idle_constructor'} else 0x0901ff90
        a=call['after']
        assert a['GP16'][15]==0x09000000
        endpoints.append((a['GP16'][15],a['GP16'],a['CPSR'],task))
    assert len(endpoints)==3
    final=d['boundary']['state']
    states=before_states+endpoints+[(final['GP16'][15],final['GP16'],final['CPSR'],d['running_task'])]
    try:
        for r in d['native_full_returns']:
            b,a=r['before'],r['after'];task=r['running_task']
            assert r['full_ABI_return']
            assert (r['entry'],b['GP16'],b['CPSR'],task)in before_states
            assert (r['return_PC'],a['GP16'],a['CPSR'],task)in states
            assert b['GP16'][4:12]==a['GP16'][4:12] and b['GP16'][13]==a['GP16'][13]
            assert (b['CPSR']^a['CPSR'])&0xdf==0
            i,j=r['entry_instruction_index'],r['return_instruction_index']
            assert i<j and trace[i]['PC']==r['entry']
            if r['return_PC']==0x09000000:
                assert (r['return_PC'],a['GP16'],a['CPSR'],task)in endpoints
            else:assert trace[j]['PC']==r['return_PC']
        zones={z['name']:z for z in d['zones']}
        final_bytes={name:bytes.fromhex(b)for name,b in d['whole_zones_after'].items()}
        def readbytes(address,size):
            z=next(z for z in d['zones']if z['start']<=address and address+size<=z['start']+z['size'])
            return final_bytes[z['name']][address-z['start']:address-z['start']+size]
        def word(address):return struct.unpack('<I',readbytes(address,4))[0]
        builders=[r for r in d['native_full_returns']if r['entry']==0x358bf8]
        assert [r['after']['GP16'][0]for r in builders]==[0x0901ff90,0x09073f90,0x183110a0]
        assert d['original_TCBs']==[0x0901ff90,0x09073f90,0x183110a0]
        restore_indices=[i for i,t in enumerate(trace)if t['PC']==0x358ec4]
        assert len(restore_indices)==4
        assert all(r['return_instruction_index']<restore_indices[0]for r in builders)
        assert [(r['target'],r['PC'])for r in d['original_context_destinations']]==[
            (0x183110a0,0x521e44),(0x0901ff90,0x2fd0ac),(0x183110a0,0x2fd016),(0x09073f90,0x0905004c)]
        assert len(d['original_root_entries'])==len(d['compiled_worker_entries'])==1
        assert d['compiled_worker_entries'][0]['state']['GP16'][0]==0x09060000
        assert d['compiled_worker_entries'][0]['running_task']==d['worker_task']==0x183110a0
        assert word(d['worker_adapter']+12)==0x09050001 and word(d['worker_adapter']+16)==0x09060000
        assert word(d['worker_adapter']+48)==d['worker_task']
        expected=(ROOT/G/'reference.pcm').read_bytes();frame=(ROOT/G/'frame.sbc').read_bytes()
        assert sha(ROOT/G/'reference.pcm')==guest['reference_PCM_SHA256']
        assert sha(ROOT/G/'frame.sbc')==guest['reference_frame_SHA256']
        assert expected.hex()==d['reference_PCM_hex'] and frame.hex()==d['frame_input_hex']
        assert readbytes(0x09062000,len(expected))==expected and len(expected)==256
        assert readbytes(0x09062000+256,4096-256)==b'\xa5'*(4096-256)
        assert readbytes(0x09061000,len(frame))==frame
        assert readbytes(0x09061000+len(frame),4096-len(frame))==b'\xa5'*(4096-len(frame))
        result=struct.unpack('<9I',readbytes(0x09063000,36))
        assert result[:7]==(72,256,16000,1,128,49,32) and result[7]==0
        assert word(0x09060000+24)==0x09060000 and word(0x09060000+28)==1
        assert word(0x09060000+32)==0 and word(0x09060000+40)==1
        assert word(0xf09090)==0x09073f90
        all_tasks=[];ptr=word(0xf0908c)
        while ptr:
            assert ptr not in all_tasks and len(all_tasks)<4
            all_tasks.append(ptr);ptr=word(ptr+40)
        assert set(all_tasks)=={0x0901ff90,0x09073f90}
        assert word(0xf071d0)==1 and word(0x014b3ad0)==0x18310008
        assert len(d['open_by_task'][str(0x0901ff90)])==1
        assert d['open_by_task'][str(0x0901ff90)][0]['entry']==0x2fd034
        assert not d['open_by_task'][str(0x183110a0)]
        assert len(d['CPU_stores'])==12085 and len(trace)==89710 and len(d['native_full_returns'])==23
        for p in [Path(__file__),ROOT/'scripts/verify_os20_scheduled_decoder_files_v1.py',ROOT/V1/'terminal-tool-receipt.json',
            ROOT/V1/'terminal-failure.json',ROOT/G/'guest-proof.json',ROOT/G/'terminal-tool-receipt.json',ROOT/G/'reference.pcm',ROOT/G/'frame.sbc']:
            sources[str(p.relative_to(ROOT))]=sha(p)
        proof=dict(all_passed=True,source_sha256=sources,completed_store_scope_in_failed_v1_preserved=True,
            completed_prefixes=failed['completed_prefixes'],v1_failure_route='missing stopped host-return endpoint at ABI check',
            totals=dict(CPU_stores=12085,store_effective_addresses=12085,whole_zones=18,
                instructions=89710,native_full_returns=23,native_TCBs=3,context_destinations=4,reference_PCM_bytes=256),
            v2_verified_scopes=['task-specific instruction and host-sentinel ABI returns','native root/decoder job argument',
                'PCM reference equality and whole output/input guards','native exit removes worker from all-task list',
                'remaining OS20 adapter and descriptor registry entries','controller second WAIT still pending'],
            compact_and_full_restore_frames_checked_by_completed_v1=True,
            original_root_and_compiled_SBC_callback_executed=True,original_task_specific_POST_WAIT_ABIs_verified=True,
            original_kernel_self_exit_unlinked_worker=True,kernel_removed_TCB_but_OS20_adapter_and_descriptor_still_present=True,
            original_controller_second_WAIT_still_pending=True,
            store_replay_or_completed_prefix_checks_repeated_in_v2=False,guest_rerun=False,
            initial_ready_membership_fixture_not_real_boot=True,full_nonstore_interpreter=False,
            new_independent_agent_review=False,physical_heap_MMU_DAC_App_or_direct_A2DP_verified=False,
            device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
        with (OUT/'ROOT_FILE-proof-v2.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
        print(json.dumps(dict(all_passed=True,totals=proof['totals'],ABI_returns=23,
            completed_v1_store_checks_not_rerun=True,OS20_adapter_reclamation_unverified=True)),flush=True)
    except BaseException as e:
        with (OUT/'terminal-failure.json').open('x')as f:json.dump(dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),guest_rerun=False),f,indent=2);f.write('\n')
        raise

if __name__=='__main__':main()
