#!/usr/bin/env python3
"""Verify new persistent-task execution from a sealed original restore prefix.

No guest rerun. The already checked 1,826 prefix stores/3,865 instructions are
inherited by exact prefix equality; only the new tail is replayed. Verify
native compact/extended contexts, task-specific ABI returns and the command
ownership/order, including stopped and duplicate START rejection.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct,traceback
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from analyze_native_sections import NativeImage
from verify_os20_allocator_files_v1 import stores_for
ROOT=Path(__file__).resolve().parents[1]
G='staging/native-os20-resident-music-v2/'
BUILD='staging/native-os20-resident-music-build-v2/manifest.json'
PREFIX='staging/native-os20-resident-prefix-v1/FILE-prefix-proof.json'
OUT=ROOT/'staging/native-os20-resident-music-file-v2'
JOB,INPUT,OUTPUT,RESULT=0x09060000,0x09061000,0x09062000,0x09063000
CONTROLLER,IDLE,WORKER=0x0901ff90,0x09073f90,0x183110a0
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.load(gzip.open(p,'rt'))if str(p).endswith('.gz')else json.loads(p.read_text())
def main():
    assert not OUT.exists();OUT.mkdir()
    guest=load(ROOT/G/'guest-proof.json');build=load(ROOT/BUILD);prefix_meta=load(ROOT/PREFIX)
    assert guest['all_passed'] and build['all_passed'] and prefix_meta['all_passed']
    sources=dict(guest['source_sha256'])
    for p,h in sources.items():assert sha(ROOT/p)==h,p
    for base in [G,'staging/native-os20-resident-music-build-v2/',
                 'staging/native-os20-resident-prefix-v1/']:
        terminal=load(ROOT/base/'terminal-tool-receipt.json')['actual_terminal_result']
        assert terminal['exit_code']==0 and 'session_id'not in terminal
        sources[base+'terminal-tool-receipt.json']=sha(ROOT/(base+'terminal-tool-receipt.json'))
    assert sha(ROOT/guest['case'])==guest['case_sha256']
    assert sha(ROOT/prefix_meta['prefix'])==prefix_meta['prefix_sha256']
    d=load(ROOT/guest['case']);prefix=load(ROOT/prefix_meta['prefix'])
    trace=d['original_and_compiled_instruction_trace'];journals=d['CPU_stores']
    start=prefix_meta['instructions'];count=prefix_meta['CPU_store_effective_addresses']
    assert start==3865 and count==1826
    assert trace[:start]==prefix['original_and_compiled_instruction_trace']
    assert journals[:count]==prefix['CPU_stores']
    assert d['zones']==prefix['zones'] and d['whole_zones_before']==prefix['whole_zones_before']
    assert d['initial_fixture_writes']==prefix['initial_fixture_writes']
    assert d['bootstrap_and_fixture_events']==prefix['bootstrap_and_fixture_events']
    assert all(row['after_instruction_count']<start for row in d['bootstrap_and_fixture_events'])
    assert d['declared_frozen_endpoint_GP_CPSR_restore_before_new_C_scope']
    assert not d['host_guest_native_context_switch_substitution']
    assert d['native_creation_and_bootstrap_restore_not_rerun']
    assert d['host_command_injections_after_dispatch']==0
    assert trace[start]['GP16']==prefix['boundary']['state']['GP16']
    assert trace[start]['CPSR']==prefix['boundary']['state']['CPSR']
    native=NativeImage();segments=[]
    for path,label in [(build['ELF'],'new_compiled_worker'),(build['decoder_ELF'],'frozen_decoder')]:
        elf=(ROOT/path).read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',elf)
        for index in range(h[10]):
            kind,offset,address,_,filesz,memsz,flags,_=struct.unpack_from('<8I',elf,h[5]+index*h[9])
            if kind==1 and flags&1:
                begin,end=address&~4095,(address+memsz+4095)&~4095
                payload=bytearray(end-begin);payload[address-begin:address-begin+filesz]=elf[offset:offset+filesz]
                segments.append((begin,end,label,bytes(payload)))
    replay={name:bytearray.fromhex(value)for name,value in prefix['whole_zones_after'].items()}
    def locate(address,size):
        z=next(z for z in d['zones']if z['start']<=address and address+size<=z['start']+z['size'])
        return replay[z['name']],address-z['start']
    def readbytes(address,size):
        b,offset=locate(address,size);return bytes(b[offset:offset+size])
    def word(address):return struct.unpack('<I',readbytes(address,4))[0]
    decoders={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    for decoder in decoders.values():decoder.detail=True
    cache={};pending=None;destinations=list(prefix['original_context_destinations'])
    reset_requests=[];decode_arguments=[];TCB_observations=[]
    try:
        for index in range(start,len(trace)):
            t=trace[index];pc=t['PC'];raw=bytes.fromhex(t['opcode_hex']);mode=bool(t['CPSR']&32)
            if t['code_source']=='original_MAIN':assert native.read(pc,len(raw))==raw
            else:
                segment=next(s for s in segments if s[0]<=pc and pc+len(raw)<=s[1])
                assert segment[2]==t['code_source'] and segment[3][pc-segment[0]:pc-segment[0]+len(raw)]==raw
            key=(mode,pc,raw)
            if key not in cache:cache[key]=next(decoders[mode].disasm(raw,pc,count=1))
            instruction=cache[key];assert instruction.size==t['size']
            if pc==0x358ec4:
                target=word(0xf09090);frame=word(target+12);kind=readbytes(target+23,1)[0]
                assert target in {CONTROLLER,WORKER,IDLE} and kind in (0,1)
                words=struct.unpack('<'+('17'if kind else '13')+'I',readbytes(frame,68 if kind else 52))
                pending=dict(target=target,frame=frame,kind=kind,words=words,PC=words[1]&~1)
            if pending and pc==pending['PC']:
                p=pending;words=p['words'];gp=t['GP16']
                assert t['running_task']==p['target'] and t['CPSR']==words[0]
                if p['kind']:assert gp[:13]==list(words[2:15]) and gp[13:15]==list(words[15:17])
                else:assert gp[4:13]==list(words[2:11]) and gp[13:15]==list(words[11:13])
                destinations.append(dict(target=p['target'],PC=pc,kind=p['kind'],instruction_index=index))
                pending=None
            if pc==0x358d24:
                assert mode, 'Corrected CURRENT helper must enter Thumb code'
                TCB_observations.append(t['running_task'])
            if pc==0x0800223c:
                assert t['running_task']==WORKER and not mode
                reset_requests.append(word(JOB+20))
            if pc==0x08002284:
                assert t['running_task']==WORKER and not mode
                decode_arguments.append(dict(request=word(JOB+20),GP_args=t['GP16'][:4],
                    stack_result=word(t['GP16'][13])))
            for address,size,value in stores_for(instruction,t):
                s=journals[count]
                assert (s['instruction_index'],s['PC'],s['address'],s['size'],s['value'])==(
                    index,pc,address,size,value)
                assert s['GP16']==t['GP16'] and s['CPSR']==t['CPSR']
                assert s['opcode_hex']==raw.hex() and s['running_task']==t['running_task']
                b,offset=locate(address,size);assert b[offset:offset+size].hex()==s['before_hex']
                b[offset:offset+size]=value.to_bytes(size,'little');count+=1
        assert not pending
        assert count==len(journals)==28050
        assert {name:b.hex()for name,b in replay.items()}==d['whole_zones_after']
        assert len(destinations)==len(d['original_context_destinations'])==28
        for actual,declared in zip(destinations,d['original_context_destinations']):
            assert actual['target']==declared['target'] and actual['PC']==declared['PC']
        inherited_returns=prefix['native_full_returns']
        assert d['native_full_returns'][:len(inherited_returns)]==inherited_returns
        new_returns=d['native_full_returns'][len(inherited_returns):]
        assert len(new_returns)==55
        for row in new_returns:
            b,a=row['before'],row['after'];i,j=row['entry_instruction_index'],row['return_instruction_index']
            assert start<=i<j<len(trace)
            assert (trace[i]['PC'],trace[i]['GP16'],trace[i]['CPSR'],trace[i]['running_task'])==(
                row['entry'],b['GP16'],b['CPSR'],row['running_task'])
            assert (trace[j]['PC'],trace[j]['GP16'],trace[j]['CPSR'],trace[j]['running_task'])==(
                row['return_PC'],a['GP16'],a['CPSR'],row['running_task'])
            assert b['GP16'][4:12]==a['GP16'][4:12] and b['GP16'][13]==a['GP16'][13]
            assert (b['CPSR']^a['CPSR'])&0xdf==0 and row['full_ABI_return']
            if row['entry']==0x358d24:
                assert b['CPSR']&32 and a['GP16'][0]==row['running_task']
        assert reset_requests==[1,7]
        assert decode_arguments==[dict(request=q,GP_args=[INPUT+i*72,72,OUTPUT+i*256,256],
            stack_result=RESULT+i*36)for i,q in enumerate([2,4,8,9])]
        assert TCB_observations==[CONTROLLER,WORKER,WORKER,IDLE]
        def field_stores(offset):return [(s['value'],s['running_task'])for s in journals[1826:]
            if s['address']==JOB+offset and s['size']==4]
        assert field_stores(20)==[(i,CONTROLLER)for i in range(1,11)]
        assert field_stores(24)==[(i,WORKER)for i in range(1,11)]
        assert field_stores(28)==[(op,CONTROLLER)for op in [1,2,1,2,3,2,1,2,2,3]]
        assert field_stores(52)==[(status,WORKER)for status in [0,0,0xfffffff0,0,0,0xfffffff5,0,0,0,0]]
        assert field_stores(68)==field_stores(72)==[(i,WORKER)for i in range(1,12)]
        assert readbytes(JOB,196).hex()==d['job196_hex']
        pcm=(ROOT/G/'reference-two-streams.pcm').read_bytes();frames=(ROOT/G/'frames.sbc').read_bytes()
        assert sha(ROOT/G/'reference-two-streams.pcm')==guest['reference_PCM_SHA256']
        assert sha(ROOT/G/'frames.sbc')==guest['frames_SHA256']
        assert readbytes(OUTPUT,1024)==pcm and readbytes(OUTPUT+1024,3072)==b'\xa5'*3072
        assert readbytes(INPUT,288)==frames and readbytes(INPUT+288,3808)==b'\xa5'*3808
        assert readbytes(RESULT+144,3952)==b'\xa5'*3952
        assert readbytes(JOB+196,3900)==b'\xa5'*3900
        for i in range(4):
            result=struct.unpack('<9I',readbytes(RESULT+i*36,36))
            assert result[:7]==(72,256,16000,1,128,49,32) and result[7]==0
        assert replay['private_extent_and_guards'].hex()==prefix['whole_zones_after']['private_extent_and_guards']
        assert word(0xf071d0)==1 and word(0x014b3ad0)==0x18310008
        adapter=d['worker_adapter'];assert word(adapter+48)==WORKER and word(adapter+12)==0x09050001
        assert readbytes(adapter+64,14*64)==bytes(14*64)
        all_tasks=[];pointer=word(0xf0908c)
        while pointer:
            assert pointer not in all_tasks and len(all_tasks)<4
            all_tasks.append(pointer);pointer=word(pointer+40)
        assert set(all_tasks)=={CONTROLLER,WORKER,IDLE} and word(0xf09090)==IDLE
        assert readbytes(CONTROLLER+22,1)==readbytes(WORKER+22,1)==b'\x02'
        assert readbytes(IDLE+22,1)==b'\x01'
        assert [r['entry']for r in d['open_by_task'][str(CONTROLLER)]]==[
            build['symbols']['resident_controller_v1']['address'],0x2fd034]
        assert [r['entry']for r in d['open_by_task'][str(WORKER)]]==[0x521e44,0x09050000,0x2fd034]
        assert [r['entry']for r in d['open_by_task'][str(IDLE)]]==[build['symbols']['resident_idle_v1']['address']]
        assert d['boundary']['PC']==build['symbols']['resident_idle_checkpoint_v1']['address']
        sources[guest['case']]=guest['case_sha256']
        for p in [Path(__file__),ROOT/G/'guest-proof.json',ROOT/G/'frames.sbc',
                  ROOT/G/'reference-two-streams.pcm',ROOT/PREFIX,ROOT/'scripts/verify_os20_allocator_files_v1.py']:
            sources[str(p.relative_to(ROOT))]=sha(p)
        totals=dict(combined_CPU_stores=count,inherited_prefix_stores_verified_once=1826,
            new_tail_store_EA_values_checked=count-1826,whole_zones=len(replay),
            combined_instructions=len(trace),new_tail_instructions=len(trace)-start,
            inherited_full_returns=9,new_full_returns=55,combined_full_returns=64,
            inherited_context_destinations=1,new_context_destinations=27,
            combined_context_destinations=28,native_commands=10,streams=2,
            successful_SBC_frames=4,reference_PCM_bytes=1024,worker_entries=1,OS20_slots_occupied=1)
        proof=dict(all_passed=True,source_sha256=sources,totals=totals,
            completed_creation_prefix_not_replayed=True,new_guest_rerun=False,
            command_store_owner_and_sequence_verified=True,reset_requests=reset_requests,
            decode_arguments=decode_arguments,compact_and_extended_contexts_verified=True,
            no_host_commands_or_switch_substitution_in_new_C_scope=True,
            declared_frozen_endpoint_GP_CPSR_restore_before_new_scope=True,
            stopped_decode_and_active_START_rejections_verified=True,
            worker_remains_same_native_WAIT_task=True,controller_final_WAIT_pending=True,
            native_kernel_self_exit_not_executed=True,OS20_adapter_reclamation_unverified=True,
            decoder_Stop_is_not_full_audio_STOP_DONE=True,
            initial_ready_bootstrap_fixture_not_full_boot=True,full_nonstore_interpreter=False,
            new_independent_agent_review=False,physical_App_DAC_A2DP_verified=False,
            device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
        with (OUT/'ROOT_FILE-proof-v2.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
        print(json.dumps(dict(all_passed=True,totals=totals,physical_App_verified=False)),flush=True)
    except BaseException as error:
        with (OUT/'terminal-failure.json').open('x')as f:json.dump(dict(all_passed=False,
            error=str(error),traceback=traceback.format_exc(),stores_checked=count,
            inherited_prefix_count=1826,new_guest_rerun=False),f,indent=2);f.write('\n')
        raise
if __name__=='__main__':main()
