#!/usr/bin/env python3
"""Review scheduler/compiled-decoder evidence without executing a guest.

Count the final cumulative execution once. Check two earlier saved endpoints
as prefixes. Validate exact code, store EA/value/preimages, explicit initial
ready fixture, compact/full context destinations and task-specific ABI.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct,traceback
from pathlib import Path
from datetime import datetime,timezone
from analyze_native_sections import NativeImage
from verify_os20_allocator_files_v1 import stores_for
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB

ROOT=Path(__file__).resolve().parents[1]
G='staging/native-os20-scheduled-decoder-v1/'
BUILD='staging/native-os20-scheduled-decoder-build-v1/manifest.json'
OUT=ROOT/'staging/native-os20-scheduled-decoder-file-v1'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.load(gzip.open(p,'rt')) if str(p).endswith('.gz') else json.loads(p.read_text())


def main():
    assert not OUT.exists();OUT.mkdir()
    guest=load(ROOT/G/'guest-proof.json');build=load(ROOT/BUILD)
    assert guest['all_passed'] and build['all_passed']
    sources=dict(guest['source_sha256'])
    for p,h in sources.items():assert sha(ROOT/p)==h,p
    for base in [G,'staging/native-os20-scheduled-decoder-build-v1/']:
        terminal=load(ROOT/base/'terminal-tool-receipt.json')['actual_terminal_result']
        assert terminal['exit_code']==0 and 'session_id'not in terminal
        sources[base+'terminal-tool-receipt.json']=sha(ROOT/base/'terminal-tool-receipt.json')
    for c in guest['cases']:assert sha(ROOT/c['path'])==c['sha256']
    d=load(ROOT/guest['cases'][-1]['path'])
    n=NativeImage();parent=load(ROOT/d['parent_checkpoint'])
    assert sha(ROOT/d['parent_checkpoint'])==d['parent_checkpoint_SHA256']
    assert d['parent_allocation_prefix_not_replayed'] and d['initial_ready_membership_is_explicit_bootstrap_fixture']
    assert d['all_three_TCBs_constructed_by_original_code'] and not d['host_context_restore_or_synthetic_return']
    assert not d['device_IO'] and d['MMU_translation_disabled']
    decoders={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    for decoder in decoders.values():decoder.detail=True
    segments=[]
    for path,label in [(build['ELF'],'new_compiled_worker'),(build['decoder_ELF'],'frozen_decoder')]:
        b=(ROOT/path).read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
        for idx in range(h[10]):
            kind,offset,address,_,filesz,memsz,flags,_=struct.unpack_from('<8I',b,h[5]+idx*h[9])
            if kind==1 and flags&1:
                start,end=address&~4095,(address+memsz+4095)&~4095
                payload=bytearray(end-start);payload[address-start:address-start+filesz]=b[offset:offset+filesz]
                segments.append((start,end,label,bytes(payload)))
    replay={name:bytearray.fromhex(value)for name,value in parent['whole_zones_after'].items()}
    byname={z['name']:z for z in d['zones']}
    for name,value in d['initial_new_zone_bytes'].items():
        assert name not in replay;replay[name]=bytearray.fromhex(value)
        z=byname[name]
        if z['original_startup_zero']:
            assert replay[name]==bytes(z['size'])
            assert any(r['runtime_start']<=z['start'] and z['start']+z['size']<=r['runtime_end']for r in n.zeros)

    def region(address,size):
        z=next(z for z in d['zones']if z['start']<=address and address+size<=z['start']+z['size'])
        return replay[z['name']],address-z['start']
    def readbytes(address,size):
        b,o=region(address,size);return bytes(b[o:o+size])
    def word(address):return struct.unpack('<I',readbytes(address,4))[0]
    def fixture(w):
        payload=bytes.fromhex(w['after_hex']);b,o=region(w['address'],len(payload))
        assert b[o:o+len(payload)].hex()==w['before_hex'];b[o:o+len(payload)]=payload
    for w in d['initial_fixture_writes']:fixture(w)
    assert {name:b.hex()for name,b in replay.items()}==d['whole_zones_before']
    assert len(d['initial_fixture_writes'])==9
    assert len(d['bootstrap_and_fixture_events'])==5
    event_index=count=0
    before_states=[];restore_frames=[];destinations=[]
    completed_prefixes=[];pending_restore=None
    prefix_checks={}
    for c in guest['cases'][:-1]:
        p=load(ROOT/c['path']);prefix_checks[len(p['original_and_compiled_instruction_trace'])]=(c,p)
    try:
        for index,t in enumerate(d['original_and_compiled_instruction_trace']):
            while event_index<len(d['bootstrap_and_fixture_events']) and d['bootstrap_and_fixture_events'][event_index]['after_instruction_count']==index:
                fixture(d['bootstrap_and_fixture_events'][event_index]);event_index+=1
            pc,cpsr=t['PC'],t['CPSR'];raw=bytes.fromhex(t['opcode_hex'])
            if t['code_source']=='original_MAIN':assert n.read(pc,len(raw))==raw
            else:
                r=next(r for r in segments if r[0]<=pc and pc+len(raw)<=r[1])
                assert r[2]==t['code_source'] and r[3][pc-r[0]:pc-r[0]+len(raw)]==raw
            ins=next(decoders[bool(cpsr&32)].disasm(raw,pc,count=1))
            assert ins.size==t['size'] and ins.bytes==raw
            before_states.append((pc,t['GP16'],cpsr,t['running_task']))
            if pc==0x358ec4:
                target=word(0xf09090);frame=word(target+12);fmt=readbytes(target+23,1)[0]
                assert target in d['original_TCBs'] and fmt in (0,1)
                words=struct.unpack('<'+('17'if fmt else '13')+'I',readbytes(frame,68 if fmt else 52))
                pending_restore=dict(target=target,frame=frame,format=fmt,words=words,PC=words[1]&~1,restore_instruction=index)
                restore_frames.append(pending_restore)
            if pending_restore and pc==pending_restore['PC']:
                r=pending_restore;values=t['GP16'];words=r['words']
                assert t['running_task']==r['target']
                if r['format']:
                    assert values[:13]==list(words[2:15]) and values[13:15]==list(words[15:17])
                else:
                    assert values[4:13]==list(words[2:11]) and values[13:15]==list(words[11:13])
                assert cpsr==words[0] and pc==words[1]&~1
                destinations.append(dict(target=r['target'],PC=pc,format=r['format'],passed=True))
                pending_restore=None
            for address,size,value in stores_for(ins,t):
                s=d['CPU_stores'][count]
                assert (s['PC'],s['address'],s['size'],s['value'])==(pc,address,size,value),(index,count,hex(pc))
                assert s['GP16']==t['GP16'] and s['CPSR']==cpsr and s['running_task']==t['running_task']
                assert s['opcode_hex']==raw.hex() and s['stage']==t['stage']
                b,o=region(address,size)
                assert b[o:o+size].hex()==s['before_hex'];b[o:o+size]=value.to_bytes(size,'little')
                count+=1
            if index+1 in prefix_checks:
                c,p=prefix_checks[index+1]
                assert p['original_and_compiled_instruction_trace']==d['original_and_compiled_instruction_trace'][:index+1]
                assert p['CPU_stores']==d['CPU_stores'][:count]
                assert p['whole_zones_after']=={name:b.hex()for name,b in replay.items()}
                completed_prefixes.append(dict(path=c['path'],trace_prefix_exact=True,CPU_store_prefix_exact=True,whole_zones_replayed=True))
        assert count==len(d['CPU_stores']) and event_index==5 and len(completed_prefixes)==2
        assert {name:b.hex()for name,b in replay.items()}==d['whole_zones_after']
        # The final native restore reaches an idle observation endpoint before
        # executing its first compiled instruction. Check its captured state.
        assert pending_restore and pending_restore['target']==0x09073f90
        t=d['boundary']['state'];r=pending_restore;values=t['GP16'];words=r['words']
        assert not r['format'] and values[4:13]==list(words[2:11]) and values[13:15]==list(words[11:13])
        assert t['CPSR']==words[0] and t['GP16'][15]==words[1]&~1
        destinations.append(dict(target=r['target'],PC=r['PC'],format=r['format'],passed=True))
        assert len(destinations)==4
        # ABI returns are attributed to the actual resumed CPU task, including
        # the worker POST suspended while the controller WAIT resumes.
        for returned in d['native_full_returns']:
            b,a=returned['before'],returned['after'];task=returned['running_task']
            assert returned['full_ABI_return']
            assert (returned['entry'],b['GP16'],b['CPSR'],task)in before_states
            assert (returned['return_PC'],a['GP16'],a['CPSR'],task)in before_states
            assert b['GP16'][4:12]==a['GP16'][4:12] and b['GP16'][13]==a['GP16'][13]
            assert (b['CPSR']^a['CPSR'])&0xdf==0
            entry_index,return_index=returned['entry_instruction_index'],returned['return_instruction_index']
            assert entry_index<return_index and d['original_and_compiled_instruction_trace'][entry_index]['PC']==returned['entry']
            assert d['original_and_compiled_instruction_trace'][return_index]['PC']==returned['return_PC']
        builders=[r for r in d['native_full_returns']if r['entry']==0x358bf8]
        assert [r['after']['GP16'][0]for r in builders]==[0x0901ff90,0x09073f90,0x183110a0]
        assert d['original_TCBs']==[0x0901ff90,0x09073f90,0x183110a0]
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
        assert readbytes(0x09061000,len(frame))==frame and readbytes(0x09061000+len(frame),4096-len(frame))==b'\xa5'*(4096-len(frame))
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
        assert count==12085 and len(before_states)==89710 and len(d['native_full_returns'])==23
        for c in guest['cases']:sources[c['path']]=c['sha256']
        for p in [Path(__file__),ROOT/G/'guest-proof.json',ROOT/G/'reference.pcm',ROOT/G/'frame.sbc',ROOT/'scripts/verify_os20_allocator_files_v1.py']:
            sources[str(p.relative_to(ROOT))]=sha(p)
        proof=dict(all_passed=True,source_sha256=sources,completed_prefixes=completed_prefixes,
            totals=dict(CPU_stores=count,store_effective_addresses=count,whole_zones=len(replay),
                instructions=len(before_states),native_full_returns=23,native_TCBs=3,
                context_destinations=4,reference_PCM_bytes=256),
            compact_and_extended_context_destinations=destinations,
            original_root_and_compiled_SBC_callback_executed=True,original_decode_output_matches_upstream_fixture=True,
            original_task_specific_post_wait_abis_verified=True,original_kernel_self_exit_unlinked_worker=True,
            kernel_removed_TCB_but_OS20_adapter_and_descriptor_still_present=True,
            original_controller_second_WAIT_still_pending=True,
            allocation_prefix_not_replayed=True,guest_rerun=False,
            initial_ready_membership_fixture_not_real_boot=True,full_nonstore_interpreter=False,
            new_independent_agent_review=False,physical_heap_MMU_DAC_App_or_direct_A2DP_verified=False,
            device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
        with (OUT/'ROOT_FILE-proof-v1.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
        print(json.dumps(dict(all_passed=True,totals=proof['totals'],original_SBC_callback_executed=True,
            OS20_adapter_reclamation_unverified=True)),flush=True)
    except BaseException as e:
        with (OUT/'terminal-failure.json').open('x')as f:json.dump(dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),
            stores_checked=count,completed_prefixes=completed_prefixes,guest_rerun=False),f,indent=2);f.write('\n')
        raise


if __name__=='__main__':main()
