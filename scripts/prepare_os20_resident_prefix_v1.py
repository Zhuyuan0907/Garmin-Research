#!/usr/bin/env python3
"""Seal the completed creation/restore prefix of failed resident guest v1.

No guest executes. Replay exact original store addresses and byte preimages,
stopping before the first compiled controller instruction, before the bad ARM
call. A successor may initialize from that endpoint without rerunning native
TCB creation, named create or bootstrap restore.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,struct
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from probe_os20_resident_music_v1 import Resident
from probe_os20_allocator_v1 import ROOT,RETURN,NativeImage,sha,save,compressed
from probe_os20_scheduled_decoder_v1 import TRACK
from verify_os20_allocator_files_v1 import stores_for
OUT=ROOT/'staging/native-os20-resident-prefix-v1'
G='staging/native-os20-resident-music-v1/'
BUILD='staging/native-os20-resident-music-build-v1/manifest.json'
PARENT='staging/native-os20-allocator-v1/native_OS20_two_allocation_prefix.json.gz'
def main():
    assert not OUT.exists();OUT.mkdir()
    failure=json.load(gzip.open(ROOT/G/'terminal-failure.json.gz','rt'))
    terminal=json.loads((ROOT/G/'terminal-tool-receipt.json').read_text())['actual_terminal_result']
    assert terminal['exit_code']==1 and 'session_id'not in terminal
    assert failure['error']=="('Native controller failure', 6)"
    build=json.loads((ROOT/BUILD).read_text())
    for p,h in build['source_sha256'].items():assert sha(ROOT/p)==h
    assert sha(ROOT/build['ELF'])==build['ELF_sha256']
    parent=json.load(gzip.open(ROOT/PARENT,'rt'));native=NativeImage()
    frames=(ROOT/G/'frames.sbc').read_bytes();refs=(ROOT/G/'reference-two-streams.pcm').read_bytes()
    initializer=Resident(native,parent,build,[frames[i:i+72]for i in range(0,288,72)],
                         [refs[i:i+256]for i in range(0,1024,256)])
    assert len(failure['destinations'])==1
    destination=failure['destinations'][0];limit=destination['instruction_index']
    assert destination['PC']==build['symbols']['resident_controller_v1']['address']
    trace=failure['trace'][:limit]
    assert trace and all(t['code_source']=='original_MAIN'for t in trace)
    replay={name:bytearray.fromhex(value)for name,value in initializer.before.items()}
    zones=initializer.zones
    def locate(address,size):
        zone=next(z for z in zones if z['start']<=address and address+size<=z['start']+z['size'])
        return replay[zone['name']],address-zone['start']
    def fixture(row):
        payload=bytes.fromhex(row['after_hex']);b,offset=locate(row['address'],len(payload))
        assert b[offset:offset+len(payload)].hex()==row['before_hex']
        b[offset:offset+len(payload)]=payload
    decoders={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    for decoder in decoders.values():decoder.detail=True
    fixtures=[f for f in failure['fixture_events']if f['after_instruction_count']<=limit]
    count=event_index=0
    for index,t in enumerate(trace):
        while event_index<len(fixtures)and fixtures[event_index]['after_instruction_count']==index:
            fixture(fixtures[event_index]);event_index+=1
        raw=bytes.fromhex(t['opcode_hex']);assert native.read(t['PC'],len(raw))==raw
        instruction=next(decoders[bool(t['CPSR']&32)].disasm(raw,t['PC'],count=1))
        for address,size,value in stores_for(instruction,t):
            row=failure['CPU_stores'][count]
            assert (row['instruction_index'],row['PC'],row['address'],row['size'],row['value'])==(
                index,t['PC'],address,size,value)
            assert row['GP16']==t['GP16'] and row['CPSR']==t['CPSR']
            b,offset=locate(address,size)
            assert b[offset:offset+size].hex()==row['before_hex']
            b[offset:offset+size]=value.to_bytes(size,'little');count+=1
    assert event_index==len(fixtures)==6
    returns=[r for r in failure['native_full_returns']if r['return_instruction_index']<=limit]
    assert {r['entry_instruction_index']for r in returns}=={i for i,t in enumerate(trace)if t['PC']in TRACK}
    host_endpoints=[]
    for row in returns:
        before,after=row['before'],row['after'];i=row['entry_instruction_index'];j=row['return_instruction_index']
        assert trace[i]['PC']==row['entry'] and trace[i]['GP16']==before['GP16']
        assert before['GP16'][4:12]==after['GP16'][4:12] and before['GP16'][13]==after['GP16'][13]
        assert (before['CPSR']^after['CPSR'])&0xdf==0
        if row['return_PC']==RETURN:
            assert after['GP16'][15]==RETURN
            host_endpoints.append(dict(instruction_index=j,state=after,
                running_task=row['running_task'],source='captured original builder terminal hook'))
        else:
            assert trace[j]['PC']==row['return_PC'] and trace[j]['GP16']==after['GP16']
    assert len(host_endpoints)==2
    tcbs=[r['after']['GP16'][0]for r in returns if r['entry']==0x358bf8]
    assert tcbs==[0x0901ff90,0x09073f90,0x183110a0]
    # The saved native restore endpoint is corroborated by its compact frame.
    state=destination['state'];b,offset=locate(tcbs[0]+12,4)
    frame=struct.unpack('<I',b[offset:offset+4])[0];b,offset=locate(frame,52)
    words=struct.unpack('<13I',b[offset:offset+52])
    assert state['CPSR']==words[0] and state['GP16'][15]==words[1]&~1
    assert state['GP16'][4:13]==list(words[2:11]) and state['GP16'][13:15]==list(words[11:13])
    dependencies=[Path(__file__),ROOT/G/'terminal-failure.json.gz',ROOT/G/'terminal-tool-receipt.json',
        ROOT/G/'frames.sbc',ROOT/G/'reference-two-streams.pcm',ROOT/BUILD,ROOT/build['ELF'],
        ROOT/PARENT,ROOT/'scripts/probe_os20_resident_music_v1.py',
        ROOT/'scripts/probe_os20_scheduled_decoder_v1.py',ROOT/'scripts/probe_os20_allocator_v1.py',
        ROOT/'scripts/verify_os20_allocator_files_v1.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    sources={str(p.relative_to(ROOT)):sha(p)for p in dependencies};sources.update(build['source_sha256'])
    data=dict(all_passed=True,source_sha256=sources,zones=zones,
        whole_zones_before=initializer.before,whole_zones_after={name:b.hex()for name,b in replay.items()},
        initial_new_zone_bytes=initializer.initial_new_zone_bytes,
        initial_fixture_writes=initializer.initial_fixture_writes,
        bootstrap_and_fixture_events=fixtures,original_and_compiled_instruction_trace=trace,
        CPU_stores=failure['CPU_stores'][:count],native_full_returns=returns,
        original_context_restores=failure['restores'],original_context_destinations=[destination],
        original_TCBs=tcbs,worker_task=tcbs[-1],worker_adapter=0x03a1b294,
        boundary=dict(kind='before_first_compiled_controller_instruction',state=state),
        captured_host_terminal_endpoints=host_endpoints,
        creation_bootstrap_prefix_only=True,bad_ARM_CURRENT_call_excluded=True,
        initial_ready_bootstrap_fixture=True,full_nonstore_interpreter=False,
        guest_rerun=False,device_IO=False)
    path=OUT/'creation-bootstrap-prefix.json.gz';compressed(path,data)
    result=dict(all_passed=True,prefix=str(path.relative_to(ROOT)),prefix_sha256=sha(path),
        source_sha256=sources,CPU_store_effective_addresses=count,instructions=limit,
        whole_zones=len(zones),native_full_returns=len(returns),native_TCBs=3,
        original_compact_restore_destination_verified=True,bad_ARM_CURRENT_call_excluded=True,
        guest_rerun=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
    save(OUT/'FILE-prefix-proof.json',result);print(json.dumps({k:result[k]for k in
        ['all_passed','CPU_store_effective_addresses','instructions','native_full_returns','native_TCBs']}),flush=True)
if __name__=='__main__':main()
