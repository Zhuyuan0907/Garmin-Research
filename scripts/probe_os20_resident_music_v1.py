#!/usr/bin/env python3
"""Native controller drives one persistent OS20 worker across two streams.

Reuse only the frozen two-allocation endpoint and initializer helpers. Do not
rerun the completed scheduled-decoder guest. After bootstrap entry all ten
command publications, waits, notifications and decoder calls execute in C
tasks through original firmware scheduling; host supplies no command events.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct,traceback
from datetime import datetime,timezone
from pathlib import Path
from probe_os20_scheduled_decoder_v1 import Scheduled,TRACK
from probe_os20_allocator_v1 import *
from emulate_native_sbc import Reference

OUT=ROOT/'staging/native-os20-resident-music-v1'
BUILD='staging/native-os20-resident-music-build-v1/manifest.json'
PARENT='staging/native-os20-allocator-v1/native_OS20_two_allocation_prefix.json.gz'
JOB,FRAME_INPUT,PCM_OUTPUT,RESULT=0x09060000,0x09061000,0x09062000,0x09063000
CONTROLLER,IDLE=0x0901ff90,0x09073f90
FIELDS=('magic controller_tcb adapter observed_argument worker_entries request_seq completed_seq '
    'operation input input_bytes output output_capacity result status active generation wait_returns '
    'notifications notify_returns decode_successes stopped_rejections stops resets event_count '
    'controller_failure controller_finished idle_pulse_request idle_pulse_delivered idle_post_returns '
    'worker_tcb_observed active_start_rejections controller_tcb_observed idle_tcb_observed').split()
assert len(FIELDS)==33


class Resident(Scheduled):
    def __init__(self,native,parent,build,frames,reference):
        compatibility=dict(build,symbols=dict(build['symbols'],
            scheduled_decode_entry_v1=build['symbols']['resident_music_worker_v1'],
            scheduled_idle_v1=build['symbols']['resident_idle_v1']))
        super().__init__(native,parent,compatibility,b''.join(frames),b''.join(reference))
        self.name='NEW_native_controller_persistent_OS20_worker'
        self.actual_build=build
        self.resident_idle_entry=self.idle_entry
        self.idle_entry=-1  # Observe final marker, not idle's first instruction.
        self.controller_entry=build['symbols']['resident_controller_v1']['address']
        self.marker=build['symbols']['resident_idle_checkpoint_v1']['address']
        self.failure_marker=build['symbols']['resident_failure_v1']['address']
        self.controller_entries=[];self.idle_entries=[]
        self.extra_track={self.controller_entry,self.resident_idle_entry}
        initial=[0]*49;initial[0]=0x53425231;initial[1]=CONTROLLER
        patches=[(JOB,struct.pack('<49I',*initial),'NEW_resident_command_object_196_bytes'),
            (INPUT+0x200,struct.pack('<I',self.controller_entry|1),'NEW_native_C_controller_descriptor_entry')]
        for address,payload,reason in patches:
            before=bytes(self.u.mem_read(address,len(payload)))
            self.u.mem_write(address,payload)
            self.initial_fixture_writes.append(dict(address=address,before_hex=before.hex(),
                after_hex=payload.hex(),reason=reason))
        self.before={z['name']:bytes(self.u.mem_read(z['start'],z['size'])).hex()for z in self.zones}

    def code(self,u,address,size,unused):
        if hasattr(self,'failure_marker') and address==self.failure_marker:
            raise AssertionError(('Native controller failure',self.word(JOB+24*4)))
        if hasattr(self,'marker') and address==self.marker:
            assert self.running_task==IDLE
            self.boundary=dict(kind='native_idle_after_two_stopped_streams',PC=address,state=self.snap())
            u.emu_stop();return
        super().code(u,address,size,unused)
        if address in getattr(self,'extra_track',set()):
            state=self.snap()
            self.open_by_task[self.running_task].append(dict(entry=address,before=state,
                return_PC=state['GP16'][14]&~1,phase=self.phase,stage=self.stage,
                running_task=self.running_task,entry_instruction_index=len(self.trace)-1,
                full_ABI_return=False))
            if address==self.controller_entry:self.controller_entries.append(dict(state=state,running_task=self.running_task))
            else:self.idle_entries.append(dict(state=state,running_task=self.running_task))

    def store(self,u,access,address,size,value,unused):
        super().store(u,access,address,size,value,unused)
        self.stores[-1]['instruction_index']=len(self.trace)-1

    def run(self):
        for label,descriptor,expected in [('native_controller_constructor',INPUT+0x200,CONTROLLER),
                                         ('native_idle_constructor',INPUT+0x220,IDLE)]:
            call=self.invoke(label,0x358bf9,(descriptor,),sp=0x0901fd00)
            assert call['full_return'] and call['after']['GP16'][0]==expected
            self.native_tcbs.add(expected)
        for address,payload,reason in [(0xf09090,struct.pack('<I',CONTROLLER),'initial_native_controller_ready_head'),
            (CONTROLLER,struct.pack('<I',IDLE),'initial_controller_to_idle_link'),
            (IDLE,bytes(4),'initial_idle_tail'),(CONTROLLER+22,b'\x01','initial_controller_ready'),
            (IDLE+22,b'\x01','initial_idle_ready')]:self.fixture(address,payload,reason)
        self.running_task=CONTROLLER
        state=self.parent['original_instruction_trace'][-2]
        assert state['PC']==0x521e8c
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        for reg,value in zip(REGS,state['GP16']):self.u.reg_write(reg,value)
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        self.stage=self.phase='NEW_original_named_create_persistent_worker'
        self.done=False
        self.worker_task=(self.parent['payloads']['workspace']+4248-108)&~7
        self.native_tcbs.add(self.worker_task)
        self.u.emu_start(0x521e8d,0,count=500000,timeout=15_000_000)
        assert self.done and not self.boundary
        builder=[r for r in self.native_calls if r['entry']==0x358bf8][-1]
        assert builder['after']['GP16'][0]==self.worker_task
        self.adapter=self.u.reg_read(UC_ARM_REG_R0)
        assert self.adapter==0x03a1b294 and self.word(self.adapter+48)==self.worker_task
        assert self.word(self.adapter+12)==self.worker_entry|1 and self.word(self.adapter+16)==JOB
        # Actual create result is published as a caller input before dispatch.
        self.fixture(JOB+8,struct.pack('<I',self.adapter),'NEW_caller_publication_of_actual_create_return')
        self.stage=self.phase='native_resident_controller_program'
        self.done=False;self.boundary=None
        # Bootstrap invocation only. Original restore loads the native compact
        # controller context; every subsequent transition is guest POST/WAIT.
        print(json.dumps(dict(stage='running_native_controller_two_streams',
            worker_TCB=hex(self.worker_task),host_command_injections=0)),flush=True)
        self.u.emu_start(0x358ec4,0,count=500000,timeout=60_000_000)
        assert self.boundary and self.boundary['kind']=='native_idle_after_two_stopped_streams'
        job_words=struct.unpack('<49I',self.u.mem_read(JOB,196))
        job=dict(zip(FIELDS,job_words[:33]));job['events']=list(job_words[33:])
        assert job['controller_failure']==0 and job['controller_finished']==1
        assert job['worker_entries']==1 and job['observed_argument']==JOB
        assert job['request_seq']==job['completed_seq']==10
        assert job['generation']==job['resets']==job['stops']==2 and job['active']==0
        assert job['wait_returns']==10 and job['notifications']==job['notify_returns']==11
        assert job['decode_successes']==4 and job['stopped_rejections']==job['active_start_rejections']==1
        assert job['worker_tcb_observed']==self.worker_task
        assert job['controller_tcb_observed']==CONTROLLER and job['idle_tcb_observed']==IDLE
        assert job['event_count']==12 and job['events']==[0x400,0x800]+[0x400]*10+[0]*4
        assert job['idle_pulse_request']==job['idle_pulse_delivered']==job['idle_post_returns']==1
        assert bytes(self.u.mem_read(PCM_OUTPUT,1024))==self.reference_pcm
        assert bytes(self.u.mem_read(PCM_OUTPUT+1024,3072))==b'\xa5'*3072
        assert bytes(self.u.mem_read(RESULT+144,4096-144))==b'\xa5'*(4096-144)
        assert bytes(self.u.mem_read(JOB+196,4096-196))==b'\xa5'*(4096-196)
        assert bytes(self.u.mem_read(FRAME_INPUT,288))==self.frame
        assert bytes(self.u.mem_read(FRAME_INPUT+288,4096-288))==b'\xa5'*(4096-288)
        for index in range(4):
            result=struct.unpack('<9I',self.u.mem_read(RESULT+index*36,36))
            assert result[:7]==(72,256,16000,1,128,49,32) and result[7]==0
        all_tasks=[];ptr=self.word(0xf0908c)
        while ptr:
            assert ptr not in all_tasks and len(all_tasks)<4
            all_tasks.append(ptr);ptr=self.word(ptr+40)
        assert set(all_tasks)=={CONTROLLER,IDLE,self.worker_task}
        assert self.word(self.adapter+48)==self.worker_task
        assert self.word(0xf071d0)==1 and self.word(0x014b3ad0)==0x18310008
        assert bytes(self.u.mem_read(self.adapter+64,14*64))==bytes(14*64)
        assert len(self.controller_entries)==len(self.idle_entries)==len(self.worker_entries)==len(self.root_entries)==1
        assert self.worker_entries[0]['state']['GP16'][0]==JOB
        assert self.running_task==IDLE and self.word(0xf09090)==IDLE
        final=self.capture('same_worker_two_streams_Stop_Start_native_waits')
        for key in ('job44_hex','result36_hex','output512_hex'):final.pop(key)
        final.update(source_scope='Native C controller + persistent OS20 SBC command worker',
            job196_hex=bytes(self.u.mem_read(JOB,196)).hex(),job=job,job_field_order=FIELDS,
            result144_hex=bytes(self.u.mem_read(RESULT,144)).hex(),output1024_hex=self.reference_pcm.hex(),
            native_controller_entries=self.controller_entries,native_idle_entries=self.idle_entries,
            current_all_task_list=all_tasks,worker_and_controller_remain_native_waiting=True,
            kernel_self_exit_executed=False,OS20_adapter_reclamation_verified=False,
            host_command_injections_after_dispatch=0,
            compatibility_initializer_symbols={'scheduled_decode_entry_v1':'resident_music_worker_v1',
                'scheduled_idle_v1':'resident_idle_v1'},
            controller_and_idle_are_test_tasks_not_original_boot=True,
            decoder_Stop_not_full_audio_STOP_DONE=True)
        return final


def main():
    assert not OUT.exists();OUT.mkdir()
    build=json.loads((ROOT/BUILD).read_text());assert build['all_passed']
    for p,h in build['source_sha256'].items():assert sha(ROOT/p)==h
    assert sha(ROOT/build['ELF'])==build['ELF_sha256']
    parent=json.load(gzip.open(ROOT/PARENT,'rt'))
    assert sha(ROOT/PARENT)=='22a35d4cf2a451981215453aca7057a773ba414cfd4ae09ffd0cd162aaae137e'
    ref=Reference();frames=ref.encode(dict(frequency=0,blocks=3,subbands=1,mode=0,allocation=0,bitpool=32),frames=4)
    assert all(len(frame)==72 for frame in frames)
    references=ref.decode_stream(frames[:2])+ref.decode_stream(frames[2:])
    assert all(len(pcm)==256 for pcm in references)
    # The new stream has distinct initial synthesis history: a missing reset
    # would yield a different frame2 even though codec format stays the same.
    continuous=ref.decode_stream(frames)
    assert continuous[2]!=references[2]
    (OUT/'frames.sbc').write_bytes(b''.join(frames))
    (OUT/'reference-two-streams.pcm').write_bytes(b''.join(references))
    sources={str(p.relative_to(ROOT)):sha(p)for p in [Path(__file__),ROOT/PARENT,ROOT/BUILD,
        ROOT/build['ELF'],ROOT/'scripts/probe_os20_scheduled_decoder_v1.py',
        ROOT/'scripts/probe_os20_allocator_v1.py',ROOT/'scripts/emulate_native_sbc.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin']}
    sources.update(build['source_sha256'])
    machine=None
    try:
        machine=Resident(NativeImage(),parent,build,frames,references)
        final=machine.run();path=OUT/'resident-native-proof.json.gz';compressed(path,final)
        result=dict(all_passed=True,case=str(path.relative_to(ROOT)),case_sha256=sha(path),
            source_sha256=sources,CPU_stores=len(machine.stores),instructions=len(machine.trace),
            native_full_returns=len(machine.native_calls),context_destinations=len(machine.destinations),
            native_commands=10,streams=2,SBC_frames=4,reference_PCM_bytes=1024,
            worker_entries=1,OS20_adapter_slots_occupied=1,all_three_native_TCBs_resident=True,
            generation_reset_affects_expected_PCM=True,active_START_and_stopped_decode_rejected=True,
            no_host_commands_after_dispatch=True,reference_version=ref.version,
            reference_library=str(ref.library_path),reference_library_SHA256=sha(ref.library_path),
            frames_SHA256=sha(OUT/'frames.sbc'),reference_PCM_SHA256=sha(OUT/'reference-two-streams.pcm'),
            original_scheduler_and_compiled_worker_executed=True,
            allocation_prefix_or_previous_scheduled_guest_rerun=False,
            initial_ready_bootstrap_fixture=True,full_audio_STOP_DONE_or_App_or_direct_A2DP_verified=False,
            device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
        save(OUT/'guest-proof.json',result)
        print(json.dumps({k:result[k]for k in ['all_passed','CPU_stores','instructions','native_full_returns',
            'context_destinations','native_commands','streams','SBC_frames','worker_entries',
            'OS20_adapter_slots_occupied']}),flush=True)
    except BaseException as error:
        data=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),
            source_sha256=sources,device_IO=False)
        if machine:
            data.update(state=machine.snap(),trace=machine.trace,CPU_stores=machine.stores,
                native_full_returns=machine.native_calls,open_by_task=dict(machine.open_by_task),
                restores=machine.restores,destinations=machine.destinations,
                fixture_events=machine.fixture_events,stage=machine.stage,boundary=machine.boundary)
        compressed(OUT/'terminal-failure.json.gz',data);raise
if __name__=='__main__':main()
