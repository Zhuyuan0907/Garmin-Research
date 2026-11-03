#!/usr/bin/env python3
"""Native controller drives one persistent OS20 worker across two streams.

Resume a verified native creation/restore endpoint, excluding the bad ARM call. Do not
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

OUT=ROOT/'staging/native-os20-resident-music-v2'
BUILD='staging/native-os20-resident-music-build-v2/manifest.json'
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
        prefix_manifest=json.loads((ROOT/'staging/native-os20-resident-prefix-v1/FILE-prefix-proof.json').read_text())
        assert prefix_manifest['all_passed']
        prefix_path=ROOT/prefix_manifest['prefix']
        assert sha(prefix_path)==prefix_manifest['prefix_sha256']
        prefix=json.load(gzip.open(prefix_path,'rt'))
        assert prefix['whole_zones_before']==self.before
        assert prefix['initial_fixture_writes']==self.initial_fixture_writes
        for p,h in prefix_manifest['source_sha256'].items():assert sha(ROOT/p)==h
        old_build=json.loads((ROOT/'staging/native-os20-resident-music-build-v1/manifest.json').read_text())
        for symbol in ['resident_music_worker_v1','resident_controller_v1','resident_idle_v1']:
            assert self.actual_build['symbols'][symbol]['address']==old_build['symbols'][symbol]['address']
        for zone in self.zones:
            self.u.mem_write(zone['start'],bytes.fromhex(prefix['whole_zones_after'][zone['name']]))
        self.trace=list(prefix['original_and_compiled_instruction_trace'])
        self.stores=list(prefix['CPU_stores'])
        self.native_calls=list(prefix['native_full_returns'])
        self.fixture_events=list(prefix['bootstrap_and_fixture_events'])
        self.native_tcbs=set(prefix['original_TCBs'])
        self.worker_task=prefix['worker_task'];self.adapter=prefix['worker_adapter']
        self.restores=list(prefix['original_context_restores'])
        self.destinations=list(prefix['original_context_destinations'])
        self.captured_prefix_host_endpoints=prefix['captured_host_terminal_endpoints']
        self.running_task=CONTROLLER;self.pending_restore=None
        state=prefix['boundary']['state']
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        for reg,value in zip(REGS,state['GP16']):self.u.reg_write(reg,value)
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        assert self.snap()==state
        self.stage=self.phase='native_resident_controller_program'
        self.done=False;self.boundary=None
        print(json.dumps(dict(stage='resuming_after_verified_original_restore_prefix',
            completed_prefix_instructions=len(self.trace),worker_TCB=hex(self.worker_task),
            original_creation_and_restore_not_rerun=True)),flush=True)
        self.u.emu_start(state['GP16'][15]|1,0,count=500000,timeout=60_000_000)
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
            completed_creation_bootstrap_prefix='staging/native-os20-resident-prefix-v1/creation-bootstrap-prefix.json.gz',
            completed_prefix_instructions=3865,completed_prefix_CPU_stores=1826,
            captured_prefix_host_endpoints=self.captured_prefix_host_endpoints,
            declared_frozen_endpoint_GP_CPSR_restore_before_new_C_scope=True,
            host_guest_native_context_switch_substitution=False,
            native_creation_and_bootstrap_restore_not_rerun=True,
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
    ref=Reference()
    prior_frames=(ROOT/'staging/native-os20-resident-music-v1/frames.sbc').read_bytes()
    prior_PCM=(ROOT/'staging/native-os20-resident-music-v1/reference-two-streams.pcm').read_bytes()
    frames=[prior_frames[i:i+72]for i in range(0,288,72)]
    references=[prior_PCM[i:i+256]for i in range(0,1024,256)]
    assert len(prior_frames)==288 and len(prior_PCM)==1024
    (OUT/'frames.sbc').write_bytes(b''.join(frames))
    (OUT/'reference-two-streams.pcm').write_bytes(b''.join(references))
    sources={str(p.relative_to(ROOT)):sha(p)for p in [Path(__file__),ROOT/PARENT,ROOT/BUILD,
        ROOT/build['ELF'],ROOT/'scripts/probe_os20_scheduled_decoder_v1.py',
        ROOT/'scripts/probe_os20_allocator_v1.py',ROOT/'scripts/emulate_native_sbc.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin']}
    sources.update(build['source_sha256'])
    prefix_meta=json.loads((ROOT/'staging/native-os20-resident-prefix-v1/FILE-prefix-proof.json').read_text())
    sources.update(prefix_meta['source_sha256'])
    for p in ['staging/native-os20-resident-prefix-v1/FILE-prefix-proof.json',
              prefix_meta['prefix'],'staging/native-os20-resident-prefix-v1/terminal-tool-receipt.json']:
        sources[p]=sha(ROOT/p)
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
            creation_bootstrap_v1_completed_prefix_not_rerun=True,
            completed_prefix_instructions=3865,completed_prefix_CPU_stores=1826,
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
