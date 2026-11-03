#!/usr/bin/env python3
"""Original kernel runs source lifecycle from compiled after-return events.

Host supplies synthetic incoming packets and virtual peripheral frames, never
pumps/selects/releases the coordinator. Entry patches exist only in emulator
RAM; original task/event/mutex/condition/FIFO bodies execute without Python
context restore. No device I/O, loaded App or real Bluetooth endpoint.
"""
from datetime import datetime, timezone
import ctypes
import json
from pathlib import Path
import struct
from unicorn import UC_PROT_READ, UC_PROT_EXEC, UC_QUERY_TIMEOUT
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_media_coordinator import CoordinatedDriver
from emulate_native_source_controller import NativeCentral, CENTRAL_GLOBAL, SOURCE_STATES
from emulate_native_audio_registration import require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm
from emulate_native_media_worker import POST, WAIT, IDLE_ENTRY
from emulate_native_sbc import RETURN
from emulate_avdtp_media import HANDLER

FIELDS=('tcb','entered','wake_returns','pending','publications','completions',
        'requests','pump_calls','cancel_requested','quit_requested','finished_on_stack',
        'init_result','last_result')


class EventDriver(CoordinatedDriver):
    def __init__(self,stock,companion,output,playback,coordinator,source):
        self.source_ready=False;self.event_trace=[];self.publication_inputs=[]
        self.publication_returns=[];self.completion_returns=[];self.source_tcb=0
        self.budget_continuations=[];self.executed_instructions=0
        self.source_ack_count=0;self.start_return_points={};self.start_returns=[]
        super().__init__(stock,companion,output,playback,coordinator)
        self.source=source
        require(source['owned_elf_sha256_required']==output['elf_sha256'] and
                source['coordinator_elf_sha256_required']==coordinator['elf_sha256'],
                'Source task private imports changed')
        n=(source['flat_binary_bytes']+4095)&~4095;base=source['load_base']
        self.uc.mem_map(base,n);self.uc.mem_write(base,(ROOT/source['flat_binary']).read_bytes())
        self.uc.mem_protect(base,n,UC_PROT_READ|UC_PROT_EXEC)
        self.source_bss=source['symbols']['__source_state_start']['address']
        self.source_end=source['symbols']['__source_state_end']['address']
        self.uc.mem_map(self.source_bss,4096);self.uc.mem_write(self.source_bss,b'\xa5'*4096)
        self.uc.mem_write(self.source_bss,bytes(self.source_end-self.source_bss))
        self.source_stack=source['symbols']['__source_stack_start']['address']
        self.source_stack_end=source['symbols']['__source_stack_end']['address']
        self.uc.mem_map(self.source_stack,source['preallocated_stack_bytes'])
        self.uc.mem_write(self.source_stack,b'\xa5'*source['preallocated_stack_bytes'])
        self.native_aliases.update({n:v['address'] for n,v in source['symbols'].items()
                                    if n.startswith('source_')})
        self.source_observe_points={self.address(n) for n in (
            'media_coordinator_init','media_coordinator_pump','media_coordinator_cancel',
            'source_publication_hook','source_publication_after_original','source_worker_published',
            'source_completion_after_original','source_worker_completed')}
        self.source_observe_points.update((0x277596,0x2775e6,0x277694,0x36b720,0x3ec498))
        self.publication_entry=source['publication_entry']
        self.publication_patch=struct.pack('<II',0xe51ff004,self.address('source_publication_hook'))
        self.completion_patch=bytes.fromhex('004b1847')+struct.pack('<I',self.address('source_completion_hook'))+bytes.fromhex('c046')
        for a,raw in ((self.publication_entry,self.publication_patch),(source['completion_entry'],self.completion_patch)):
            self.uc.mem_write(a,raw);self.uc.ctl_remove_cache(a,a+len(raw))
        self.source_ready=True

    def source_state(self):
        a=self.source['symbols']['source_worker_state']['address']
        return dict(zip(FIELDS,struct.unpack('<11I2i',self.uc.mem_read(a,52))))

    def assert_coord_call(self):
        s=self.coord();lr=self.uc.reg_read(UC_ARM_REG_LR)
        require(self.current()==s['owner_tcb']==self.source_state()['tcb'] and s['busy']==1 and
                self.source_stack<=self.uc.reg_read(UC_ARM_REG_SP)<self.source_stack_end and
                self.coordinator['load_base']<=lr<self.coordinator['load_base']+self.coordinator['flat_binary_bytes'],
                'Lifecycle did not execute from compiled coordinator on native source task')

    def kernel_call(self,name,args=(),stack=None):
        if not self.source_ready:return super().kernel_call(name,args,stack)
        native={'_kernel_create':0x358bf9,'_mutex_init':0x3008a1,'_post':POST,'_wait':WAIT|1}
        address=HANDLER|1 if name=='stock_handler' else native.get(name)
        if address is None:address=self.address(name)
        if stack is None:stack=self.current()
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        for reg,val in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):
            self.uc.reg_write(reg,val)
        for _ in range(8):
            before=self.executed_instructions
            self.uc.emu_start(address,RETURN,timeout=30000000,count=6000000)
            pc=self.uc.reg_read(UC_ARM_REG_PC)
            if pc in (RETURN,IDLE_ENTRY):return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value
            # Resume the same pending kernel call, keeping every CPU register,
            # banked stack, LR and task/list state. No new wait/post or caller
            # reset occurs between chunks. This is emulator budget only.
            self.budget_continuations.append({'call':name,'pc':hex(pc),'current':hex(self.current()),
                'timeout':bool(self.uc.query(UC_QUERY_TIMEOUT)),
                'instructions_in_chunk':self.executed_instructions-before,
                'register_stack_context_retained':True})
            address=pc | bool(self.uc.reg_read(UC_ARM_REG_CPSR)&0x20)
        raise ValueError('Same kernel call exceeded eight resumed emulator budgets: '+name+' '+hex(pc))

    def observe(self,uc,address,size,data):
        if self.source_ready:
            self.executed_instructions+=1
            if address not in self.source_observe_points:
                super().observe(uc,address,size,data);return
            s=self.source_state()
            if address==0x3ec498 and uc.reg_read(UC_ARM_REG_R0)==self.record+0x24:
                require(self.current()==self.word(CENTRAL_GLOBAL),'Native start signal came from another task')
                self.source_ack_count+=1
            if address==0x36b720 and self.current()==s['tcb']:
                pc=uc.reg_read(UC_ARM_REG_LR)&~1
                require(pc not in self.start_return_points,'Reentrant original source start')
                self.start_return_points[pc]={'ack_before':self.source_ack_count,
                    'condition_before':self.word(self.record+0x30)}
                self.source_observe_points.add(pc)
            if address in self.start_return_points:
                pending=self.start_return_points.pop(address)
                require(self.current()==s['tcb'] and uc.reg_read(UC_ARM_REG_R0)==0 and
                        self.source_ack_count>pending['ack_before'] and
                        not self.word(self.record+0x30) and self.byte(self.record+2)==1 and
                        self.byte(SOURCE_STATES+self.channel) in (3,4),
                        'Publication wake falsely completed native synchronous start before original ACK')
                self.start_returns.append({'current':self.current(),'original_ack_observed':True,
                    'condition_waiters_at_return':0,'source_state':self.byte(SOURCE_STATES+self.channel),
                    'prepared':1})
            if address in (self.address('media_coordinator_init'),self.address('media_coordinator_pump'),
                           self.address('media_coordinator_cancel')):
                require(self.current()==s['tcb'] and
                        self.source_stack<=uc.reg_read(UC_ARM_REG_SP)<self.source_stack_end,
                        'Host or another actor called the source coordinator')
            if address==self.address('source_publication_hook'):
                require(self.current()==self.worker_tcb,'Publication wrapper not called by decoder')
                self.publication_inputs.append({'current':self.current(),
                    'length':self.word(uc.reg_read(UC_ARM_REG_SP)),
                    'coordinator_busy':self.coord()['busy'],'pending':s['pending']})
            if address==self.address('source_publication_after_original'):
                require(not self.pipeline()[1],'Publication event precedes whole-packet busy release')
                self.publication_returns.append({'result':uc.reg_read(UC_ARM_REG_R0),
                    'held':self.pipeline()[4],'committed':self.pipeline()[8],
                    'coordinator_busy':self.coord()['busy']})
            if address==self.address('source_worker_published'):
                require(uc.reg_read(UC_ARM_REG_SP)%8==0,'Publication C call not aligned')
                self.event_trace.append({'kind':'publication','current':self.current(),
                    'coordinator_busy':self.coord()['busy'],'ticket':self.coord()['ticket'],
                    'held':self.pipeline()[4],'result':uc.reg_read(UC_ARM_REG_R0),
                    'native_condition_waiter':self.word(self.record+0x30)})
            if address==self.address('source_completion_after_original'):
                require(self.current()==self.word(CENTRAL_GLOBAL) and
                        self.byte(SOURCE_STATES+self.channel)==1 and
                        not self.byte(self.record+2) and not self.half(self.driver_record) and
                        not self.byte(self.mixer+0x84) and not self.state()['native_calls'],
                        'Completion notification precedes full original cleanup return')
                self.completion_returns.append({'current':self.current(),
                    'source_state':1,'nodes':self.half(self.record+0x1c0),
                    'result':uc.reg_read(UC_ARM_REG_R0)})
            if address==self.address('source_worker_completed'):
                require(uc.reg_read(UC_ARM_REG_R0)==self.record and uc.reg_read(UC_ARM_REG_SP)%8==0,
                        'Completion wrapper lost record or C alignment')
                self.event_trace.append({'kind':'completion','current':self.current(),
                    'coordinator_busy':self.coord()['busy'],'ticket':self.coord()['ticket'],
                    'held':self.pipeline()[4]})
            if address==0x277596 and self.current()==s['tcb']:
                require(self.coord()['busy']==self.coord()['cancel_pending']==1 and
                        self.state()['native_calls']==1 and not self.byte(self.record+2) and
                        not self.byte(self.mixer+0x84) and not self.half(self.driver_record) and
                        uc.reg_read(UC_ARM_REG_R0)==self.record+0x1a8 and
                        uc.reg_read(UC_ARM_REG_R1)==0 and self.half(self.record+0x1c0)==1,
                        'Native worker cancel did not use held original deletion boundary')
                self.original_node_removals.append({'current':self.current(),'driver':self.record+0x1a8,
                    'index':0,'node_count_at_entry':1,'internal_entry':hex(address),'actor':'source_worker'})
                NativeCentral.observe(self,uc,address,size,data);return
            if address==0x2775e6 and self.current()==s['tcb']:
                require(self.state()['native_calls']==1 and self.half(self.record+0x1c0)==1,
                        'Early cancellation report mistaken for complete removal')
                self.cancel_notices.append({'current':self.current(),'native_calls':1,'node_count':1})
            if address==0x277694 and self.current()==s['tcb']:
                require(self.state()['native_calls']==1 and not self.half(self.record+0x1c0),
                        'Cancel hold ended before full original public return')
                self.coord_events.append({'kind':'public_remove_return','current':self.current(),
                    'native_calls':1,'node_count':0})
        super().observe(uc,address,size,data)

    def initialize(self,priority=40):
        self.source_tcb=self.kernel_call('source_worker_boot',(priority,));self.yield_all()
        require(self.source_tcb==(self.source_stack_end-108)&~7 and
                self.source_state()['tcb']==self.source_tcb and self.source_state()['entered']==1 and
                self.source_state()['init_result']==0 and self.coord()['owner_tcb']==self.source_tcb and
                self.byte(self.source_tcb+22)==2 and not self.word(self.source_tcb+4),
                'Original kernel did not construct/enter/block coordinator on its own stack')
        require(self.kernel_call('source_worker_boot',(priority,))==0,'Source worker boot reused live stack')

    def pump(self):raise ValueError('Host must not pump event-driven coordinator')

    def verify_event_worker(self):
        require(self.source_state()['entered']==1 and self.source_state()['finished_on_stack']==1 and
                self.byte(self.source_tcb+22)==0x80 and not self.source_state()['pending'] and
                not self.coord()['busy'] and not self.coord()['ticket'] and
                not self.coord()['cancel_pending'] and not self.pipeline()[4],
                'Source task not fully stopped/unlinked or retained lifecycle work')
        require(self.kernel_call('source_worker_shutdown')==-22 and
                self.kernel_call('source_worker_cancel')==-22 and
                self.kernel_call('source_worker_boot',(40,))==0,
                'Ended task accepted work or reused retained module/stack')
        require(bytes(self.uc.mem_read(self.source['load_base'],self.source['flat_binary_bytes']))==
                (ROOT/self.source['flat_binary']).read_bytes() and
                bytes(self.uc.mem_read(self.source_end,self.source_bss+4096-self.source_end))==
                b'\xa5'*(self.source_bss+4096-self.source_end) and
                bytes(self.uc.mem_read(self.source_stack,64))==b'\xa5'*64,
                'Source code/state/stack guard changed')
        require(len(self.publication_inputs)==len(self.publication_returns)==len(
                [e for e in self.event_trace if e['kind']=='publication'])>0 and
                len(self.completion_returns)==self.source_state()['completions']>0,
                'After-return wrapper bodies skipped')
        require(all(self.byte(tcb+22)==2 and self.word(tcb+4)==0 and t['sends']==t['receives']
                    for tcb,t in self.aux_tasks.items()) and self.byte(self.worker_tcb+22)==0x80,
                'Native tasks/call chains active before emulator patch restoration')
        owned=(ROOT/self.output['flat_binary']).read_bytes()
        off=self.publication_entry-self.output['load_base']
        expected=owned[:off]+self.publication_patch+owned[off+8:]
        require(bytes(self.uc.mem_read(self.output['load_base'],len(owned)))==expected and
                bytes(self.uc.mem_read(self.source['completion_entry'],10))==self.completion_patch and
                bytes(self.uc.mem_read(self.source['completion_entry']+10,80))==
                self.stock.read(self.source['completion_entry']+10,80),
                'Runtime entry patch or preserved original body differs')
        self.source_ready=False
        for a,raw in ((self.publication_entry,owned[off:off+8]),
                      (self.source['completion_entry'],self.stock.read(self.source['completion_entry'],10))):
            self.uc.mem_write(a,raw);self.uc.ctl_remove_cache(a,a+len(raw))
        self.verify_coordinator()


def stream(stock,manifests,reference,tables,frequency,mode,priority):
    m=EventDriver(stock,*manifests);m.initialize(priority);tts=m.tts_snapshot()
    frames=reference.encode(dict(frequency=frequency,mode=mode,subbands=1,blocks=3,
        allocation=0,bitpool=31 if mode==0 else 53),frames=10)
    rate,channels=(16000,32000,44100,48000)[frequency],1 if mode==0 else 2
    wanted,_=reference_pcm(reference,frames,rate,channels,tables)
    # Queue four packets before yielding. With priority28, decoder36
    # publishes later packets while coordinator is synchronously starting.
    lengths=[]
    for i in range(4):
        p=packet(frames[2*i:2*i+2],i);lengths.append(len(p));m.deliver(p)
    m.yield_all()
    p=packet(frames[8:],4);lengths.append(len(p));m.deliver(p);m.yield_all()
    require(m.coord()['starts']==1 and m.pipeline()[4]==4 and m.queue_state()[2]==1,
            'Automatic publication start/capacity deferral failed: '+repr(
                (m.coord(),m.source_state(),m.pipeline(),m.queue_state(),m.publication_returns)))
    for _ in range(30):
        if m.half(m.driver_record):m.frame()
        if m.coord()['completed']==5 and not m.coord()['ticket']:break
    stereo=b''.join(wanted[i:i+2]*2 for i in range(0,len(wanted),2))
    require(m.coord()['starts']==m.coord()['completed']==5 and not m.pipeline()[4] and
            not m.queue_state()[2] and b''.join(m.native_chunks)==wanted and
            b''.join(m.peripheral_chunks)==stereo and m.tts_snapshot()==tts and
            m.source_state()['publications']==m.source_state()['completions']==5 and
            m.coord()['failures']==0,
            'Event-driven source lifecycle/output/reference/cleanup differs')
    require([p['length'] for p in m.publication_inputs]==lengths and
            all(p['result']==0 for p in m.publication_returns) and
            all(e['current']==m.source_tcb for e in m.coord_events) and
            len(m.original_node_removals)==5 and
            all(e['current']==m.mixer_tcb for e in m.original_node_removals),
            'Wrapper fifth-argument/results or native lifecycle actor differs')
    during=sum(e['kind']=='publication' and e['coordinator_busy']==1 and
               e['native_condition_waiter']!=0 for e in m.event_trace)
    require(len(m.start_returns)==5 and not m.start_return_points,
            'Not every original public source start returned after actual condition signal')
    if priority==28:require(during>=1,'No actual publication occurred during synchronous native start')
    require(m.kernel_call('source_worker_shutdown')==0,'Source shutdown request failed')
    m.yield_all();require(m.pipe('media_worker_shutdown')==0,'Decoder shutdown failed')
    m.yield_all();m.verify_event_worker()
    return {'rate':rate,'channels':channels,'source_priority':priority,'decoded_frames':10,'packets':5,
        'pcm_bytes':len(wanted),'pcm_sha256':sha(wanted),'virtual_stereo_bytes':len(stereo),
        'virtual_stereo_sha256':sha(stereo),'source_worker':m.source_state(),'coordinator':m.coord(),
        'publication_during_synchronous_start':during,'after_return_events':m.event_trace,
        'publication_inputs':m.publication_inputs,'completion_returns':m.completion_returns,
        'native_synchronous_start_returns':m.start_returns,
        'guarded_reads':len(m.guarded_reads),'native_node_removals':m.original_node_removals,
        'compiled_lifecycle_events':m.coord_events,'host_coordinator_pump_or_notify':False,
        'same_call_budget_continuations':m.budget_continuations,
        'host_packets_and_virtual_peripheral_frames':True,'passed':True}


def cancel(stock,manifests,reference):
    m=EventDriver(stock,*manifests);m.initialize(40)
    frames=reference.encode(dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31),frames=10)
    for i in range(4):m.deliver(packet(frames[2*i:2*i+2],i))
    m.yield_all();m.deliver(packet(frames[8:],4));m.yield_all();reads=len(m.guarded_reads)
    require(m.kernel_call('source_worker_cancel')==0,'Asynchronous native cancellation request failed')
    m.yield_all()
    require(m.coord()['cancel_pending']==1 and not m.queue_state()[4] and
            not m.queue_state()[2] and m.pipeline()[4]==4,'Cancel recycled before native stop completion')
    for _ in range(10):
        if m.half(m.driver_record):m.frame()
        if not m.coord()['cancel_pending']:break
    require(m.coord()['cancelled']==1 and m.coord()['discarded']==m.coord()['remove_calls']==4 and
            not m.pipeline()[4] and all(s['state']==0 for s in m.slots()) and
            len(m.cancel_notices)==4 and len(m.guarded_reads)==reads and
            all(e['current']==m.source_tcb for e in m.coord_events),
            'Native completion event did not finish bounded full queued-data cancellation')
    committed=m.pipeline()[8];m.deliver(packet(frames[:2],5));m.yield_all()
    require(m.pipeline()[8]==committed and not m.pipeline()[4],'Late stopped packet published PCM')
    require(m.kernel_call('source_worker_shutdown')==0,'Cancelled source shutdown failed')
    m.yield_all();require(m.pipe('media_worker_shutdown')==0,'Cancelled decoder shutdown failed')
    m.yield_all();m.verify_event_worker()
    return {'source_worker':m.source_state(),'coordinator':m.coord(),'guarded_reads':reads,
        'unplayed_ready_sources_cancelled_without_reads':3,'pending_compressed_packets_discarded':1,
        'all_slots_free':True,'original_node_removals':m.original_node_removals,
        'compiled_lifecycle_events':m.coord_events,'after_return_events':m.event_trace,
        'same_call_budget_continuations':m.budget_continuations,
        'host_coordinator_pump_or_notify':False,'passed':True}


def main():
    stock,reference=NativeImage(),Reference()
    manifests=list(map(check_manifest,(ROOT/'staging/native-media-consumer/manifest.json',
        ROOT/'staging/native-owned-media/manifest.json',ROOT/'staging/native-playback-control/manifest.json',
        ROOT/'staging/native-media-coordinator/manifest.json',ROOT/'staging/native-source-worker/manifest.json')))
    cv=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cv['coefficient_table']).read_text())['tables'];routes=[]
    for priority in (40,28):
        for f,mode in ((0,0),(2,3),(3,2)):
            routes.append(stream(stock,manifests,reference,tables,f,mode,priority))
            print(json.dumps({'rate':routes[-1]['rate'],'priority':priority,'passed':True}),flush=True)
    cancelled=cancel(stock,manifests,reference)
    previous=ROOT/'evidence/firmware-analysis/native-media-coordinator-emulation.json'
    prior=json.loads(previous.read_text());paths=[ROOT/p for p in prior['dependency_sha256']]
    paths.extend((previous,ROOT/'scripts/emulate_native_media_coordinator.py',
                  ROOT/'staging/native-source-worker/manifest.json'))
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'script_sha256':sha(Path(__file__).read_bytes()),
        'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in paths},
        'source_worker_elf_sha256':manifests[-1]['elf_sha256'],
        'source_worker_code_bytes':manifests[-1]['flat_binary_bytes'],'routes':routes,'cancellation':cancelled,
        'all_passed':True,'previous_compiled_artifacts_changed':False,'device_io':False,'device_install_candidate':False,
        'limitations':'Original kernel source worker owns frozen coordinator. Compiled after-return packet-publication/full-source-completion events drive finite PCM register/start/release/next-source and bounded cancel; durable pending flags survive actual publication during synchronous native start. Host does not pump/notify/register/select/start/remove/release coordinator, but supplies all synthetic incoming packets and virtual peripheral frames. Entry patches exist only in emulator RAM, restored after both custom tasks exit and native FIFOs block/drain; modules/TCB/stacks retained, no safe unload. Existing priority/event/mutex/condition/driver/mixer/FIFO bodies run, heap/physical inventory/arbitration/power/virtual peripheral fixtures remain. No real IRQ/DAC/DMA/resampler/multisource/navigation coexistence/continuous producer timing/accepted VPM/package/UI/App/SEP/SDP/actual phone/speaker/Android Auto/Google Maps proven. In-flight producer cancel, cross-actor reservation/future callback quiescence and failure reconciliation remain unverified.'}
    p=ROOT/'evidence/firmware-analysis/native-source-worker-emulation.json'
    p.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'evidence':str(p),'all_passed':True}))


if __name__=='__main__':main()
