#!/usr/bin/env python3
"""Kernel event-driven owned-PCM decode and release wakeup, offline only.

Decoder post/wait/context switches are original instructions. Existing audio
actor remains a controlled message/CPU-context fixture with a separate wait
return veneer. It is not a second booted kernel audio task or a device hook.
"""
from datetime import datetime,timezone
import json,struct,ctypes
from pathlib import Path
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
                               UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,
                               UC_ARM_REG_PC,UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_owned_media import OwnedDecoder
from emulate_native_memory_notice import check_manifest
from emulate_native_media_worker import (ALL_TASKS,READY_TASKS,CODE,IDLE_ENTRY,
    DESCRIPTORS,CONTROLLER_STACK,IDLE_STACK,EXIT_LIST,POST,RESTORE)
from emulate_native_audio_messages import WAIT,GET_MESSAGE
from emulate_native_audio_registration import require,sha
from emulate_native_sbc import Reference,INPUT_PAGE,PAGE_BYTES,RETURN
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm
from emulate_avdtp_media import HANDLER


class OwnedWorker(OwnedDecoder):
    def __init__(self,stock,companion,output,priority=36):
        self.kernel_ready=False;self.mixer_domain=False
        self.controller=self.idle=self.worker_tcb=0
        self.real_waits=0;self.shadow_waits=0
        self.switch_visits=set();self.kernel_events=[];self.worker_steps=[]
        super().__init__(stock,companion,output)
        for page in (0x358000,0x300000,0x2fb000,0x2fc000,0x2fd000,
                     0x20b000,0x20e000,0xf5000,0x23d000,0x1c0000,0x3cc000):
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096);self.uc.mem_write(page,stock.read(page,4096))
        self.uc.mem_write(WAIT,stock.read(WAIT,4))
        self.stack_start=output['symbols']['__worker_stack_start']['address']
        self.stack_end=output['symbols']['__worker_stack_end']['address']
        self.uc.mem_map(self.stack_start,output['preallocated_stack_bytes'])
        self.uc.mem_write(self.stack_start,b'\xa5'*output['preallocated_stack_bytes'])
        for addr,size in ((CODE,4096),(CONTROLLER_STACK,16384),(IDLE_STACK,16384),
                          (0x14b3000,4096),(EXIT_LIST&~4095,4096)):
            self.uc.mem_map(addr,size)
        self.uc.mem_write(IDLE_ENTRY,struct.pack('<I',0xeafffffe))
        self.uc.mem_write(CODE+0x40,bytes.fromhex('7047')) # Only controlled mixer wait returns here.
        self.uc.mem_write(0xf5030,bytes.fromhex('7047'))
        self.put(ALL_TASKS,0);self.put(READY_TASKS,0)
        self.put(0xf09094,0);self.put(0xf0909c,0)
        self.uc.mem_write(0xf071cc,b'\x01'+bytes(7))
        # The inherited source fixture defaults to SVC mode. Stock restore
        #loads the task's user/system bank via LDM^, so constructing a parked
        #caller in SVC mode gives it the wrong SP/LR bank on return. Use the
        #same explicit normal System mode as the original worker harness.
        self.uc.reg_write(UC_ARM_REG_CPSR,0x1f)
        self.kernel_ready=True
        self.kernel_call('_mutex_init',(EXIT_LIST+4,))
        self.idle=self.build_raw(DESCRIPTORS,IDLE_ENTRY,IDLE_STACK+16384,240)
        self.controller=self.build_raw(DESCRIPTORS+32,CODE+4,CONTROLLER_STACK+16384,16)
        self.put(READY_TASKS,self.controller);self.put(self.controller,self.idle);self.put(self.idle,0)
        self.uc.mem_write(self.controller+22,b'\x01');self.uc.mem_write(self.idle+22,b'\x01')
        self.dispatch.callback=self.address('media_worker_callback')
        self.dispatch.configure(slot=2,channel_index=11,context_index=1)
        require(self.kernel_call('media_worker_init')==0,'Worker init failed')
        self.worker_tcb=self.kernel_call('media_worker_boot',(priority,))
        require(self.worker_tcb==(self.stack_end-108)&~7,'Unexpected original worker TCB placement')
        self.park_controller();self.activate_controller()
        require(self.worker_state()[1]==1 and self.byte(self.worker_tcb+22)==2,
                'Original kernel did not enter/block decoder worker')

    def current(self):return self.word(READY_TASKS)
    def worker_state(self):return struct.unpack('<7Ii',self.uc.mem_read(self.address('media_worker_state'),32))
    def build_raw(self,address,entry,stack_end,priority):
        self.uc.mem_write(address,struct.pack('<5I',entry,0,stack_end,priority<<16,0))
        return self.kernel_call('_kernel_create',(address,))

    def kernel_call(self,name,args=(),stack=None):
        native={'_kernel_create':0x358bf9,'_mutex_init':0x3008a1,'_post':POST,'_wait':WAIT|1}
        address=HANDLER|1 if name=='stock_handler' else native.get(name)
        if address is None:address=self.address(name)
        if stack is None:stack=self.current() if self.controller else 0x0990f000
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        for reg,val in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):self.uc.reg_write(reg,val)
        self.uc.emu_start(address,RETURN,timeout=30000000,count=6000000)
        require(self.uc.reg_read(UC_ARM_REG_PC) in (RETURN,IDLE_ENTRY),
                'Original kernel call missed bounded endpoint: '+hex(self.uc.reg_read(UC_ARM_REG_PC)))
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def pipe(self,name,args=(),stack=None):
        if not self.kernel_ready:return OwnedDecoder.pipe(self,name,args,stack or 0x0990f000)
        require(name!='media_queue_step','Test may not explicitly invoke decoder step')
        return self.kernel_call(name,args,stack)

    def observe(self,uc,address,size,data):
        if not self.kernel_ready:
            super().observe(uc,address,size,data);return
        if address in (POST,WAIT,0x2fcfb0,0x2fcfec,0x2fd06c,0x2fd0a8,
                       RESTORE,0x358f08,0x358fa4,0x1c06a4,0x2fbbbe):self.switch_visits.add(address)
        if address==0xf5030:uc.reg_write(UC_ARM_REG_R0,0)
        if address==POST:
            self.kernel_events.append({'current':self.current(),'target':uc.reg_read(UC_ARM_REG_R0),
                                       'events':uc.reg_read(UC_ARM_REG_R1)})
        if address==WAIT:
            if self.mixer_domain:
                self.shadow_waits+=1
                if self.pending_messages:
                    uc.reg_write(UC_ARM_REG_R0,2)
                    uc.reg_write(UC_ARM_REG_PC,(CODE+0x40)|1)
                else:uc.emu_stop()
            else:self.real_waits+=1
            # In the decoder/controller domain, execute restored stock wait.
            # Never run inherited MixerMessages' fake wait hook here.
            return
        if address==GET_MESSAGE and not self.mixer_domain:
            raise ValueError('Decoder/kernel unexpectedly entered controlled mixer message-get')
        if address==self.address('media_queue_step'):
            require(self.current()==self.word(self.address('media_worker_state')) and
                    self.stack_start<=uc.reg_read(UC_ARM_REG_SP)<self.stack_end and
                    uc.reg_read(UC_ARM_REG_CPSR)&0x1f==0x1f,
                    'Decoder step did not execute on original scheduled worker/stack')
            self.worker_steps.append({'current':self.current(),'sp':uc.reg_read(UC_ARM_REG_SP),
                                      'pending':self.queue_state()[2],'held_pcm':self.pipeline()[4]})
        if address==IDLE_ENTRY:uc.emu_stop();return
        super().observe(uc,address,size,data)

    def run_worker(self,messages=(),pause_after_select=False):
        # This inherited actor is a controlled frame, not a kernel task. Its
        #wait veneer cannot consume the decoder worker's mailbox or contexts.
        self.mixer_domain=True
        try:return super().run_worker(messages,pause_after_select)
        finally:self.mixer_domain=False

    def park_controller(self):
        require(self.current()==self.controller,'Cannot yield a non-controller task')
        self.kernel_call('_wait')
        require(self.current()==self.idle,'Controller wait did not schedule worker then idle')

    def activate_controller(self):
        if self.current()==self.controller:return
        require(self.current()==self.idle,'Controller activation expected idle')
        require(self.kernel_call('_post',(self.controller,1))==1 and self.current()==self.controller,
                'Original post/restore did not return controller wait')

    def verify_kernel(self):
        self.activate_controller();self.verify()
        require(bytes(self.uc.mem_read(WAIT,4))==self.stock.read(WAIT,4),'Stock wait entry changed')
        require(bytes(self.uc.mem_read(self.stack_start,64))==b'\xa5'*64,'Decoder stack crossed canary')
        require({POST,WAIT,0x2fcfb0,0x2fd06c,RESTORE,0x358f08,0x2fbbbe}.issubset(self.switch_visits),
                'Original event/priority/context paths were skipped')
        require(self.worker_state()[1]==1,'Decoder worker entry restarted instead of resumed')


def route(stock,companion,output,reference,tables,frequency,mode,priority=36):
    m=OwnedWorker(stock,companion,output,priority)
    frames=reference.encode(dict(frequency=frequency,mode=mode,subbands=1,blocks=3,
                                allocation=0,bitpool=31 if mode==0 else 53),frames=10)
    rate=(16000,32000,44100,48000)[frequency];channels=1 if mode==0 else 2
    wanted,_=reference_pcm(reference,frames,rate,channels,tables)
    tts=m.tts_snapshot()
    for i in range(4):
        before=m.pipeline()[8]
        m.deliver(packet(frames[i*2:i*2+2],i))
        require(m.pipeline()[8]==before+(priority<16),
                'Packet-post priority/preemption behavior differs')
        m.park_controller();m.activate_controller()
        require(m.pipeline()[8]==before+1 and m.queue_state()[2]==0,'Scheduled decoder did not commit PCM')
    m.deliver(packet(frames[8:],4));m.park_controller();m.activate_controller()
    require(m.pipeline()[4]==4 and m.queue_state()[2]==1 and m.worker_state()[4]==1 and
            m.byte(m.worker_tcb+22)==2,'Full owned PCM did not block decoder on original wait')
    events=len(m.kernel_events);steps=len(m.worker_steps)
    first=m.play_one()
    require(any(x['target']==m.worker_tcb and x['events']==1 for x in m.kernel_events[events:]),
            'Compiled release did not post the original capacity event')
    if priority<16:
        require(m.queue_state()[2]==0 and m.pipeline()[4]==4 and m.byte(m.worker_tcb+22)==2 and
                len(m.worker_steps)>steps, 'High-priority decoder did not preempt during release post')
    else:
        require(m.queue_state()[2]==1 and m.pipeline()[4]==3 and m.byte(m.worker_tcb+22)==1 and
                len(m.worker_steps)==steps,'Low-priority release did not make waiting worker ready')
    # No explicit step/notify or new incoming packet: native controller wait
    #schedules the worker solely from the release's original post event.
    m.park_controller();m.activate_controller()
    require(m.queue_state()[2]==0 and m.pipeline()[4]==4 and m.byte(m.worker_tcb+22)==2,
            'Release wake did not process pending packet and block again')
    actual=first+b''.join(m.play_one() for _ in range(4))
    require(actual==wanted and m.pipeline()[4]==0 and m.tts_snapshot()==tts,
            'Scheduled owned PCM or navigation TTS context/ring differs')
    require(m.pipe('media_worker_shutdown')==0,'Compiled shutdown failed')
    m.park_controller();m.activate_controller()
    require(m.worker_state()[6]==1 and m.byte(m.worker_tcb+22)==0x80 and
            {0x358fa4,0x1c06a4}.issubset(m.switch_visits),'Original worker self-exit was not completed')
    require(m.pipe('media_worker_boot',(priority,))==0,'Exited retained worker was wrongly reused')
    m.verify_kernel()
    return {'rate':rate,'channels':channels,'kernel_priority':priority,'frames':10,'packets':5,'pcm_bytes':len(actual),
            'pcm_sha256':sha(actual),'upstream_codec_absolute_convolution_identical':True,
            'decoder_worker_entries':m.worker_state()[1],'decoder_steps_on_kernel_task':len(m.worker_steps),
            'capacity_deferrals':m.worker_state()[4],
            'release_event_preempts_controller':priority<16,
            'explicit_normal_system_mode_fixture':True,
            'compiled_release_original_post_wakes_worker_without_new_packet_or_explicit_step':True,
            'original_kernel_post_wait_priority_context_restore_and_self_exit_executed':True,
            'real_wait_calls':m.real_waits,'controlled_mixer_shadow_wait_calls':m.shadow_waits,
            'mixer_actor_wait_get_and_python_context_remain_fixtures':True,
            'audio_actor_booted_as_real_kernel_task':False,
            'stack_and_module_retained_after_exit_no_safe_unload_claim':True,
            'tts_context_and_entire_ring_unchanged':True,'passed':True}


def main():
    stock=NativeImage();reference=Reference()
    cp=ROOT/'staging/native-media-consumer/manifest.json';op=ROOT/'staging/native-owned-media/manifest.json'
    companion,output=map(check_manifest,(cp,op))
    cv=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes=[]
    for f,q,priority in ((0,0,36),(2,3,36),(3,2,36),(0,0,3)):
        routes.append(route(stock,companion,output,reference,tables,f,q,priority))
        print(json.dumps({'route_rate':routes[-1]['rate'],'kernel_priority':priority,'passed':True}),flush=True)
    dependencies=(cp,op,ROOT/'scripts/emulate_native_owned_media.py',ROOT/'scripts/emulate_native_media_worker.py',
                  ROOT/'scripts/emulate_native_audio_messages.py',ROOT/'scripts/emulate_native_memory_output.py',
                  ROOT/'scripts/emulate_native_memory_completion.py',ROOT/'scripts/emulate_native_voice_convert.py',
                  ROOT/'scripts/emulate_native_voice_media.py',ROOT/'scripts/emulate_native_sbc.py',
                  ROOT/'scripts/emulate_native_memory_audio.py',ROOT/'scripts/emulate_native_pcm_initialization.py',
                  ROOT/'scripts/emulate_native_pcm_flow_control.py',ROOT/'scripts/emulate_native_sbc_pcm.py',
                  ROOT/'scripts/emulate_native_audio_registration.py',ROOT/'scripts/emulate_avdtp_media.py',
                  ROOT/'scripts/emulate_native_memory_notice.py',ROOT/'scripts/analyze_native_sections.py')
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'script_sha256':sha(Path(__file__).read_bytes()),
            'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in dependencies},
            'owned_elf_sha256':output['elf_sha256'],'routes':routes,'all_passed':True,
            'compiled_components_changed':False,'decoder_step_explicitly_called_by_test':False,
            'kernel_event_driven_decoder_and_release_capacity_wakeup_verified_offline':True,
            'audio_actor_scheduling_and_source_channel_pool_lifetime_exclusive_contract_proved':False,
            'real_irq_clock_navigation_speaker_sep_ui_loading_verified':False,
            'device_io':False,'device_install_candidate':False,
            'limitations':'Original kernel creates decoder worker and executes normal post/wait/priority/context save/restore and self-exit. Controller/idle ready membership, stacks and construction bookkeeping are fixtures. Original AVDTP uses synthetic endpoint/channel/context and controlled Bluetooth mutex. Source actor still runs via explicit messages and Python context restoration on its fixture stack; restored stock wait is used for decoder/controller/idle, while only controlled mixer wait redirects to a Thumb return veneer. Source GET/handles/mutex/priority/start/activation/mixer/consumer read index remain supplied. Compiled release posts capacity event and decoder handles pending packet after controller waits, with no explicit step/notify/new packet; this is not hardware IRQ/timing or a fully native audio-actor scheduling test. Source post-selection/release boundaries, single actor/channel ownership/pool admission/not-yet-entered callback exclusion remain unproven in live firmware. TTS context/full ring unchanged, not true navigation speech/coexistence. No SEP/SDP/UI/phone/speaker/VPM acceptance or Google Maps. Retained worker stack/TCB and module are not recycled/unloaded. No device I/O.'}
    path=ROOT/'evidence/firmware-analysis/native-owned-worker-emulation.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(path),'routes':len(routes),'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
