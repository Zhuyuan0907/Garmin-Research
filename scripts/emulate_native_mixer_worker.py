#!/usr/bin/env python3
"""Original kernel mixer task/FIFO plus owned decoder, entirely offline.

Original task creation, post/get/wait and source actor execute. Native source
selection/attachment/release and hardware consumption still have explicit
controller boundaries. No Python CPU context restoration drives the actor.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_SP,UC_ARM_REG_PC
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_owned_worker import OwnedWorker,WAIT,CODE,IDLE_ENTRY,POST
from emulate_native_memory_notice import check_manifest
from emulate_native_memory_completion import NOTICE_QUEUE
from emulate_native_audio_registration import MIX_DESCRIPTOR,MIX_BUFFER,SCRATCH,require,sha
from emulate_native_audio_messages import GET_MESSAGE,WORKER
from emulate_native_sbc import Reference,PAGE_BYTES
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

MESSAGE_POST=0x37bce4
MESSAGE_RESULT=0x37bc82
MESSAGE_PAGE=0x09620000
STATE_HINT=0x46cc7a


class NativeMixer(OwnedWorker):
    def __init__(self,stock,companion,output):
        self.native_audio=False;self.mixer_tcb=0;self.mixer_allocations={}
        self.message_sends=[];self.message_receives=[];self.message_origins=[];self.get_destination=None
        self.pull_before=None;self.native_chunks=[];self.read_batches=[]
        self.actor_stack_calls=[];self.native_actor_entries=0;self.fifo_wraps=0
        self.native_aliases={'stock_mixer_init':0x3b9b67,'stock_message_post':MESSAGE_POST|1,
                             'source_remove':0x277675,'queue_start':0x277537}
        super().__init__(stock,companion,output)
        for a in (0x387000,):
            if not any(lo<=a and a+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(a,4096);self.uc.mem_write(a,stock.read(a,4096))
        self.uc.mem_map(MESSAGE_PAGE,4096);self.uc.mem_write(MESSAGE_PAGE,b'\xa5'*4096)
        self.uc.mem_write(GET_MESSAGE,stock.read(GET_MESSAGE,4))
        self.uc.mem_write(MESSAGE_POST,stock.read(MESSAGE_POST,4))
        del self.control_hooks[MESSAGE_POST]
        # This external channel/timing hint is a hardware policy boundary.
        #Task creation, registration, wake and initial message13 are original.
        self.uc.mem_write(STATE_HINT,bytes.fromhex('7047'))
        self.control_hooks[STATE_HINT]='external_audio_state_hint'
        self.uc.mem_write(0x38756a,bytes.fromhex('7047'))
        self.native_audio=True

    def address(self,name):
        if name in self.native_aliases:return self.native_aliases[name]
        return super().address(name)

    def out(self,name,args=()):
        return self.pipe(name if name.startswith('memory_output_') else 'memory_output_'+name,args)

    def call(self,name,args=(),stack_args=()):
        if not self.native_audio:return super().call(name,args,stack_args)
        require(not stack_args,'Native controller fixture needs explicit stack-argument support')
        return self.kernel_call(name,args)

    def run_worker(self,*args,**kwargs):
        raise ValueError('Synthetic message actor/Python context restoration is forbidden here')

    def observe(self,uc,address,size,data):
        if not self.native_audio:
            super().observe(uc,address,size,data);return
        if address==0x38853c:
            n,kind,out=(uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2))
            if n in (8192,240) and out==0:
                require(kind==2 and len(self.mixer_allocations)<2,'Unexpected native mixer allocation')
                h=0xd1100000+len(self.mixer_allocations)+1
                p=0x09600000+len(self.mixer_allocations)*0x4000
                mapped=(n+4095)&~4095
                uc.mem_map(p,mapped);uc.mem_write(p,b'\xa5'*mapped)
                self.mixer_allocations[h]={'pointer':p,'bytes':n,'mapped':mapped,'locks':0}
                uc.reg_write(UC_ARM_REG_R0,h);return
        if address==0x388804 and uc.reg_read(UC_ARM_REG_R0) in self.mixer_allocations:
            a=self.mixer_allocations[uc.reg_read(UC_ARM_REG_R0)];a['locks']+=1
            uc.reg_write(UC_ARM_REG_R0,a['pointer']);return
        if address==0x38756a:
            uc.mem_write(uc.reg_read(UC_ARM_REG_R0),('Mixer'+str(self.channel)+'\0').encode('utf-16le'))
            uc.reg_write(UC_ARM_REG_R0,0);return
        if address==0x3b9c1e:
            self.mixer_tcb=self.word(self.mixer+0x78)
            require(self.mixer_tcb!=0,'Original initializer did not publish mixer TCB')
        if address==MESSAGE_POST:
            target=uc.reg_read(UC_ARM_REG_R0);pointer=uc.reg_read(UC_ARM_REG_R1)
            if target==NOTICE_QUEUE:
                raw=bytes(uc.mem_read(pointer,20))
                self.notice_packets.append({'channel':raw[0],'event':raw[1],
                    'packet_owner':struct.unpack_from('<I',raw,4)[0],'bytes':raw})
                uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,(CODE+0x40)|1);return
            require(target==self.mixer_tcb,'Native message target is not the original mixer task')
            require((self.byte(target+0x15)+1)%20!=self.byte(target+0x12),
                    'Fixture attempted to overfill the original one-empty-slot FIFO')
            self.message_sends.append(bytes(uc.mem_read(pointer,12)))
            self.message_origins.append({'current':self.current(),'kind':self.message_sends[-1][0]})
            if self.byte(target+0x15)==19:self.fifo_wraps+=1
            # Do not run inherited queue-message capture/stub here.
            return
        if address==GET_MESSAGE:
            require(self.current()==self.mixer_tcb,'Native get did not execute on mixer task')
            self.get_destination=uc.reg_read(UC_ARM_REG_R0)
            self.assert_actor_stack(address)
            # Execute the restored original FIFO getter, never fake transport.
            return
        if address==MESSAGE_RESULT:
            require(self.get_destination is not None,'Message return missing entry')
            if uc.reg_read(UC_ARM_REG_R0)==1:
                self.message_receives.append(bytes(uc.mem_read(self.get_destination,12)))
            self.get_destination=None
        if address==WORKER:self.native_actor_entries+=1
        if address in (0x2f9f2e,0x2f9cca,0x437a90):self.assert_actor_stack(address)
        if address==0x2f9cca:
            require(self.pull_before is None,'Nested original source pull')
            self.pull_before=self.word(MIX_DESCRIPTOR+16)
            uc.mem_write(SCRATCH-32,b'\xa5'*(32+256))
        if address==0x2fa576:
            require(self.pull_before is not None,'Original pull return missed entry')
            before=self.pull_before;self.pull_before=None
            after=self.word(MIX_DESCRIPTOR+16);n=(after-before)%2048
            require(n<=256,'One original read exceeded controlled scratch capacity')
            first=min(n,MIX_BUFFER+2048-before)
            raw=bytes(uc.mem_read(before,first))
            if first<n:raw+=bytes(uc.mem_read(MIX_BUFFER,n-first))
            require(bytes(uc.mem_read(SCRATCH-32,32))==b'\xa5'*32 and
                    bytes(uc.mem_read(SCRATCH+n,256-n))==b'\xa5'*(256-n),
                    'Original per-read scratch guard differs')
            require(bytes(uc.mem_read(MIX_BUFFER-32,32))==b'\xa5'*32 and
                    bytes(uc.mem_read(MIX_BUFFER+2048,32))==b'\xa5'*32,'Mixer ring guard differs')
            self.native_chunks.append(raw)
        super().observe(uc,address,size,data)

    def assert_actor_stack(self,address):
        a=self.mixer_allocations[self.word(self.mixer+0x34)]
        sp=self.uc.reg_read(UC_ARM_REG_SP)
        require(self.current()==self.mixer_tcb and a['pointer']<=sp<a['pointer']+a['bytes'],
                'Original source actor did not run on its scheduled kernel task/stack')
        self.actor_stack_calls.append({'address':address,'sp':sp,'tcb':self.current()})

    def yield_all(self):
        self.park_controller();self.activate_controller()
        if self.mixer_tcb:
            require(self.byte(self.mixer_tcb+22)==2 and self.word(self.mixer_tcb+4)==0,
                    'Original actor did not consume FIFO and block with empty mailbox')

    def post_audio(self,kind,arg=0):
        p=MESSAGE_PAGE+4096-12;raw=struct.pack('<BBHII',kind,self.channel,0,arg,0)
        self.uc.mem_write(p,raw)
        write=self.byte(self.mixer_tcb+0x15)
        self.kernel_call('stock_message_post',(self.mixer_tcb,p))
        require(self.byte(self.mixer_tcb+0x15)==(write+1)%20 and
                bytes(self.uc.mem_read(self.word(self.mixer_tcb+8)+write*12,12))==raw,
                'Original FIFO post did not copy/advance expected message')
        self.uc.mem_write(p,b'\xcc'*12)

    def select_native(self,ticket):
        require(self.out('selection_guard',(ticket,))==0,'Native pool admission failed')
        require(self.call('queue_start',(self.record+0x1a8,))==0,'Original queue start failed')
        if not self.mixer_tcb:
            require(self.kernel_call('stock_mixer_init',(self.channel,0))==0,'Original mixer init failed')
            require(self.byte(self.mixer_tcb+0x14)==12 and self.byte(self.mixer_tcb+0x13)==20,
                    'Original task message size/slot count differs')
        else:self.post_audio(13)
        self.yield_all()
        require(self.out('memory_output_after_selection',(ticket,))==0,'Explicit serialized attachment failed')
        saved=self.mixer_tcb
        self.activate_fixture()
        # The inherited hardware fixture writes a fake TCB; restore the real
        #handle before any post. Buffer/scratch/activation are still fixtures.
        self.put(self.mixer+0x78,saved)

    def pull_native(self):
        before=self.word(MIX_DESCRIPTOR+16);cursor=len(self.native_chunks)
        self.post_audio(18);self.yield_all()
        after=self.word(MIX_DESCRIPTOR+16);n=(after-before)%2048
        raw=b''.join(self.native_chunks[cursor:])
        require(len(raw)==n and n<=1792,'Native auto-read exceeded unconsumed fixture ring capacity')
        self.read_batches.append(n)
        return raw

    def play_native(self):
        ticket=self.pipe('owned_media_next');require(ticket>0,'Owned PCM FIFO empty')
        n=self.slots()[ticket&3]['bytes'];wanted=bytes(self.uc.mem_read(self.buffers[ticket&3],n))
        self.buffer_expected[ticket&3]=wanted
        self.register_owned(ticket);self.select_native(ticket)
        actual=bytearray()
        for _ in range((n+1791)//1792):
            chunk=self.pull_native();require(chunk,'Native actor stalled without PCM progress')
            actual.extend(chunk)
            self.put(MIX_DESCRIPTOR+12,self.word(MIX_DESCRIPTOR+16)) # Explicit hardware consumer fixture.
        require(bytes(actual)==wanted and self.pull_native()==b'','Native actor PCM/EOF differs')
        require(self.pipe('owned_media_release',(ticket,))==-25,'EOF released PCM early')
        self.post_audio(15);self.post_audio(19);self.yield_all()
        require(self.byte(self.mixer+0x84)==0 and self.byte(self.record+2)==0 and
                bytes(self.uc.mem_read(self.record+0xf4,68))==bytes(68),'Native cleanup left source active')
        require(self.call('source_remove',(self.record+0x1a8,0))==0,'Original node removal failed')
        require(self.pipe('owned_media_release',(ticket,))==0,'Complete native actor release failed')
        self.yield_all()
        return bytes(actual)

    def verify_native(self):
        self.verify_kernel()
        require(self.native_actor_entries==1 and self.worker_context is None and not self.shadow_waits,
                'Mixer actor restarted or used synthetic CPU restore/wait')
        require(self.message_sends==self.message_receives and self.fifo_wraps>0 and
                any(x['current']==self.mixer_tcb and x['kind']==18 for x in self.message_origins),
                'Original FIFO transport order/copy/wrap differs')
        require(self.word(self.mixer+0x78)==self.mixer_tcb,'Hardware fixture overwrote original task handle')
        for a in self.mixer_allocations.values():
            require(a['locks']==1,'Original initializer did not retain borrowed mixer allocation')
            if a['bytes']==8192:require(bytes(self.uc.mem_read(a['pointer'],64))==b'\xa5'*64,'Mixer stack crossed canary')
            else:require(bytes(self.uc.mem_read(a['pointer']+240,a['mapped']-240))==b'\xa5'*(a['mapped']-240),
                         'Original FIFO crossed240-byte allocation')
        for a in (WAIT,GET_MESSAGE,MESSAGE_POST):
            require(bytes(self.uc.mem_read(a,4))==self.stock.read(a,4),'Original wait/message entry changed')


def route(stock,companion,output,reference,tables,f,q):
    m=NativeMixer(stock,companion,output)
    frames=reference.encode(dict(frequency=f,mode=q,subbands=1,blocks=3,allocation=0,
                                bitpool=31 if q==0 else 53),frames=10)
    rate=(16000,32000,44100,48000)[f];channels=1 if q==0 else 2
    wanted,_=reference_pcm(reference,frames,rate,channels,tables);tts=m.tts_snapshot()
    for i in range(5):m.deliver(packet(frames[i*2:i*2+2],i));m.yield_all()
    require(m.queue_state()[2]==1 and m.pipeline()[4]==4,'Full owned output did not defer fifth packet')
    actual=b''.join(m.play_native() for _ in range(5))
    require(actual==wanted and m.pipeline()[4]==0 and m.tts_snapshot()==tts,'Scheduled native PCM/TTS isolation differs')
    require(m.pipe('media_worker_shutdown')==0,'Decoder shutdown failed');m.yield_all()
    require(m.worker_state()[6]==1 and m.byte(m.worker_tcb+22)==0x80,'Original decoder exit failed')
    m.verify_native()
    return {'rate':rate,'channels':channels,'frames':10,'packets':5,'pcm_bytes':len(actual),'pcm_sha256':sha(actual),
            'native_actor_entries':m.native_actor_entries,'original_message_count':len(m.message_sends),
            'fifo_wraps':m.fifo_wraps,'native_actor_stack_calls':len(m.actor_stack_calls),
            'original_actor_self_posted_read_messages':sum(x['current']==m.mixer_tcb and x['kind']==18 for x in m.message_origins),
            'individual_source_read_calls':len(m.native_chunks),'individual_reads_max_bytes':max(map(len,m.native_chunks)),
            'kernel_scheduled_decoder_and_audio_actor':True,'original_post_get_wait_fifo_executed':True,
            'python_cpu_context_restore_or_fake_message_transport_used':False,
            'serialized_attachment_release_messages_and_consumer_index_explicit':True,
            'hardware14_dma_automatic_playback_or_live_loading_verified':False,
            'upstream_codec_absolute_convolution_identical':True,'tts_full_context_ring_unchanged':True,'passed':True}


def capacity_control(stock,companion,output,reference,tables):
    m=NativeMixer(stock,companion,output)
    frames=reference.encode(dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31),frames=15)
    wanted,_=reference_pcm(reference,frames,16000,1,tables);tts=m.tts_snapshot()
    m.deliver(packet(frames,0));m.yield_all()
    require(m.pipeline()[4]==1 and len(wanted)==3840,'Maximum packet did not publish one3840-byte source')
    actual=m.play_native()
    require(actual==wanted and m.read_batches==[1792,1792,256,0] and m.tts_snapshot()==tts,
            'Native auto-read capacity stall/rearm lost or advanced PCM incorrectly')
    require(m.pipe('media_worker_shutdown')==0,'Capacity-control decoder shutdown failed');m.yield_all()
    m.verify_native()
    return {'case':'maximum_packet_small_mixer_capacity_and_explicit_consumer_rearm','frames':15,
            'pcm_bytes':len(actual),'pcm_sha256':sha(actual),'native_read_batches':m.read_batches,
            'fifo_wraps':m.fifo_wraps,'original_message_count':len(m.message_sends),
            'source_self_posts_until_space_insufficient_then_blocks':True,
            'consumer_read_index_and_next_read18_explicit_not_dma_or_native_capacity_irq':True,
            'native_source_fifo_order_guards_and_reference_identical':True,'passed':True}


def main():
    stock=NativeImage();reference=Reference()
    cp=ROOT/'staging/native-media-consumer/manifest.json';op=ROOT/'staging/native-owned-media/manifest.json'
    companion,output=map(check_manifest,(cp,op))
    cv=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes=[]
    for f,q in ((0,0),(2,3),(3,2)):
        routes.append(route(stock,companion,output,reference,tables,f,q))
        print(json.dumps({'rate':routes[-1]['rate'],'passed':True}),flush=True)
    controls=[capacity_control(stock,companion,output,reference,tables)]
    print(json.dumps({'capacity_control':'passed'}),flush=True)
    prior=json.loads((ROOT/'evidence/firmware-analysis/native-owned-worker-emulation.json').read_text())
    paths=[ROOT/p for p in prior['dependency_sha256']]
    paths.append(ROOT/'scripts/emulate_native_owned_worker.py')
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'script_sha256':sha(Path(__file__).read_bytes()),
            'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in paths},
            'owned_elf_sha256':output['elf_sha256'],'routes':routes,'controls':controls,'all_passed':True,
            'original_kernel_audio_actor_and_message_transport_verified_offline':True,
            'automatic_fifo_source_adapter_cross_actor_ownership_or_future_callback_quiescence_proved':False,
            'compiled_components_changed':False,'device_io':False,'device_install_candidate':False,
            'limitations':'Original mixer initializer builds/registers/wakes its task and copies initial message13; external audio timing/state hint, allocation/locking/name/bookkeeping remain controlled. Decoder and mixer execute original kernel post/wait/context switching; restored original12-byte post/get updates the20-slot240-byte FIFO, copy/order/wrap verified, with one empty slot reserved by fixture admission rather than proof of native full handling. No Python CPU context restoration or fake actor message delivery. Original source actor self-posts read18 while space remains and stops reading at the controlled mixer capacity; maximum3840-byte source reads1792/1792/256 after explicit consumer advancement/read18 rearm. Source attachment/controller queue start, initial13/18 and cleanup15/19, node removal/release and mixer consumer index remain explicit controller boundaries; hardware activation/scratch/ring, generic mutex/priority/busy/start remain fixtures, so no complete automatic FIFO source lifecycle/real DMA or actor lifetime/exclusive allocation proof. Scratch canaries are reseeded at each original pull entry; per-read checks precede aggregate output checks. Inherited hardware setup would replace mixer+78 with a fake TCB; fixture restores original handle before posting. Only one audio channel actor runs here. TTS context/full ring unchanged, not true navigation concurrency. Decoder exits with retained stack/TCB/module; audio actor stays blocked with pinned allocations, no unload/reuse. No real SEP/SDP/phone/UI/speaker/accepted package or Google Maps. No device I/O.'}
    p=ROOT/'evidence/firmware-analysis/native-mixer-worker-emulation.json'
    p.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(p),'routes':len(routes),'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
