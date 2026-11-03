#!/usr/bin/env python3
"""Original AVDTP -> compiled queue/SBC/FIR -> owned PCM -> original actor.

Queue work/actor boundaries/consumer index are explicit test calls, not a
booted decoder worker or installed native hooks. No device I/O occurs.
"""
from datetime import datetime,timezone
import ctypes,json,struct
from pathlib import Path
from unicorn import UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_memory_completion import CompletionAudio
from emulate_native_memory_output import OwnedOutput
from emulate_native_memory_notice import check_manifest
from emulate_native_audio_registration import require,sha,MIX_DESCRIPTOR
from emulate_native_sbc import Reference,INPUT_PAGE,PAGE_BYTES,RETURN
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm
from emulate_avdtp_media import MediaDispatch,HANDLER,LOOKUP,VENEER


class OwnedDecoder(CompletionAudio):
    out=OwnedOutput.out
    state=OwnedOutput.state
    slots=OwnedOutput.slots
    register_owned=OwnedOutput.register_owned
    select_owned=OwnedOutput.select_owned

    def __init__(self,stock,companion,output):
        super().__init__(stock,companion)
        self.output=output;self.allowed_channels.add(self.channel)
        self.uc.mem_map(output['load_base'],(output['flat_binary_bytes']+4095)&~4095)
        self.uc.mem_write(output['load_base'],(ROOT/output['flat_binary']).read_bytes())
        self.uc.mem_protect(output['load_base'],(output['flat_binary_bytes']+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
        self.state_start=output['symbols']['__output_state_start']['address']
        self.state_end=output['symbols']['__output_state_end']['address']
        self.mapping_end=(self.state_end+4095)&~4095
        self.uc.mem_map(self.state_start,self.mapping_end-self.state_start)
        self.uc.mem_write(self.state_start,b'\xa5'*(self.mapping_end-self.state_start))
        self.uc.mem_write(self.state_start,bytes(self.state_end-self.state_start))
        self.buffers=output['pcm_pages'];self.buffer_expected={}
        for page in [*self.buffers,output['gather_page']]:
            self.uc.mem_map(page,PAGE_BYTES);self.uc.mem_write(page,b'\xa5'*PAGE_BYTES)
        payload=output['symbols']['__queue_payload_start']['address']
        self.uc.mem_map(payload,output['payload_bytes'])
        self.uc.mem_write(payload,b'\xa5'*output['payload_bytes'])
        self.symbols.update(output['symbols'])
        self.control=output['symbols']['memory_output_control']['address']
        self.slot_base=output['symbols']['memory_output_slots']['address']
        self.dispatch=MediaDispatch(stock,self.uc,self.address('media_queue_callback'))
        self.dispatch.configure(slot=2,channel_index=11,context_index=1)
        require(self.pipe('owned_media_init',(self.channel,))==0,'Owned decoder init failed')
        require(self.pipe('media_queue_begin')==0,'Owned queue begin failed')

    def address(self,name):return self.output['symbols'][name]['address']
    def pipeline(self):return struct.unpack('<13I',self.uc.mem_read(self.address('owned_media_control'),52))
    def queue_state(self):return struct.unpack('<9I',self.uc.mem_read(self.address('media_queue_control'),36))

    def pipe(self,name,args=(),stack=0x0990f000):
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        for reg,val in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):self.uc.reg_write(reg,val)
        address=HANDLER|1 if name=='stock_handler' else self.address(name)
        self.uc.emu_start(address,RETURN,timeout=30000000,count=6000000)
        require(self.uc.reg_read(UC_ARM_REG_PC)==RETURN,'Owned pipeline exceeded bounded endpoint')
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def deliver(self,data):
        pointer=INPUT_PAGE+PAGE_BYTES-len(data)
        self.uc.mem_write(INPUT_PAGE,b'\xa5'*PAGE_BYTES);self.uc.mem_write(pointer,data)
        require(self.pipe('stock_handler',(0x1234,pointer,len(data)))==0 and not self.dispatch.mutex_held,
                'Original AVDTP delivery failed')
        self.uc.mem_write(INPUT_PAGE,b'\xcc'*PAGE_BYTES)

    def retire_handle_fixture(self):
        # Both RTP temporary objects and source nodes use the inherited
        #16-page synthetic allocator. Reuse it only after all handles retire.
        require(all(h['freed'] for h in self.handles.values()) and
                not self.queue_state()[2] and not self.pipeline()[4] and
                not self.half(self.record+0x1c0),'Allocator fixture still has live references')
        self.verify()
        self.handles.clear();self.next_handle=1

    def play_one(self):
        ticket=self.pipe('owned_media_next');require(ticket>0,'No owned FIFO ticket')
        count=self.slots()[ticket&3]['bytes']
        payload=bytes(self.uc.mem_read(self.buffers[ticket&3],count))
        self.buffer_expected[ticket&3]=payload
        self.register_owned(ticket);self.select_owned(ticket);self.activate_fixture()
        actual=bytearray()
        for _ in range((count+255)//256):
            actual.extend(self.actor_pull())
            self.put(MIX_DESCRIPTOR+12,self.word(MIX_DESCRIPTOR+16)) # Explicit mixer consumer fixture.
        require(bytes(actual)==payload and self.actor_pull()==b'','Owned decoder PCM reader differs')
        require(self.pipe('owned_media_release',(ticket,))==-25,'EOF released PCM early')
        self.stop_cleanup();self.remove_first()
        require(self.pipe('owned_media_release',(ticket,))==0,'Complete actor lifecycle release failed')
        return bytes(actual)

    def verify(self):
        super().verify()
        require(not self.state()['native_calls'] and not self.state()['reader_in_flight'],'Output call retained')
        require(bytes(self.uc.mem_read(self.state_end,self.mapping_end-self.state_end))==
                b'\xa5'*(self.mapping_end-self.state_end),'Metadata guard changed')
        require(bytes(self.uc.mem_read(self.output['load_base'],self.output['flat_binary_bytes']))==
                (ROOT/self.output['flat_binary']).read_bytes(),'Compiled code changed')
        for i,p in self.buffer_expected.items():
            if self.slots()[i]['state']:
                require(bytes(self.uc.mem_read(self.buffers[i],len(p)))==p,'Immutable owned PCM changed')
        require({HANDLER,LOOKUP,VENEER}.issubset(self.dispatch.visited),'Original AVDTP route skipped')


def stream(m,reference,tables,frequency,mode):
    require(m.pipe('media_queue_stop')==0 and m.pipe('media_queue_begin')==0,'Stream reset failed')
    frames=reference.encode(dict(frequency=frequency,mode=mode,subbands=1,blocks=3,
                                allocation=0,bitpool=31 if mode==0 else 53),frames=10)
    rate=(16000,32000,44100,48000)[frequency];channels=1 if mode==0 else 2
    wanted,_=reference_pcm(reference,frames,rate,channels,tables)
    tts=m.tts_snapshot();before=m.pipeline()[8]
    for i in range(4):
        m.deliver(packet(frames[i*2:i*2+2],i))
        require(m.pipe('media_queue_step')==0,'Owned queue step failed')
    require(m.pipeline()[4]==4 and all(s['state']==2 for s in m.slots()),'Four PCM slots not held READY')
    m.deliver(packet(frames[8:],4))
    state=bytes(m.uc.mem_read(m.state_start,m.state_end-m.state_start))
    require(m.pipe('media_queue_step')==1 and m.queue_state()[2]==1 and
            bytes(m.uc.mem_read(m.state_start,m.state_end-m.state_start))==state,
            'Capacity deferral advanced decoder/FIR or lost compressed packet')
    require(m.pipe('media_queue_stop')==0 and m.pipe('media_queue_begin')==-25,
            'Restart with previously owned PCM was accepted')
    # Stop retains committed PCM; restart is tested separately. Recreate the
    #pending fifth packet after old PCM drain rather than mixing stream epochs.
    actual=b''.join(m.play_one() for _ in range(4))
    expected4,_=reference_pcm(reference,frames[:8],rate,channels,tables)
    require(actual==expected4 and m.tts_snapshot()==tts,'Four held PCM blocks differ')
    require(m.pipe('media_queue_begin')==0,'Restart after drain failed')
    m.retire_handle_fixture()
    # Rebuild identical codec history, then prove ordinary capacity recovery
    #without stop: fifth packet remains pending until a release and explicit step.
    actual=[]
    for i in range(4):
        m.deliver(packet(frames[i*2:i*2+2],i));require(m.pipe('media_queue_step')==0,'Second fill failed')
    m.deliver(packet(frames[8:],4));require(m.pipe('media_queue_step')==1,'Second capacity gate failed')
    actual.append(m.play_one())
    require(m.pipe('media_queue_step')==0 and m.queue_state()[2]==0,'Release did not permit pending work')
    actual.extend(m.play_one() for _ in range(4));actual=b''.join(actual)
    require(actual==wanted and m.pipeline()[4]==0 and m.pipe('owned_media_next')==0 and
            m.tts_snapshot()==tts,'Owned full-stream output or TTS isolation differs')
    m.verify()
    return {'rate':rate,'channels':channels,'decoded_frames':18,'processed_packets':9,
            'accepted_callback_packets':10,'stopped_pending_packets_discarded':1,
            'recovery_stream_frames':10,'pcm_bytes':len(actual), 'pcm_sha256':sha(actual),
            'upstream_sbc_absolute_convolution_byte_identical':True,
            'four_pcm_slots_defer_without_advancing_decoder_or_fir':True,
            'pending_packet_after_release_processed_by_explicit_step':True,
            'stop_keeps_committed_pcm_and_restart_requires_drain':True,
            'committed_blocks_delta':m.pipeline()[8]-before,
            'original_avdtp_and_source_actor_executed':True,'tts_context_ring_unchanged':True,'passed':True}


def controls(m,reference):
    config=dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31)
    frames=reference.encode(config,frames=2)
    require(m.pipe('media_queue_stop')==0 and m.pipe('media_queue_begin')==0,'Control reset failed')
    m.retire_handle_fixture()
    bad=bytearray(frames[1]);bad[3]^=1
    before=m.pipeline()[8];generation=m.state()['generation']
    m.deliver(packet([frames[0],bytes(bad)],0))
    require(m.pipe('media_queue_step')==-6 and m.pipeline()[4]==0 and
            m.pipeline()[8]==before and m.state()['generation']==generation,
            'Later CRC failure published a PCM prefix')
    m.deliver(packet(frames,1));require(m.pipe('media_queue_step')==0,'CRC recovery failed')
    actual=m.play_one();wanted=b''.join(reference.decode_stream(frames))
    require(actual==wanted,'CRC reset retained speculative codec/FIR history')
    require(m.pipe('media_queue_stop')==0 and m.pipe('media_queue_begin')==0,'Maximum packet reset failed')
    maximum=reference.encode(config,frames=15)
    m.deliver(packet(maximum,2));require(m.pipe('media_queue_step')==0,'Maximum packet failed')
    maximum_pcm=m.play_one()
    require(len(maximum_pcm)==3840 and maximum_pcm==b''.join(reference.decode_stream(maximum)),
            'Maximum fifteen-frame gather/owned PCM differs')
    cancel_cases=[]
    for name in ('owned_media_submit_frame','memory_output_submit'):
        require(m.pipe('media_queue_stop')==0 and m.pipe('media_queue_begin')==0,'Cancel reset failed')
        m.deliver(packet(frames,2));committed=m.pipeline()[8]
        m.stop_address=m.address(name)
        m.uc.reg_write(UC_ARM_REG_SP,0x0990c000);m.uc.reg_write(UC_ARM_REG_LR,RETURN)
        m.uc.emu_start(m.address('media_queue_step'),RETURN,timeout=30000000,count=6000000)
        require(m.uc.reg_read(UC_ARM_REG_PC)==m.stop_address,'Missed cancellation boundary')
        paused=m.uc.context_save()
        require(m.pipe('media_queue_stop')==0,'In-flight stop failed')
        pc=m.stop_address;m.stop_address=None;m.uc.context_restore(paused)
        m.uc.emu_start(pc,RETURN,timeout=30000000,count=6000000)
        require(m.uc.reg_read(UC_ARM_REG_PC)==RETURN and
                ctypes.c_int32(m.uc.reg_read(UC_ARM_REG_R0)).value==-24 and
                not m.pipeline()[4] and m.pipeline()[8]==committed and
                all(s['state']==0 for s in m.slots()),'Canceled packet published/retained PCM')
        cancel_cases.append(name)
    m.verify()
    return {'later_crc_failure_publishes_no_native_pcm_prefix':True,
            'maximum_fifteen_frame_packet_pcm_bytes':len(maximum_pcm),
            'maximum_gather_native_pcm_reference_identical':True,
            'next_valid_packet_after_reset_matches_reference':True,
            'stop_before_decode_and_during_private_submit_cancel_before_fifo_commit':cancel_cases,
            'separate_stacks_python_context_restore':True,
            'actual_irq_quiescence_or_worker_wakeup_verified':False,'passed':True}


def main():
    stock=NativeImage()
    cp=ROOT/'staging/native-media-consumer/manifest.json';op=ROOT/'staging/native-owned-media/manifest.json'
    companion,output=map(check_manifest,(cp,op))
    reference=Reference()
    cm=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cm['coefficient_table']).read_text())['tables']
    routes=[]
    for f,q in ((0,0),(2,3),(3,2)):
        # Each independent route stays within the unchanged16-handle fixture;
        #do not turn its synthetic allocator into an unbounded heap.
        m=OwnedDecoder(stock,companion,output)
        routes.append(stream(m,reference,tables,f,q))
    checks=controls(m,reference)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'script_sha256':sha(Path(__file__).read_bytes()),'owned_elf_sha256':output['elf_sha256'],
            'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in
                (cp,op,ROOT/'scripts/emulate_native_memory_output.py',
                 ROOT/'scripts/emulate_native_memory_completion.py',ROOT/'scripts/emulate_avdtp_media.py',
                 ROOT/'scripts/emulate_native_voice_convert.py',ROOT/'scripts/emulate_native_voice_media.py',
                 ROOT/'scripts/emulate_native_sbc.py')},
            'routes':routes,'controls':checks,'all_passed':True,
            'queue_steps_and_actor_hooks_explicit_test_calls':True,'decoder_worker_booted':False,
            'synthetic_handle_allocator_reused_only_at_all_released_phase_boundaries':True,
            'kernel_release_capacity_wakeup_exercised':False,'real_endpoint_registration_verified':False,
            'native_source_actor_and_pool_ownership_are_caller_contracts':True,
            'existing_navigation_tts_imports_or_ring_modified':False,
            'device_io':False,'device_install_candidate':False,
            'limitations':'Standalone original AVDTP handler/lookup/veneer with synthetic SEP/channel/context and controlled Bluetooth mutex. Compiled derived queue, whole-packet SBC/FIR and owned PCM run; original native kind10 actor13/18/15/19/list-remove and reader copy also run. Steps, admission/post-selection/release and mixer consumer read-index advancement are explicit test calls; no decoder task boot or kernel capacity wakeup here, no hardware14/DMA/drain/speaker. Four slots defer before codec/FIR advancement; only one producer owns decode/submit. CRC/stop-before-commit drop tentative output; stop after commit keeps queued PCM until serialized drain and new begin rejects remaining PCM. Actor/channel-list/allocation boundary exclusivity remain supplied contracts, not real cross-actor reservation/not-yet-entered callback quiescence/unload. Existing TTS context/whole ring stay unchanged; no VPM merge/acceptance, real SEP/SDP/UI/phone audio/navigation concurrency or Google Maps. Worker/wake support linked but unexercised. No device installation.'}
    path=ROOT/'evidence/firmware-analysis/native-owned-media-emulation.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(path),'routes':len(routes),'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
