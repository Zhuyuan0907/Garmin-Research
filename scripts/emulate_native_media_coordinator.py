#!/usr/bin/env python3
"""Compiled finite-source pump/full queued-data cancel; explicitly polled offline.

The host supplies incoming packets and virtual frames/pump polls. Source
registration/start/removal/release are compiled calls on the captured actor.
No coordinator worker, real Bluetooth endpoint/hardware or device package.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_playback_control import BeforeStartDriver
from emulate_native_source_controller import NativeCentral, SOURCE_STATES
from emulate_native_audio_registration import require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

FIELDS=('initialized','owner_tcb','busy','ticket','cancel_pending','stop_sent',
        'starts','completed','cancelled','discarded','remove_calls','pump_calls',
        'cancel_calls','failures','last_result')


class CoordinatedDriver(BeforeStartDriver):
    def __init__(self,stock,companion,output,playback,coordinator):
        self.coord_ready=False;self.coord_events=[];self.cancel_notices=[]
        super().__init__(stock,companion,output,playback)
        require(coordinator['owned_elf_sha256_required']==output['elf_sha256'],'Coordinator import version differs')
        self.coordinator=coordinator
        base=coordinator['load_base'];n=(coordinator['flat_binary_bytes']+4095)&~4095
        self.uc.mem_map(base,n);self.uc.mem_write(base,(ROOT/coordinator['flat_binary']).read_bytes())
        self.uc.mem_protect(base,n,UC_PROT_READ|UC_PROT_EXEC)
        self.coord_bss=coordinator['symbols']['__coordinator_state_start']['address']
        self.coord_end=coordinator['symbols']['__coordinator_state_end']['address']
        self.uc.mem_map(self.coord_bss,4096);self.uc.mem_write(self.coord_bss,b'\xa5'*4096)
        self.uc.mem_write(self.coord_bss,bytes(self.coord_end-self.coord_bss))
        self.native_aliases.update({n:v['address'] for n,v in coordinator['symbols'].items()
                                    if n.startswith('media_coordinator')})
        self.coord_ready=True

    def coord(self):
        return dict(zip(FIELDS,struct.unpack('<14Ii',self.uc.mem_read(self.coord_bss,60))))

    def assert_coord_call(self):
        state=self.coord();lr=self.uc.reg_read(UC_ARM_REG_LR)
        require(self.current()==state['owner_tcb']==self.controller and state['busy']==1 and
                self.coordinator['load_base'] <= lr < self.coordinator['load_base']+self.coordinator['flat_binary_bytes'],
                'Lifecycle operation not called from compiled coordinator on captured actor')

    def observe(self,uc,address,size,data):
        if self.coord_ready:
            if address==self.address('memory_output_register'):
                self.assert_coord_call();t=uc.reg_read(UC_ARM_REG_R0);slot=self.slots()[t&3]
                require(slot['ticket']==t and slot['state']==2,'Coordinator did not register READY PCM')
                self.buffer_expected[t&3]=bytes(uc.mem_read(self.buffers[t&3],slot['bytes']))
                self.coord_events.append({'kind':'register','ticket':t,'bytes':slot['bytes'],'current':self.current()})
            if address==self.address('owned_media_release'):
                self.assert_coord_call()
                require(not self.half(self.record+0x1c0) and not self.state()['native_calls'] and
                        not self.state()['reader_in_flight'] and not self.byte(self.record+2) and
                        not self.byte(self.mixer+0x84),'Coordinator released before native retirement')
                self.coord_events.append({'kind':'release','ticket':uc.reg_read(UC_ARM_REG_R0),'current':self.current()})
            if address==0x277674:
                self.assert_coord_call()
                require(self.coord()['cancel_pending']==1 and self.state()['native_calls']==1,
                        'Original public remover not protected through completion')
                self.coord_events.append({'kind':'public_remove','current':self.current()})
            if address==0x277596 and self.current()==self.controller:
                require(self.coord()['busy']==self.coord()['cancel_pending']==1 and
                        self.state()['native_calls']==1 and not self.byte(self.record+2) and
                        not self.byte(self.mixer+0x84) and not self.half(self.driver_record) and
                        uc.reg_read(UC_ARM_REG_R0)==self.record+0x1a8 and
                        uc.reg_read(UC_ARM_REG_R1)==0 and self.half(self.record+0x1c0)==1,
                        'Compiled cancel did not reach original stopped-source deletion boundary')
                self.original_node_removals.append({'current':self.current(),'driver':self.record+0x1a8,
                    'index':0,'node_count_at_entry':1,'internal_entry':hex(address),'actor':'coordinator'})
                NativeCentral.observe(self,uc,address,size,data)
                return  # Skip only old natural-removal must-be-mixer assertion; original body executes.
            if address==0x2775e6 and self.current()==self.controller:
                require(self.state()['native_calls']==1 and self.half(self.record+0x1c0)==1,
                        'Early report23 incorrectly treated as completed removal')
                self.cancel_notices.append({'current':self.current(),'native_calls':1,'node_count':1,
                                             'completed_remove_return':False})
            if address==0x277694 and self.current()==self.controller:
                require(self.state()['native_calls']==1 and not self.half(self.record+0x1c0),
                        'Private removal hold ended before public return')
                self.coord_events.append({'kind':'public_remove_return','current':self.current(),
                                          'native_calls':1,'node_count':0})
        super().observe(uc,address,size,data)

    def pump(self):
        result=self.kernel_call('media_coordinator_pump');self.yield_all();return result

    def initialize(self):
        require(self.kernel_call('media_coordinator_pump')==-34,'Uninitialized coordinator accepted call')
        require(self.kernel_call('media_coordinator_init')==0 and
                self.coord()['owner_tcb']==self.controller,'Original current-TCB owner capture failed')
        require(self.kernel_call('media_coordinator_init')==-25,'Coordinator reinitialized')

    def verify_coordinator(self):
        require(not self.coord()['busy'] and not self.coord()['ticket'] and
                not self.coord()['cancel_pending'] and
                bytes(self.uc.mem_read(self.coordinator['load_base'],self.coordinator['flat_binary_bytes']))==
                (ROOT/self.coordinator['flat_binary']).read_bytes() and
                bytes(self.uc.mem_read(self.coord_end,self.coord_bss+4096-self.coord_end))==
                b'\xa5'*(self.coord_bss+4096-self.coord_end),'Coordinator retained work/changed code or guard')
        for a in (0x277674,0x277596,0x3009a0,0x3008b0,0x358d24):
            require(bytes(self.uc.mem_read(a,4))==self.stock.read(a,4),'Original removal/sync/current query changed')
        self.verify_playback()


def make(stock,manifests):return CoordinatedDriver(stock,*manifests)


def stream(stock,manifests,reference,tables,frequency,mode):
    m=make(stock,manifests);m.initialize();tts=m.tts_snapshot()
    frames=reference.encode(dict(frequency=frequency,mode=mode,subbands=1,blocks=3,
                                allocation=0,bitpool=31 if mode==0 else 53),frames=10)
    rate,channels=(16000,32000,44100,48000)[frequency],1 if mode==0 else 2
    wanted,_=reference_pcm(reference,frames,rate,channels,tables)
    for i in range(5):m.deliver(packet(frames[2*i:2*i+2],i));m.yield_all()
    require(m.pipeline()[4]==4 and m.queue_state()[2]==1,'Four-held/fifth-pending capacity gate differs')
    require(m.pump()==0 and m.coord()['starts']==1,'Compiled pump did not select/start first block')
    for _ in range(30):
        if m.half(m.driver_record):m.frame()
        require(m.pump() in (0,1),'Compiled source pump failed')
        if m.coord()['completed']==5 and not m.coord()['ticket']:break
    stereo=b''.join(wanted[i:i+2]*2 for i in range(0,len(wanted),2))
    require(m.coord()['starts']==m.coord()['completed']==5 and not m.pipeline()[4] and
            not m.queue_state()[2] and b''.join(m.native_chunks)==wanted and
            b''.join(m.peripheral_chunks)==stereo and m.tts_snapshot()==tts,
            'Compiled next-block/release wake/native virtual output differs from reference')
    require(sum(e['kind']=='register' for e in m.coord_events)==5 and
            sum(e['kind']=='release' for e in m.coord_events)==5 and
            not m.cancel_notices and len(m.original_node_removals)==5,
            'Compiled lifecycle counts or natural actor removal differ')
    require(m.pipe('media_worker_shutdown')==0,'Decoder shutdown failed')
    m.yield_all();m.verify_coordinator()
    return {'rate':rate,'channels':channels,'decoded_frames':10,'packets':5,'pcm_bytes':len(wanted),
        'pcm_sha256':sha(wanted),'peripheral_pcm_bytes':len(stereo),'peripheral_pcm_sha256':sha(stereo),
        'coordinator':m.coord(),'compiled_lifecycle_events':m.coord_events,
        'guarded_read_calls':len(m.guarded_reads),'original_read_calls':len(m.original_reads),
        'source_node_removals':m.original_node_removals,
        'four_held_fifth_deferred_then_compiled_owned_release_native_kernel_wakeup':True,
        'controller_direct_register_start_remove_or_owned_release':False,
        'host_pump_polling_and_virtual_frames_remain':True,'passed':True}


def cancel(stock,manifests,reference):
    m=make(stock,manifests);m.initialize();tts=m.tts_snapshot()
    frames=reference.encode(dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31),frames=10)
    for i in range(5):m.deliver(packet(frames[2*i:2*i+2],i));m.yield_all()
    require(m.pipeline()[4]==4 and m.queue_state()[2]==1 and m.pump()==0,'Cancel capacity/source setup failed')
    reads=len(m.guarded_reads)
    require(m.kernel_call('media_coordinator_cancel')==1,'Compiled cancel did not enter pending native stop')
    m.yield_all()
    require(not m.queue_state()[2] and not m.queue_state()[4] and m.coord()['cancel_pending']==1 and
            m.pipeline()[4]==4,'Producer/pending-packet stop incorrectly recycled held PCM')
    for _ in range(10):
        if m.half(m.driver_record):m.frame()
        require(m.pump() in (0,1),'Compiled cancellation step failed')
        if not m.coord()['cancel_pending']:break
    require(m.coord()['cancelled']==1 and m.coord()['discarded']==m.coord()['remove_calls']==4 and
            m.coord()['starts']==1 and not m.pipeline()[4] and not m.half(m.record+0x1c0) and
            not m.state()['native_calls'] and not m.state()['reader_in_flight'] and
            all(s['state']==0 for s in m.slots()) and len(m.guarded_reads)==reads and
            len(m.cancel_notices)==4 and m.tts_snapshot()==tts,
            'Full queued-data cancel/pinned-until-removal/no-unplayed-reads invariants differ')
    committed=m.pipeline()[8]
    m.deliver(packet(frames[:2],5));m.yield_all()
    require(not m.queue_state()[2] and m.pipeline()[8]==committed and not m.pipeline()[4],
            'Stopped synthetic receive callback committed late PCM')
    require(m.kernel_call('media_coordinator_cancel')==0 and m.coord()['discarded']==4,
            'Repeated completed cancellation changed retired buffers')
    require(m.pipe('media_worker_shutdown')==0,'Cancelled decoder shutdown failed')
    m.yield_all();m.verify_coordinator()
    return {'decoded_frames_committed':8,'committed_packets':4,'pending_compressed_packets_cancelled':1,
        'queue_running_after_cancel':m.queue_state()[4],'queued_compressed_packets_after_cancel':m.queue_state()[2],
        'queued_owned_pcm_after_cancel':m.pipeline()[4],'all_private_pcm_slots_free':all(s['state']==0 for s in m.slots()),
        'coordinator':m.coord(),'guarded_reads':reads,'compiled_lifecycle_events':m.coord_events,
        'early_report23_observations':m.cancel_notices,'source_node_removals':m.original_node_removals,
        'all_queued_pcm_released_after_original_stopped_source_remove_returns':True,
        'never_selected_ready_pcm_register_remove_release_without_reads':3,
        'late_packet_not_committed_after_queue_stop':True,
        'host_pump_polling_and_virtual_frames_remain':True,'passed':True}


def main():
    stock,reference=NativeImage(),Reference()
    manifests=list(map(check_manifest,(ROOT/'staging/native-media-consumer/manifest.json',
        ROOT/'staging/native-owned-media/manifest.json',ROOT/'staging/native-playback-control/manifest.json',
        ROOT/'staging/native-media-coordinator/manifest.json')))
    cv=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables=json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes=[]
    for f,mode in ((0,0),(2,3),(3,2)):
        routes.append(stream(stock,manifests,reference,tables,f,mode))
        print(json.dumps({'rate':routes[-1]['rate'],'passed':True}),flush=True)
    cancelled=cancel(stock,manifests,reference);print(json.dumps({'cancelled':True,'passed':True}),flush=True)
    prior_path=ROOT/'evidence/firmware-analysis/native-playback-control-emulation.json'
    prior=json.loads(prior_path.read_text());paths=[ROOT/p for p in prior['dependency_sha256']]
    paths.extend((prior_path,ROOT/'scripts/emulate_native_playback_control.py',
                  ROOT/'staging/native-media-coordinator/manifest.json'))
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'script_sha256':sha(Path(__file__).read_bytes()),
        'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in paths},
        'coordinator_elf_sha256':manifests[-1]['elf_sha256'],
        'coordinator_flat_bytes':manifests[-1]['flat_binary_bytes'],'routes':routes,'cancellation':cancelled,
        'all_passed':True,'previous_compiled_artifacts_changed':False,'device_io':False,'device_install_candidate':False,
        'limitations':'Offline private-ABI coordinator on host controller actor captured by original current-TCB query; new compiled pump registers/starts/releases/selects next finite source, compiled cancel stops synthetic producer queue, waits native cleanup, holds native_calls across actual public mutex/list removal and releases all committed PCM. READY buffers register/remove without selection to use existing QUEUED release; pending compressed packet discarded, late stopped packet not committed. Host still supplies packets/virtual frames and explicitly polls pump, no coordinator native worker/automatic lifecycle wake/timer or infinite continuous stream/jitterless output. Exact frozen before-START hook only in emulator RAM; virtual addresses/private imports not loader acceptance/device memory placement. Actor identity gate is not global pool/list reservation or future callback quiescence; modules/tasks remain pinned, no safe unload. Wrong-actor/reentrant producer-busy cancellation, invalid-owned hook failure reconciliation/unrelated-channel bypass/multisource navigation/resampler/real hardware/SEP/phone/speaker/UI/App/VPM acceptance/Android Auto/Google Maps unproved. Inherited heap/frame/physical inventory/gain/power/arbitration remain fixtures, decoder shutdown explicit after tests. No device I/O.'}
    p=ROOT/'evidence/firmware-analysis/native-media-coordinator-emulation.json'
    p.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(p),'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
