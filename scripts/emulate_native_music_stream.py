#!/usr/bin/env python3
"""Original loader/registered wire callback -> guarded copying queue -> PCM.

Same VM as the preceding original outer/registration harness, new compiled
module only. Queue consumer is called cooperatively by this test, not by an OS
task. Finite READY PCM is inspected then canceled, never treated as DAC output.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
import unicorn
import importlib.metadata
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_tts_vpm import sha,require
from analyze_native_loader import IMAGE
from emulate_native_music_loaded import LoadedMusicVM,INPUT,STACK,RETURN,REGS,STATE,CHANNELS,MEDIA_LCID,PEER
from emulate_native_sbc import Reference,verify_guard_faults
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

BUILD='staging/native-music-stream/manifest.json'


class StreamVM(LoadedMusicVM):
    def __init__(self,stock,build):
        super().__init__(stock,build)
        self.consumer_calls=[]
        self.music_boundary_sites.add(self.sym['music_stream_configuration_gate'])

    def stream(self):
        raw=struct.unpack('<20Ii',self.uc.mem_read(self.sym['music_stream_state'],84))
        names=['active','session','local_seid','remote_seid','codec_word','prepared','configured','next_session',
               'queue_epoch','callbacks','enqueued','rejected','consumed','consumer_rejected','cancellations',
               'private_retired','slot0_session','slot1_session','slot2_session','slot3_session','last_error']
        return dict(zip(names,raw))

    def q(self):return struct.unpack('<9I',self.uc.mem_read(self.sym['media_queue_control'],36))
    def pipeline(self):return struct.unpack('<13I',self.uc.mem_read(self.sym['owned_media_control'],52))

    def feed(self,raw):
        before=self.stream();self.invoke(0x50bbb8,[MEDIA_LCID,0,len(raw)],payload=raw,pointer_arg=1)
        after=self.stream()
        return {'error':after['last_error'],'enqueued':after['enqueued']-before['enqueued'],
                'rejected':after['rejected']-before['rejected'],'queue_count':self.q()[2]}

    def step(self):
        self.returned=False;self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        self.uc.emu_start(self.sym['media_queue_step'],RETURN+2,count=6000000,timeout=30000000)
        require(self.returned and self.uc.reg_read(UC_ARM_REG_SP)==STACK,'Native queue consumer exceeded bounded call')
        require(not any(self.radio_locks.values()),'Consumer retained native radio lock')
        value=self.uc.reg_read(REGS[0]);result=value if value<0x80000000 else value-0x100000000
        self.consumer_calls.append(result);return result

    def collect_private(self):
        output=[];rows=[]
        while self.pipeline()[4]:
            ticket=self.invoke(self.sym['owned_media_next'],arm=True)
            row=struct.unpack('<6I',self.uc.mem_read(self.sym['memory_output_slots']+(ticket&3)*24,24))
            require(row[0]==ticket and row[1]==2 and row[2]>0,'PCM is not a private READY ticket')
            pcm=bytes(self.uc.mem_read(self.build['pcm_pages'][ticket&3],row[2]));output.append(pcm)
            rows.append({'ticket':ticket,'bytes':row[2],'sha256':sha(pcm),'state':'READY_never_published'})
            require(self.invoke(self.sym['music_stream_retire_private'],[ticket],arm=True)==0,
                    'Private PCM cancellation failed')
        return b''.join(output),rows

    def configure(self,config):
        b0={2:0x20,3:0x10}[config['frequency']]|{0:8,1:4,2:2,3:1}[config['mode']]
        b1={0:0x80,1:0x40,2:0x20,3:0x10}[config['blocks']]|{0:8,1:4}[config['subbands']]|{0:1,1:2}[config['allocation']]
        body=bytes([4,8,1,0,7,6,0,0,b0,b1,2,53])
        configured=self.wire(b'\x10\x03'+body)
        require(configured['new_sends'][0]['wire_hex']=='1203' and self.stream()['active']==1,
                'Native guarded configuration failed: '+str((configured,self.stream())))
        self.wire(bytes.fromhex('100604'))
        self.invoke(0x50b988,[0,MEDIA_LCID,0],payload=PEER,pointer_arg=0)
        data=bytearray(12);struct.pack_into('<H',data,8,1008)
        self.invoke(0x50b3dc,[MEDIA_LCID,0],payload=bytes(data),pointer_arg=1)
        self.invoke(0x50b1f8,[MEDIA_LCID,0]);self.wire(bytes.fromhex('100704'))
        require(self.byte(STATE+0x12)==8 and self.q()[4]==1,'Original native stream did not become ready/running')

    def disconnect(self):
        self.invoke(0x50be1c,[MEDIA_LCID])
        require(not self.stream()['active'] and not self.q()[4] and self.byte(STATE+0x12)==1,
                'Original disconnect did not cancel guarded stream')

    def guards(self):
        super().guards()
        require(bytes(self.uc.mem_read(IMAGE+12,len(self.original_voice_runtime)))==self.original_voice_runtime,
                'Music touched original voice runtime')
        base=self.build['extension_base']
        for a,n in [(base+0x15000,4096),(base+0x1f000,4096),(base+0x20000,16384),(base+0x24000,16384)]:
            require(bytes(self.uc.mem_read(a,n))==bytes(n),'PCM/queue padding or unbooted worker stack changed')
        require(not any(self.mutexes.values()),'Filesystem IRQ/kernel mutex retained')


def main():
    build=json.loads((ROOT/BUILD).read_text())
    for path,h in build['source_sha256'].items():require(sha((ROOT/path).read_bytes())==h,'Build source changed: '+path)
    guard_fault_controls=verify_guard_faults()
    reference=Reference();tables=json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    vm=StreamVM(NativeImage(),build);vm.boot();load=vm.load();vm.signaling_fixture()
    original=(ROOT/build['original_binary']).read_bytes();ram=struct.unpack_from('<I',original,4)[0]
    vm.original_voice_runtime=bytes(vm.uc.mem_read(IMAGE+12,ram-12));cases=[]
    def record(name,checks,extra=None):
        require(all(checks.values()),name+': '+str(checks));vm.guards()
        cases.append({'name':name,'passed':True,'checks':checks,'stream':vm.stream(),
            'queue':list(vm.q()),'pipeline':list(vm.pipeline()),'extra':extra or {}})
        print(json.dumps({'case':name,'passed':True}),flush=True)
    default={'frequency':2,'mode':3,'blocks':3,'subbands':1,'allocation':0,'bitpool':32}
    pre=vm.wire(bytes.fromhex('1003040801000706000021150235'))
    record('owned_SetConfiguration_rejected_until_output_initialized',{
        'preaccept_reject_before_state_or_session_change':pre['new_sends'][0]['wire_hex']=='13030031' and
            vm.byte(STATE+0x12)==1 and vm.stream()['session']==0,
        'no_callback_or_queue_started':vm.stream()['callbacks']==0 and not vm.q()[4]})
    require(vm.invoke(vm.sym['music_stream_output_prepare'],[0],arm=True)==0,'Private output configure failed')
    require(vm.invoke(vm.sym['music_stream_output_prepare'],[0],arm=True)==-16,'Repeated initialize not rejected')
    codec_cases=[];frames_total=0;packets_total=0;pcm_total=0
    for frequency in [2,3]:
        for mode in range(4):
            config=dict(default,frequency=frequency,mode=mode)
            vm.configure(config);frames=reference.encode(config,frames=6,bitpools=[2,32,53,8,16,53])
            rate=44100 if frequency==2 else 48000;channels=1 if mode==0 else 2
            wanted,_=reference_pcm(reference,frames,rate,channels,tables);actual=[];chunks=[]
            for pos in range(0,6,2):
                raw=packet(frames[pos:pos+2],pos,csrc=pos==0,extension=pos==2,padding=pos==4)
                require(vm.feed(raw)['enqueued']==1,'Valid native media not copied')
                # Destroy borrowed input after callback. Decoder must use its
                # queue copy, not this transient stock receive buffer/handle.
                vm.uc.mem_write(INPUT,b'\xcc'*4096)
                require(vm.step()==0,'Native queue/SBC/FIR failed')
                pcm,rows=vm.collect_private();actual.append(pcm);chunks.extend(rows)
            output=b''.join(actual);require(output==wanted,'Reference PCM mismatch')
            codec_cases.append({'frequency':rate,'mode':mode,'channels':channels,'frames':6,'packets':3,
                'session':vm.stream()['session'],'PCM_bytes':len(output),'PCM_sha256':sha(output),
                'byte_identical_to_upstream_SBC_and_independent_FIR':True,'private_PCM':chunks})
            frames_total+=6;packets_total+=3;pcm_total+=len(output)
            record('negotiated_'+str(rate)+'_mode'+str(mode)+'_guarded_copy_decode_finite_PCM',{
                'configured_guard_uses_original_registered_callback':vm.stream()['active']==1 and vm.q()[7]==vm.sym['music_stream_consume'],
                'three_packets_six_frames_PCM_byte_identical':output==wanted,
                'borrowed_input_destroyed_before_native_decode':True,
                'private_PCM_canceled_not_DAC_or_OS_playback':not vm.pipeline()[4]},codec_cases[-1])
            vm.disconnect()
    # Stateful rejection/cancellation controls use the real configured wire
    # chain. Explicit corrupt-state fixtures are restored, never used to fake
    # a successful SEP/ready transition.
    vm.configure(default);frames=reference.encode(default,frames=6);valid=packet(frames[:2])
    rejected=[]
    f1=bytearray(frames[0]);f1[1]^=0x40
    f2=bytearray(frames[1]);f2[2]=54
    bad_rtp=bytearray(valid);bad_rtp[0]=0
    fragmented=bytearray(valid);fragmented[12]|=0x80
    for name,raw in [('wrong_negotiated_rate',packet([bytes(f1)])),
                     ('second_frame_outside_negotiated_bitpool',packet([frames[0],bytes(f2)])),
                     ('invalid_RTP_version',bytes(bad_rtp)),('unsupported_fragment',bytes(fragmented)),
                     ('truncated_frame',valid[:-1]),('trailing_bytes',valid+b'\0')]:
        before=(vm.pipeline(),vm.q()[2],vm.q()[1]);r=vm.feed(raw)
        require(r['rejected']==1 and r['enqueued']==0 and before==(vm.pipeline(),vm.q()[2],vm.q()[1]),
                'Rejected framing advanced decoder or queue')
        rejected.append({'name':name,'callback_error':r['error']})
    record('all_frames_and_RTP_checked_before_queue_decode_publication',{
        'six_rejections_without_queue_or_decoder_advancement':len(rejected)==6,
        'later_frame_mismatch_has_no_published_prefix':not vm.pipeline()[4]},rejected)
    saved=bytes(vm.uc.mem_read(STATE+0x13,1));vm.uc.mem_write(STATE+0x13,b'\x01')
    busy=vm.feed(valid);vm.uc.mem_write(STATE+0x13,saved)
    saved=bytes(vm.uc.mem_read(STATE+12,2));vm.uc.mem_write(STATE+12,struct.pack('<H',len(valid)-1))
    over=vm.feed(valid);vm.uc.mem_write(STATE+12,saved)
    index=vm.byte(STATE+15);c=CHANNELS+index*8
    saved=bytes(vm.uc.mem_read(c+5,1));vm.uc.mem_write(c+5,b'\0');flags=vm.feed(valid);vm.uc.mem_write(c+5,saved)
    record('coherent_native_pending_local_receiveMTU_channel_flags_guards',{
        'pending_rejected':busy['error']==-17,'local_receiveMTU_rejected':over['error']==-19,
        'wrong_flags_rejected':flags['error']==-18,'no_packet_enqueued':all(r['enqueued']==0 for r in [busy,over,flags])})
    # Peer receive MTU is intentionally tiny; incoming uses the local limit.
    saved=bytes(vm.uc.mem_read(c+2,2));vm.uc.mem_write(c+2,struct.pack('<H',8))
    direction=vm.feed(valid);vm.uc.mem_write(c+2,saved)
    require(vm.step()==0,'Local/peer MTU direction test decode failed');pcm,_=vm.collect_private()
    wanted,_=reference_pcm(reference,frames[:2],44100,2,tables)
    record('local_receive_limit_distinct_from_peer_transmit_limit',{
        'larger_than_peer_limit_accepted_under_local672':direction['enqueued']==1 and len(valid)>8,
        'decoded_PCM_reference':pcm==wanted})
    vm.disconnect();vm.configure(default)
    # Four slots retain their own packets; fifth cannot overwrite them.
    for i in range(4):require(vm.feed(packet([frames[i]],i))['enqueued']==1,'Queue fill failed')
    full=vm.feed(packet([frames[4]],4));out=[]
    for _ in range(4):require(vm.step()==0,'Queue FIFO decode failed');out.append(vm.collect_private()[0])
    wanted,_=reference_pcm(reference,frames[:4],44100,2,tables)
    record('bounded_copy_queue_full_does_not_overwrite_FIFO',{
        'fifth_packet_rejected_full':full['error']==-23 and full['enqueued']==0,
        'four_copied_packets_retained_order_and_PCM':b''.join(out)==wanted})
    vm.disconnect();vm.configure(default);before=vm.stream()['session'];vm.feed(valid)
    vm.disconnect();vm.configure(default);after=vm.stream()['session'];stale=vm.step()
    record('disconnect_reconnect_reused_LCID_has_new_session_and_discards_old_work',{
        'session_increases':after>before,'queued_old_packet_not_decoded':stale==2 and not vm.pipeline()[4],
        'same_original_LCID_reconnected':struct.unpack('<H',vm.uc.mem_read(CHANNELS+vm.byte(STATE+15)*8,2))[0]==MEDIA_LCID})
    vm.feed(valid);slot=vm.q()[0];where=vm.sym['music_stream_state']+64+4*slot
    old_session=vm.word(where);vm.put(where,before);stale=vm.step();vm.put(where,old_session)
    record('captured_slot_session_checked_at_consumer_not_inferred_from_LCID',{
        'stale_queued_epoch_rejected':stale==-15,'no_finite_PCM_published':not vm.pipeline()[4]})
    vm.feed(valid);saved=bytes(vm.uc.mem_read(STATE+0x13,1));vm.uc.mem_write(STATE+0x13,b'\x01')
    moved=vm.step();vm.uc.mem_write(STATE+0x13,saved)
    record('consumer_rechecks_native_state_after_enqueue_before_decode',{
        'changed_pending_rejected_before_decode':moved==-17,'no_PCM_published':not vm.pipeline()[4]})
    # Decoder CRC failure after an earlier valid frame remains atomic: private
    # packet gathering never publishes that prefix. A following packet resets.
    vm.disconnect();vm.configure(default);crc=bytearray(frames[1]);crc[3]^=1
    accepted=vm.feed(packet([frames[0],bytes(crc)]));error=vm.step()
    record('later_SBC_CRC_error_has_no_private_PCM_prefix',{
        'framing_accepted_but_decoder_rejects':accepted['enqueued']==1 and error==-6,
        'whole_packet_not_published':not vm.pipeline()[4]})
    vm.feed(packet([frames[2]]));require(vm.step()==0,'CRC reset recovery failed');pcm,_=vm.collect_private()
    wanted,_=reference_pcm(reference,[frames[2]],44100,2,tables)
    record('after_CRC_failure_decoder_FIR_restart_matches_fresh_reference',{'fresh_reset_PCM':pcm==wanted})
    vm.disconnect();vm.configure(default);vm.feed(valid);old_epoch=vm.q()[3]
    pause=vm.wire(bytes.fromhex('100904'));paused=vm.feed(valid);vm.wire(bytes.fromhex('100704'))
    record('native_Suspend_invalidates_queue_Start_begins_clean_epoch',{
        'paused_receive_rejected':paused['error']==-17,
        'old_queue_discarded_new_epoch_running':vm.q()[2]==0 and vm.q()[3]>old_epoch and vm.q()[4]==1,
        'guard_session_retained':vm.stream()['active']==1})
    vm.feed(valid);require(vm.step()==0,'Outstanding private ticket setup failed');vm.disconnect()
    blocked=vm.wire(bytes.fromhex('1003040801000706000021150235'))
    record('new_configuration_rejected_while_old_private_PCM_retained',{
        'preaccept_ownership_busy':blocked['new_sends'][0]['wire_hex']=='13030031' and vm.byte(STATE+0x12)==1,
        'old_private_PCM_still_pinned':vm.pipeline()[4]==1 and not vm.stream()['active']})
    vm.collect_private();vm.configure(default)
    record('retiring_unpublished_PCM_allows_new_original_configuration',{
        'new_session_accepted_after_cleanup':vm.stream()['active']==1 and vm.byte(STATE+0x12)==8,
        'no_real_output_task_or_speaker_claim':vm.pipeline()[4]==0})
    deps=[Path(__file__),ROOT/'scripts/emulate_native_music_loaded.py',ROOT/'scripts/emulate_native_sbc.py',
      ROOT/'scripts/emulate_native_voice_media.py',ROOT/'scripts/emulate_native_voice_convert.py',
      ROOT/'scripts/emulate_native_pcm_converter.py',ROOT/'staging/native-pcm-converter/coefficients.json']
    previous=json.loads((ROOT/'staging/native-music-stream/previous-checkpoint.json').read_text())
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
      'emulator':{'binding_version':unicorn.__version__,'distribution_version':importlib.metadata.version('unicorn'),
                  'native_version':list(unicorn.uc_version()),'binding_file':unicorn.__file__,
                  'native_library':next(row.split()[-1] for row in Path('/proc/self/maps').read_text().splitlines() if 'libunicorn.so' in row)},
      'all_passed':True,'case_count':len(cases),'cases':cases,'build_manifest':BUILD,
      'build_manifest_sha256':sha((ROOT/BUILD).read_bytes()),'loader':load,'codec_formats':codec_cases,
      'format_count':len(codec_cases),'frames_reference_checked':frames_total,'packets_reference_checked':packets_total,
      'guard_fault_controls':guard_fault_controls,
      'PCM_reference_checked_bytes':pcm_total,'guard_and_failure_case_count':len(cases)-len(codec_cases),
      'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in deps},
      'previous_checkpoint':previous,'original_outer_load_registered_endpoint_wire_guard_queue_decoder_same_VM':True,
      'original40_voice_runtime_preserved_during_stream_tests':True,
      'captured_session_native_view_local_receiveMTU_RTP_all_frame_checks_integrated':True,
      'upstream_SBC_independent_FIR_private_PCM_byte_identical':True,
      'queue_consumer_cooperatively_called_not_booted_OS_worker':True,
      'READY_PCM_inspected_then_canceled_not_DAC_output':True,'radio_kernel_storage_cache_writability_fixtures':True,
      'native_OS_output_actor_speaker_navigation_coexistence_verified':False,
      'device_io':False,'device_install_candidate':False,'actual_package_acceptance_verified':False,
      'limits':'Same original outer loader/bootstrap/registered endpoint/native wire and loaded callback VM with fixture storage/kernel/cache/MAIN write permissions. Native callback snapshots under AVDTP lock, captures session per slot, verifies local receiveMTU/state/pending/channel/RTP/all SBC frames before copying, consumer rechecks captured session and native state then frozen whole-packet SBC/FIR produces owned finite READY PCM. Queue worker step explicitly called by test, PCM inspected then canceled as never published. No OS worker/output actor/real DAC/speaker/radio/phone/App/menu/navigation/lifetime/MMU/cache/device package acceptance or concurrent scheduling proof; large legacy signaling/fragmentation/jitter/reorder/inflight-cancel remain open.'}
    path=ROOT/'evidence/firmware-analysis/native-music-stream-emulation.json'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),'all_passed':True,
                      'formats':len(codec_cases),'frames':frames_total,'packets':packets_total}))


if __name__=='__main__':main()
