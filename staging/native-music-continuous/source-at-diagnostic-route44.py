#!/usr/bin/env python3
"""Persistent source/FIFO in the loaded original-kernel VM, no device I/O.

Virtual frame arrival, physical inventory/MMU/cache/radio/storage remain the
explicit frozen fixtures. Silence underflow is characterized, not gapless or
real-time quality. Never install the experimental voice container.
"""
import argparse
import hashlib
from datetime import datetime, timezone
import json
import struct
from emulate_native_music_ready import *
from emulate_native_sbc import verify_guard_faults
from emulate_native_mixer_timer import CLOCK

BUILD = 'staging/native-music-continuous/manifest.json'
FIELDS = ['offset', 'reads', 'payload_bytes', 'silence_bytes', 'packets_consumed',
          'underflows', 'canceled_reads', 'capacity_posts']


def hash_path(path):
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


class ContinuousMusicVM(ReadyMusicVM):
    def __init__(self, *args, **kwargs):
        self.expected_pcm = b''
        self.reference_cursor = 0
        self.reader_call = None
        self.reader_trace = []
        self.last_slot_tickets = {}
        super().__init__(*args, **kwargs)
        self.native_aliases.update({n:v['address'] for n,v in self.app['symbols'].items()
                                   if n.startswith('continuous_')})

    def continuous(self):
        return dict(zip(FIELDS, struct.unpack('<8I', self.uc.mem_read(
            self.address('continuous_media_control'), 32))))

    def frame(self):
        super().frame()
        # Explicit virtual elapsed time paired with 4480-byte stereo16k frame
        # consumption: 70ms. Original timer tick/expiry/kernel wake/mixer read
        # execute; no host event is posted directly to force a source read.
        self.tick(70)

    def drain_until(self, predicate, limit=30):
        try:
            super().drain_until(predicate, limit)
        except Exception:
            (ROOT/'staging/native-music-continuous/failed-drain-snapshot.json').write_text(
                json.dumps({'snapshot':self.snapshot(),'timer_node':self.timer_node(),
                    'clock':self.word(CLOCK),'driver_state':self.half(self.driver_record),
                    'mixer_eof':self.byte(self.mixer+0x7e)},indent=2)+'\n')
            raise

    def observe(self, uc, address, size, data):
        if getattr(self, 'loaded_playback_ready', False):
            if address == self.address('memory_output_submit'):
                # The finite predecessor's observation retained the first
                # payload forever. Release that observation only after actual
                # FIFO state says FREE; never change guest state or payloads.
                for i,s in enumerate(self.slots()):
                    if s['state'] == 0 and not s['in_flight']:
                        self.buffer_expected.pop(i, None)
            if address == self.address('continuous_media_read'):
                require(self.current() == self.mixer_tcb and self.reader_call is None,
                        'FIFO reader not serialized on original mixer')
                self.reader_call = {'pointer':uc.reg_read(UC_ARM_REG_R0),
                    'capacity':uc.reg_read(UC_ARM_REG_R1),
                    'return':uc.reg_read(UC_ARM_REG_LR)&~1,
                    'payload_before':self.continuous()['payload_bytes'],
                    'running_before':bool(self.queue_state()[4])}
            elif self.reader_call and address == self.reader_call['return']:
                entry = self.reader_call
                self.reader_call = None
                returned = uc.reg_read(UC_ARM_REG_R0)
                payload = self.continuous()['payload_bytes']-entry['payload_before']
                require(returned <= entry['capacity'] and payload <= returned,
                        'Continuous reader count or payload exceeded capacity')
                raw = bytes(uc.mem_read(entry['pointer'], returned))
                wanted = self.expected_pcm[self.reference_cursor:self.reference_cursor+payload]
                require(raw[:payload] == wanted and len(wanted) == payload,
                        'Continuous source bytes differ from independent SBC/FIR reference')
                require(raw[payload:] == bytes(returned-payload), 'Underrun filler is not silence')
                self.reference_cursor += payload
                self.reader_trace.append({k:v for k,v in entry.items() if k!='return'} |
                    {'returned':returned, 'payload':payload, 'silence':returned-payload,
                     'PCM_sha256':sha(raw), 'reference_cursor':self.reference_cursor})
        super().observe(uc, address, size, data)

    def cancel_and_retire(self):
        before = self.reference_cursor
        self.yield_all()
        self.drain_until(lambda:not self.coord()['cancel_pending'] and not self.coord()['ticket']
                         and not self.pipeline()[4], limit=45)
        require(not self.state()['active_ticket'] and not self.half(self.record+0x1c0)
                and all(s['state']==0 and not s['in_flight'] for s in self.slots())
                and self.reference_cursor==before,
                'Cancellation failed to retire anchor/FIFO or consumed new PCM after stop')

    def stop_tasks(self):
        if self.coord()['ticket'] or self.pipeline()[4]:
            require(self.kernel_call('music_runtime_cancel')==0, 'Continuous cancellation failed')
            self.cancel_and_retire()
        super().stop_tasks()

    def snapshot(self):
        return super().snapshot() | {'continuous':self.continuous(),
            'reader_trace':self.reader_trace,'reference_cursor':self.reference_cursor,
            'compiled_reader_replaces_finite_read_only_for_owned_anchor':True}


def main():
    import unicorn
    args = argparse.ArgumentParser()
    args.add_argument('--case', choices=['route44', 'route48', 'suspend', 'disconnect', 'startup'])
    selected = args.parse_args().case
    app = json.loads((ROOT/BUILD).read_text())
    for path,h in app['source_sha256'].items():require(hash_path(path)==h,'Build source changed '+path)
    guards = verify_guard_faults()
    original = (ROOT/app['original_binary']).read_bytes()
    app['original_ram_bytes']=struct.unpack_from('<I',original,4)[0]
    app['manifest_path']=BUILD
    legacy_paths=['staging/native-media-consumer/manifest.json','staging/native-owned-media/manifest.json',
        'staging/native-playback-control/manifest.json','staging/native-media-coordinator/manifest.json',
        'staging/native-source-worker/manifest.json']
    legacy=list(map(check_manifest,(ROOT/p for p in legacy_paths)))
    stock=NativeImage();reference=Reference()
    tables=json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    cases=[]

    def config(frequency=2, mode=3):
        return dict(frequency=frequency,mode=mode,subbands=1,blocks=3,allocation=0,bitpool=32)

    def record(name,m,checks,extra):
        require(all(checks.values()),name+': '+repr(checks))
        m.stop_tasks()
        require(m.continuous()['payload_bytes']==m.reference_cursor and
                not m.reader_call and all(t['returned']==t['capacity']
                    for t in m.reader_trace if t['running_before']),
                'Full-capacity reads/reference cursor do not match')
        cases.append({'name':name,'passed':True,'checks':checks,'extra':extra,'snapshot':m.snapshot()})
        print(json.dumps({'case':name,'passed':True}),flush=True)

    def prepare(m,cfg,frames):
        rate=44100 if cfg['frequency']==2 else 48000
        channels=1 if cfg['mode']==0 else 2
        wanted,_=reference_pcm(reference,frames,rate,channels,tables)
        m.expected_pcm+=wanted
        return wanted

    def send(m,frames,seq):
        require(m.deliver(packet(frames,seq))[1]==1,'Packet was not copied into native queue')

    def feed_frames(m,frames,first_sequence=0):
        for i in range(0,len(frames),2):
            send(m,frames[i:i+2],first_sequence+i//2);m.yield_all()
            if m.pipeline()[4]>=4 or m.queue_state()[2]:m.frame()
        m.drain_until(lambda:m.reference_cursor==len(m.expected_pcm) and not m.pipeline()[4]
                      and not m.queue_state()[2],limit=45)

    for choice,frequency,mode,priority in [('route44',2,3,40),('route48',3,2,28)]:
        if selected and selected!=choice:continue
        m=ContinuousMusicVM(stock,legacy,app,priority);cfg=config(frequency,mode);m.configure(cfg)
        frames=reference.encode(cfg,frames=32);wanted=prepare(m,cfg,frames)
        send(m,frames[:2],0);m.yield_all()
        require(m.coord()['starts']==1 and m.coord()['ticket'] and not m.pipeline()[4]
                and m.byte(m.mixer+0x7e)==0 and m.half(m.record+0x1c0)==1,
                'Empty FIFO incorrectly ended the persistent native source')
        first_ticket=m.coord()['ticket'];first_instance=m.word(m.record+0xf0)
        first_reads=len(m.reader_trace)
        m.frame();m.frame()
        require(m.coord()['starts']==1 and m.coord()['ticket']==first_ticket and
                m.byte(m.mixer+0x7e)==0 and m.continuous()['underflows']>0,
                'Starvation stopped or restarted the source instead of silence')
        # Fill all PCM slots while the output ring is full. The fifth packet
        # must remain compressed until the real reader frees capacity.
        for i in range(1,5):send(m,frames[2*i:2*i+2],i)
        m.yield_all();send(m,frames[10:12],5);m.yield_all()
        held_before={'PCM':m.pipeline()[4],'compressed':m.queue_state()[2]}
        require(held_before=={'PCM':4,'compressed':1},'PCM FIFO did not exert real capacity backpressure')
        m.drain_until(lambda:not m.pipeline()[4] and not m.queue_state()[2],limit=45)
        feed_frames(m,frames[12:],6)
        native=b''.join(m.native_chunks)
        stereo=b''.join(native[i:i+2]*2 for i in range(0,len(native),2))
        peripheral=b''.join(m.peripheral_chunks)
        require(peripheral==stereo[:len(peripheral)],'Original virtual stereo output differs from mono source and silence')
        record('persistent_'+str(44100 if frequency==2 else 48000)+'_priority'+str(priority),m,{
            'all32_frames_reference_PCM':m.reference_cursor==len(wanted),
            'one_native_source_across16_packets':m.coord()['starts']==1 and m.coord()['ticket']==first_ticket,
            'native_instance_not_reallocated':m.word(m.record+0xf0)==first_instance,
            'no_original_EOF_or_node_removal_until_cancel':not m.original_node_removals and m.byte(m.mixer+0x7e)==0,
            'reader_capacity_event_resumed_fifth_packet':m.continuous()['capacity_posts']>0,
            'starvation_silence_and_later_payload':len(m.reader_trace)>first_reads and m.continuous()['silence_bytes']>0,
            'virtual_stereo_reference_including_explicit_silence':True},
            {'frames_reference_checked':32,'PCM_reference_bytes':len(wanted),'PCM_sha256':sha(wanted),
             'held_before_reader_wakeup':held_before,'source_ticket':first_ticket,'source_instance':first_instance,
             'virtual_output_bytes_before_stop':len(peripheral),'silence_bytes_before_stop':m.continuous()['silence_bytes']})

    for choice in ['suspend','disconnect','startup']:
        if selected and selected!=choice:continue
        m=ContinuousMusicVM(stock,legacy,app,defer_yield=(choice=='startup'));cfg=config()
        early=None
        if choice=='startup':
            early=m.wire(bytes.fromhex('1003040801000706000021150235'))
            require(early['new_sends'][0]['wire_hex']=='13030031','Unentered workers accepted configuration')
            m.yield_all()
        m.configure(cfg);frames=reference.encode(cfg,frames=12);prepare(m,cfg,frames)
        send(m,frames[:2],0);m.yield_all()
        first_session=m.stream_state()['session'];first_starts=m.coord()['starts']
        for i in range(1,5):send(m,frames[2*i:2*i+2],i)
        m.yield_all();send(m,frames[10:],5);m.yield_all()
        require(m.pipeline()[4]==4 and m.queue_state()[2]==1,'Cancellation setup lacks held/pending data')
        if choice=='disconnect':
            m.radio_call(0x50be1c,[MEDIA_LCID])
            busy=m.wire(bytes.fromhex('1003040801000706000021150235'))
            require(busy['new_sends'][0]['wire_hex']=='13030031' and busy['state']==1,'Busy disconnect configuration accepted')
        else:
            m.wire(bytes.fromhex('100904'));busy=m.wire(bytes.fromhex('100704'))
            require(busy['new_sends'][0]['wire_hex']=='13070431' and busy['state']==4,'Busy suspended START accepted')
        consumed=m.reference_cursor;m.cancel_and_retire()
        require(m.coord()['discarded']==4 and m.coord()['remove_calls']==1 and
                len(m.original_node_removals)==1,'Persistent cancellation did not remove one anchor and discard four slots')
        # Unplayed old PCM was canceled. A new start resets SBC/FIR; add only
        # the fresh reference after the already consumed original prefix.
        m.expected_pcm=m.expected_pcm[:consumed]
        if choice=='disconnect':m.configure(cfg)
        else:require(m.wire(bytes.fromhex('100704'))['state']==8,'Same-session resume failed')
        fresh=reference.encode(cfg,frames=2);wanted=prepare(m,cfg,fresh)
        send(m,fresh,6);m.yield_all()
        record('persistent_'+choice+'_cancel_resume',m,{
            'four_held_packets_plus_pending_compressed_canceled':not m.queue_state()[2] and m.coord()['discarded']==4,
            'one_original_anchor_removal_for_cancel':m.coord()['remove_calls']==1,
            'fresh_PCM_reference_after_resume':m.reference_cursor==len(m.expected_pcm),
            'one_new_source_start_after_cancel':m.coord()['starts']==first_starts+1,
            'session_policy':m.stream_state()['session']>first_session if choice=='disconnect' else m.stream_state()['session']==first_session,
            'unentered_startup_closed':early is None or early['state']==1},
            {'frames_reference_checked':4,'PCM_reference_bytes':consumed+len(wanted),'busy_reply':busy,'early_reply':early})

    paths=set(app['source_sha256']) | set(legacy_paths) | {BUILD,
        'scripts/emulate_native_music_continuous.py','scripts/emulate_native_music_ready.py'}
    frozen=json.loads((ROOT/'evidence/firmware-analysis/native-music-ready-emulation.json').read_text())
    paths.update(frozen['source_sha256']);paths.add('evidence/firmware-analysis/native-music-ready-emulation.json')
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':BUILD,'build_manifest_sha256':hash_path(BUILD),
        'source_sha256':{p:hash_path(p) for p in sorted(paths)},'case_count':len(cases),'cases':cases,'all_passed':True,
        'frames_reference_checked':sum(r['extra']['frames_reference_checked'] for r in cases),
        'PCM_reference_checked_bytes':sum(r['extra']['PCM_reference_bytes'] for r in cases),
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':guards,'persistent_original_kind10_anchor_with_bounded_PCM_FIFO':True,
        'original_loader_wire_kernel_mixer_source_cancel_same_VM':True,
        'temporary_underflow_silence_keeps_source_alive':True,
        'host_decoder_step_or_coordinator_pump_register_start_remove_release':False,
        'whole_packet_reference_before_FIFO_reuse_verified':True,
        'original_timer_expiry_drives_capacity_waiting_mixer':True,
        'virtual_70ms_ticks_and_output_frames_are_explicit_fixtures':True,
        'original_TTS40_runtime_preserved':True,'device_io':False,'device_install_candidate':False,
        'actual_package_acceptance_verified':False,'phone_speaker_navigation_verified':False,
        'long_duration_gapless_or_realtime_verified':False,
        'limits':'Offline loaded original DLL/kernel/wire integration with one compiled persistent kind10 anchor and copied FIFO. Reader replaces stock finite read for exact owned anchor before START; other methods remain original. Four4096-byte slots reused only after copy-return and stop retains anchor until original stop/cleanup/remove return. Temporary starvation fills silence; native mixer/ring/virtual stereo reference includes filler. Radio/storage/MMU/cache/heap/power/exclusive channel and peripheral arrival remain fixtures; virtual bridge still bypasses physical multisource dispatcher. No sustained phone pacing, clock/jitter/underrun tuning, gapless music, final fidelity, real IRQ/DAC/speaker/navigation/accepted VPM/App/menu/safe reload/unload. Full outer filesystem is separate frozen evidence. Module/TCBs/stacks/hooks remain pinned. Never transfer EMULATION-ONLY package.'}
    path=('staging/native-music-continuous/diagnostic-'+selected+'.json' if selected else
          'evidence/firmware-analysis/native-music-continuous-emulation.json')
    (ROOT/path).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':path,'cases':len(cases),'all_passed':True}),flush=True)


if __name__=='__main__':main()
