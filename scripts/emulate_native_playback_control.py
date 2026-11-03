#!/usr/bin/env python3
"""Compiled before-START attachment and guarded retained-source replay, offline.

Hook is installed only in emulator RAM. Stock kernel/tasks/output retirement
run with the inherited virtual hardware inventory/peripheral/heap fixtures.
This is not a mounted native package or a complete stream/cancel coordinator.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_output_manager import NativeDriver
from emulate_native_source_controller import CENTRAL_GLOBAL, SOURCE_STATES, DRIVER_CALLBACK
from emulate_native_output_stop import snapshot
from emulate_native_audio_registration import require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm


class BeforeStartDriver(NativeDriver):
    def __init__(self, stock, companion, output, playback):
        self.hook_ready = False
        self.early_callbacks = []
        self.attach_calls = []
        self.guarded_reads = []
        self.original_reads = []
        self.callback_original_entries = []
        super().__init__(stock, companion, output)
        require(playback['owned_elf_sha256_required'] == output['elf_sha256'],
                'Private owned-media import version differs')
        self.playback = playback
        base = playback['load_base']
        size = (playback['flat_binary_bytes']+4095)&~4095
        self.uc.mem_map(base, size)
        self.uc.mem_write(base, (ROOT/playback['flat_binary']).read_bytes())
        self.uc.mem_protect(base, size, UC_PROT_READ | UC_PROT_EXEC)
        self.playback_bss = playback['symbols']['__playback_state_start']['address']
        self.playback_end = playback['symbols']['__playback_state_end']['address']
        self.uc.mem_map(self.playback_bss, 4096)
        self.uc.mem_write(self.playback_bss, b'\xa5'*4096)
        self.uc.mem_write(self.playback_bss, bytes(self.playback_end-self.playback_bss))
        self.native_aliases.update({n:v['address'] for n,v in playback['symbols'].items()
                                    if n.startswith('playback_')})
        self.hook_bytes = bytes.fromhex('014b1847c046')+struct.pack('<I', self.address('playback_callback_hook'))
        require(DRIVER_CALLBACK % 4 == 2 and stock.read(DRIVER_CALLBACK, 10).hex() ==
                playback['displaced_thumb_hex'], 'Original callback entry differs from displaced semantics')
        self.uc.mem_write(DRIVER_CALLBACK, self.hook_bytes)
        self.uc.ctl_remove_cache(DRIVER_CALLBACK, DRIVER_CALLBACK+10)
        self.hook_ready = True

    def playback_state(self):
        return dict(zip(('callback_entries','bypassed','attached','attach_rejected',
                         'rearm_attempts','rearmed','rearm_refused','last_result'),
                        struct.unpack('<7Ii', self.uc.mem_read(self.playback_bss, 32))))

    def observe(self, uc, address, size, data):
        if self.hook_ready:
            if address == self.address('playback_callback_hook'):
                descriptor = uc.reg_read(UC_ARM_REG_R0)
                if descriptor:
                    require(self.current() == self.word(CENTRAL_GLOBAL) and
                            descriptor == self.actual_descriptor and
                            self.word(self.record+0x108) == 0x48edf9,
                            'Before-start hook did not precede original reader activation')
                    self.early_callbacks.append({'current': self.current(), 'descriptor': descriptor,
                        'reader_before': hex(self.word(self.record+0x108)),
                        'source_slot_state': self.slots()[self.state()['active_ticket'] & 3]['state'],
                        'stack': uc.reg_read(UC_ARM_REG_SP), 'guarded_reads_before': len(self.guarded_reads)})
            if address == self.address('memory_output_after_selection'):
                require(self.current() == self.word(CENTRAL_GLOBAL) and
                        uc.reg_read(UC_ARM_REG_SP) % 8 == 0,
                        'Compiled attachment not on central task/aligned native hook stack')
                self.attach_calls.append({'current': self.current(), 'ticket': uc.reg_read(UC_ARM_REG_R0)})
            if address == self.address('playback_callback_original'):
                require(self.current() == self.word(CENTRAL_GLOBAL) and
                        self.word(self.record+0x108) == self.address('memory_output_read') and
                        self.state()['installed'] == 1,
                        'Original START body ran before compiled reader attachment')
                self.callback_original_entries.append({'current': self.current(),
                    'reader': hex(self.word(self.record+0x108)), 'stack': uc.reg_read(UC_ARM_REG_SP)})
            if address == self.address('memory_output_read'):
                require(self.current() == self.mixer_tcb and self.state()['installed'] == 1 and
                        self.playback_state()['attached'] == len(self.early_callbacks) and
                        len(self.callback_original_entries) == len(self.early_callbacks),
                        'Native source read escaped compiled before-START guard')
                self.guarded_reads.append({'current': self.current(), 'instance': uc.reg_read(UC_ARM_REG_R0)})
            if address == 0x48edf8 and self.current() == self.mixer_tcb:
                require(len(self.guarded_reads) == len(self.original_reads)+1,
                        'An original source read occurred without compiled reader entry')
                self.original_reads.append({'current': self.current(), 'instance': uc.reg_read(UC_ARM_REG_R0)})
        super().observe(uc, address, size, data)

    def select_native(self, ticket):
        require(self.out('selection_guard', (ticket,)) == 0 and
                self.byte(SOURCE_STATES+self.channel) == 1, 'Serialized queued source admission failed')
        before = len(self.early_callbacks)
        require(self.kernel_call('stock_source_start', (self.channel, 0)) == 0, 'Stock source start failed')
        self.yield_all()
        require(len(self.early_callbacks) == len(self.callback_original_entries) ==
                len(self.attach_calls) == before+1 and
                self.byte(self.record+2) == 1 and self.half(self.driver_record) == 3 and
                self.byte(self.mixer+0x84) == 1 and self.word(self.mixer) == self.actual_descriptor and
                self.word(self.record+0x108) == self.address('memory_output_read') and
                self.state()['installed'] == 1,
                'Native allocation/before-START attachment/original mixer activation failed')

    def verify_playback(self):
        require(bytes(self.uc.mem_read(DRIVER_CALLBACK, 10)) == self.hook_bytes and
                bytes(self.uc.mem_read(DRIVER_CALLBACK+10, 48)) == self.stock.read(DRIVER_CALLBACK+10, 48),
                'Explicit entry patch or preserved original callback body differs')
        require(bytes(self.uc.mem_read(self.playback['load_base'], self.playback['flat_binary_bytes'])) ==
                (ROOT/self.playback['flat_binary']).read_bytes() and
                bytes(self.uc.mem_read(self.playback_end, self.playback_bss+4096-self.playback_end)) ==
                b'\xa5'*(self.playback_bss+4096-self.playback_end), 'Playback code/metadata guard changed')
        require(len(self.guarded_reads) == len(self.original_reads) > 0 and
                self.state()['reads'] == len(self.guarded_reads) and
                not self.state()['reader_in_flight'] and not self.state()['native_calls'] and
                all(h['freed'] and not h['locks'] for h in self.output_handles.values()),
                'Reader pairing or native driver retirement incomplete')
        # Entry patch is deliberately removed only AFTER all native FIFOs are
        #blocked/empty, allowing inherited unchanged-entry checks. Runtime
        #patch identity/body preservation was checked above, not concealed.
        require(all(self.byte(tcb+22) == 2 and self.word(tcb+4) == 0 and t['sends'] == t['receives']
                    for tcb,t in self.aux_tasks.items()), 'Native tasks not idle before emulator hook removal')
        self.uc.mem_write(DRIVER_CALLBACK, self.stock.read(DRIVER_CALLBACK, 10))
        self.uc.ctl_remove_cache(DRIVER_CALLBACK, DRIVER_CALLBACK+10)
        self.hook_ready = False
        self.verify_central()


def route(stock, companion, output, playback, reference, tables, frequency, mode):
    m = BeforeStartDriver(stock, companion, output, playback)
    count = 15 if frequency == 0 else 2
    frames = reference.encode(dict(frequency=frequency, mode=mode, subbands=1, blocks=3,
                                   allocation=0, bitpool=31 if mode==0 else 53), frames=count)
    rate, channels = (16000,32000,44100,48000)[frequency], 1 if mode==0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    tts = m.tts_snapshot()
    require(m.kernel_call('playback_rearm', (0,)) == -28, 'Invalid rearm ticket accepted')
    require(m.kernel_call('playback_callback_hook', (0,)) == -20 and not m.callback_original_entries,
            'Full native hook did not reject NULL before original callback')
    m.deliver(packet(frames, 0));m.yield_all()
    ticket = m.pipe('owned_media_next')
    require(ticket > 0, 'No owned source')
    m.buffer_expected[ticket & 3] = wanted
    node = m.register_owned(ticket)
    m.select_native(ticket)
    require(b''.join(m.native_chunks) == wanted and m.state()['bytes_read'] == len(wanted),
            'First native reads did not all traverse compiled wrapper/reference PCM')
    require(m.kernel_call('playback_rearm', (ticket,)) == -25, 'Active playback permitted rearm')
    require(m.kernel_call('stock_public_stop', (m.channel,1)) == 0, 'Stock stop failed')
    m.yield_all()
    stages = [snapshot(m,ticket,'stop_requested')]
    require(m.kernel_call('playback_rearm', (ticket,)) == -25, 'Pending stop permitted rearm')
    for i in range(8):
        m.frame();stages.append(snapshot(m,ticket,f'stop_frame_{i+1}'))
        if not m.half(m.driver_record):break
    require(stages[-1]['source_state'] == 1 and stages[-1]['driver_state'] == 0 and
            not stages[-1]['prepared'] and not stages[-1]['mixer_active'] and
            stages[-1]['queue_nodes'] == 1 and stages[-1]['owned_release_result'] == -25 and
            not m.handles[node]['freed'] and not m.original_node_removals,
            'Original stop completion did not preserve the pinned source')
    require(m.kernel_call('playback_rearm', (ticket,)) == 0 and
            m.slots()[ticket & 3]['state'] == 3 and not m.state()['installed'] and
            m.slots()[ticket & 3]['instance'] == 0xffffffff and
            m.pipe('owned_media_release', (ticket,)) == -25,
            'Guarded C rearm failed or recycled pinned PCM')
    require(m.kernel_call('playback_rearm', (ticket,)) == -28, 'Repeated rearm accepted')
    native_before, peripheral_before = len(m.native_chunks), len(m.peripheral_chunks)
    m.select_native(ticket)
    require(b''.join(m.native_chunks[native_before:]) == wanted and
            m.state()['bytes_read'] == 2*len(wanted), 'Replayed original source PCM/guard count differs')
    for _ in range(8):
        m.frame()
        if m.byte(SOURCE_STATES+m.channel) == 1 and not m.half(m.record+0x1c0):break
    stereo = b''.join(wanted[i:i+2]*2 for i in range(0,len(wanted),2))
    require(b''.join(m.peripheral_chunks[peripheral_before:]) == stereo and
            m.half(m.record+0x1c0) == 0 and len(m.original_node_removals) == 1 and
            m.handles[node]['freed'] and m.tts_snapshot() == tts,
            'Replayed virtual output/native natural-end retirement/TTS differs')
    require(m.kernel_call('playback_rearm', (ticket,)) == -25, 'Deleted source permitted replay')
    require(m.pipe('owned_media_release', (ticket,)) == 0 and
            m.kernel_call('playback_rearm', (ticket,)) == -28, 'Final release/stale ticket guard failed')
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all();m.verify_playback()
    control = m.playback_state()
    require(control['attached'] == 2 and control['rearmed'] == 1 and
            control['attach_rejected'] == 1 and control['bypassed'] == 0,
            'Native hook/rearm control counters differ')
    return {'rate':rate,'channels':channels,'decoded_frames':count,'source_pcm_bytes':len(wanted),
        'source_pcm_sha256':sha(wanted),'replay_peripheral_pcm_bytes':len(stereo),
        'replay_peripheral_pcm_sha256':sha(stereo),'before_start_callbacks':m.early_callbacks,
        'compiled_attach_calls':m.attach_calls,'original_callback_entries':m.callback_original_entries,
        'guarded_read_calls':len(m.guarded_reads),'original_read_calls':len(m.original_reads),
        'all_first_reads_guarded':True,'control':control,'stop_stages':stages,
        'native_driver_events':m.output_events,'source_node_removals':m.original_node_removals,
        'controller_after_selection_or_native_state_overwrite':False,
        'stop_then_guarded_rearm_original_reselection_and_reference_identical_virtual_replay':True,
        'old_artifacts_unchanged_and_new_hook_only_in_emulator':True,'passed':True}


def main():
    stock, reference = NativeImage(), Reference()
    companion, output, playback = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
        ROOT/'staging/native-owned-media/manifest.json', ROOT/'staging/native-playback-control/manifest.json'))
    cv = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables = json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes = []
    for frequency,mode in ((0,0),(2,3),(3,2)):
        routes.append(route(stock,companion,output,playback,reference,tables,frequency,mode))
        print(json.dumps({'rate':routes[-1]['rate'],'passed':True}),flush=True)
    prior_path = ROOT/'evidence/firmware-analysis/native-output-stop-emulation.json'
    prior = json.loads(prior_path.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((prior_path,ROOT/'scripts/emulate_native_output_stop.py',
                  ROOT/'staging/native-playback-control/manifest.json'))
    result = {'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'script_sha256':sha(Path(__file__).read_bytes()),
        'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in paths},
        'owned_elf_sha256':output['elf_sha256'],'playback_elf_sha256':playback['elf_sha256'],
        'routes':routes,'all_passed':True,'previous_compiled_artifacts_changed':False,
        'new_compiled_playback_bytes':playback['flat_binary_bytes'],
        'device_io':False,'device_install_candidate':False,
        'limitations':'Offline exact-version compiled C/ARM shim, direct private imports into unchanged owned-media ELF; explicitly patches10 bytes at stock allocation callback2F998E in emulator RAM only. C call stack aligned then displaced semantics replayed/resume2F9998; original callback body preserved, hook removed/cache invalidated only after task FIFOs idle for inherited entry checks. All native reads, including first reads/replay, traverse original compiled memory_output_read; no controller after-selection call. Public stock stop retains queue node, new C rearm checks cleared provider/methods/mixer/driver/source state1/no in-flight private calls before transitioning own ACTIVE->QUEUED, retains PCM and original native state. Exclusive serialized channel/list owner and pinned modules still required; checks/IRQ exclusion do not establish global pool reservation/future callback exclusion/safe unload. Mono15-frame and stereo2-frame sources already reach writer EOF before stop, no long producer cancellation/continuous next-published-source/actual mute or fade quality. NULL full-hook rejection tested, failed owned attach retains allocations and lacks automatic failure cancellation; unrelated source bypass/multichannel navigation not executed. Inherited physical inventory/gain/peripheral/frame/heap/power/arbitration fixtures remain, no real IRQ/clock/DMA/DAC/speaker/realtime. No loader accepted package/UI/App/registered SEP/SDP/phone/native Android Auto/Google Maps. No device I/O.'}
    path = ROOT/'evidence/firmware-analysis/native-playback-control-emulation.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(path),'all_passed':True,'device_io':False}))


if __name__ == '__main__':main()
