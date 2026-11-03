#!/usr/bin/env python3
"""Original central source requests and driver-to-mixer callback, offline.

Boots stock central/notifier tasks and executes the public synchronous start.
Physical output requests/arbitration/power and the output descriptor remain
explicit fixtures. Reader attachment and retirement are still controlled.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_mixer_timer import NativeTimer
from emulate_native_mixer_worker import GET_MESSAGE, MESSAGE_POST, MESSAGE_RESULT
from emulate_native_owned_worker import POST, WAIT
from emulate_native_audio_registration import MIX_DESCRIPTOR, require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

CENTRAL_GLOBAL = 0x00f29360
NOTICE_GLOBAL = 0x00f2936c
SOURCE_STATES = 0x034e9398
DRIVER_REQUEST = 0x1d8c60
DRIVER_CALLBACK = 0x2f998e


class NativeCentral(NativeTimer):
    def __init__(self, stock, companion, output):
        self.central_ready = False
        self.aux_tasks = {}
        self.aux_get = {}
        self.driver_requests = []
        self.power_requests = []
        self.arbitration_requests = []
        self.sync_events = []
        self.driver_callbacks = []
        self.central_start_calls = []
        self.native_sync_visits = set()
        super().__init__(stock, companion, output)
        # These addresses belong to a verified startup zero range. Queue
        #storage is above each stack end; the 1 KiB lower bound below is a
        #test guard, not a recovered original stack allocation boundary.
        for p in range(0x034ea000, 0x034ee000, 4096):
            require(any(r['runtime_start'] <= p and p+4096 <= r['runtime_end']
                        for r in stock.zeros if not r['conditional']),
                    'Auxiliary task RAM is not verified normal startup BSS')
            if not any(lo <= p and p+4095 <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(p, 4096)
        self.native_aliases.update({'stock_central_init': 0x30ee63,
            'stock_source_start': 0x36b721, 'stock_source_state': 0x3b967d,
            'stock_condition_init': 0x3ec541, 'stock_driver_callback': DRIVER_CALLBACK | 1,
            'stock_driver_outcome11': 0x1d9141, 'stock_driver_outcome12': 0x1d9161})
        del self.policy[0x36b720]
        self.uc.mem_write(0x36b720, stock.read(0x36b720, 4))
        self.uc.ctl_remove_cache(0x36b720, 0x36b724)
        # Run real kernel mutexes for this phase, including the mutex checked
        #by stock condition wait. No generic owner/depth success shim remains.
        for a in (0x3009a0, 0x3008b0):
            del self.control_hooks[a]
            self.uc.mem_write(a, stock.read(a, 4))
            self.uc.ctl_remove_cache(a, a+4)
        self.hardware_fixtures = {DRIVER_REQUEST: 'physical_output_request',
                                  0x4c2800: 'channel_arbitration',
                                  0x276148: 'power_state_query',
                                  0x3e0088: 'physical_power'}
        for a in self.hardware_fixtures:
            page = a & ~4095
            if not any(lo <= page and page+4095 <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                self.uc.mem_write(page, stock.read(page, 4096))
            self.uc.mem_write(a, bytes.fromhex('1eff2fe1') if a == 0x3e0088 else bytes.fromhex('7047'))
            self.uc.ctl_remove_cache(a, a+4)
        for end in (0x034eb42c, 0x034ebce0):
            self.uc.mem_write(end-1024, b'\xa5'*64)
        self.kernel_call('stock_central_init')
        for name, global_addr, end, n, slots, priority, entry in (
                ('central', CENTRAL_GLOBAL, 0x034eb42c, 12, 15, 92, 0x3ba036),
                ('notice', NOTICE_GLOBAL, 0x034ebce0, 20, 30, 93, 0x455c42)):
            tcb = self.word(global_addr)
            require(tcb == (end-108)&~7 and self.byte(tcb+17) == priority and
                    self.byte(tcb+20) == n and self.byte(tcb+19) == slots,
                    'Original central/notifier task fields differ')
            self.aux_tasks[tcb] = {'name': name, 'stack_end': end, 'entry': entry,
                'message_bytes': n, 'slots': slots, 'priority': priority,
                'sends': [], 'receives': [], 'origins': [], 'entries': 0}
        self.central_ready = True
        for tcb in self.aux_tasks:
            self.kernel_call('_post', (tcb, 0x10))
        self.yield_all()
        require(all(t['entries'] == 1 for t in self.aux_tasks.values()),
                'Original central/notifier boot did not enter each task once')
        # Explicit cold synchronization and hardware-ready input; these do
        #not establish real board startup or all global condition policies.
        self.kernel_call('_mutex_init', (self.record+0xc,))
        self.kernel_call('stock_condition_init', (self.record+0x24,))
        self.kernel_call('stock_source_state', (self.channel, 1))
        # Real driver outcome wrappers post to central; neither is the
        #allocation callback which publishes the mixer descriptor/START14.
        for name in ('stock_driver_outcome11', 'stock_driver_outcome12'):
            require(self.kernel_call(name, (self.channel,)) == 0, 'Original outcome wrapper failed')
        self.yield_all()
        central = self.aux_tasks[self.word(CENTRAL_GLOBAL)]
        require([p[0] for p in central['receives']] == [11, 12] and
                not self.mixer_tcb and not self.message_sends and not self.central_start_calls and
                not self.driver_requests and not self.driver_callbacks and
                not self.byte(self.record+2) and self.byte(SOURCE_STATES+self.channel) == 1,
                'Driver outcomes11/12 unexpectedly created/started a source')

    def assert_aux_stack(self, tcb):
        t = self.aux_tasks[tcb]
        require(self.current() == tcb and
                t['stack_end']-960 <= self.uc.reg_read(UC_ARM_REG_SP) <= tcb,
                'Central/notifier work escaped its scheduled task/guarded stack')

    def observe(self, uc, address, size, data):
        if self.central_ready:
            if address == 0x23d6e8:
                raise ValueError('Original diagnostic assertion entered at '+hex(uc.reg_read(UC_ARM_REG_R0)))
            if address in self.hardware_fixtures:
                args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
                if address == DRIVER_REQUEST:
                    self.assert_aux_stack(self.word(CENTRAL_GLOBAL))
                    raw = bytes(uc.mem_read(args[1], 52))
                    require(raw[0] == self.channel, 'Original output wrapper changed the channel')
                    self.driver_requests.append({'opcode': args[0], 'parameters_hex': raw.hex(),
                                                 'current_task': self.current()})
                elif address == 0x4c2800:
                    self.arbitration_requests.append({'args': args, 'current_task': self.current()})
                else:
                    self.power_requests.append({'boundary': self.hardware_fixtures[address],
                                                'args': args, 'current_task': self.current()})
                uc.reg_write(UC_ARM_REG_R0, 0)
                return
            if address == MESSAGE_POST and uc.reg_read(UC_ARM_REG_R0) in self.aux_tasks:
                tcb = uc.reg_read(UC_ARM_REG_R0)
                t = self.aux_tasks[tcb]
                require((self.byte(tcb+21)+1)%t['slots'] != self.byte(tcb+18),
                        'Fixture would overfill original central/notifier FIFO')
                t['sends'].append(bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), t['message_bytes'])))
                t['origins'].append(self.current())
                return
            if address == GET_MESSAGE and self.current() in self.aux_tasks:
                tcb = self.current()
                self.assert_aux_stack(tcb)
                require(tcb not in self.aux_get, 'Nested auxiliary message-get')
                self.aux_get[tcb] = uc.reg_read(UC_ARM_REG_R0)
                return
            if address == MESSAGE_RESULT and self.current() in self.aux_tasks:
                tcb = self.current()
                pointer = self.aux_get.pop(tcb)
                if uc.reg_read(UC_ARM_REG_R0) == 1:
                    t = self.aux_tasks[tcb]
                    t['receives'].append(bytes(uc.mem_read(pointer, t['message_bytes'])))
                return
            for tcb, t in self.aux_tasks.items():
                if address == t['entry']:
                    self.assert_aux_stack(tcb)
                    t['entries'] += 1
            if address == 0x3b9c5e:
                self.assert_aux_stack(self.word(CENTRAL_GLOBAL))
                self.central_start_calls.append({'record': uc.reg_read(UC_ARM_REG_R0),
                                                'arg': uc.reg_read(UC_ARM_REG_R1)})
            if address in (0x30edfe, 0x3ec6a2, 0x3ec498, 0x3b96b8):
                self.sync_events.append({'address': address, 'current_task': self.current(),
                    'r0': uc.reg_read(UC_ARM_REG_R0), 'r1': uc.reg_read(UC_ARM_REG_R1),
                    'r2': uc.reg_read(UC_ARM_REG_R2), 'sp': uc.reg_read(UC_ARM_REG_SP)})
            if address in (0x3009bc, 0x3008cc, 0x300a14, 0x300bb8):
                self.native_sync_visits.add(address)
            if address == DRIVER_CALLBACK:
                require(uc.reg_read(UC_ARM_REG_R0) == MIX_DESCRIPTOR,
                        'Unexpected original driver callback descriptor')
                self.driver_callbacks.append({'current_task': self.current(),
                                             'descriptor': MIX_DESCRIPTOR})
        super().observe(uc, address, size, data)

    def select_native(self, ticket):
        require(self.out('selection_guard', (ticket,)) == 0, 'Original pool admission failed')
        require(self.kernel_call('stock_source_start', (self.channel, 0)) == 0,
                'Public synchronous native source start failed')
        # The acknowledgment can preempt central while its frame is still
        #live. Drain original ready tasks before attaching the test reader.
        self.yield_all()
        require(self.byte(self.record+2) == 1 and self.byte(SOURCE_STATES+self.channel) == 4 and
                self.central_start_calls == [{'record': self.record, 'arg': 0}],
                'Central start did not prepare the original selected source')
        require([p['opcode'] for p in self.driver_requests] == [1, 0, 4],
                'Original central output state/create/start requests differ: '+
                str([p['opcode'] for p in self.driver_requests]))
        require(all(m[0] != 14 for m in self.message_sends),
                'Central selection incorrectly triggered mixer START before driver callback')
        require(self.out('after_selection', (ticket,)) == 0, 'Explicit reader attachment failed')
        self.prepare_virtual_output()
        self.uc.mem_write(MIX_DESCRIPTOR, bytes([self.channel]))
        self.put(self.mixer, 0)  # Require the stock callback itself to publish it.

    def start_native(self):
        before = len(self.native_chunks)
        self.kernel_call('stock_driver_callback', (MIX_DESCRIPTOR,))
        require(self.word(self.mixer) == MIX_DESCRIPTOR and self.message_sends[-1][0] == 14,
                'Original driver callback did not publish descriptor/post START14')
        self.yield_all()
        return b''.join(self.native_chunks[before:])

    def verify_central(self):
        self.verify_timer()
        require({0x30edfe, 0x3ec6a2, 0x3ec498, 0x3b96b8}.issubset(
                e['address'] for e in self.sync_events), 'Native condition request/ack path skipped')
        require({0x3009bc, 0x3008cc, 0x300a14, 0x300bb8}.issubset(self.native_sync_visits),
                'Original mutex bodies/condition blocking skipped after restoring bytes/cache')
        for tcb, t in self.aux_tasks.items():
            require(t['entries'] == 1 and t['sends'] == t['receives'] and
                    self.byte(tcb+22) == 2 and self.word(tcb+4) == 0,
                    'Original central/notifier task/FIFO did not finish blocked')
            require(bytes(self.uc.mem_read(t['stack_end']-1024, 64)) == b'\xa5'*64,
                    'Auxiliary stack crossed test canary')
        require(not self.aux_get and self.word(self.record+0xc+8) == 0 and
                self.word(self.record+0x24+0xc) == 0,
                'Native request left a held mutex or condition waiter')
        for a in (0x36b720, 0x30edfe, 0x3ba036, 0x455c42, 0x3009a0, 0x3008b0,
                  0x3ec6a2, 0x3ec498, DRIVER_CALLBACK, 0x1d9140, 0x1d9160):
            require(bytes(self.uc.mem_read(a, 4)) == self.stock.read(a, 4),
                    'Claimed original central/synchronization entry changed')


def route(stock, companion, output, reference, tables, frequency, mode):
    m = NativeCentral(stock, companion, output)
    frame_count = 15 if frequency == 0 else 2
    frames = reference.encode(dict(frequency=frequency, mode=mode, subbands=1, blocks=3,
                                   allocation=0, bitpool=31 if mode == 0 else 53), frames=frame_count)
    rate = (16000, 32000, 44100, 48000)[frequency]
    channels = 1 if mode == 0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    tts = m.tts_snapshot()
    m.deliver(packet(frames, 0))
    m.yield_all()
    ticket = m.pipe('owned_media_next')
    require(ticket > 0, 'Decoder did not publish its source')
    m.buffer_expected[ticket & 3] = wanted
    m.register_owned(ticket)
    m.select_native(ticket)
    actual = m.start_native()
    require(actual == wanted, 'Original controller/callback route PCM differs')
    if not m.byte(m.mixer+0x7e):
        interval = m.timer_node()['deadline']
        m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))  # Virtual consumer.
        m.tick(interval)
    require(m.byte(m.mixer+0x7e) == 1 and m.tts_snapshot() == tts, 'EOF/TTS isolation differs')
    m.finish_native(ticket)  # Still explicit; no physical drain/end lifecycle claimed.
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_central()
    tasks = {t['name']: {'tcb': hex(tcb), 'priority': t['priority'], 'entries': t['entries'],
             'message_bytes': t['message_bytes'], 'message_slots': t['slots'],
             'messages': [p.hex() for p in t['receives']]} for tcb, t in m.aux_tasks.items()}
    return {'rate': rate, 'channels': channels, 'frames': frame_count, 'pcm_bytes': len(actual),
        'pcm_sha256': sha(actual), 'tasks': tasks, 'driver_requests': m.driver_requests,
        'sync_events': m.sync_events, 'driver_callbacks': m.driver_callbacks,
        'native_mutex_and_condition_body_visits': sorted(hex(p) for p in m.native_sync_visits),
        'power_boundary_fixtures': m.power_requests,
        'public_start_original_queue_selection_and_synchronous_condition_ack': True,
        'actual_driver_outcomes11_and12_consumed_without_source_start': True,
        'original_driver_callback_publishes_descriptor_and_posts_start14': True,
        'controller_explicit_queue_start_mixer_init_select_or_post14': False,
        'all_pcm_upstream_reference_identical': True, 'passed': True}


def main():
    stock, reference = NativeImage(), Reference()
    companion, output = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
                                            ROOT/'staging/native-owned-media/manifest.json'))
    cv = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables = json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes = []
    for frequency, mode in ((0, 0), (2, 3), (3, 2)):
        routes.append(route(stock, companion, output, reference, tables, frequency, mode))
        print(json.dumps({'rate': routes[-1]['rate'], 'passed': True}), flush=True)
    previous = ROOT/'evidence/firmware-analysis/native-mixer-timer-emulation.json'
    prior = json.loads(previous.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_mixer_timer.py', previous))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
        'owned_elf_sha256': output['elf_sha256'], 'routes': routes, 'all_passed': True,
        'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
        'limitations': 'Offline exact stock central/notifier/kernel tasks and public source start with native condition request/wait/ack. After inherited cold initialization, generic kernel mutex lock/unlock bodies are restored and executed; translation caches invalidated, condition blocking/internal drop-owner bodies observed. Native source queue start, mixer init/wake/select/factory/prepare and driver state/create/start wrappers execute; physical output request1D8C60, arbitration4C2800, power query276148 and power3E0088 are explicit fixtures. Driver outcome11/12 wrappers and actual central dispatch execute without starting a source. Driver allocation completion invocation and matching16k output descriptor/ring/consumption are synthetic, though original callback2F998E publishes descriptor and posts START14. Initial source state1 and condition init are explicit cold inputs, stack lower guard is a test boundary not a recovered allocation extent. Mono route has15 frames;44.1/48k stereo controls have2 frames each, not maximum stereo packets or realtime throughput. Heap services, Bluetooth mutex, source priority/hardware hints still controlled. Notifier task boots/waits but receives no notification packets because registered owned sources use NULL metadata; no App listener/main UI proven. Reader attachment, STOP15/CLEANUP19/remove/release remain controller arranged; no actual DAC/resampler/DMA/IRQ/end/drain or automatic next-source lifecycle, cross-channel pool/list reservation/future callback exclusion, accepted module/UI/SEP/phone/speaker/navigation/Google Maps or safe unload. Task/module memory pinned, no device I/O.'}
    p = ROOT/'evidence/firmware-analysis/native-source-controller-emulation.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
