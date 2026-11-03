#!/usr/bin/env python3
"""Original timer task/expiry drives audio capacity response, offline only.

Original timer descriptor initializer, kernel creation, scheduling, tick and
expiry loop execute. Tick arrival and the idle-to-ready dispatcher handoff
are explicit fixtures, not a physical IRQ. Output consumption stays virtual.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_mixer_start import NativeStart
from emulate_native_owned_worker import POST, IDLE_ENTRY
from emulate_native_media_worker import RESTORE
from emulate_native_audio_registration import MIX_DESCRIPTOR, require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

CLOCK = 0x00f09098
TIMERS = 0x00f0909c
TIMER_TASK = 0x00f090a0
TIMER_DESCRIPTOR = 0x02d226e0
TIMER_STACK = 0x02d226f4
TIMER_STACK_END = 0x02d22834
TIMER_ENTRY = 0x353d78
TICK = 0x353ce0
IRQ_SAFE_POST = 0x2fce38


class NativeTimer(NativeStart):
    def __init__(self, stock, companion, output):
        self.timer_ready = False
        self.timer_tcb = 0
        self.timer_wait_loop_visits = 0
        self.timer_initial_dispatches = 0
        self.timer_restore_contexts = []
        self.timer_expiries = []
        self.tick_posts = []
        self.tick_history = []
        self.dispatch_handoffs = 0
        super().__init__(stock, companion, output, ring_bytes=6144)
        self.virtual_handler_stack = 0x09c01000-32
        self.uc.mem_map(0x09c00000, 4096)
        self.uc.mem_write(0x09c00000, b'\xa5'*4096)
        self.native_aliases.update({'stock_timer_descriptor': 0xf6e49,
                                   'stock_timer_init': 0x353d3d,
                                   'stock_timer_tick': TICK,
                                   'stock_timer_dispatch': RESTORE})
        self.uc.mem_write(TIMER_STACK, b'\xa5'*(TIMER_STACK_END-TIMER_STACK))
        self.kernel_call('stock_timer_descriptor')
        require(struct.unpack('<5I', self.uc.mem_read(TIMER_DESCRIPTOR, 20)) ==
                (TIMER_ENTRY | 1, 0, TIMER_STACK_END, 1 << 16, 0),
                'Original timer descriptor differs from its boot initializer')
        self.kernel_call('stock_timer_init')
        self.timer_tcb = self.word(TIMER_TASK)
        require(self.timer_tcb == (TIMER_STACK_END-108)&~7 and self.byte(self.timer_tcb+17) == 1,
                'Original timer kernel task placement/priority differs')
        self.timer_ready = True
        # Boot wake is explicit; the original task enters once and waits.
        self.kernel_call('_post', (self.timer_tcb, 0x10))
        require(self.current() == self.controller and self.timer_initial_dispatches == 1 and
                self.byte(self.timer_tcb+22) == 2,
                f'Original timer boot differs: current={self.current():#x}, controller={self.controller:#x}, '
                f'initial_dispatches={self.timer_initial_dispatches}, state={self.byte(self.timer_tcb+22):#x}, '
                f'mailbox={self.word(self.timer_tcb+4):#x}')

    def observe(self, uc, address, size, data):
        if self.timer_ready:
            if address == TIMER_ENTRY:
                # Entry is also the original wait-loop head; repeated visits
                #do not establish that the task was restarted.
                self.timer_wait_loop_visits += 1
            if address == RESTORE and self.current() == self.timer_tcb:
                frame = self.word(self.timer_tcb+12)
                pc = self.word(frame+4)
                self.timer_restore_contexts.append({'saved_pc': pc, 'clock': self.word(CLOCK),
                                                   'context_format': self.byte(self.timer_tcb+23)})
                # Flag0 is also a compact suspended wait context. Count
                #only an original initial entry PC as a fresh dispatch.
                if pc == TIMER_ENTRY | 1:
                    self.timer_initial_dispatches += 1
            if address in (TIMER_ENTRY, 0x353d8c, 0x353dc6):
                require(self.current() == self.timer_tcb and
                        TIMER_STACK <= uc.reg_read(UC_ARM_REG_SP) <= self.timer_tcb,
                        'Timer expiry did not run on the original kernel task/stack')
            if address == 0x353dc6:
                # The one-shot entry has been removed from the linked list,
                #but its target is not cleared until the next instruction.
                node = self.word(TIMERS)
                self.timer_expiries.append({'current_task': self.current(),
                    'clock': self.word(CLOCK), 'remaining_head': node})
            if address == IRQ_SAFE_POST:
                self.tick_posts.append({'current_before': self.current(),
                    'target': uc.reg_read(UC_ARM_REG_R0), 'events': uc.reg_read(UC_ARM_REG_R1),
                    'clock': self.word(CLOCK)})
        super().observe(uc, address, size, data)

    def timer_node(self):
        p = self.mixer+0x88
        words = struct.unpack('<5I', self.uc.mem_read(p, 20))
        return {'pointer': p, 'next': words[0], 'target': words[1], 'deadline': words[2],
                'kind': words[3] & 255, 'event': words[4]}

    def tick(self, advance):
        require(0 < advance < 600000 and self.current() == self.controller,
                'Virtual tick must begin on the controller within observed timer horizon')
        before = self.word(CLOCK)
        expires = len(self.timer_expiries)
        events = len(self.tick_posts)
        # Preserve the controller through original wait. Idle is a synthetic
        #sentinel with an original initial context and no live continuation.
        self.park_controller()
        # Use a separate virtual handler stack. READY may change before the
        #IRQ-safe post returns; using that newly ready task's stack would
        #overwrite its suspended context before original restore reads it.
        self.kernel_call('stock_timer_tick', (advance,), stack=self.virtual_handler_stack)
        require(self.word(CLOCK) == (before+advance)&0xffffffff, 'Original tick counter differs')
        if self.current() != self.idle:
            require(self.current() == self.timer_tcb, 'Virtual tick readied an unexpected task')
            # This explicit dispatch from the idle sentinel is not original
            #IRQ entry/exit or a Python CPU-context restore. All task work
            #from here uses original kernel contexts/post/wait/restore.
            self.dispatch_handoffs += 1
            self.kernel_call('stock_timer_dispatch', stack=self.virtual_handler_stack)
        require(self.current() == self.idle, 'Timer/audio work did not return to idle')
        require(self.uc.reg_read(UC_ARM_REG_SP) in (self.idle, self.virtual_handler_stack),
                'Virtual tick/dispatch lost the original idle or handler stack')
        self.activate_controller()
        self.tick_history.append({'advance': advance, 'clock_before': before,
                                  'clock_after': self.word(CLOCK),
                                  'timer_expiries': len(self.timer_expiries)-expires,
                                  'irq_safe_tick_posts': len(self.tick_posts)-events})

    def verify_timer(self):
        self.verify_start()
        require(self.timer_initial_dispatches == 1 and self.byte(self.timer_tcb+22) == 2 and
                self.word(self.timer_tcb+4) == 0,
                f'Timer dispatch/state/mailbox differs: {self.timer_initial_dispatches}, '
                f'{self.byte(self.timer_tcb+22):#x}, {self.word(self.timer_tcb+4):#x}')
        require(bytes(self.uc.mem_read(TIMER_STACK, 24)) == b'\xa5'*24,
                'Original timer stack crossed leading canary')
        require(bytes(self.uc.mem_read(0x09c00000, 64)) == b'\xa5'*64,
                'Virtual tick/dispatch stack crossed leading canary')
        for a in (TIMER_ENTRY, TICK, IRQ_SAFE_POST, 0x353bd4):
            require(bytes(self.uc.mem_read(a, 4)) == self.stock.read(a, 4), 'Original timer entry changed')


def route(stock, companion, output, reference, tables, initial_clock=0):
    m = NativeTimer(stock, companion, output)
    if initial_clock:
        # Epoch is a virtual input for the rollover control; subsequent
        #changes execute original tick arithmetic, not direct clock writes.
        m.put(CLOCK, initial_clock)
    frames = reference.encode(dict(frequency=0, mode=0, subbands=1, blocks=3,
                                   allocation=0, bitpool=31), frames=15)
    wanted, _ = reference_pcm(reference, frames, 16000, 1, tables)
    tts = m.tts_snapshot()
    m.deliver(packet(frames, 0))
    m.yield_all()
    ticket = m.pipe('owned_media_next')
    require(ticket > 0, 'Maximum packet did not publish owned PCM')
    m.buffer_expected[ticket & 3] = wanted
    m.register_owned(ticket)
    m.select_native(ticket)
    actual = m.start_native()
    node = m.timer_node()
    interval = (node['deadline']-initial_clock)&0xffffffff
    require(actual == wanted and len(actual) == 3840 and not m.byte(m.mixer+0x7e) and
            node['target'] == m.mixer_tcb and node['kind'] == 1 and node['event'] == 0x200 and
            m.word(TIMERS) == node['pointer'],
            'Original source capacity stall did not schedule its own one-shot timer')
    require(interval == 34, 'Original controlled-format timing arithmetic differs')
    reads, sends = len(m.native_chunks), len(m.message_sends)
    m.tick(interval-1)
    require(not m.timer_expiries and not m.tick_posts and len(m.native_chunks) == reads and
            len(m.message_sends) == sends and m.timer_node() == node,
            'Timer fired before its original deadline')
    m.tick(1)
    delayed = m.timer_node()
    require(len(m.timer_expiries) == 1 and not m.byte(m.mixer+0x7e) and
            len(m.native_chunks) == reads and len(m.message_sends) == sends and
            delayed['target'] == m.mixer_tcb and delayed['deadline'] == (initial_clock+2*interval)&0xffffffff,
            'Insufficient-capacity expiry did not reschedule without reading')
    require(m.pipe('owned_media_release', (ticket,)) == -25, 'Waiting timer permitted early PCM release')

    m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))  # Explicit virtual output consumption.
    m.tick(interval)
    require(len(m.timer_expiries) == 2 and m.byte(m.mixer+0x7e) == 1 and
            m.native_chunks[reads:] == [b''] and m.word(TIMERS) == 0 and
            m.timer_node()['target'] == 0, 'Native expiry/rearm did not complete its EOF probe')
    require(m.message_sends[-1][0] == 18 and
            m.message_origins[-1] == {'current': m.mixer_tcb, 'kind': 18} and
            all(e['target'] == m.timer_tcb and e['events'] == 1 for e in m.tick_posts),
            'Controller directly posted audio capacity/read instead of original timer worker')
    capacity_posts = [e for e in m.kernel_events if e['current'] == m.timer_tcb and
                      e['target'] == m.mixer_tcb and e['events'] == 0x204]
    require(len(capacity_posts) == 2, 'Original one-shot timer did not post event0x200|4 twice')
    m.finish_native(ticket)
    require(m.tts_snapshot() == tts, 'Timer route changed navigation TTS context/ring')
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_timer()
    return {'case': 'original_timer_capacity_expiry_with_virtual_epoch_rollover' if initial_clock else
                    'original_timer_capacity_expiry_at_exact_deadline',
            'frames': 15, 'pcm_bytes': len(actual), 'pcm_sha256': sha(actual),
            'initial_virtual_clock': initial_clock, 'original_interval_ticks': interval,
            'original_timer_initial_dispatches': m.timer_initial_dispatches,
            'original_timer_wait_loop_visits': m.timer_wait_loop_visits,
            'original_timer_restore_contexts': m.timer_restore_contexts,
            'original_timer_priority': m.byte(m.timer_tcb+17),
            'original_timer_stack_end': TIMER_STACK_END, 'original_timer_tcb': m.timer_tcb,
            'original_descriptor_initializer_and_kernel_builder_executed': True,
            'ticks': m.tick_history, 'one_shot_expiries': len(m.timer_expiries),
            'original_timer_to_audio_capacity_posts': len(capacity_posts),
            'controller_audio_capacity_or_read18_posts': 0,
            'early_tick_keeps_timer_pending': True, 'no_space_expiry_reschedules_without_read': True,
            'space_available_expiry_actor_self_posts_read18_and_probes_eof': True,
            'epoch_wraparound_exercised': bool(initial_clock),
            'explicit_idle_dispatch_handoffs': m.dispatch_handoffs,
            'original_timer_stack_leading24_byte_canary_and_audio_decoder_guards_intact': True,
            'virtual_tick_arrival_and_output_consumption_remain_fixtures': True,
            'physical_irq_entry_exit_clock_dma_driver_drain_or_auto_source_transition_verified': False,
            'tts_context_full_ring_unchanged': True, 'passed': True}


def main():
    stock, reference = NativeImage(), Reference()
    companion, output = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
                                            ROOT/'staging/native-owned-media/manifest.json'))
    cv = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables = json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes = []
    for epoch in (0, 0xffffffe0):
        routes.append(route(stock, companion, output, reference, tables, epoch))
        print(json.dumps({'epoch': epoch, 'passed': True}), flush=True)
    prior_path = ROOT/'evidence/firmware-analysis/native-mixer-capacity-emulation.json'
    prior = json.loads(prior_path.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_mixer_capacity.py', prior_path))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
              'owned_elf_sha256': output['elf_sha256'], 'routes': routes, 'all_passed': True,
              'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
              'original_timer_descriptor_task_schedule_tick_expiry_and_audio_capacity_response_executed': True,
              'physical_irq_or_clock_output_drain_or_complete_automatic_playback_verified': False,
              'limitations': 'Offline original timer descriptor initializer0xF6E48 and creator0x353D3C build priority1 task at original static stack ending0x02D22834. Original schedule0x353BD4/insert0x353E48, ARM tick0x353CE0 with IRQ-safe post0x2FCE38 and timer loop0x353D78/one-shot expiry run. Virtual ticks arrive while controller is parked and idle sentinel has no live continuation; an explicit original-context-restore handoff dispatches newly ready task, not actual IRQ entry/exit or Python CPU context restoration. Original timer posts0x204 to audio actor; controller sends neither audio0x200 nor read18. Before-deadline, no-space reschedule, available-space EOF and32bit virtual epoch rollover controls pass. Tick arrival and physical output consumption remain fixtures; no physical IRQ/clock/DMA/driver allocation/start/format/resampler/drain. Output ring/descriptor, heap/locks/generic mutex/priority/hardware hints and explicit source attach/stop/cleanup/remove/release remain inherited fixtures. Original static timer task remains blocked/pinned, audio allocations and decoder TCB/stack/module retained. No cross-channel pool/list ownership, future callback exclusion, native App/UI/SEP/phone/speaker/navigation coexistence/accepted package/safe unload or Google Maps. No device I/O.'}
    p = ROOT/'evidence/firmware-analysis/native-mixer-timer-emulation.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__':
    main()
