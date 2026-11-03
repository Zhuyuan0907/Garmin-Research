#!/usr/bin/env python3
"""Original event/context switching drives compiled media work, offline only.

Only kernel construction bookkeeping and prior Bluetooth mutex/audio policy
hooks are controlled. Event posting/waiting, priority insertion, context
save/restore, registration and kernel exit execute original instructions.
Initial controller/idle ready membership is synthetic; there is no IRQ clock.
"""
from datetime import datetime, timezone
import ctypes
import json
from pathlib import Path
import struct

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_sbc import Reference, INPUT_PAGE, PAGE_BYTES, STACK, RETURN
from emulate_native_sbc_pcm import CONTEXT, HOST_OUTPUT, RING_BYTES
from emulate_native_voice_convert import reference_pcm, drain
from emulate_native_voice_media import packet, counters
from emulate_native_media_queue import QueueSession, sha, require, VOICES
from emulate_avdtp_media import HANDLER

BUILD = ROOT/'staging/native-media-worker'
ALL_TASKS = 0xf0908c
READY_TASKS = 0xf09090
CODE = 0x09400000
IDLE_ENTRY = CODE
DESCRIPTORS = CODE+0x800
CONTROLLER_STACK = 0x09500000
IDLE_STACK = 0x09505000
EXIT_LIST = 0x2d226b4
POST = 0x2fcf44
WAIT = 0x2fd035
RESTORE = 0x358ec4


class WorkerSession(QueueSession):
    def __init__(self, stock, voice, worker, priority=36):
        self.kernel_events = []
        self.switch_visits = set()
        self.worker_output_calls = []
        self.controller = self.idle = self.worker_tcb = 0
        self.worker_stack_start = worker['symbols']['__worker_stack_start']['address']
        self.worker_stack_end = worker['symbols']['__worker_stack_end']['address']
        super().__init__(stock, voice, worker)
        for page in (0x358000, 0x300000, 0x2fb000, 0x2fc000, 0x2fd000,
                     0x20b000, 0x20e000, 0xf5000, 0x23d000, 0x1c0000, 0x3cc000):
            if not any(begin <= page and page+4095 <= end for begin, end, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                self.uc.mem_write(page, stock.read(page, 4096))
        self.uc.mem_map(self.worker_stack_start, worker['preallocated_stack_bytes'])
        self.uc.mem_write(self.worker_stack_start, b'\xa5'*worker['preallocated_stack_bytes'])
        for address, size in ((CODE, 4096), (CONTROLLER_STACK, 16384),
                              (IDLE_STACK, 16384), (0x14b3000, 4096), (EXIT_LIST & ~4095, 4096)):
            self.uc.mem_map(address, size)
        self.uc.mem_write(CODE, struct.pack('<I', 0xeafffffe))  # Synthetic idle sentinel.
        self.uc.mem_write(0xf5030, b'\x70\x47')  # Only construction bookkeeping is hooked.
        self.put(ALL_TASKS, 0)
        self.put(READY_TASKS, 0)
        self.put(0xf09094, 0)  # Normal context, not the alternate IRQ post path.
        self.put(0xf0909c, 0)
        self.uc.mem_write(0xf071cc, b'\x01'+bytes(7))
        self.invoke('_mutex_init', (EXIT_LIST+4,))
        self.idle = self.build_raw(DESCRIPTORS, IDLE_ENTRY, IDLE_STACK+16384, 240)
        self.controller = self.build_raw(DESCRIPTORS+32, CODE+4, CONTROLLER_STACK+16384, 16)
        self.put(READY_TASKS, self.controller)
        self.put(self.controller, self.idle)
        self.put(self.idle, 0)
        self.uc.mem_write(self.controller+22, b'\x01')
        self.uc.mem_write(self.idle+22, b'\x01')
        self.dispatch.callback = self.address('media_worker_callback')
        self.fresh()
        require(self.invoke('media_worker_init') == 0, 'Worker initialization failed')
        self.worker_tcb = self.invoke('media_worker_boot', (priority,))
        require(self.worker_tcb == (self.worker_stack_end-108) & ~7,
                'Original kernel builder chose unexpected worker TCB placement')
        require(self.state()[0] == self.worker_tcb, 'Worker lost its TCB handle')
        require(self.word(0xf071d0) == 1, 'Original descriptor registration did not execute')
        require(self.word(self.worker_tcb+8) == 0, 'Worker descriptor acknowledgement field is not zero')
        # Lower priority first runs after controller waits; higher priority
        # already ran and blocked during the original boot post's preemption.
        self.park_controller()
        require(self.current() == self.idle and self.byte(self.worker_tcb+22) == 2,
                'Empty worker did not block and restore the idle task')
        self.activate_controller()

    def put(self, address, value): self.uc.mem_write(address, struct.pack('<I', value))
    def word(self, address): return struct.unpack('<I', self.uc.mem_read(address, 4))[0]
    def byte(self, address): return bytes(self.uc.mem_read(address, 1))[0]
    def current(self): return self.word(READY_TASKS)
    def state(self): return struct.unpack('<7Ii', self.uc.mem_read(self.address('media_worker_state'), 32))

    def build_raw(self, address, entry, stack_end, priority):
        self.uc.mem_write(address, struct.pack('<5I', entry, 0, stack_end, priority << 16, 0))
        return self.invoke('_kernel_create', (address,))

    def observe(self, uc, address, size, data):
        super().observe(uc, address, size, data)
        if address == 0xf5030:
            self.kernel_events.append({'hook': 'construction_bookkeeping',
                                       'descriptor': hex(uc.reg_read(UC_ARM_REG_R0))})
            uc.reg_write(UC_ARM_REG_R0, 0)
        if address in (POST, WAIT & ~1, 0x2fcfb0, 0x2fcfec, 0x2fd06c,
                       0x2fd0a8, RESTORE, 0x358f08, 0x358fa4, 0x1c06a4, 0x2fbbbe):
            self.switch_visits.add(address)
        if address in (POST, WAIT & ~1):
            self.kernel_events.append({'entry': hex(address), 'current': hex(self.current()),
                                       'r0': hex(uc.reg_read(UC_ARM_REG_R0)),
                                       'r1': hex(uc.reg_read(UC_ARM_REG_R1))})
        if address == self.address('media_queue_step'):
            require(self.worker_stack_start <= uc.reg_read(UC_ARM_REG_SP) < self.worker_stack_end,
                    'Queue work was explicitly called on a non-worker stack')
            require(self.current() == self.state()[0], 'Queue work did not run as its kernel task')
        if address == HOST_OUTPUT:
            require(self.current() == self.state()[0] and
                    self.worker_stack_start <= uc.reg_read(UC_ARM_REG_SP) < self.worker_stack_end,
                    'PCM output did not execute on the worker task/stack')
            self.worker_output_calls.append({'tcb': hex(self.current()),
                                             'sp': hex(uc.reg_read(UC_ARM_REG_SP))})
        if address == IDLE_ENTRY:
            uc.emu_stop()

    def invoke(self, name, args=(), fifth=None, stack=None):
        stock_calls = {'_kernel_create': 0x358bf9, '_mutex_init': 0x3008a1,
                       '_post': POST, '_wait': WAIT}
        address = HANDLER | 1 if name == 'stock_handler' else stock_calls.get(name)
        if address is None: address = self.address(name)
        if stack is None:
            stack = self.current() if getattr(self, 'controller', 0) else STACK
        self.uc.reg_write(UC_ARM_REG_SP, stack)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        if fifth is not None: self.uc.mem_write(stack, struct.pack('<I', fifth))
        self.uc.emu_start(address, RETURN, timeout=10000000, count=6000000)
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        require(pc in (RETURN, IDLE_ENTRY), 'Worker call exceeded execution endpoint bounds: '+hex(pc))
        return ctypes.c_uint32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def deliver(self, data, stack=None):
        require(self.current() == self.controller, 'Media must arrive on synthetic controller task')
        require(0 < len(data) <= PAGE_BYTES, 'Synthetic packet exceeds guarded page')
        source = INPUT_PAGE+PAGE_BYTES-len(data)
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(source, data)
        result = self.invoke('stock_handler', (0x1234, source, len(data)), stack=stack)
        require(not self.dispatch.mutex_held, 'Stock media dispatch left its mutex held')
        require(bytes(self.uc.mem_read(source, len(data))) == data, 'Worker modified input source')
        self.machine.verify_ring_guards()
        return result

    def activate_controller(self):
        if self.current() == self.controller: return
        require(self.current() == self.idle, 'Unexpected task at controller activation')
        require(self.invoke('_post', (self.controller, 1)) == 1,
                'Restored controller wait did not return its posted event')
        require(self.current() == self.controller, 'Original post did not preempt idle for controller')

    def park_controller(self):
        require(self.current() == self.controller, 'Cannot park a non-controller task')
        self.invoke('_wait')
        require(self.current() == self.idle, 'Blocked controller did not yield to worker/idle')

    def fresh(self):
        if self.controller: self.activate_controller()
        super().fresh()

    def verify_worker(self):
        self.activate_controller()
        self.verify_preserved()
        require(bytes(self.uc.mem_read(self.worker_stack_start, 64)) == b'\xa5'*64,
                'Worker stack leading canary changed')
        require({POST, WAIT & ~1, 0x2fcfb0, 0x2fd06c, RESTORE, 0x358f08, 0x2fbbbe}
                .issubset(self.switch_visits), 'Original task/event/context paths were skipped')
        require(self.state()[1] == 1, 'Worker entry was restarted rather than resumed')


def stream(session, reference, tables, frequency, mode):
    session.fresh()
    config = dict(frequency=frequency, mode=mode, subbands=1, blocks=3, allocation=0,
                  bitpool=31 if mode == 0 else 53)
    frames = reference.encode(config, frames=28)
    rate, channels = (16000, 32000, 44100, 48000)[frequency], 1 if mode == 0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    output, cursor = [], 0
    for index, count in enumerate((1, 4, 8, 15)):
        before = counters(session.machine, session.voice)
        require(session.deliver(packet(frames[cursor:cursor+count], index)) == 0, 'Stock delivery failed')
        require(counters(session.machine, session.voice) == before,
                'Lower-priority worker decoded before controller yielded')
        session.uc.mem_write(INPUT_PAGE, b'\xcc'*PAGE_BYTES)
        session.park_controller()
        require(session.control()[2] == 0 and session.byte(session.worker_tcb+22) == 2,
                'Event worker did not consume packet then block')
        session.activate_controller()
        while session.machine.queued() >= 4096: output.append(session.machine.read(3840))
        cursor += count
    output.append(drain(session.machine))
    actual = b''.join(output)
    require(actual == wanted, 'OS-driven queue/converter/original PCM differs from reference')
    return {'rate': rate, 'channels': channels, 'frames': len(frames), 'packets': 4,
            'packet_group_sizes': [1, 4, 8, 15], 'pcm_sha256': sha(actual),
            'original_event_and_context_switch_drives_work': True,
            'source_destroyed_before_worker_runs': True, 'reference_byte_identical': True,
            'worker_entry_runs_once_then_resumes': True, 'passed': True}


def controls(session, reference, tables):
    config = dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53)
    frames = reference.encode(config, frames=4)
    first, _ = reference_pcm(reference, frames[:1], 44100, 2, tables)
    whole, _ = reference_pcm(reference, frames, 44100, 2, tables)
    cases = []
    session.fresh()
    before = session.stats()
    for index, frame in enumerate(frames): session.deliver(packet([frame], index))
    require(session.word(session.worker_tcb+4) == 1 and session.control()[2] == 4,
            'Original event posting failed to coalesce while queue retained packets')
    session.deliver(packet(frames[:1], 5))
    require(session.stats()[2] == before[2]+1 and session.control()[2] == 4,
            'Full queue did not reject extra packet')
    session.park_controller(); session.activate_controller()
    require(drain(session.machine) == whole and session.control()[2] == 0,
            'Coalesced event failed to consume all copied packets in FIFO order')
    cases.append({'case': 'coalesced_events_four_packets_and_full_rejection', 'passed': True})

    session.fresh(); session.deliver(packet(frames[:1]))
    write, _ = session.machine.offsets()
    session.put(CONTEXT+16, (write+8960)%RING_BYTES)
    prior = session.state()[4]
    session.park_controller()
    require(session.control()[2] == 1 and session.state()[4] == prior+1 and
            session.byte(session.worker_tcb+22) == 2, 'Capacity deferral did not block the worker')
    # Explicitly controlled capacity release, not a real audio-consumer event.
    session.put(CONTEXT+16, write)
    session.activate_controller()
    require(session.invoke('media_worker_notify_capacity') == 0, 'Capacity notification failed')
    session.park_controller(); session.activate_controller()
    require(session.control()[2] == 0 and drain(session.machine) == first,
            'Original capacity-event wake did not retry pending packet')
    cases.append({'case': 'capacity_deferral_blocks_then_explicit_capacity_event_retries',
                  'consumer_capacity_release_synthetic': True, 'automatic_consumer_notification_wired': False,
                  'passed': True})

    session.fresh()
    corrupt = frames[0][:3]+bytes([frames[0][3]^1])+frames[0][4:]
    failed = session.stats()[5]
    session.deliver(packet([corrupt])); session.deliver(packet(frames[:1]))
    session.park_controller(); session.activate_controller()
    require(session.stats()[5] == failed+1 and drain(session.machine) == first,
            'Worker failed to continue after CRC rejection/reset')
    cases.append({'case': 'worker_continues_after_bad_crc_and_reset', 'passed': True})

    session.fresh(); session.deliver(packet(frames[:1])); session.deliver(packet(frames[1:2]))
    handled = session.state()[3]
    require(session.invoke('media_worker_shutdown') == 0, 'Worker shutdown request failed')
    session.park_controller(); session.activate_controller()
    require(session.control()[2] == 0 and session.machine.queued() == 0 and session.state()[3] == handled,
            'Shutdown processed discarded pending data')
    require(session.byte(session.worker_tcb+22) == 0x80 and session.state()[6] == 1,
            'Worker did not return through original kernel self-exit')
    node, seen = session.word(ALL_TASKS), set()
    while node:
        require(node not in seen, 'Cycle in original all-task list')
        seen.add(node); node = session.word(node+40)
    require(session.worker_tcb not in seen and session.current() != session.worker_tcb,
            'Kernel exit retained worker in a task list')
    require(session.invoke('media_worker_boot', (36,)) == 0,
            'Worker allowed unchecked stack/descriptor reuse after shutdown')
    require(session.deliver(packet(frames[:1])) == 0 and session.control()[2] == 0,
            'Post-shutdown callback enqueued or woke dead worker')
    cases.append({'case': 'shutdown_discards_pending_and_original_kernel_unlinks_worker',
                  'stack_and_module_retained': True, 'unchecked_reboot_rejected': True,
                  'passed': True})
    return cases


def priority_preemption(stock, voice, worker, reference, tables):
    session = WorkerSession(stock, voice, worker, priority=3)
    config = dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53)
    frames = reference.encode(config, frames=2)
    wanted, _ = reference_pcm(reference, frames, 44100, 2, tables)
    for index, frame in enumerate(frames):
        handled = session.state()[3]
        require(session.deliver(packet([frame], index)) == 0 and
                session.state()[3] == handled+1 and session.current() == session.controller,
                'Higher-priority worker did not preempt and restore original callback caller')
    require(drain(session.machine) == wanted, 'Preempted worker output differs')
    session.invoke('media_worker_shutdown')
    require(session.byte(session.worker_tcb+22) == 0x80, 'Higher-priority shutdown failed')
    session.verify_worker()
    return {'case': 'higher_priority_worker_preempts_event_post_then_restores_callback',
            'kernel_priority': 3, 'controller_priority': 16, 'frames': 2,
            'reference_byte_identical': True, 'pcm_runs_on_worker_stack': True,
            'shutdown_self_exit_verified': True, 'passed': True}


def main():
    worker = json.loads((BUILD/'manifest.json').read_text())
    for path, digest in worker['source_sha256'].items():
        require(sha((ROOT/path).read_bytes()) == digest, 'Worker source changed: '+path)
    require(sha((ROOT/worker['elf']).read_bytes()) == worker['elf_sha256'], 'Worker ELF changed')
    require(sha((ROOT/worker['flat_binary']).read_bytes()) == worker['flat_binary_sha256'], 'Worker binary changed')
    stock, reference = NativeImage(), Reference()
    tables = json.loads((ROOT/'staging/native-pcm-converter/coefficients.json').read_text())['tables']
    paths = sorted(VOICES.glob('*/manifest.json'))
    require(len(paths) == 3, 'Three preserving voices required')
    cases, preemption = [], None
    for index, path in enumerate(paths):
        voice = json.loads(path.read_text())
        for source, digest in voice['source_sha256'].items():
            require(sha((ROOT/source).read_bytes()) == digest, 'Voice source changed: '+source)
        session = WorkerSession(stock, voice, worker)
        streams = [stream(session, reference, tables, 2, 3),
                   stream(session, reference, tables, 3, 2),
                   stream(session, reference, tables, 0, 0)]
        guards = controls(session, reference, tables) if index == 0 else []
        session.verify_worker()
        if index == 0: preemption = priority_preemption(stock, voice, worker, reference, tables)
        row = {'voice': voice['voice_package'], 'combined_sha256': voice['combined_sha256'],
               'streams': streams, 'controls': guards, 'worker_state': list(session.state()),
               'stock_context_paths_visited': [hex(a) for a in sorted(session.switch_visits)],
               'kernel_events': session.kernel_events, 'worker_pcm_calls': session.worker_output_calls,
               'original40_exports_imports_trampolines_and_ram_preserved': True,
               'stock_event_wait_post_save_restore_executed': True,
               'queue_step_not_explicitly_invoked_by_test': True, 'all_passed': True}
        cases.append(row)
        print(json.dumps({'voice_finished': voice['voice_package'], 'stream_frames': 84,
                          'controls': len(guards), 'all_passed': True}), flush=True)
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()), 'worker_elf_sha256': worker['elf_sha256'],
              'worker_manifest': str((BUILD/'manifest.json').relative_to(ROOT)),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                   (ROOT/'scripts/emulate_native_media_queue.py',
                                    ROOT/'scripts/emulate_native_voice_convert.py',
                                    ROOT/'staging/native-pcm-converter/coefficients.json')},
              'cases': cases, 'voices': len(cases), 'priority_preemption_control': preemption,
              'decoded_converted_and_routed_stream_frames': sum(s['frames'] for c in cases for s in c['streams']),
              'accepted_stream_packets': sum(s['packets'] for c in cases for s in c['streams']),
              'additional_control_cases': sum(len(c['controls']) for c in cases)+1,
              'all_passed': True, 'compiled_worker_event_loop_implemented': True,
              'original_event_operations_and_context_switching_executed': True,
              'original_task_builder_and_descriptor_registry_executed': True,
              'worker_stack_bytes': 16384, 'kernel_construction_bookkeeping_hooked': True,
              'initial_controller_and_idle_ready_membership_synthetic': True,
              'live_irq_clock_or_physical_scheduling_verified': False,
              'interrupt_context_post_path_tested': False,
              'automatic_consumer_capacity_notification_wired': False,
              'cold_pcm_init_and_navigation_output_ownership_verified': False,
              'stack_and_module_reclamation_implemented': False,
              'native_on_device_verified': False, 'device_io': False, 'device_install_candidate': False,
              'limitations': 'Offline standalone companion ELF with exact stock normal-context event post/wait, priority insertion, kernel context save/restore and self-exit. Original kernel builder constructs idle/controller/worker TCBs, with construction bookkeeping hooked and initial idle/controller ready membership supplied. Compiled callbacks post events; stock code switches to the persistent worker, which drains the queue and blocks. No explicit test call to work step, Python CPU context restore or synthetic event-return hook drives work. Bluetooth endpoint/ring state and prior mutex/audio policy hooks remain synthetic. Capacity release/notification is explicitly supplied by the test and is not wired to an actual consumer. No IRQ clock/interrupt-context post, real navigation workload, hardware performance, SEP/UI, VPM acceptance, physical worker or speaker is verified. Stack/module remain allocated after shutdown; reboot is rejected. Queue stop is not immediate PCM mute/flush. Experimental code is not merged into a voice package or installed.'}
    path = ROOT/'evidence/firmware-analysis/native-media-worker-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'voices': report['voices'],
                      'stream_frames': report['decoded_converted_and_routed_stream_frames'],
                      'packets': report['accepted_stream_packets'], 'controls': report['additional_control_cases'],
                      'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
