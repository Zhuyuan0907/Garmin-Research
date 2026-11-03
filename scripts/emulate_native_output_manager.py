#!/usr/bin/env python3
"""Stock output task/allocation/end retirement, with a virtual peripheral.

Original 56-byte transport, format policy, ring allocation caller, START14,
source-frame consumption and central completion execute. Peripheral startup,
frame arrival and physical-channel inventory are fixtures, not a live DAC.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import UcError
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_PC, UC_ARM_REG_SP)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_source_controller import (NativeCentral, CENTRAL_GLOBAL, SOURCE_STATES,
                                              DRIVER_REQUEST, DRIVER_CALLBACK)
from emulate_native_mixer_timer import NativeTimer
from emulate_native_mixer_start import VIRTUAL_RING, PULL, PULL_RETURNS
from emulate_native_audio_registration import MIX_DESCRIPTOR, require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

OUTPUT_GLOBAL = 0x00f29320
OUTPUT_STACK_END = 0x034e2e38
DRIVERS = 0x034e32bc
PHYSICAL_CHANNELS = 0x034e38f8
BRIDGE = 0x09d00000
BRIDGE_ENABLE = 0x09d01020
FRAME_BUFFER = 0x09d02020
FRAME_BYTES = 4480  # Physical-channel byte length; native helper writes 16-bit samples.
SOURCE_FRAME = 0x436e5e


def frame_contract(stock):
    """Derive the virtual source-frame ABI from the stock physical caller."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    expected = ((0x4376c8, 2, 'ldr', 'r1, [r5, #4]'),
        (0x4376d0, 2, 'movs', 'r0, #1'), (0x4376d4, 2, 'str', 'r0, [sp]'),
        (0x43770e, 2, 'ldr', 'r2, [sp]'), (0x437714, 4, 'bl', '#0x436e5e'),
        (0x437718, 2, 'movs', 'r1, #0'), (0x43771a, 2, 'lsls', 'r0, r0, #1'),
        (0x43771e, 2, 'str', 'r1, [sp]'), (0x43766e, 2, 'ldr', 'r0, [r1, #4]'),
        (0x437670, 2, 'lsrs', 'r2, r0, #1'))
    trace = []
    for address, n, mnemonic, operands in expected:
        code = list(md.disasm(stock.read(address, n), address))
        require(len(code) == 1 and code[0].mnemonic == mnemonic and code[0].op_str == operands,
                'Stock peripheral source-frame ABI evidence differs')
        trace.append({'address': hex(address), 'bytes': stock.read(address, n).hex(),
                      'mnemonic': mnemonic, 'operands': operands})
    return {'original_physical_frame_dispatcher': '0x437688', 'source_helper': hex(SOURCE_FRAME),
        'third_argument_first_source_flag_not_sample_count': True,
        'physical_channel_offset4_frame_byte_length': FRAME_BYTES,
        'source_helper_return_16bit_samples': True,
        'virtual_bridge_bypasses_original_multisource_dispatch_loop': True, 'trace': trace}


class NativeDriver(NativeCentral):
    def __init__(self, stock, companion, output):
        self.driver_ready = False
        self.output_tcb = 0
        self.output_handles = {}
        self.output_events = []
        self.frame_calls = []
        self.peripheral_chunks = []
        self.native_driver_visits = set()
        self.driver_allocation_calls = []
        self.original_node_removals = []
        super().__init__(stock, companion, output)
        for p in (0x034e2000,):
            require(any(r['runtime_start'] <= p and p+4096 <= r['runtime_end']
                        for r in stock.zeros if not r['conditional']), 'Output stack not normal BSS')
            if not any(lo <= p and p+4095 <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(p, 4096)
        self.uc.mem_map(BRIDGE, 0x5000)
        self.uc.mem_write(BRIDGE, b'\xa5'*0x5000)
        self.put(BRIDGE_ENABLE, 0)
        # ARM fixture called by original peripheral-dispatch helpers. It
        #executes the real source-frame helper on the output task's stack.
        #No Python register/context restoration or nested emulation is used.
        words = (0xe92d4010, 0xe59f3024, 0xe5933000, 0xe3530000,
                 0x0a000004, 0xe3a00000 | self.channel, 0xe59f1014, 0xe3a02001,
                 0xe59f3010, 0xe12fff33, 0xe3a00000, 0xe8bd8010,
                 BRIDGE_ENABLE, FRAME_BUFFER, SOURCE_FRAME | 1)
        self.uc.mem_write(BRIDGE, struct.pack('<15I', *words))
        for a in (0x2d992e, 0x2d9792):
            page = a & ~4095
            if not any(lo <= page and page+4095 <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                self.uc.mem_write(page, stock.read(page, 4096))
            require(a % 4 == 2, 'Virtual Thumb-to-ARM fixture alignment differs')
            self.uc.mem_write(a, bytes.fromhex('014b1847c046')+struct.pack('<I', BRIDGE))
            self.uc.ctl_remove_cache(a, a+10)
        self.hardware_fixtures.update({0x1fbab6: 'board_mode_input',
            0x277054: 'codec_boot_registration', 0x33fa3c: 'audio_boot_registration',
            0x2d971c: 'physical_channel_init', 0x325e1c: 'peripheral_switch',
            0x3275b0: 'global_audio_power', 0x4c2898: 'arbitration_reset'})
        for a in (0x1fbab6, 0x277054, 0x33fa3c, 0x2d971c, 0x325e1c, 0x3275b0, 0x4c2898):
            page = a & ~4095
            if not any(lo <= page and page+4095 <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                self.uc.mem_write(page, stock.read(page, 4096))
            self.uc.mem_write(a, bytes.fromhex('1eff2fe1') if a in (0x325e1c, 0x3275b0)
                              else bytes.fromhex('7047'))
            self.uc.ctl_remove_cache(a, a+4)
        del self.hardware_fixtures[DRIVER_REQUEST]
        self.uc.mem_write(DRIVER_REQUEST, stock.read(DRIVER_REQUEST, 4))
        self.uc.ctl_remove_cache(DRIVER_REQUEST, DRIVER_REQUEST+4)
        self.native_aliases.update({'stock_output_init': 0x40ca81,
                                    'stock_public_stop': 0x36af75})
        self.uc.mem_write(OUTPUT_STACK_END-1024, b'\xa5'*64)
        self.kernel_call('stock_output_init')
        self.output_tcb = self.word(OUTPUT_GLOBAL)
        require(self.output_tcb == (OUTPUT_STACK_END-108)&~7 and
                self.byte(self.output_tcb+17) == 22 and self.byte(self.output_tcb+20) == 56 and
                self.byte(self.output_tcb+19) == 20, 'Original output task fields differ')
        self.aux_tasks[self.output_tcb] = {'name': 'output', 'stack_end': OUTPUT_STACK_END,
            'entry': 0x436c64, 'message_bytes': 56, 'slots': 20, 'priority': 22,
            'sends': [], 'receives': [], 'origins': [], 'entries': 0}
        self.driver_record = DRIVERS+self.channel*84
        self.actual_descriptor = self.driver_record+0x14
        # Explicit available physical-channel0 stereo16k inventory, with
        #mono16k source PCM; stock format/selection policy subsequently runs.
        self.uc.mem_write(self.driver_record+4, struct.pack('<H', 0))
        for offset, value in ((4, 4480), (8, 16000), (12, 16000), (16, 16000)):
            self.put(PHYSICAL_CHANNELS+offset, value)
        self.uc.mem_write(PHYSICAL_CHANNELS+20, struct.pack('<H', 2))
        # Cold routing/property mask and gain input. Original1FB85E/1FB4E0
        #copy/apply them; do not fill the resulting driver gain directly.
        self.put(self.record+0xcc, 1)
        self.uc.mem_write(self.record+0xd8, struct.pack('<h', 100))
        # Original allocation computes a one-second ring from this format.
        self.ring_bytes = 32000
        self.uc.mem_map((VIRTUAL_RING & ~4095)+0x3000, 0x6000)
        self.driver_ready = True
        self.kernel_call('_post', (self.output_tcb, 0x10))
        self.yield_all()
        require(self.aux_tasks[self.output_tcb]['entries'] == 1,
                'Original output task did not enter and block once')

    def kernel_call(self, name, args=(), stack=None):
        try:
            return super().kernel_call(name, args, stack)
        except (UcError, ValueError) as error:
            if hasattr(self, 'uc'):
                raise RuntimeError(f'{name}: {error}; PC={self.uc.reg_read(UC_ARM_REG_PC):#x}, '
                                   f'current={self.current():#x}, output_events={self.output_events[-4:]}') from error
            raise

    def observe(self, uc, address, size, data):
        if self.driver_ready:
            if address == DRIVER_REQUEST:
                raw = bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), 52))
                require(raw[0] == self.channel, 'Original output request channel differs')
                self.driver_requests.append({'opcode': uc.reg_read(UC_ARM_REG_R0),
                    'parameters_hex': raw.hex(), 'current_task': self.current()})
                return  # Restored original direct allocate / FIFO enqueue executes.
            if address == 0x38853c:
                n, kind, owner = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
                if kind == 1 and owner == self.driver_record+0x3c:
                    require(n == self.ring_bytes and all(h['freed'] for h in self.output_handles.values()),
                            'Unexpected/overlapping native output ring allocation')
                    h = 0xd1300001+len(self.output_handles)
                    uc.mem_write(VIRTUAL_RING-32, b'\xa5'*(n+64))
                    self.output_handles[h] = {'pointer': VIRTUAL_RING, 'bytes': n,
                                             'locks': 0, 'freed': False}
                    self.output_events.append({'kind': 'ring_allocate', 'handle': h,
                                              'bytes': n, 'current': self.current()})
                    uc.reg_write(UC_ARM_REG_R0, h)
                    return
            if address == 0x388804 and uc.reg_read(UC_ARM_REG_R0) in self.output_handles:
                h = self.output_handles[uc.reg_read(UC_ARM_REG_R0)]
                require(not h['freed'] and h['locks'] == 0, 'Output ring lock differs')
                h['locks'] = 1
                uc.reg_write(UC_ARM_REG_R0, h['pointer'])
                return
            if address == 0x3887a2 and uc.reg_read(UC_ARM_REG_R0) == self.driver_record+0x3c:
                h = self.word(self.driver_record+0x3c)
                a = self.output_handles[h]
                require(not a['freed'] and a['locks'] == 1 and self.current() == self.output_tcb,
                        'Original output retirement used unexpected handle/task')
                # Stock caller releases the held handle without a separate
                #unlock; heap-service behavior remains a controlled fixture.
                a['freed'], a['locks'] = True, 0
                self.put(self.driver_record+0x3c, 0)
                self.output_events.append({'kind': 'ring_release', 'handle': h, 'current': self.current()})
                uc.reg_write(UC_ARM_REG_R0, 0)
                return
            if address == DRIVER_CALLBACK:
                require(uc.reg_read(UC_ARM_REG_R0) == self.actual_descriptor and
                        self.current() == self.word(CENTRAL_GLOBAL),
                        'Allocation callback did not come from original central allocation caller')
                self.driver_callbacks.append({'current_task': self.current(),
                                              'descriptor': self.actual_descriptor})
                NativeTimer.observe(self, uc, address, size, data)
                return  # Skip older fixed-descriptor assertion only.
            if address in (PULL, *PULL_RETURNS):
                # Read-only observation shadow for inherited scratch/ring
                #checks. Original routines use actual driver-record+0x14;
                #the shadow is never copied back into original runtime data.
                uc.mem_write(MIX_DESCRIPTOR, bytes(uc.mem_read(self.actual_descriptor, 36)))
            if address in (0x1d9084, 0x1d8de2, 0x1d8d24, 0x1d8f2c, 0x1d8c98, SOURCE_FRAME):
                self.assert_aux_stack(self.output_tcb)
                self.native_driver_visits.add(address)
            if address == 0x1d8b74:
                self.driver_allocation_calls.append({'current': self.current(), 'parameters': uc.reg_read(UC_ARM_REG_R0)})
            if address == SOURCE_FRAME:
                require(uc.reg_read(UC_ARM_REG_R0) == self.channel and
                        uc.reg_read(UC_ARM_REG_R1) == FRAME_BUFFER and uc.reg_read(UC_ARM_REG_R2) == 1,
                        'Virtual peripheral source-frame ABI differs')
                self.frame_calls.append({'current': self.current(), 'consumer': self.word(self.actual_descriptor+12),
                                         'writer': self.word(self.actual_descriptor+16),
                                         'driver_state': self.half(self.driver_record),
                                         'first_source_flag': 1,
                                         'configured_gain': self.half(self.driver_record+0x52),
                                         'live_gain': self.half(self.driver_record+2)})
            if address == BRIDGE+40 and self.word(BRIDGE_ENABLE):
                samples = uc.reg_read(UC_ARM_REG_R0)
                require(self.current() == self.output_tcb and 2*samples <= FRAME_BYTES,
                        'Original source-frame result/task differs')
                raw = bytes(uc.mem_read(FRAME_BUFFER, 2*samples))
                self.peripheral_chunks.append(raw)
                self.frame_calls[-1].update({'output_samples': samples, 'output_bytes': len(raw),
                    'output_sha256': sha(raw), 'consumer_after': self.word(self.actual_descriptor+12)})
            if address == 0x277596:
                # Native next-selection calls the internal remover directly,
                #rather than the public wrapper277674 used by older fixtures.
                driver, index = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1))
                require(self.current() == self.mixer_tcb and driver == self.record+0x1a8 and
                        index == 0 and self.half(self.record+0x1c0) == 1,
                        'Original native next-selection deletion differs')
                self.original_node_removals.append({'current': self.current(), 'driver': driver,
                    'index': index, 'node_count_at_entry': self.half(self.record+0x1c0),
                    'internal_entry': hex(address)})
        super().observe(uc, address, size, data)

    def select_native(self, ticket):
        require(self.out('selection_guard', (ticket,)) == 0, 'Source admission failed')
        require(self.byte(SOURCE_STATES+self.channel) == 1, 'Previous native source did not return idle')
        require(self.kernel_call('stock_source_start', (self.channel, 0)) == 0, 'Original public start failed')
        self.yield_all()
        require(self.byte(self.record+2) == 1 and self.word(self.mixer) == self.actual_descriptor and
                self.half(self.driver_record) == 3 and self.byte(self.mixer+0x84) == 1,
                'Original driver allocation/start did not activate the source')
        require(self.word(self.actual_descriptor+4) == VIRTUAL_RING and
                self.word(self.actual_descriptor+8) == 32000 and
                self.word(self.actual_descriptor+24) == 2 and
                self.word(self.actual_descriptor+28) == 16000,
                'Original allocation descriptor/format differs from controlled physical input')
        require(self.half(self.driver_record+0x52) == 100 and self.half(self.driver_record+2) == 100,
                'Original output gain policy did not apply controlled gain100')
        # First pulls have already occurred through stock reader48EDF9,
        #while static owned PCM is pinned. This late attachment is explicit
        #and does not prove a production pre-first-read lifetime hook.
        require(self.out('after_selection', (ticket,)) == 0, 'Late serialized reader attachment failed')

    def frame(self):
        self.put(BRIDGE_ENABLE, 1)
        # Virtual interrupt availability/frame arrival, not physical IRQ.
        self.uc.mem_write(PHYSICAL_CHANNELS+23, b'\x01')
        self.uc.mem_write(FRAME_BUFFER-32, b'\xa5'*(FRAME_BYTES+64))
        self.uc.mem_write(FRAME_BUFFER, bytes(FRAME_BYTES))
        self.kernel_call('_post', (self.output_tcb, 1 << 15))
        self.yield_all()
        require(bytes(self.uc.mem_read(FRAME_BUFFER-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(FRAME_BUFFER+FRAME_BYTES, 32)) == b'\xa5'*32,
                'Original source-frame helper crossed virtual output guards')
        self.check_virtual_ring()

    def play_driver(self):
        ticket = self.pipe('owned_media_next')
        require(ticket > 0, 'Owned FIFO empty')
        n = self.slots()[ticket & 3]['bytes']
        wanted = bytes(self.uc.mem_read(self.buffers[ticket & 3], n))
        self.buffer_expected[ticket & 3] = wanted
        self.register_owned(ticket)
        before = len(self.native_chunks)
        peripheral_before = len(self.peripheral_chunks)
        removals_before = len(self.original_node_removals)
        self.select_native(ticket)
        require(b''.join(self.native_chunks[before:]) == wanted and self.byte(self.mixer+0x7e) == 1,
                'Automatic native allocation callback START/reads/EOF differ')
        require(self.pipe('owned_media_release', (ticket,)) == -25, 'EOF prematurely released source PCM')
        for _ in range(8):
            self.frame()
            if self.byte(SOURCE_STATES+self.channel) == 1 and not self.half(self.record+0x1c0):
                break
        require(self.byte(SOURCE_STATES+self.channel) == 1 and not self.byte(self.record+2) and
                not self.byte(self.mixer+0x84) and not self.word(self.mixer+0xb0) and
                not self.half(self.record+0x1c0) and not self.half(self.driver_record),
                'Original frame/end/stop/completion/next-source did not retire all native resources: '+
                str({'source_state': self.byte(SOURCE_STATES+self.channel),
                     'prepared': self.byte(self.record+2), 'mixer_active': self.byte(self.mixer+0x84),
                     'nodes': self.half(self.record+0x1c0), 'driver_state': self.half(self.driver_record),
                     'frames': self.frame_calls, 'requests': [p['opcode'] for p in self.driver_requests],
                     'central': [p[0] for p in self.aux_tasks[self.word(CENTRAL_GLOBAL)]['receives']]}))
        stereo = b''.join(wanted[i:i+2]*2 for i in range(0, len(wanted), 2))
        require(b''.join(self.peripheral_chunks[peripheral_before:]) == stereo and
                len(self.original_node_removals) == removals_before+1,
                'Native peripheral mono-to-stereo PCM or automatic source deletion differs')
        require(self.pipe('owned_media_release', (ticket,)) == 0, 'Native automatic retirement did not permit owned release')
        self.put(BRIDGE_ENABLE, 0)
        self.yield_all()
        return wanted

    def verify_driver(self):
        self.verify_central()
        require({0x1d9084, 0x1d8de2, 0x1d8d24, 0x1d8f2c, 0x1d8c98, SOURCE_FRAME}.issubset(self.native_driver_visits),
                'Original output dispatch/config/start/stop/retirement/frame path skipped')
        require(all(h['freed'] and not h['locks'] for h in self.output_handles.values()), 'Output ring retained')
        require(self.word(self.actual_descriptor+4) == VIRTUAL_RING and
                len(self.original_node_removals) == len(self.output_handles) > 0 and
                all(x['current'] == self.mixer_tcb for x in self.original_node_removals),
                'Source list retirement did not run on original audio task')
        for a in (DRIVER_REQUEST, 0x40ca80, 0x436c64, 0x1d8b74, 0x1fb85e, 0x1d8f2c, SOURCE_FRAME):
            require(bytes(self.uc.mem_read(a, 4)) == self.stock.read(a, 4), 'Original output entry altered')
        require(bytes(self.uc.mem_read(BRIDGE+60, 4096-60)) == b'\xa5'*(4096-60), 'Virtual frame veneer bounds differ')


def route(stock, companion, output, reference, tables, frequency, mode, packets=1):
    m = NativeDriver(stock, companion, output)
    frames = reference.encode(dict(frequency=frequency, mode=mode, subbands=1, blocks=3,
                                   allocation=0, bitpool=31 if mode == 0 else 53), frames=2*packets)
    rate, channels = (16000, 32000, 44100, 48000)[frequency], 1 if mode == 0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    tts = m.tts_snapshot()
    for i in range(packets):
        m.deliver(packet(frames[2*i:2*i+2], i))
        m.yield_all()
    if packets == 5:
        require(m.pipeline()[4] == 4 and m.queue_state()[2] == 1, 'Fifth compressed packet did not defer')
    actual = b''.join(m.play_driver() for _ in range(packets))
    require(actual == wanted and m.tts_snapshot() == tts and m.pipeline()[4] == 0,
            'Native driver source PCM/reference/TTS isolation differs')
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_driver()
    tasks = {t['name']: {'tcb': hex(tcb), 'entries': t['entries'], 'priority': t['priority'],
                        'messages': [p.hex() for p in t['receives']]} for tcb, t in m.aux_tasks.items()}
    return {'rate': rate, 'channels': channels, 'frames': 2*packets, 'packets': packets,
        'pcm_bytes': len(actual), 'pcm_sha256': sha(actual), 'tasks': tasks,
        'driver_requests': m.driver_requests, 'driver_events': m.output_events,
        'frame_calls': m.frame_calls, 'source_node_removals': m.original_node_removals,
        'peripheral_pcm_bytes': sum(len(p) for p in m.peripheral_chunks),
        'peripheral_pcm_sha256': sha(b''.join(m.peripheral_chunks)),
        'virtual_peripheral_stereo16k_pcm_identical_to_duplicated_mono_reference': True,
        'physical_frame_bytes': FRAME_BYTES, 'controlled_source_gain': 100,
        'original_driver_path_visits': sorted(hex(p) for p in m.native_driver_visits),
        'output_allocations': len(m.output_handles), 'all_reference_pcm_identical': True,
        'controller_direct_start14_stop15_cleanup19_remove_or_consumer_advance': False,
        'driver_allocation_callbacks_and_original_source_frames_execute_on_native_tasks': True,
        'late_reader_attachment_first_reads_original_reader_unwrapped': True,
        'passed': True}


def main():
    stock, reference = NativeImage(), Reference()
    contract = frame_contract(stock)
    companion, output = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
                                            ROOT/'staging/native-owned-media/manifest.json'))
    cv = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables = json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    routes = []
    for frequency, mode, packets in ((0, 0, 5), (2, 3, 1), (3, 2, 1)):
        routes.append(route(stock, companion, output, reference, tables, frequency, mode, packets))
        print(json.dumps({'rate': routes[-1]['rate'], 'passed': True}), flush=True)
    previous = ROOT/'evidence/firmware-analysis/native-source-controller-emulation.json'
    prior = json.loads(previous.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_source_controller.py', previous))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
        'owned_elf_sha256': output['elf_sha256'], 'routes': routes, 'all_passed': True,
        'source_frame_contract': contract,
        'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
        'limitations': 'Offline stock output task/56-byte FIFO/configuration/start/stop/allocation-caller/source-frame/central completion and end-next selection retiring the only registered source. Physical-channel0 stereo16k/4480-byte frame inventory and cold source routing mask1/gain100 are explicit inputs; original format/gain policy applies them. Peripheral startup/power/arbitration and frame-ready events/native ARM peripheral veneer are fixtures, not actual hardware IRQ/clock/DMA/DAC/speaker. Virtual bridge bypasses stock multisource physical dispatch loop437688, invokes one original source helper436E5E with first-source flag1, captures returned16-bit samples. Virtual output exactly duplicates reference mono16k samples into stereo at controlled gain100; other gain/mute policies, resampler, multisource mixing and speaker audibility unproved. Output allocator/held-handle release remain controlled, virtual ring reused only after original retirement. Fixed old descriptor is a read-only observation shadow, never written back into original data. Internal remover277596 runs nonvacuously on native mixer task once per source, ending node count0; public wrapper277674 is not the natural end-next deletion path. First reads occur through original unwrapped reader before explicit late compiled attachment, static owned PCM pinned under supplied single-actor/exclusive-source contract; no production first-read lifetime hook or future-callback/cross-channel reservation. Controller still registers sources, attaches reader, releases owned tickets and initiates each published source; this is not automatic selection of the next published PCM block, a continuous stream App, public-stop cancellation/restart or UI/accepted module/SEP/phone/realtime/safe unload. Notifier boot/wait only, no metadata/App notifications. Decoder/audio/output/timer/module storage retained. Google Maps deferred/full goal incomplete. No device I/O.'}
    p = ROOT/'evidence/firmware-analysis/native-output-manager-emulation.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
