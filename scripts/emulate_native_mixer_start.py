#!/usr/bin/env python3
"""Original mixer START14/STOP15 on native tasks, with a virtual output ring.

The actor obtains its real source block size, allocates/locks a scratch handle,
starts its first pull and frees the scratch on stop. Heap services and the
output descriptor/consumer remain fixtures; no hardware or device I/O occurs.
"""
from datetime import datetime, timezone
import json
import struct
from pathlib import Path

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_mixer_worker import NativeMixer, GET_MESSAGE, MESSAGE_POST, WAIT
from emulate_native_owned_worker import OwnedWorker
from emulate_native_audio_registration import MIX_DESCRIPTOR, require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm

VIRTUAL_RING = 0x09b00020
VIRTUAL_RING_BYTES = 8192
SCRATCH_HEAP = 0x09a00000
PULL = 0x2f9cca
PULL_RETURNS = (0x2fa43c, 0x2fa576)


class NativeStart(NativeMixer):
    def __init__(self, stock, companion, output, ring_bytes=VIRTUAL_RING_BYTES):
        self.start_ready = False
        self.scratch_handles = {}
        self.start_events = []
        self.block_size_returns = []
        self.ring_bytes = ring_bytes
        super().__init__(stock, companion, output)
        require(4096 < ring_bytes <= VIRTUAL_RING_BYTES, 'Unsupported virtual ring size')
        self.uc.mem_map(VIRTUAL_RING & ~4095, 3*4096)
        self.start_ready = True

    def observe(self, uc, address, size, data):
        if not self.start_ready:
            super().observe(uc, address, size, data)
            return
        if address == 0x38853c:
            n, kind, out = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if kind == 0 and out == 0:
                self.assert_actor_stack(address)
                require(n == 4096, 'Original START requested an unexpected source block size')
                index = len(self.scratch_handles)
                h = 0xd1200001+index
                p = SCRATCH_HEAP+index*0x4000
                uc.mem_map(p, 8192)
                uc.mem_write(p, b'\xa5'*8192)
                self.scratch_handles[h] = {'pointer': p+32, 'bytes': n, 'locks': 0,
                                           'freed': False, 'channel': self.channel}
                self.start_events.append({'kind': 'allocate', 'handle': h, 'bytes': n,
                                          'current_task': self.current()})
                uc.reg_write(UC_ARM_REG_R0, h)
                return
        if address == 0x388804 and uc.reg_read(UC_ARM_REG_R0) in self.scratch_handles:
            self.assert_actor_stack(address)
            a = self.scratch_handles[uc.reg_read(UC_ARM_REG_R0)]
            require(not a['freed'] and a['locks'] == 0, 'Original scratch lock is unbalanced')
            a['locks'] = 1
            uc.reg_write(UC_ARM_REG_R0, a['pointer'])
            return
        if address == 0x388b22 and uc.reg_read(UC_ARM_REG_R0) in self.scratch_handles:
            self.assert_actor_stack(address)
            h = uc.reg_read(UC_ARM_REG_R0)
            a = self.scratch_handles[h]
            require(not a['freed'] and a['locks'] == 1, 'Original scratch unlock is unbalanced')
            a['locks'] = 0
            self.start_events.append({'kind': 'unlock', 'handle': h, 'current_task': self.current()})
            uc.reg_write(UC_ARM_REG_R0, 0)
            return
        if address == 0x3887a2 and uc.reg_read(UC_ARM_REG_R0) == self.mixer+0xb0:
            self.assert_actor_stack(address)
            p = uc.reg_read(UC_ARM_REG_R0)
            h = self.word(p)
            a = self.scratch_handles[h]
            require(not a['freed'] and a['locks'] == 0, 'Original STOP freed a locked scratch handle')
            a['freed'] = True
            self.put(p, 0)
            self.start_events.append({'kind': 'free', 'handle': h, 'current_task': self.current()})
            uc.reg_write(UC_ARM_REG_R0, 0)
            return
        if address == 0x2fa3be:
            require(uc.reg_read(UC_ARM_REG_R0) == 4096 and self.word(self.record+0x100) == 0x48ee9f,
                    'START did not execute the original kind10 block-size getter')
            self.block_size_returns.append(uc.reg_read(UC_ARM_REG_R0))
        if address == PULL:
            self.assert_actor_stack(address)
            require(self.pull_before is None, 'Nested original pull')
            self.pull_before = self.word(MIX_DESCRIPTOR+16)
            a = self.scratch_handles[self.word(self.mixer+0xb0)]
            require(a['locks'] == 1 and not a['freed'] and self.word(self.mixer+0xb4) == a['pointer'],
                    'Original pull used an unowned/unlocked scratch buffer')
            uc.mem_write(a['pointer']-32, b'\xa5'*(a['bytes']+64))
            # Skip only NativeMixer's obsolete 256-byte scratch capture.
            OwnedWorker.observe(self, uc, address, size, data)
            return
        if address in PULL_RETURNS:
            require(self.pull_before is not None, 'Original START/READ return missed its pull')
            before = self.pull_before
            self.pull_before = None
            after = self.word(MIX_DESCRIPTOR+16)
            n = (after-before) % self.ring_bytes
            a = self.scratch_handles[self.word(self.mixer+0xb0)]
            require(n <= a['bytes'], 'Original source pull exceeded its allocated block')
            first = min(n, VIRTUAL_RING+self.ring_bytes-before)
            raw = bytes(uc.mem_read(before, first))
            if first < n:
                raw += bytes(uc.mem_read(VIRTUAL_RING, n-first))
            require(bytes(uc.mem_read(a['pointer']-32, 32)) == b'\xa5'*32 and
                    bytes(uc.mem_read(a['pointer']+n, a['bytes']+32-n)) == b'\xa5'*(a['bytes']+32-n),
                    'Original source reader crossed scratch bounds')
            self.check_virtual_ring()
            self.native_chunks.append(raw)
            OwnedWorker.observe(self, uc, address, size, data)
            return
        super().observe(uc, address, size, data)

    def check_virtual_ring(self):
        require(bytes(self.uc.mem_read(VIRTUAL_RING-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(VIRTUAL_RING+self.ring_bytes, 32)) == b'\xa5'*32,
                'Original source pull crossed virtual ring bounds')

    def prepare_virtual_output(self):
        require(not self.byte(self.mixer+0x84) and not self.word(self.mixer+0xb0),
                'Cannot replace the virtual output of an active actor')
        self.uc.mem_write(MIX_DESCRIPTOR-32, b'\xa5'*(36+64))
        self.uc.mem_write(VIRTUAL_RING-32, b'\xa5'*(self.ring_bytes+64))
        initial = VIRTUAL_RING+self.ring_bytes-64
        # This output descriptor is synthetic. Matching the selected 16 kHz
        #source isolates START's no-resampler branch, not a real DAC clock.
        self.uc.mem_write(MIX_DESCRIPTOR, struct.pack('<9I', 0, VIRTUAL_RING, self.ring_bytes,
                                                      initial, initial, 0, 2, 16000, 0))
        self.put(self.mixer, MIX_DESCRIPTOR)

    def select_native(self, ticket):
        require(self.out('selection_guard', (ticket,)) == 0, 'Native pool admission failed')
        require(self.call('queue_start', (self.record+0x1a8,)) == 0, 'Original queue start failed')
        if not self.mixer_tcb:
            require(self.kernel_call('stock_mixer_init', (self.channel, 0)) == 0,
                    'Original mixer initializer failed')
        else:
            self.post_audio(13)
        self.yield_all()
        require(self.out('after_selection', (ticket,)) == 0, 'Explicit serialized reader attachment failed')
        self.prepare_virtual_output()

    def start_native(self):
        before = len(self.native_chunks)
        self.post_audio(14)
        self.yield_all()
        require(self.byte(self.mixer+0x84) == 1 and not self.byte(self.mixer+0x7f) and
                self.word(self.mixer+4) == 4096 and self.word(self.mixer+8) == 16384,
                'Original START flags/block size differ')
        return b''.join(self.native_chunks[before:])

    def finish_native(self, ticket):
        require(self.pipe('owned_media_release', (ticket,)) == -25, 'EOF alone released native PCM')
        self.post_audio(15)
        self.yield_all()
        require(not self.byte(self.mixer+0x84) and not self.word(self.mixer+0xb0) and
                not self.word(self.mixer+0xb4), 'STOP did not release scratch and deactivate actor')
        require(self.pipe('owned_media_release', (ticket,)) == -25, 'STOP alone released native PCM')
        self.post_audio(19)
        self.yield_all()
        require(not self.byte(self.record+2) and
                bytes(self.uc.mem_read(self.record+0xf4, 68)) == bytes(68), 'CLEANUP left source methods')
        require(self.pipe('owned_media_release', (ticket,)) == -25, 'CLEANUP alone released native PCM')
        require(self.call('source_remove', (self.record+0x1a8, 0)) == 0, 'Original node removal failed')
        require(self.pipe('owned_media_release', (ticket,)) == 0, 'Complete lifecycle release failed')
        self.yield_all()

    def play_native(self):
        ticket = self.pipe('owned_media_next')
        require(ticket > 0, 'Owned PCM FIFO is empty')
        n = self.slots()[ticket & 3]['bytes']
        wanted = bytes(self.uc.mem_read(self.buffers[ticket & 3], n))
        self.buffer_expected[ticket & 3] = wanted
        self.register_owned(ticket)
        self.select_native(ticket)
        actual = self.start_native()
        require(actual == wanted and self.byte(self.mixer+0x7e) == 1 and
                self.byte(MIX_DESCRIPTOR+0x20) == 1, 'START/self-read did not reach exact PCM/EOF')
        # EOF leaves the original actor active, provider prepared, scratch
        #locked and list present. A software end marker is not DAC drain.
        require(self.byte(self.mixer+0x84) == 1 and self.byte(self.record+2) == 1 and
                self.half(self.record+0x1c0) == 1 and
                self.scratch_handles[self.word(self.mixer+0xb0)]['locks'] == 1,
                'EOF unexpectedly completed native resource retirement')
        self.finish_native(ticket)
        return actual

    def verify_start(self):
        self.verify_kernel()
        require(self.native_actor_entries == 1 and self.worker_context is None and not self.shadow_waits,
                'Actor restarted or used Python context/transport fixture')
        require(self.message_sends == self.message_receives, 'Original FIFO copy/order differs')
        require(len(self.block_size_returns) == len(self.scratch_handles) and
                all(a['freed'] and not a['locks'] for a in self.scratch_handles.values()),
                'Original START/STOP scratch lifetimes are incomplete')
        for a in self.scratch_handles.values():
            require(bytes(self.uc.mem_read(a['pointer']-32, 32)) == b'\xa5'*32 and
                    bytes(self.uc.mem_read(a['pointer']+a['bytes'], 32)) == b'\xa5'*32,
                    'Scratch boundary canary differs')
        for a in self.mixer_allocations.values():
            require(a['locks'] == 1, 'Mixer task/FIFO allocation unexpectedly released')
            if a['bytes'] == 8192:
                require(bytes(self.uc.mem_read(a['pointer'], 64)) == b'\xa5'*64, 'Mixer stack crossed canary')
            else:
                require(bytes(self.uc.mem_read(a['pointer']+240, a['mapped']-240)) ==
                        b'\xa5'*(a['mapped']-240), 'Original FIFO exceeded allocation')
        for a in (WAIT, GET_MESSAGE, MESSAGE_POST, 0x48ee9e):
            require(bytes(self.uc.mem_read(a, 4)) == self.stock.read(a, 4), 'Original kernel/source entry changed')
        require(self.word(self.mixer+0x78) == self.mixer_tcb, 'Original mixer TCB was overwritten')
        self.check_virtual_ring()


def route(stock, companion, output, reference, tables, frequency, mode):
    m = NativeStart(stock, companion, output)
    frames = reference.encode(dict(frequency=frequency, mode=mode, subbands=1, blocks=3,
                                   allocation=0, bitpool=31 if mode == 0 else 53), frames=10)
    rate = (16000, 32000, 44100, 48000)[frequency]
    channels = 1 if mode == 0 else 2
    wanted, _ = reference_pcm(reference, frames, rate, channels, tables)
    tts = m.tts_snapshot()
    for i in range(5):
        m.deliver(packet(frames[i*2:i*2+2], i))
        m.yield_all()
    require(m.queue_state()[2] == 1 and m.pipeline()[4] == 4, 'Fifth compressed packet did not defer')
    actual = b''.join(m.play_native() for _ in range(5))
    require(actual == wanted and m.pipeline()[4] == 0 and m.tts_snapshot() == tts,
            'Original START route PCM/TTS isolation differs')
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_start()
    require(m.fifo_wraps > 0, 'Repeated START route did not exercise native FIFO wrap')
    return {'rate': rate, 'channels': channels, 'frames': 10, 'packets': 5,
            'pcm_bytes': len(actual), 'pcm_sha256': sha(actual), 'native_actor_entries': m.native_actor_entries,
            'original_message_count': len(m.message_sends), 'fifo_wraps': m.fifo_wraps,
            'scratch_allocations_and_frees': len(m.scratch_handles), 'source_block_bytes': m.block_size_returns,
            'first_pull_from_original_start14': True, 'external_read18_not_needed_for_these_sources': True,
            'eof_keeps_actor_provider_scratch_and_source_list_live': True,
            'all_source_pcm_upstream_absolute_convolution_identical': True,
            'tts_context_and_entire_ring_unchanged': True, 'passed': True}


def capacity_control(stock, companion, output, reference, tables):
    m = NativeStart(stock, companion, output, ring_bytes=6144)
    frames = reference.encode(dict(frequency=0, mode=0, subbands=1, blocks=3,
                                   allocation=0, bitpool=31), frames=15)
    wanted, _ = reference_pcm(reference, frames, 16000, 1, tables)
    m.deliver(packet(frames, 0))
    m.yield_all()
    ticket = m.pipe('owned_media_next')
    m.buffer_expected[ticket & 3] = wanted
    m.register_owned(ticket)
    m.select_native(ticket)
    actual = m.start_native()
    require(actual == wanted and len(wanted) == 3840 and not m.byte(self_address := m.mixer+0x7e),
            'Virtual capacity should prevent the next original 4096-byte read/EOF probe')
    require(m.pipe('owned_media_release', (ticket,)) == -25, 'Capacity stall released PCM early')
    before = len(m.native_chunks)
    m.yield_all()
    require(len(m.native_chunks) == before, 'Blocked actor advanced without a capacity event')
    # Explicit virtual hardware consumption and rearm; not DMA/IRQ evidence.
    m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))
    m.post_audio(18)
    m.yield_all()
    require(m.byte(self_address) == 1 and m.native_chunks[before:] == [b''],
            'Explicit consumer advancement/read18 did not reach original EOF')
    m.finish_native(ticket)
    require(m.pipe('media_worker_shutdown') == 0, 'Capacity-control shutdown failed')
    m.yield_all()
    m.verify_start()
    return {'case': '4096_byte_source_read_gate_on_6144_byte_virtual_ring', 'frames': 15,
            'pcm_bytes': len(actual), 'pcm_sha256': sha(actual), 'source_block_bytes': 4096,
            'source_pcm_copied_before_eof_probe_is_capacity_blocked': True,
            'remaining_virtual_ring_space': 2304,
            'explicit_consumer_index_and_read18_required_to_probe_eof': True,
            'native_dma_capacity_irq_or_hardware_drain_verified': False, 'passed': True}


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
    controls = [capacity_control(stock, companion, output, reference, tables)]
    prior_path = ROOT/'evidence/firmware-analysis/native-mixer-worker-emulation.json'
    prior = json.loads(prior_path.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_mixer_worker.py', prior_path))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
              'owned_elf_sha256': output['elf_sha256'], 'routes': routes, 'controls': controls, 'all_passed': True,
              'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
              'original_message14_source_allocation_first_pull_and15_scratch_retirement_executed': True,
              'real_output_driver_dac_rate_dma_drain_or_complete_automatic_source_lifecycle_verified': False,
              'limitations': 'Offline original kernel decoder/audio tasks and original12-byte FIFO transport. START14 executes original kind10 block-size getter(4096), scratch allocation/lock calls, matching-format branch, integer timing arithmetic, report24 and initial source pull. STOP15 executes original unlock/free calls and deactivates source; allocator/lock services themselves remain controlled. Output descriptor/ring and matching16kHz rate are synthetic, not a DAC/driver configuration. No resampler branch, physical output allocation/start/drain/DMA/IRQ or real clock. Original auto-read probes EOF on8192-byte ring;6144-byte capacity control stalls before EOF despite all3840 source bytes copied, then explicit consumer advancement/read18 probes EOF. EOF retains active actor/prepared provider/locked scratch/list; explicit15/19/remove/release are still required. Selection guard/queue start/reader attachment/source lifecycle boundaries remain controller supplied, one actor, no cross-channel pool reservation/future callback exclusion or installed UI/SEP. Generic mutex/priority and hardware hints remain inherited fixtures. Scratch canaries reseeded each original pull. Immutable PCM/TTS ring checks are not navigation concurrency. Audio task allocations and decoder TCB/stack/module remain pinned. No real phone/speaker/package acceptance/safe unload/Google Maps. No device I/O.'}
    p = ROOT/'evidence/firmware-analysis/native-mixer-start-emulation.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__':
    main()
