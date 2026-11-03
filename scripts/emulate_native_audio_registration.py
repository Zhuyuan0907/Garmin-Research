#!/usr/bin/env python3
"""Execute stock type17 registration -> source queue -> factory -> pull offline.

Channel mapping and mixer RAM are synthetic; heap handles, mutexes, pull-loop
priority and message delivery are explicit hooks. No hardware/App is used.
Registration, source linked-list logic, source selection/factory and PCM
reading/copying run original instructions, not a fabricated method pointer.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
from unicorn import UcError

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_pcm_flow_control import StockPcm, REGISTER
from emulate_native_sbc import PAGE_BYTES, STACK
from emulate_native_sbc_pcm import CONTEXT, RING_BYTES

CHANNELS = 0x34e6f08
CHANNEL_STRIDE = 0x208
MIXERS = 0x34e5378
MIXER_STRIDE = 0x130
SOURCE_HEADS = 0x34e68d8
HEAP = 0x09700000
MIX_DESCRIPTOR = 0x09800020
MIX_BUFFER = 0x09801020
SCRATCH = 0x09803f00
SELECT = 0x2f9f2e
PULL = 0x2f9cca


def sha(data): return hashlib.sha256(data).hexdigest()
def require(value, message):
    if not value: raise ValueError(message)


class RegisteredPcm(StockPcm):
    def __init__(self, stock, channel=5, selector=1):
        self.stock = stock
        self.registration_visits = Counter()
        self.handles = {}
        self.allocations = []
        self.next_handle = 1
        self.fail_next_allocation = False
        self.mutex_depth = Counter()
        self.control_hooks = {}
        self.control_events = []
        super().__init__(stock)
        self.channel = channel
        self.record = CHANNELS+channel*CHANNEL_STRIDE
        self.mixer = MIXERS+channel*MIXER_STRIDE
        for page in (0x277000, 0x437000, 0x35b000, 0x2f9000, 0x2fa000,
                     0x300000, 0x388000, 0x37b000, 0x36a000, 0x3b9000):
            self.uc.mem_map(page, PAGE_BYTES)
            self.uc.mem_write(page, stock.read(page, PAGE_BYTES))
        self.uc.mem_map(0x34e5000, 0x5000)
        self.uc.mem_map(HEAP, 16*PAGE_BYTES)
        for page in (MIX_DESCRIPTOR & ~4095, MIX_BUFFER & ~4095, SCRATCH & ~4095):
            self.uc.mem_map(page, PAGE_BYTES)
        for address, name in ((0x38853c, 'allocate_handle'), (0x388804, 'lock_handle'),
                              (0x388b22, 'unlock_handle'), (0x3887a2, 'release_handle'),
                              (0x3009a0, 'mutex_lock'), (0x3008b0, 'mutex_unlock'),
                              (0x2f9c52, 'mixer_pull_priority'), (0x37bce4, 'queue_message')):
            self.control_hooks[address] = name
            self.uc.mem_write(address, b'\x70\x47')
        # Undo only the earlier high-level registration hook. Execute it and
        # the selected queue driver unchanged; prior hardware policy remains.
        del self.policy[REGISTER]
        self.uc.mem_write(REGISTER, stock.read(REGISTER, 4))
        self.policy[0x2554ca] = ('channel_selector', selector)
        for index in range(18): self.uc.mem_write(CHANNELS+index*CHANNEL_STRIDE, b'\x12')
        self.uc.mem_write(self.record, bytes([channel]))
        self.uc.mem_write(self.record+0x15d, b'\x02')
        self.uc.mem_write(self.record+0x1f8, bytes([channel]))
        self.symbols.update({
            'profile': {'address': 0x277d27},
            'select': {'address': SELECT | 1}, 'pull': {'address': PULL | 1},
            'register': {'address': REGISTER | 1}})
        require(self.call('profile', (channel, 0, 1)) == 0, 'Stock queue profile initialization failed')
        require(self.word(self.record+0x160) == 0x277c6b,
                'Stock profile did not install the original source-registration method')
        self.channel_baseline = bytes(self.uc.mem_read(CHANNELS, 18*CHANNEL_STRIDE))

    def word(self, address): return struct.unpack('<I', self.uc.mem_read(address, 4))[0]
    def put(self, address, value): self.uc.mem_write(address, struct.pack('<I', value))
    def half(self, address): return struct.unpack('<H', self.uc.mem_read(address, 2))[0]

    def call(self, name, args=(), stack_args=()):
        if stack_args: self.uc.mem_write(STACK, struct.pack('<'+'I'*len(stack_args), *stack_args))
        try:
            returned, result = self.invoke(name, args)
        except UcError as error:
            raise RuntimeError(f'{name}: {error}, PC={self.uc.reg_read(UC_ARM_REG_PC):#x}, '
                               f'control_events={self.control_events[-4:]}') from error
        require(returned, 'Registration call did not return')
        return result

    def observe(self, uc, address, size, data):
        self.registration_visits[address] += 1
        super().observe(uc, address, size, data)
        if address not in self.control_hooks: return
        name = self.control_hooks[address]
        args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                        UC_ARM_REG_R2, UC_ARM_REG_R3)]
        self.control_events.append({'hook': name, 'args': [hex(a) for a in args]})
        result = 0
        if name == 'allocate_handle':
            size, kind, out = args[:3]
            require(0 < size <= PAGE_BYTES-64 and kind in (2, 3), 'Unexpected handle allocation')
            handle = 0
            if self.fail_next_allocation: self.fail_next_allocation = False
            else:
                index = self.next_handle; self.next_handle += 1
                require(index <= 16, 'Synthetic handle heap exhausted')
                handle, pointer = 0xd0000000+index, HEAP+(index-1)*PAGE_BYTES+32
                uc.mem_write(pointer-32, b'\xa5'*(size+64))
                self.handles[handle] = {'pointer': pointer, 'size': size, 'locks': 0, 'freed': False}
            self.allocations.append({'size': size, 'kind': kind, 'handle': hex(handle)})
            self.put(out, handle)
        elif name == 'lock_handle':
            entry = self.handles[args[0]]
            require(not entry['freed'], 'Lock of released synthetic handle')
            entry['locks'] += 1; result = entry['pointer']
        elif name == 'unlock_handle':
            entry = self.handles[args[0]]
            require(not entry['freed'] and entry['locks'] > 0, 'Unbalanced handle unlock')
            entry['locks'] -= 1
        elif name == 'release_handle':
            handle = self.word(args[0]); entry = self.handles[handle]
            require(not entry['freed'] and entry['locks'] <= 1, 'Unexpected handle release')
            # This controlled handle service accepts release of the selected
            # parameter handle while held, as the original caller does.
            entry['freed'] = True; entry['locks'] = 0; self.put(args[0], 0)
        elif name == 'mutex_lock': self.mutex_depth[args[0]] += 1
        elif name == 'mutex_unlock':
            require(self.mutex_depth[args[0]] > 0, 'Unbalanced synthetic mutex')
            self.mutex_depth[args[0]] -= 1
        elif name == 'queue_message':
            # Observe the real copied message request, but do not run a mixer
            # OS task or hardware drain. PULL is explicitly called by the test.
            payload = bytes(uc.mem_read(args[1], 2))
            self.control_events[-1]['message_first_two_bytes'] = payload.hex()
        uc.reg_write(UC_ARM_REG_R0, result)

    def verify_controls(self):
        require(not any(self.mutex_depth.values()), 'Stock flow retained synthetic mutex')
        for entry in self.handles.values():
            require(entry['locks'] == 0, 'Stock flow retained synthetic handle lock')
            pointer, size = entry['pointer'], entry['size']
            require(bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32 and
                    bytes(self.uc.mem_read(pointer+size, 32)) == b'\xa5'*32,
                    'Source queue crossed its allocated object bounds')
        current = bytes(self.uc.mem_read(CHANNELS, 18*CHANNEL_STRIDE))
        for index in range(18):
            if index != self.channel:
                lo, hi = index*CHANNEL_STRIDE, (index+1)*CHANNEL_STRIDE
                require(current[lo:hi] == self.channel_baseline[lo:hi], 'Stock flow changed neighboring source slot')
        self.verify_ring_guards()

    def populate(self, initial=0):
        self.configure(initial, active=False)
        chunk = struct.pack('<128h', *range(-64, 64))
        for _ in range(40): self.put_pcm(chunk)
        require(len(self.requests) == 1 and self.requests[0]['register_args'] ==
                [self.channel, 17, 6, CONTEXT+4], 'Original PCM start registration arguments differ')
        return chunk*40

    def select_source(self):
        self.call('select', (self.channel, 0))
        require(self.word(self.record+0x108) == 0x484c05 and
                self.word(self.record+0x10c) == 0x484c49,
                'Registered source did not select the exact kind17 read/format methods')
        channels, bits, align, rate = struct.unpack('<HHII', self.uc.mem_read(self.record+0x138, 12))
        require((channels, bits, align, rate) == (1, 16, 2, 16000), 'Selected source format differs')
        require(bytes(self.uc.mem_read(self.record+2, 1)) == b'\x01', 'Source was not prepared')

    def setup_mixer(self):
        self.uc.mem_write(MIX_DESCRIPTOR-32, b'\xa5'*(32+36+32))
        buffer_bytes = 2048
        self.uc.mem_write(MIX_BUFFER-32, b'\xa5'*(buffer_bytes+64))
        initial = MIX_BUFFER+buffer_bytes-64
        descriptor = struct.pack('<9I', 0, MIX_BUFFER, buffer_bytes, initial, initial, 0, 0, 0, 0)
        self.uc.mem_write(MIX_DESCRIPTOR, descriptor)
        self.put(self.mixer, MIX_DESCRIPTOR)
        self.put(self.mixer+4, 256)
        self.put(self.mixer+0x78, 0xa002)
        self.put(self.mixer+0xb4, SCRATCH)
        self.uc.mem_write(SCRATCH-32, b'\xa5'*(256+32))
        self.uc.mem_write(self.mixer+0x7f, b'\x00')
        return initial

    def pull(self):
        before = self.word(MIX_DESCRIPTOR+16)
        self.uc.mem_write(SCRATCH-32, b'\xa5'*(256+32))
        self.call('pull', (self.channel,))
        after = self.word(MIX_DESCRIPTOR+16)
        count = (after-before)%2048
        require(0 < count <= 256, 'Stock pull did not commit a bounded PCM chunk')
        first = min(count, MIX_BUFFER+2048-before)
        actual = bytes(self.uc.mem_read(before, first))
        if first < count: actual += bytes(self.uc.mem_read(MIX_BUFFER, count-first))
        require(bytes(self.uc.mem_read(SCRATCH-32, 32)) == b'\xa5'*32,
                'Stock pull crossed scratch leading guard')
        require(bytes(self.uc.mem_read(SCRATCH+count, 256-count)) == b'\xa5'*(256-count),
                'Stock reader wrote beyond the committed count')
        require(bytes(self.uc.mem_read(MIX_BUFFER-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(MIX_BUFFER+2048, 32)) == b'\xa5'*32,
                'Stock pull crossed mixer-buffer guard')
        return actual, after < before

    def attachment_reselection_control(self, companion):
        """Stock source selection may recreate methods while wrapper remains marked attached."""
        symbols = companion['symbols']
        base = companion['load_base']
        code_bytes = (symbols['__queue_code_end']['address']-base+4095)&~4095
        self.uc.mem_map(base, code_bytes)
        self.uc.mem_write(base, (ROOT/companion['flat_binary']).read_bytes())
        state = symbols['__queue_state_start']['address']
        self.uc.mem_map(state, PAGE_BYTES)  # Zero BSS; worker/queue are never booted here.
        self.uc.mem_map(0x21b000, PAGE_BYTES)
        self.uc.mem_write(0x21b000, self.stock.read(0x21b000, PAGE_BYTES))
        for name in ('media_consumer_init', 'media_consumer_attach', 'media_consumer_detach'):
            self.symbols[name] = symbols[name]
        methods = self.record+0xf4
        original = bytes(self.uc.mem_read(methods, 68))
        require(self.call('media_consumer_init') == 0 and
                self.call('media_consumer_attach', (methods, 68)) == 0,
                'Compiled wrapper failed to attach to stock-selected source instance')
        wrapped = bytearray(original)
        struct.pack_into('<I', wrapped, 20, symbols['media_consumer_read']['address'])
        require(bytes(self.uc.mem_read(methods, 68)) == wrapped,
                'Attachment changed source method other than the reader')
        before = self.registration_visits[0x437764]
        self.select_source()
        require(self.registration_visits[0x437764] == before+1 and
                bytes(self.uc.mem_read(methods, 68)) == original,
                'Original source reselection did not recreate its method array')
        metadata = symbols['media_consumer_state']['address']
        require(self.word(metadata+4) == 1 and self.word(self.record+0x108) == 0x484c05,
                'Reselection control did not reproduce overwritten attachment')
        require(self.call('media_consumer_detach') == (-29)&0xffffffff,
                'Compiled detach failed to detect provider replacing the wrapped reader')
        self.verify_controls()
        return {'case': 'stock_source_reselection_overwrites_attached_reader',
                'channel': self.channel, 'descriptor_created_by_stock_source_selection': True,
                'compiled_wrapper_changes_only_reader': True,
                'stock_factory_recreates_all_methods_on_reselection': True,
                'consumer_metadata_still_marked_installed': True,
                'reader_reverts_to_stock': True, 'detach_detects_replacement_error': -29,
                'production_rehook_and_quiescence_not_implemented': True,
                'registered_pull_capacity_feedback_not_tested_here': True, 'passed': True}


def registered_route(stock, channel, selector, initial, companion):
    m = RegisteredPcm(stock, channel, selector)
    expected = m.populate(initial)
    require(m.half(m.record+0x1c0) == 1, 'Actual source queue did not retain one registered entry')
    handle = m.word(SOURCE_HEADS+channel*4)
    entry = m.handles[handle]
    require(bytes(m.uc.mem_read(entry['pointer']+12, 2)) == bytes([17, 6]) and
            m.half(entry['pointer']+16) == 1, 'Original source queue lost kind/flags/parameter length')
    m.select_source(); m.setup_mixer()
    output, wraps = [], 0
    for _ in range(3):
        data, wrapped = m.pull(); output.append(data); wraps += int(wrapped)
    actual = b''.join(output)
    require(actual == expected[:768] and wraps == 1, 'Registered reader/mixer copy changed PCM or missed wrap')
    required = {REGISTER, 0x277c6a, 0x277b38, SELECT, 0x277ac2, 0x2777f0,
                0x4379d4, 0x437764, 0x35b4f4, 0x437a3e, PULL, 0x2f9d1a, 0x484c04, 0x33f662}
    require(required.issubset(m.registration_visits), 'Registered source path skipped original instructions')
    m.verify_controls()
    reselection = m.attachment_reselection_control(companion)
    return {'channel': channel, 'selector': selector, 'initial_tts_ring_index': initial,
            'original_source_queue_entries': 1, 'registered_source_kind': 17, 'registered_source_flags': 6,
            'factory_descriptor_address': hex(m.record+0xf4), 'reader_pointer_address': hex(m.record+0x108),
            'reader_pointer_word': '0x484c05', 'logical_format': {'channels': 1, 'bits': 16, 'rate': 16000},
            'explicit_stock_pull_calls': 3, 'copied_pcm_bytes': len(actual), 'mixer_copy_wraps': wraps,
            'pcm_sha256': sha(actual), 'reference_byte_identical': True,
            'registration_and_factory_not_hooked': True, 'read_method_not_supplied_by_test': True,
            'allocations': m.allocations, 'requests': m.requests,
            'stock_paths_visited': [hex(a) for a in sorted(required)],
            'controlled_calls': m.control_events, 'attachment_reselection_control': reselection, 'passed': True}


def guards(stock):
    m = RegisteredPcm(stock)
    m.fail_next_allocation = True
    m.populate()
    require(m.half(m.record+0x1c0) == 0 and m.word(SOURCE_HEADS+5*4) == 0 and
            bytes(m.uc.mem_read(CONTEXT+4, 1)) == b'\x01',
            'Allocation failure did not expose ignored registration result with controlled successful start')
    m.call('select', (5, 0))
    require(not m.registration_visits[0x437764] and m.word(m.record+0x108) == 0,
            'Empty source queue fabricated a read method after failed registration')
    m.verify_controls()
    cases = [{'case': 'source_allocation_failure_leaves_empty_queue_but_host_success',
              'registered_source_count': 0, 'host_callback_return': 0,
              'start_success_is_still_hooked': True, 'factory_not_entered': True, 'passed': True}]
    for name, channel in (('out_of_range_channel', 18), ('unmapped_channel', 4)):
        before = len(m.allocations)
        status = m.call('register', (channel, 17, 6, CONTEXT+4), (1, 0, 0))
        require(status == 8 and len(m.allocations) == before, 'Invalid channel reached source allocation')
        cases.append({'case': name, 'channel': channel, 'status': status,
                      'no_source_allocation': True, 'passed': True})
    return cases


def main():
    stock = NativeImage()
    companion_path = ROOT/'staging/native-media-consumer/manifest.json'
    companion = json.loads(companion_path.read_text())
    for path, digest in companion['source_sha256'].items():
        require(sha((ROOT/path).read_bytes()) == digest, 'Companion source changed: '+path)
    for field in ('elf', 'flat_binary'):
        require(sha((ROOT/companion[field]).read_bytes()) == companion[field+'_sha256'], 'Companion artifact changed')
    routes = [registered_route(stock, 5, 1, 0, companion),
              registered_route(stock, 8, 0, RING_BYTES-64, companion)]
    controls = guards(stock)
    functions = (REGISTER, 0x277d26, 0x277c6a, 0x277b38, 0x2777f0,
                 SELECT, 0x4379d4, 0x437a3e, PULL, 0x2f9c12)
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                   (ROOT/'scripts/emulate_native_pcm_flow_control.py',
                                    ROOT/'scripts/emulate_native_sbc_pcm.py',
                                    ROOT/'scripts/analyze_sdp_activation.py', companion_path)},
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'channel_table': hex(CHANNELS), 'channel_count': 18, 'channel_stride': CHANNEL_STRIDE,
              'factory_method_offset_in_channel_record': 0xf4,
              'read_pointer_offset_in_channel_record': 0x108,
              'routes': routes, 'control_cases': controls, 'all_passed': True,
              'attachment_reselection_controls': len(routes),
              'stock_source_reselection_overwrites_wrapped_reader_verified': True,
              'production_rehook_and_quiescence_implemented': False,
              'actual_registration_queue_factory_and_indirect_pull_executed_offline': True,
              'stock_source_kind17_reader_selected_without_test_pointer_injection': True,
              'source_allocator_and_handle_service_hooked': True,
              'channel_mapping_and_driver_initial_state_synthetic': True,
              'mutexes_mixer_priority_and_message_delivery_hooked': True,
              'pull_loop_explicitly_called_not_hardware_scheduled': True,
              'cold_pcm_initialization_verified': False, 'navigation_ring_ownership_verified': False,
              'actual_device_registration_or_audio_playback_verified': False,
              'device_io': False, 'device_install_candidate': False,
              'stock_function_traces': {hex(a): trace(stock, a, 300) for a in functions},
              'limitations': 'Offline original registration/source queue/factory/prepare/indirect reader/mixer copy with synthetic mapped channel5 or8 and initialized producer. Handles/allocation, both source mutexes, mixer pull priority and next-message delivery are controlled. Existing busy/selector/sequence/start hardware policy hooks remain. Pull function is called explicitly, not by an actual mixer worker/IRQ. Mixer descriptor/buffer/scratch are synthetic. Compiled consumer attaches to the actually stock-selected descriptor, then original reselection overwrites it and detach detects replacement; worker/queue are not booted in this attachment control and registered-pull capacity feedback/reinstallation/quiescence are untested. No live driver initialization or exclusive ring ownership/navigation coexistence, cold producer init, hardware sample rate/resampling, physical speaker, SEP/UI/phone stream or modified package acceptance is verified. Allocation failure shows original host ignores registration failure only with the controlled successful-start hook; it does not prove live channel starts successfully after failure.'}
    path = ROOT/'evidence/firmware-analysis/native-audio-registration-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'registered_routes': len(routes), 'controls': len(controls),
                      'attachment_reselection_controls': len(routes),
                      'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
