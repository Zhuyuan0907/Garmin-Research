#!/usr/bin/env python3
"""Observe exact stock PCM start requests and waiting, offline only.

The producer is already initialized; cold initialization is not exercised.
Stock callback/reserve/commit/start/reader and memcpy execute unchanged. Channel
policy, registration/start and wait functions are explicit synthetic hooks.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_sbc import (INPUT_PAGE, OUTPUT_PAGE, PAGE_BYTES,
                                RETURN, STACK)
from emulate_native_sbc_pcm import (PcmMachine, CONTEXT, RING_BYTES, HOST_OUTPUT)

WAIT = 0x353be4
RESERVE = 0x33f824
START = 0x33f474
REGISTER = 0x270458


class StockPcm(PcmMachine):
    def __init__(self, stock):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.manifest = {'exports': []}
        self.symbols = {'host': {'address': HOST_OUTPUT | 1},
                        'reserve': {'address': RESERVE | 1}}
        self.counter = self.total_instructions = 0
        self.trampoline_visits = []
        self.uc.mem_map(0xf00000, 0x73000)
        self.uc.mem_write(0xf00000, stock.read(0xcb1980, 0x7224c))
        for page in (INPUT_PAGE, OUTPUT_PAGE, RETURN):
            self.uc.mem_map(page, PAGE_BYTES)
        self.uc.mem_map(STACK & ~0xffff, 0x10000)
        self.uc.mem_map(0x391000, PAGE_BYTES)
        self.uc.mem_write(0x391000, stock.read(0x391000, PAGE_BYTES))
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.visits = Counter()
        self.requests = []
        self.waits = []
        self.release_after = None
        self.stop_after = None
        self.synthetic_consumer_advance = 0
        self.setup_pcm_route(stock)
        self.uc.mem_map(WAIT & ~0xfff, PAGE_BYTES)
        self.uc.mem_write(WAIT & ~0xfff, stock.read(WAIT & ~0xfff, PAGE_BYTES))
        self.uc.mem_write(WAIT, b'\x70\x47')

    def observe(self, uc, address, size, data):
        args = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]
        self.visits[address] += 1
        if address == REGISTER:
            stack = uc.reg_read(UC_ARM_REG_SP)
            extras = struct.unpack('<3I', uc.mem_read(stack, 12))
            self.requests.append({'register_args': args,
                                  'stack_arguments': [extras[0], hex(extras[1]), extras[2]]})
        super().observe(uc, address, size, data)
        if address == WAIT:
            self.waits.append({'argument': args[0], 'queued_bytes': self.queued()})
            if self.release_after == len(self.waits):
                write, read = self.offsets()
                uc.mem_write(CONTEXT+16, struct.pack('<I',
                    (read+self.synthetic_consumer_advance) % RING_BYTES))
            if self.stop_after == len(self.waits):
                # Bound this observation without adding a timeout to stock code.
                uc.emu_stop()

    def invoke(self, name, args, allow_wait_stop=False):
        self.counter = 0
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(self.symbols[name]['address'], RETURN,
                          timeout=1000000, count=100000)
        returned = self.uc.reg_read(UC_ARM_REG_PC) == RETURN
        if not returned and not (allow_wait_stop and
                                self.uc.reg_read(UC_ARM_REG_PC) == WAIT):
            raise ValueError('Stock call exceeded bounds outside the intended wait')
        return returned, self.uc.reg_read(UC_ARM_REG_R0)

    def put_pcm(self, pcm):
        if not 0 < len(pcm) <= PAGE_BYTES-32:
            raise ValueError('PCM input outside guarded page')
        source = INPUT_PAGE+PAGE_BYTES-len(pcm)
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(source, pcm)
        returned, status = self.invoke('host', (0, 0, source, len(pcm)))
        if not returned or status != 0:
            raise ValueError('Stock host callback changed return behavior')
        if bytes(self.uc.mem_read(source, len(pcm))) != pcm:
            raise ValueError('Stock writer changed input')
        self.verify_ring_guards()

    def reserve(self, allow_wait_stop=False):
        out = OUTPUT_PAGE+PAGE_BYTES-8
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        returned, _ = self.invoke('reserve', (out, out+4), allow_wait_stop)
        values = struct.unpack('<2I', self.uc.mem_read(out, 8)) if returned else None
        if not returned and bytes(self.uc.mem_read(out, 8)) != b'\xa5'*8:
            raise ValueError('Waiting reservation exposed a premature pointer')
        if bytes(self.uc.mem_read(out-32, 32)) != b'\xa5'*32:
            raise ValueError('Stock reservation changed leading guard')
        self.verify_ring_guards()
        return returned, values


def startup_case(stock, selector=1, initial_index=0, start_result=0, register_result=0):
    m = StockPcm(stock)
    m.configure(initial_index, active=False)
    m.policy[0x2554ca] = ('channel_selector', selector)
    m.policy[0x36b720] = ('channel_start', start_result)
    m.policy[REGISTER] = ('channel_register', register_result)
    chunk = struct.pack('<128h', *range(-64, 64))
    # The initialized stock producer starts at0x2800 queued bytes.
    for _ in range(39):
        m.put_pcm(chunk)
        if m.visits[START] or bytes(m.uc.mem_read(CONTEXT+4, 1)) != b'\0':
            raise ValueError('Stock producer started before its threshold')
    if m.queued() != 9984 or m.requests:
        raise ValueError('Pre-threshold stock queue/request differs')
    m.put_pcm(chunk)
    if m.queued() != 10240 or m.visits[START] != 1 or len(m.requests) != 1:
        raise ValueError('Stock producer did not request start at10240 bytes')
    channel = 5 if selector else 8
    request = m.requests[0]
    if request['register_args'] != [channel, 17, 6, CONTEXT+4]:
        raise ValueError('Stock start registration ABI differs')
    if request['stack_arguments'][0] != 1 or request['stack_arguments'][2] != 0:
        raise ValueError('Stock registration extra arguments differ')
    active = bytes(m.uc.mem_read(CONTEXT+4, 1)) == b'\x01'
    if active != (start_result == 0):
        raise ValueError('Active flag did not follow stock channel-start result')
    if active:
        output = []
        while m.queued(): output.append(m.read(3840))
        if b''.join(output) != chunk*40:
            raise ValueError('Starting the source changed queued PCM')
    elif m.read(256) != b'':
        raise ValueError('Failed-start channel exposed samples through reader')
    return {'selector': selector, 'channel': channel, 'initial_index': initial_index,
            'threshold_bytes': 10240, 'before_threshold_bytes': 9984,
            'logical_16k_mono_buffer_seconds': 10240/32000,
            'stock_start_calls': m.visits[START], 'request': request,
            'register_hook_result': register_result, 'start_hook_result': start_result,
            'active_flag': active, 'host_callback_return': 0,
            'reader_byte_identical_when_started': active,
            'physical_start_or_latency_verified': False, 'passed': True}


def reservation_case(stock, free, release_after=None, stop_after=None):
    m = StockPcm(stock)
    m.configure()
    m.uc.mem_write(CONTEXT+16, struct.pack('<I', free))
    m.release_after = release_after
    m.stop_after = stop_after
    m.synthetic_consumer_advance = 256
    returned, values = m.reserve(allow_wait_stop=stop_after is not None)
    if release_after is not None:
        if not returned or len(m.waits) != release_after:
            raise ValueError('Reservation did not recover after controlled consumer progress')
    elif stop_after is not None:
        if returned or len(m.waits) != stop_after:
            raise ValueError('Reservation unexpectedly escaped the observed wait')
    elif not returned or m.waits:
        raise ValueError('Sufficient-capacity reservation unexpectedly waited')
    if returned and values != (0x2d3f030, 5120):
        raise ValueError('Stock reservation pointer/capacity changed')
    return {'initial_free_bytes': free, 'returned': returned,
            'reservation': [hex(values[0]), values[1]] if values else None,
            'wait_calls': m.waits, 'observation_stop_after_waits': stop_after,
            'synthetic_consumer_advance_bytes': 256 if release_after else 0,
            'stock_timeout_added': False, 'passed': True}


def main():
    stock = NativeImage()
    starts = [startup_case(stock), startup_case(stock, selector=0),
              startup_case(stock, initial_index=RING_BYTES-64),
              startup_case(stock, start_result=8),
              startup_case(stock, register_result=8)]
    reservations = [reservation_case(stock, 5121),
                    reservation_case(stock, 5120, release_after=2),
                    reservation_case(stock, 4096, stop_after=3)]
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED, 'unicorn_version': unicorn.__version__,
              'cpu_model': 'ARM1176', 'startup_cases': starts,
              'reservation_cases': reservations, 'all_passed': True,
              'producer_preinitialized': True, 'cold_initialization_verified': False,
              'initialized_start_threshold_bytes': 10240,
              'reservation_minimum_free_bytes': 5121,
              'reservation_return_capacity_bytes': 5120,
              'stock_wait_argument': 160, 'wait_units_verified': False,
              'register_return_not_checked_before_start': True,
              'host_success_does_not_prove_channel_active': True,
              'repeated_wait_observed_without_consumer_progress': True,
              'inference': 'Native media callback should copy into a bounded queue and return; a serialized audio worker must handle blocking stock output, cancellation and channel policy. The actual worker/task API remains unverified.',
              'stock_reserve_trace': trace(stock, RESERVE, 150),
              'stock_start_trace': trace(stock, START, 150),
              'code_hashes': {hex(addr): hashlib.sha256(stock.read(addr, size)).hexdigest()
                              for addr, size in ((RESERVE, 180), (START, 172))},
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'device_io': False, 'audible_output': False,
              'hardware_mixer_or_speaker_verified': False,
              'live_os_scheduling_or_wait_duration_verified': False,
              'limitations': 'Exact stock callback/reserve/commit/start/reader execute with synthetic already-initialized producer/ring RAM. Selector, sequence/priority, busy, registration/start and wait functions are hooks; actual registration, hardware start and thread timing are not exercised. Wait recovery advances a synthetic consumer index, not an actual concurrent reader. Three waits with fixed indices are a bounded observation, not a hardware deadlock test. Cold initializer, producer lifecycle, navigation concurrency, actual worker/task API and speaker output remain unverified.'}
    path = ROOT/'evidence/firmware-analysis/native-pcm-flow-control-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'startup_cases': len(starts),
                      'reservation_cases': len(reservations), 'all_passed': True,
                      'device_io': False}))


if __name__ == '__main__':
    main()
