#!/usr/bin/env python3
"""ROOT guest: compiled source task -> original kernel mixer -> leased PCM.

    Only an offline copy of the exact MAIN is used. Three call-site branches and
three low interworking veneers are declared guest patches. Kernel creation,
registration, events, restore, and mixer FIFO post/get/wait are original.
Opaque memory services, generic mutexes, bookkeeping, audio timing/priority,
output activation, scratch and an explicit output consumer remain fixtures.
No installation, physical speaker, phone, native ownership or STOP_DONE claim.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import importlib.util, json, struct, hashlib, traceback
from datetime import datetime, timezone
from collections import Counter
import unicorn
from unicorn.arm_const import *

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED

PARENT = ROOT / 'staging/native-player-session-native-call/emulate_queue_call.py'
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
old = load(PARENT, 'mixer_handoff_queue_fixture')
sha, rel, dump, require = old.sha, old.rel, old.dump, old.require
ALL_TASKS, READY_TASKS = 0xF0908C, 0xF09090
POST, WAIT, RESTORE = 0x2FCF44, 0x2FD034, 0x358EC4
IDLE, DESCRIPTORS = 0x09400000, 0x09401800
CONTROLLER_STACK, IDLE_STACK = 0x09500000, 0x09505000
EXIT_LIST = 0x02D226B4
POOL, RECORD, MIXER = 0x034E3CF4, old.RECORD, 0x034E5378 + 8 * 0x130
DESCRIPTOR, BUFFER, SCRATCH = 0x09800020, 0x09801020, 0x09803F00
RING_BYTES, CAPACITY = 2048, 256
GP = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]

def thumb_bl(address, target):
    delta = target - address - 4
    require(delta % 2 == 0 and -(1 << 22) <= delta < (1 << 22), 'Thumb BL range')
    return struct.pack('<HH', 0xF000 | ((delta >> 12) & 0x7FF),
                       0xF800 | ((delta >> 1) & 0x7FF))

class Handoff(old.QueueCall):
    def __init__(self, stock, elf, build):
        self.ordinal = 0
        self.kernel_events, self.message_sends, self.message_receives = [], [], []
        self.entries, self.endpoints, self.patches, self.fixture_services = [], [], [], []
        self.full_returns, self.outer_returns, self.reader_entries, self.selector_entries = [], [], [], []
        self.pending_full = self.pending_outer = self.pending_get = None
        self.mixer_tcb = self.controller = self.idle = self.source_tcb = 0
        self.kernel_ready = False
        self.mixer_allocations = {}
        self.chunks = []
        super().__init__(stock, elf, build)
        self.map(0x034E3000, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.map(0x09800000, 0x5000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        for start, size in ((IDLE, 4096), (0x09401000, 4096), (CONTROLLER_STACK, 16384),
                            (IDLE_STACK, 16384), (0x014B3000, 4096),
                            (EXIT_LIST & ~4095, 4096), (0x09600000, 8192),
                            (0x09604000, 4096)):
            self.map(start, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.uc.mem_write(IDLE, bytes.fromhex('feffffea'))
        self.uc.mem_protect(IDLE, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.zones = [(a, n, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC if a == IDLE else p)
                      for a, n, p in self.zones]
        self.fixture(POOL - 32, b'\xa5' * 32, 'declared cold provider-pool leading canary')
        self.fixture(POOL + 10 * 576, b'\xa5' * 4, 'declared provider-pool trailing canary')
        self.fixture(0x09600000, b'\xa5' * 8192, 'declared opaque mixer-stack backing')
        self.fixture(0x09604000, b'\xa5' * 4096, 'declared opaque mixer FIFO backing')
        self.fixture(CONTROLLER_STACK, b'\xa5' * 16384, 'controller stack fixture')
        self.fixture(IDLE_STACK, b'\xa5' * 16384, 'idle stack fixture')
        source_stack = build['symbols']['source_stack']['value']
        self.fixture(source_stack, b'\xa5' * 16384, 'compiled resident source stack canary fixture')
        for address in (ALL_TASKS, READY_TASKS, 0xF09094, 0xF0909C):
            self.fixture(address, bytes(4), 'declared initial kernel list/IRQ/tick input')
        self.fixture(0xF071CC, b'\x01' + bytes(7), 'bounded kernel registry setup input')
        self.fixture(0xF2936C, struct.pack('<I', 0xB00D), 'external notice queue fixture identity')
        self.offsets = struct.unpack('<5I', self.uc.mem_read(build['symbols']['aas_offsets']['value'], 20))
        for address, target, veneer in (
                (0x2FA294, 'mh_selector_bridge', 0x6E8000),
                (0x2FA536, 'mcs_pull_bridge', 0x6E8010),
                (0x2FA572, 'mcs_pull_bridge', 0x6E8020)):
            expected_target = 0x2F9F2E if address == 0x2FA294 else 0x2F9CCA
            require(bytes(self.uc.mem_read(address, 4)) == thumb_bl(address, expected_target),
                    'original call-site opcode mismatch')
            target_address = build['symbols'][target]['value']
            veneer_bytes = bytes.fromhex('004b1847') + struct.pack('<I', target_address)
            for a, after, why in ((address, thumb_bl(address, veneer), 'guest call-site BL'),
                                  (veneer, veneer_bytes, 'guest Thumb LDR/BX to ARM veneer')):
                before = bytes(self.uc.mem_read(a, len(after)))
                self.uc.mem_write(a, after)
                self.patches.append(dict(address=a, before_hex=before.hex(), after_hex=after.hex(),
                                         reason=why, original_return_LR=address + 5,
                                         target_symbol=target, target_address=target_address))
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x1F)
        self.initial_ordinal = self.ordinal
        self.initial = {str(a): bytes(self.uc.mem_read(a, n)).hex()
                        for a, n, p in self.zones if not p & unicorn.UC_PROT_EXEC}
        self.RX_before = {str(a): hashlib.sha256(bytes(self.uc.mem_read(a, n))).hexdigest()
                          for a, n, p in self.zones if p & unicorn.UC_PROT_EXEC}
        self.kernel_ready = True

    def fixture(self, address, data, reason):
        super().fixture(address, data, reason)
        self.ordinal += 1
        self.fixtures[-1].update(ordinal=self.ordinal, event_type='declared_host_fixture')

    def snapshot(self):
        return dict(GP16=[self.uc.reg_read(r) for r in GP], CPSR=self.uc.reg_read(UC_ARM_REG_CPSR),
                    current_TCB=self.word(READY_TASKS), ordinal=self.ordinal, phase=self.phase)

    def store(self, uc, access, address, size, value, data):
        super().store(uc, access, address, size, value, data)
        self.ordinal += 1
        self.journal[-1].update(self.snapshot(), ordinal=self.ordinal, event_type='actual_CPU_store')

    def leases(self):
        guard = self.build['symbols']['aas_guard']['value']
        control = self.build['symbols']['aas_control']['value']
        return dict(borrow=self.word(guard + self.offsets[0]),
                    selected_session=self.word(guard + self.offsets[1]),
                    selected_instance=self.word(guard + self.offsets[2]),
                    media=self.word(control + self.offsets[3]),
                    callback=self.word(control + self.offsets[4]), current_TCB=self.word(READY_TASKS))

    def service(self, name, result=0):
        row = dict(name=name, before=self.snapshot(), args=self.regs())
        self.boundary_return(result)
        row['after'] = self.snapshot()
        self.fixture_services.append(row)

    def code(self, uc, address, size, data):
        self.instructions += 1
        self.visits[address] += 1
        self.last_instruction = (address, size, bool(uc.reg_read(UC_ARM_REG_CPSR) & 32),
                                 bytes(uc.mem_read(address, size)).hex())
        self.trace.append(hex(address)); self.trace = self.trace[-48:]
        if address in (old.RETURN, IDLE):
            self.endpoints.append(dict(address=address, **self.snapshot()))
            uc.emu_stop(); return
        if self.pending_lower and address == self.pending_lower['return_PC']:
            require(uc.reg_read(UC_ARM_REG_SP) == self.pending_lower['entry_SP'], 'queue writer full SP return')
            self.lower_returns.append(dict(self.pending_lower, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0)))
            self.pending_lower = None
        if address == 0x277C6A:
            self.lower_calls.append(self.args())
            self.pending_lower = dict(entry_SP=uc.reg_read(UC_ARM_REG_SP),
                                      return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1, args=self.args())
        if self.pending_full and address == self.pending_full['return_PC']:
            p = self.pending_full; view = self.leases()
            require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'] + 64, 'original 64-byte full-pull frame not returned')
            require(view['borrow'] and view['media'] == view['callback'] == 1, 'leases gone before original full return')
            self.full_returns.append(dict(p, returned=self.snapshot(), return_leases=view,
                                          r0=uc.reg_read(UC_ARM_REG_R0)))
            self.pending_full = None
        if self.pending_outer and address == self.pending_outer['return_PC']:
            p = self.pending_outer; view = self.leases()
            require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'outer wrapper did not preserve original mixer SP')
            require(view['borrow'] == view['media'] == view['callback'] == 0, 'leases remain after wrapper return')
            before, after = p['ring_before'], self.word(DESCRIPTOR + 16)
            count = (after - before) % RING_BYTES
            require(count <= CAPACITY, 'unbounded pull output')
            first = min(count, BUFFER + RING_BYTES - before)
            raw = bytes(uc.mem_read(before, first))
            if first < count: raw += bytes(uc.mem_read(BUFFER, count - first))
            self.chunks.append(raw)
            self.outer_returns.append(dict(p, returned=self.snapshot(), return_leases=view,
                bytes=count, PCM_hex=raw.hex(), full_native_return_count=len(self.full_returns)))
            self.pending_outer = None
        if address == 0x2F9CCE:
            require(self.pending_full is None, 'nested native full pull')
            view = self.leases()
            require(view['borrow'] and view['media'] == view['callback'] == 1, 'native entry without leases')
            self.pending_full = dict(entry_PC=address, entry_SP=uc.reg_read(UC_ARM_REG_SP),
                                     return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1,
                                     entry=self.snapshot(), entry_leases=view)
        symbols = self.build['symbols']
        if address in (symbols['memory_output_read']['value'], symbols['continuous_media_read']['value']):
            view = self.leases()
            require(view['borrow'] and view['media'] == view['callback'] == 1, 'reader lacks full-frame leases')
            require(self.word(READY_TASKS) == self.mixer_tcb, 'reader actor differs from original mixer TCB')
            self.reader_entries.append(dict(PC=address, state=self.snapshot(), leases=view))
        if address in (0x2FA536, 0x2FA572):
            require(self.pending_outer is None and self.word(READY_TASKS) == self.mixer_tcb,
                    'outer pull not original mixer actor')
            self.pending_outer = dict(call_site=address, return_PC=address + 4,
                                      entry_SP=uc.reg_read(UC_ARM_REG_SP), ring_before=self.word(DESCRIPTOR + 16),
                                      entry=self.snapshot(), full_before=len(self.full_returns))
            self.fixture(SCRATCH - 32, b'\xa5' * (CAPACITY + 64), 'explicit per-pull scratch boundary reseed')
        if address == symbols['mh_selector_bridge']['value']:
            require(self.word(READY_TASKS) == self.mixer_tcb, 'selector bridge not on original mixer')
            require(uc.reg_read(UC_ARM_REG_LR) == 0x2FA299, 'selector veneer changed original LR')
            self.selector_entries.append(dict(state=self.snapshot(), leases=self.leases()))
        if address in (POST, WAIT, RESTORE, 0x358BF8, 0x2FBBBE,
                       symbols['mh_source_entry']['value'], 0x2FA0DC):
            row = dict(PC=address, state=self.snapshot(), args=self.regs())
            self.entries.append(row)
            if address == POST: self.kernel_events.append(row)
        if address == 0x3B9C1E:
            self.mixer_tcb = self.word(MIXER + 0x78)
            require(self.mixer_tcb == (0x09600000 + 8192 - 108) & ~7, 'mixer TCB not built on original descriptor stack')
        if address == 0x37BCE4:
            target, pointer = self.regs()[:2]
            if target == 0xB00D:
                self.service('external notice queue capture', 0); return
            if target == 0 and uc.reg_read(UC_ARM_REG_LR) == 0x1D8C8D:
                require(self.word(READY_TASKS) == self.mixer_tcb and
                        0x09600000 <= pointer and pointer + 56 <= 0x09602000 and
                        struct.unpack('<H', uc.mem_read(pointer, 2))[0] == 2,
                        'hardware reset transport fixture outside exact original request')
                packet = bytes(uc.mem_read(pointer, 56))
                self.service('explicit hardware reset request transport; backend queue uninitialized; no driver/ack', 0)
                self.fixture_services[-1]['original_request_hex'] = packet.hex()
                return
            require(target == self.mixer_tcb and target, 'unexpected original message queue target')
            require((uc.mem_read(target + 0x15, 1)[0] + 1) % 20 != uc.mem_read(target + 0x12, 1)[0], 'bounded FIFO admission')
            self.message_sends.append(dict(state=self.snapshot(), bytes_hex=bytes(uc.mem_read(pointer, 12)).hex()))
        if address == 0x37BC00:
            require(self.word(READY_TASKS) == self.mixer_tcb, 'FIFO getter not original scheduled actor')
            self.pending_get = uc.reg_read(UC_ARM_REG_R0)
        if address == 0x37BC82:
            require(self.pending_get is not None, 'message result lacks actual getter entry')
            if uc.reg_read(UC_ARM_REG_R0) == 1:
                self.message_receives.append(dict(state=self.snapshot(), bytes_hex=bytes(uc.mem_read(self.pending_get, 12)).hex()))
            self.pending_get = None
        args = self.regs()
        if address in (0x3009A0, 0x3008B0):
            if address == 0x3009A0: self.mutex[args[0]] += 1
            else:
                require(self.mutex[args[0]] > 0, 'generic mutex fixture unbalanced')
                self.mutex[args[0]] -= 1
            self.service('generic mutex fixture', 0); return
        if address == 0x38853C:
            length, kind, out = args[:3]
            if out == 0 and kind == 2 and length in (8192, 240):
                require(len(self.mixer_allocations) < 2, 'unexpected additional mixer backing')
                handle = 0xD1100001 + len(self.mixer_allocations)
                pointer = 0x09600000 if length == 8192 else 0x09604000
                self.mixer_allocations[handle] = dict(pointer=pointer, size=length, queries=0)
                self.service('opaque mixer backing allocation', handle); return
            require(0 < length < 4000 and kind in (2, 3) and out, 'opaque node/selector allocation shape')
            require(self.next_handle <= 16, 'opaque backing fixture exhausted')
            handle = 0xD0000000 + self.next_handle
            pointer = old.HEAP + (self.next_handle - 1) * 4096 + 32
            self.next_handle += 1
            self.handles[handle] = dict(pointer=pointer, size=length, kind=kind, queries=0, released=False)
            self.fixture(pointer - 32, b'\xa5' * (length + 64), 'opaque node/selector backing and guards')
            self.fixture(out, struct.pack('<I', handle), 'opaque allocator output cell fixture')
            self.service('opaque node/selector allocation', 0); return
        if address == 0x388804:
            handle = self.handles.get(args[0]) or self.mixer_allocations.get(args[0])
            require(handle and not handle.get('released'), 'unknown/released opaque handle')
            handle['queries'] += 1
            self.service('opaque handle query', handle['pointer']); return
        if address == 0x388B22:
            require(args[0] in self.handles, 'unknown opaque query completion')
            # Its original one-instruction BX LR runs; no lifetime inference.
        if address == 0x3887A2:
            handle = self.word(args[0]); require(handle in self.handles, 'unknown release handle')
            require(not self.handles[handle]['released'], 'duplicate opaque release')
            self.handles[handle]['released'] = True
            self.fixture(args[0], bytes(4), 'opaque release output fixture')
            self.service('opaque release', 0); return
        if address == 0x38756A:
            self.fixture(args[0], 'Mixer8\0'.encode('utf-16le'), 'opaque mixer naming service fixture')
            self.service('opaque naming service', 0); return
        if address in (0xF5030, 0x46CC7A, 0x2F9C52, 0x3B9674):
            self.service({0xF5030:'task construction bookkeeping', 0x46CC7A:'external audio timing hint',
                          0x2F9C52:'audio pull priority policy', 0x3B9674:'audio diagnostic policy'}[address], 0)
            return

    def invoke_kernel(self, entry, args=(), phase=None):
        self.phase = phase or str(entry)
        if isinstance(entry, str): entry = self.build['symbols'][entry]['value']
        stack = self.word(READY_TASKS) if self.controller else old.STACK
        # Bounded controller/idle call entry; never Python actor context restore.
        self.uc.reg_write(UC_ARM_REG_SP, stack)
        self.uc.reg_write(UC_ARM_REG_LR, old.RETURN)
        for reg, value in zip(GP[:4], args): self.uc.reg_write(reg, value)
        self.uc.emu_start(entry, old.RETURN, count=1500000, timeout=15000000)
        require(self.uc.reg_read(UC_ARM_REG_PC) in (old.RETURN, IDLE), 'kernel call missed return/idle endpoint')
        return self.uc.reg_read(UC_ARM_REG_R0)

    def park(self):
        require(self.word(READY_TASKS) == self.controller, 'park requires controller')
        self.invoke_kernel(WAIT | 1, phase='original controller wait schedules ready actors')
        require(self.word(READY_TASKS) == self.idle, 'actors did not block and yield to idle')
        self.invoke_kernel(POST, (self.controller, 1), phase='original event wakes controller')
        require(self.word(READY_TASKS) == self.controller, 'controller not restored through original kernel')

    def boot(self):
        self.invoke_kernel(0x3008A1, (EXIT_LIST + 4,), phase='original kernel exit-list mutex initialization')
        for i, (entry, top, priority) in enumerate(((IDLE, IDLE_STACK + 16384, 240),
                                                  (IDLE + 4, CONTROLLER_STACK + 16384, 16))):
            desc = DESCRIPTORS + 32 * i
            self.fixture(desc, struct.pack('<5I', entry, 0, top, priority << 16, 0), 'declared controller/idle task descriptor')
            tcb = self.invoke_kernel(0x358BF9, (desc,), phase='original controller/idle TCB construction')
            if i == 0: self.idle = tcb
            else: self.controller = tcb
        for address, value in ((READY_TASKS, self.controller), (self.controller, self.idle), (self.idle, 0)):
            self.fixture(address, struct.pack('<I', value), 'initial controller/idle ready-list fixture')
        self.fixture(self.controller + 22, b'\x01', 'initial ready controller state fixture')
        self.fixture(self.idle + 22, b'\x01', 'initial ready idle state fixture')
        self.source_tcb = self.invoke_kernel('mh_boot_source', phase='compiled bootstrap creates and posts source task')
        require(self.source_tcb and self.mixer_tcb, 'source did not construct original mixer')
        state = self.status()
        require(state[30] == state[35] == self.source_tcb and state[31] == state[32] == 1,
                'source initialization did not run on constructed source task')
        require(state[33] == state[34] == 0 and state[36] == self.mixer_tcb and state[40] == 1,
                'source to mixer capability handoff failed')
        require(state[50] == 0, 'mixer preempted before source handoff')
        self.park()
        state = self.status()
        require(state[0] and state[42] == state[43] == state[52] == 1 and state[44] == 0,
                'original scheduled selector did not establish native binding')
        self.fixture(DESCRIPTOR - 32, b'\xa5' * (36 + 64), 'declared output descriptor boundaries')
        self.fixture(BUFFER - 32, b'\xa5' * (RING_BYTES + 64), 'declared hardware output ring boundaries')
        initial = BUFFER + RING_BYTES - 64
        self.fixture(DESCRIPTOR, struct.pack('<9I', 0, BUFFER, RING_BYTES, initial, initial, 0, 0, 0, 0), 'empty output ring fixture')
        for address, value in ((MIXER, DESCRIPTOR), (MIXER + 4, CAPACITY), (MIXER + 0xB4, SCRATCH)):
            self.fixture(address, struct.pack('<I', value), 'explicit hardware buffer/capacity fixture')
        self.fixture(MIXER + 0x7F, b'\0', 'declared raw memcpy output mode')
        self.fixture(MIXER + 0x7E, b'\0', 'declared no hardware seek pending')
        self.fixture(MIXER + 0x84, b'\1', 'declared hardware activation; no message14 or DMA')
        self.fixture(SCRATCH - 32, b'\xa5' * (CAPACITY + 64), 'declared scratch boundaries')

    def status(self):
        self.invoke_kernel('mh_status', (old.RESULT,), phase='compiled status read on controller')
        return list(struct.unpack('<55I', self.uc.mem_read(old.RESULT, 220)))

    def command(self, number):
        cursor = len(self.chunks)
        require(self.invoke_kernel('mh_request_command', (number,), phase='request source command ' + str(number)) == 0,
                'compiled source command rejected')
        state = self.status()
        require(state[45] == number and state[46] == 0, 'source command failed before yielding')
        expected = bytes(self.uc.mem_read(self.build['symbols']['input_pcm']['value'], 512))
        self.park()
        actual = b''.join(self.chunks[cursor:])
        if number <= 4:
            require(len(actual) == 1792 and actual[:512] == expected and actual[512:] == bytes(1280),
                    'scheduled mixer lost PCM or failed continuous underrun silence for command ' + str(number))
        else: require(actual == b'', 'revoked/stopped source continued publishing PCM')
        state = self.status()
        require(state[2] == state[6] == state[7] == state[8] == state[12] == 0, 'retained lease or invented completion')
        self.fixture(DESCRIPTOR + 12, struct.pack('<I', self.word(DESCRIPTOR + 16)),
                     'explicit output consumer advances only after full kernel actor returns; no DMA claim')
        return dict(command=number, state=state, PCM_hex=actual.hex(), bytes=len(actual),
                    source_PCM_bytes=512 if number <= 4 else 0,
                    original_self_posted_underrun_silence_bytes=1280 if number <= 4 else 0)

    def replay(self):
        zones = {int(a): bytearray.fromhex(raw) for a, raw in self.initial.items()}
        events = sorted((e for e in self.journal + self.fixtures if e['ordinal'] > self.initial_ordinal),
                        key=lambda e: e['ordinal'])
        require(len({e['ordinal'] for e in events}) == len(events), 'duplicate event ordinal')
        for e in events:
            address = int(e['address'], 16); before = bytes.fromhex(e['before_hex'])
            candidates = [a for a, b in zones.items() if a <= address and address + len(before) <= a + len(b)]
            require(len(candidates) == 1, 'store outside one declared RW zone')
            a = candidates[0]; b = zones[a]; offset = address - a
            require(bytes(b[offset:offset + len(before)]) == before, 'mixed-journal preimage differs')
            after = ((e['value'] & ((1 << (8 * e['size'])) - 1)).to_bytes(e['size'], 'little')
                     if e['event_type'] == 'actual_CPU_store' else bytes.fromhex(e['after_hex']))
            b[offset:offset + len(before)] = after
        for a, b in zones.items(): require(bytes(self.uc.mem_read(a, len(b))) == bytes(b), 'whole-zone replay differs ' + hex(a))
        return dict(passed=True, zones=len(zones), joint_events=len(events), CPU_stores=len(self.journal))

    def result(self, name, commands):
        state = self.status()
        require(self.pending_full is self.pending_outer is self.pending_lower is self.pending_get is None,
                'unfinished original frame/message')
        require(not any(self.mutex.values()), 'retained generic mutex fixture')
        require([e['bytes_hex'] for e in self.message_sends] == [e['bytes_hex'] for e in self.message_receives],
                'original FIFO copy/order differs')
        require(self.word(MIXER + 0x78) == self.mixer_tcb, 'original mixer TCB replaced')
        for a, n, p in self.zones:
            if p & unicorn.UC_PROT_EXEC:
                require(hashlib.sha256(bytes(self.uc.mem_read(a, n))).hexdigest() == self.RX_before[str(a)], 'RX changed during guest')
        for a in (CONTROLLER_STACK, IDLE_STACK, self.build['symbols']['source_stack']['value'], 0x09600000):
            require(bytes(self.uc.mem_read(a, 64)) == b'\xa5' * 64, 'task stack crossed canary')
        require(bytes(self.uc.mem_read(0x09604000 + 240, 4096 - 240)) == b'\xa5' * (4096 - 240), 'FIFO exceeded opaque allocation')
        witness_before = bytes(self.uc.mem_read(old.RESULT + 256, 128))
        witness = self.invoke_kernel('mcs_native_ownership_snapshot', (0, 1, 0x1352, old.RESULT + 256), phase='uncertified ownership witness')
        require(witness == (-200 & 0xFFFFFFFF) and bytes(self.uc.mem_read(old.RESULT + 256, 128)) == witness_before,
                'uncertified witness changed')
        return dict(name=name, passed=True, status=state, commands=commands,
            source_TCB=self.source_tcb, mixer_TCB=self.mixer_tcb, controller_TCB=self.controller,
            original_scheduled_actor_entries=self.entries, original_kernel_events=self.kernel_events,
            selector_bridge_entries=self.selector_entries, full_native_returns=self.full_returns,
            original_mixer_call_site_returns=self.outer_returns, compiled_reader_entries=self.reader_entries,
            original_message_sends=self.message_sends, original_message_receives=self.message_receives,
            terminal_register_snapshots=self.endpoints, patches=self.patches,
            declared_service_calls=self.fixture_services, opaque_handles=self.handles,
            original_queue_calls=self.lower_calls, original_queue_returns=self.lower_returns,
            native_visits={hex(a): n for a, n in self.visits.items()}, instructions=self.instructions,
            initial_ordinal=self.initial_ordinal, initial_whole_RW_zones=self.initial,
            final_whole_RW_zones={str(a): bytes(self.uc.mem_read(a, n)).hex() for a, n, p in self.zones if not p & unicorn.UC_PROT_EXEC},
            zones=[dict(start=a, size=n, protection=p) for a, n, p in self.zones],
            CPU_store_journal=self.journal, declared_fixture_mutations=self.fixtures,
            unchanged_after_declared_patches_RX_sha256=self.RX_before, replay=self.replay(),
            native_ownership_snapshot=-200, native_STOP_DONE=False,
            physical_speaker_phone_App_installation_or_complete_player_verified=False, device_io=False)

def main():
    require(unicorn.__version__ == '2.1.4', 'requires isolated Unicorn 2.1.4')
    runtime = BASE / 'guest-v4'; runtime.mkdir(exist_ok=False)
    build = json.loads((BASE / 'build-v4.json').read_text())
    source = dict(build['source_sha256']); source.update(build['generated_sha256'])
    for path in (Path(__file__).resolve(), PARENT, ROOT / 'scripts/analyze_native_sections.py',
                 BASE / 'build-v4.json', ROOT / build['ELF'],
                 ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',
                 ROOT / 'evidence/firmware-analysis/main_02bd.bin'):
        source[rel(path)] = sha(path)
    require(source['evidence/firmware-analysis/main_02bd.bin'] == EXPECTED, 'wrong MAIN')
    require(source[build['ELF']] == build['ELF_sha256'], 'wrong ELF')
    for path, digest in source.items(): require(sha(ROOT / path) == digest, 'changed input ' + path)
    dump(runtime / 'inputs-at-run.json', source)
    (runtime / 'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    mod = load(ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py', 'mixer_handoff_elf')
    elf = mod.ELF32(ROOT / build['ELF']); stock = NativeImage(); cases = []; m = None
    try:
        for name, commands in (('normal_reuse_reselection_reset', (1, 2, 3, 4)),
                               ('Stop_revokes_new_original_pulls', (1, 5)),
                               ('original_profile_rewrite_revokes_mixer', (1, 6))):
            m = Handoff(stock, elf, build); m.boot()
            results = [m.command(c) for c in commands]
            row = m.result(name, results); path = runtime / (name + '.json'); dump(path, row)
            cases.append(dict(name=name, path=rel(path), sha256=sha(path), passed=True))
            print(json.dumps(dict(case=name, full_returns=len(m.full_returns), bytes=sum(r['bytes'] for r in results))), flush=True)
            m = None
        proof = dict(all_passed=True, source_sha256=source, cases=cases,
                     case_count=len(cases), updated_utc=datetime.now(timezone.utc).isoformat(),
                     actual_original_kernel_source_and_mixer_handoff=True,
                     three_guest_only_original_call_site_branches=True,
                     physical_speaker_phone_App_installation_or_complete_player_verified=False,
                     native_heap_mutex_exclusive_or_STOP_DONE_verified=False, device_io=False)
        dump(BASE / 'mixer-handoff-v4-proof.json', proof)
        print(json.dumps(dict(all_passed=True, proof=rel(BASE / 'mixer-handoff-v4-proof.json'))), flush=True)
    except BaseException as error:
        row = dict(all_passed=False, error=str(error), traceback=traceback.format_exc(),
                   source_sha256=source, cases_completed=cases, device_io=False)
        if m:
            row.update(phase=m.phase, trace=m.trace, registers=m.snapshot(),
                       initial_ordinal=m.initial_ordinal, initial_whole_RW_zones=m.initial,
                       final_whole_RW_zones={str(a): bytes(m.uc.mem_read(a, n)).hex() for a, n, p in m.zones if not p & unicorn.UC_PROT_EXEC},
                       CPU_store_journal=m.journal, declared_fixture_mutations=m.fixtures,
                       service_calls=m.fixture_services, original_entries=m.entries,
                       selector_entries=m.selector_entries, full_returns=m.full_returns,
                       outer_returns=m.outer_returns, patches=m.patches)
        dump(runtime / 'terminal-failure.json', row)
        raise

if __name__ == '__main__': main()
