#!/usr/bin/env python3
"""Execute the stock OS20 create prefix on a NEW, explicit software heap.

Not a complete boot: current TCB, storage and MMU table bytes are declared
fixtures. Original private/public initialization, locks, allocation, page pops
and software mapping run unpatched. Stop BEFORE the next task-object call.
"""
import gzip
import hashlib
import json
import struct
import sys
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *

OUT = ROOT / 'staging/native-os20-allocator-v1'
PRIVATE, PUBLIC, WORK, LIST = 0x18301000, 0x18310000, 0x03a7f170, 0x02d226b4
STACK, RETURN, INPUT, CURRENT = 0x09010000, 0x09000000, 0x09030000, 0x09040000
L1, L2 = 0x03e00000, 0x03f00000
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]
TRACKED = {0x395440, 0x39544c, 0x2dc954, 0x38850a, 0x388804,
           0x38806c, 0x221d34, 0x3009a0, 0x3008b0}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def compressed(path, data):
    with path.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0) as zipped:
            zipped.write(json.dumps(data, separators=(',', ':')).encode())


class HeapCase:
    def __init__(self, native, name, private_bytes=32768, public_bytes=65536):
        self.native, self.name = native, name
        self.private_bytes, self.public_bytes = private_bytes, public_bytes
        self.u = u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.decoders = {False: Cs(CS_ARCH_ARM, CS_MODE_ARM),
                         True: Cs(CS_ARCH_ARM, CS_MODE_THUMB)}
        copy = next(row for row in native.copies if row['runtime_start'] == 0x50000)
        self.rom_size = (copy['size'] + 4095) & ~4095
        u.mem_map(0x50000, self.rom_size, UC_PROT_READ | UC_PROT_EXEC)
        u.mem_write(0x50000, native.read(0x50000, copy['size']))
        self.zones = []

        def zone(name, start, length, data, original_zero=False):
            assert start % 4096 == 0 and length % 4096 == 0 and len(data) == length
            if original_zero:
                assert any(r['runtime_start'] <= start and start + length <= r['runtime_end']
                           for r in native.zeros), name
            u.mem_map(start, length, UC_PROT_READ | UC_PROT_WRITE)
            u.mem_write(start, data)
            self.zones.append(dict(name=name, start=start, size=length,
                                   original_startup_zero=original_zero))

        data = next(row for row in native.copies if row['runtime_start'] == 0xf00000)
        size = (data['size'] + 4095) & ~4095
        zone('startup_data', 0xf00000, size, native.read(data['load_start'], data['size']) +
             bytes(size - data['size']))
        zone('WORK_page', WORK & ~4095, 4096, bytes(4096), True)
        zone('exit_list_page', LIST & ~4095, 4096, bytes(4096), True)
        zone('stack', STACK, 65536, b'\xa5' * 65536)
        zone('current_TCB_fixture', CURRENT, 4096, bytes(4096))
        zone('input_descriptors', INPUT, 4096, b'\xa5' * 4096)
        zone('private_extent_and_guards', PRIVATE - 4096, private_bytes + 8192,
             b'\xa5' * 4096 + b'\xcc' * private_bytes + b'\xa5' * 4096)
        zone('public_extent_and_guards', PUBLIC - 4096, 65536 + 8192,
             b'\xa5' * 4096 + b'\xcc' * 65536 + b'\xa5' * 4096)
        zone('L1_fixture', L1, 16384, bytes(16384))
        zone('L2_fixture', L2, 4096, b'\xa5' * 4096)
        u.mem_map(RETURN, 4096, UC_PROT_READ | UC_PROT_EXEC)
        u.mem_write(RETURN, bytes.fromhex('1eff2fe1'))
        u.mem_write(0xf09090, struct.pack('<I', CURRENT))
        u.mem_write(0xf09094, bytes(4))
        u.mem_write(INPUT, struct.pack('<2I', PRIVATE, private_bytes))
        u.mem_write(INPUT + 16, struct.pack('<2I', PUBLIC, public_bytes))
        u.mem_write(L1 + (PUBLIC >> 20) * 4, struct.pack('<I', L2 | 1))
        # Explicit pre-existing software descriptors, not real boot tables.
        for address in range(PUBLIC, PUBLIC + 65536, 4096):
            u.mem_write(L2 + ((address & 0xfffff) >> 12) * 4,
                        struct.pack('<I', (2 << 30) | 0x150))
        self.before = {r['name']: bytes(u.mem_read(r['start'], r['size'])).hex()
                       for r in self.zones}
        self.rx_sha = hashlib.sha256(bytes(u.mem_read(0x50000, self.rom_size))).hexdigest()
        self.stores, self.trace, self.host_calls, self.native_calls, self.open_calls = [], [], [], [], []
        self.visits, self.phase, self.done, self.boundary = Counter(), '', False, None
        self.sp = STACK + 65536 - 256
        self.sctlr = u.reg_read(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 0))
        assert not self.sctlr & 1, 'Software test only; hardware translations not modeled'
        u.hook_add(UC_HOOK_CODE, self.code)
        u.hook_add(UC_HOOK_MEM_WRITE, self.store)

    def snap(self):
        return dict(GP16=[self.u.reg_read(r) for r in REGS],
                    CPSR=self.u.reg_read(UC_ARM_REG_CPSR))

    def code(self, u, address, size, unused):
        while self.open_calls and self.open_calls[-1]['return_PC'] == address:
            row = self.open_calls.pop()
            row['after'] = self.snap()
            b, a = row['before'], row['after']
            assert b['GP16'][4:12] == a['GP16'][4:12], hex(row['entry'])
            assert b['GP16'][13] == a['GP16'][13], hex(row['entry'])
            assert (b['CPSR'] ^ a['CPSR']) & 0xdf == 0, hex(row['entry'])
            row['full_ABI_return'] = True
            self.native_calls.append(row)
        if address == RETURN:
            self.done = True
            u.emu_stop()
            return
        # OS20 create has completed both allocations; next object constructor
        # semantics have not yet been established. Do not pretend a return.
        if address == 0x521e90:
            self.boundary = dict(kind='before_original_task_object_constructor',
                                 PC=address, state=self.snap(), original_call_not_executed=True)
            u.emu_stop()
            return
        if address == 0x23d6e8:
            self.boundary = dict(kind='before_original_diagnostic', PC=address,
                                 state=self.snap(), original_diagnostic_not_executed=True)
            u.emu_stop()
            return
        assert 0x50000 <= address and address + size <= 0x50000 + self.rom_size
        original = self.native.read(address, size)
        assert bytes(u.mem_read(address, size)) == original, hex(address)
        assert len(self.trace) < 30000
        self.visits[address] += 1
        state = self.snap()
        self.trace.append(dict(PC=address, opcode_hex=original.hex(), size=size,
                               phase=self.phase, **state))
        if address in TRACKED:
            self.open_calls.append(dict(entry=address, before=state,
                                        return_PC=state['GP16'][14] & ~1,
                                        phase=self.phase, full_ABI_return=False))

    def store(self, u, access, address, size, value, unused):
        zone = next((r for r in self.zones if r['start'] <= address and
                     address + size <= r['start'] + r['size']), None)
        assert zone and size in (1, 2, 4), hex(address)
        assert zone['name'] != 'input_descriptors', 'Original extent inputs must remain unchanged'
        pc, cpsr = u.reg_read(UC_ARM_REG_PC), u.reg_read(UC_ARM_REG_CPSR)
        md = self.decoders[bool(cpsr & 32)]
        instruction = next(md.disasm(self.native.read(pc, 4), pc, count=1))
        assert instruction.mnemonic.startswith(('str', 'stm', 'push', 'swp')), hex(pc)
        self.stores.append(dict(zone=zone['name'], address=address, size=size,
                                value=value & ((1 << (size * 8)) - 1), PC=pc,
                                opcode_hex=instruction.bytes.hex(),
                                instruction=instruction.mnemonic + ' ' + instruction.op_str,
                                before_hex=bytes(u.mem_read(address, size)).hex(),
                                phase=self.phase, **self.snap()))

    def call(self, phase, entry, args):
        assert not self.open_calls
        self.phase, self.done, self.boundary = phase, False, None
        self.u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        for index, reg in enumerate(REGS[:13]):
            self.u.reg_write(reg, 0x13520000 + index)
        for reg, value in zip(REGS[:4], args[:4]):
            self.u.reg_write(reg, value)
        if len(args) > 4:
            # Explicit caller stack argument input, journal separately.
            old = bytes(self.u.mem_read(self.sp, 4))
            self.u.mem_write(self.sp, struct.pack('<I', args[4]))
            self.host_calls.append(dict(kind='caller_stack_arg5_input', address=self.sp,
                                        before_hex=old.hex(), after_hex=struct.pack('<I', args[4]).hex()))
        self.u.reg_write(UC_ARM_REG_SP, self.sp)
        self.u.reg_write(UC_ARM_REG_LR, RETURN | 1)
        before = self.snap()
        self.u.emu_start(entry | 1, 0, count=30000, timeout=5_000_000)
        after = self.snap()
        assert self.done or self.boundary, ('Unclosed observation', hex(after['GP16'][15]))
        if self.done:
            assert before['GP16'][4:12] == after['GP16'][4:12]
            assert before['GP16'][13] == after['GP16'][13]
            assert (before['CPSR'] ^ after['CPSR']) & 0xdf == 0
        self.host_calls.append(dict(phase=phase, entry=entry, args=args, before=before,
                                    after=after, full_ABI_return=self.done, boundary=self.boundary))

    def run(self):
        self.call('original_exit_list_constructor', 0x3cc57c, [LIST])
        assert self.done
        self.call('new_original_heap_constructor', 0x388b6c,
                  [INPUT, 1, INPUT + 16, int(self.public_bytes != 0)])
        if self.boundary:
            assert self.name == 'private_prefix_only_exhausts_at_constructor'
            assert self.boundary['state']['GP16'][14] == 0x388085
        else:
            assert self.done
            assert struct.unpack('<I', self.u.mem_read(PRIVATE, 4))[0] == 27
            assert struct.unpack('<I', self.u.mem_read(WORK + 0x18, 4))[0] == PRIVATE
            assert struct.unpack('<I', self.u.mem_read(CURRENT + 32, 4))[0] == 0
            self.call('original_OS20_create_prefix', 0x521e5e,
                      [RETURN + 0x101, 0x13520001, 4096, 0, 0])
            assert self.boundary and not self.done
            if self.public_bytes:
                assert self.boundary['PC'] == 0x521e90
                allocs = [r for r in self.native_calls if r['entry'] in (0x395440, 0x39544c)]
                assert [r['entry'] for r in allocs] == [0x395440, 0x39544c]
                descriptor, workspace = [r['after']['GP16'][0] for r in allocs]
                assert PUBLIC <= descriptor and descriptor + 100 <= PUBLIC + self.public_bytes
                assert PUBLIC <= workspace and workspace + 4248 <= PUBLIC + self.public_bytes
                assert descriptor % 8 == workspace % 8 == 0
                assert descriptor + 100 <= workspace or workspace + 4248 <= descriptor
                assert bytes(self.u.mem_read(descriptor, 100)) == bytes(100)
                assert bytes(self.u.mem_read(workspace, 4248)) == b'\xcc' * 4248
                assert struct.unpack('<I', self.u.mem_read(CURRENT + 32, 4))[0] == 0
                self.payloads = dict(descriptor=descriptor, descriptor_bytes=100,
                                     zeroed_descriptor=True, workspace=workspace,
                                     workspace_bytes=4248, workspace_not_zeroed=True)
            else:
                assert self.boundary['state']['GP16'][14] == 0x388501
        self.final = {r['name']: bytes(self.u.mem_read(r['start'], r['size'])).hex()
                      for r in self.zones}
        # Whole-zone replay includes only original CPU stores and the caller's
        # explicitly recorded arg5 input at the moment its phase begins.
        for row in self.zones:
            expected = bytearray.fromhex(self.before[row['name']])
            argument_applied = False
            for store in self.stores:
                if store['zone'] != row['name']:
                    continue
                if row['name'] == 'stack' and store['phase'] == 'original_OS20_create_prefix' and not argument_applied:
                    argument = next(x for x in self.host_calls if x.get('kind') == 'caller_stack_arg5_input')
                    offset = argument['address'] - row['start']
                    assert expected[offset:offset + 4].hex() == argument['before_hex']
                    expected[offset:offset + 4] = bytes.fromhex(argument['after_hex'])
                    argument_applied = True
                offset = store['address'] - row['start']
                assert expected[offset:offset + store['size']].hex() == store['before_hex']
                expected[offset:offset + store['size']] = store['value'].to_bytes(store['size'], 'little')
            assert expected.hex() == self.final[row['name']], row['name']
        for base, length in [(PRIVATE, self.private_bytes), (PUBLIC, 65536)]:
            assert bytes(self.u.mem_read(base - 4096, 4096)) == b'\xa5' * 4096
            assert bytes(self.u.mem_read(base + length, 4096)) == b'\xa5' * 4096
        assert hashlib.sha256(bytes(self.u.mem_read(0x50000, self.rom_size))).hexdigest() == self.rx_sha
        return dict(all_passed=True, name=self.name, input_private_bytes=self.private_bytes,
                    input_public_bytes=self.public_bytes, declared_synthetic_current_TCB=CURRENT,
                    current_TCB_not_constructed_by_kernel=True, model_SCTLR=self.sctlr,
                    MMU_translation_disabled=True, table_bytes_not_captured_from_hardware=True,
                    original_constructor_calls=self.host_calls, native_full_returns=self.native_calls,
                    unreturned_native_frames=self.open_calls, boundary=self.boundary,
                    payloads=getattr(self, 'payloads', None), zones=self.zones,
                    whole_zones_before=self.before, whole_zones_after=self.final,
                    CPU_stores=self.stores, original_instruction_trace=self.trace,
                    visits={hex(a): count for a, count in self.visits.items()},
                    unchanged_original_RX_sha256=self.rx_sha,
                    original_code_or_functions_not_replaced=True,
                    no_WORK_or_free_page_heads_seeded=True,
                    actual_task_created_or_callback_or_physical_heap_verified=False, device_IO=False)


def main():
    assert not OUT.exists()
    OUT.mkdir()
    n = NativeImage()
    sources = {str(p.relative_to(ROOT)): sha(p) for p in
               (Path(__file__), ROOT / 'scripts/analyze_native_sections.py',
                ROOT / 'evidence/firmware-analysis/main_02bd.bin')}
    assert n.word(0x395448) == 0x2dc983
    assert n.word(0x395454) == n.word(0x3954d4) == 0x2dc9eb
    assert n.word(n.runtime_to_load(0xf070b0, 4)) == 0
    save(OUT / 'inputs-at-run.json', dict(source_sha256=sources, previous_frozen_heap_not_modified=True,
                                        new_private_extent_bytes=32768, new_public_extent_bytes=65536,
                                        explicit_software_L1_type=1, explicit_L2_class=2,
                                        exact_original_veneers_verified=True, device_IO=False))
    rows, m = [], None
    try:
        for name, private_bytes, public_bytes in [
                ('native_OS20_two_allocation_prefix', 32768, 65536),
                ('no_public_extent_hits_original_diagnostic', 32768, 0),
                ('private_prefix_only_exhausts_at_constructor', 4096, 65536)]:
            m = HeapCase(n, name, private_bytes, public_bytes)
            result = m.run()
            path = OUT / (name + '.json.gz')
            compressed(path, result)
            rows.append(dict(name=name, path=str(path.relative_to(ROOT)), sha256=sha(path),
                             CPU_stores=len(result['CPU_stores']), instructions=len(result['original_instruction_trace']),
                             native_full_returns=len(result['native_full_returns']), boundary=result['boundary']['kind']))
            print(json.dumps(rows[-1]), flush=True)
        assert all(sha(ROOT / path) == expected for path, expected in sources.items())
        save(OUT / 'guest-proof.json', dict(all_passed=True, cases=rows, source_sha256=sources,
                                          case_count=len(rows), device_IO=False,
                                          actual_task_created_or_physical_heap_verified=False,
                                          updated_utc=datetime.now(timezone.utc).isoformat()))
    except BaseException as error:
        failure = dict(all_passed=False, error=str(error), traceback=traceback.format_exc(),
                       completed_cases=rows, source_sha256=sources, device_IO=False)
        if m:
            failure.update(state=m.snap(), phase=m.phase, boundary=m.boundary,
                           CPU_stores=m.stores, trace=m.trace, open_calls=m.open_calls,
                           native_full_returns=m.native_calls)
        compressed(OUT / 'terminal-failure.json.gz', failure)
        raise


if __name__ == '__main__':
    main()
