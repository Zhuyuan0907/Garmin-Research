#!/usr/bin/env python3
"""Continue a frozen real allocator endpoint without replaying its prefix.

Current TCB and storage/table bytes remain model inputs. Two NEW zero BSS
pages come from original startup declarations. No original code or return
is replaced. Stop before scheduling the new task.
"""
import sys
sys.dont_write_bytecode = True
import gzip
import hashlib
import json
import struct
import traceback
from datetime import datetime, timezone
from pathlib import Path
from probe_os20_allocator_v1 import (
    ROOT, HeapCase, NativeImage, REGS, RETURN, PRIVATE, PUBLIC, CURRENT,
    UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_PROT_READ, UC_PROT_WRITE,
    compressed, save, sha)

OUT = ROOT / 'staging/native-os20-create-continuation-v2'
PARENT = 'staging/native-os20-allocator-v1/native_OS20_two_allocation_prefix.json.gz'
FILE = 'staging/native-os20-allocator-v2/ROOT_FILE-proof-v1.json'
EXTRA_TRACKED = {0x2fcd0a, 0x2fccce, 0x2fc9bc, 0x358bf8, 0x2fbbbe, 0x521d7c}


class Continuation(HeapCase):
    def __init__(self, native, parent):
        super().__init__(native, 'original_OS20_name_TCB_and_adapter_before_POST')
        assert parent['all_passed'] and parent['boundary']['PC'] == 0x521e90
        assert not parent['unreturned_native_frames']
        assert parent['model_SCTLR'] == self.sctlr and not self.sctlr & 1
        assert self.zones == parent['zones']
        for row in self.zones:
            restored = bytes.fromhex(parent['whole_zones_after'][row['name']])
            assert len(restored) == row['size']
            self.u.mem_write(row['start'], restored)
        for name, page in [('OS20_adapter_pool_page', 0x03a1b000),
                           ('descriptor_registry_page', 0x014b3000)]:
            assert any(r['runtime_start'] <= page and page + 4096 <= r['runtime_end']
                       for r in native.zeros)
            self.u.mem_map(page, 4096, UC_PROT_READ | UC_PROT_WRITE)
            self.zones.append(dict(name=name, start=page, size=4096,
                                   original_startup_zero=True))
        self.before = {r['name']: bytes(self.u.mem_read(r['start'], r['size'])).hex()
                       for r in self.zones}
        state = parent['boundary']['state']
        self.u.reg_write(UC_ARM_REG_CPSR, state['CPSR'])
        for reg, value in zip(REGS, state['GP16']):
            self.u.reg_write(reg, value)
        # Writing an even PC in Unicorn changes CPSR.T. Restore the full
        # caller CPSR after GP16, preserving the frozen Thumb endpoint.
        self.u.reg_write(UC_ARM_REG_CPSR, state['CPSR'])
        assert self.snap() == state
        self.phase = 'continue_original_OS20_create_after_allocation'
        self.parent = parent

    def code(self, u, address, size, unused):
        if address == 0x521f0c:
            self.boundary = dict(kind='before_original_POST_call', PC=address,
                                 state=self.snap(), original_POST_not_executed=True)
            u.emu_stop()
            return
        if address == 0x521e90:
            # The parent stopped BEFORE this BL. Admit exactly that original
            # instruction; all remaining observations use the frozen guard.
            raw = self.native.read(address, size)
            assert raw.hex() == 'daf53bff' and bytes(u.mem_read(address, size)) == raw
            self.visits[address] += 1
            self.trace.append(dict(PC=address, opcode_hex=raw.hex(), size=size,
                                   phase=self.phase, **self.snap()))
            return
        super().code(u, address, size, unused)
        if address in EXTRA_TRACKED:
            state = self.snap()
            self.open_calls.append(dict(entry=address, before=state,
                                        return_PC=state['GP16'][14] & ~1,
                                        phase=self.phase, full_ABI_return=False))

    def run_continuation(self):
        self.u.emu_start(0x521e91, 0, count=30000, timeout=5_000_000)
        assert self.boundary and self.boundary['PC'] == 0x521f0c
        assert not self.done and not self.open_calls
        assert [r['entry'] for r in self.native_calls if r['entry'] in EXTRA_TRACKED] == [
            0x2fc9bc, 0x2fccce, 0x2fcd0a, 0x358bf8, 0x2fbbbe, 0x521d7c]
        descriptor = self.parent['payloads']['descriptor']
        workspace = self.parent['payloads']['workspace']
        top = workspace + 4248
        task = (top - 108) & ~7
        builder = next(r for r in self.native_calls if r['entry'] == 0x358bf8)
        assert builder['after']['GP16'][0] == task
        assert self.boundary['state']['GP16'][0] == task
        pool = 0x03a1b294
        record = bytes(self.u.mem_read(pool, 64))
        words = struct.unpack('<16I', record)
        assert words[:6] == (workspace, 4248, 0, RETURN + 0x101, 0x13520001, top)
        assert record[24:48] == bytes(24) and words[12] == task and words[13:] == (0, 0, 0)
        assert bytes(self.u.mem_read(pool + 64, 14 * 64)) == bytes(14 * 64)
        assert struct.unpack('<I', self.u.mem_read(0xf071cc, 4))[0] == 1
        assert struct.unpack('<I', self.u.mem_read(0xf071d0, 4))[0] == 1
        assert struct.unpack('<I', self.u.mem_read(0x014b3ad0, 4))[0] == descriptor
        assert struct.unpack('<I', self.u.mem_read(CURRENT + 32, 4))[0] == 0
        frame = struct.unpack('<I', self.u.mem_read(task + 12, 4))[0]
        assert frame == task - 52
        assert struct.unpack('<I', self.u.mem_read(frame + 4, 4))[0] == 0x521e45
        assert self.u.mem_read(task + 22, 1)[0] == 2
        # Original name conversion is reached with NULL input. The resulting
        # name bytes were already zero from calloc; this does not establish
        # non-NULL encoding semantics or a user-visible name.
        assert bytes(self.u.mem_read(descriptor + 60, 40)) == bytes(40)
        final = {r['name']: bytes(self.u.mem_read(r['start'], r['size'])).hex()
                 for r in self.zones}
        for row in self.zones:
            expected = bytearray.fromhex(self.before[row['name']])
            for store in self.stores:
                if store['zone'] != row['name']:
                    continue
                offset, length = store['address'] - row['start'], store['size']
                assert expected[offset:offset + length].hex() == store['before_hex']
                expected[offset:offset + length] = store['value'].to_bytes(length, 'little')
            assert expected.hex() == final[row['name']], row['name']
        assert hashlib.sha256(bytes(self.u.mem_read(0x50000, self.rom_size))).hexdigest() == self.rx_sha
        for base, length in ((PRIVATE, 32768), (PUBLIC, 65536)):
            assert bytes(self.u.mem_read(base - 4096, 4096)) == b'\xa5' * 4096
            assert bytes(self.u.mem_read(base + length, 4096)) == b'\xa5' * 4096
        return dict(all_passed=True, name=self.name,
                    parent_checkpoint=PARENT, parent_checkpoint_sha256=sha(ROOT / PARENT),
                    parent_prefix_not_replayed=True, checkpoint_GP_memory_restored=True,
                    complete_hardware_CP15_cache_checkpoint_not_captured=True,
                    two_new_pages_original_startup_zero=True, declared_synthetic_current_TCB=CURRENT,
                    current_TCB_not_constructed_by_kernel=True, table_bytes_not_captured_from_hardware=True,
                    MMU_translation_disabled=True, model_SCTLR=self.sctlr,
                    zones=self.zones, whole_zones_before=self.before, whole_zones_after=final,
                    CPU_stores=self.stores, original_instruction_trace=self.trace,
                    native_full_returns=self.native_calls, boundary=self.boundary,
                    descriptor=descriptor, workspace=workspace, workspace_bytes=4248,
                    original_new_TCB=task, original_saved_frame=frame, adapter_record=pool,
                    adapter_record64_hex=record.hex(), NULL_name_conversion_called=True,
                    name_conversion_not_generic_task_object_constructor=True,
                    POST_or_root_callback_or_task_execution=False,
                    complete_create_function_returned=False, physical_heap_or_App_verified=False,
                    original_code_unmodified=True, no_original_function_return_hooks=True,
                    unchanged_RX_sha256=self.rx_sha, device_IO=False)


def main():
    assert not OUT.exists()
    OUT.mkdir()
    reviewed = json.loads((ROOT / FILE).read_text())
    assert reviewed['all_passed'] and reviewed['actual_two_OS20_allocations_full_returns']
    expected = reviewed['source_sha256'][PARENT]
    assert sha(ROOT / PARENT) == expected
    parent = json.load(gzip.open(ROOT / PARENT, 'rt'))
    n = NativeImage()
    sources = {str(p.relative_to(ROOT)): sha(p) for p in
               (Path(__file__), ROOT / 'scripts/probe_os20_allocator_v1.py',
                ROOT / 'scripts/analyze_native_sections.py', ROOT / PARENT,
                ROOT / FILE, ROOT / 'evidence/firmware-analysis/main_02bd.bin')}
    m = Continuation(n, parent)
    try:
        result = m.run_continuation()
        path = OUT / 'create-after-allocation.json.gz'
        compressed(path, result)
        save(OUT / 'guest-proof.json', dict(all_passed=True, source_sha256=sources,
            case=dict(path=str(path.relative_to(ROOT)), sha256=sha(path), passed=True),
            original_TCBuilder_returned=True, original_adapter_record_written=True,
            original_task_execution_or_physical_App_verified=False, parent_prefix_rerun=False,
            CPU_stores=len(m.stores), instructions=len(m.trace), native_full_returns=len(m.native_calls),
            device_IO=False, updated_utc=datetime.now(timezone.utc).isoformat()))
        print(json.dumps(dict(all_passed=True, CPU_stores=len(m.stores), instructions=len(m.trace),
                              native_full_returns=len(m.native_calls), TCB=hex(result['original_new_TCB']),
                              stop_before_POST=True)), flush=True)
    except BaseException as error:
        compressed(OUT / 'terminal-failure.json.gz', dict(
            all_passed=False, error=str(error), traceback=traceback.format_exc(),
            source_sha256=sources, state=m.snap(), boundary=m.boundary,
            trace=m.trace, CPU_stores=m.stores, native_full_returns=m.native_calls,
            open_calls=m.open_calls, device_IO=False))
        raise


if __name__ == '__main__':
    main()
