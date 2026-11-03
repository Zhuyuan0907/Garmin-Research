#!/usr/bin/env python3
"""Resume completed native TCB setup and execute the original POST suffix.

No allocation or successful TCB/name scope is replayed. The existing current
TCB remains a declared fixture; this is not a full boot or real task run.
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
    ROOT, HeapCase, NativeImage, REGS, RETURN, CURRENT, UC_ARM_REG_CPSR,
    UC_PROT_READ, UC_PROT_WRITE, compressed, save, sha)

OUT = ROOT / 'staging/native-os20-create-finish-v2'
PARENT = 'staging/native-os20-create-continuation-v3/create-after-allocation.json.gz'


class Finish(HeapCase):
    def __init__(self, native, parent):
        super().__init__(native, 'original_OS20_POST_and_create_return')
        assert parent['all_passed'] and parent['boundary']['PC'] == 0x521f0c
        assert parent['model_SCTLR'] == self.sctlr and not self.sctlr & 1
        for row in parent['zones']:
            if not any(z['name'] == row['name'] for z in self.zones):
                assert row['original_startup_zero'] and row['size'] == 4096
                self.u.mem_map(row['start'], row['size'], UC_PROT_READ | UC_PROT_WRITE)
                self.zones.append(row)
            payload = bytes.fromhex(parent['whole_zones_after'][row['name']])
            assert len(payload) == row['size']
            self.u.mem_write(row['start'], payload)
        assert self.zones == parent['zones']
        state = parent['boundary']['state']
        # Select the captured register bank before writing SP/LR; then restore
        # CPSR again after PC so both the bank and Thumb bit stay exact.
        self.u.reg_write(UC_ARM_REG_CPSR, state['CPSR'])
        for reg, value in zip(REGS, state['GP16']):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_CPSR, state['CPSR'])
        assert self.snap() == state
        self.before = {z['name']: bytes(self.u.mem_read(z['start'], z['size'])).hex()
                       for z in self.zones}
        self.parent = parent
        self.phase = 'original_POST_suffix_only'

    def code(self, u, address, size, unused):
        # A preemption would require a real controller context. Preserve the
        # actual boundary if one occurs, never manufacture a return.
        if address == 0x358ec4:
            self.boundary = dict(kind='before_original_context_restore', PC=address,
                                 state=self.snap())
            u.emu_stop()
            return
        super().code(u, address, size, unused)
        if address == 0x2fcf44:
            before = self.snap()
            self.open_calls.append(dict(entry=address, before=before,
                return_PC=before['GP16'][14] & ~1, phase=self.phase, full_ABI_return=False))

    def run_finish(self):
        original_before = self.snap()
        self.u.emu_start(0x521f0d, 0, count=30000, timeout=5_000_000)
        assert self.done and not self.boundary and not self.open_calls
        assert len(self.native_calls) == 1 and self.native_calls[0]['entry'] == 0x2fcf44
        after = self.snap()
        assert after['GP16'][0] == self.parent['adapter_record']
        caller = json.load(gzip.open(ROOT / self.parent['parent_checkpoint'], 'rt'))
        entry_before = caller['original_constructor_calls'][-1]['before']
        assert entry_before['GP16'][4:12] == after['GP16'][4:12]
        assert entry_before['GP16'][13] == after['GP16'][13]
        assert (entry_before['CPSR'] ^ after['CPSR']) & 0xdf == 0
        task = self.parent['original_new_TCB']
        assert self.u.mem_read(task + 22, 1)[0] == 1
        assert struct.unpack('<I', self.u.mem_read(CURRENT, 4))[0] == task
        assert struct.unpack('<I', self.u.mem_read(task, 4))[0] == 0
        assert struct.unpack('<I', self.u.mem_read(0xf09090, 4))[0] == CURRENT
        assert not any(t['PC'] == 0x521e44 for t in self.trace)
        final = {z['name']: bytes(self.u.mem_read(z['start'], z['size'])).hex()
                 for z in self.zones}
        for z in self.zones:
            replay = bytearray.fromhex(self.before[z['name']])
            for store in self.stores:
                if store['zone'] != z['name']:
                    continue
                off, size = store['address'] - z['start'], store['size']
                assert replay[off:off + size].hex() == store['before_hex']
                replay[off:off + size] = store['value'].to_bytes(size, 'little')
            assert replay.hex() == final[z['name']]
        assert hashlib.sha256(bytes(self.u.mem_read(0x50000, self.rom_size))).hexdigest() == self.rx_sha
        return dict(all_passed=True, name=self.name, parent_checkpoint=PARENT,
            parent_checkpoint_sha256=sha(ROOT / PARENT), complete_parent_GP_memory_restored=True,
            allocation_or_TCB_scope_replayed=False, zones=self.zones,
            whole_zones_before=self.before, whole_zones_after=final,
            original_instruction_trace=self.trace, CPU_stores=self.stores,
            native_full_returns=self.native_calls,
            original_create_entry_before=entry_before, suffix_before=original_before,
            original_create_return_after=after,
            original_create_complete_ABI_return=True, original_POST_complete_return=True,
            original_new_TCB=task, adapter_record=self.parent['adapter_record'],
            original_new_task_state=1, original_ready_queue_inserted_after_current=True,
            original_current_TCB_still_synthetic=CURRENT,
            new_task_priority=240, original_current_model_priority=0,
            original_root_callback_executed=False, task_execution_or_player_or_physical_App_verified=False,
            MMU_translation_disabled=True, original_code_unmodified=True,
            original_functions_not_hooked=True, device_IO=False)


def main():
    assert not OUT.exists()
    OUT.mkdir()
    guest = json.loads((ROOT / 'staging/native-os20-create-continuation-v3/guest-proof.json').read_text())
    assert guest['all_passed'] and sha(ROOT / PARENT) == guest['case']['sha256']
    sources = dict(guest['source_sha256'])
    for p in (Path(__file__), ROOT / PARENT, ROOT / 'staging/native-os20-create-continuation-v3/guest-proof.json'):
        sources[str(p.relative_to(ROOT))] = sha(p)
    for p, expected in sources.items():
        assert sha(ROOT / p) == expected
    parent = json.load(gzip.open(ROOT / PARENT, 'rt'))
    m = None
    try:
        m = Finish(NativeImage(), parent)
        result = m.run_finish()
        p = OUT / 'create-POST-return.json.gz'
        compressed(p, result)
        save(OUT / 'guest-proof.json', dict(all_passed=True, source_sha256=sources,
            case=dict(path=str(p.relative_to(ROOT)), sha256=sha(p), passed=True),
            CPU_stores=len(m.stores), instructions=len(m.trace), native_full_returns=len(m.native_calls),
            complete_original_create_return=True, original_ready_queue_inserted=True,
            original_root_callback_or_physical_App_verified=False,
            device_IO=False, updated_utc=datetime.now(timezone.utc).isoformat()))
        print(json.dumps(dict(all_passed=True, CPU_stores=len(m.stores), instructions=len(m.trace),
            native_full_returns=len(m.native_calls), original_create_return=hex(result['adapter_record']),
            original_ready_queue_inserted=True, original_callback_executed=False)), flush=True)
    except BaseException as error:
        data = dict(all_passed=False, error=str(error), traceback=traceback.format_exc(),
                    source_sha256=sources, device_IO=False)
        if m is not None:
            data.update(state=m.snap(), trace=m.trace, CPU_stores=m.stores,
                        native_full_returns=m.native_calls, open_calls=m.open_calls, boundary=m.boundary)
        compressed(OUT / 'terminal-failure.json.gz', data)
        raise


if __name__ == '__main__':
    main()
