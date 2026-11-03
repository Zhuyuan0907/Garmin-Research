#!/usr/bin/env python3
"""Integrate the frozen original-fragment VFP observer with a native task VM.

Construction belongs after the complete cold-controller component endpoint.
This module neither constructs a VM nor executes guest code. It writes no
TCB, metadata, pool, FP owner or FP register. The inherited enter() models
only the already-declared architectural undefined-exception entry.
"""
from pathlib import Path
import hashlib
import json
import struct

import unicorn
from unicorn.arm_const import (UC_ARM_REG_C1_C0_2, UC_ARM_REG_CPSR, UC_ARM_REG_FPEXC,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0)
from probe_native_multiowner_vfp import MultiOwnerVFPState, MAGIC, require, word, OWNER

FROZEN_HELPER_SHA256 = '8fc0a2bcf6319f9a2b5a00c15c1f9c213b1717f6c55105b0785433e594a4cab4'
CURRENT_GETTER = 0x358d24
CURRENT_GETTER_RETURN = 0x20ec88
IRQ_MARKER = 0xf09094
READY_HEAD = 0xf09090
CONTROLLER = 0x9503f90
CONTROLLER_METADATA = 0x9400900
CONTROLLER_POOL = 0x9500000
CODE_RUNTIME_STARTS = (0x50000, 0x4400000, 0x5400000)


class _RuntimeCodeImage:
    """A read-only adapter for the frozen enter() load-domain read.

    Frozen decode() already maps its writer PC before calling read(). Load
    addresses for the copied440/540 code do not occupy a runtime code range,
    so those reads remain load-domain reads and are never relocated twice.
    """
    def __init__(self, image):
        self.image = image
        self.copies = image.copies

    def code_origin(self, address, length):
        require(isinstance(address, int) and isinstance(length, int) and length > 0,
                'Invalid original runtime instruction range')
        matches = [r for r in self.copies if r['runtime_start'] in CODE_RUNTIME_STARTS
                   and r['runtime_start'] <= address and address+length <= r['runtime_end']]
        require(len(matches) == 1, 'FP instruction is outside declared original runtime code copies')
        row = matches[0]
        load = self.image.runtime_to_load(address, length)
        require(load == row['load_start']+address-row['runtime_start'],
                'Original runtime code mapping differs')
        return load, row

    def read(self, address, length):
        matches = [r for r in self.copies if r['runtime_start'] in CODE_RUNTIME_STARTS
                   and r['runtime_start'] <= address and address+length <= r['runtime_end']]
        if matches:
            load, _ = self.code_origin(address, length)
            return self.image.read(load, length)
        return self.image.read(address, length)

    def runtime_to_load(self, address, length=1):
        return self.image.runtime_to_load(address, length)


class NativeDispatcherMultiOwnerVFPState(MultiOwnerVFPState):
    """Post-cold-endpoint FP exchange; ordinary task stores stay journaled.

    running_task must return the VM's task identified by an actual native
    restore destination, not a fallback ready-head pointer. tasks has exactly
    the controller and the actual Dispatcher, each with metadata/pool and a
    conservative minimum_live_SP supplied by the native VM. prior_lazy is
    the completed first/same-controller observer retained for provenance.
    """
    def __init__(self, uc, stock, running_task, live, stack_top, tasks, prior_lazy,
                 exclusive=False):
        require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
                'Use the isolated binding/native Unicorn2.1.4 pair')
        require(exclusive is False, 'Native integration requires ordinary CPU histories')
        helper = Path(__file__).with_name('probe_native_multiowner_vfp.py')
        require(hashlib.sha256(helper.read_bytes()).hexdigest() == FROZEN_HELPER_SHA256,
                'Frozen FP fragment observer source changed')
        require(callable(running_task), 'Need actual native running-task callback')
        require(prior_lazy is not None and prior_lazy.uc is uc and prior_lazy.stack_top == stack_top
                and prior_lazy.active is None and prior_lazy.rows,
                'Complete prior first/same-controller observer required')
        require(all(r.get('original_handler_entered') and r.get('original_exception_return_seen')
                    and r.get('original_opcode_retry_reached') and not r.get('host_wrote_FP_enable_or_context')
                    and int(r['after_native_handler']['FPowner'], 16) == CONTROLLER
                    for r in prior_lazy.rows), 'Prior controller FP rows are incomplete or outside cold scope')
        require(CONTROLLER in tasks and tasks[CONTROLLER]['metadata'] == CONTROLLER_METADATA
                and tasks[CONTROLLER]['pool'] == CONTROLLER_POOL,
                'Controller lacks the declared original cold-builder metadata/pool')
        self.native_stock = stock
        self.native_running_task = running_task
        self.prior_lazy = prior_lazy
        self.prior_rows_sha256 = self._prior_rows_hash()
        self.runtime_code = _RuntimeCodeImage(stock)
        self.original_current_getter = stock.read(CURRENT_GETTER, 24)
        require(struct.unpack_from('<2I', self.original_current_getter, 16) == (IRQ_MARKER, READY_HEAD),
                'Original current getter literal pointers changed')
        require(bytes(uc.mem_read(CURRENT_GETTER, 24)) == self.original_current_getter,
                'Resident original current getter differs')
        require(word(uc, IRQ_MARKER) == 0 and word(uc, READY_HEAD) == running_task() == CONTROLLER
                and word(uc, OWNER) == CONTROLLER,
                'Cold component endpoint lacks actual controller/current/FP-owner agreement')
        require(uc.reg_read(UC_ARM_REG_FPEXC) == 0x40000000
                and uc.reg_read(UC_ARM_REG_C1_C0_2)&0xf00000 == 0xf00000,
                'Complete cold component endpoint lacks enabled native FP/access state')
        self.outside_active_CPU_store_count = 0
        super().__init__(uc, self.runtime_code, running_task, live, stack_top, tasks,
                         exclusive=False)
        self.integration_inputs = dict(existing_FP_owner=hex(CONTROLLER),
            prior_completed_controller_rows=len(prior_lazy.rows), prior_rows_sha256=self.prior_rows_sha256,
            two_tasks=[hex(t) for t in tasks], architectural_UND_entry_is_fixture=True,
            original_cold_builder_or_scheduler_execution_performed_by_this_helper=False,
            host_changed_live_TCB_or_owner_metadata_slot_pool_or_FP_bank=False)

    def _prior_rows_hash(self):
        return hashlib.sha256(json.dumps(self.prior_lazy.rows, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()

    def _current_gate(self, expected=None):
        task = self.native_running_task()
        require(task in self.tasks and self.live(task, 108),
                'Running FP task lacks admitted actual native TCB backing')
        require(word(self.uc, IRQ_MARKER) == 0,
                'Original current getter returns zero in IRQ-marker scope')
        require(bytes(self.uc.mem_read(CURRENT_GETTER, 24)) == self.original_current_getter,
                'Original current getter changed')
        original_result = word(self.uc, READY_HEAD)
        require(original_result == task and (expected is None or task == expected),
                'Original current-getter result differs from actual running task')
        return task

    def enter(self, error):
        # Admission is performed before inherited architectural entry changes
        # the banked exception state. This adapter changes file addressing only.
        require(error.errno == unicorn.UC_ERR_INSN_INVALID and self.active is None,
                'Unexpected or recursive native FP exception')
        task = self._current_gate()
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        load, section = self.runtime_code.code_origin(pc, 4)
        raw = self.native_stock.read(load, 4)
        require(bytes(self.uc.mem_read(pc, 4)) == raw, 'Runtime fault opcode differs from exact MAIN copy')
        entry = super().enter(error)
        self.active.update(actual_native_running_task=hex(task), original_getter_preentry_result=hex(task),
            original_IRQ_marker=0, fault_load_PC=hex(load),
            fault_runtime_copy_start=hex(section['runtime_start']),
            original_current_getter_entered=False, original_current_getter_returned=False)
        return entry

    def observe(self, uc, address, size, data):
        row = self.active
        if row is not None:
            new = int(row['new_owner'], 16)
            if address == CURRENT_GETTER:
                require(uc.reg_read(UC_ARM_REG_CPSR)&0x3f == 0x3b
                        and uc.reg_read(UC_ARM_REG_LR) == CURRENT_GETTER_RETURN,
                        'Original handler current-getter call ABI differs')
                self._current_gate(new)
                require(not row['original_current_getter_entered'], 'Repeated original handler current query')
                row['original_current_getter_entered'] = True
            if address == CURRENT_GETTER_RETURN:
                require(row['original_current_getter_entered'] and not row['original_current_getter_returned']
                        and uc.reg_read(UC_ARM_REG_CPSR)&0x3f == 0x1b
                        and uc.reg_read(UC_ARM_REG_R0) == self._current_gate(new),
                        'Actual original current query did not return the running task in ARM')
                row['original_current_getter_returned'] = True
                row['actual_original_current_getter_result'] = hex(uc.reg_read(UC_ARM_REG_R0))
        super().observe(uc, address, size, data)
        if row is not None and self.active is None:
            require(row['original_current_getter_entered'] and row['original_current_getter_returned'],
                    'Native FP retry lacked original current-query entry/return')
            self._current_gate(int(row['new_owner'], 16))

    def _zone(self, address, size):
        return next((r for low, r in self.zones.items()
                     if low <= address and address+size <= low+r['bytes']), None)

    def _protected_without_exception(self, address, size):
        ranges = [(OWNER, 4), (self.stack_top-4096+32, 4096)]
        for task, spec in self.tasks.items():
            ranges.extend([(task+28, 4), (spec['metadata'], 40), (spec['pool'], 320)])
        return any(address < low+n and low < address+size for low, n in ranges)

    def _active_store(self, uc, address, size, value):
        """Pure validation used by both our hook and the parent-zone bridge.

        It does not alter pending push/coverage sets. Hook registration order
        is immaterial: the inherited hook alone records and consumes coverage.
        """
        require(uc is self.uc and self.active is not None, 'No active FP handler for parent bridge')
        require(size in (1, 2, 4, 8) and self._zone(address, size) is not None,
                'FP parent store crosses a declared whole-zone boundary')
        row = self.active
        self._current_gate(int(row['new_owner'], 16))
        status = uc.reg_read(UC_ARM_REG_CPSR)
        require(status&31 == 0x1b, 'FP store left original UND mode')
        pc, thumb = uc.reg_read(UC_ARM_REG_PC), bool(status&32)
        self.runtime_code.code_origin(pc, 4)
        load, opcode, instruction = self.decode(pc, thumb)
        value &= (1 << (8*size))-1
        top = self.stack_top
        if top-4096+32 <= address < top+32:
            pending = row.get('pending_push')
            require(pending and pending['PC'] == hex(pc) and size == 4
                    and pending['expected'].get(address) == value,
                    'Parent UND store differs from exact pending native push')
        elif pc == 0x20ecd8:
            pending = row.get('pending_save')
            require(pending and pending['context'] <= address
                    and address+size <= pending['context']+128, 'Parent VSTM store outside exact128')
            offset = address-pending['context']
            require(value.to_bytes(size, 'little') == bytes.fromhex(pending['bank_hex'])[offset:offset+size],
                    'Parent VSTM payload differs from actual captured D16')
        elif pc == 0x20ecf8:
            pending = row.get('pending_control')
            require(pending and size == 4 and pending['expected'].get(address) == value,
                    'Parent control store differs from actual r1/r2/r3/ip')
        else:
            old, new = int(row['old_owner'], 16), int(row['new_owner'], 16)
            spec = self.tasks.get(old)
            if pc == 0x20ec98:
                require((address, size, value) == (OWNER, 4, new), 'Parent owner publication differs')
            elif pc in (0xf6f02, 0xf6f10, 0xf6f18):
                pending = row.get('pending_allocation')
                require(spec is not None and pending, 'Native pool store lacks exact pending allocation')
                expected = (spec['pool'], 4, MAGIC) if pc == 0xf6f02 else (
                    spec['pool']+4, 4, spec['first_context'] if pc == 0xf6f10 else int(pending['end'], 16))
                require((address, size, value) == expected, 'Native pool header/cursor store differs')
            elif pc in (0xf6e2e, 0xf6e32, 0xf6e36, 0xf6e3c, 0xf6e40):
                require(spec is not None and row['allocation_rows'], 'Metadata clone lacks native allocation')
                alloc = row['allocation_rows'][-1]
                require(alloc['request'] == 40, 'Metadata clone does not use native40-byte allocation')
                clone = int(alloc['result'], 16)
                if pc in (0xf6e2e, 0xf6e32, 0xf6e36):
                    low, high = {0xf6e2e:(0, 16), 0xf6e32:(16, 32), 0xf6e36:(32, 40)}[pc]
                    offset = address-clone
                    require(size == 4 and low <= offset and offset+size <= high
                            and value.to_bytes(size, 'little') == bytes.fromhex(spec['original_metadata_hex'])[offset:offset+size],
                            'Native clone40 chunk differs from original immutable metadata')
                elif pc == 0xf6e3c:
                    require((address, size, value) == (clone+4, 1, 1), 'Native clone writable-byte store differs')
                else:
                    require((address, size, value) == (old+28, 4, clone), 'Native clone TCB publication differs')
            elif pc == 0x6e0858:
                require((address, size, value) == (row.get('attach_metadata', -1)+28, 4, row.get('attach_context')),
                        'Native context slot publication differs')
            else:
                raise AssertionError('Unknown active original FP store')
        return dict(PC=hex(pc), load_PC=hex(load), Thumb=thumb, address=hex(address), size=size, value=value,
            before_hex=bytes(uc.mem_read(address, size)).hex(), opcode_hex=opcode.hex(),
            original_instruction=instruction, running_task=hex(self.native_running_task()),
            exact_original_FP_store_validated=True, parent_bridge_did_not_consume_helper_coverage=True)

    def validate_parent_store(self, uc, access, address, size, value, data=None):
        """Return a validated parent journal row, or None outside FP exception.

        The VM appends this row to its own matching whole-zone history, with
        its phase. Do not call journal() manually: its installed memory hook
        separately records each store once and validates complete coverage.
        """
        if self.active is None:
            return None
        return self._active_store(uc, address, size, value)

    def journal(self, uc, access, address, size, value, data):
        if self.active is not None:
            self._active_store(uc, address, size, value)
        else:
            require(not self._protected_without_exception(address, size),
                    'FP owner/metadata/pool/UND mutation outside original active FP handler')
            require(self._zone(address, size) is not None and size in (1, 2, 4, 8),
                    'Ordinary CPU store crosses FP-journal boundary')
            self.runtime_code.code_origin(uc.reg_read(UC_ARM_REG_PC), 4)
            self.outside_active_CPU_store_count += 1
        super().journal(uc, access, address, size, value, data)
        if self.active is None:
            zone = self._zone(address, size)
            zone['stores'][-1].update(outside_active_native_CPU_store=True,
                actual_running_task=hex(self.native_running_task() or 0),
                ready_head=hex(word(uc, READY_HEAD)), IRQ_marker=hex(word(uc, IRQ_MARKER)))

    def verify(self):
        require(self.prior_lazy.active is None and self._prior_rows_hash() == self.prior_rows_sha256,
                'Preserved complete cold-controller FP history changed')
        zones = super().verify()
        require(all(r.get('original_current_getter_entered') and r.get('original_current_getter_returned')
                    and r.get('actual_original_current_getter_result') == r['new_owner']
                    for r in self.rows), 'Post-cold FP rows lack actual original current-query return')
        return zones
