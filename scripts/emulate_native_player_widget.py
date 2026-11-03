#!/usr/bin/env python3
"""Development probe for stock Widget construction; never accesses a device."""
from collections import deque
import json
from pathlib import Path
import struct
import sys
import unicorn
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_CP_REG,
                              UC_ARM_REG_FPEXC, UC_ARM_REG_FPSCR, UC_ARM_REG_SP)
from analyze_native_sections import NativeImage, ROOT
from emulate_native_player_menu_selection import SelectionPlayerVM, BUILD, SQL_OUT
from emulate_native_vpm_filesystem import REGS, require
from emulate_native_player_menu_loaded import PLAYER_ID, SEED
from emulate_native_player_menu_selection import SQL_OUT
CONTROL_CALLBACK = SEED + 0x800
WIDGET_OUT = 0x084c9000


class WidgetVM(SelectionPlayerVM):
    def __init__(self, stock, build):
        self.recent = deque(maxlen=32)
        self.invalid_accesses = []
        self.zero_pages = []
        self.control_clicks = []
        self.conditional_region_writes = []
        super().__init__(stock, build)
        self.sql_hooks.pop(0x315b64)
        # Supply virtual CP10/11 access, as in the earlier exact volume-math
        # experiment. Original GUI geometry VFP instructions execute normally.
        self.uc.reg_write(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 2, 0xf << 20))
        self.uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
        self.uc.reg_write(UC_ARM_REG_FPSCR, 0)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self.invalid_memory)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.record_region_write,
                         begin=0x05400000, end=0x055fffff)

    def record_region_write(self, uc, access, address, size, value, data):
        if any(r['runtime_start'] <= address and address + size <= r['runtime_end']
               for r in self.stock.copies if r['runtime_start'] == 0x05400000):
            self.conditional_region_writes.append({'address': hex(address), 'size': size,
                                                  'value': hex(value), 'PC': hex(uc.reg_read(UC_ARM_REG_PC))})

    def invalid_memory(self, uc, access, address, size, value, data):
        # Map only verified startup-zero BSS touched by these GUI routines.
        # Never satisfy instruction fetches, arbitrary pointers or heap faults.
        if access in [unicorn.UC_MEM_READ_UNMAPPED, unicorn.UC_MEM_WRITE_UNMAPPED] and any(
                r['runtime_start'] <= address and address + size <= r['runtime_end']
                for r in self.stock.zeros):
            start = address & ~4095
            uc.mem_map(start, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.zero_pages.append({'start': hex(start), 'startup_zero_provenance': True})
            return True
        self.invalid_accesses.append({'access': access, 'address': hex(address), 'size': size,
                                     'PC': hex(uc.reg_read(UC_ARM_REG_PC)),
                                     'LR': hex(uc.reg_read(UC_ARM_REG_LR)),
                                     'stack_words': [hex(self.word(uc.reg_read(UC_ARM_REG_SP) + n * 4))
                                                     for n in range(48)]})
        return False

    def observe(self, uc, address, size, data):
        self.recent.append(hex(address))
        if address == CONTROL_CALLBACK:
            self.control_clicks.append([uc.reg_read(r) for r in REGS[:2]])
            self.ret(0)
            return
        if address in [0x2dc982, 0x2dc954]:
            # Stock calloc or aligned allocation boundary. The latter reaches
            # a kernel heap absent from this offline VM. Its caller requests a
            #480x272x2 canvas; no pixels or successful rendering are supplied.
            self.visits[address] += 1
            args = [uc.reg_read(r) for r in REGS]
            length = args[0] * args[1] if address == 0x2dc982 else args[0]
            require(0 < length < 0x100000, 'Unexpected GUI calloc length')
            require(address == 0x2dc982 or args[2] == 8, 'Unexpected GUI allocation alignment')
            pointer = self.next_raw
            self.next_raw += (length + 127) & ~63
            require(self.next_raw < 0x084c0000, 'GUI raw heap overlaps SQL fixture')
            uc.mem_write(pointer - 32, b'\xa5' * (length + 64))
            if address == 0x2dc982:
                uc.mem_write(pointer, b'\0' * length)
            self.raw_allocations[pointer] = {'length': length, 'freed': False, 'service': hex(address)}
            self.events.append({'allocation_boundary': hex(address), 'length': length,
                                'arguments': args[:3], 'pointer': hex(pointer)})
            self.ret(pointer)
            return
        return super().observe(uc, address, size, data)

    def normal_lookup(self, cell, style=0):
        label, icon, size, info = SQL_OUT, SQL_OUT + 0x40, SQL_OUT + 0x44, SQL_OUT + 0x48
        self.uc.mem_write(SQL_OUT, b'\xa5' * 0x200)
        # The factory assigns a shared_ptr, releasing its previous holder. A
        # caller must supply a constructed empty holder, not poisoned storage.
        out = WIDGET_OUT + style * 8
        self.put(out, 0)
        self.put(out + 4, 0)
        self.invoke(0x39272b, (label,))
        self.put(label + 16, 0)
        # Actual fifth factory argument is forwarded from getter r3; the stock
        # factory handles0/1. Old boundary-only probe used opaque0x1352 instead.
        result = self.invoke(0x315f17, (self.menu_pointer(), cell, out, style),
                             (label, icon, size, info))
        widget = self.word(out)
        row = {'matched': result, 'widget': hex(widget), 'widget_control_block': hex(self.word(out + 4)),
               'output_holder': hex(out), 'output_holder_initialized_empty': True,
               'caption': self.wide(self.invoke(0x3927f5, (label,))), 'factory_fifth_argument': style}
        self.invoke(0x392773, (label,))
        return row

    def finish(self):
        # This conditional copy contains initialized data as well as the
        # platform flag used by earlier fixtures. GUI calls execute the stock
        # one-time0->1 guard write; do not treat the whole data copy as code.
        # Verify the entire region against a single exact word allowance. No
        # guest memory is rewritten and all other original guards remain.
        base, flag = 0x05400000, 0x0551c80c
        before = self.initial_regions[base]
        offset = flag - base
        require(before[offset:offset + 4] == b'\0' * 4, 'Original GUI guard word is not zero')
        expected = bytearray(before)
        expected[offset:offset + 4] = struct.pack('<I', 1)
        require(bytes(self.uc.mem_read(base, len(before))) == bytes(expected),
                'Unexpected conditional initialized-data mutation')
        require(self.conditional_region_writes == [{'address': hex(flag), 'size': 4,
                'value': '0x1', 'PC': '0x385450'}], 'GUI guard writer or value differs')
        self.initial_regions[base] = bytes(expected)
        try:
            snapshot = super().finish()
        finally:
            self.initial_regions[base] = before
        snapshot['original_GUI_initialized_data_mutations'] = [{'address': hex(flag),
            'word_before': 0, 'word_after': 1, 'writer_PC': '0x385450',
            'original_instruction_executed': True, 'guest_memory_rewritten_by_test': False}]
        snapshot['full_conditional_data_region_matches_single_native_word_allowance'] = True
        return snapshot


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
            'Run with staging/unicorn-stream-venv/bin/python; system runtime is not the validated GUI runner')
    build = json.loads((ROOT / BUILD).read_text())
    vm = WidgetVM(NativeImage(), build)
    # Initialize the original GUI timer-list object using its exact constructor.
    # Boot ordering and physical OS/event delivery are still outside this probe.
    vm.invoke(0x395981, ())
    if '--loaded-normal' in sys.argv or '--synthetic-normal' in sys.argv:
        loaded = None
        if '--loaded-normal' in sys.argv:
            print(json.dumps({'phase': 'before_original_outer_loader'}), flush=True)
            loaded = vm.load()
            print(json.dumps({'phase': 'original_outer_loader_returned'}), flush=True)
        else:
            self_label_aux = SEED + 0x100 + 16
            vm.put(self_label_aux, 0)
            vm.seed_control(PLAYER_ID, 'Pi 播放器', 0x13528000)
            vm.put(vm.menu_records()[0] + 84, CONTROL_CALLBACK | 1)
        vm.init_DB_fixture()
        vm.set_cell(15, PLAYER_ID, 0)
        print(json.dumps({'phase': 'before_original_normal_widget_factory'}), flush=True)
        try:
            row = vm.normal_lookup(15, 1 if '--style1' in sys.argv else 0)
            obj = int(row['widget'], 16)
            row['vtable'] = hex(vm.word(obj))
            row['event_slot'] = hex(vm.word(vm.word(obj) + 16))
            row['click_signal'] = hex(vm.word(obj + 0x88))
            row['enabled'] = list(vm.uc.mem_read(obj + 0xc8, 2))
            row['click_sound_selector'] = vm.uc.mem_read(obj + 0x120, 1)[0]
            before = len(vm.audio)
            if '--emit-click' in sys.argv:
                vm.invoke(0x27a98b, (obj,))
                row['stock_Widget_click_signal_executed'] = True
                row['control_clicks'] = vm.control_clicks
                row['audio_requests_added'] = len(vm.audio) - before
            if '--touch' in sys.argv:
                # Explicit synthetic page-layout rectangle and event payload;
                # physical input driver and normal page layout are not run.
                vm.invoke(vm.word(vm.word(obj) + 39 * 4), (obj, 0))
                vm.uc.mem_write(obj + 0x20, struct.pack('<4I', 0, 0, 100, 40))
                event = SQL_OUT + 0x400
                vm.uc.mem_write(event, b'\0' * 64)
                vm.put(event + 0x10, 50)
                vm.put(event + 0x14, 20)
                row['touch_results'] = []
                for action in [0, 1]:
                    vm.uc.mem_write(event + 0x28, bytes([action]))
                    row['touch_results'].append(vm.invoke(vm.word(vm.word(obj) + 16), (obj, event)))
                row['control_clicks_after_touch'] = vm.control_clicks
                row['state_after_touch'] = list(vm.uc.mem_read(obj + 0xc8, 2))
                manager = vm.invoke(0x393a2d, (0,))
                row['manager'] = hex(manager)
                row['post_virtual'] = hex(vm.word(vm.word(manager) + 0xc4))
                row['manager_vtable'] = hex(vm.word(manager))
                row['manager_virtuals'] = [hex(vm.word(vm.word(manager) + n * 4)) for n in range(70)]
                row['queued_callbacks'] = vm.word(manager + 0xe30)
            for pointer, entry in vm.raw_allocations.items():
                vm.verify_guard(pointer, entry)
            row.update({'normal_factory_returned': True, 'loaded': loaded, 'allocation_guards_intact': True})
        except Exception as error:
            row = {'normal_factory_returned': False, 'error': str(error), 'recent': list(vm.recent),
                   'invalid_accesses': vm.invalid_accesses, 'events': vm.events[-10:]}
        row.update({'device_io': False, 'sounds_emitted': False, 'zero_pages': vm.zero_pages})
        (ROOT / 'staging/native-player-widget/development-normal-probe.json').write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps(row), flush=True)
        sys.exit(0 if row['normal_factory_returned'] else 1)
    caption, text, visual = SQL_OUT, SQL_OUT + 0x40, SQL_OUT + 0x100
    vm.uc.mem_write(text, 'Pi 播放器'.encode('utf-16le') + b'\0\0')
    vm.invoke(0x39274f, (caption, text, 0xffffffff))
    vm.put(caption + 16, 0)
    vm.put(visual, visual + 8)
    vm.put(visual + 4, 0)
    vm.uc.mem_write(visual + 8, b'\0')
    # The original Add constructor is allocated0x8f4 bytes by its caller.
    # This is a synthetic direct-constructor probe, not loaded App/UI proof.
    obj = vm.invoke(0x3954cc, (0x8f4,))
    try:
        result = vm.invoke(0x6a56d9, (obj, 0x7f135201, visual, caption), (0, 1, 0))
        for pointer, entry in vm.raw_allocations.items():
            vm.verify_guard(pointer, entry)
        row = {'constructor_returned': True, 'result': hex(result), 'object': hex(obj),
               'vtable': hex(vm.word(obj)), 'caption': vm.wide(vm.invoke(0x3927f5, (obj + 0x678,))),
               'caption_auxiliary': vm.word(obj + 0x688), 'id': vm.word(obj + 0x8f0),
               'flags': list(vm.uc.mem_read(obj + 0x544, 3)), 'allocation_guards_intact': True}
    except Exception as error:
        row = {'constructor_returned': False, 'error': str(error), 'recent': list(vm.recent),
               'invalid_accesses': vm.invalid_accesses, 'events': vm.events[-10:]}
    row.update({'device_io': False, 'sounds_emitted': False, 'synthetic_direct_constructor': True,
                'mapped_startup_zero_pages': vm.zero_pages})
    path = ROOT / 'staging/native-player-widget/development-probe.json'
    path.write_text(json.dumps(row, indent=2) + '\n')
    print(json.dumps(row))
    if not row['constructor_returned']:
        sys.exit(1)


if __name__ == '__main__':
    main()
