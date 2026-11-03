#!/usr/bin/env python3
"""Development probes for original custom-menu Page construction; offline only.

This subclass preserves frozen Widget/loader proofs. No GUI callback, capture
flag, page or synthetic successful return is invented for the Page constructor.
"""
from pathlib import Path
import json
import struct
import sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT
from emulate_native_player_widget import WidgetVM, CONTROL_CALLBACK
from emulate_native_player_menu_selection import BUILD, SQL_OUT, SelectionPlayerVM
from emulate_native_player_menu_loaded import PLAYER_ID, SEED
from emulate_native_vpm_filesystem import require
from emulate_native_vpm_filesystem import REGS


class PageVM(WidgetVM):
    def __init__(self, stock, build):
        self.page_writes = []
        self.watch = None
        self.wake_boundaries = []
        self.native_setter_calls = []
        super().__init__(stock, build)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.record_page_write)

    def record_page_write(self, uc, access, address, size, value, data):
        if self.watch and self.watch[0] <= address < self.watch[1]:
            self.page_writes.append({'offset': hex(address - self.watch[0]),
                'size': size, 'value': hex(value), 'PC': hex(uc.reg_read(UC_ARM_REG_PC))})

    def observe(self, uc, address, size, data):
        if address == 0x316276:
            self.native_setter_calls.append({'arguments': [uc.reg_read(r) for r in REGS],
                                            'PC': hex(address)})
        if address == 0x2fcf44:
            # OS wake service needs a live kernel/current thread absent here.
            # Only acknowledge the boundary; never deliver events/callbacks or
            # set Widget flags. All GUI dispatch beyond it remains stock code.
            self.visits[address] += 1
            self.wake_boundaries.append([uc.reg_read(r) for r in REGS])
            self.ret(0)
            return
        return super().observe(uc, address, size, data)

    def finish(self):
        # Two original once-initialization words in this data copy. Preserve
        # frozen WidgetVM's narrower one-word proof; independently compare the
        # entire region here with exactly these stock385450 writes permitted.
        base = 0x05400000
        flags = [0x0551c80c, 0x0551c7f4]
        before = self.initial_regions[base]
        expected = bytearray(before)
        for flag in flags:
            offset = flag - base
            require(before[offset:offset + 4] == b'\0' * 4, 'Original Page guard word not zero')
            expected[offset:offset + 4] = struct.pack('<I',1)
        writers = [{'address':hex(flag),'size':4,'value':'0x1','PC':'0x385450'}for flag in flags]
        require(self.conditional_region_writes == writers, 'Unexpected original Page initialized-data writer')
        require(bytes(self.uc.mem_read(base,len(before))) == bytes(expected),
                'Page conditional region differs beyond two native guard words')
        self.initial_regions[base] = bytes(expected)
        try:
            snapshot = SelectionPlayerVM.finish(self)
        finally:
            self.initial_regions[base] = before
        snapshot['original_GUI_initialized_data_mutations'] = [
            {'address':hex(flag),'word_before':0,'word_after':1,'writer_PC':'0x385450',
             'original_instruction_executed':True,'guest_memory_rewritten_by_test':False}for flag in flags]
        snapshot['full_conditional_data_region_matches_two_native_word_allowances'] = True
        return snapshot


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
            'Use the validated isolated Unicorn runtime')
    vm = PageVM(NativeImage(), json.loads((ROOT / BUILD).read_text()))
    vm.invoke(0x395981, ())
    vm.put(SEED + 0x110, 0)
    vm.seed_control(PLAYER_ID, 'Pi 播放器', 0x13528000)
    vm.put(vm.menu_records()[0] + 84, CONTROL_CALLBACK | 1)
    vm.init_DB_fixture()
    vm.set_cell(15, PLAYER_ID, 0)
    result = {'device_io': False, 'sounds_emitted': False,
              'catalog_seed_is_synthetic_control': True}
    try:
        obj = vm.invoke(0x3954cc, (0x7c4,))
        vm.watch = (obj, obj + 0x7c4)
        result['page_allocation'] = hex(obj)
        returned = vm.invoke(0x5a2995, (obj,))
        result.update(constructor_returned=True, returned=hex(returned),
                      vtable=hex(vm.word(obj)))
        result['registry_after_constructor'] = {'pointer': hex(vm.menu_pointer()),
            'DB': hex(vm.word(vm.menu_pointer() + 24)),
            'loaded': vm.uc.mem_read(vm.menu_pointer() + 28, 1)[0],
            'records': [{'id': hex(vm.word(x)), 'callback': hex(vm.word(x + 84))}
                        for x in vm.menu_records()],
            'cell15': list(vm.db.execute('SELECT icon,size FROM custom_table WHERE id=15'))}
        result['phase'] = 'construct_normal_Widget'
        vm.init_DB_fixture()
        vm.set_cell(15, PLAYER_ID, 0)
        row = vm.normal_lookup(15, 0)
        require(row['matched'] == 1 and int(row['widget'], 16) != 0, 'Player lookup is absent')
        widget = int(row['widget'], 16)
        result['widget'] = row
        vm.watch = (widget, widget + 0x550)
        vm.page_writes = []
        # Original setting APIs; the sound selector36 skips the optional click
        # sound wait. This is explicitly a test setting, not the stock default.
        vm.invoke(vm.word(vm.word(widget) + 39 * 4), (widget, 0))
        vm.invoke(0x27abf9, (widget, 0x36))
        result['phase'] = 'attach_Widget_with_original_parent_API'
        vm.invoke(0x37707b, (obj, widget))
        require(vm.word(widget + 0x48) == obj, 'Original parent assignment differs')
        result['original_page_child_count'] = vm.word(obj + 0x7c)
        vm.invoke(vm.word(vm.word(obj) + 9 * 4), (obj, 1))
        result['visibility'] = {'page': list(vm.uc.mem_read(obj + 0x84, 2)),
                                'widget': list(vm.uc.mem_read(widget + 0x84, 2))}
        # Explicit layout/input payload fixtures, not recovered screen pixels
        # or actual Page layout. Original parent and Widget dispatch execute.
        vm.uc.mem_write(obj + 0x20, struct.pack('<4I', 0, 0, 480, 272))
        vm.uc.mem_write(widget + 0x20, struct.pack('<4I', 100, 200, 100, 40))
        event = SQL_OUT + 0x400
        vm.uc.mem_write(event, b'\0' * 64)
        vm.put(event + 0x10, 150)
        vm.put(event + 0x14, 220)
        result['phase'] = 'synthetic_page_input'
        result['event_results'] = []
        for action in [0, 1, 2]:
            vm.uc.mem_write(event + 0x28, bytes([action]))
            before = len(vm.control_clicks)
            value = vm.invoke(vm.word(vm.word(obj) + 16), (obj, event))
            result['event_results'].append({'action': action, 'returned': hex(value),
                'callbacks_added': len(vm.control_clicks) - before,
                'state': list(vm.uc.mem_read(widget + 0xc8, 3))})
        result['phase'] = 'page_input_returned'
        for pointer, entry in vm.raw_allocations.items():
            vm.verify_guard(pointer, entry)
        result['allocation_guards_intact'] = True
        result['page_and_input_completed'] = True
    except Exception as error:
        result.update(page_and_input_completed=False, error=str(error),
                      invalid_accesses=vm.invalid_accesses, recent=list(vm.recent))
    result.update(page_writes=vm.page_writes, zero_pages=vm.zero_pages,
                  events=vm.events[-15:], wake_service_boundaries=vm.wake_boundaries,
                  original_SQL_setter_entries=vm.native_setter_calls)
    result['conditional_region_differences'] = []
    for base,before in vm.initial_regions.items():
        after = bytes(vm.uc.mem_read(base,len(before)))
        if before != after:
            result['conditional_region_differences'].append({'base':hex(base),
                'changed_bytes':[{'address':hex(base+n),'before':a,'after':b}
                                 for n,(a,b) in enumerate(zip(before,after)) if a!=b]})
    result['conditional_region_writes'] = vm.conditional_region_writes
    path = ROOT / 'staging/native-player-page/development-probe.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['page_writes','zero_pages']}, ensure_ascii=False), flush=True)
    if not result.get('page_and_input_completed'):
        sys.exit(1)


if __name__ == '__main__':
    main()
