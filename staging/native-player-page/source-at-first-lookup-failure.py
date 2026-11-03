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
from emulate_native_player_menu_selection import BUILD, SQL_OUT
from emulate_native_player_menu_loaded import PLAYER_ID, SEED
from emulate_native_vpm_filesystem import require


class PageVM(WidgetVM):
    def __init__(self, stock, build):
        self.page_writes = []
        self.watch = None
        super().__init__(stock, build)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.record_page_write)

    def record_page_write(self, uc, access, address, size, value, data):
        if self.watch and self.watch[0] <= address < self.watch[1]:
            self.page_writes.append({'offset': hex(address - self.watch[0]),
                'size': size, 'value': hex(value), 'PC': hex(uc.reg_read(UC_ARM_REG_PC))})


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
        result['phase'] = 'construct_normal_Widget'
        row = vm.normal_lookup(15, 0)
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
                  events=vm.events[-15:])
    path = ROOT / 'staging/native-player-page/development-probe.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['page_writes','zero_pages']}, ensure_ascii=False), flush=True)
    if not result.get('page_and_input_completed'):
        sys.exit(1)


if __name__ == '__main__':
    main()
