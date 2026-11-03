#!/usr/bin/env python3
"""Development probe for stock Widget construction; never accesses a device."""
from collections import deque
import json
from pathlib import Path
import sys
import unicorn
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_CP_REG,
                              UC_ARM_REG_FPEXC, UC_ARM_REG_FPSCR, UC_ARM_REG_SP)
from analyze_native_sections import NativeImage, ROOT
from emulate_native_player_menu_selection import SelectionPlayerVM, BUILD, SQL_OUT
from emulate_native_vpm_filesystem import REGS, require
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_player_menu_selection import SQL_OUT


class WidgetVM(SelectionPlayerVM):
    def __init__(self, stock, build):
        self.recent = deque(maxlen=32)
        self.invalid_accesses = []
        self.zero_pages = []
        super().__init__(stock, build)
        self.sql_hooks.pop(0x315b64)
        # Supply virtual CP10/11 access, as in the earlier exact volume-math
        # experiment. Original GUI geometry VFP instructions execute normally.
        self.uc.reg_write(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 2, 0xf << 20))
        self.uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
        self.uc.reg_write(UC_ARM_REG_FPSCR, 0)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self.invalid_memory)

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
        self.invoke(0x39272b, (label,))
        self.put(label + 16, 0)
        # Actual fifth factory argument is forwarded from getter r3; the stock
        # factory handles0/1. Old boundary-only probe used opaque0x1352 instead.
        result = self.invoke(0x315f17, (self.menu_pointer(), cell, SQL_OUT + 0x80, style),
                             (label, icon, size, info))
        widget = self.word(SQL_OUT + 0x80)
        row = {'matched': result, 'widget': hex(widget), 'widget_control_block': hex(self.word(SQL_OUT + 0x84)),
               'caption': self.wide(self.invoke(0x3927f5, (label,))), 'factory_fifth_argument': style}
        self.invoke(0x392773, (label,))
        return row


def main():
    build = json.loads((ROOT / BUILD).read_text())
    vm = WidgetVM(NativeImage(), build)
    # Initialize the original GUI timer-list object using its exact constructor.
    # Boot ordering and physical OS/event delivery are still outside this probe.
    vm.invoke(0x395981, ())
    if '--loaded-normal' in sys.argv:
        loaded = vm.load()
        vm.init_DB_fixture()
        vm.set_cell(15, PLAYER_ID, 0)
        try:
            row = vm.normal_lookup(15)
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
