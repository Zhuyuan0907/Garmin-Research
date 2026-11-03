#!/usr/bin/env python3
"""Development probe for stock CustomMainMenuGrid automatic population.

Direct original ctor calls and DB/platform fixtures; no device operations.
"""
from datetime import datetime,timezone
import json
import struct
import sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT
from emulate_native_player_page import PageVM
from emulate_native_player_widget import CONTROL_CALLBACK
from emulate_native_player_menu_selection import BUILD,SQL_OUT
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_vpm_filesystem import require,REGS


class GridVM(PageVM):
    def __init__(self,stock,build):
        self.setter_callers=[]
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address==0x316276:
            self.setter_callers.append({'arguments':[uc.reg_read(r)for r in REGS],
                'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        return super().observe(uc,address,size,data)

    def grid_rows(self,grid):
        begin,end=self.word(grid+0xcc),self.word(grid+0xd0)
        require(end>=begin and (end-begin)%72==0,'Invalid original Grid row vector')
        result=[]
        for n in range((end-begin)//72):
            address=begin+n*72;widget=self.word(address)
            result.append({'row':n,'address':hex(address),'widget':hex(widget),
                'vtable':hex(self.word(widget))if widget else None,
                'parent':hex(self.word(widget+0x48))if widget else None,
                'words':[hex(self.word(address+4*k))for k in range(18)]})
        return result


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),
            'Use isolated Unicorn2.1.4')
    vm=GridVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    vm.invoke(0x395981,())
    vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
    vm.put(vm.menu_records()[0]+84,CONTROL_CALLBACK|1)
    vm.init_DB_fixture()
    result={'device_io':False,'sounds_emitted':False,'synthetic_catalog_seed':True}
    try:
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,))
        result['Page_ctor_setter_callers']=vm.setter_callers[:]
        vm.set_cell(12,PLAYER_ID,0)
        before=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
        grid=vm.invoke(0x3954cc,(0x420,))
        result['phase']='before_Grid_constructor';result['grid']=hex(grid)
        returned=vm.invoke(0x546c95,(grid,1 if '--mode1'in sys.argv else 0))
        result.update(phase='Grid_constructor_returned',returned=hex(returned),
            vtable=hex(vm.word(grid)),child_count=vm.word(grid+0x7c),
            row_limit=vm.word(grid+0xe4),rows=vm.grid_rows(grid),
            DB_rows_unchanged_after_Grid=before==list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result.update(allocation_guards_intact=True,completed=True)
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses)
    result.update(events=vm.events[-10:],original_conditional_writes=vm.conditional_region_writes,
        latest_raw_pointer=hex(vm.next_raw))
    path=ROOT/'staging/native-player-grid/development-probe.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items()if k not in['rows','Page_ctor_setter_callers']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)


if __name__=='__main__':main()
