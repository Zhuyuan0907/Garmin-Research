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
from emulate_native_player_menu_selection import BUILD,SQL_OUT,DB,SQL_BASE
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_vpm_filesystem import require,REGS


class GridVM(PageVM):
    def __init__(self,stock,build):
        self.setter_callers=[]
        self.next_small=0x08800020
        super().__init__(stock,build)
        # Additional guarded virtual C++ heap; separate from every inherited
        # file/SQL/output/stack fixture. This is no physical free-RAM claim.
        self.uc.mem_map(0x08800000,0x400000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address==0x316276:
            self.setter_callers.append({'arguments':[uc.reg_read(r)for r in REGS],
                'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        if address==0x3162f2:
            self.setter_callers.append({'reset15_entry':hex(address),
                'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        if self.menu_hooks.get(address)=='raw_allocate':
            self.visits[address]+=1
            length=uc.reg_read(REGS[0]);require(0<length<0x10000,'Unexpected C++ allocation length')
            pointer=self.next_small;self.next_small+=(length+127)&~63
            require(self.next_small<0x08c00000,'Separate Grid C++ heap exhausted')
            uc.mem_write(pointer-32,b'\xa5'*(length+64))
            self.raw_allocations[pointer]={'length':length,'freed':False,'service':hex(address)}
            self.events.append({'allocate':length,'pointer':hex(pointer),'separate_CXX_heap_fixture':True})
            self.ret(pointer);return
        if address==0x2b4d70 and self.ascii(uc.reg_read(REGS[1]))=='SELECT id, icon FROM custom_table WHERE size = ?':
            self.visits[address]+=1
            args=[uc.reg_read(r)for r in REGS]
            require(args[0]==DB and args[2]==0xffffffff,'Unexpected Grid query prepare ABI')
            sql=self.ascii(args[1]);statement=SQL_BASE+0x200+len(self.statements)*0x40
            require(statement+0x40<SQL_BASE+0x4000,'Grid statement inventory exhausted')
            self.put(statement,DB);self.put(args[3],statement)
            self.statements[statement]={'sql':sql,'bound':{},'cursor':None,'row':None,'closed':False}
            self.sql_events.append({'operation':'prepare_engine_fixture','SQL':sql,'statement':hex(statement),
                'additional_size_query_uses_same_real_host_SQLite':True})
            self.ret(0);return
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
        rows=result['rows'];chosen=rows[11];widget=int(chosen['widget'],16)
        result['chosen_row']=dict(chosen,caption=vm.wide(vm.invoke(0x3927f5,(int(chosen['address'],16)+0x1c,))),
            state=list(vm.uc.mem_read(widget+0xc8,3)),click_signal=hex(vm.word(widget+0x88)),
            rectangle=list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16))))
        result['phase']='before_Grid_geometry_API'
        manager=vm.invoke(0x393a2d,(0,));canvas=vm.word(manager+0x44)
        result['canvas']={'pointer':hex(canvas),'vtable':hex(vm.word(canvas)),
                          'manager':hex(manager),'manager_virtual2':hex(vm.word(vm.word(manager)+8))}
        # Outer containing frame is supplied explicitly; stock geometry setter
        # and Grid virtual3 are tested separately from rendering/display.
        rect=SQL_OUT+0x500;vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,220))
        vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0))
        result['phase']='before_Grid_virtual3'
        vm.invoke(vm.word(vm.word(grid)+12),(grid,canvas))
        result['phase']='Grid_virtual3_returned'
        result['chosen_rectangle_after_virtual3']=list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16)))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result.update(allocation_guards_intact=True,completed=True)
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses)
    result.update(events=vm.events[-10:],original_conditional_writes=vm.conditional_region_writes,
        latest_raw_pointer=hex(vm.next_raw),latest_separate_CXX_heap_pointer=hex(vm.next_small))
    path=ROOT/'staging/native-player-grid/development-probe.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items()if k not in['rows','Page_ctor_setter_callers']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)


if __name__=='__main__':main()
