#!/usr/bin/env python3
"""Development: original embedded-font initialization and Grid geometry.

Uses exact backup instructions/fonts. Stock heap/driver/cache inventories are
inherited fixtures; r0=0 explicitly asks the initializer to skip external
font names. No fabricated font metrics, glyph success, pixels or hardware I/O.
"""
import json
import hashlib
import struct
import sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from emulate_native_player_grid import GridVM
from emulate_native_player_widget import CONTROL_CALLBACK
from emulate_native_player_menu_selection import BUILD,SQL_OUT
from emulate_native_player_menu_loaded import PLAYER_ID,SEED
from emulate_native_vpm_filesystem import require,REGS


class TextVM(GridVM):
    def __init__(self,stock,build):
        self.font_calls=[]
        self.font_handles=set()
        self.font_release_records=[]
        self.font_pointer_queries=[]
        self.font_allocator_records=[]
        self.appearance_calls=[]
        self.appearance_pending={}
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address in self.appearance_pending:
            row=self.appearance_pending.pop(address)
            row['returned_state']=uc.reg_read(REGS[0])
            row['stock_output_objects_byte_unchanged']=all(
                bytes(uc.mem_read(pointer,length)).hex()==before
                for pointer,length,before in row['output_before'])
        if address==0x388804 and uc.reg_read(REGS[0]) in self.font_handles:
            self.font_pointer_queries.append({'original_pointer_query_entry':hex(address),
                'handle':hex(uc.reg_read(REGS[0])),'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        if address==0x1408b0:
            pointer=uc.reg_read(REGS[0])
            if pointer:
                handle=self.word(pointer-8)
                self.font_release_records.append({'original_free_entry':hex(address),
                    'user_pointer':hex(pointer),'handle':hex(handle),
                    'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        if address==0x14089a:
            handle=self.word(uc.reg_read(UC_ARM_REG_SP))
            require(handle in self.handles,'Original font malloc returned unknown handle')
            self.font_handles.add(handle)
            self.font_allocator_records.append({'original_post_allocate_PC':hex(address),'handle':hex(handle),
                'length':self.handles[handle]['length']})
        symbol=self.build['symbols'].get('native_player_menu_appearance')
        if symbol and address==symbol['address']:
            args=[uc.reg_read(r)for r in REGS];caller=uc.reg_read(UC_ARM_REG_LR)&~1
            require(caller in [0x315ba8,0x54a364] and caller not in self.appearance_pending,
                    'Unexpected original updater caller')
            row={'entry':hex(address),'arguments':args,'caller':hex(caller),'compiled_callback_executed':True,
                'output_before':[(p,n,bytes(uc.mem_read(p,n)).hex())for p,n in zip(args[1:],[56,20,4])]}
            self.appearance_calls.append(row);self.appearance_pending[caller]=row
        if address in [0x4df248,0x4de236,0x265f16,0x4de0e0,0x26707a,0x266d0e,0x26849e,0x140878]:
            self.font_calls.append({'entry':hex(address),'arguments':[uc.reg_read(r)for r in REGS],
                'caller':hex(uc.reg_read(UC_ARM_REG_LR)&~1)})
        return super().observe(uc,address,size,data)

    def verify_released(self):
        # Original388804 is a pointer-query wrapper;388B22 is BX LR. Neither
        # pins or unpins native heap memory. Keep exact fixture locks0 rather
        # than inventing lock1. Resident font contexts are not safely released.
        # Audit prefix/pointer-query/canaries, then all inherited non-font checks.
        handles=self.handles
        released={int(r['handle'],16)for r in self.font_release_records}
        inventory=[dict(handle=hex(h),**handles[h])for h in sorted(self.font_handles)]
        (ROOT/'staging/native-player-text/font-handle-ownership-development-probe.json').write_text(
            json.dumps({'handles':inventory,'original_free_calls':self.font_release_records,
                'original_pointer_queries':self.font_pointer_queries,'native_heap_pinning_proven':False,'device_io':False},indent=2)+'\n')
        live=set()
        for handle in self.font_handles:
            entry=handles[handle];p,n=entry['pointer'],entry['length']
            if entry['freed']:
                require(entry['locks']==0 and handle in released,'Font temporary handle not natively released')
            else:
                require(entry['locks']==0,'Font pointer-query fixture bookkeeping changed')
                require(any(int(r['handle'],16)==handle for r in self.font_pointer_queries),
                        'Original font pointer-query entry not executed')
                require(self.word(p)==handle and 0<self.word(p+4)<=n-8,'Native malloc prefix differs')
                live.add(handle)
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and
                    bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'Original font allocator guard changed')
        # Released font temporaries remain in the inherited ownership audit.
        # Only verified resident malloc allocations need a separate inventory.
        self.handles={h:e for h,e in handles.items()if h not in live}
        try:super().verify_released()
        finally:self.handles=handles

    def finish(self):
        result=super().finish()
        result['original_font_persistent_handles']=[dict(handle=hex(h),**self.handles[h])for h in sorted(self.font_handles)if not self.handles[h]['freed']]
        result['original_font_temporary_handles_released']=[dict(handle=hex(h),**self.handles[h])
            for h in sorted(self.font_handles)if self.handles[h]['freed']]
        result['original_font_free_calls']=self.font_release_records
        result['released_font_temporaries_keep_inherited_ownership_checks']=True
        result['original_font_pointer_queries']=self.font_pointer_queries
        result['original_font_resident_handles_fixture_locks0_prefixes_queries_and_canaries_verified']=True
        result['native_heap_pin_or_lock1_claim']=False
        result['inherited_outer_checks_retained_for_every_non_font_handle']=True
        return result

    def fonts(self):
        result=[]
        for n in range(13):
            metadata=0x14b3c60+64*n;record=0x14b4014+0x330*n;context=self.word(record)
            result.append({'index':n,'metadata':hex(metadata),'record':hex(record),
                'context':hex(context),'metadata_flags':list(self.uc.mem_read(metadata+0x3c,2)),
                'metadata_words34_38':[hex(self.word(metadata+0x34)),hex(self.word(metadata+0x38))],
                'name':self.ascii(metadata),'context_error':hex(self.word(context+0x24))if context else None,
                'source_metadata':hex(self.word(record+4))})
        return result


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build_path='staging/native-player-text/manifest.json' if '--full-load'in sys.argv else BUILD
    vm=TextVM(NativeImage(),json.loads((ROOT/build_path).read_text()))
    result={'device_io':False,'sounds_emitted':False,'original_embedded_fonts_used':True,
        'requested_initializer_parameter':0,'external_font_loading_requested':False,'synthetic_catalog_seed':True}
    try:
        if '--full-load'in sys.argv:
            result['phase']='before_original_loader';vm.load()
        result['phase']='before_font_static_initializer'
        vm.invoke(0x4df249,());result['phase']='before_font_runtime_initializer'
        status=vm.invoke(0x4de237,(0,));result.update(font_initializer_return=hex(status),fonts=vm.fonts(),
            current_context_record=hex(vm.word(0xf071f0)),phase='original_font_initializer_returned')
        vm.invoke(0x395981,())
        if '--full-load'not in sys.argv:
            vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
            vm.put(vm.menu_records()[0]+84,CONTROL_CALLBACK|1)
        vm.init_DB_fixture()
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,));vm.set_cell(12,PLAYER_ID,0)
        grid=vm.invoke(0x3954cc,(0x420,));vm.invoke(0x546c95,(grid,0));widget=int(vm.grid_rows(grid)[11]['widget'],16)
        result['Grid']={'object':hex(grid),'Widget':hex(widget),'rows':vm.grid_rows(grid)}
        result['phase']='before_native_Grid_geometry_API'
        rect=SQL_OUT+0x500;vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,220))
        vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0));result['phase']='native_Grid_geometry_API_returned'
        result['chosen_Widget_rectangle']=list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16)))
        result['chosen_Widget_state_before_refresh']=list(vm.uc.mem_read(widget+0xc8,3))
        if '--full-load'in sys.argv:
            result['phase']='before_stock_state_refresh';vm.invoke(0x54a4ed,(grid,))
            result['phase']='stock_state_refresh_returned'
        result['chosen_Widget_state']=list(vm.uc.mem_read(widget+0xc8,3))
        result['appearance_calls']=vm.appearance_calls
        if '--paint'in sys.argv:
            manager=vm.invoke(0x393a2d,(0,));canvas=vm.word(manager+0x44)
            vm.invoke(vm.word(vm.word(grid)+9*4),(grid,1))
            buffers=[p for p,e in vm.raw_allocations.items()if e['length']==480*272*2]
            require(len(buffers)==1,'Unexpected canvas buffer inventory')
            pixels=buffers[0];before=bytes(vm.uc.mem_read(pixels,480*272*2));calls=len(vm.font_calls)
            result['canvas']={'object':hex(canvas),'buffer':hex(pixels),'object_words':[hex(vm.word(canvas+4*k))for k in range(32)]}
            result['phase']='before_stock_Grid_paint';vm.invoke(vm.word(vm.word(grid)+8),(grid,canvas))
            result['phase']='stock_Grid_paint_returned'
            after=bytes(vm.uc.mem_read(pixels,480*272*2))
            result['paint_pixel_buffer_changed']=before!=after
            result['paint_changed_bytes']=sum(a!=b for a,b in zip(before,after))
            result['paint_font_calls']=vm.font_calls[calls:]
            (ROOT/'staging/native-player-text/development-canvas.bin').write_bytes(after)
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result.update(completed=True,allocation_guards_intact=True)
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={vm.uc.reg_name(r):hex(vm.uc.reg_read(r))for r in REGS+(UC_ARM_REG_LR,UC_ARM_REG_SP)})
    result.update(font_calls=vm.font_calls,original_conditional_writes=vm.conditional_region_writes,
        startup_zero_pages=vm.zero_pages,latest_small_heap=hex(vm.next_small))
    path=ROOT/'staging/native-player-text/development-probe.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items()if k not in ['font_calls','startup_zero_pages','Grid','fonts']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)


if __name__=='__main__':main()
