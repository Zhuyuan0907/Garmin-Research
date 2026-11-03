#!/usr/bin/env python3
"""Development probe of stock child clipping/painting; offline only.

Font/file/DB/heap/kernel endpoints inherit explicit fixtures. The default
catalog is synthetic; --load instead uses the preserved full outer loader.
No renderer, glyph rasterizer, display output or paint-success return is mocked.
This is a development probe and does not assert a full integration checkpoint.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import struct
import sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_player_external_fonts import ExternalFontVM, BUILD
from emulate_native_player_menu_selection import SQL_OUT
from emulate_native_player_menu_loaded import PLAYER_ID, SEED
from emulate_native_player_widget import CONTROL_CALLBACK
from emulate_native_vpm_filesystem import REGS, require

STAGE = ROOT/'staging/native-player-rendering'


class RenderingVM(ExternalFontVM):
    def __init__(self, stock, build):
        self.paint_active = False
        self.paint_entries = set()
        self.paint_calls = []
        self.paint_counts = Counter()
        self.pixel_span = None
        self.pixel_write_count = 0
        self.pixel_write_examples = []
        self.glyph_calls = []
        self.pending_glyph_calls = {}
        self.native_raster_calls = []
        super().__init__(stock, build)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.observe_pixels)

    def observe_pixels(self, uc, access, address, size, value, data):
        if self.paint_active and self.pixel_span and self.pixel_span[0] <= address < self.pixel_span[1]:
            self.pixel_write_count += 1
            if len(self.pixel_write_examples) < 32:
                self.pixel_write_examples.append(dict(address=hex(address),size=size,
                    value=hex(value),PC=hex(uc.reg_read(UC_ARM_REG_PC))))

    def observe(self, uc, address, size, data):
        if address in self.pending_glyph_calls:
            row=self.pending_glyph_calls.pop(address)
            row['native_returned_glyph_index']=uc.reg_read(REGS[0])
        if address==0x26849e:
            caller=uc.reg_read(UC_ARM_REG_LR)&~1
            require(caller not in self.pending_glyph_calls,'Unexpected recursive glyph caller')
            row=dict(context=hex(uc.reg_read(REGS[0])),unicode=uc.reg_read(REGS[1]),
                caller=hex(caller),original_entry=hex(address))
            self.glyph_calls.append(row);self.pending_glyph_calls[caller]=row
        if address in [0x4dd93e,0x4de302,0x26659e,0x13cf46,0x13d850,0x1370fa,0x14ec9c]:
            self.native_raster_calls.append(dict(entry=hex(address),arguments=[uc.reg_read(r)for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        if self.paint_active and address in self.paint_entries:
            self.paint_counts[hex(address)] += 1
            if len(self.paint_calls) < 256:
                args=[uc.reg_read(r) for r in REGS]
                self.paint_calls.append(dict(entry=hex(address),arguments=args,
                    caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

    def tree(self, obj, depth=0, seen=None):
        seen=set() if seen is None else seen
        require(obj not in seen and len(seen)<128 and depth<8,'Unexpected native tree cycle/size')
        seen.add(obj)
        vt=self.word(obj); paint=self.word(vt+8)
        self.paint_entries.add(paint&~1)
        row=dict(object=hex(obj),vtable=hex(vt),paint=hex(paint),parent=hex(self.word(obj+0x48)),
            frame=list(struct.unpack('<4i',self.uc.mem_read(obj+0x20,16))),
            scale_values=list(struct.unpack('<2f',self.uc.mem_read(obj+0x30,8))),
            flags84_85=list(self.uc.mem_read(obj+0x84,2)),child_count=self.word(obj+0x7c),children=[])
        head=self.word(obj+0x78)
        node=self.word(head) if head else 0
        nodes=set()
        while node and node!=head:
            require(node not in nodes and len(nodes)<128,'Invalid native child list')
            nodes.add(node);child=self.word(node+8)
            row['children'].append(self.tree(child,depth+1,seen))
            node=self.word(node)
        require(len(row['children'])==row['child_count'],'Native child inventory differs')
        return row


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),
        'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True)
    source=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
    im=NativeImage();vm=RenderingVM(im,json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        probe_source_sha256_before_run=source,device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,actual_display_or_installation_verified=False,
        synthetic_catalog_seed='--load' not in sys.argv)
    try:
        if '--load' in sys.argv:
            result['phase']='original_outer_loader';print(json.dumps(dict(phase=result['phase'])),flush=True)
            result['load']=vm.load()
        else:
            vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
            vm.put(vm.menu_records()[0]+84,CONTROL_CALLBACK|1)
        result['phase']='original_external_font_initialization'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.external_IO_active=True
        vm.invoke(0x4df249,());result['font_return']=vm.invoke(0x4de237,(1,))
        result['fonts']=vm.fonts()
        vm.invoke(0x395981,());vm.init_DB_fixture()
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,));vm.set_cell(12,PLAYER_ID,0)
        grid=vm.invoke(0x3954cc,(0x420,));vm.invoke(0x546c95,(grid,0));rows=vm.grid_rows(grid)
        widget=int(rows[11]['widget'],16)
        rect=SQL_OUT+0x500;vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,220))
        vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0))
        if '--load' in sys.argv:vm.invoke(0x54a4ed,(grid,))
        else:vm.invoke(vm.word(vm.word(widget)+39*4),(widget,0))
        vm.invoke(vm.word(vm.word(grid)+9*4),(grid,1))
        manager=vm.invoke(0x393a2d,(0,));canvas=vm.word(manager+0x44)
        result['native_tree_before']=vm.tree(grid)
        result['chosen_Widget']=hex(widget)
        result['canvas_before']=dict(object=hex(canvas),vtable=hex(vm.word(canvas)),
            words=[hex(vm.word(canvas+4*k))for k in range(48)],
            clip=list(struct.unpack('<4i',vm.uc.mem_read(canvas+0x3c,16))))
        buffers=[p for p,e in vm.raw_allocations.items() if e['length']==480*272*2]
        require(len(buffers)==1,'Unexpected native canvas allocation inventory')
        pixels=buffers[0]
        if '--white-background' in sys.argv:
            # Explicit diagnostic background, drawn by the original rectangle
            # painter/ARM pixel driver. Do not synthesize caption pixels.
            vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,272))
            color=SQL_OUT+0x550;vm.uc.mem_write(color,b'\xff'*4)
            vm.invoke(0x2db88b,(canvas,rect,color))
            result['background']=dict(original_rectangle_painter='0x2db88a',
                explicit_test_RGBA=[255,255,255,255],original_pixel_driver='0x3979e4',
                entire_buffer_white=bytes(vm.uc.mem_read(pixels,480*272*2))==b'\xff'*(480*272*2),
                host_wrote_pixel_buffer=False)
            require(result['background']['entire_buffer_white'],'Native diagnostic background failed')
        before=bytes(vm.uc.mem_read(pixels,480*272*2))
        vm.pixel_span=(pixels,pixels+len(before));font_start=len(vm.font_calls)
        vm.paint_entries.update([0x549baa,0x3766e4,0x4dd93e,0x4de302,0x26849e,0x6f63f4,
            0x2db816,0x2db88a,0x2db976,0x43866e,0x438672])
        result['phase']='before_original_Grid_paint';print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.paint_active=True;vm.invoke(vm.word(vm.word(grid)+8),(grid,canvas));vm.paint_active=False
        after=bytes(vm.uc.mem_read(pixels,len(before)))
        result.update(phase='original_Grid_paint_returned',completed=True,
            changed_bytes=sum(a!=b for a,b in zip(before,after)),pixel_buffer=hex(pixels),
            before_pixel_SHA256=hashlib.sha256(before).hexdigest(),after_pixel_SHA256=hashlib.sha256(after).hexdigest(),
            native_tree_after=vm.tree(grid),new_font_calls=vm.font_calls[font_start:])
        raw=STAGE/('loaded-canvas.bin' if '--load' in sys.argv else 'synthetic-canvas.bin')
        raw.write_bytes(after);result['raw_canvas_artifact']=str(raw.relative_to(ROOT))
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result['allocation_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr'],REGS+(UC_ARM_REG_LR,))})
    result.update(native_paint_call_counts=dict(vm.paint_counts),native_paint_calls=vm.paint_calls,
        native_pixel_write_count=vm.pixel_write_count,native_pixel_write_examples=vm.pixel_write_examples,
        original_font_calls_count=len(vm.font_calls),font_file_request_count=len(vm.external_file_requests),
        original_font_calls=vm.font_calls,
        native_glyph_calls_with_returns=vm.glyph_calls,native_raster_calls=vm.native_raster_calls,
        zero_pages=vm.zero_pages,original_conditional_writes=vm.conditional_region_writes)
    target=STAGE/('loaded-development-probe.json' if '--load' in sys.argv else 'synthetic-development-probe.json')
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k) for k in ['phase','completed','changed_bytes','native_pixel_write_count',
        'native_paint_call_counts','error','allocation_guards_intact']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)


if __name__=='__main__':main()
