#!/usr/bin/env python3
"""Development: stock resource-backed Image setter, geometry and canvas paint.

Not a full checkpoint or installed player. Original64px MainMenu resource is
an explicit test input; stock boot mapping, controller and display are absent.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT
from emulate_native_player_external_fonts import BUILD
from emulate_native_vpm_filesystem import REGS,require
from probe_native_player_resources import ResourceVM,INPUT,STAGE,GIR

def main():
    source=Path(__file__).resolve();vm=ResourceVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest())
    try:
        vm.invoke(0x395981,());result['registration']=vm.register_stock_GIR()
        ref=INPUT+0x100;rect=INPUT+0x200;color=INPUT+0x220
        vm.invoke(0x3894ad,(ref,0x8a56eac))
        obj=vm.invoke(0x3954cc,(0x130,));result['object']=hex(obj)
        result['phase']='original_Image_constructor';print(json.dumps(dict(phase=result['phase'])),flush=True)
        returned=vm.invoke(0x361a4d,(obj,));require(returned==obj,'Original Image ctor returned other object')
        result['phase']='original_Image_resource_setter';print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.invoke(0x361aa5,(obj,ref,0,0))
        result['Image_words']=[hex(vm.word(obj+4*k))for k in range(76)]
        vm.uc.mem_write(rect,struct.pack('<4I',32,32,64,64))
        result['phase']='original_Image_geometry';print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.invoke(0x377ab9,(obj,rect,0,0),(0,0,0,0))
        manager=vm.invoke(0x393a2d,(0,));canvas=vm.word(manager+0x44)
        result['native_tree']=vm.tree(obj)
        buffers=[p for p,e in vm.raw_allocations.items()if e['length']==480*272*2]
        require(len(buffers)==1,'Canvas allocation inventory differs');pixels=buffers[0];length=480*272*2
        vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,272));vm.uc.mem_write(color,b'\xff'*4)
        vm.invoke(0x2db88b,(canvas,rect,color))
        before=bytes(vm.uc.mem_read(pixels,length));require(before==b'\xff'*length,'Native white background failed')
        vm.pixel_span=(pixels,pixels+length);vm.paint_entries.update([0x3620e4,0x2dba3e,0x41b9bc,0x6f63f4])
        result['phase']='original_Image_paint';print(json.dumps(dict(phase=result['phase'])),flush=True)
        vm.paint_active=True;vm.invoke(vm.word(vm.word(obj)+8),(obj,canvas));vm.paint_active=False
        after=bytes(vm.uc.mem_read(pixels,length));values=struct.unpack('<130560H',after)
        points=[(n%480,n//480)for n,v in enumerate(values)if v!=0xffff]
        result.update(completed=True,native_pixel_writes=vm.pixel_write_count,
            changed_pixels=len(points),changed_bytes=sum(a!=b for a,b in zip(before,after)),
            pixel_bounds=([min(x for x,y in points),min(y for x,y in points),max(x for x,y in points),max(y for x,y in points)]if points else None),
            after_canvas_sha256=hashlib.sha256(after).hexdigest(),
            actual_framebuffer_or_display=False,host_wrote_pixel_buffer=False)
        (STAGE/'Image-development-canvas.bin').write_bytes(after)
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result['allocation_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC))})
    result.update(resource_calls=vm.resource_calls,native_paint_calls=vm.paint_calls,
        conditional_writes=vm.conditional_region_writes,
        readonly_GIR_unchanged=bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes)
    path=STAGE/'Image-development-probe.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','changed_pixels','pixel_bounds','native_pixel_writes']}),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
