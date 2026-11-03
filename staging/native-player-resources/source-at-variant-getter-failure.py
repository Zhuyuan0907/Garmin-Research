#!/usr/bin/env python3
"""Development only: register unchanged appended GIR with stock instructions.

GIR placement in mapped read-only guest memory is an explicit inventory input,
not a recovered boot map. Resource constructors/resolver are never hooked.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_PC
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_player_external_fonts import BUILD
from probe_native_player_rendering import RenderingVM
from emulate_native_vpm_filesystem import REGS,require
from analyze_native_player_resources import STAGE,RESOURCE_LOAD

GIR=0x09600000
INPUT=0x09700020

class ResourceVM(RenderingVM):
    def __init__(self,stock,build):
        self.resource_calls=[]
        super().__init__(stock,build)
        n=stock.word(RESOURCE_LOAD+28)
        self.resource_bytes=stock.read(RESOURCE_LOAD,n)
        self.uc.mem_map(GIR,(n+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(GIR,self.resource_bytes)
        self.uc.mem_protect(GIR,(n+4095)&~4095,unicorn.UC_PROT_READ)
        self.uc.mem_map(0x09700000,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address in [0x3894ac,0x3894b4,0x3894f0,0x389530,0x389544,0x389556,
            0x3895c2,0x41c3da,0x41c298,0x41cc46,0x41d31c,0x41c91c]:
            self.resource_calls.append(dict(entry=hex(address),arguments=[uc.reg_read(r)for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

    def register_stock_GIR(self):
        platform=self.invoke(0x25dc81,())
        require(platform==struct.unpack_from('<I',self.resource_bytes,12)[0],'Original resource platform check differs')
        self.uc.mem_write(INPUT,b'\xcc'*128)
        accepted=self.invoke(0x41cc47,(GIR,INPUT))
        require(accepted==1,'Original GIR registration rejected')
        catalog=self.invoke(0x41b15b,());begin,end,capacity=struct.unpack('<3I',self.uc.mem_read(catalog,12))
        require(end-begin==24 and capacity>=end,'Original GIR catalog not one record')
        kind=self.uc.mem_read(INPUT,1)[0];record=bytes(self.uc.mem_read(begin,24))
        require(record[0]==kind and record[1]==1 and self.word(begin+12)==GIR and
            self.word(begin+16)==len(self.resource_bytes),'Original GIR catalog source fields differ')
        return dict(original_entry='0x41cc46',accepted=accepted,platform_hash=hex(platform),
            catalog=hex(catalog),kind=kind,record=hex(begin),record_words=[hex(x)for x in struct.unpack('<6I',record)],
            mapped_stock_bytes_sha256=hashlib.sha256(self.resource_bytes).hexdigest(),
            original_boot_resource_registration_location_verified=False,host_seeded_catalog=False,
            appended_stock_GIR_placement_is_explicit_fixture=True)

def main():
    require(unicorn.__version__=='2.1.4','Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_integration_checkpoint=False)
    vm=ResourceVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    try:
        result['phase']='original_stock_GIR_registration'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        result['registration']=vm.register_stock_GIR()
        ref=INPUT+0x100;out=INPUT+0x200
        vm.invoke(0x3894ad,(ref,0x8a56eac));vm.uc.mem_write(out,b'\xcc'*128)
        result['phase']='original_ResourceRef_resolver'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        success=vm.invoke(0x3895c3,(ref,out))
        result['resolution']=dict(success=success,reference_words=[hex(vm.word(ref+4*n))for n in range(2)],
            descriptor_words=[hex(vm.word(out+4*n))for n in range(21)],guard_tail_unchanged=bytes(vm.uc.mem_read(out+84,44))==b'\xcc'*44)
        require(success==1 and vm.word(out)==0x8a56eac and vm.word(out+72)==64 and vm.word(out+76)==64,
            'Original descriptor hash/dimensions differ')
        result.update(completed=True,native_nonempty_image_resource_resolved=True,
            native_nonempty_icon_rendering_verified=False)
        for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
        result['allocation_guards_intact']=True
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC))})
    result.update(resource_calls=vm.resource_calls,conditional_writes=vm.conditional_region_writes,
        readonly_GIR_unchanged=bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes)
    target=STAGE/'registration-development-probe.json';target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','registration','resolution']}),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
