#!/usr/bin/env python3
"""Scoped opaque-handle translation into explicit native descriptor fixtures.

Original388E92 validation,388804 query and388AF4 registration execute.
This is not a real heap allocator or callback/lifetime scheduler.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from probe_native_mainmenu_context import ContextVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import SEED,PLAYER_ID
from emulate_native_vpm_filesystem import REGS,RETURN,require

STAGE=ROOT/'staging/native-player-heap-callback'
BASE=0x10a00000

class HeapDescriptorVM(ContextVM):
    def __init__(self,stock,build):
        self.heap_descriptors={};self.heap_descriptor_entries=[];self.native_heap_validation_returns=[]
        self.heap_registration_writes=[];self.allow_direct_descriptor_controls=False
        super().__init__(stock,build)
        self.uc.mem_map(BASE,0x100000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_descriptor_write,begin=BASE,end=BASE+0xfffff)

    def descriptor(self,handle):
        entry=self.handles[handle];require(not entry['freed'],'Descriptor query of released opaque fixture handle')
        require(entry['pointer']&7==0,'Payload fixture pointer is not eight-byte aligned')
        if handle not in self.heap_descriptors:
            require(len(self.heap_descriptors)<1024,'Finite descriptor fixture inventory exhausted')
            pointer=BASE+32+128*len(self.heap_descriptors)
            self.uc.mem_write(pointer-32,b'\xa5'*96);self.uc.mem_write(pointer,b'\0'*32)
            self.put(pointer+4,entry['pointer']|4);self.put(pointer+8,pointer+16);self.put(pointer+16,pointer)
            self.heap_descriptors[handle]=pointer
        pointer=self.heap_descriptors[handle]
        require(self.word(pointer+4)&~7==entry['pointer'],'Descriptor payload pointer changed')
        return pointer

    def observe_descriptor_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        require(pc in [0x388b0c,0x388b14]and size==4,'Unexpected native descriptor write')
        owner=next((p for p in self.heap_descriptors.values()if p<=address<p+32),None)
        require(owner is not None and address-owner in [4,12],'Descriptor write outside original fields')
        self.heap_registration_writes.append(dict(address=hex(address),descriptor=hex(owner),offset=address-owner,
            value=hex(value),original_writer_PC=hex(pc)))

    def observe(self,uc,address,size,data):
        if address==0x388e92:
            opaque=uc.reg_read(REGS[0]);caller=uc.reg_read(UC_ARM_REG_LR)&~1
            if opaque in self.heap_descriptors.values():
                require(self.allow_direct_descriptor_controls and caller==RETURN,'Unexpected direct descriptor caller')
                translated=opaque;kind='explicit_direct_descriptor_control'
            else:
                require(caller in [0x38881a,0x388b0c],'Unexpected native heap descriptor caller')
                translated=self.descriptor(opaque);kind='opaque_storage_handle_to_descriptor_fixture'
            self.heap_descriptor_entries.append(dict(original_validation_entry=hex(address),caller=hex(caller),
                opaque_handle=hex(opaque),descriptor=hex(translated),translation=kind,
                original_validation_body_executed=True,host_returned_validation_success=False,
                fields_before=[hex(self.word(translated+4*n))for n in range(5)]))
            uc.reg_write(REGS[0],translated)
            # Leave PC/SP/LR untouched. Run the original validator, including
            # invalid descriptor branches, instead of the inherited hook.
            self.visits[address]+=1;return
        if address==0x388ec2:
            self.native_heap_validation_returns.append(dict(original_success_branch=hex(address),
                descriptor=hex(uc.reg_read(REGS[0]))))
        return super().observe(uc,address,size,data)

    def verify_descriptor_guards(self):
        for h,p in self.heap_descriptors.items():
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+32,32))==b'\xa5'*32,
                'Descriptor fixture canary changed')
            require(self.word(p+4)&~7==self.handles[h]['pointer']and self.word(p+8)==p+16 and self.word(p+16)==p,
                'Stable descriptor pointer/backlink changed')

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve();vm=HeapDescriptorVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_integration_checkpoint=False)
    try:
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR();vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.invoke(0x4a388b,());vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(vm.menu_records()[0]+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0);vm.supply_setting_record(1)
        obj=vm.invoke(0x3954cc,(0x3f04,));result['object']=hex(obj)
        print(json.dumps(dict(phase='before_original_MainMenu_with_native_heap_validation')),flush=True)
        value=vm.invoke(0x40434d,(obj,1));vm.verify_descriptor_guards()
        result.update(completed=True,constructor_returned=hex(value),native_tree=vm.tree(obj))
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(heap_descriptor_entries=vm.heap_descriptor_entries,native_heap_validation_returns=vm.native_heap_validation_returns,
        heap_registration_writes=vm.heap_registration_writes,conditional_writes=vm.conditional_region_writes,
        native_fatal_entries=vm.native_fatal_entries,original_main_entries=vm.main_entries)
    (STAGE/'general-menu-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),heap_queries=len(vm.heap_descriptor_entries))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
