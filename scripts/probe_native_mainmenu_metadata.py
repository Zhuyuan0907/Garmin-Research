#!/usr/bin/env python3
"""Original consumer-default metadata reads on an explicit lower inventory.

No hardware factory data is reconstructed. Missing storage returns nonzero
and leaves outputs untouched; the original caller decides its fallback.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from probe_native_settings_writer import SettingsVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import SEED,PLAYER_ID
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu-metadata'
HEADER_CALLERS={139:0x35d454,140:0x35d482,141:0x35d4e0,142:0x35d512,143:0x35d542}
BODY_CALLERS={139:{0x35d476},140:{0x35d49a,0x35d4cc},141:{0x35d506},142:{0x35d536},143:{0x35d564}}
MAX_BODY_BYTES={139:34,140:32,141:336,142:560,143:176}
PROFILE_TABLE=0x2cf443c
DRIVER=0x18401000

class MetadataVM(SettingsVM):
    def __init__(self,stock,build):
        self.consumer_metadata_inventory={n:None for n in HEADER_CALLERS}
        self.consumer_metadata_reads=[];self.consumer_metadata_entries=[]
        self.native_bank_lookup_entries=[];self.active_metadata_request=None
        super().__init__(stock,build)
        require(any(z['runtime_start']<=0x2cf4000 and 0x2cf5000<=z['runtime_end']for z in stock.zeros),
            'Consumer profile table lacks original startup-zero BSS range')
        if not any(a<=0x2cf4000 and 0x2cf4fff<=b for a,b,_ in self.uc.mem_regions()):self.uc.mem_map(0x2cf4000,4096)
        require(bytes(self.uc.mem_read(PROFILE_TABLE,24))==b'\0'*24,'Consumer storage profiles not initially empty')
        self.uc.mem_map(0x18400000,0x2000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(DRIVER,b'\x70\x47')
        self.uc.mem_protect(DRIVER,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.driver_inventory_snapshot=None

    def install_inventory(self,inventory):
        require(set(inventory)==set(HEADER_CALLERS),'Unexpected consumer inventory bank set')
        self.consumer_metadata_inventory=inventory
        self.uc.mem_write(PROFILE_TABLE,b'\0'*24)
        self.uc.mem_write(0x18400000,b'\xa5'*4096)
        present=[n for n in HEADER_CALLERS if inventory[n]is not None]
        if present:
            profile=0x18400020;rows=0x18400100;vtable=0x18400200
            self.uc.mem_write(profile,b'\0'*32);self.put(profile+4,rows);self.put(profile+8,vtable)
            self.uc.mem_write(rows,b'\0'*(8*(len(present)+1)))
            for i,n in enumerate(present):self.uc.mem_write(rows+8*i,bytes([n]))
            self.uc.mem_write(rows+8*len(present),b'\xff')
            self.uc.mem_write(vtable,b'\0'*16);self.put(vtable+12,DRIVER|1);self.put(PROFILE_TABLE,profile)
        self.driver_inventory_snapshot=bytes(self.uc.mem_read(0x18400000,4096))

    def observe(self,uc,address,size,data):
        if address==0x26a300 and uc.reg_read(REGS[0])in HEADER_CALLERS:
            bank,offset,length,destination=[uc.reg_read(r)for r in REGS];caller=uc.reg_read(UC_ARM_REG_LR)&~1
            header=offset==0
            require((header and caller in [HEADER_CALLERS[bank]]+([0x2363c8]if bank==140 else[])and length==8)or
                (offset==8 and caller in BODY_CALLERS[bank]and length>0),
                'Unexpected consumer metadata lower-read ABI')
            require(self.active_metadata_request is None,'Overlapping consumer metadata requests')
            self.consumer_metadata_reads.append(dict(bank=bank,offset=offset,requested_bytes=length,destination=hex(destination),
                original_caller=hex(caller),operation='header'if header else'body',
                original_generic_read_body_executed=True,host_returned_generic_read_success=False,
                physical_factory_metadata_or_device_read=False))
            self.active_metadata_request=len(self.consumer_metadata_reads)-1
            # Skip the inherited high-level settings-only read hook, keeping
            # PC/SP/LR untouched. Run original26A300 AND26A240 bank lookup.
            self.visits[address]+=1;return
        if address==0x26a240 and self.active_metadata_request is not None:
            require((uc.reg_read(UC_ARM_REG_LR)&~1)==0x26a312,'Unexpected original metadata lookup caller')
            self.native_bank_lookup_entries.append(dict(original_entry=hex(address),bank=uc.reg_read(REGS[0]),
                original_body_executed=True,host_replaced_lookup_return=False))
        if address==DRIVER:
            require(self.active_metadata_request is not None and (uc.reg_read(UC_ARM_REG_LR)&~1)==0x26a332,
                'Unexpected lower consumer driver caller')
            row=self.consumer_metadata_reads[self.active_metadata_request]
            profile,record,offset,length=[uc.reg_read(r)for r in REGS];destination=self.word(uc.reg_read(UC_ARM_REG_SP))
            bank=uc.mem_read(record,1)[0];blob=self.consumer_metadata_inventory[bank]
            require(profile==0x18400020 and bank==row['bank']and offset==row['offset']and destination==int(row['destination'],16),
                'Native generic driver dispatch arguments differ')
            # Original wrapper normalizes negative signed byte counts before
            # this lower boundary. Only bounded supplied bytes may be copied.
            available=blob is not None and 0<length<=560 and offset+length<=len(blob)
            if available:uc.mem_write(destination,blob[offset:offset+length])
            row.update(normalized_driver_bytes=length,explicit_lower_status=0 if available else 1,
                output_written=available,invalid_or_unavailable_output_left_unchanged=not available,
                original_profile_lookup_and_indirect_driver_dispatch=True)
            self.visits[address]+=1;self.ret(0 if available else 1);return
        if address in [0x26a318,0x26a332]and self.active_metadata_request is not None:
            row=self.consumer_metadata_reads[self.active_metadata_request]
            row['native_generic_read_return']=uc.reg_read(REGS[0])
            if address==0x26a318:row.update(native_missing_profile_status11=True,output_written=False,
                invalid_or_unavailable_output_left_unchanged=True)
            self.active_metadata_request=None
        if address==0x35d430:
            pointer=uc.reg_read(REGS[0])
            self.consumer_metadata_entries.append(dict(original_entry=hex(address),object=hex(pointer),
                vtable=hex(self.word(pointer)),caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        return super().observe(uc,address,size,data)

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve();vm=MetadataVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_integration_checkpoint=False,full_general_MainMenu_final_guards_passed=False,
        general_MainMenu_controller_executed=False,catalog_seed_is_synthetic_not_loaded_player_entry=True)
    try:
        vm.invoke(0x2cbd17,());vm.uc.mem_write(INPUT+0x400,struct.pack('<I',1))
        require(vm.invoke(0x2ca82d,(0x19b,INPUT+0x400,4,0))==0,'Original setting19B write failed')
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR();vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original font initialization failed')
        vm.invoke(0x4a388b,());vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(vm.menu_records()[0]+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        obj=vm.invoke(0x3954cc,(0x3f04,));result['object']=hex(obj)
        print(json.dumps(dict(phase='original_MainMenu_with_native_metadata_absence_fallback')),flush=True)
        value=vm.invoke(0x40434d,(obj,1));vm.verify_storage_guards();vm.verify_descriptor_guards()
        result.update(completed=True,constructor_returned=hex(value),vtable=hex(vm.word(obj)),native_tree=vm.tree(obj),
            embedded_Grid_rows=vm.grid_rows(obj+0x39b0))
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(consumer_metadata_reads=vm.consumer_metadata_reads,consumer_metadata_entries=vm.consumer_metadata_entries,
        native_bank_lookup_entries=vm.native_bank_lookup_entries,
        storage_events=vm.storage_events,settings_native_entries=vm.settings_native_entries,
        heap_descriptor_entries=vm.heap_descriptor_entries,native_heap_validation_returns=vm.native_heap_validation_returns,
        conditional_writes=vm.conditional_region_writes,original_main_entries=vm.main_entries,native_fatal_entries=vm.native_fatal_entries,
        full_constructor_GUI_data_voice_allocation_SQL_final_guards_not_run=True)
    (STAGE/'general-menu-metadata-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),constructor_returned=result.get('constructor_returned'))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
