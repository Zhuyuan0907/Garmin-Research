#!/usr/bin/env python3
"""Original consumer-default metadata reads on an explicit lower inventory.

No hardware factory data is reconstructed. Missing storage returns nonzero
and leaves outputs untouched; the original caller decides its fallback.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
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

class MetadataVM(SettingsVM):
    def __init__(self,stock,build):
        self.consumer_metadata_inventory={n:None for n in HEADER_CALLERS}
        self.consumer_metadata_reads=[];self.consumer_metadata_entries=[]
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address==0x26a300 and uc.reg_read(REGS[0])in HEADER_CALLERS:
            bank,offset,length,destination=[uc.reg_read(r)for r in REGS];caller=uc.reg_read(UC_ARM_REG_LR)&~1
            header=offset==0
            require((header and caller==HEADER_CALLERS[bank]and length==8)or
                (offset==8 and caller in BODY_CALLERS[bank]and length>0),
                'Unexpected consumer metadata lower-read ABI')
            blob=self.consumer_metadata_inventory[bank]
            valid_length=length<= (8 if header else MAX_BODY_BYTES[bank])
            available=blob is not None and valid_length and offset+length<=len(blob)
            if available:uc.mem_write(destination,blob[offset:offset+length])
            self.consumer_metadata_reads.append(dict(bank=bank,offset=offset,requested_bytes=length,destination=hex(destination),
                original_caller=hex(caller),operation='header'if header else'body',synthetic_inventory_present=blob is not None,
                explicit_lower_status=0 if available else 1,output_written=available,invalid_or_unavailable_output_left_unchanged=not available,
                physical_factory_metadata_or_device_read=False))
            self.visits[address]+=1;self.ret(0 if available else 1);return
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
        storage_events=vm.storage_events,settings_native_entries=vm.settings_native_entries,
        heap_descriptor_entries=vm.heap_descriptor_entries,native_heap_validation_returns=vm.native_heap_validation_returns,
        conditional_writes=vm.conditional_region_writes,original_main_entries=vm.main_entries,native_fatal_entries=vm.native_fatal_entries,
        full_constructor_GUI_data_voice_allocation_SQL_final_guards_not_run=True)
    (STAGE/'general-menu-metadata-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),constructor_returned=result.get('constructor_returned'))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
