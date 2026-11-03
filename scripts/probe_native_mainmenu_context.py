#!/usr/bin/env python3
"""Trace original general-menu signal/map context without changing frozen VMs."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import NativeImage,ROOT
from probe_native_player_mainmenu import MainMenuVM,BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_loaded import SEED,PLAYER_ID
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu-context'

class ContextVM(MainMenuVM):
    def __init__(self,stock,build):
        self.signal_context_entries=[];self.signal_disconnect_entries=[];self.audio_context_entries=[];self.shared_signal_entries=[]
        super().__init__(stock,build)

    def mapped_words(self,pointer,count):
        if pointer and any(lo<=pointer and pointer+4*count-1<=hi for lo,hi,_ in self.uc.mem_regions()):
            return [hex(self.word(pointer+4*n))for n in range(count)]
        return None

    def observe(self,uc,address,size,data):
        args=[uc.reg_read(r)for r in REGS]if address in [0x36294e,0x362a2c,0x36270c,0x3959e8,0x2efc1e,0x2f3ebc,0x3b52fe,0x4419b8,0x4a3846,0x4a388a]else None
        if address in [0x4419b8,0x4a3846,0x4a388a]:
            self.shared_signal_entries.append(dict(entry=hex(address),caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),
                arguments=[hex(a)for a in args],global_shared_signal_words=self.mapped_words(0x3471c30,4)))
        if address in [0x36294e,0x362a2c,0x36270c]:
            self.signal_context_entries.append(dict(entry=hex(address),arguments=[hex(a)for a in args],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),object_words=self.mapped_words(args[0],16),
                context_words=self.mapped_words(args[1],16),third_argument_words=self.mapped_words(args[2],8),
                stack_words=[hex(self.word(uc.reg_read(UC_ARM_REG_SP)+4*n))for n in range(8)]))
        if address==0x3959e8:
            holder=self.word(args[0]);self.signal_disconnect_entries.append(dict(entry=hex(address),
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),holder=hex(args[0]),
                holder_words=self.mapped_words(args[0],4),connection=hex(holder),
                connection_words=self.mapped_words(holder,12)))
        if address in [0x2efc1e,0x2f3ebc,0x3b52fe]:
            require(len(self.audio_context_entries)<1000,'Finite audio observation budget exhausted')
            self.audio_context_entries.append(dict(entry=hex(address),arguments=[hex(a)for a in args],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),object_words=self.mapped_words(args[0],12)))
        return super().observe(uc,address,size,data)

def main():
    STAGE.mkdir(exist_ok=True);source=Path(__file__).resolve();vm=ContextVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),device_io=False,sounds_emitted=False,
        full_integration_checkpoint=False,source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        frozen_MainMenuVM_source_sha256=hashlib.sha256((ROOT/'scripts/probe_native_player_mainmenu.py').read_bytes()).hexdigest())
    try:
        vm.invoke(0x395981,());vm.invoke(0x2db541,());vm.register_stock_GIR();vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        print(json.dumps(dict(phase='before_original_shared_signal_initialization')),flush=True)
        vm.invoke(0x4a388b,())
        result['original_shared_signal_initializer_returned']=True
        result['shared_signal_global_after_initializer']=vm.mapped_words(0x3471c30,4)
        vm.put(SEED+0x110,0);vm.seed_control(PLAYER_ID,'Pi 播放器',0x13528000)
        vm.invoke(0x3894ad,(INPUT+0x100,0x8a56eac))
        for n in range(7):vm.invoke(0x3894f1,(vm.menu_records()[0]+28+8*n,INPUT+0x100))
        vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0);vm.supply_setting_record(1)
        obj=vm.invoke(0x3954cc,(0x3f04,));result['object']=hex(obj)
        print(json.dumps(dict(phase='before_original_MainMenu_context_trace')),flush=True)
        returned=vm.invoke(0x40434d,(obj,1))
        result.update(completed=True,original_constructor_returned=hex(returned),native_tree=vm.tree(obj))
    except Exception as error:
        sp=vm.uc.reg_read(UC_ARM_REG_SP)
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
            stack_words=[hex(vm.word(sp+4*n))for n in range(112)])
    result.update(shared_signal_entries=vm.shared_signal_entries,signal_context_entries=vm.signal_context_entries,signal_disconnect_entries=vm.signal_disconnect_entries,
        audio_context_entries=vm.audio_context_entries,unavailable_audio_pool_waits=vm.unavailable_audio_pool_waits,
        conditional_writes=vm.conditional_region_writes,original_main_entries=vm.main_entries)
    (STAGE/'general-context-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),
        context_entry_count=len(vm.signal_context_entries),disconnect_entry_count=len(vm.signal_disconnect_entries))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
