#!/usr/bin/env python3
"""Scoped original eight-signal initializer and empty callback controls.

Original signal, shared ownership and tree constructors run unchanged. No
general MainMenu constructor, callback delivery, device or audio execution.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from analyze_native_menu_signals import GLOBALS
from probe_native_player_mainmenu import MainMenuVM,BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu-context'

class SignalVM(MainMenuVM):
    def __init__(self,stock,build):
        self.signal_constructors=[];self.signal_shared_constructors=[];self.subscription_entries=[]
        super().__init__(stock,build)
        # Materialize one original startup zero-fill page before host-side
        # inspection; emulation otherwise maps such pages on guest access.
        require(any(r['runtime_start']<=0x3471000 and 0x3472000<=r['runtime_end']for r in stock.zeros),
            'Signal page is not in an original startup zero-fill region')
        require(not any(lo<=0x3471000<=hi for lo,hi,_ in self.uc.mem_regions()),'Signal BSS page already mapped')
        self.uc.mem_map(0x3471000,0x1000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address in [0x362a2c,0x36270c,0x4a3846,0x4419b8,0x36294e]:
            row=dict(entry=hex(address),arguments=[hex(uc.reg_read(r))for r in REGS],
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1))
            if address==0x362a2c:self.signal_shared_constructors.append(row)
            elif address==0x36270c:self.signal_constructors.append(row)
            else:self.subscription_entries.append(row)
        return super().observe(uc,address,size,data)

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());database_sha=sha(DATABASE)
    vm=SignalVM(NativeImage(),build);cases=[]
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        require([vm.word(p)for p in GLOBALS]==[0]*8,'Signal globals initially nonzero; inspect first')
        record('stock_zero_initialized_signal_globals_before_original_initializer',
            globals=[hex(p)for p in GLOBALS],owner_values_before=[0]*8,host_seeded_owners=False)
        vm.invoke(0x4a388b,());rows=[]
        require(len(vm.signal_constructors)==len(vm.signal_shared_constructors)==8,'Original constructors did not run eight times')
        for p in GLOBALS:
            owner,control=vm.word(p),vm.word(p+4);sentinel=vm.word(owner+0x18)
            require(owner and control and vm.word(control+0xc)==owner and vm.word(control+4)==1 and vm.word(control+8)==1,
                'Signal shared control does not own original object')
            require(vm.word(owner)==0 and vm.word(sentinel+4)==0 and vm.word(sentinel+8)==sentinel and vm.word(sentinel+12)==sentinel,
                'Original signal map/sentinel differs')
            rows.append(dict(global_address=hex(p),owner=hex(owner),shared_control=hex(control),
                native_reference_counts=[vm.word(control+4),vm.word(control+8)],sentinel=hex(sentinel),
                original_empty_tree_sentinel_verified=True,word38=hex(vm.word(owner+0x38))))
        require(len({r['owner']for r in rows})==8 and len({r['shared_control']for r in rows})==8,
            'Original signals unexpectedly alias')
        record('original_initializer_builds_eight_distinct_shared_signals_and_empty_native_trees',
            original_entry='0x4a388a',signals=rows,host_seeded_signals_or_tree_links=False,
            original_constructor_calls=vm.signal_constructors,original_shared_constructor_calls=vm.signal_shared_constructors)
        # An explicitly empty callback is rejected by the original gate before
        # subscription. This is not a successful listener or event delivery.
        out=INPUT+0x800;callback=INPUT+0x900
        vm.uc.mem_write(callback,b'\0'*32);vm.uc.mem_write(out-16,b'\xa5'*48)
        vm.invoke(0x4a3847,(out,callback))
        expected=b'\xa5'*16+b'\0'*9+b'\xa5'*23
        require(bytes(vm.uc.mem_read(out-16,48))==expected,'Original empty-callback output extent differs')
        require([r['entry']for r in vm.subscription_entries]==['0x4a3846','0x4419b8'],
            'Empty callback reached actual map subscription')
        record('original_subscription_empty_callback_branch_returns_empty_holder_without_connecting',
            original_wrapper='0x4a3846',original_gate='0x4419b8',output_bytes_cleared=9,
            surrounding_canaries_intact=True,actual_map_subscription_executed=False,callback_delivery_verified=False)
        require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes,
            'Focused signal control faulted, requested audio or changed GUI initialized data')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(sha(DATABASE)==database_sha and not vm.statements,'Backup DB changed or unexpected SQL')
        snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        dependencies={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            STAGE/'shared-signal-static-preflight.json'}
        dependencies.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name:
                path=Path(name).resolve()
                if path.is_file()and path.is_relative_to(ROOT/'scripts'):dependencies.add(path)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
            build_manifest=BUILD,build_manifest_sha256=sha(BUILD),
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(dependencies)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,snapshot=snapshot,
            original_voice_RAM_and40_exports_unchanged=True,raw_DB_backup_unchanged=True,
            no_GUI_conditional_initialized_data_changes=True,device_io=False,sounds_emitted=False,
            general_MainMenu_constructor_returned=False,callback_delivery_verified=False,
            actual_boot_initializer_order_or_event_meanings_verified=False,
            limits='Three scoped original-code controls validate the zero initial inventory, eight shared signal/tree constructors and the original empty-callback rejection. Explicit storage/heap/mutex/IRQ fixtures remain. No general MainMenu, actual boot order, listener/callback delivery, visible player App, audio/device display or accepted package is established.')
        target=ROOT/'evidence/firmware-analysis/native-menu-signals-emulation.json';require(not target.exists(),'Use a new proof namespace')
        target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(dependencies))),flush=True)
    except Exception as error:
        failure=dict(error=str(error),cases=cases,all_final_guards_passed=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses)
        (STAGE/'focused-signals-failure.json').write_text(json.dumps(failure,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases))),flush=True);sys.exit(1)

if __name__=='__main__':main()
