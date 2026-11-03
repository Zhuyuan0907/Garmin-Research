#!/usr/bin/env python3
"""Original outer selection/loader -> compiled entry -> private menu click.

Directory/driver inventories, allocation and audio API boundaries are explicit
fixtures. No MAIN patch or host call to the installer is used. UI-thread timing,
full Widget/SQL/rendering, SIG/device acceptance and actual playback remain open.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR, STUBS, INIT
from emulate_native_loader import simulate
from emulate_native_voice_outer import OuterVM
from emulate_native_vpm_filesystem import REGS, STACK, RETURN, DRIVE, REGION, require
from emulate_native_player_menu import MenuVM
from emulate_native_sbc import verify_guard_faults

BUILD='staging/native-player-menu-loaded/manifest.json'
SEED=0x084e0000
BIND=0x084f0020
PLAYER_ID=0x7f135201

def sha_path(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def digest(data): return hashlib.sha256(data).hexdigest()

class LoadedPlayerVM(OuterVM):
    def __init__(self,stock,build):
        self.build=build
        self.raw_allocations={};self.next_raw=0x08400020
        self.audio=[];self.events=[];self.entry_events=[];self.install_callers=[]
        super().__init__(stock,[{'name':'Chinese_Big5_MeiLing.vpm',
            'data':(ROOT/build['package']).read_bytes()}],selected_voice='mei-lingb')
        self.menu_hooks={0x3954cc:'raw_allocate',0x3954e4:'raw_allocate',
            0x3954d8:'raw_allocate',0x39544c:'raw_allocate',
            0x386f04:'raw_free',0x386f14:'raw_free',0x3954f0:'raw_free',
            0x525f14:'audio_register_boundary',0x36b720:'audio_start_boundary'}
        self.hooks.update(self.menu_hooks)
        self.initial_regions={}
        self.declared_platform_fixture_changes=[]
        for region in self.stock.copies:
            if region['runtime_start']==0xf00000:continue
            actual=bytes(self.uc.mem_read(region['runtime_start'],region['size']))
            original=self.stock.read(region['load_start'],region['size'])
            if actual!=original:
                differences=[n for n,(a,b) in enumerate(zip(actual,original)) if a!=b]
                require(region['runtime_start']==0x05400000 and differences==[0] and actual[0]==1,
                        'Unknown initialized fixture modification: '+hex(region['runtime_start']))
                self.declared_platform_fixture_changes.append({'address':'0x05400000',
                    'before':hex(original[0]),'fixture':1,'purpose':'Inherited platform active-byte fixture'})
            self.initial_regions[region['runtime_start']]=actual
        require(build['combined_file_bytes']<0x300000,'Readback would overlap the new raw heap')
        require(self.word(0xf11e04+8)==0,'Unexpected stock registry seed')

    symbol=MenuVM.symbol
    invoke=MenuVM.invoke
    describe=MenuVM.describe
    verify_guard=MenuVM.verify_guard

    def observe(self,uc,address,size,data):
        if address==self.symbol('native_player_component_entry'):
            self.entry_events.append({'entry':hex(address),'from_original_loader':self.allow_module_execution})
        if address==self.symbol('native_player_menu_install'):
            caller=uc.reg_read(UC_ARM_REG_LR)&~1
            require(self.build['extension_base']<=caller<self.symbol('__app_code_end'),
                    'Installer called by host or outside loaded entry')
            self.install_callers.append({'caller':hex(caller),'inside_loaded_component':True})
        name=self.menu_hooks.get(address) if hasattr(self,'menu_hooks') else None
        if name in ['audio_register_boundary','audio_start_boundary']:
            # This known branch of the frozen helper only records the API
            # boundary; its fallback to a different VM is never entered.
            return MenuVM.observe(self,uc,address,size,data)
        if name in ['raw_allocate','raw_free']:
            self.visits[address]+=1
            args=[uc.reg_read(r) for r in REGS]
            if name=='raw_allocate':
                length=args[0];require(0<length<0x10000,'Unexpected C++ allocation')
                pointer=self.next_raw;self.next_raw+=(length+127)&~63
                require(self.next_raw<0x084d0000,'Raw heap exhausted')
                uc.mem_write(pointer-32,b'\xa5'*(length+64))
                self.raw_allocations[pointer]={'length':length,'freed':False,'service':hex(address)}
                self.events.append({'allocate':length,'pointer':hex(pointer)})
                self.ret(pointer)
            else:
                pointer=args[0]
                if pointer:
                    entry=self.raw_allocations.get(pointer)
                    require(entry is not None and not entry['freed'],'Unknown/double raw free')
                    self.verify_guard(pointer,entry);entry['freed']=True
                    self.events.append({'free':hex(pointer)})
                self.ret()
            return
        return super().observe(uc,address,size,data)

    def menu_pointer(self): return self.word(0xf11e04+8)
    def menu_records(self):
        obj=self.menu_pointer()
        if not obj:return []
        begin,end=self.word(obj+12),self.word(obj+16)
        require(end>=begin and (end-begin)%100==0,'Invalid native catalog')
        return [begin+n*100 for n in range((end-begin)//100)]

    def seed_control(self,id,caption,context):
        # Existing entries are synthetic controls constructed by stock code.
        # RETURN is a fixture callback, not a recovered production page for ID.
        registry=self.invoke(0x31590b,())
        self.uc.mem_write(SEED,caption.encode('utf-16le')+b'\0\0')
        label,record,visual=SEED+0x100,SEED+0x200,SEED+0x300
        self.put(visual,visual+8);self.put(visual+4,0);self.uc.mem_write(visual+8,b'\0')
        self.invoke(0x39274f,(label,SEED,0xffffffff))
        self.invoke(0x498fc4,(record,id,0,label),
            (visual,visual,visual,visual,visual,RETURN|1,context,0,visual,visual,0))
        self.invoke(0x31592b,(registry,record))
        self.invoke(0x399088,(record,));self.invoke(0x392773,(label,))

    def load(self):
        enumeration=self.enumerate();self.verify_released()
        require(len(enumeration['registry'])==1,'Package not enumerated once')
        require(self.mount(),'Original outer mount failed')
        status,handle=self.open('dllimg.bin');require(status==0,'Embedded DLL open failed')
        readback=self.read_file(handle);self.close(handle)
        require(digest(readback)==self.build['combined_sha256'],'Original full readback differs')
        self.call(0xfea50,(DRIVE,0));self.call(0x2d32de,(REGION,));self.verify_released()
        self.allow_module_execution=True
        self.uc.mem_write(IMAGE,b'\xa5'*self.build['combined_ram_bytes'])
        callbacks=[0x1fb2f8,0x1fb304,0x1fb3a2,0x1fb3ce,0x1fb3e4]
        before={a:self.visits[a] for a in callbacks}
        self.call(0x240498,(0,0))
        require(self.loader_return==11 and self.init_calls==1 and len(self.entry_events)==1 and
                len(self.install_callers)==1,'Original loader did not enter/register automatically once')
        require(all(self.visits[a]>before[a] for a in callbacks),'Loader file callback bypassed')
        original=(ROOT/self.build['original_binary']).read_bytes()
        oldram=struct.unpack_from('<I',original,4)[0]
        control,baseline=simulate(self.stock,'original_voice',module_bytes=original,
            module_ram_bytes=oldram,poison_module_ram=True,return_session=True)
        require(bytes(self.uc.mem_read(IMAGE+12,oldram-12))==bytes(control.mem_read(IMAGE+12,oldram-12)),
                'Original voice runtime altered by player entry')
        require(bytes(self.uc.mem_read(STUBS,480))==bytes(control.mem_read(STUBS,480)),
                'Original40 exports altered')
        require(struct.unpack('<Iii',self.uc.mem_read(self.symbol('app_component_state'),12))==(1,11,0),
                'Preserving initializer differs')
        for table,names in [('app_component_api',self.build['private_api']),
                            ('player_component_api',self.build['player_api'])]:
            require(list(struct.unpack('<'+str(len(names))+'I',self.uc.mem_read(self.symbol(table),4*len(names))))==
                    [self.symbol(n) for n in names],'Native API table differs')
        base=self.build['extension_base']
        self.uc.mem_protect(base,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.uc.mem_protect(base+0x10000,0x18000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.extension_code=bytes(self.uc.mem_read(base,0x10000))
        compatible=self.call(0x222a34,(0,))
        require(compatible==1 and not self.diagnostics,'Native voice compatibility failed under matching cache fixture')
        return {'native_readback_bytes':len(readback),'native_readback_sha256':digest(readback),
            'original_loader_result':self.loader_return,'original_control_result':baseline['status'],
            'original40_and_original_runtime_preserved':True,
            'native_private12_and_player2_tables_match':True,
            'native_file_callback_entries':{hex(a):self.visits[a]-before[a] for a in callbacks},
            'entry_events':self.entry_events,'install_callers':self.install_callers,
            'original_compatibility_result':compatible,'current_voice_cache_is_fixture':True,
            'same_VM_execution_budget_resumes':self.execution_resumes,
            'original_3MiB_reservation_retained':IMAGE+self.build['combined_ram_bytes']<=DESCRIPTOR}

    def player_state(self):
        values=struct.unpack('<IiIIi',self.uc.mem_read(self.symbol('player_component_state'),20))
        return dict(zip(['entered','original_result','registry','icon_id','registration_result'],values))

    def click_player(self):
        entry=next(e for e in self.menu_records() if self.word(e)==PLAYER_ID)
        require(self.word(entry+84)==self.symbol('native_player_menu_activate'),
                'Player callback not in loaded component')
        require(self.build['extension_base']<=self.word(entry+84)<self.symbol('__app_code_end'),
                'Player points to standalone synthetic code')
        self.uc.mem_write(BIND-32,b'\xa5'*176)
        method,adjust=self.word(0x9e0970),self.word(0x9e0974)
        self.invoke(0x6acf3b,(BIND,method,adjust,self.menu_pointer()),(entry,))
        require(self.describe(BIND+12)==self.describe(entry),'Native bind copy differs')
        self.invoke(self.word(BIND),(self.word(BIND+8),BIND+12))
        self.invoke(0x399088,(BIND+12,))
        require(bytes(self.uc.mem_read(BIND-32,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(BIND+112,32))==b'\xa5'*32,'Native bind crossed buffer')

    def finish(self):
        # Close outer storage/cache, retaining the already-loaded module and
        # catalog callback. This is not erasure, unregister or safe unloading.
        self.call(0xfea50,(DRIVE,0));self.call(0x2d32de,(REGION,));self.verify_released()
        for pointer,entry in self.raw_allocations.items():self.verify_guard(pointer,entry)
        for address,raw in self.initial_regions.items():
            require(bytes(self.uc.mem_read(address,len(raw)))==raw,
                    'Initialized original/declared platform region changed '+hex(address))
        require(bytes(self.uc.mem_read(self.build['extension_base'],0x10000))==self.extension_code,
                'Loaded RX extension code changed')
        return {'state':self.player_state(),
            'catalog':[self.describe(e) for e in self.menu_records()],
            'native_menu_state':list(struct.unpack('<6I',self.uc.mem_read(self.symbol('native_player_menu_state'),24))),
            'audio_API_boundary_requests':self.audio,
            'original_entry_visits':{hex(a):self.visits[a] for a in [0x31590a,0x3158c8,
                0x31592a,0x6a4d66,0x44f6702,0x6acf3a,0x31649a,INIT,0x240498]},
            'all_allocation_guards_intact':True,'stock_and_loaded_code_unchanged':True,
            'declared_platform_fixture_changes':self.declared_platform_fixture_changes,
            'outer_files_and_temporary_handles_closed':True,'loaded_module_and_callback_remain_resident':True,
            'live_Cpp_allocations':sum(not e['freed'] for e in self.raw_allocations.values()),
            'full_Widget_SQL_touch_rendering_executed':False,'speaker_or_DAC_executed':False,
            'UI_thread_timing_proven':False,'outer':self.summarize()}

def main():
    build=json.loads((ROOT/BUILD).read_text())
    for path,h in build['source_sha256'].items():require(sha_path(path)==h,'Build source changed '+path)
    stock=NativeImage();cases=[]
    for name,seeds,registration,activate in [
        ('original_loader_auto_registers_resident_player',[],0,True),
        ('original_loader_preserves_existing_catalog_and_grows',[(1,'Existing A',101),(307,'Existing B',102)],0,True),
        ('duplicate_player_ID_retains_existing_callback_and_voice',[(PLAYER_ID,'Existing owner',0xf00d)],2,False)]:
        vm=LoadedPlayerVM(stock,build)
        for id,caption,context in seeds:vm.seed_control(id,caption,context)
        prior=[vm.describe(e) for e in vm.menu_records()]
        load=vm.load()
        require(vm.player_state()['registration_result']==registration,'Unexpected registration result')
        if activate:vm.click_player()
        snapshot=vm.finish()
        require(snapshot['catalog'][:len(prior)]==prior,'Loaded entry changed an existing catalog item')
        if activate:
            row=snapshot['catalog'][-1]
            require(row['id']==PLAYER_ID and row['caption']=='Pi 播放器' and
                    row['context']==0x13528000 and len(snapshot['audio_API_boundary_requests'])==2 and
                    snapshot['native_menu_state']==[1,1,1,0x13528000,1,1],
                    'Registered loaded callback did not execute once')
        else:
            require(snapshot['catalog']==prior and not snapshot['audio_API_boundary_requests'] and
                    snapshot['native_menu_state']==[1,0,0,0,0,0],
                    'Duplicate ID hijacked prior callback or emitted audio request')
        cases.append({'name':name,'passed':True,'load':load,'snapshot':snapshot,
            'existing_entries_are_explicit_control_fixtures':bool(seeds),
            'host_calls_menu_installer':False,'catalog_before':prior})
        print(json.dumps({'case':name,'passed':True}),flush=True)
    paths={ROOT/p for p in build['source_sha256']} | {ROOT/BUILD,Path(__file__).resolve(),
        ROOT/build['combined_binary'],ROOT/build['extension_elf'],ROOT/build['extension_flat'],ROOT/build['package']}
    for module in tuple(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':BUILD,'build_manifest_sha256':sha_path(BUILD),
        'source_sha256':{str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in sorted(paths)},
        'case_count':len(cases),'all_passed':True,'cases':cases,
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(),
        'original_outer_loader_and_catalog_same_VM':True,'automatic_registration_from_loaded_entry':True,
        'stock_WAV_request_from_callback_in_original_reservation':True,'MAIN_patch_bytes':0,
        'device_io':False,'device_files_modified':False,'sounds_emitted':False,
        'device_install_candidate':False,'actual_package_acceptance_verified':False,
        'native_App_running_on_device':False,'phone_direct_music_verified':False,
        'limits':'Original full outer readback/selection/DLL loader/40 voice exports and private '
            'catalog construction/copy/click consumer share one VM. New compiled entry automatically '
            'attempts menu registration; no host installer call, standalone synthetic menu image or MAIN '
            'patch is used. Directory/driver/platform/current settings/kernel/allocations are fixtures. '
            'Registration timing is the TTS loader context, not proven production UI-thread ownership. '
            'Existing entries are synthetic controls with fixture callbacks. Empty visual resources, '
            'SQL selection/full Widget/touch/rendering, audio decode/kernel/DAC, ID9 lifecycle, '
            'SIG/physical package acceptance, rollback/unregister/reload/unload and Bluetooth remain '
            'unverified. Module/callback resources remain resident after outer storage cleanup. '
            'This does not replace the separate direct-music work. Never transfer experimental VPM.'}
    path=ROOT/'evidence/firmware-analysis/native-player-menu-loaded-emulation.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'cases':len(cases),'all_passed':True,'device_io':False}))

if __name__=='__main__':main()
