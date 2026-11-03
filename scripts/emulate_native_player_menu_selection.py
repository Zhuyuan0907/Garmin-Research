#!/usr/bin/env python3
"""Caption initialization and stock SQL-cell selection into loaded callback.

SQLite C-engine boundaries use a real in-memory copy of the verified icon DB;
Garmin formatting/conversion, bind/step/status/finalize wrappers and the menu
get/set/caption/bind/click functions execute original instructions. DB-ready
state, heap/completion, widget construction and Add policy are fixtures. No
hardware or backup DB is modified. Add probing stops before GUI construction.
"""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys

import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_player_menu import MenuVM
from emulate_native_player_menu_loaded import LoadedPlayerVM,PLAYER_ID,BIND
from emulate_native_vpm_filesystem import REGS,STACK,RETURN,require
from emulate_native_sbc import verify_guard_faults

BUILD='staging/native-player-menu-selection/manifest.json'
DATABASE='backups/20261002T154458Z/files/.System/SQLite/custom_mm_icons.db'
SQL_BASE=0x084c0000
SQL_OUT=0x084c8000
DB=SQL_BASE

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def digest(data):return hashlib.sha256(data).hexdigest()

class SelectionPlayerVM(LoadedPlayerVM):
    def __init__(self,stock,build):
        super().__init__(stock,build)
        self.db=sqlite3.connect(':memory:')
        source=sqlite3.connect((ROOT/DATABASE).as_uri()+'?mode=ro',uri=True)
        source.backup(self.db);source.close()
        self.database_before=list(self.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
        self.statements={};self.sql_events=[];self.widget_boundaries=[]
        self.root_probe_active=False;self.root_policy=0;self.root_endpoint=None
        self.sql_hooks={0x2b4d70:'prepare',0x2b2c10:'bind64',0x2aec46:'step',
            0x2b299e:'column_int',0x298528:'finalize',0x21d546:'completion',
            0x315b64:'widget_factory_boundary'}
        # 3954F0 is a control-block-holder destructor veneer, not a raw free
        # ABI. The older registry-only VM did not exercise it on a holder.
        # Execute its original instructions for the Add temporary holders.
        self.menu_hooks.pop(0x3954f0,None)
        self.hooks.pop(0x3954f0,None)
        self.menu_hooks.update({0x2dc9ea:'raw_allocate',0x2dc9ae:'raw_free'})
        self.hooks.update({0x2dc9ea:'raw_allocate',0x2dc9ae:'raw_free'})

    def ascii(self,pointer):
        data=bytearray()
        for n in range(512):
            value=self.uc.mem_read(pointer+n,1)[0]
            if not value:return data.decode('utf-8')
            data.append(value)
        raise ValueError('Unterminated SQL fixture string')

    def observe(self,uc,address,size,data):
        if self.root_probe_active:
            if address==0x529814:
                self.visits[address]+=1;self.ret(self.root_policy);return
            if address==0x6a56d8:
                self.visits[address]+=1
                args=[uc.reg_read(r) for r in REGS]
                label=args[3];shared=self.word(label+8)
                require(args[1]==PLAYER_ID and shared!=0,'Wrong Add constructor endpoint')
                self.root_endpoint={'entry':hex(address),'id':args[1],
                    'caption':self.wide(shared+8),'caption_auxiliary':self.word(label+16),
                    'constructor_executed':False,'full_Add_function_returned':False,
                    'stack_args':[self.word(uc.reg_read(UC_ARM_REG_SP)+n*4) for n in range(3)]}
                uc.emu_stop();return
        name=self.sql_hooks.get(address) if hasattr(self,'sql_hooks') else None
        if name is None:return super().observe(uc,address,size,data)
        self.visits[address]+=1
        args=[uc.reg_read(r) for r in REGS]
        value=0
        if name=='prepare':
            require(args[0]==DB and args[2]==0xffffffff,'Unexpected native sqlite prepare ABI')
            sql=self.ascii(args[1])
            require(sql in ['SELECT icon, size FROM custom_table WHERE id = ?',
                           'UPDATE custom_table SET icon = ?, size = ? WHERE id = ?'],
                    'Unexpected SQL from original formatter: '+sql)
            statement=SQL_BASE+0x200+len(self.statements)*0x40
            require(statement+0x40<SQL_BASE+0x4000,'Statement inventory exhausted')
            self.put(statement,DB)
            self.statements[statement]={'sql':sql,'bound':{},'cursor':None,'row':None,'closed':False}
            self.put(args[3],statement)
            self.sql_events.append({'operation':'prepare_engine_fixture','SQL':sql,'statement':hex(statement)})
        elif name=='bind64':
            row=self.statements[args[0]]
            require(not row['closed'] and 1<=args[1]<=row['sql'].count('?'),'Bad SQLite parameter index')
            raw=args[2] | args[3]<<32
            signed=raw if raw<1<<63 else raw-(1<<64)
            row['bound'][args[1]]=signed
            self.sql_events.append({'operation':'bind64_engine_fixture','index':args[1],'value':signed})
        elif name=='step':
            row=self.statements[args[0]];require(not row['closed'],'Step on closed statement')
            if row['cursor'] is None:
                require(len(row['bound'])==row['sql'].count('?'),'Native bind did not fill query')
                row['cursor']=self.db.execute(row['sql'],tuple(row['bound'][n] for n in range(1,len(row['bound'])+1)))
            row['row']=row['cursor'].fetchone()
            value=100 if row['row'] is not None else 101  # SQLITE_ROW / SQLITE_DONE
            self.sql_events.append({'operation':'step_engine_fixture','SQLite_result':value})
        elif name=='column_int':
            row=self.statements[args[0]]
            require(not row['closed'] and row['row'] is not None and args[1] in [0,1],'Invalid column read')
            value=int(row['row'][args[1]])&0xffffffff
        elif name=='finalize':
            row=self.statements[args[0]];require(not row['closed'],'Statement finalized twice')
            if row['cursor'] is not None:row['cursor'].close()
            row['closed']=True;self.sql_events.append({'operation':'finalize_engine_fixture'})
        elif name=='completion':
            # Original prepare/step calls this OS notification on all results.
            # No SQLITE_BUSY injection or wait/thread scheduling is claimed.
            self.sql_events.append({'operation':'completion_notification_fixture'})
        else:
            require(args[0]==self.menu_pointer() and args[3]==0,'Unexpected normal widget factory ABI')
            self.widget_boundaries.append({'entry':hex(address),'registry':args[0],
                'output':args[1],'catalog_index':args[2],'mode':args[3],
                'fifth_argument':self.word(uc.reg_read(UC_ARM_REG_SP)),
                'widget_constructed':False})
            # Do not manufacture a Widget, vtable or rendered control. The
            # native getter ignores this return and independently reports match.
        self.ret(value)

    def init_DB_fixture(self):
        self.put(self.menu_pointer()+24,DB)
        self.uc.mem_write(self.menu_pointer()+28,b'\x01')
        self.put(DB,0)

    def set_cell(self,id,icon,size):
        before=len(self.sql_events)
        self.invoke(0x316277,(self.menu_pointer(),icon,id,size))
        require(all(r['closed'] for r in self.statements.values()),'Setter left native statement open')
        return self.sql_events[before:]

    def lookup(self,id):
        label,icon,size,info=SQL_OUT,SQL_OUT+0x40,SQL_OUT+0x44,SQL_OUT+0x48
        self.uc.mem_write(SQL_OUT,b'\xa5'*0x200)
        self.invoke(0x39272b,(label,));self.put(label+16,0)
        self.put(icon,0xdead0001);self.put(size,0xdead0002)
        before=len(self.widget_boundaries)
        status=self.invoke(0x315f17,(self.menu_pointer(),id,SQL_OUT+0x80,0x1352),
                           (label,icon,size,info))
        title=self.wide(self.invoke(0x3927f5,(label,)))
        result={'id':id,'matched':status,'icon':self.word(icon),'size':self.word(size),
            'caption':title,'caption_auxiliary':self.word(label+16),
            'appearance':self.word(info),'context':self.word(info+4),
            'widget_requests':self.widget_boundaries[before:],
            'widget_output_untouched':bytes(self.uc.mem_read(SQL_OUT+0x80,32))==b'\xa5'*32}
        self.invoke(0x392773,(label,))
        require(all(r['closed'] for r in self.statements.values()),'Getter left native statement open')
        return result

    def click_lookup(self,result):
        require(result['matched']==1 and len(result['widget_requests'])==1,'No selected native catalog entry')
        index=result['widget_requests'][0]['catalog_index']
        entry=self.menu_records()[index]
        self.uc.mem_write(BIND-32,b'\xa5'*176)
        self.invoke(0x6acf3b,(BIND,self.word(0x9e0970),self.word(0x9e0974),self.menu_pointer()),(entry,))
        self.invoke(self.word(BIND),(self.word(BIND+8),BIND+12))
        self.invoke(0x399088,(BIND+12,))
        require(bytes(self.uc.mem_read(BIND-32,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(BIND+112,32))==b'\xa5'*32,'Selected bind copy overflow')

    def probe_add(self,category):
        self.root_probe_active=True;self.root_endpoint=None;self.returned=False
        reference=SQL_OUT+0x300;self.put(reference,0);self.put(reference+4,0)
        args=(self.menu_pointer(),category,1,reference)
        for r,v in zip(REGS,args):self.uc.reg_write(r,v)
        self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        self.uc.emu_start(0x3164db,RETURN+2,count=200000,timeout=5000000)
        self.root_probe_active=False
        require(self.returned or self.root_endpoint is not None,'Add probe did not reach a bounded endpoint')
        return {'category':category,'returned':self.returned,'constructor_endpoint':self.root_endpoint,
                'policy_boolean_is_fixture':self.root_policy}

def main():
    build=json.loads((ROOT/BUILD).read_text())
    for path,h in build['source_sha256'].items():require(sha(path)==h,'Build dependency changed '+path)
    database_sha=sha(DATABASE)
    require(database_sha==json.loads((ROOT/'staging/native-player-menu/preflight.json').read_text())['database_sha256'],
            'Database differs from verified backup')
    stock=NativeImage();cases=[]
    old=json.loads((ROOT/'staging/native-player-menu/build.json').read_text())
    control=MenuVM(stock,old)
    control.uc.mem_write(STACK-0x4000,b'\xa5'*0x4000)
    require(control.install(PLAYER_ID,0x13528000,'Pi 播放器')==0,'Old control failed')
    old_aux=control.word(control.records()[0]+24)
    require(old_aux==0xa5a5a5a5,'Poison control did not expose uninitialized caption auxiliary')
    cases.append({'name':'old_stack_poison_exposes_uncopied_caption_initialization','passed':True,
        'old_auxiliary_word':hex(old_aux),'text_still_correct':control.describe(control.records()[0])['caption']=='Pi 播放器',
        'old_binary_unchanged':True,'physical_UI_failure_proven':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)

    vm=SelectionPlayerVM(stock,build)
    vm.uc.mem_write(STACK-0x4000,b'\xa5'*0x4000)
    loaded=vm.load()
    entry=vm.menu_records()[0]
    require(vm.word(entry+24)==0,'New caption auxiliary retained stack bytes')
    vm.init_DB_fixture();stages=[]
    baseline=vm.lookup(15)
    require(baseline['matched']==0 and baseline['icon']==0 and not baseline['widget_requests'],'Empty backup cell matched')
    stages.append({'name':'original_empty_cell','result':baseline})
    set_events=vm.set_cell(15,PLAYER_ID,0)
    selected=vm.lookup(15)
    require(selected['matched']==1 and selected['icon']==PLAYER_ID and selected['size']==0 and
            selected['caption']=='Pi 播放器' and selected['caption_auxiliary']==0 and
            selected['appearance']==0 and selected['context']==0x13528000 and
            selected['widget_output_untouched'],'Native selection/caption outputs differ')
    vm.click_lookup(selected)
    stages.append({'name':'native_setter_getter_selects_loaded_callback','set_events':set_events,'result':selected})
    for size in [1,2]:
        vm.set_cell(15,PLAYER_ID,size);result=vm.lookup(15)
        require(result['matched']==0 and not result['widget_requests'],'Normal-cell getter accepted nonzero size')
        stages.append({'name':'normal_getter_rejects_size'+str(size),'result':result})
    vm.set_cell(15,PLAYER_ID+1,0);unknown=vm.lookup(15)
    require(unknown['matched']==0 and not unknown['widget_requests'],'Unknown icon invoked widget factory')
    stages.append({'name':'unknown_icon_ID_rejected','result':unknown})
    missing=vm.lookup(16)
    require(missing['matched']==0 and missing['icon']==0xdead0001 and not missing['widget_requests'],'Missing cell matched')
    stages.append({'name':'missing_cell_rejected','result':missing})
    original15=vm.database_before[-1]
    vm.set_cell(*original15)
    require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before,
            'In-memory cell restore changed other menu rows')
    snapshot=vm.finish()
    require(snapshot['native_menu_state']==[1,1,1,0x13528000,1,1] and len(vm.audio)==2,
            'Selected callback did not request audio once')
    cases.append({'name':'loaded_caption_native_SQL_cell_selection_and_click','passed':True,
        'load':loaded,'stages':stages,'snapshot':snapshot,'new_record_auxiliary_word':0,
        'SQL_engine_is_host_SQLite_fixture':True,'DB_ready_handle_and_flag_are_fixtures':True,
        'all_statements_finalized_by_original_wrapper':all(r['closed'] for r in vm.statements.values()),
        'all15_rows_restored_in_memory':True,'database_backup_unchanged':sha(DATABASE)==database_sha,
        'sql_events':vm.sql_events,'original_SQL_wrapper_visits':{hex(a):vm.visits[a] for a in
            [0x316276,0x315f16,0x392938,0x2fb78e,0x2376dc,0x23762c,0x2378ae,0x237588,0x237a70,0x2376b8]}})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    nonroot=vm.probe_add(1)
    require(nonroot['returned'] and nonroot['constructor_endpoint'] is None,'Wrong category accepted player')
    root=vm.probe_add(0)
    require(not root['returned'] and root['constructor_endpoint'] is not None and
            root['constructor_endpoint']['caption']=='Pi 播放器' and
            root['constructor_endpoint']['caption_auxiliary']==0,'Root Add did not reach correct player constructor endpoint')
    cases.append({'name':'original_Add_category_filter_to_unexecuted_constructor','passed':True,
        'nonroot':nonroot,'root':root,'full_GUI_or_root_function_completion_proven':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    vm.db.close()
    paths={ROOT/p for p in build['source_sha256']}|{ROOT/BUILD,Path(__file__).resolve(),ROOT/DATABASE,
        ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],ROOT/build['extension_flat'],
        ROOT/'staging/native-player-menu/build.json',ROOT/old['elf'],ROOT/old['flat_binary']}
    paths.update(ROOT/p for p in old['source_sha256'])
    for module in tuple(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':BUILD,'build_manifest_sha256':sha(BUILD),
        'source_sha256':{str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in sorted(paths)},
        'case_count':len(cases),'all_passed':True,'cases':cases,'database_sha256':database_sha,
        'SQLite_engine_version':sqlite3.sqlite_version,
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(),'device_io':False,'device_files_modified':False,
        'sounds_emitted':False,'device_install_candidate':False,'native_App_running_on_device':False,
        'actual_package_acceptance_verified':False,'rendered_touchable_icon_verified':False,
        'phone_direct_music_verified':False,
        'limits':'Poison control shows prior ctor/copy tests missed the separately-copied caption word. '
            'New20-byte grid caption initializes auxiliary0 around original16-byte string constructor. '
            'Original outer/DLL load, menu setter/getter, formatter/UTF16-UTF8 converter, SQLite thin wrappers '
            'and compiled callback execute. SQLite C-engine prepare/bind/step/column/finalize and OS completion, '
            'DB-ready inventory/heap are explicit fixtures using host in-memory SQLite copied read-only '
            'from the verified backup. Original DB open/schema initialization and real FAT/storage not '
            'tested. Normal widget factory is a boundary and its output stays untouched; native matched1 '
            'only proves ID/size/caption selection, not successful Widget creation. Original Add category1 '
            'returns without this icon; category0 stops before actual constructor after matching flag0. '
            'No complete Add function/GUI/render/touch/physical package/SIG acceptance, actual WAV/DAC, '
            'UI-thread timing, safe ID9/reload/unload or phone Bluetooth. Backup DB remains unchanged.'}
    path=ROOT/'evidence/firmware-analysis/native-player-menu-selection-emulation.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'cases':len(cases),'all_passed':True,'device_io':False}))

if __name__=='__main__':main()
