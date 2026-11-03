#!/usr/bin/env python3
"""Original VPM enumeration/metadata/predicate/registry with explicit outer I/O.

Directory inventory, mapped-region binding and activation wrappers are fixtures.
The stock enumerator, metadata, platform predicate, sorted registry, embedded
container parser and file reader execute. No physical navigator is accessed.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_tts_vpm import parse_image
from analyze_native_loader import INIT,IMAGE,DESCRIPTOR
from emulate_native_voice_metadata import VoiceMetadata,sha,require,tags_from,replace_metadata
from emulate_native_vpm_filesystem import REGION,DRIVE,REGS,STACK,mutate_member

ENUM=0x1d897c
HEAD=0xf09668
DIRECTORY=0x0802a000
PLATFORM=0x0691ce40
NODE_BYTES=0x778


class RegistryVM(VoiceMetadata):
    def __init__(self,stock,inventory,*,predicate_accept=True,mount_error=0):
        self.inventory=inventory;self.cursor=0;self.directory_events=[];self.binding_events=[]
        self.activation_events=[];self.registry_snapshots=[];self.mount_error=mount_error
        self.allow_module_execution=False;self.module_executed=False;self.init_calls=0
        super().__init__(stock,inventory[0]['data'] if inventory else b'',changed=False)
        self.put(HEAD,0)
        self.uc.mem_map(0x0691c000,4096)
        self.uc.mem_write(0x05400000,b'\x01')
        self.uc.mem_write(PLATFORM+0x20,b'\x4c')
        self.uc.mem_write(0xf070fc,struct.pack('<H',0x1234 if predicate_accept else 0xa1e))
        # Synthetic cached platform values; neither key13A nor byte20 is a
        # measured unit value. All callers and predicate instructions execute.
        self.uc.mem_write(DIRECTORY,'0:/Garmin/Voice/\0'.encode('utf-16le'))
        self.code_images=[]
        for copy in stock.copies:
            if copy['runtime_start'] in [0x50000,0x04400000]:
                a=copy['runtime_start'];raw=stock.read(copy['load_start'],copy['size'])
                self.code_images.append((a,raw))
                self.uc.mem_protect(a,(len(raw)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)

    def wide(self,p):
        units=[]
        for i in range(512):
            u=bytes(self.uc.mem_read(p+2*i,2))
            if u==b'\0\0':return b''.join(units).decode('utf-16le')
            units.append(u)
        raise ValueError('Unterminated fixture UTF16 path')

    def ret(self,value=0):
        self.uc.reg_write(UC_ARM_REG_R0,value&0xffffffff)
        self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))

    def filename_handle(self,name):
        content=(name+'\0').encode('utf-16le');length=len(content)
        handle=0xd0000000+len(self.handles)+1
        pointer=self.next_heap;self.next_heap+=(length+127)&~63
        require(self.next_heap<0x080f0000,'Fixture filename heap exhausted')
        self.uc.mem_write(pointer-32,b'\xa5'*(length+64));self.uc.mem_write(pointer,content)
        self.handles[handle]={'pointer':pointer,'length':length,'locks':0,'freed':False,'directory_fixture':True}
        return handle

    def observe(self,uc,address,size,unused):
        if address in [0x31d5f2,0x31d8fe,0x31d19c,0x2d3166,0xfea50,0x2d32de,0x33e912]:
            args=[uc.reg_read(r) for r in REGS]
        if address==INIT:
            self.init_calls+=1
            require(self.allow_module_execution,'Outer enumeration unexpectedly loaded executable code')
        if IMAGE<=address<DESCRIPTOR:
            require(self.allow_module_execution,'Unexpected voice module execution')
            self.module_executed=True
        if address==0x31d5f2:
            self.visits[address]+=1
            require(self.wide(args[0])=='0:/Garmin/Voice/' and args[1]==1,'Unexpected outer directory-open ABI')
            require(STACK-0x1800<args[2]<STACK,'Directory handle outside stack')
            self.put(args[2],0xc0000001);self.cursor=0
            self.directory_events.append({'operation':'open_directory_fixture','path':self.wide(args[0])})
            self.ret();return
        if address==0x31d8fe:
            self.visits[address]+=1
            require(args[0]==0xc0000001,'Unexpected directory cursor')
            pattern=self.wide(args[1]);require(pattern in ['*.vpm','*.NEW'],'Unexpected native search pattern')
            if pattern=='*.NEW' or self.cursor>=len(self.inventory):
                self.directory_events.append({'operation':'next_directory_fixture','pattern':pattern,'end':True})
                self.ret(0xffffffff);return
            name=self.inventory[self.cursor]['name'];self.cursor+=1
            # Stock31D8FE result's filename handle is at +16. Other queried
            # fields are zero fixture values; no pre-built metadata/registry.
            uc.mem_write(args[2],bytes(40));self.put(args[2]+16,self.filename_handle(name))
            self.directory_events.append({'operation':'next_directory_fixture','pattern':pattern,'name':name})
            self.ret();return
        if address==0x31d19c:
            self.visits[address]+=1;require(args[0]==0xc0000001,'Unknown outer directory close')
            self.directory_events.append({'operation':'close_directory_fixture'});self.ret();return
        if address==0x2d3166:
            self.visits[address]+=1
            require(args[:2]==[0,REGION],'Unexpected mapped-region binding ABI')
            path=self.wide(args[2]);name=Path(path).name
            row=next((r for r in self.inventory if r['name']==name),None)
            require(row is not None,'Native path not found in outer immutable inventory')
            self.data=row['data']
            self.binding_events.append({'path':path,'package_sha256':sha(self.data),'result':self.mount_error,
                'operation':'outer_file_to_mapped_region_fixture'})
            self.ret(self.mount_error);return
        if address==0xfea50:
            self.visits[address]+=1
            require(args[0]==DRIVE and args[1] in [0,1],'Unexpected drive activation wrapper')
            self.activation_events.append({'drive':args[0],'active':args[1],
                'operation':'activation_wrapper_tail_routes_to_original_1E86CE'})
            # Keep the original caller's LR; tail-route wrapper to the real
            # embedded mount/unmount parser. Lower device notification is not
            # simulated as recovered code or real I/O.
            uc.reg_write(UC_ARM_REG_R2,0);uc.reg_write(UC_ARM_REG_PC,0x1e86cf);return
        if address in [0x2d32de,0x33e912]:
            self.visits[address]+=1
            require(args[0] in [REGION,17],'Unexpected unbind/notification fixture')
            self.ret();return
        return super().observe(uc,address,size,unused)

    def registry(self):
        rows=[];handle=self.word(HEAD)
        while handle:
            require(handle in self.handles and handle not in [r['handle'] for r in rows],'Invalid native registry link')
            entry=self.handles[handle];p=entry['pointer'];require(not entry['freed'] and entry['length']==NODE_BYTES,'Invalid registry node')
            rows.append({'handle':handle,'filename':self.wide(p),'volume_id':self.wide(p+0x3fc),
                'language_name':self.wide(p+0x460),'type':self.uc.mem_read(p+0x760,1)[0],
                'metadata_checksum':self.word(p+0x764),'private_offset770':self.word(p+0x770),
                'next':self.word(p+0x774),'bytes':NODE_BYTES,'native_allocated_node':True})
            handle=rows[-1]['next']
        return rows

    def enumerate(self):
        before_sp=STACK
        self.uc.mem_write(STACK-0x1800,b'\xa5'*0x1800)
        result=self.call(ENUM,(DIRECTORY,))
        require(self.uc.reg_read(UC_ARM_REG_SP)==before_sp,'Enumerator stack not restored')
        require(bytes(self.uc.mem_read(STACK-0x1800,128))==b'\xa5'*128,'Enumerator stack lower guard changed')
        self.verify_closed_files()
        rows=self.registry();retained={r['handle'] for r in rows}
        for handle,entry in self.handles.items():
            p,n=entry['pointer'],entry['length']
            require(entry['freed']==(handle not in retained),'Only native registry nodes may remain allocated')
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,
                'Native heap allocation guard changed')
        require(all(bytes(self.uc.mem_read(a,len(raw)))==raw for a,raw in self.code_images),'Original code changed')
        require(not self.module_executed and self.init_calls==0,'Enumeration executed module')
        return {'native_return':result,'registry':rows,'directory_events':self.directory_events,
            'binding_events':self.binding_events,'activation_events':self.activation_events,
            'metadata_open_attempts':self.open_attempts,'original_functions_executed':{hex(a):self.visits[a] for a in
                [ENUM,0x1d854e,0x1d8514,0x275590,0x274acc,0x278194,0x2745cc,0x274992,0x274978,
                 0x39129c,0x1e86ce,0x1e8046,0x2fb988,0x1fb304]},
            'original_code_heap_and_stack_guards_intact':True,'temporary_objects_released_registry_nodes_retained':True,
            'outer_directory_and_binding_activation_wrappers_are_fixtures':True,
            'modified_module_instructions_executed':False}


def main():
    stock=NativeImage();allrows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
    rows=[r for r in allrows if r['native_module_container']];cases=[]
    def inventory(row,data=None,name=None):return {'name':name or Path(row['file']).name,
        'data':(ROOT/row['file']).read_bytes() if data is None else data}
    def test(name,items,expected_count,*,predicate=True,mount_error=0):
        vm=RegistryVM(stock,items,predicate_accept=predicate,mount_error=mount_error);result=vm.enumerate()
        require(len(result['registry'])==expected_count,name+': native registry count differs')
        cases.append({'name':name,'passed':True,'expected_registered_voices':expected_count,
            'predicate_accept_fixture':predicate,'mount_error_fixture':mount_error,'result':result})
        return vm,result
    for row in rows:test('original_'+Path(row['file']).stem,[inventory(row)],1)
    test('all_three_original_sorted_native_registry',[inventory(r) for r in reversed(rows)],3)
    row=rows[0];original=(ROOT/row['file']).read_bytes();files,geometry=parse_image(original)
    changed=mutate_member(original,files['DLLIMG.BIN'],geometry,lambda p:p.__setitem__(0x100,p[0x100]^1))
    zero_sig=mutate_member(original,files['DLLIMG.SIG'],geometry,lambda p:p.__setitem__(slice(None),bytes(len(p))))
    absent=replace_metadata(original,files,geometry,b'lang_name',b'lang_none')
    for name,data,n in [('modified_DLL_stale_metadata_sum',changed,1),('zero_SIG',zero_sig,1),('missing_required_language',absent,0)]:
        test(name,[inventory(row,data)],n)
    test('platform_predicate_rejects_type1',[inventory(row)],0,predicate=False)
    test('outer_region_binding_failure_skips_metadata',[inventory(row)],0,mount_error=-1)
    test('duplicate_volume_ID_skips_second_registration',[inventory(row),inventory(row,name='duplicate.vpm')],1)
    deps=[Path(__file__),ROOT/'scripts/emulate_native_voice_metadata.py',ROOT/'scripts/emulate_native_vpm_filesystem.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_tts_vpm.py',ROOT/'scripts/analyze_native_voice_acceptance.py',
        ROOT/'scripts/analyze_native_loader.py',ROOT/'scripts/emulate_native_loader.py']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,'all_passed':True,'case_count':len(cases),
        'cases':cases,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in deps},
        'outer_original_enumerator_metadata_platform_predicate_sorted_registry_executed':True,
        'original_embedded_mount_parser_and_readers_executed':True,'outer_storage_and_activation_wrappers_are_fixtures':True,
        'live_platform_predicate_or_real_outer_mount_verified':False,'modified_module_instructions_executed':False,
        'device_io':False,'backup_modified':False,'device_install_candidate':False,
        'limits':'Original1D897C scans fixture *.vpm directory, invokes real metadata/predicate/duplicate checks/native sorted1912-byte registry and *.NEW fallback. Directory inventory and file-to-region binding are fixtures; FEA50 is tail-routed to stock1E86CE embedded parser, not complete actual wrapper/device notifications. Cached platform ID/config values arbitrary, not live HWID. Stale checksum/zeroSIG registration proves only this path under fixtures, no global signature-policy absence or real package acceptance. No modified code executed or actual selection/load/App.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-registry-emulation.json'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),'all_passed':True}))


if __name__=='__main__':main()
