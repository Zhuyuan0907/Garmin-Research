#!/usr/bin/env python3
"""Finite native metadata/getter frontier, actual new IMG and explicit fixtures.

Reads saved original pages only (new MAIN captures total exactly 64 KiB).
No original/old cases or main functions executed. No high-level return hook.
"""
import ast, gc, hashlib, importlib.util, json, struct, sys, time
from datetime import datetime, timezone
from pathlib import Path
sys.dont_write_bytecode=True
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *
ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
OLD=ROOT/'staging/navigation-native-jai-img-materializer-abi-v1'
IMG='staging/navigation-new-street-v2-4k-offline-prototype-v2/new-street-v2-original4k-experiment.img.disabled'
CTX,FILE,DIR,OUT,RET,GMP,STACK=0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09008000,0x09010000
GFILE=FILE+0x400;CACHE_MARKER=CTX+0x600;THREAD=CTX+0x700
REG_NODE=0x09100000;REG_BLOCK=REG_NODE+0x1000;DESC=REG_BLOCK+0x100
REG_GLOBAL=0x01286BCC;SLOTS=0x00F00114
RAM_AUX=0x09110000
DEPENDENCIES=[]
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
    x=p.stat();return[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def save(name,obj):
    with(HERE/name).open('x')as f:json.dump(obj,f,ensure_ascii=False,indent=2);f.write('\n')
def pinned(rel,digest,cap=1500000):
    p=ROOT/rel;x=stat(p);need(x[2]<=cap,'Small input cap');b=p.read_bytes();need(stat(p)==x and sha(b)==digest,'Input identity:'+rel)
    DEPENDENCIES.append(dict(path=rel,bytes=len(b),sha256=digest,stat=x));return b
def module(rel,digest,name):
    pinned(rel,digest);spec=importlib.util.spec_from_file_location(name,ROOT/rel);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

class SavedMAIN:
    def __init__(self):
        self.pages={};self.receipts=[]
        captures=[json.loads((HERE/n).read_text())for n in ['initial-MAIN-capture-receipt.json','additional-MAIN-capture-receipt.json','final-MAIN-capture-receipt.json']]
        # Per-capture shapes are inherited and all page identities are checked.
        for p in sorted(HERE.glob('MAIN-page-*.bin')):
            b=p.read_bytes();need(len(b)==4096,'Saved bounded original page');a=int(p.stem.split('-')[-1],16)
            witnesses=[]
            for r in captures:
                for x in r.get('reads',r.get('pages',[])):
                    if x.get('runtime')==a or x.get('runtime')==hex(a):witnesses.append(x)
            need(len(witnesses)==1 and witnesses[0]['sha256']==sha(b),'Exact initial bounded original capture')
            self.pages[a]=b;self.receipts.append(dict(path=str(p.relative_to(ROOT)),runtime=a,bytes=len(b),sha256=sha(b),new_original_page=True))
        need(len(self.pages)==16 and sum(len(x)for x in self.pages.values())==65536,'Exact new MAIN budget')
        oldseal=json.loads(pinned(str((OLD/'sealed-files.json').relative_to(ROOT)),'333dc553b0e259a8b5493d77168ebffca726b22f99be1992f7f3481443e38b3b'))
        for a in [0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000,0x00332000,0x044C0000,0x044C1000]:
            p=OLD/f'MAIN-page-{a:08x}.bin';row=next(x for x in oldseal['files']if x['path']==str(p.relative_to(ROOT)))
            b=pinned(str(p.relative_to(ROOT)),row['sha256']);need(len(b)==4096,'Inherited sealed page');self.pages[a]=b
            self.receipts.append(dict(path=str(p.relative_to(ROOT)),runtime=a,bytes=len(b),sha256=sha(b),new_original_page=False))
        row=next(x for x in oldseal['files']if x['path']==str((OLD/'proof.json').relative_to(ROOT)))
        self.old=json.loads(pinned(str((OLD/'proof.json').relative_to(ROOT)),row['sha256']))
    def read(self,a,n):
        need(n==4096 and a in self.pages,'Saved original pages only');return self.pages[a]
    def runtime_to_load(self,*args):raise ValueError('Saved runtime pages already mapped')

class Guest:
    def __init__(self,machine,saved,windows,metadata,level=None,missing_registry=False):
        self.saved=saved;self.windows=windows;self.metadata=metadata;self.events=[];self.trace=[];self.visits={};self.frontier=None;self.invalid=None;self.stopped=False;self.allocations={};self.allocated=0
        self.u,self.page_receipts=machine.CPU(saved).machine(sorted(saved.pages))
        u=self.u
        for a,n in [(0x01286000,0x3000),(0x00F00000,0x1000),(0x00F09000,0x1000),(REG_NODE,0x2000),(RAM_AUX,0x10000)]:u.mem_map(a,n)
        # Explicit already-initialized registry. Native lookup/enumeration is run.
        self.w32(0x00F004F0,0);u.mem_write(SLOTS,b'\xff'*99);u.mem_write(SLOTS,b'\x03')
        if not missing_registry:
            self.w32(REG_GLOBAL,REG_NODE);u.mem_write(REG_GLOBAL+0xC,struct.pack('<H',1))
            self.w32(REG_NODE,REG_BLOCK);self.w32(REG_NODE+4,0);u.mem_write(REG_BLOCK+2,struct.pack('<h',1));self.w32(DESC+0x2C,metadata['mapID'])
        # Native current-thread helper returns zero by its own pointer comparison.
        thread_ptr=struct.unpack_from('<I',saved.pages[0x1C0000],0x620)[0]
        need(thread_ptr==0x00F09090,'Observed original current-thread context pointer literal')
        self.w32(thread_ptr,THREAD);self.w32(THREAD+0x40,THREAD)
        # Actual header-derived MDR1 fields plus previously sealed native DIR endpoint.
        self.w32(CTX+0x20,FILE);self.w32(CTX+0x24,0)
        self.w32(CTX+0x58,metadata['MDR1_offset']);u.mem_write(CTX+0x5C,struct.pack('<H',metadata['MDR1_stride']));self.w32(CTX+0x64,metadata['MDR1_count'])
        u.mem_write(CTX+0x28,struct.pack('<H',950))
        for f,component in [(FILE,'00004171.MDR'),(GFILE,'I053061A.GMP')]:
            u.mem_write(f+11,b'\x40');self.w32(f+12,metadata['component_bytes'][component]);self.w32(f+16,0)
        self.w32(CTX+0x3F4,GMP);self.w32(CTX+0x3F8,CACHE_MARKER);u.mem_write(CACHE_MARKER,b'\x01')
        # Explicit open and cached GMP context; no file loader/admission claim.
        self.w32(GMP+0x20,metadata['mapID']);self.w32(GMP+0x34,GFILE);self.w32(GMP+0x38,0)
        self.w32(GMP+0x33C,GFILE);self.w32(GMP+0x340,0)
        u.mem_write(GMP+0x345,bytes([metadata['shift']]));u.mem_write(GMP+0x346,bytes([metadata['encoding']]));u.mem_write(GMP+0x34C,struct.pack('<H',metadata['codepage']))
        self.w32(GMP+0x364,metadata['label_start']);self.w32(GMP+0x368,metadata['label_size'])
        # TRE current minimum level is explicit public level-table initialization.
        u.mem_write(GMP+0x68,bytes([metadata['minimum_TRE_level']]));u.mem_write(GMP+0x56+metadata['minimum_TRE_level'],bytes([metadata['native_coordinate_bits']]))
        self.w32(GMP+0xCC0,0xA5A5A5A5);self.w32(GMP+0xCC4,0x5A5A5A5A)
        u.mem_write(DIR,bytes.fromhex(saved.old['actual_original_directory_execution']['actual_output_hex']));self.w32(DIR+0x154,CTX)
        if level:self.w32(DIR+0x160,level)
        # Each actual mapped FS span ends against an unmapped guard page.
        self.buffers={}
        for idx,((component,offset),raw)in enumerate(windows.items()):
            base=0x09200000+idx*0x2000;u.mem_map(base,4096);ptr=base+4096-len(raw);u.mem_write(ptr,raw);u.mem_protect(base,4096,UC_PROT_READ);self.buffers[component,offset]=(ptr,len(raw),sha(raw))
        self.hook=u.hook_add(UC_HOOK_CODE,self.code);u.hook_add(UC_HOOK_MEM_INVALID,self.bad)
    def r(self,n):return self.u.reg_read([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3][n])
    def word(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
    def w32(self,a,x):self.u.mem_write(a,struct.pack('<I',x&0xFFFFFFFF))
    def ret(self,x):self.u.reg_write(UC_ARM_REG_R0,x&0xFFFFFFFF);self.u.reg_write(UC_ARM_REG_PC,self.u.reg_read(UC_ARM_REG_LR))
    def bad(self,u,access,a,n,value,_):
        self.invalid=dict(access=access,address=hex(a),bytes=n,value=value,pc=hex(u.reg_read(UC_ARM_REG_PC)));return False
    def code(self,u,pc,n,_):
        self.trace.append((pc,bytes(u.mem_read(pc,n)).hex()));self.visits[pc]=self.visits.get(pc,0)+1
        if pc==RET:self.stopped=True;u.emu_stop();return
        if pc in [0x3009A0,0x3008B0]:
            self.events.append(dict(kind='explicit_OS_mutex_boundary_fixture',entry=hex(pc),mutex=hex(self.r(0)),semantics='single guest no concurrent OS owner'));self.ret(0);return
        if pc==0x3324B8:
            fp,dst,count=self.r(0),self.r(1),self.r(2);need(fp==FILE and count==4,'Only actual MDR1 FS read fixture')
            off=self.word(FILE+16);raw=self.windows['00004171.MDR',off];need(len(raw)==4,'MDR1 actual 4 bytes')
            u.mem_write(dst,raw);self.w32(FILE+16,off+4);self.events.append(dict(kind='actual_MDR1_bottom_FS_read_fixture',offset=off,bytes=4,sha256=sha(raw)));self.ret(0);return
        if pc==0x112194:
            fp,dst,mode=self.r(0),self.r(1),self.r(2);need(mode==0 and fp in [FILE,GFILE],'Supported actual bottom FS mapping only')
            c='00004171.MDR'if fp==FILE else'I053061A.GMP';off=self.word(fp+16);need((c,off)in self.buffers,'No invented FS bytes outside assigned windows')
            ptr,count,digest=self.buffers[c,off];self.w32(dst,ptr);self.events.append(dict(kind='actual_bottom_FS_window_mapping_fixture',component=c,offset=off,bytes=count,sha256=digest,guard_page=True,realigned=False));self.ret(count);return
        if pc==0x38853C:
            count,flags,out=self.r(0),self.r(1),self.r(2);need(count==0x98 and flags==0 and self.allocated==0,'One bounded temporary-memory allocator fixture')
            self.allocated+=1;handle=RAM_AUX+0x100;buf=RAM_AUX+0x200;self.allocations[handle]=buf;self.w32(out,handle)
            self.events.append(dict(kind='explicit_temporary_memory_allocator_fixture',bytes=count,handle=hex(handle),buffer=hex(buf)));self.ret(0);return
        if pc==0x388804:
            h=self.r(0);need(h in self.allocations,'Exact allocated fixture handle');self.events.append(dict(kind='explicit_temporary_handle_buffer_fixture',handle=hex(h)));self.ret(self.allocations[h]);return
        if pc==0x3887A2:
            p=self.r(0);h=self.word(p);need(h in self.allocations,'Only allocated fixture memory release');self.w32(p,0);self.events.append(dict(kind='explicit_temporary_memory_free_fixture',handle=hex(h)));self.ret(0);return
        if pc==0x448FD60:
            # This literal original veneer targets known two-argument byte-zero API.
            dst,count=self.r(0),self.r(1);need(0<count<=192 and (RAM_AUX<=dst<RAM_AUX+0x10000 or OUT<=dst<OUT+4096),'Bounded known zero-buffer ABI')
            u.mem_write(dst,b'\0'*count);self.events.append(dict(kind='explicit_byte_zero_libc_fixture',bytes=count,destination=hex(dst)));self.ret(dst);return
        if pc==0x44BFF32:
            self.frontier=dict(stop_before_original_call=hex(pc),callee_veneer='0x0448E868',actual_original_veneer_target='0x0049A711',arguments_r0_r1=[self.r(0),self.r(1)],
                source_pointer=hex(self.r(0)),source_bytes=bytes(u.mem_read(self.r(0),32)).hex(),unknown_callee_return_not_faked=True,stage='complete LBL decoder already reached original postprocess call')
            u.emu_stop();return
    def run(self,entry,args,limit=50000):
        for i,x in enumerate(args):self.u.reg_write([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3][i],x)
        self.u.emu_start(entry|1,RET+2,count=limit,timeout=3000000)
        need(self.stopped or self.frontier,'Guest exceeded finite scope without known frontier')
        return dict(entry=hex(entry),native_function_return=self.stopped,native_return_r0=self.r(0)if self.stopped else None,
            instructions=len(self.trace),trace_sha256=sha(json.dumps(self.trace).encode()),last_original_instructions=self.trace[-16:],frontier=self.frontier,invalid_memory=self.invalid,
            explicit_fixture_events=self.events,actual_original_entry_visits={hex(k):v for k,v in self.visits.items()if k in [0x44B10E4,0x448F740,0x359038,0x1F7814,0x1EE156,0x32C2C2,0x32BE40,0x1AF428,0x1AF4BA,0x1BE518,0x1C0600,0x1AFB3E,0x1AFC7C,0x2BF5F4,0x44C170E,0x44C0E9A,0x44BFF18]},
            GMP_CC0_CC4_after=[self.word(GMP+0xCC0),self.word(GMP+0xCC4)],output_hex=bytes(self.u.mem_read(OUT,192)).hex(),readonly_RX_pages=self.page_receipts)

def main():
    started=datetime.now(timezone.utc).isoformat();need(not(HERE/'proof.json').exists(),'Finite new scope only');saved=SavedMAIN()
    machine=module('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','reused_frozen_FS_and_CPU_only')
    seal=json.loads(pinned('staging/navigation-new-street-v2-4k-offline-prototype-v2/sealed-files.json','5dc142d545ad114c727e7ecad97b8e42ef8df348aaaf406291a631e36496ba03'))
    row=next(x for x in seal['files']if x['path']==IMG);need(stat(ROOT/IMG)==row['stat_at_seal'],'Actual candidate freeze pin')
    class BudgetIMG(machine.CandidateIMG):
        def physical(self,off,n,purpose):
            need(sum(x['bytes']for x in self.log)+n<=131072,'Actual IMG byte cap');need(0<=off<=off+n<=self.before[2],'Actual IMG bounds')
            if not self.log:self.stream.close();self.stream=self.path.open('rb',buffering=0)
            self.stream.seek(off);raw=self.stream.read(n);need(len(raw)==n,'Actual IMG shortread')
            self.log.append(dict(physical_offset=off,bytes=n,purpose=purpose,sha256=sha(raw)));return raw
    image=BudgetIMG(ROOT/IMG);sources=[];windows={};results=[]
    def read(c,off,n,p):
        witness,raw=image.read(c,off,n,p);sources.append(witness);return raw
    try:
        need(image.block_size==4096 and image.before[2]==132173824,'Exact actual candidate geometry')
        header=read('00004171.MDR',0,772,'actual_new_MDR_header_for_MDR1_fields')
        need(header.hex()==saved.old['actual_MDR_header_source']['hex'],'Exact previous endpoint actual header')
        mdr1start=struct.unpack_from('<I',header,29)[0];mdr1size=struct.unpack_from('<I',header,33)[0];mdr1stride=struct.unpack_from('<H',header,37)[0]
        need((mdr1start,mdr1size,mdr1stride)==(772,4,4),'Actual MDR1 unique mapordinal schema')
        mapbytes=read('00004171.MDR',mdr1start,4,'actual mapordinal1 source mapID');windows['00004171.MDR',mdr1start]=mapbytes;mapID=struct.unpack('<I',mapbytes)[0]
        gh=read('I053061A.GMP',0,57,'actual newGMP public header');tre,_,lbl=struct.unpack_from('<3I',gh,25)
        th=read('I053061A.GMP',tre,289,'actual TRE public metadata for exact mapID and scale')
        need(struct.unpack_from('<I',th,116)[0]&0x0FFFFFFF==mapID,'Actual TRE/MDR1 exact mapID')
        leveloffset,levelsize=struct.unpack_from('<2I',th,33);need(levelsize==20,'Bounded actual TRElevels table')
        lv=read('I053061A.GMP',leveloffset,levelsize,'actual TRE5levels min and coordinate precision')
        levels=[dict(level=lv[i]&0x7F,precision=lv[i+1],hex=lv[i:i+4].hex())for i in range(0,len(lv),4)];minimum=min(x['level']for x in levels);bits=next(x['precision']for x in levels if x['level']==minimum)
        lh=read('I053061A.GMP',lbl,661,'actual new LBL full public header')
        labelstart,labelsize=struct.unpack_from('<2I',lh,21);shift,encoding=lh[29:31];codepage=struct.unpack_from('<H',lh,170)[0]
        meta=dict(mapID=mapID,MDR1_offset=mdr1start,MDR1_stride=mdr1stride,MDR1_count=mdr1size//mdr1stride,label_start=labelstart,label_size=labelsize,shift=shift,encoding=encoding,codepage=codepage,minimum_TRE_level=minimum,native_coordinate_bits=bits,TRE_levels=levels,component_bytes={x:y['bytes']for x,y in image.components.items()})
        need((mapID,labelstart,labelsize,shift,encoding,codepage,minimum,bits)==(5441050,3812824,3805448,3,10,950,0,24),'Actual exact metadata values')
        for low,level in [(48312,3),(3781595,4)]:
            old=next(x for x in saved.old['actual_native_prefixes']if x['lowID']==low and x['level']==level);off=old['MDR_offset'];n=len(bytes.fromhex(old['actual_IMG_source']['hex']))
            raw=read('00004171.MDR',off,n,'actual_new_full_getter_record_'+str(low));need(raw.hex()==old['actual_IMG_source']['hex'],'Actual packed input identity');windows['00004171.MDR',off]=raw
        for ref in [475679,2967]:
            off=labelstart+(ref<<shift);n=min(32,image.components['I053061A.GMP']['bytes']-off)
            windows['I053061A.GMP',off]=read('I053061A.GMP',off,n,'actual_new_LBL_source_'+str(ref))
        # Save all original candidate reads once; subsequent CPU consumes these windows.
        save('actual-source-windows.json',dict(candidate_bytes=image.before[2],inherited_whole_SHA256=row['sha256'],wholehash_not_repeated=True,metadata=meta,sources=sources,actual_IMG_read_log=image.log,candidate_stat=image.before))
        # New real failure guard, genuinely executed registry enumeration exhausts.
        g=Guest(machine,saved,windows,meta,missing_registry=True);r=g.run(0x359038,[CTX,1,0]);need(r['native_function_return']and r['native_return_r0']==1,'True registry missing-descriptor guard')
        r.update(name='new_actual_MDR1_registry_missing_guard',metadata_or_getter_return_hooked=False,fixture='registry head/count absent; initialized cached GMP has actual mapID, real lookup must refuse');save('actual-registry-missing-guard.json',r);results.append(r);del g;gc.collect()
        # Two new paths share actual source, do not run old prefix or old labels cases.
        for low,level,text in [(48312,3,'敦富六街'),(3781595,4,'368號')]:
            g=Guest(machine,saved,windows,meta,level=level);r=g.run(0x44B153A,[DIR,low,OUT,192]);r.update(name='actual_full_getter_frontier_'+str(low),lowID=low,level=level,expected_CP950_text=text,whole_query_UI_not_executed=True)
            raw=bytes.fromhex(r['output_hex']).split(b'\0',1)[0];r['actual_output_CP950_hex']=raw.hex();r['actual_output_text']=raw.decode('cp950')
            need(r['frontier']and r['frontier']['stop_before_original_call']=='0x44bff32','Exact unknown original formatter frontier')
            need(r['actual_output_text']==text,'True complete LBL decoder actual source text')
            need(all(r['actual_original_entry_visits'].get(hex(x),0)>0 for x in [0x44B10E4,0x448F740,0x359038,0x1F7814,0x1EE156,0x32BE40,0x1AF428,0x1BE518,0x1AFB3E,0x1AFC7C,0x2BF5F4,0x44C170E,0x44C0E9A,0x44BFF18]),'Unbroken original packed/provider/decoder instruction chain')
            need(r['GMP_CC0_CC4_after']==[0,0],'Real GMP cached-selector state reset')
            save('actual-getter-frontier-'+str(low)+'.json',r);results.append(r);del g;gc.collect()
    finally:image.close()
    proof=dict(schema='garmin-true-MDR-provider-LBL-getter-frontier/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        candidate=dict(path=IMG,bytes=image.before[2],inherited_root_readback_sha256=row['sha256'],wholehash_not_repeated=True,stat_before=image.before,stat_after=stat(ROOT/IMG)),
        script_sha256=sha(Path(__file__).read_bytes()),dependencies=DEPENDENCIES,source_metadata=meta,new_MAIN_bytes=65536,new_MAIN_cap=65536,new_IMG_bytes=sum(x['bytes']for x in image.log),new_IMG_cap=131072,actual_IMG_read_log=image.log,
        original_code_pages=saved.receipts,actual_cases=[dict(name=x['name'],instructions=x['instructions'],native_function_return=x['native_function_return'],native_return_r0=x['native_return_r0'],frontier=x['frontier'],actual_output_text=x.get('actual_output_text'),trace_sha256=x['trace_sha256'])for x in results],
        all_actual_guest_invalid_accesses=[x['invalid_memory']for x in results],actual_registry_lookup_cached_GMP_selection_beyond_old_0448F740=True,
        actual_full_LBL_decoder_read_actual_IMG_and_output_CP950=True,complete_public_getter_return=False,unknown_formatter_methods_return_faked=False,
        frozen_query_chain_inherited_not_rerun=saved.old['true_JAI_chain'],query_vector_consumer_entry_not_verified=True,
        uninterrupted_native_query_to_getter=False,native_SQLite=False,native_UI=False,physical_acceptance=False,device_IO=False,installable=False,full_Taiwan_complete=False,
        explicit_fixtures=['already initialized registry slot 0, linked block count1 descriptor+2C actual mapID; no Mapload admission','already open GMP cached context mapID/FS pair and TRE/LBL metadata from actual public headers, not original full file-parser execution','external mutex OS boundary for single guest','bounded temporary handle allocator/lookup/free and known byte-zero API','bottom filesystem read/map returns exact bytes only from actual windows; native wrapper/current-position logic executes','query chain is inherited frozen materializer result; no claimed uninterrupted query/provider setup'],
        no_old_cases_or_suites=True,no_sealed_source_or_candidate_IMG_change=True,all_handles_closed=True,
        limits=['Original cached selector executes; actual mapregistry loading/provider cold initialization remains unverified.','MDR public caller complete return is held at true unknown formatter call 044BFF32→0448E868→0049A711; no unknown return fake.','Full source name official2016 witness is parent separate later evidence; historical alias, house368 and2026 continuity not proved here.'])
    save('proof.json',proof);print(json.dumps(dict(all_assigned_checks_passed=True,new_MAIN_bytes=65536,new_IMG_bytes=proof['new_IMG_bytes'],actual_case_count=len(results),complete_getter_return=False,actual_CP950_outputs=[x.get('actual_output_text')for x in results[1:]],all_handles_closed=True),ensure_ascii=False))
if __name__=='__main__':main()
