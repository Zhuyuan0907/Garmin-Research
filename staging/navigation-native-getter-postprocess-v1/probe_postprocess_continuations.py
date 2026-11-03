#!/usr/bin/env python3
"""At most two saved-endpoint continuations, no preceding getter replay.

The saved endpoint has text/arguments but no complete RAM snapshot. Every
callframe here is explicitly reconstructed from original push/pop ABI and
known former arguments. This is neither a native cold setup nor an
uninterrupted native query.
"""
import hashlib,importlib.util,json,struct,sys,gc
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
PREVIOUS=ROOT/'staging/navigation-native-query-provider-full-getter-v1'
DEPS=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,s):
    if not x:raise ValueError(s)
def stat(p):
    x=p.stat();return[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def pin(p,d):
    before=stat(p);b=p.read_bytes();need(sha(b)==d and stat(p)==before,'Frozen small source:'+str(p));DEPS.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=d,stat=before));return b
def save(n,x):
    with(HERE/n).open('x')as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')
def load_module(p,d,name):
    pin(p,d);sp=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

def main():
    need(not(HERE/'proof.json').exists(),'New finite postprocess scope only')
    for low in[48312,3781595]:need(not(HERE/f'actual-continuation-{low}.json').exists(),'No successful/failed case replay')
    started=datetime.now(timezone.utc).isoformat()
    seal=json.loads(pin(PREVIOUS/'sealed-files.json','49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'))
    def old(n):
        p=PREVIOUS/n;e=next(x for x in seal['files']if x['path']==str(p.relative_to(ROOT)));return pin(p,e['sha256'])
    src=json.loads(old('actual-source-windows.json'));priorproof=json.loads(old('proof.json'))
    street=json.loads(old('fixture-development-getter-attempt.json'));house=json.loads(old('actual-house-getter-frontier.json'))
    gmodule=load_module(PREVIOUS/'probe_actual_provider_getter.py','a8ddd164df35c997536ec610b7bf2b7839d2a4befaea8bc121873f85d662cc6e','frozen_guest_scaffold_only')
    saved=gmodule.SavedMAIN();machine=gmodule.module('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','frozen_ARM1176_machine_only')
    receipts=[json.loads((HERE/n).read_text())for n in['initial-capture-receipt.json','additional-capture-receipt.json']]
    new_pages=[]
    for r in receipts:
        for e in r['reads']:
            p=HERE/f"MAIN-page-{e['runtime']:08x}.bin";b=pin(p,e['sha256']);need(len(b)==4096,'New original code page');saved.pages[e['runtime']]=b;new_pages.append(e)
    need(sum(x['bytes']for x in new_pages)==12288<=24576,'New MAIN finite cap')
    need(saved.pages[0x49A000][0x710:0x72A].hex()=='0a06120e401e4178401c8a4201d00029f9d18a4200d000207047','Exact original byte-character search code')
    windows={(e['component'],e['offset']):bytes.fromhex(e['hex'])for e in src['sources']if(e['component']=='00004171.MDR'and e['bytes']in[4,18,20])or(e['component']=='I053061A.GMP'and e['offset']>=3812824)}
    original=ROOT/'evidence/firmware-analysis/main_02bd.bin';candidate=ROOT/priorproof['candidate']['path']
    beforemain=stat(original);beforeimg=stat(candidate);need(beforeimg==src['candidate_stat']and all(r['stat_before']==r['stat_after']==beforemain for r in receipts),'Actual inherited source identity stats')
    cases=[];frames=[]
    for low,level,label,ref,frozen in[(48312,3,'敦富六街',475679,street),(3781595,4,'368號',2967,house)]:
        raw=bytes.fromhex(frozen['output_hex']);text=raw.split(b'\0',1)[0];need(text.decode('cp950')==label and frozen['frontier']['arguments_r0_r1']==[gmodule.OUT,29],'Frozen actual endpoint text/ABI')
        class Continuation(gmodule.Guest):
            def __init__(self,*a,**k):super().__init__(*a,**k);self.observations=[];self.unexpected=None
            def code(self,u,pc,n,opaque):
                if pc in[0x112194,0x3324B8,0x44B10E4,0x448F740,0x359038,0x1F7814,0x1EE156,0x1AF428,0x1BE518,0x44C0E9A,0x44C170E,0x44BFF18]:
                    self.unexpected=dict(pc=hex(pc),reason='would replay preceding successful getter/metadata/FS path');u.emu_stop();return
                if pc==0x44BFF32:
                    # This BLX was the precise prior stop-before-call. It executes
                    # now and reaches the genuine new helper, no replacement.
                    self.trace.append((pc,bytes(u.mem_read(pc,n)).hex()));self.visits[pc]=self.visits.get(pc,0)+1;return
                if pc in[0x49A710,0x49A728,0x44C12D4,0x44C1B4E,0x1AFBA0,0x44B1590]:
                    self.observations.append(dict(pc=hex(pc),r0=self.r(0),r1=self.r(1),SP=u.reg_read(gmodule.UC_ARM_REG_SP)))
                super().code(u,pc,n,opaque)
        guest=Continuation(machine,saved,windows,src['metadata'],level=level);u=guest.u
        # No native instruction from the earlier case is re-executed. Output,
        # cache and existing allocation come from frozen observed values.
        u.mem_write(gmodule.OUT,raw);guest.w32(gmodule.GMP+0xCC0,0);guest.w32(gmodule.GMP+0xCC4,0)
        handle=0x09110100;allocbuf=0x09110200;guest.allocations[handle]=allocbuf;guest.allocated=1
        # Parent's frozen stack was not saved. ABI-defined frame reconstruction.
        top=gmodule.STACK+0x3000;s6=top-0x48;s5=s6-0x50;s4=s5-0x38;s3=s4-0x120;s2=s3-0x88;s1=s2-0x40
        pair=s6+0x0C;refptr=pair+4;fmt=gmodule.GMP+0x774;flags=0x00800000
        def put(base,items):
            for off,value in items:guest.w32(base+off,value)
        # Public 044B153A frame: caller registers are declared zero fixtures.
        put(s6,[(0,192),(4,flags),(0x0C,1),(0x10,ref),(0x38,0),(0x3C,0),(0x40,0),(0x44,gmodule.RET|1)])
        # 1AFC7C kind7 dispatch frame, returns to the original consumer tail.
        put(s5,[(0x2C,gmodule.CTX),(0x30,pair),(0x34,7),(0x38,gmodule.OUT),(0x3C,gmodule.DIR+0x140),(0x40,gmodule.OUT),(0x44,192),(0x48,0),(0x4C,0x44B1591),(0x50,192),(0x54,flags)])
        # 1AFB3E frame: current-thread helper result was truly0 in previous case.
        put(s4,[(0x10,0),(0x14,gmodule.CTX),(0x18,pair),(0x1C,gmodule.OUT),(0x20,192),(0x24,pair),(0x28,gmodule.OUT),(0x2C,192),(0x30,0),(0x34,0x1AFCB7),(0x38,flags)])
        # 044C170E dispatcher frame/local fields required after decoder return.
        # ldr r7 at1774 uses literal1B6C; its value is saved original bytes.
        const7=struct.unpack_from('<I',saved.pages[0x44C1000],0xB6C)[0]
        put(s3,[(0x18,handle),(0x1C,0),(0x20,2),(0x24,950),(0x5C,gmodule.OUT),(0x64,192),(0x68,ref),(0x70,0),(0x78,255),(0x7C,0),(0xEC,fmt),(0xF8,gmodule.GMP+0x340),
            (0xFC,gmodule.GMP),(0x100,refptr),(0x104,5),(0x108,gmodule.OUT),(0x10C,pair),(0x110,gmodule.OUT),(0x114,192),(0x118,refptr),(0x11C,0x1AFBA1),(0x120,192),(0x124,flags),(0x128,0)])
        # 044C0E9A decoder frame: only its return tail remains. The consumed
        # label offset includes the actual terminating zero from frozen text.
        labelend=src['metadata']['label_start']+(ref<<src['metadata']['shift'])+len(text)+1
        put(s2,[(0x48,labelend),(0x64,gmodule.GMP),(0x68,ref),(0x6C,gmodule.OUT),(0x70,192),(0x74,refptr),(0x78,flags),(0x7C,0),(0x80,const7),(0x84,0x44C1B4F),(0x88,flags),(0x8C,0),(0x90,0)])
        # 044BFF18 frame at its actual stop-before-first-helper call.
        put(s1,[(0,0),(0x14,gmodule.OUT+192-32),(0x18,0),(0x1C,fmt),(0x20,gmodule.OUT),(0x24,192),(0x28,flags),(0x2C,0),(0x30,gmodule.OUT),(0x34,len(text)+1),(0x38,0),(0x3C,0x44C12D5)])
        for reg,value in[(gmodule.UC_ARM_REG_R0,gmodule.OUT),(gmodule.UC_ARM_REG_R1,29),(gmodule.UC_ARM_REG_R4,gmodule.OUT),(gmodule.UC_ARM_REG_R5,192),(gmodule.UC_ARM_REG_R6,flags),(gmodule.UC_ARM_REG_R7,0),(gmodule.UC_ARM_REG_SP,s1)]:u.reg_write(reg,value)
        frame=dict(lowID=low,SP_top=hex(top),frames=dict(public=hex(s6),kind7=hex(s5),provider=hex(s4),kind5=hex(s3),decoder=hex(s2),postprocess=hex(s1)),
            frame_total_bytes=top-s1,frame_hex=bytes(u.mem_read(s1,top-s1)).hex(),frame_sha256=sha(bytes(u.mem_read(s1,top-s1))),not_a_saved_CPU_RAM_snapshot=True,unknown_caller_saved_registers_zero_fixture=True,
            every_return_PC_from_original_callsite=True,expected_next_label_offset=labelend,raw_text_origin='previous sealed actual decoder output',GMP_format_context_at774_zero_fields_inherited_from_prior_fixture=True)
        frames.append(frame)
        try:
            result=guest.run(0x44BFF32,[gmodule.OUT,29],limit=12000);result.update(lowID=low,level=level,text_before=label,observed_native_returns=guest.observations,ABI_frame_fixture=frame,unexpected_old_path=guest.unexpected)
            need(guest.unexpected is None,'No earlier successful case replay')
            emitted=bytes(u.mem_read(gmodule.OUT,192));result['text_after']=emitted.split(b'\0',1)[0].decode('cp950');need(result['text_after']==label,'Plain literal text remains exact')
            need(result['native_function_return']and result['native_return_r0']==0,'Resumed original public getter tail actual return0')
            for pc in['0x49a728','0x44c12d4','0x44c1b4e','0x1afba0','0x44b1590']:
                need(any(x['pc']==pc and x['r0']==0 for x in guest.observations),'True byte-search/formatter/decoder/dispatcher/public return0:'+pc)
            need(len([x for x in result['explicit_fixture_events']if x['kind']=='explicit_temporary_memory_free_fixture'])==1,'Frozen allocation released at original free call boundary')
            result['all_assigned_checks_passed']=True
        except Exception as e:
            result=dict(lowID=low,level=level,error=repr(e),invalid=guest.invalid,unexpected_old_path=guest.unexpected,last_original_instructions=guest.trace[-32:],observations=guest.observations,events=guest.events,instructions=len(guest.trace),ABI_frame_fixture=frame,
                all_assigned_checks_passed=False,no_unknown_callee_return_faked=True,not_retried=True)
        save(f'actual-continuation-{low}.json',result);cases.append(result);del guest;gc.collect()
    need(stat(original)==beforemain and stat(candidate)==beforeimg,'Original source stats unchanged after saved-byte continuations')
    proof=dict(schema='garmin-native-getter-postprocess-continuation/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=all(x['all_assigned_checks_passed']for x in cases),
        scope_completed=True,script_sha256=sha(Path(__file__).read_bytes()),dependencies=DEPS+gmodule.DEPENDENCIES,new_MAIN_bytes_read=12288,new_MAIN_cap_bytes=24576,new_IMG_bytes_read=0,new_IMG_max_if_needed=4096,
        MAIN_source_stat_before=beforemain,MAIN_source_stat_after=stat(original),candidate_stat_before=beforeimg,candidate_stat_after=stat(candidate),candidate_whole_sha256_inherited=priorproof['candidate']['inherited_root_readback_sha256'],whole_blob_hash_repeated=False,
        original_postprocess_helper=dict(address='0x0049A710',bytes=26,semantics='byte-character search with r1 low8bits; returns pointer to matching byte, or0 after NUL mismatch',current_search_byte=29,guest_original_return_zero_for_both_literals=True),
        current_postprocess_semantics='find marker0x1D then optional flag-controlled label formatting/marker stripping; current rawflags0x800000 plain CP950 inputs unchanged and original formatterreturn0',
        actual_cases=[dict(lowID=x['lowID'],instructions=x['instructions'],passed=x['all_assigned_checks_passed'],native_return_r0=x.get('native_return_r0'),text_after=x.get('text_after'),error=x.get('error'),trace_sha256=x.get('trace_sha256'))for x in cases],
        source_endpoint_complete_RAM_snapshot_available=False,callframe_ABI_reconstruction_is_explicit_fixture=True,
        native_public_getter_tail_return0_under_reconstructed_frame_fixture=all(x['all_assigned_checks_passed']for x in cases),same_original_guest_resumed=False,
        preceding_sealed_3671_3607_instruction_cases_replayed=False,old_query_IMG_or_CPU_suites_run=False,actual_FS_getter_prefix_metadata_replayed=False,source_IMG_or_DB_opened=False,
        unknown_native_callee_return_faked=False,original_MAIN_or_code_patched=False,
        actual_uninterrupted_query_vector_to_MDR_to_full_getter=False,native_cold_provider_registry_or_GMP_initialization=False,native_SQLite=False,native_UI=False,physical_device_acceptance=False,installable=False,full_Taiwan_complete=False,
        explicit_fixtures=['frozen actual street/house bytes and first helper arguments from prior sealed endpoint','saved callframes reconstructed from original push/sub/add/pop ABI and known previous arguments, not a full CPU/RAM snapshot','unknown caller preserved registers zero; relevant output/flags/context/descriptor values explicit','GMP+774 format context remains the zeroed object from prior fixture: original validity helper naturally chooses byte-terminal scan fallback','existing152-byte allocation handle/buffer and same free-boundaryfixture; no allocator or FS calls replayed','provider cleanup marker from prior initialized fixture prevents cold close, native cleanup wrapper itself executes'],
        source_alias_house368_2026_continuity_proof_not_added=True,all_handles_closed=True,no_sealed_source_candidate_report_or_device_mutation=True,
        limitation='Resumed original decoder/dispatch/public return0 is observed under declared reconstructed ABI frames. It does not restore a saved full guest or connect native SQLite/query/provider initialization/UI.')
    save('proof.json',proof);print(json.dumps(dict(all_assigned_checks_passed=proof['all_assigned_checks_passed'],new_MAIN_bytes=12288,new_IMG_bytes=0,cases=proof['actual_cases'],ABI_callframe_fixture=True,uninterrupted_query=False,all_handles_closed=True),ensure_ascii=False))
if __name__=='__main__':main()
