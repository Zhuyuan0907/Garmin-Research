#!/usr/bin/env python3
"""Eight new bounded state-observation controls, no device or audio output.
Exact original voice/loader/locks/getter run. Warm state is explicit native
initializer input, not a full navigation boot or accepted new physical file.
"""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,struct,gc,mmap,traceback,hashlib
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-inline-fields/marker-package-prep'
def load(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
S=load(OLD/'source-at-strict-first-run.py','frozen_strict_warm_probe');B=S.base
require=S.require
RECORD=0x034e7f48;MIXER=0x034e5378+8*0x130;POOL=0x034e3cf4;HEAD=0x034e68d8+8*4
AUDIO=0x034e3000;AUDIO_BYTES=0x7000
LAST=None
def sha(p):return B.filehash(p)
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
    with p.open('x')as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def reference_sample(vm):
    methods=bytes(vm.uc.mem_read(RECORD+0xf4,68))
    return [vm.word(RECORD+0x88),vm.uc.mem_read(RECORD+0x1f8,1)[0],vm.word(RECORD+0x160),vm.uc.mem_read(RECORD+0x15d,1)[0],
        vm.word(RECORD+0x1ac),struct.unpack('<H',vm.uc.mem_read(RECORD+0x1c0,2))[0],vm.uc.mem_read(RECORD+2,1)[0],int(not any(methods)),
        vm.word(HEAD),vm.uc.mem_read(MIXER+0x84,1)[0],sum(vm.uc.mem_read(POOL+i*576+12,1)[0]==0 for i in range(5)),vm.uc.mem_read(RECORD+0x1a8,1)[0]]
def mask(a):
    flags=[a[0]==0xd4475b83,a[1]==8,a[2]==0x277c6b,a[3]==0,a[4]==0xffff,a[5]==0,a[6]==0,a[7]!=0,a[8]==0,a[9]==0,a[10]!=0,a[11]==8]
    return sum((1<<i)for i,v in enumerate(flags)if v)
class ProbeVM(S.StrictVM):
    def __init__(self,*args):
        self.probe_reads=[];self.audio_writes=[];self.new_native_calls=[]
        super().__init__(*args)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ,self.read_audio)
    def read_audio(self,uc,access,address,size,value,unused):
        if not self.zones or not AUDIO<=address<AUDIO+AUDIO_BYTES:return
        m=self.manifest
        if m['symbols']['cache_marker_entry']<=self.last_pc<B.IMAGE+m['combined_ram']:
            require(uc.reg_read(UC_ARM_REG_CPSR)&0x80,'Compiled audio observation outside IRQ-bounded sample')
            self.probe_reads.append(dict(address=address,size=size,PC=self.last_pc,opcode_hex=bytes(uc.mem_read(self.last_pc,self.last_size)).hex(),value_hex=bytes(uc.mem_read(address,size)).hex(),CPSR=uc.reg_read(UC_ARM_REG_CPSR)))
    def write(self,uc,access,address,size,value,unused):
        if self.zones and AUDIO<=address<AUDIO+AUDIO_BYTES:
            require(not self.manifest['symbols']['cache_marker_entry']<=self.last_pc<B.IMAGE+self.manifest['combined_ram'],'New diagnostic writes native audio')
            self.audio_writes.append(dict(PC=self.last_pc,address=address,size=size,value=value))
        super().write(uc,access,address,size,value,unused)
    def observe(self,uc,address,size,unused):
        if self.zones and address in (0x277e20,0x269f6c,0x277d26):
            raise ValueError('New loader/probe reinitialized native audio')
        return super().observe(uc,address,size,unused)
def run(stock,inventory,m,kind,runtime):
    global LAST
    vm=ProbeVM(stock,inventory,(ROOT/m['combined_file']).read_bytes(),m);LAST=vm
    e=vm.enumerate();record=e['registry'][0];p=vm.handles[record['handle']]['pointer']
    outer_kind={'wrong_current_path':'wrong_current_path'}.get(kind,'valid_unique_repeat')
    outer=vm.typed_outer_file(record['filename'],outer_kind)
    setup=[];fixtures=[]
    if kind not in ('cold_zero_audio',):
        before_calls=len(vm.calls)
        vm.call(0x277e20,())
        for channel in range(18):vm.call(0x269f6c,(channel,))
        vm.call(0x3ec540,(RECORD+0x70,))
        r=vm.call(0x277d26,(8,0,1));require(r==0,'Original profile0 did not finish')
        if kind=='original_profile1':require(vm.call(0x277d26,(8,1,1))==10,'Original profile1 genuine nonzero result differs')
        setup=vm.calls[before_calls:]
    if kind=='declared_busy_channel':
        for address,data in [(RECORD+2,b'\1'),(MIXER+0x84,b'\1'),(HEAD,struct.pack('<I',0xd0ffffff)),(RECORD+0x1c0,struct.pack('<H',1))]:
            vm.uc.mem_write(address,data);fixtures.append(dict(address=address,hex=data.hex(),kind='explicit negative busy metadata; no native state transition asserted'))
    if kind=='foreign_file_lock':
        vm.put(0xf09090,S.OTHER);vm.call(0x300934,(S.FILESEM,));vm.put(0xf09090,S.TCB)
        require(vm.word(S.FILESEM+8)==S.OTHER,'Original foreign owner was not obtained')
        fixtures.append(dict(kind='declared TCB head transition; original try primitive actually acquired foreign file lock',foreign_TCB=S.OTHER))
    if kind=='preexisting_unknown_W':
        vm.uc.mem_write(p+0x6b8,'W123\0'.encode('utf-16le'));fixtures.append(dict(kind='explicit preexisting cache input; never attributed to current code'))
    expected=reference_sample(vm);expected_mask=mask(expected)
    vm.allow_module_execution=True;vm.loader_input=True;vm.cpu_input_write(B.IMAGE,b'\xa5'*m['combined_ram']);vm.begin_journal(p)
    bss=m['symbols']['__marker_bss_start'];end=m['symbols']['__marker_bss_end']
    vm.zones.update(outer_file=(S.FILE,72),slot_record=(S.PARENT,36),private_state=(bss,end-bss),provider=(S.PROVIDER,64),driver=(S.DRIVER,4),map_entry=(S.MAP+198,2),native_audio_bank=(AUDIO,AUDIO_BYTES))
    vm.zone_before={k:bytes(vm.uc.mem_read(a,n))for k,(a,n)in vm.zones.items()}
    raw=vm.call(0x240498,(0,0));require(raw==11,'Optional diagnostic changed original raw return')
    state=m['symbols']['marker_state'];first=bytes(vm.uc.mem_read(state,104));reason=struct.unpack_from('<I',first,24)[0]
    skip={'wrong_current_path':16,'foreign_file_lock':14,'preexisting_unknown_W':18}.get(kind)
    if skip is None:
        require(reason==0 and len(vm.marker_stores)==5,'New diagnostic did not execute guarded five stores')
        actual_mask=struct.unpack_from('<I',first,52)[0];actual=list(struct.unpack_from('<12I',first,56))
        require(actual==expected and actual_mask==expected_mask,'Actual native sample/private fields differ from reference bytes')
        version=f'W{expected_mask:03X}\0';require(vm.probe_reads,'No actual native audio reads')
    else:
        require(reason==skip and not vm.marker_stores and not vm.probe_reads,'Guard failure sampled or wrote version')
        actual_mask=actual=None;version='W123\0'if kind=='preexisting_unknown_W'else'2.10\0'
    repeat=None
    if kind=='original_initialized_repeat':
        reads=len(vm.probe_reads);vm.call(0x240498,(0,0));repeat=bytes(vm.uc.mem_read(state,104))
        require(struct.unpack_from('<I',repeat,24)[0]==17 and struct.unpack_from('<I',repeat,16)[0]==2,'Repeated warm diagnostic not recognized')
        require(repeat[40:104]==first[40:104]and len(vm.probe_reads)==reads and len(vm.marker_stores)==5,'Repeat changed retained before bytes or sampled again')
    require(not vm.audio_writes,'Original voice changed diagnostic input audio bank in this scope')
    out=0x0801b000;vm.call(0x2744f6,(0,out));observed=bytes(vm.uc.mem_read(out,10))
    require(observed==version.encode('utf-16le'),'Original getter did not read dynamic diagnostic tag')
    frame=B.STACK-0x500;vm.uc.reg_write(UC_ARM_REG_SP,frame);vm.uc.reg_write(UC_ARM_REG_R0,0);vm.uc.reg_write(UC_ARM_REG_R1,frame+0x2bc)
    vm.fragment(0x6817d2,0x6817d6);require(bytes(vm.uc.mem_read(frame+0x2bc,10))==observed,'Original Aud Ver callsite input differs')
    zones=vm.finish_journal();require(zones['native_audio_bank']['before_hex']==zones['native_audio_bank']['after_hex'],'Whole native bank changed')
    require(all(x['raw_return']==11 for x in vm.entry_rows)and vm.word(B.SELECTED)==0,'Voice selection/entry result changed')
    module=bytes(vm.uc.mem_read(B.IMAGE,2296496));exports=vm.registration_rows[-1]['targets']
    baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text())
    require(B.digest(module[12:])==baseline['original_module_postheader_runtime_sha256'],'Original runtime module postheader altered')
    require(B.digest(bytes(vm.uc.mem_read(B.STUBS,480)))==baseline['original40_stubs_sha256'],'Original40 stubs altered')
    require(B.digest(bytes(vm.uc.mem_read(0xf09364,396)))==baseline['original99_imports_sha256'],'Original99 imports altered')
    row=dict(name=kind,all_passed=True,original_initializer_calls_as_explicit_input=setup,additional_negative_fixtures=fixtures,typed_outer_file_fixture=outer,
        native_original_metadata_record=record,reference_native_sample=expected,actual_sample=actual,actual_mask=actual_mask,reason=reason,
        observed_getter_UTF16_hex=observed.hex(),expected_tag=version.rstrip('\0'),first_private_state_hex=first.hex(),repeat_private_state_hex=repeat.hex()if repeat else None,
        original_voice_entry=vm.entry_rows,original_bootstrap=vm.bootstrap_rows,original40_targets=exports,original_native_try_calls=vm.try_calls,
        actual_new_audio_reads=vm.probe_reads,new_audio_writes=vm.audio_writes,CPU_version_stores=vm.marker_stores,CPU_write_journal=vm.journals,whole_zone_replay=zones,
        original_postheader_runtime_sha256=B.digest(module[12:]),native_audio_unchanged=True,instructions=vm.instructions,
        native_Warm_boot_ownership_or_phone_App_physical_UI_verified=False,device_IO=False)
    path=runtime/(kind+'.json');create(path,row);S.guard(kind+' terminal');LAST=None;del vm;gc.collect()
    return dict(name=kind,path=rel(path),sha256=sha(path),all_passed=True,tag=row['expected_tag'],reason=reason,CPU_version_stores=len(row['CPU_version_stores']),new_audio_reads=len(row['actual_new_audio_reads']),original40_preserved=True,native_audio_unchanged=True)
def main():
    require(unicorn.__version__=='2.1.4','Use isolated Unicorn2.1.4')
    runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
    m=json.loads((BASE/'strict_marker/manifest.json').read_text())
    require(sha(ROOT/m['combined_file'])==m['binary_sha256'],'Compiled program changed')
    source={p:h for p,h in m['source_sha256'].items()}
    for module in list(sys.modules.values()):
        p=getattr(module,'__file__',None)
        if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:source[rel(Path(p))]=sha(Path(p))
    source[rel(Path(__file__))]=sha(Path(__file__))
    rows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers'];voice=next(r for r in rows if 'Chinese_Big5_MeiLing'in r['file'])
    for p in [BASE/'strict_marker/manifest.json',BASE/'warm-audio-static-and-diagnostic-source-contract-v1.json',ROOT/m['combined_file'],ROOT/voice['file'],ROOT/'evidence/firmware-analysis/main_02bd.bin']:
        source[rel(p)]=sha(p)
    create(runtime/'inputs-at-run.json',source);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    stock=B.NativeImage();file=(ROOT/voice['file']).open('rb');package=mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ);inventory=[dict(name=Path(voice['file']).name,data=package)]
    cases=[]
    try:
        for kind in ['cold_zero_audio','original_initialized_idle','original_profile1','declared_busy_channel','wrong_current_path','foreign_file_lock','preexisting_unknown_W','original_initialized_repeat']:
            case=run(stock,inventory,m,kind,runtime);cases.append(case);print(json.dumps(case),flush=True)
        require(all(sha(ROOT/p)==h for p,h in source.items()),'Frozen source changed')
        create(BASE/'warm-probe-v1-control-proof.json',dict(all_passed=True,case_count=8,cases=cases,source_sha256=source,
            exact_original40_and99_and_postheader_preserved=True,native_audio_bank_unchanged_all_cases=True,actual_original_getter_Aud_Ver_callsite_verified=True,
            device_IO=False,physical_new_candidate_acceptance_or_display_verified=False,native_warm_channel_ownership_or_navigation_boot_or_music_App_verified=False,
            limits='Bounded diagnostic snapshot at module entry. Exact original cold audio initializer calls are explicit test inputs; busy metadata and outer file/TCB/heap are fixtures. Original audio memory is unchanged by the tested loader/probe interval. The displayed code is observations, not exclusive/readiness certification. Original Aud Ver callsite input, not actual UI rendering.',updated_utc=datetime.now(timezone.utc).isoformat()))
        print(json.dumps(dict(all_passed=True,case_count=8,proof=rel(BASE/'warm-probe-v1-control-proof.json'),device_IO=False)),flush=True)
    except BaseException as error:
        detail=dict(all_passed=False,error=repr(error),traceback=traceback.format_exc(),completed_cases=cases,device_IO=False)
        if LAST:detail['partial']=dict(last_PC=LAST.last_pc,original_calls=LAST.calls,probe_reads=LAST.probe_reads,CPU_write_journal=LAST.journals)
        create(runtime/'terminal-failure.json',detail);raise
if __name__=='__main__':main()
