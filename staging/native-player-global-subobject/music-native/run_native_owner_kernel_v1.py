#!/usr/bin/env python3
"""Bounded original kernel drives exact frozen owner image, no audio binding.

No ABI spies, fake native returns, MAIN patches or host CPU context restore.
ELF BSS/controller/idle/idle-source RAM remain explicit offline fixtures.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import ctypes,hashlib,importlib.util,json,struct,traceback
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
RETURN=0x10000;CODE=0x9400000;CONTROLLER_STACK=0x9500000;IDLE_STACK=0x9505000;STACK_BYTES=16384
POST=0x2fcf44;WAIT=0x2fd035;RESTORE=0x358ec4;CURRENT=0xf09090
FIELDS=('tcb','entered','wake_returns','pending','publications','completions','requests','pump_calls','cancel_requested','quit_requested','finished_on_stack','init_result','last_result')
TRACE=('initializer_returns','control_events','ordinary_events','owner_rejections','service_calls','publication_observations','iteration_returns','cancel_flag_cleared_observations','last_ready','last_service','last_publication','last_iteration')
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(d):
    for p,h in d.items():assert sha(ROOT/p)==h,p
def newjson(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
def require(c,message):
    if not c:raise AssertionError(message)

class OwnerKernel:
    def __init__(self,im,manifest,elf,publisher,priority):
        self.im=im;self.manifest=manifest;self.elf=elf;self.publisher=publisher;self.priority=priority
        self.uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.uc.reg_write(UC_ARM_REG_CPSR,0x1f)
        self.uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000)
        self.uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
        self.zones={};self.journal=[];self.code_pages={};self.kernel_events=[];self.actor_calls=[];self.cancel_returns=[];self.after_returns=[];self.instructions=0
        self.idle=self.controller=self.source=0;self.recent=[];self.calls=[];self.invalid_accesses=[];self.phase='declared_initial_RAM'
        self.disasm={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)};self.decoded={}
        self.map_rw(0xf00000,0x73000,'exact_initialized_bank_and_zero_tail_fixture')
        bank=next(r for r in im.copies if r['runtime_start']==0xf00000)
        require(bank['size']==0x7224c,'Exact bank copy differs')
        self.uc.mem_write(0xf00000,im.read(bank['load_start'],bank['size']))
        self.map_rw(0x14b3000,4096,'original_zero_descriptor_registry_fixture')
        self.map_rw(CODE,4096,'declared_controller_idle_code_and_descriptors')
        self.uc.mem_write(CODE,struct.pack('<2I',0xeafffffe,0xe12fff1e))
        self.map_rw(RETURN,4096,'declared_stop_endpoint')
        self.map_rw(CONTROLLER_STACK,STACK_BYTES,'declared_controller_stack',0xa5)
        self.map_rw(IDLE_STACK,STACK_BYTES,'declared_idle_stack',0xa5)
        self.map_rw(0x34e3000,0x8000,'original_zero_idle_audio_record_fixture')
        for p,n in [(0x14b3000,4096),(0x34e3000,0x8000)]:
            require(any(r['runtime_start']<=p and p+n<=r['runtime_end']for r in im.zeros),'RAM fixture outside exact stock zeros')
        self.map_rw(0x2f9d000,0x19000,'exact_linked_image_RW_data_BSS_payload_stacks_fixture')
        for p in [elf,publisher]:
            for s in p.sections:
                if not s['flags']&2 or not s['size']:continue
                if s['flags']&1:
                    require(0x2f9d000<=s['address'] and s['address']+s['size']<=0x2fb6000,'Unexpected writable image section')
                    if s['type']!=8:self.uc.mem_write(s['address'],p.data(s))
                else:
                    lo=s['address']&~4095;hi=(s['address']+s['size']+4095)&~4095
                    if not self.mapped(lo,hi-lo):self.uc.mem_map(lo,hi-lo)
                    self.uc.mem_write(s['address'],p.data(s));self.uc.mem_protect(lo,hi-lo,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        for name in ['__source_stack_start','__worker_stack_start']:
            self.uc.mem_write(self.address(name),b'\xa5'*16384)
        self.uc.mem_write(0xf071cc,b'\x01'+bytes(7))
        self.uc.mem_write(0xf0908c,bytes(0x20))
        self.uc.mem_write(0x34e9398+8,b'\x01')
        # Journal includes every mutation after declared setup, both actual
        # CPU writes and explicitly labelled held-producer host fixture events.
        for row in self.zones.values():row['before_hex']=bytes(self.uc.mem_read(row['start'],row['bytes'])).hex()
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.store)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID,self.invalid)
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.observe)
        self.actor_points={self.address(n):n for n in ['source_worker_entry','music_owner_initialized','music_owner_control_boundary','music_owner_after_boundary','media_coordinator_pump','media_coordinator_cancel','__wrap_media_coordinator_init','native_ui_music_service_owner','native_ui_music_after_iteration']}
        self.cancel_pending={};self.after_pending={}
        self.phase='original_controller_idle_context_build'
        self.idle=self.build(CODE+0x800,CODE,IDLE_STACK+STACK_BYTES,240)
        self.controller=self.build(CODE+0x820,CODE+4,CONTROLLER_STACK+STACK_BYTES,16)
        self.fixture_write(CURRENT,struct.pack('<I',self.controller),'initial_controller_idle_ready_membership')
        self.fixture_write(self.controller,struct.pack('<I',self.idle),'initial_controller_next_idle')
        self.fixture_write(self.idle,bytes(4),'initial_idle_next_null')
        self.fixture_write(self.controller+22,b'\x01','initial_controller_ready_state')
        self.fixture_write(self.idle+22,b'\x01','initial_idle_ready_state')
        self.phase='actual_owned_private_configuration'
        require(self.call(self.address('owned_media_init'),(8,))==0,'Actual compiled owned init failed')
        self.phase='actual_original_source_boot'
        self.source=self.call(self.address('source_worker_boot'),(priority,))
        require(self.source==(self.address('__source_stack_end')-108)&~7,'Original source TCB placement differs')
        if self.current()==self.controller:self.park()
        require(self.current()==self.idle and self.byte(self.source+22)==2 and self.source_state()['entered']==1,'Actual compiled source did not initialize/block')
        self.activate()
        require(self.source_state()['init_result']==0 and self.word(self.address('coordinator_state')+4)==self.source,'Actual compiled coordinator owner init differs')
        require(self.word(self.address('music_runtime_state')+20)==1 and self.word(self.address('music_runtime_state')+28)==self.source,'Actual original initializer return was not wrapped/published')

    def address(self,name):return self.elf.symbol(name)['value']
    def mapped(self,a,n):return any(lo<=a and a+n-1<=hi for lo,hi,_ in self.uc.mem_regions())
    def map_rw(self,a,n,kind,fill=0):
        require(not self.mapped(a,n),'Overlapping declared RAM')
        self.uc.mem_map(a,n,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        if fill:self.uc.mem_write(a,bytes([fill])*n)
        self.zones[a]=dict(start=a,bytes=n,kind=kind,before_hex=None)
    def word(self,a):return struct.unpack('<I',self.uc.mem_read(a,4))[0]
    def byte(self,a):return self.uc.mem_read(a,1)[0]
    def current(self):return self.word(CURRENT)
    def source_state(self):return dict(zip(FIELDS,struct.unpack('<11I2i',self.uc.mem_read(self.address('source_worker_state'),52))))
    def trace(self):return dict(zip(TRACE,struct.unpack('<8I4i',self.uc.mem_read(self.address('music_owner_trace'),48))))
    def fixture_write(self,a,data,reason):
        before=bytes(self.uc.mem_read(a,len(data)))
        self.journal.append(dict(kind='explicit_host_RAM_fixture',address=a,size=len(data),before_hex=before.hex(),after_hex=data.hex(),reason=reason,phase=self.phase))
        self.uc.mem_write(a,data)
    def invalid(self,uc,access,a,n,value,data):
        page=a&~4095
        if access in [unicorn.UC_MEM_FETCH_UNMAPPED,unicorn.UC_MEM_READ_UNMAPPED] and 0x50000<=page and page+4096<=0x50000+len(self.im.data) and page<0xf00000:
            require(not self.mapped(page,4096),'Invalid access to existing code page')
            raw=self.im.read(page,4096);uc.mem_map(page,4096);uc.mem_write(page,raw);uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
            self.code_pages[page]=hashlib.sha256(raw).hexdigest();return True
        self.invalid_accesses.append(dict(access=access,address=hex(a),size=n,PC=hex(uc.reg_read(UC_ARM_REG_PC))));return False
    def store(self,uc,access,a,n,value,data):
        if access!=unicorn.UC_MEM_WRITE:return
        rows=[r for r in self.zones.values()if r['start']<=a and a+n<=r['start']+r['bytes']]
        require(len(rows)==1 and n in [1,2,4,8],'CPU write outside complete declared RW zone')
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32);key=pc,thumb
        if key not in self.decoded:
            raw=bytes(uc.mem_read(pc,4));i=next(self.disasm[thumb].disasm(raw,pc,count=1))
            require(i.mnemonic.startswith(('str','stm','push','vstr','vstm','swp')),'Write not associated with decoded CPU store')
            self.decoded[key]=dict(opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
        self.journal.append(dict(kind='CPU',address=a,size=n,before_hex=bytes(uc.mem_read(a,n)).hex(),after_hex=(value&((1<<(8*n))-1)).to_bytes(n,'little').hex(),PC=hex(pc),Thumb=thumb,current=hex(self.current()),phase=self.phase,**self.decoded[key]))
    def build(self,desc,entry,stack,priority):
        self.fixture_write(desc,struct.pack('<5I',entry,0,stack,priority<<16,0),'declared_raw_descriptor')
        t=self.call(0x358bf9,(desc,),stack=CONTROLLER_STACK+STACK_BYTES-256)
        require(t==((stack-108)&~7),'Actual original kernel builder TCB differs');return t
    def call(self,a,args=(),stack=None):
        require(a!=self.address('source_worker_entry'),'Never explicitly invoke source entry')
        if stack is None:stack=self.current() or CONTROLLER_STACK+STACK_BYTES-256
        self.uc.reg_write(UC_ARM_REG_SP,stack);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        for r,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):self.uc.reg_write(r,v)
        before=self.instructions;self.uc.emu_start(a,RETURN,count=1000000,timeout=10000000)
        pc=self.uc.reg_read(UC_ARM_REG_PC);require(pc in [RETURN,CODE],'Actual bounded call missed original return/idle endpoint '+hex(pc))
        result=ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value
        self.calls.append(dict(entry=hex(a),arguments=args,current_after=hex(self.current()),endpoint=hex(pc),result=result,instructions=self.instructions-before));return result
    def observe(self,uc,a,n,data):
        self.instructions+=1;self.recent=(self.recent+[hex(a)])[-32:]
        if a==CODE:
            require(self.current()==self.idle,'Synthetic idle reached by wrong task');uc.emu_stop();return
        if a in [POST,WAIT&~1,RESTORE,0xf5030,0xf6f26,0x2fbbbe,0x358f08,0x358d24,0x21b6cc,0x21b6dc]:
            self.kernel_events.append(dict(PC=hex(a),current=hex(self.current()),SP=hex(uc.reg_read(UC_ARM_REG_SP)),LR=hex(uc.reg_read(UC_ARM_REG_LR)),r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),opcode_hex=bytes(uc.mem_read(a,n)).hex(),Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
        if a in self.actor_points:
            name=self.actor_points[a];s=self.source_state()
            require(self.current()==s['tcb'] and self.address('__source_stack_start')<=uc.reg_read(UC_ARM_REG_SP)<self.address('__source_stack_end'),'Compiled lifecycle call outside actual source TCB/stack '+name)
            row=dict(name=name,PC=hex(a),source=s,trace=self.trace(),current=hex(self.current()),SP=hex(uc.reg_read(UC_ARM_REG_SP)),LR=hex(uc.reg_read(UC_ARM_REG_LR)),argument=uc.reg_read(UC_ARM_REG_R0))
            self.actor_calls.append(row)
            if name=='media_coordinator_cancel':self.cancel_pending[uc.reg_read(UC_ARM_REG_LR)&~1]=row
            if name=='music_owner_after_boundary':
                require(s['last_result']==ctypes.c_int32(uc.reg_read(UC_ARM_REG_R0)).value,'after-boundary before actual last_result store')
                if not s['last_result']:require(not s['cancel_requested'],'after-boundary before returned-cancel flag clear')
                self.after_pending[uc.reg_read(UC_ARM_REG_LR)&~1]=row
        if a in self.cancel_pending:
            row=self.cancel_pending.pop(a);row=dict(row,actual_return_PC=hex(a),actual_return_r0=ctypes.c_int32(uc.reg_read(UC_ARM_REG_R0)).value,source_at_return=self.source_state())
            require(self.current()==self.source_state()['tcb'],'Cancel returned on wrong task')
            self.cancel_returns.append(row)
        if a in self.after_pending:
            row=self.after_pending.pop(a);self.after_returns.append(dict(row,actual_return_r0=ctypes.c_int32(uc.reg_read(UC_ARM_REG_R0)).value))
    def park(self):
        require(self.current()==self.controller,'Cannot wait on another caller');self.call(WAIT)
        require(self.current()==self.idle,'Original controller wait did not drain source to idle')
    def activate(self):
        if self.current()==self.controller:return
        require(self.current()==self.idle,'Controller activation lacks idle')
        require(self.call(POST,(self.controller,1))==1 and self.current()==self.controller,'Original controller wait not restored')
    def publish(self,bits):
        require(self.current()==self.controller,'Publisher not current controller')
        return self.call(self.publisher.symbol('music_native_publish')['value'],(bits,))
    def cycle(self):
        self.park();self.activate()
    def verify(self):
        require(not self.invalid_accesses,'Unexpected invalid accesses')
        require(not self.cancel_pending and not self.after_pending,'Unreturned original calls')
        require(self.source_state()['entered']==1 and not self.source_state()['finished_on_stack'],'Persistent source entry reentered/exited')
        require(bytes(self.uc.mem_read(self.address('__source_stack_start'),64))==b'\xa5'*64,'Source stack canary changed')
        require(bytes(self.uc.mem_read(self.address('native_ui_music_resident'),356))==bytes(356),'Unattached controller was fabricated')
        require(not self.trace()['service_calls'] and not self.trace()['publication_observations'],'Missing adapter supplied success')
        require({POST,WAIT&~1,RESTORE,0xf5030,0xf6f26,0x2fbbbe,0x358f08}.issubset({int(r['PC'],16)for r in self.kernel_events}),'Actual original kernel scope skipped')
        for page,digest in self.code_pages.items():require(hashlib.sha256(self.uc.mem_read(page,4096)).hexdigest()==digest,'MAIN page mutated')
        for elf in [self.elf,self.publisher]:
            for s in elf.sections:
                if s['flags']&2 and not s['flags']&1 and s['size']:require(bytes(self.uc.mem_read(s['address'],s['size']))==elf.data(s),'Compiled code mutated')
        finals=[]
        for row in self.zones.values():
            expected=bytearray.fromhex(row['before_hex']);low=row['start']
            events=[e for e in self.journal if low<=e['address'] and e['address']+e['size']<=low+row['bytes']]
            for e in events:
                offset=e['address']-low;require(expected[offset:offset+e['size']].hex()==e['before_hex'],'Whole zone before-value chronology missed mutation')
                expected[offset:offset+e['size']]=bytes.fromhex(e['after_hex'])
            actual=bytes(self.uc.mem_read(low,row['bytes']));require(actual==expected,'Whole declared RW bytes differ from journal')
            finals.append(dict(row,after_sha256=hashlib.sha256(actual).hexdigest(),CPU_events=sum(e['kind']=='CPU'for e in events),fixture_events=sum(e['kind']!='CPU'for e in events),whole_replay=True))
        return dict(priority=self.priority,source=self.source_state(),trace=self.trace(),kernel_events=self.kernel_events,actor_calls=self.actor_calls,cancel_returns=self.cancel_returns,after_returns=self.after_returns,calls=self.calls,journal=self.journal,whole_RW_zones=finals,immutable_MAIN_pages={hex(k):v for k,v in self.code_pages.items()},instructions=self.instructions,guest_mapped_bytes=sum(hi-lo+1 for lo,hi,_ in self.uc.mem_regions()))

def main():
    require(unicorn.__version__=='2.1.4','Requires isolated Unicorn2.1.4')
    directory=OUT/'kernel-v1';directory.mkdir(exist_ok=False)
    source=Path(__file__).resolve();(directory/'runner-at-run.py').write_bytes(source.read_bytes())
    pre=json.loads((OUT/'preflight.json').read_text());check(pre['source_sha256']);check(pre['artifacts_sha256'])
    deps=dict(pre['source_sha256']);deps[rel(source)]=sha(source);deps[rel(OUT/'preflight.json')]=sha(OUT/'preflight.json')
    newjson(directory/'inputs-before-run.json',dict(source_sha256=deps,artifacts_sha256=pre['artifacts_sha256'],device_io=False,MAIN_patch_bytes=0))
    spec=importlib.util.spec_from_file_location('frozen_ELF_reader',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    im=NativeImage();m=json.loads((ROOT/pre['frozen_image_manifest']).read_text());e=mod.ELF32(ROOT/pre['frozen_image_elf']);p=mod.ELF32(ROOT/pre['new_ARM_ET_EXEC'])
    cases=[];runs=[];vm=None;error=None
    try:
        vm=OwnerKernel(im,m,e,p,36)
        cases.append(dict(name='actual_original_kernel_build_registry_and_persistent_source_owner_boot',passed=True,source=vm.source_state(),owner_init=vm.trace()))
        before=vm.source_state();require(vm.publish(0x80000)==0,'Private publisher rejected')
        require(vm.source_state()['pending']==0x80000,'Durable command missing before lowerpriority source scheduled')
        vm.cycle();require(vm.trace()['control_events']==1 and not vm.trace()['service_calls'] and vm.trace()['last_ready']==-100,'Missing adapter did not fail closed')
        cases.append(dict(name='private_control_event_actual_source_owner_missing_adapter_rejected',passed=True))
        require(vm.publish(0x10000|0x20000|0x80000)==0,'Mixed event publish failed');vm.cycle()
        require(vm.trace()['ordinary_events']==1 and vm.source_state()['pump_calls']==1 and vm.source_state()['last_result']==1,'Mixed original events not consumed via compiled empty pump')
        require(vm.after_returns[-1]['actual_return_r0']==-100,'Unattached after iteration not rejected')
        cases.append(dict(name='mixed_durable_original_and_controller_events_preserved_with_actual_empty_pump',passed=True))
        vm.phase='explicit_held_producer_private_RAM_control';vm.fixture_write(vm.address('owned_media_control')+4,struct.pack('<I',1),'declared producer busy fixture; not a live producer/IRQ witness')
        require(vm.call(vm.address('source_worker_cancel'))==0,'Actual cancel request rejected');vm.cycle()
        require(vm.source_state()['cancel_requested']==1 and vm.cancel_returns[-1]['actual_return_r0']==1 and vm.after_returns[-1]['source']['cancel_requested']==1,'Pending actualcancel return incorrectly completed')
        cases.append(dict(name='compiled_pending_cancel_actual_return1_keeps_flag_until_later_iteration',passed=True))
        vm.phase='explicit_producer_fixture_release_then_actual_cancel_return';vm.fixture_write(vm.address('owned_media_control')+4,bytes(4),'release declared busy fixture only; no native producer quiescence claim')
        require(vm.publish(0x20000)==0,'Completion-event publisher failed');vm.cycle()
        require(vm.cancel_returns[-1]['actual_return_r0']==0 and vm.cancel_returns[-1]['source_at_return']['cancel_requested']==1 and vm.after_returns[-1]['source']['cancel_requested']==0 and vm.after_returns[-1]['actual_return_r0']==-100,'Actual cancel returned/flag clear/ownerafter order differs')
        require(vm.word(vm.address('music_runtime_state')+24)==0,'Actual wrapper init result differs')
        cases.append(dict(name='actual_compiled_cancel_return0_precedes_flag_clear_and_after_iteration_still_missing',passed=True,STOP_DONE_proven=False))
        vm.phase='repeated_empty_cancel_control';require(vm.call(vm.address('source_worker_cancel'))==0,'Repeat cancel request failed');vm.cycle()
        require(vm.source_state()['cancel_requested']==0 and vm.source_state()['entered']==1,'Repeat cancel reset persistent actor')
        require(vm.call(vm.address('native_ui_music_request_start'),(0,))<0,'Unattached GUI start accepted')
        require(vm.publish(8)==-20,'Unsupported publisher event accepted')
        cases.append(dict(name='repeated_cancel_and_unattached_GUI_start_fail_closed_without_entry_reset',passed=True))
        runs.append(vm.verify())
        print(json.dumps(dict(priority36_completed=True,instructions=vm.instructions)),flush=True)
        vm=OwnerKernel(im,m,e,p,3);before=vm.trace()['control_events']
        require(vm.publish(0x80000)==0 and vm.current()==vm.controller and vm.trace()['control_events']==before+1 and vm.source_state()['pending']==0,'Actual original post did not preempt and return publisher')
        require(vm.publish(0x10000|0x20000)==0 and vm.source_state()['pump_calls']==1 and vm.current()==vm.controller,'High-priority ordinary event roundtrip differs')
        require(vm.call(vm.address('source_worker_cancel'))==0 and vm.source_state()['cancel_requested']==0 and vm.current()==vm.controller,'High-priority cancel original caller not restored')
        cases.append(dict(name='higher_priority_original_post_preempts_source_then_restores_actual_compiled_publisher_cancel_caller',passed=True))
        runs.append(vm.verify())
    except BaseException as exc:
        error=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())
    check(deps);check(pre['artifacts_sha256'])
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),completed=error is None,error=error,source_sha256=deps,artifacts_sha256=pre['artifacts_sha256'],cases=cases,case_count=len(cases),runs=runs,
      exact_target=pre['exact_target'],execution=dict(actual_Unicorn_version=unicorn.__version__,original_MAIN_patch_bytes=0,host_CPU_context_restore=False,host_ABI_spies=False,host_native_return_replacement=False,no_audio_device_or_service_IO=True),
      limitations=dict(image_section_loading_and_BSS_zeroing_are_declared_fixtures=True,not_new_original_TTS_loader_bootstrap_proof=True,
        initial_raw_descriptors_ready_list_and_channel8_idle_source_records_are_declared_RAM=True,
        busy_producer_pause_release_are_explicit_host_fixture_events=True,not_actual_producer_or_IRQ_quiescence=True,
        adapter_never_attached_exclusive_witness_session_missing=True,native_register_head_remove_release_and_audio_not_entered=True,
        native_GUI_generation_and_STOP_DONE_unproven=True,source9_binding_missing=True,source8_runtime_decoder_radio_HFP_boot_not_integrated=True,
        module_stacks_resident_no_unload=True,physical_App_direct_A2DP_or_VPM_acceptance=False))
    if error and vm is not None:
        result['terminal_state']=dict(source=vm.source_state(),trace=vm.trace(),PC=hex(vm.uc.reg_read(UC_ARM_REG_PC)),recent=vm.recent,invalid_accesses=vm.invalid_accesses,calls=vm.calls,actor_calls=vm.actor_calls,kernel_events=vm.kernel_events,journal=vm.journal,zones=vm.zones)
    newjson(directory/'terminal-probe.json',result)
    print(json.dumps(dict(completed=result['completed'],case_count=len(cases),error=error and error['message'],proof=rel(directory/'terminal-probe.json'),sha256=sha(directory/'terminal-probe.json'))),flush=True)
    if error:sys.exit(1)
if __name__=='__main__':main()
