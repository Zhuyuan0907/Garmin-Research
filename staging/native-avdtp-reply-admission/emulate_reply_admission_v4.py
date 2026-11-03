#!/usr/bin/env python3
"""New wire-driven native TX failure / false Start controls, offline only."""
import sys
sys.dont_write_bytecode=True
import json,struct,gc,hashlib,traceback
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_CPSR,UC_ARM_REG_SP
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from emulate_native_l2cap_send import SendVM,ENTITY,TX,LCID
from emulate_native_music_dispatch import TABLE
from emulate_avdtp_control import CONFIG,CONTEXT,STATE,REGS,STACK,INPUT
from emulate_native_music_endpoint import HEAP

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def guard():
    values={line.split(':')[0]:int(line.split(':')[1].split()[0])for line in Path('/proc/self/status').read_text().splitlines()if line.startswith(('VmRSS:','VmHWM:'))}
    assert max(values.values())<200*1024,values

class AdmissionVM(SendVM):
    def __init__(self,stock,build,strict):
        self.capture_requested=False;self.capturing=False;self.journals=[];self.wire_scopes=[]
        self.last_PC=0;self.last_size=0;self.strict=strict;self.scope_entries=[]
        super().__init__(stock,build)
        if strict:
            patches=[]
            for signal,name in [(3,'nr_configuration_gate'),(5,'nr_configuration_gate'),
                                (7,'nr_start_suspend_gate'),(9,'nr_start_suspend_gate')]:
                patches.append((TABLE+(signal-1)*4,struct.pack('<I',self.symbols[name]),'new compiled gate signal'+str(signal)))
            p=build['patch'];patches.append((p['address'],bytes.fromhex(p['after_hex']),'owned acceptance reply with native written-byte witness'))
            image=bytearray(self.code)
            for address,after,purpose in patches:
                before=bytes(self.uc.mem_read(address,len(after)))
                self.uc.mem_write(address,after);image[address-0x50000:address-0x50000+len(after)]=after
                self.patch_plan.append(dict(address=hex(address),original=before.hex(),replacement=after.hex(),purpose=purpose))
            self.code=bytes(image)
        self.zones={'AVDTP':(0x03a88000,0x2000),'native_TX':(0x03a96000,0x2000),
                    'native_TX_globals':(0x00f69000,4096),'module_BSS':(self.bss,4096),
                    'stack':(STACK,0x10000),'native_reassembly_heap':(HEAP,4096)}
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.store)

    def zone(self,address,size):
        matches=[name for name,(a,n)in self.zones.items()if a<=address and address+size<=a+n]
        assert len(matches)==1,(hex(address),size,matches)
        return matches[0]

    def store(self,uc,access,address,size,value,unused):
        if not self.capturing:return
        name=self.zone(address,size);assert size in (1,2,4,8)
        self.journals.append(dict(kind='CPU_store',zone=name,address=address,size=size,value=value,
                                 before_hex=bytes(uc.mem_read(address,size)).hex(),PC=self.last_PC,
                                 opcode_hex=bytes(uc.mem_read(self.last_PC,self.last_size)).hex(),
                                 CPSR=uc.reg_read(UC_ARM_REG_CPSR)))

    def host_write(self,address,data,reason,source=None):
        name=self.zone(address,len(data))
        self.journals.append(dict(kind='explicit_service_write',zone=name,address=address,size=len(data),
                                 before_hex=bytes(self.uc.mem_read(address,len(data))).hex(),after_hex=bytes(data).hex(),
                                 reason=reason,source=source,PC=self.last_PC,
                                 opcode_hex=bytes(self.uc.mem_read(self.last_PC,self.last_size)).hex()))

    def hook(self,uc,address,size,unused):
        self.last_PC=address;self.last_size=size
        if self.capture_requested:
            self.capture_requested=False;self.capturing=True;self.journals=[];self.scope_entries=[]
            self.zone_before={name:bytes(uc.mem_read(a,n))for name,(a,n)in self.zones.items()}
        if self.capturing:
            args=[uc.reg_read(r)for r in REGS]
            if address==0x5524da:
                self.host_write(HEAP,b'\xa5'*4096,'inherited bounded signaling allocator resets synthetic heap')
            if address==0x5524f6:
                dest,source,n=args[:3]
                self.host_write(dest,bytes(uc.mem_read(source,n)),'inherited explicit memcpy service, not native memcpy CPU execution',source)
            if address in [self.symbols['nr_configuration_gate'],self.symbols['nr_start_suspend_gate'],self.symbols['nr_reply_dispatch']]:
                assert self.mutex_held,'New native command/reply scope must run under original AVDTP lock contract'
                self.scope_entries.append(dict(PC=address,args=args+[self.word(uc.reg_read(UC_ARM_REG_SP))],
                                               AV_mutex_held=True,nr_scope_words=self.scope()))
        return super().hook(uc,address,size,unused)

    def scope(self):return list(struct.unpack('<13I',self.uc.mem_read(self.symbols['nr_scope'],52)))

    def wire(self,payload):
        self.capture_requested=True
        result=super().wire(payload)
        assert self.capturing and not self.capture_requested
        zones={name:dict(address=a,bytes=n,before_hex=self.zone_before[name].hex(),after_hex=bytes(self.uc.mem_read(a,n)).hex())
               for name,(a,n)in self.zones.items()}
        replay={name:bytearray(self.zone_before[name])for name in zones}
        for row in self.journals:
            k=row['zone'];off=row['address']-zones[k]['address'];n=row['size']
            assert replay[k][off:off+n].hex()==row['before_hex']
            data=row['value'].to_bytes(n,'little')if row['kind']=='CPU_store'else bytes.fromhex(row['after_hex'])
            replay[k][off:off+n]=data
        assert all(replay[k].hex()==z['after_hex']for k,z in zones.items())
        self.wire_scopes.append(dict(wire_hex=payload.hex(),result=result,nr_scope=self.scope(),
                                     actual_native_scope_entries=self.scope_entries,journal=self.journals,whole_zones=zones))
        self.capturing=False
        return result

def ready(vm):
    cfg=vm.wire(b'\x10\x03'+CONFIG);assert cfg['state']==2
    op=vm.wire(bytes.fromhex('100604'));assert op['pending']==2
    vm.incoming();vm.config_request();done=vm.config_confirm()
    assert done['state']==4 and not done['pending']
    return done

LAST=None
def main():
    global LAST
    assert unicorn.__version__=='2.1.4','Use isolated Unicorn2.1.4'
    runtime=BASE/'guest-v4';runtime.mkdir(exist_ok=False)
    build=json.loads((BASE/'build-v2.json').read_text());stock=NativeImage()
    assert build['all_passed'] and sha(ROOT/build['flat'])==build['flat_sha256']
    sources=dict(build['source_sha256'])
    for module in list(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name and Path(name).is_file()and Path(name).is_relative_to(ROOT)and 'site-packages'not in Path(name).parts:
            sources[rel(Path(name))]=sha(Path(name))
    for p in (Path(__file__),BASE/'build-v1.json',BASE/'build-v2.json',ROOT/build['flat'],BASE/'pre-guest-v2-scope-adjustment.json'):
        sources[rel(p)]=sha(p)
    create(runtime/'inputs-at-run.json',sources);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    cases=[]
    try:
        names=['Configure_lock_failure','Configure_entity_not_ready','Start_lock_failure','Start_entity_not_ready',
               'Start_pending_Open_rejected','Suspend_lock_failure','valid_Start_Suspend_resume_media','oversized_Start_fenced']
        for name in names:
            variants=[]
            for strict in ([True]if name in names[-2:]else[False,True]):
                vm=AdmissionVM(stock,build,strict);LAST=vm
                if name.startswith(('Start_','Suspend_')):
                    if name=='Start_pending_Open_rejected':
                        vm.wire(b'\x10\x03'+CONFIG);vm.wire(bytes.fromhex('100604'));vm.incoming()
                    else:ready(vm)
                if name.startswith('Suspend_'):
                    assert vm.wire(bytes.fromhex('100704'))['state']==8
                if name.endswith('lock_failure'):vm.l2_lock_error=-1
                if name.endswith('entity_not_ready'):
                    vm.uc.mem_write(ENTITY+0x1e,b'\x04');vm.entities_expected=bytes(vm.uc.mem_read(ENTITY,880))
                if name.startswith('Configure_'):result=vm.wire(b'\x10\x03'+CONFIG)
                elif name.startswith('Start_'):result=vm.wire(bytes.fromhex('100704'))
                elif name.startswith('Suspend_'):result=vm.wire(bytes.fromhex('100904'))
                elif name=='valid_Start_Suspend_resume_media':
                    caps=vm.wire(bytes.fromhex('100204'));assert caps['TX_queue'][0]['wire_hex']=='12020100070600003fff0235'
                    ready(vm);start=vm.wire(bytes.fromhex('100704'));assert start['state']==8
                    suspend=vm.wire(bytes.fromhex('100904'));assert suspend['state']==4
                    result=vm.wire(bytes.fromhex('200704'));assert result['state']==8
                    media=vm.media(b'exact-native-callback-ABI-not-decoded-here')
                    assert media['callbacks'][0]['event']==0xf1 and media['callbacks'][0]['status']==0
                    assert vm.scope()[5:8]==[4,4,0] and not vm.scope()[0]
                else:
                    result=vm.wire(bytes.fromhex('1007')+bytes([4])*269)
                    assert result['state']==1 and not result['callbacks'] and result['TX_queue'][-1]['wire_hex']=='13070011'
                if name in names[:4]+[names[5]]:
                    expected=(2 if name.startswith('Configure')else 4 if name.startswith('Start')else 8)if strict else(2 if name.startswith('Configure')else 8 if name.startswith('Start')else 4)
                    assert result['state']==expected,(name,strict,result['state'])
                    if strict:assert not result['callbacks']
                    elif not name.startswith('Configure_'):assert result['callbacks']
                    assert result['native_sends'][-1]['native_written_payload_bytes']==0
                    if strict:assert vm.scope()[7]==1 and vm.scope()[11]==0 and not vm.scope()[0]
                if name=='Start_pending_Open_rejected':
                    assert result['state']==(2 if strict else 8)and result['pending']==2
                    assert result['TX_queue'][-1]['wire_hex']=='13070431'
                    assert bool(result['callbacks'])==(not strict)
                    if strict:assert vm.scope()[9]==1 and not vm.scope()[0]
                vm.guards();guard()
                variants.append(dict(strict=strict,result=result,scopes=vm.wire_scopes,nr_scope=vm.scope(),
                                     original_lifecycle_inputs=vm.history,patches=vm.patch_plan,code_expected_sha256=hashlib.sha256(vm.code).hexdigest()))
                LAST=None;del vm;gc.collect()
            row=dict(name=name,all_passed=True,variants=variants)
            path=runtime/(name+'.json');create(path,row)
            cases.append(dict(name=name,path=rel(path),sha256=sha(path),variant_count=len(variants)))
            print(json.dumps(dict(name=name,all_passed=True,variant_count=len(variants))),flush=True)
        assert all(sha(ROOT/p)==h for p,h in sources.items()),'Inputs changed'
        create(BASE/'native-reply-admission-v4-proof.json',dict(all_passed=True,case_count=8,cases=cases,source_sha256=sources,
               original_known_acceptance_send_zero_can_have_written_zero=True,new_native_written_byte_witness=True,
               original_pending_Open_rejected_Start_false_state_transition_blocked=True,
               original_L2CAP_send_allocator_TX_queue_execute=True,real_radio_delivery=False,
               accepted_Configure_Start_generation_or_copied_PCM_or_App=False,
               limits='New compiled command scopes are entered by actual original signaling dispatcher, not host per-message arm. Scope generation is command-local, not remote stream generation. Selected owned accept formatter makes exact two-byte standard reply and checks original native send written2; other paths retain original relocated reply. Native L2CAP alloc/link/send execute, but original memcpy, kernel mutex, heap allocation, PSM/channel/credit/transport/event services and dummy endpoint callback remain explicit fixtures. Journal includes typed host service writes separately. Original lifecycle input calls between recorded wire scopes execute but their stores are outside this new journal. Construction-time synthetic link/dispatch/prologue patches remain VM-only; no cache/MMU/pin/unload/App/phone/hardware proof.',
               new_independent_agent_review=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat()))
        print(json.dumps(dict(all_passed=True,case_count=8,proof=rel(BASE/'native-reply-admission-v4-proof.json'),device_IO=False)),flush=True)
    except BaseException as error:
        failure=dict(all_passed=False,error=repr(error),traceback=traceback.format_exc(),completed_cases=cases,device_IO=False)
        if LAST:failure['partial']=dict(last_PC=LAST.last_PC,scope=LAST.scope(),journal=LAST.journals,wire_scopes=LAST.wire_scopes)
        create(runtime/'terminal-failure.json',failure);raise
if __name__=='__main__':main()
