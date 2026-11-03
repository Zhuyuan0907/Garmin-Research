#!/usr/bin/env python3
"""Execute the compiled ARMv6 core against independent protocol byte vectors.

Controller completion/events are Python fixtures. No Garmin firmware or USB
driver executes here. Guard pages bound context/options/request/string storage.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR)

ROOT=Path(__file__).resolve().parents[1]
MANIFEST='staging/native-aoa-host/manifest.json'
RETURN=0x10000
CONTEXT_PAGE=0x08001000
OPTIONS_PAGE=0x08003000
REQUEST_PAGE=0x08005000
STACK_PAGE=0x080ff000
STRINGS_PAGE=0x08110000
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
DEFAULT=[b'Android\0',b'Android Auto\0',b'Android Auto\0',b'2.0.1\0',
         b'https://f1xstudio.com\0',b'HU-PROTOTYPE001\0']

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def signed(v):return v if v<0x80000000 else v-0x100000000

class VM:
    def __init__(self,strings=None,now=100,initial=(0x1234,0x5678),
                 session=41,generation=7,timeouts=(1000,3000)):
        self.m=json.loads((ROOT/MANIFEST).read_text())
        for name,want in self.m['source_sha256'].items():assert sha(name)==want,name
        assert sha(self.m['flat'])==self.m['flat_sha256']
        assert sha(self.m['elf'])==self.m['elf_sha256']
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.code=(ROOT/self.m['flat']).read_bytes()
        self.uc.mem_map(self.m['base'],(len(self.code)+4095)&~4095)
        self.uc.mem_write(self.m['base'],self.code)
        self.uc.mem_protect(self.m['base'],(len(self.code)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
        self.uc.mem_map(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
        for page in (CONTEXT_PAGE,OPTIONS_PAGE,REQUEST_PAGE,STACK_PAGE):self.uc.mem_map(page,4096)
        self.returned=False
        def stop(cpu,address,size,data):
            if address==RETURN:self.returned=True;cpu.emu_stop()
        self.uc.hook_add(UC_HOOK_CODE,stop)
        self.context_bytes=self.call('aoa_context_bytes')
        self.options_bytes=self.call('aoa_options_bytes')
        self.request_bytes=self.call('aoa_request_bytes')
        assert (self.options_bytes,self.request_bytes)==(68,28)
        self.c=CONTEXT_PAGE+4096-self.context_bytes
        self.o=OPTIONS_PAGE+4096-self.options_bytes
        self.r=REQUEST_PAGE+4096-self.request_bytes
        for ptr,n in ((self.c,self.context_bytes),(self.o,self.options_bytes),(self.r,self.request_bytes)):
            self.uc.mem_write(ptr-32,b'\xa5'*32)
            self.uc.mem_write(ptr,b'\xee'*n)
        self.strings=list(DEFAULT if strings is None else strings)
        pointers=[]
        for i,data in enumerate(self.strings):
            page=STRINGS_PAGE+i*8192;self.uc.mem_map(page,4096)
            pointer=page+4096-len(data)
            self.uc.mem_write(pointer-32,b'\xa5'*32)
            if data:self.uc.mem_write(pointer,data)
            pointers.append(pointer)
        self.pointers=pointers
        self.uc.mem_write(self.o,struct.pack('<4I2H12I',session,generation,*timeouts,*initial,
                                           *pointers,*map(len,self.strings)))
        self.now=now;self.session=session;self.generation=generation
        self.init_result=self.call('aoa_init',self.c,self.o,now)

    def call(self,name,*args):
        sp=STACK_PAGE+4096-256
        for i,reg in enumerate(REGS):self.uc.reg_write(reg,args[i]&0xffffffff if i<len(args) else 0)
        if len(args)>4:self.uc.mem_write(sp,struct.pack('<'+'I'*(len(args)-4),*[a&0xffffffff for a in args[4:]]))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        self.returned=False
        self.uc.emu_start(self.m['symbols'][name],0,timeout=2_000_000,count=300_000)
        assert self.returned,name+' did not return'
        return signed(self.uc.reg_read(UC_ARM_REG_R0))

    def context(self):return bytes(self.uc.mem_read(self.c,self.context_bytes))
    def fields(self):return struct.unpack('<11I',self.uc.mem_read(self.c,44))
    def request(self,now=None):
        result=self.call('aoa_next',self.c,self.now if now is None else now,self.r)
        if result!=1:return result,None
        session,seq,generation,setup,data,size,direction=struct.unpack('<7I',self.uc.mem_read(self.r,28))
        return result,{'session':session,'seq':seq,'generation':generation,'setup_ptr':setup,
          'setup':bytes(self.uc.mem_read(setup,8)),'data_ptr':data,'size':size,'direction':direction,
          'data':bytes(self.uc.mem_read(data,size)) if size else b''}

    def complete(self,q,actual=None,status=0,now=None,response=None):
        if response is not None:self.uc.mem_write(q['data_ptr'],response)
        return self.call('aoa_complete',self.c,q['session'],q['seq'],status,
                         q['size'] if actual is None else actual,self.now if now is None else now)

    def handshake(self,version=2):
        assert self.init_result==0
        packets=[]
        result,q=self.request();assert result==1
        assert q['setup']==bytes.fromhex('c033000000000200') and q['direction']==1
        assert q['size']==2 and q['data']==b'\0\0'
        packets.append(q['setup'].hex())
        assert self.complete(q,response=struct.pack('<H',version))==0
        for index,value in enumerate(self.strings):
            result,q=self.request();assert result==1
            # Independent wire oracle from Google's request52 specification.
            expected=struct.pack('<BBHHH',0x40,52,0,index,len(value))
            assert q['setup']==expected and q['direction']==0 and q['data']==value
            assert q['session']==self.session and q['generation']==self.generation
            assert q['seq']==index+2
            packets.append(q['setup'].hex())
            assert self.complete(q)==0
        result,q=self.request();assert result==1
        assert q['setup']==bytes.fromhex('4035000000000000') and q['data_ptr']==0 and q['size']==0
        packets.append(q['setup'].hex());assert self.complete(q)==0
        assert self.fields()[3]==4 and self.fields()[8]==0
        return packets

    def reenum(self,vid=0x18d1,pid=0x2d00,generation=8,session=None,now=None):
        return self.call('aoa_reenumerated',self.c,self.session if session is None else session,
                         generation,vid,pid,self.now if now is None else now)

    def guards(self):
        for ptr in (self.c,self.o,self.r,*self.pointers):
            assert bytes(self.uc.mem_read(ptr-32,32))==b'\xa5'*32,'prefix guard changed'
        assert bytes(self.uc.mem_read(self.m['base'],len(self.code)))==self.code
        return True

def main():
    cases=[]
    def record(name,vm,**details):
        cases.append({'name':name,'all_passed':True,'guard_pages_and_canaries_intact':vm.guards(),**details})
    for version in (1,2):
        vm=VM();packets=vm.handshake(version)
        assert vm.reenum()==0 and vm.fields()[3]==5 and vm.request()[0]==0
        record('published_protocol'+str(version)+'_full_handshake',vm,setup_hex=packets)
    # All four accessory-bearing PIDs; audio-only PIDs must not be accepted.
    for pid in (0x2d00,0x2d01,0x2d04,0x2d05):
        vm=VM();vm.handshake();assert vm.reenum(pid=pid)==0
        record('accessory_PID_'+hex(pid),vm)
        vm=VM(initial=(0x18d1,pid));assert vm.init_result==0 and vm.request()[0]==0 and vm.fields()[3]==5
        record('already_accessory_'+hex(pid),vm)
    for vid,pid in ((0x18d1,0x2d02),(0x18d1,0x2d03),(0x1234,0x2d00),(0x18d1,0xffff)):
        vm=VM();vm.handshake();before=vm.context();assert vm.reenum(vid=vid,pid=pid)==-5
        assert vm.context()==before
        record('wrong_or_audio_only_identity_'+hex(vid)+'_'+hex(pid),vm)
    for version in (0,3,0x100,0xffff):
        vm=VM();_,q=vm.request();assert vm.complete(q,response=struct.pack('<H',version))==-5
        assert vm.request()[0]==-5
        record('unsupported_protocol_'+str(version),vm)
    for actual,status in ((0,0),(1,0),(3,0),(2,-1)):
        vm=VM();_,q=vm.request();assert vm.complete(q,actual=actual,status=status,response=b'\x02\x00')==-4
        record('protocol_bad_transfer_'+str(actual)+'_'+str(status),vm)
    vm=VM();_,q=vm.request();before=vm.context();request_before=bytes(vm.uc.mem_read(vm.r,28))
    assert vm.request()[0]==2 and vm.context()==before
    assert bytes(vm.uc.mem_read(vm.r,28))==request_before
    for session,seq in ((42,1),(41,2),(0,1)):
        assert vm.call('aoa_complete',vm.c,session,seq,0,2,100)==-2 and vm.context()==before
    assert vm.complete(q,response=b'\x02\0')==0
    after=vm.context();assert vm.complete(q)==-2 and vm.context()==after
    record('duplicate_submission_stale_and_duplicate_completions',vm)
    vm=VM();_,q=vm.request();assert vm.request(now=1100)[0]==-3
    assert vm.fields()[8]==1  # timeout never frees borrowed storage
    held=vm.context();assert vm.request(now=1101)[0]==-3 and vm.context()==held
    assert vm.complete(q,now=1101)==-3 and vm.fields()[8]==0
    record('timeout_retains_borrow_until_terminal_callback',vm)
    vm=VM();_,q=vm.request();assert vm.call('aoa_cancel_ack',vm.c,41,1)==-6
    assert vm.call('aoa_cancel',vm.c)==-8 and vm.fields()[8]==1
    before=vm.context();assert vm.call('aoa_cancel_ack',vm.c,42,1)==-2 and vm.context()==before
    assert vm.call('aoa_cancel_ack',vm.c,41,1)==0 and vm.fields()[8]==0
    assert vm.complete(q)==-2
    record('cancel_requires_controller_ack_before_release',vm)
    vm=VM();_,q=vm.request();assert vm.complete(q,response=b'\x02\0',now=1100)==-3
    assert vm.fields()[8]==0
    record('completion_at_deadline_is_timeout_and_terminal',vm)
    vm=VM(now=0xfffffff0);_,q=vm.request()
    assert vm.request(now=0x3d7)[0]==2
    assert vm.request(now=0x3d8)[0]==-3 and vm.fields()[8]==1
    assert vm.call('aoa_cancel_ack',vm.c,41,1)==0
    record('32bit_millisecond_wrap_timeout',vm)
    vm=VM();vm.handshake();before=vm.context()
    assert vm.reenum(generation=7)==-2 and vm.context()==before
    assert vm.reenum(generation=6)==-2 and vm.context()==before
    assert vm.reenum(generation=0)==-2 and vm.context()==before
    assert vm.reenum(session=42)==-2 and vm.context()==before
    assert vm.reenum(now=3100)==-3
    record('reenumeration_generation_session_and_deadline',vm)
    vm=VM();assert vm.reenum()==-6
    vm.uc.mem_write(vm.c+8,struct.pack('<I',0xffffffff))
    assert vm.request()[0]==-7 and vm.fields()[8]==0
    record('wrong_state_and_sequence_exhaustion_no_token_reuse',vm)
    # Required fields + UTF8 min/max/surrogates/embedded NUL + buffer boundary.
    bad=[b'\0',b'a',b'a\0b\0',b'\xc0\xaf\0',b'\xe0\x80\x80\0',
         b'\xed\xa0\x80\0',b'\xf4\x90\x80\x80\0',b'\xf5\x80\x80\x80\0',
         b'\xe2\x82\0',b'\x80\0',b'x'*256+b'\0']
    for i,value in enumerate(bad):
        strings=DEFAULT.copy();strings[0]=value;vm=VM(strings)
        assert vm.init_result==-1 and vm.context()==b'\xee'*vm.context_bytes
        record('invalid_identity_string_'+str(i),vm)
    strings=DEFAULT.copy();strings[2]=b'x'*255+b'\0';strings[4]=b'\0'
    strings[5]='竺原😀'.encode()+b'\0';vm=VM(strings);vm.handshake()
    record('256byte_boundary_empty_optional_valid_UTF8',vm)
    vm=VM();vm.uc.mem_write(vm.pointers[0],b'X'*len(DEFAULT[0]))
    _,q=vm.request();assert vm.complete(q,response=b'\x02\0')==0
    _,q=vm.request();assert q['data']==DEFAULT[0]
    record('identity_copied_before_async_use',vm)
    for timeouts in ((0,3000),(0x80000000,3000),(1000,0),(1000,0x80000000)):
        vm=VM(timeouts=timeouts);assert vm.init_result==-1
        record('invalid_timeout_'+str(timeouts),vm)
    for session,generation in ((0,7),(41,0)):
        vm=VM(session=session,generation=generation);assert vm.init_result==-1
        record('zero_session_or_generation_'+str((session,generation)),vm)
    vm=VM();_,q=vm.request();assert vm.complete(q,response=b'\x02\0')==0
    _,q=vm.request();assert vm.complete(q,actual=q['size']-1)==-4
    record('short_OUT_string_fails_without_START',vm)
    vm=VM();_,q=vm.request();assert vm.call('aoa_cancel',vm.c)==-8
    assert vm.complete(q,response=b'\x02\0')==-8 and vm.fields()[8]==0
    record('terminal_completion_after_cancel_releases_borrow',vm)
    m=json.loads((ROOT/MANIFEST).read_text())
    names=list(m['source_sha256'])+[MANIFEST,m['flat'],m['elf'],str(Path(__file__).relative_to(ROOT))]
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,
      'case_count':len(cases),'cases':cases,'ARM_architecture':'ARMv6/ARM1176/soft-float',
      'context_bytes':vm.context_bytes,'code_bytes':len(vm.code),
      'source_sha256':{name:sha(name) for name in names},
      'new_compiled_code_executed':True,'code_mappings_write_protected':True,
      'controller_completions_and_enumeration_are_fixtures':True,
      'configuration_interface_or_bulk_endpoint_selection_implemented':False,
      'host_controller_VBUS_or_real_phone_session_verified':False,
      'session_ID_uniqueness_same_port_binding_and_single_actor_are_caller_contracts':True,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'Compiled new negotiation core executes on synthetic ARM1176 memory, no stock Garmin '
        'firmware/driver. Request51/52/53 bytes checked against independently authored Google '
        'protocol vectors. PID acceptance only accessory-bearing IDs, not bulk/TLS/AA readiness. '
        'Input/output storage page-bounded and guarded. This does not test current Pixel, host '
        'enumeration, USB status stage, actual callbacks/DMA, physical controller, UI/video/audio '
        'or available Garmin RAM. Borrow held across timeout/cancel until terminal ack; caller '
        'must keep context alive, serialize, bind same port and never reuse session IDs.'}
    name='evidence/firmware-analysis/native-aoa-emulation.json'
    (ROOT/name).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':name,'all_passed':True,'cases':len(cases),
      'code_bytes':len(vm.code),'context_bytes':vm.context_bytes,'device_io':False}))

if __name__=='__main__':main()
