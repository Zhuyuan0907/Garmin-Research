#!/usr/bin/env python3
"""Run ARMv6 descriptor/configuration code with synthetic USB descriptors/events."""
from datetime import datetime,timezone
import json
from pathlib import Path
import struct
from unicorn import UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_LR
from emulate_native_aoa import VM,ROOT,REGS,STACK_PAGE,RETURN,signed,sha

MANIFEST='staging/native-aoa-config/manifest.json'
CONFIG_PAGE=0x08130000;CHILD_PAGE=0x08007000;PLAN_PAGE=0x08009000

def ep(address,packet=512,attributes=2):return struct.pack('<4BHB',7,5,address,attributes,packet,0)
def interface(number=0,alt=0,endpoints=None,identity=(255,255,0)):
    endpoints=[ep(0x81),ep(2)] if endpoints is None else endpoints
    return struct.pack('<9B',9,4,number,alt,len(endpoints),*identity,0)+b''.join(endpoints)
def config(body=None,count=1,value=1):
    body=interface() if body is None else body
    return struct.pack('<BBH5B',9,2,9+len(body),count,value,0,0x80,250)+body
def changed(blob,offset,value):
    out=bytearray(blob);out[offset]=value;return bytes(out)

class ConfigVM(VM):
    def __init__(self,blob=None):
        super().__init__()
        self.n=json.loads((ROOT/MANIFEST).read_text())
        for name,want in self.n['source_sha256'].items():assert sha(name)==want,name
        assert sha(self.n['flat'])==self.n['flat_sha256'] and sha(self.n['elf'])==self.n['elf_sha256']
        self.new_code=(ROOT/self.n['flat']).read_bytes()
        size=(len(self.new_code)+4095)&~4095
        self.uc.mem_map(self.n['base'],size)
        self.uc.mem_write(self.n['base'],self.new_code)
        self.uc.mem_protect(self.n['base'],size,UC_PROT_READ|UC_PROT_EXEC)
        for page in (CONFIG_PAGE,CHILD_PAGE,PLAN_PAGE):self.uc.mem_map(page,4096)
        self.child_bytes=self.newcall('aoa_usb_context_bytes');self.plan_bytes=self.newcall('aoa_usb_plan_bytes')
        assert self.child_bytes==64 and self.plan_bytes==24
        self.child=CHILD_PAGE+4096-self.child_bytes;self.plan=PLAN_PAGE+4096-self.plan_bytes
        for pointer,size in ((self.child,self.child_bytes),(self.plan,self.plan_bytes)):
            self.uc.mem_write(pointer-32,b'\xa5'*32);self.uc.mem_write(pointer,b'\xee'*size)
        self.blob=config() if blob is None else blob
        self.source=CONFIG_PAGE+4096-len(self.blob)
        self.uc.mem_write(self.source-32,b'\xa5'*32)
        if self.blob:self.uc.mem_write(self.source,self.blob)
        self.uc.mem_protect(CONFIG_PAGE,4096,UC_PROT_READ)

    def newcall(self,name,*args):
        sp=STACK_PAGE+4096-256
        for i,reg in enumerate(REGS):self.uc.reg_write(reg,args[i]&0xffffffff if i<len(args) else 0)
        if len(args)>4:self.uc.mem_write(sp,struct.pack('<'+'I'*(len(args)-4),*[v&0xffffffff for v in args[4:]]))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN);self.returned=False
        self.uc.emu_start(self.n['symbols'][name],0,timeout=2_000_000,count=300_000)
        assert self.returned,name
        return signed(self.uc.reg_read(UC_ARM_REG_R0))

    def parse(self,speed=2):return self.newcall('aoa_usb_parse',self.source,len(self.blob),speed,self.plan)
    def plan_values(self):return list(struct.unpack('<6I',self.uc.mem_read(self.plan,24)))
    def initialize(self,speed=2):
        return self.newcall('aoa_usb_init',self.child,self.c,self.source,len(self.blob),speed)
    def child_fields(self):return struct.unpack('<8I',self.uc.mem_read(self.child,32))
    def child_memory(self):return bytes(self.uc.mem_read(self.child,self.child_bytes))
    def next_config(self,now=100):
        result=self.newcall('aoa_usb_next',self.child,now,self.r)
        if result!=1:return result,None
        session,sequence,generation,setup,data,size,direction=struct.unpack('<7I',self.uc.mem_read(self.r,28))
        assert not data and not size and not direction
        return result,{'session':session,'sequence':sequence,'generation':generation,
                       'setup':bytes(self.uc.mem_read(setup,8))}
    def complete_config(self,q,status=0,actual=0,now=100):
        return self.newcall('aoa_usb_complete',self.child,q['session'],q['sequence'],status,actual,now)
    def new_guards(self):
        assert super().guards()
        for ptr in (self.child,self.plan,self.source):assert bytes(self.uc.mem_read(ptr-32,32))==b'\xa5'*32
        assert bytes(self.uc.mem_read(self.source,len(self.blob)))==self.blob
        assert bytes(self.uc.mem_read(self.n['base'],len(self.new_code)))==self.new_code
        return True

def main():
    cases=[]
    def record(name,vm,**details):
        cases.append({'name':name,'all_passed':True,'guards_and_code_intact':vm.new_guards(),**details})
    def accepted(name,blob,plan,speed=2):
        vm=ConfigVM(blob);assert vm.parse(speed)==0;assert vm.plan_values()==plan
        record(name,vm,selected_plan=plan)
    accepted('HS_accessory_default',config(),[1,0,0x81,2,512,512])
    accepted('OUT_before_IN',config(interface(endpoints=[ep(2),ep(0x81)])),[1,0,0x81,2,512,512])
    accepted('accessory_after_ADB_fixture',config(interface(identity=(255,66,1),endpoints=[ep(0x83),ep(4)])+
             interface(number=1),count=2,value=7),[7,1,0x81,2,512,512])
    accepted('alternate_not_selected',config(interface()+interface(alt=1,endpoints=[ep(0x81),ep(2)])),[1,0,0x81,2,512,512])
    accepted('audio_interfaces_and_alt_are_ignored',config(interface(number=0,identity=(1,1,0),endpoints=[])+
             interface(number=1,identity=(1,2,0),endpoints=[])+
             interface(number=1,alt=1,identity=(1,2,0),endpoints=[ep(0x83,192,1)])+
             interface(number=2),count=3),[1,2,0x81,2,512,512])
    accepted('well_formed_class_extensions',config(interface()+bytes([5,0x24,1,2,3])),[1,0,0x81,2,512,512])
    for packet in (8,16,32,64):
        accepted('FS_bulk_packet_'+str(packet),config(interface(endpoints=[ep(0x81,packet),ep(2,packet)])),
                 [1,0,0x81,2,packet,packet],speed=1)
    extension=b'';remaining=1024-len(config())
    while remaining:
        size=min(255,remaining)
        if remaining-size==1:size-=1
        extension+=bytes([size,0x24])+bytes(size-2);remaining-=size
    accepted('1024byte_configuration_boundary',config(interface()+extension),[1,0,0x81,2,512,512])
    accepted('64_interface_alt_pairs_boundary',config(interface()+b''.join(interface(alt=a,endpoints=[]) for a in range(1,64))),
             [1,0,0x81,2,512,512])
    valid=config()
    malformed=[
      ('short_header',valid[:8],-1),('oversize',valid+b'x'*1000,-1),
      ('wrong_header_length',changed(valid,0,8),-20),('wrong_descriptor_type',changed(valid,1,1),-20),
      ('wrong_total_low',changed(valid,2,31),-20),('wrong_total_high',changed(valid,3,1),-20),
      ('zero_interfaces',changed(valid,4,0),-20),('wrong_interface_count',changed(valid,4,2),-20),
      ('zero_config_value',changed(valid,5,0),-20),('mandatory_attribute_missing',changed(valid,7,0),-20),
      ('reserved_attribute_set',changed(valid,7,0x81),-20),
      ('zero_descriptor_length',changed(valid,9,0),-20),('one_byte_descriptor',changed(valid,9,1),-20),
      ('descriptor_overrun',changed(valid,9,255),-20),('short_interface',changed(valid,9,8),-20),
      ('interface_number_out_of_range',changed(valid,11,1),-20),
      ('missing_endpoint',config(interface(endpoints=[ep(0x81)])),-20),
      ('extra_endpoint',config(interface(endpoints=[ep(0x81),ep(2),ep(3)])),-20),
      ('endpoint_before_interface',config(ep(0x81)+interface()),-20),
      ('short_endpoint',changed(valid,18,6),-20),('endpoint_zero',changed(valid,20,0x80),-20),
      ('endpoint_reserved_address_bits',changed(valid,20,0x91),-20),
      ('selected_interrupt_endpoint',changed(valid,21,3),-20),
      ('bulk_reserved_attributes',changed(valid,21,0x82),-20),
      ('invalid_HS_packet',changed(valid,23,1),-20),('HS_additional_transaction_bits',changed(valid,23,0x12),-20),
      ('duplicate_endpoint',config(interface(endpoints=[ep(0x81),ep(0x81)])),-20),
      ('two_IN_endpoints',config(interface(endpoints=[ep(0x81),ep(0x82)])),-20),
      ('two_OUT_endpoints',config(interface(endpoints=[ep(1),ep(2)])),-20),
      ('duplicate_alt_pair',config(interface()+interface()),-20),
      ('global_active_endpoint_collision',config(interface()+interface(number=1,identity=(255,66,1)),count=2),-20),
      ('ADB_only_fixture',config(interface(identity=(255,66,1))),-21),
      ('accessory_nondefault_alt_only',config(interface(identity=(255,66,1),endpoints=[])+interface(alt=1)),-21),
      ('missing_default_alt',config(interface(alt=1)),-20),
      ('ambiguous_accessory_interfaces',config(interface()+interface(number=1,endpoints=[ep(0x83),ep(4)]),count=2),-22),
      ('nested_config_descriptor',config(interface()+valid[:9]),-20),
      ('65_alt_pairs_over_bound',config(interface()+b''.join(interface(alt=a,endpoints=[]) for a in range(1,65))),-20),
      ('partial_descriptor_trailer',config(interface()+b'\x02'),-20),
    ]
    for name,blob,result in malformed:
        vm=ConfigVM(blob);before=bytes(vm.uc.mem_read(vm.plan,24));actual=vm.parse()
        assert actual==result,(name,actual,result)
        assert bytes(vm.uc.mem_read(vm.plan,24))==before
        record(name,vm,expected_status=result)
    vm=ConfigVM();assert vm.parse(1)==-20 and vm.parse(3)==-1
    record('FS_rejects_HS_packet_and_unsupported_speed',vm)
    vm=ConfigVM();assert vm.initialize()==-6 and vm.child_memory()==b'\xee'*64
    record('parent_not_identified_rejected',vm)
    vm=ConfigVM();vm.handshake();assert vm.reenum()==0
    parent=vm.context();assert vm.initialize()==0 and vm.context()==parent
    _,q=vm.next_config();assert q['setup']==bytes.fromhex('0009010000000000') and q['sequence']==9
    assert q['session']==41 and q['generation']==8
    assert vm.complete_config(q)==0 and vm.child_fields()[3]==2 and vm.next_config()[0]==0
    assert vm.context()==parent
    record('full_handshake_reenum_parse_SET_CONFIGURATION_chain',vm,setup_hex=q['setup'].hex(),sequence=q['sequence'])
    vm=ConfigVM(config(value=7));vm.handshake();vm.reenum();assert vm.initialize()==0
    _,q=vm.next_config();assert q['setup']==bytes.fromhex('0009070000000000')
    # Descriptor input is no longer used after copying the plan.
    vm.uc.mem_write(vm.source+5,b'\x63');assert vm.complete_config(q)==0
    vm.uc.mem_write(vm.source+5,b'\x07')
    record('configuration_value7_owned_plan_not_constant1',vm,setup_hex=q['setup'].hex())
    vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize();_,q=vm.next_config();before=vm.child_memory()
    assert vm.next_config()[0]==2 and vm.child_memory()==before
    assert vm.newcall('aoa_usb_complete',vm.child,42,9,0,0,100)==-2 and vm.child_memory()==before
    assert vm.newcall('aoa_usb_complete',vm.child,41,8,0,0,100)==-2 and vm.child_memory()==before
    assert vm.complete_config(q)==0;after=vm.child_memory()
    assert vm.complete_config(q)==-2 and vm.child_memory()==after
    record('duplicate_submission_stale_and_duplicate_completion',vm)
    for status,actual in ((-1,0),(0,1)):
        vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize();_,q=vm.next_config()
        assert vm.complete_config(q,status=status,actual=actual)==-4
        record('config_transfer_error_'+str((status,actual)),vm)
    vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize();_,q=vm.next_config()
    assert vm.next_config(now=1100)[0]==-3 and vm.child_fields()[6]==1
    assert vm.complete_config(q,now=1101)==-3 and vm.child_fields()[6]==0
    record('timeout_retains_setup_borrow_until_terminal_completion',vm)
    vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize();_,q=vm.next_config()
    assert vm.newcall('aoa_usb_cancel_ack',vm.child,41,9)==-6
    assert vm.newcall('aoa_usb_cancel',vm.child)==-8 and vm.child_fields()[6]==1
    assert vm.newcall('aoa_usb_cancel_ack',vm.child,42,9)==-2
    assert vm.newcall('aoa_usb_cancel_ack',vm.child,41,9)==0 and vm.child_fields()[6]==0
    record('cancel_ack_requires_failed_state_and_matching_token',vm)
    vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize();_,q=vm.next_config(now=0xfffffff0)
    assert vm.next_config(now=0x3d7)[0]==2 and vm.next_config(now=0x3d8)[0]==-3
    assert vm.newcall('aoa_usb_cancel_ack',vm.child,41,9)==0
    record('configuration_timeout_32bit_clock_wrap',vm)
    vm=ConfigVM();vm.handshake();vm.reenum();vm.initialize()
    vm.uc.mem_write(vm.child+8,struct.pack('<I',0xffffffff));assert vm.next_config()[0]==-7
    record('configuration_sequence_exhaustion',vm)
    vm=ConfigVM();vm.handshake();vm.reenum();vm.uc.mem_write(vm.c+32,struct.pack('<I',1))
    assert vm.initialize()==-6
    vm.uc.mem_write(vm.c+32,struct.pack('<I',0))
    record('borrowed_parent_rejected',vm)
    m=json.loads((ROOT/MANIFEST).read_text());old=json.loads((ROOT/'staging/native-aoa-host/manifest.json').read_text())
    deps=set(m['source_sha256'])|set(old['source_sha256'])|{MANIFEST,m['flat'],m['elf'],
      'staging/native-aoa-host/manifest.json',old['flat'],old['elf'],
      'scripts/emulate_native_aoa.py',str(Path(__file__).relative_to(ROOT))}
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'case_count':len(cases),
      'cases':cases,'code_bytes':m['flat_bytes'],'context_bytes':vm.child_bytes,'plan_bytes':vm.plan_bytes,
      'source_sha256':{name:sha(name) for name in sorted(deps)},
      'compiled_ARMv6_code_executed':True,'code_protected_and_guard_pages_used':True,
      'handshake_core_original_artifacts_unchanged':True,'descriptor_and_controller_events_are_fixtures':True,
      'configuration_interface_bulk_endpoint_selection_implemented':True,
      'actual_bulk_data_transfer_or_interface_claim_implemented':False,
      'host_controller_VBUS_real_phone_TLS_or_AA_verified':False,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'Independent synthetic USB2 FS/HS descriptor vectors exercise new bounded parser, '
        'same synthetic parent handshake/re-enumeration chain and child SET_CONFIGURATION control. '
        'Class FF/FF/00 from pinned older AOSP snapshot, current Pixel descriptors not read. ADB/audio '
        'fixtures excluded; malformed/ambiguous configs fail, failure output unchanged. '
        'No controller/USB bus/status/DMA, enumeration request, bulk traffic, TLS/video/UI/audio '
        'or Garmin loaded execution. New and old code protected; parent state unchanged. '
        'Fresh child/context/session ownership, one child/single actor/same port remain caller contracts.'}
    name='evidence/firmware-analysis/native-aoa-config-emulation.json'
    (ROOT/name).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':name,'cases':len(cases),'code_bytes':m['flat_bytes'],
      'context_bytes':vm.child_bytes,'dependencies':len(deps),'device_io':False}))
if __name__=='__main__':main()
