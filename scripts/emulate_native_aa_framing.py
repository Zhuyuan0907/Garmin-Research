#!/usr/bin/env python3
"""Run ARMv6 framing on independent byte vectors and synthetic bulk events.

No TLS fake, actual USB, current phone or native OS installation. Python is the
serialized fixture driver, not a native dispatch loop or running receiver.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
from unicorn import UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_LR
from emulate_native_aoa_bulk import BulkVM,ROOT,REGS,STACK_PAGE,RETURN,signed,sha
MANIFEST='staging/native-aa-framing/manifest.json'
META=[0x08400000+0x2000*i for i in range(5)]
FRAME_POOL,MSG_POOL,SOURCE,ENCODE=0x09000000,0x09100000,0x09200000,0x09300000

def wire(channel,flags,payload=b'',total=0):
    return bytes((channel,flags))+struct.pack('>H',len(payload))+(struct.pack('>I',total) if flags&3==1 else b'')+payload
def snapshot_frames(payload,channel=2,control=4):
    # Independently model pinned outbound boundary: exactly16384 produces
    # FIRST with a full payload followed by an empty LAST.
    if len(payload)<16384:return [wire(channel,3|control,payload)]
    frames=[wire(channel,1|control,payload[:16384],len(payload))];offset=16384
    while True:
        part=payload[offset:offset+16384];last=offset+len(part)==len(payload)
        frames.append(wire(channel,(2 if last else 0)|control,part))
        if last:return frames
        offset+=len(part)

class FramingVM(BulkVM):
    def __init__(self,frame_capacity=65535,message_capacity=262144,max_fragments=1024):
        super().__init__();self.fm=json.loads((ROOT/MANIFEST).read_text())
        for path,want in self.fm['source_sha256'].items():assert sha(path)==want,path
        assert sha(self.fm['flat'])==self.fm['flat_sha256'] and sha(self.fm['elf'])==self.fm['elf_sha256']
        self.frame_code=(ROOT/self.fm['flat']).read_bytes();size=(len(self.frame_code)+4095)&~4095
        self.uc.mem_map(self.fm['base'],size);self.uc.mem_write(self.fm['base'],self.frame_code)
        self.uc.mem_protect(self.fm['base'],size,UC_PROT_READ|UC_PROT_EXEC)
        assert [self.framecall(n) for n in ('aa_frame_context_bytes','aa_message_context_bytes','aa_frame_view_bytes','aa_message_view_bytes')]==[52,52,28,24]
        for page in META:self.uc.mem_map(page,4096)
        self.fc,self.mc,self.fv,self.mv,self.used=[page+4096-n for page,n in zip(META,(52,52,28,24,4))]
        self.uc.mem_map(FRAME_POOL,69632);self.uc.mem_map(MSG_POOL,266240)
        self.uc.mem_map(SOURCE,135168);self.uc.mem_map(ENCODE,69632)
        self.frame_capacity=frame_capacity;self.message_capacity=message_capacity
        self.fp=FRAME_POOL+69632-frame_capacity;self.mp=MSG_POOL+266240-message_capacity
        self.ep=ENCODE+69632-65543;self.source_end=SOURCE+135168;self.last_source=None
        self.guards=[(self.fc,52),(self.mc,52),(self.fv,28),(self.mv,24),(self.used,4),
                     (self.fp,frame_capacity),(self.mp,message_capacity),(self.ep,65543)]
        for pointer,n in self.guards:self.uc.mem_write(pointer-32,b'\xa5'*32);self.uc.mem_write(pointer,b'\xee'*n)
        assert self.framecall('aa_frame_init',self.fc,41,self.fp,frame_capacity)==0
        assert self.framecall('aa_message_init',self.mc,41,self.mp,message_capacity,max_fragments)==0
    def framecall(self,name,*args):
        sp=STACK_PAGE+4096-256
        for i,reg in enumerate(REGS):self.uc.reg_write(reg,args[i]&0xffffffff if i<len(args) else 0)
        if len(args)>4:self.uc.mem_write(sp,struct.pack('<'+'I'*(len(args)-4),*[v&0xffffffff for v in args[4:]]))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN);self.returned=False
        self.uc.emu_start(self.fm['symbols'][name],0,timeout=2_000_000,count=2_000_000)
        assert self.returned,name
        return signed(self.uc.reg_read(UC_ARM_REG_R0))
    def upload(self,data):
        assert len(data)<=131072;pointer=self.source_end-len(data)
        self.uc.mem_write(pointer-32,b'\xa5'*32)
        if data:self.uc.mem_write(pointer,data)
        self.last_source=pointer;return pointer
    def feed_pointer(self,pointer,bytes):
        status=self.framecall('aa_frame_feed',self.fc,pointer,bytes,self.used)
        return status,struct.unpack('<I',self.uc.mem_read(self.used,4))[0]
    def feed(self,data):return self.feed_pointer(self.upload(data),len(data))
    def peek_frame(self):
        status=self.framecall('aa_frame_peek',self.fc,self.fv)
        if status!=1:return status,None
        a=struct.unpack('<7I',self.uc.mem_read(self.fv,28));f=dict(zip(('session','sequence','channel','flags','bytes','total','data'),a))
        f['payload']=bytes(self.uc.mem_read(f['data'],f['bytes']));return status,f
    def push(self):return self.framecall('aa_message_push',self.mc,self.fv)
    def message(self):
        status=self.framecall('aa_message_peek',self.mc,self.mv)
        if status!=1:return status,None
        a=struct.unpack('<6I',self.uc.mem_read(self.mv,24));m=dict(zip(('session','sequence','channel','flags','bytes','data'),a))
        m['payload']=bytes(self.uc.mem_read(m['data'],m['bytes']));return status,m
    def frame_release(self):return self.framecall('aa_frame_release',self.fc)
    def message_release(self):return self.framecall('aa_message_release',self.mc)
    def consume_stream(self,data,cuts=(1,3,17,4096,8192)):
        frames=[];messages=[];offset=0;idx=0
        while offset<len(data):
            block=data[offset:offset+cuts[idx%len(cuts)]];idx+=1;offset+=len(block)
            ptr=self.upload(block);used=0
            while used<len(block):
                status,n=self.feed_pointer(ptr+used,len(block)-used);used+=n
                assert status in (0,1) and n>0,(status,n)
                if status==1:
                    _,f=self.peek_frame();frames.append(f);r=self.push();assert r in (0,1),r
                    if r==1:
                        _,m=self.message();messages.append(m);assert self.message_release()==0
                    assert self.frame_release()==0
        return frames,messages
    def encode(self,channel,flags,payload,total=0,capacity=65543):
        src=self.upload(payload)
        n=self.framecall('aa_frame_encode',self.ep,capacity,channel,flags,src,len(payload),total)
        return n,bytes(self.uc.mem_read(self.ep,n)) if n>=0 else b''
    def final_guards(self):
        assert self.bulk_guards()
        for pointer,n in self.guards:assert bytes(self.uc.mem_read(pointer-32,32))==b'\xa5'*32
        if self.last_source is not None:assert bytes(self.uc.mem_read(self.last_source-32,32))==b'\xa5'*32
        assert bytes(self.uc.mem_read(self.fm['base'],len(self.frame_code)))==self.frame_code
        return True

def main():
    cases=[];payload=bytes((i*29+7)&255 for i in range(262144))
    def record(name,vm,**detail):cases.append({'name':name,'all_passed':True,
       'guard_pages_canaries_and_four_code_images_intact':vm.final_guards(),**detail})
    vectors=[(0,3,b'\x00\x01',0,'000300020001'),(1,7,b'',0,'01070000'),
      (2,5,b'abc',6,'0205000300000006616263'),(2,4,b'def',0,'02040003646566'),
      (2,6,b'',0,'02060000'),(7,9,b'XYZXYZXY',1,'070900080000000158595a58595a5859')]
    for channel,flags,body,total,expected in vectors:
        vm=FramingVM();n,out=vm.encode(channel,flags,body,total);assert out.hex()==expected and n==len(bytes.fromhex(expected))
        for byte in bytes.fromhex(expected):r,used=vm.feed(bytes((byte,)));assert used==1
        assert r==1;_,f=vm.peek_frame();assert (f['channel'],f['flags'],f['payload'],f['total'])==(channel,flags,body,total)
        record('independent_literal_wire_vector_'+expected[:8],vm,encoded_hex=expected)
    stream=wire(5,5,b'abcde',8)+wire(5,6,b'xyz')
    for cut in range(len(stream)+1):
        vm=FramingVM();frames=[];messages=[]
        # Two input calls, with each half allowed to contain multiple frames.
        for block in (stream[:cut],stream[cut:]):
            if block:
                fs,ms=vm.consume_stream(block,cuts=(len(block),));frames+=fs;messages+=ms
            else:assert vm.feed(b'')==(0,0)
        assert len(frames)==2 and len(messages)==1 and messages[0]['payload']==b'abcdexyz'
        record('all_header_payload_two_call_split_'+str(cut),vm)
    for size in (0,1,2,16383,16384,16385,32768,65535,65536,262144):
        vm=FramingVM();expected=payload[:size];packets=snapshot_frames(expected)
        frames,messages=vm.consume_stream(b''.join(packets))
        assert len(frames)==len(packets) and len(messages)==1 and messages[0]['payload']==expected
        assert messages[0]['flags']==4 and messages[0]['channel']==2
        if size==16384:assert frames[-1]['bytes']==0
        record('bounded_message_'+str(size),vm,plain_bytes=size,frame_count=len(frames),
          empty_last_supported_at_exact_upstream_fragment_size=size==16384)
    vm=FramingVM();assert vm.feed(wire(0,3,b'first')+wire(1,7,b'second'))==(1,9)
    _,f=vm.peek_frame();assert vm.push()==1;_,m=vm.message();assert m['payload']==b'first'
    before=bytes(vm.uc.mem_read(vm.fc,52));assert vm.feed(b'garbage')==(2,0) and bytes(vm.uc.mem_read(vm.fc,52))==before
    assert vm.frame_release()==0 and vm.feed(wire(1,7,b'second'))==(1,10)
    vm.peek_frame();before=bytes(vm.uc.mem_read(vm.mc,52));assert vm.push()==2 and bytes(vm.uc.mem_read(vm.mc,52))==before
    assert vm.message_release()==0 and vm.push()==1;_,m=vm.message();assert m['payload']==b'second'
    record('coalesced_input_exact_consumption_and_frame_message_backpressure',vm)
    vm=FramingVM();assert vm.feed(wire(7,9,b'ciphertext',1))==(1,18);_,f=vm.peek_frame()
    before=(bytes(vm.uc.mem_read(vm.mc,52)),bytes(vm.uc.mem_read(vm.mp,vm.message_capacity)))
    assert f['total']==1 and f['bytes']==10 and vm.push()==-44 and vm.message()[0]==-41
    assert (bytes(vm.uc.mem_read(vm.mc,52)),bytes(vm.uc.mem_read(vm.mp,vm.message_capacity)))==before
    record('opaque_ciphertext_length_not_plain_total_and_no_fake_decryption',vm)
    malformed=[('middle_without_first',[wire(0,0,b'x')],-43),('last_without_first',[wire(0,2,b'x')],-43),
      ('first_total_less_than_payload',[wire(0,1,b'abc',2)],-42),
      ('interleaved_channel',[wire(0,1,b'a',2),wire(1,2,b'b')],-43),
      ('changed_control_flag',[wire(0,5,b'a',2),wire(0,2,b'b')],-43),
      ('second_first',[wire(0,1,b'a',2),wire(0,1,b'b',2)],-43),
      ('bulk_inside_fragment',[wire(0,1,b'a',2),wire(0,3,b'b')],-43),
      ('payload_over_declared_total',[wire(0,1,b'a',2),wire(0,0,b'bc')],-42),
      ('short_last',[wire(0,1,b'a',3),wire(0,2,b'b')],-43),
      ('total_uint32_over_capacity',[wire(0,1,b'a',0xffffffff)],-42)]
    for name,packets,expected in malformed:
        vm=FramingVM()
        for packet in packets:
            assert vm.feed(packet)[0]==1;vm.peek_frame();result=vm.push();assert vm.frame_release()==0
        assert result==expected and vm.message()[0]==expected
        assert vm.framecall('aa_message_push',vm.mc,vm.fv)==expected
        record('reject_'+name,vm,expected_error=expected)
    for flags in (16,128,255):
        vm=FramingVM();assert vm.feed(wire(0,flags,b'bad'))==(-43,4)
        assert vm.peek_frame()[0]==-43 and vm.feed(wire(0,3,b'ok'))==(-43,0)
        record('reserved_flags_lock_stream_'+str(flags),vm)
    vm=FramingVM(frame_capacity=8);assert vm.feed(wire(0,3,b'123456789'))==(-42,4)
    assert vm.peek_frame()[0]==-42;record('wire_payload_over_pool_capacity',vm)
    vm=FramingVM();vm.uc.mem_write(vm.fc+8,struct.pack('<I',0xffffffff))
    assert vm.feed(wire(0,3,b'x'))==(-46,5) and vm.peek_frame()[0]==-46
    record('frame_sequence_exhaustion_no_reused_token',vm)
    for field,value in ((0,42),(4,2),(4,0)):
        vm=FramingVM();vm.feed(wire(0,3,b'x'));vm.peek_frame();vm.uc.mem_write(vm.fv+field,struct.pack('<I',value))
        assert vm.push()==-45 and vm.message()[0]==-45
        record('stale_session_or_sequence_'+str((field,value)),vm)
    vm=FramingVM();vm.feed(wire(0,3,b'x'));vm.peek_frame()
    vm.uc.mem_write(vm.mc+8,struct.pack('<I',0xffffffff))
    assert vm.push()==-46 and vm.message()[0]==-46
    record('message_sequence_exhaustion_no_wrap',vm)
    vm=FramingVM();vm.feed(wire(0,3,b'x'));vm.peek_frame()
    vm.uc.mem_write(vm.fv+20,struct.pack('<I',1))
    assert vm.push()==-43 and vm.message()[0]==-43
    record('non_FIRST_extended_total_metadata_rejected',vm)
    vm=FramingVM();vm.feed(wire(0,1,b'a',2));vm.peek_frame();assert vm.push()==0
    assert vm.push()==-45;record('duplicate_fragment_locks_message',vm)
    vm=FramingVM(max_fragments=2)
    for p in [wire(0,1,b'',0),wire(0,0,b''),wire(0,2,b'')]:
        assert vm.feed(p)[0]==1;vm.peek_frame();r=vm.push();vm.frame_release()
    assert r==-48 and vm.message()[0]==-48
    record('bounded_empty_fragment_count',vm)
    vm=FramingVM();vm.feed(wire(0,3,b'snapshot'));_,f=vm.peek_frame();before=bytes(vm.uc.mem_read(vm.fp,8))
    assert vm.framecall('aa_frame_cancel',vm.fc)==-49 and vm.feed(wire(0,3,b'next'))==(-49,0)
    assert vm.peek_frame()[1]['payload']==b'snapshot' and bytes(vm.uc.mem_read(vm.fp,8))==before
    assert vm.frame_release()==-49 and vm.peek_frame()[0]==-49
    record('cancel_holds_ready_frame_until_release',vm)
    vm=FramingVM();assert vm.feed(wire(0,1,b'abcdef',6)[:7])==(0,7)
    assert vm.framecall('aa_frame_cancel',vm.fc)==-49 and vm.feed(b'ignored')==(-49,0)
    record('cancel_partial_extended_header_no_partial_delivery',vm)
    vm=FramingVM();vm.feed(wire(0,3,b'snapshot'));vm.peek_frame();assert vm.push()==1
    assert vm.framecall('aa_message_cancel',vm.mc)==-49 and vm.push()==-49
    assert vm.message()[1]['payload']==b'snapshot' and vm.message_release()==-49 and vm.message()[0]==-49
    record('cancel_holds_ready_message_until_release',vm)
    vm=FramingVM();src=vm.upload(wire(0,3,b'owned'));assert vm.feed_pointer(src,9)==(1,9)
    vm.uc.mem_write(src,b'X'*9);vm.peek_frame();assert vm.push()==1;assert vm.frame_release()==0
    assert vm.feed(wire(0,3,b'other'))[0]==1 and vm.message()[1]['payload']==b'owned'
    record('input_and_frame_pool_reuse_do_not_change_copied_message',vm)
    vm=FramingVM();before=bytes(vm.uc.mem_read(vm.ep,65543))
    for args,error in [((256,3,b'x',0,100),-40),((0,16,b'x',0,100),-40),
      ((0,3,b'x',1,100),-40),((0,1,b'abc',2,100),-43),((0,3,b'abc',0,6),-42)]:
        assert vm.encode(*args)[0]==error and bytes(vm.uc.mem_read(vm.ep,65543))==before
    assert vm.framecall('aa_frame_encode',vm.ep,65543,0,3,0,1,0)==-40
    assert vm.framecall('aa_frame_encode',vm.ep,65543,0,3,vm.fp,65536,0)==-40
    record('encoder_rejected_arguments_leave_output_unchanged',vm)
    vm=FramingVM();before=bytes(vm.uc.mem_read(vm.fc,52))
    for session,pointer,cap in [(0,vm.fp,10),(41,0,10),(41,vm.fp,0),(41,vm.fp,65536),(41,0xfffffff0,32)]:
        assert vm.framecall('aa_frame_init',vm.fc,session,pointer,cap)==-40 and bytes(vm.uc.mem_read(vm.fc,52))==before
    for count in (0,1025):assert vm.framecall('aa_message_init',vm.mc,41,vm.mp,262144,count)==-40
    record('initializer_bounds_pool_wrap_and_fragment_limits',vm)
    # Full wire uint16 length boundary, not just a small-frame decoder.
    vm=FramingVM();body=payload[:65535];n,out=vm.encode(255,3,body);assert n==65539 and out==wire(255,3,body)
    fs,ms=vm.consume_stream(out,cuts=(8192,));assert fs[0]['bytes']==65535 and ms[0]['payload']==body
    record('full_uint16_wire_payload_boundary_unaligned_frame_pool',vm)
    vm=FramingVM();body=payload[:65535];n,out=vm.encode(255,9,body,1)
    assert n==65543 and out==wire(255,9,body,1)
    assert vm.feed(out)==(1,65543);_,f=vm.peek_frame()
    assert f['payload']==body and f['total']==1 and vm.push()==-44
    record('largest_extended_wire_frame_keeps_ciphertext_opaque',vm)
    # New native encoder → preserved bulk TX short completion → fixture RX →
    # preserved bulk read → new native parser/message assembler, same session.
    vm=FramingVM();body=payload[:20000];expected_packets=snapshot_frames(body);sent=b''
    for packet in expected_packets:
        flags=packet[1];head=8 if flags&3==1 else 4
        n,out=vm.encode(packet[0],flags,packet[head:],len(body) if head==8 else 0)
        assert out==packet
        for offset in range(0,n,4096):
            block=out[offset:offset+4096];assert vm.queue(block)==0
            while True:
                r,q=vm.tx()
                if r==0:break
                assert r==1;actual=min(q['bytes'],997)
                sent+=bytes(vm.uc.mem_read(q['data'],actual));assert vm.complete_bulk(q,actual=actual)==0
    assert sent==b''.join(expected_packets);frames=[];messages=[]
    for offset in range(0,len(sent),4096):
        block=sent[offset:offset+4096];_,q=vm.rx();assert vm.complete_bulk(q,actual=len(block),data=block)==0
        copied=vm.bulkcall('aoa_bulk_read_rx',vm.b,vm.output,4096);assert copied==len(block)
        consumed=0
        while consumed<copied:
            r,n=vm.feed_pointer(vm.output+consumed,copied-consumed);consumed+=n;assert r in (0,1) and n>0
            if r==1:
                _,f=vm.peek_frame();frames.append(f);r=vm.push();assert r in (0,1)
                if r==1:messages.append(vm.message()[1]);assert vm.message_release()==0
                assert vm.frame_release()==0
    assert len(frames)==2 and len(messages)==1 and messages[0]['payload']==body
    assert vm.quiescent()==1
    record('same_VM_handshake_config_bulk_and_framing_chain',vm,plain_bytes=20000,
      encoded_wire_exact_reference=True,Python_dispatch_and_controller_events_are_fixtures=True)
    fm=json.loads((ROOT/MANIFEST).read_text());deps=set(fm['source_sha256'])|{MANIFEST,fm['flat'],fm['elf'],str(Path(__file__).relative_to(ROOT)),
       'scripts/emulate_native_aoa.py','scripts/emulate_native_aoa_config.py','scripts/emulate_native_aoa_bulk.py'}
    for name in ('staging/native-aoa-host/manifest.json','staging/native-aoa-config/manifest.json','staging/native-aoa-bulk/manifest.json'):
        m=json.loads((ROOT/name).read_text());deps.update(m['source_sha256']);deps.update((name,m['flat'],m['elf']))
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'case_count':len(cases),'cases':cases,
      'code_bytes':fm['flat_bytes'],'frame_context_bytes':52,'message_context_bytes':52,'frame_view_bytes':28,'message_view_bytes':24,
      'tested_frame_pool_capacity':65535,'tested_message_pool_capacity':262144,
      'source_sha256':{name:sha(name) for name in sorted(deps)},'compiled_ARMv6_code_executed':True,
      'independent_wire_vectors_and_old_upstream_fragment_boundary':True,
      'ciphertext_not_delivered_as_plaintext_no_fake_TLS':True,
      'preserved_negotiation_configuration_bulk_artifacts_unchanged':True,
      'controller_events_and_dispatch_driver_are_fixtures':True,
      'real_TLS_crypto_auth_current_phone_host_Garmin_RAM_UI_or_AA_verified':False,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'Compiled native one-frame wire encoder, incremental parser and plaintext message assembler execute on '
        'ARM1176 with independent wire fixtures. Same synthetic VM chains preserved handshake/config/bulk and framing; '
        'Python serialized driver/terminal RX writes not native dispatch or actual USB. Full16-bit wire length and256KiB '
        'plain-message boundary tested. Encrypted payload remains opaque and refused by plain assembler, no crypto '
        'or fake TLS. Older pinned aasdk model, stricter ordering/length/reserved-bit policies, not official/current '
        'phone protocol proof. Caller-owned pools/borrow release/session/lifetime remain contracts, synthetic addresses '
        'not proven Garmin allocations. No automatic outbound fragmentation, TLS/Protobuf/channel/auth/decoder/UI/'
        'speaker/device installation/performance or full goal completion.'}
    name='evidence/firmware-analysis/native-aa-framing-emulation.json';(ROOT/name).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':name,'cases':len(cases),'code_bytes':fm['flat_bytes'],'dependencies':len(deps),'device_io':False}))
if __name__=='__main__':main()
