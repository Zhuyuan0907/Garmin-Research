#!/usr/bin/env python3
"""Execute owned full-duplex ARMv6 bulk code, with fake terminal/DMA events only."""
from datetime import datetime,timezone
import json
from pathlib import Path
import struct
from unicorn import UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_LR
from emulate_native_aoa_config import ConfigVM,ROOT,REGS,STACK_PAGE,RETURN,signed,sha

MANIFEST='staging/native-aoa-bulk/manifest.json'
BULK_PAGE=0x08200000;INPUT_PAGE=0x08300000;OUTPUT_PAGE=0x08303000;SECOND_REQUEST_PAGE=0x0800b000

class BulkVM(ConfigVM):
    def __init__(self,ready=True):
        super().__init__();self.bm=json.loads((ROOT/MANIFEST).read_text())
        for name,want in self.bm['source_sha256'].items():assert sha(name)==want,name
        assert sha(self.bm['flat'])==self.bm['flat_sha256'] and sha(self.bm['elf'])==self.bm['elf_sha256']
        self.bulk_code=(ROOT/self.bm['flat']).read_bytes();size=(len(self.bulk_code)+4095)&~4095
        self.uc.mem_map(self.bm['base'],size);self.uc.mem_write(self.bm['base'],self.bulk_code)
        self.uc.mem_protect(self.bm['base'],size,UC_PROT_READ|UC_PROT_EXEC)
        self.bulk_bytes=self.bulkcall('aoa_bulk_context_bytes');assert self.bulk_bytes==8284
        assert self.bulkcall('aoa_bulk_request_bytes')==28
        self.uc.mem_map(BULK_PAGE,12288);self.uc.mem_map(INPUT_PAGE,8192);self.uc.mem_map(OUTPUT_PAGE,8192)
        self.uc.mem_map(SECOND_REQUEST_PAGE,4096)
        self.b=BULK_PAGE+12288-self.bulk_bytes;self.input=INPUT_PAGE+4096;self.output=OUTPUT_PAGE+4096
        self.r2=SECOND_REQUEST_PAGE+4096-28
        for pointer,size in ((self.b,self.bulk_bytes),(self.input,4096),(self.output,4096),(self.r2,28)):
            self.uc.mem_write(pointer-32,b'\xa5'*32);self.uc.mem_write(pointer,b'\xee'*size)
        if ready:
            self.handshake();assert self.reenum()==0 and self.initialize()==0
            _,q=self.next_config();assert self.complete_config(q)==0
            parent=self.child_memory();assert self.bulkcall('aoa_bulk_init',self.b,self.child)==0
            assert self.child_memory()==parent

    def bulkcall(self,name,*args):
        sp=STACK_PAGE+4096-256
        for i,reg in enumerate(REGS):self.uc.reg_write(reg,args[i]&0xffffffff if i<len(args) else 0)
        if len(args)>4:self.uc.mem_write(sp,struct.pack('<'+'I'*(len(args)-4),*[v&0xffffffff for v in args[4:]]))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN);self.returned=False
        self.uc.emu_start(self.bm['symbols'][name],0,timeout=2_000_000,count=300_000)
        assert self.returned,name
        return signed(self.uc.reg_read(UC_ARM_REG_R0))
    def memory(self):return bytes(self.uc.mem_read(self.b,self.bulk_bytes))
    def queue(self,data):
        if data:self.uc.mem_write(self.input,data)
        return self.bulkcall('aoa_bulk_queue_tx',self.b,self.input,len(data))
    def tx(self,now=100):
        result=self.bulkcall('aoa_bulk_next_tx',self.b,now,self.r)
        return result,self.request_values(self.r) if result==1 else None
    def rx(self,size=4096,now=100):
        result=self.bulkcall('aoa_bulk_next_rx',self.b,size,now,self.r2)
        return result,self.request_values(self.r2) if result==1 else None
    def request_values(self,pointer):
        a=struct.unpack('<7I',self.uc.mem_read(pointer,28))
        return dict(zip(('session','sequence','generation','direction','endpoint','data','bytes'),a))
    def complete_bulk(self,q,status=0,actual=None,now=100,data=None):
        if data is not None:
            assert len(data)<=q['bytes']
            self.uc.mem_write(q['data'],data)
        return self.bulkcall('aoa_bulk_complete',self.b,q['session'],q['sequence'],q['direction'],status,
                             q['bytes'] if actual is None else actual,now)
    def take(self,capacity=4096):
        n=self.bulkcall('aoa_bulk_read_rx',self.b,self.output,capacity)
        return n,bytes(self.uc.mem_read(self.output,n)) if n>0 else b''
    def quiescent(self):return self.bulkcall('aoa_bulk_quiescent',self.b)
    def bulk_guards(self):
        assert self.new_guards()
        for ptr in (self.b,self.input,self.output,self.r2):assert bytes(self.uc.mem_read(ptr-32,32))==b'\xa5'*32
        assert bytes(self.uc.mem_read(self.bm['base'],len(self.bulk_code)))==self.bulk_code
        return True

def main():
    cases=[]
    def record(name,vm,**detail):
        cases.append({'name':name,'all_passed':True,'guards_and_all_three_code_images_intact':vm.bulk_guards(),**detail})
    payload=bytes((i*37+11)&255 for i in range(4096))
    for order in ('IN_first','OUT_first'):
        vm=BulkVM();parents=(vm.context(),vm.child_memory());assert vm.queue(payload)==0
        _,tx=vm.tx();_,rx=vm.rx();assert tx['sequence']==10 and rx['sequence']==11
        assert (tx['endpoint'],rx['endpoint'])==(2,0x81) and tx['data']!=rx['data']
        assert vm.quiescent()==0 and vm.tx()[0]==2 and vm.rx()[0]==2
        vm.uc.mem_write(vm.input,b'X'*4096);assert bytes(vm.uc.mem_read(tx['data'],4096))==payload
        received=b'reply-'+payload[:900]
        if order=='IN_first':
            assert vm.complete_bulk(rx,actual=len(received),data=received)==0 and vm.quiescent()==0
            assert vm.take()==(len(received),received)
            assert vm.complete_bulk(tx)==0
        else:
            assert vm.complete_bulk(tx)==0 and vm.quiescent()==0
            assert vm.complete_bulk(rx,actual=len(received),data=received)==0
            assert vm.take()==(len(received),received)
        assert vm.quiescent()==1 and (vm.context(),vm.child_memory())==parents
        record('full_chain_duplex_'+order,vm,TX_bytes=4096,RX_bytes=len(received))
    for chunks in ((1,511,512,3072),(2048,2048),(4096,)):
        vm=BulkVM();assert vm.queue(payload)==0;sent=b'';tokens=[]
        for size in chunks:
            result,q=vm.tx();assert result==1 and q['bytes']==4096-len(sent)
            assert bytes(vm.uc.mem_read(q['data'],q['bytes']))==payload[len(sent):]
            sent+=bytes(vm.uc.mem_read(q['data'],size));tokens.append(q['sequence'])
            assert vm.complete_bulk(q,actual=size)==0
        assert sent==payload and vm.tx()[0]==0
        assert vm.queue(b'next')==0;_,new=vm.tx();assert new['sequence']>tokens[-1]
        assert vm.complete_bulk(q)==-2 and vm.complete_bulk(new)==0
        record('partial_success_OUT_'+str(chunks),vm,exact_original_bytes_sent_without_duplication=True)
    for actual in (0,1,511,512,1023,4096):
        vm=BulkVM();_,q=vm.rx();data=payload[:actual]
        assert vm.complete_bulk(q,actual=actual,data=data)==0
        if actual:
            assert vm.rx()[0]==2
            first=min(actual,17);assert vm.take(first)==(first,data[:first])
            if actual>first:assert vm.rx()[0]==2
            assert vm.take()==(actual-first,data[first:])
        else:assert vm.take()==(0,b'')
        assert vm.rx()[0]==1
        record('valid_short_or_zero_IN_'+str(actual),vm)
    vm=BulkVM();assert vm.queue(b'owned')==0;_,q=vm.tx();before=vm.memory()
    assert vm.queue(b'newer')==2 and vm.memory()==before
    assert vm.complete_bulk(q)==0 and vm.queue(b'newer')==0
    record('TX_capacity_gates_replacement',vm)
    vm=BulkVM();vm.queue(b'bytes');_,tx=vm.tx();_,rx=vm.rx();before=vm.memory()
    for session,sequence,direction,result in ((42,tx['sequence'],0,-2),(41,tx['sequence'],1,-2),
                                             (41,tx['sequence']+100,0,-2),(41,tx['sequence'],2,-1)):
        assert vm.bulkcall('aoa_bulk_complete',vm.b,session,sequence,direction,0,0,100)==result
        assert vm.memory()==before
    assert vm.complete_bulk(tx)==0 and vm.complete_bulk(tx)==-2
    assert vm.complete_bulk(rx,actual=0)==0
    record('stale_direction_session_duplicate_callback_guards',vm)
    for error_case,status,actual in [('short_zero_OUT',0,0),('OUT_overflow',0,11),('OUT_error_partial',-1,3)]:
        vm=BulkVM();vm.queue(b'1234567890');_,tx=vm.tx();_,rx=vm.rx()
        assert vm.complete_bulk(tx,status=status,actual=actual)==-4 and vm.quiescent()==0
        assert vm.queue(b'retry')==-4 and vm.tx()[0]==-4 and vm.take()[0]==-4
        assert vm.complete_bulk(rx,actual=0)==-4 and vm.quiescent()==1
        record(error_case+'_locks_stream_other_borrow_retained',vm)
    for status,actual in ((-1,7),(0,4097)):
        vm=BulkVM();vm.queue(b'pending');_,tx=vm.tx();_,rx=vm.rx()
        assert vm.complete_bulk(rx,status=status,actual=actual)==-4 and vm.quiescent()==0
        assert vm.complete_bulk(tx,actual=3)==-4 and vm.quiescent()==1
        record('IN_error_or_overflow_'+str((status,actual)),vm)
    for disconnect in (0,1):
        for order in (0,1):
            vm=BulkVM();vm.queue(payload);_,tx=vm.tx();_,rx=vm.rx();expected=-30 if disconnect else -8
            data_before=(bytes(vm.uc.mem_read(tx['data'],4096)),bytes(vm.uc.mem_read(rx['data'],4096)))
            assert vm.bulkcall('aoa_bulk_stop',vm.b,disconnect)==expected and vm.quiescent()==0
            assert (bytes(vm.uc.mem_read(tx['data'],4096)),bytes(vm.uc.mem_read(rx['data'],4096)))==data_before
            assert vm.queue(b'new')==expected and vm.rx()[0]==expected
            first,second=(rx,tx) if order else (tx,rx)
            assert vm.complete_bulk(first,status=-1,actual=3)==expected and vm.quiescent()==0
            assert vm.complete_bulk(second,status=-1,actual=0)==expected and vm.quiescent()==1
            record('stop_'+str(disconnect)+'_terminal_order_'+str(order),vm)
    vm=BulkVM();vm.queue(b'pending');_,tx=vm.tx();_,rx=vm.rx(now=200)
    assert vm.bulkcall('aoa_bulk_poll',vm.b,1099)==0
    assert vm.bulkcall('aoa_bulk_poll',vm.b,1100)==-3 and vm.quiescent()==0
    assert vm.complete_bulk(tx,now=1101)==-3 and vm.quiescent()==0
    assert vm.complete_bulk(rx,actual=0,now=1101)==-3 and vm.quiescent()==1
    record('timeout_retains_both_borrows_until_terminal_callbacks',vm)
    vm=BulkVM();vm.queue(b'pending');_,tx=vm.tx(now=100);_,rx=vm.rx(now=200)
    assert vm.complete_bulk(rx,actual=1,data=b'R',now=1100)==-3
    assert vm.quiescent()==0 and vm.take()[0]==-3
    assert vm.complete_bulk(tx,status=-1,actual=0,now=1100)==-3 and vm.quiescent()==1
    record('IN_completion_observes_expired_OUT_deadline_without_prior_poll',vm)
    vm=BulkVM();_,rx=vm.rx(now=100);vm.queue(b'pending');_,tx=vm.tx(now=200)
    assert vm.complete_bulk(tx,now=1100)==-3 and vm.quiescent()==0
    assert vm.complete_bulk(rx,status=-1,actual=0,now=1100)==-3 and vm.quiescent()==1
    record('OUT_completion_observes_expired_IN_deadline_without_prior_poll',vm)
    vm=BulkVM();_,rx=vm.rx(now=0xfffffff0)
    assert vm.bulkcall('aoa_bulk_poll',vm.b,0x3d7)==0
    assert vm.bulkcall('aoa_bulk_poll',vm.b,0x3d8)==-3
    assert vm.complete_bulk(rx,actual=0,now=0x3d8)==-3 and vm.quiescent()==1
    record('bulk_deadline_32bit_wrap',vm)
    vm=BulkVM();_,rx=vm.rx();vm.queue(b'pending');vm.uc.mem_write(vm.b+8,struct.pack('<I',0xffffffff))
    assert vm.tx()[0]==-7 and vm.quiescent()==0
    assert vm.complete_bulk(rx,actual=0)==-7 and vm.quiescent()==1
    record('sequence_exhaustion_keeps_existing_RX_borrow',vm)
    for size in (0,1,511,4097):
        vm=BulkVM();before=vm.memory();assert vm.rx(size)[0]==-1 and vm.memory()==before
        record('invalid_RX_packet_multiple_or_bound_'+str(size),vm)
    vm=BulkVM();before=vm.memory()
    assert vm.queue(b'')==-1 and vm.bulkcall('aoa_bulk_queue_tx',vm.b,vm.input,4097)==-1
    assert vm.bulkcall('aoa_bulk_queue_tx',vm.b,0,1)==-1 and vm.memory()==before
    assert vm.bulkcall('aoa_bulk_read_rx',vm.b,0,10)==-1
    assert vm.bulkcall('aoa_bulk_read_rx',vm.b,vm.output,0)==-1
    assert vm.bulkcall('aoa_bulk_stop',vm.b,2)==-1
    record('invalid_TX_RX_output_and_stop_arguments',vm)
    vm=BulkVM(ready=False);assert vm.bulkcall('aoa_bulk_init',vm.b,vm.child)==-6
    assert vm.memory()==b'\xee'*vm.bulk_bytes
    record('unconfigured_parent_rejected_without_output_change',vm)
    vm=BulkVM();vm.uc.mem_write(vm.child+24,struct.pack('<I',1))
    assert vm.bulkcall('aoa_bulk_init',vm.b,vm.child)==-6
    vm.uc.mem_write(vm.child+24,struct.pack('<I',0))
    record('borrowed_config_parent_rejected',vm)
    vm=BulkVM();_,rx=vm.rx(size=512);before=vm.memory()
    assert vm.take()==(-31,b'') and vm.memory()==before
    assert vm.complete_bulk(rx,actual=512,data=payload[:512])==0
    assert vm.take(2)==(2,payload[:2])
    assert vm.take()==(510,payload[2:512])
    record('consumer_copies_across_small_reads_while_RX_reuse_blocked',vm)
    bm=json.loads((ROOT/MANIFEST).read_text());deps=set(bm['source_sha256'])|{MANIFEST,bm['flat'],bm['elf'],
      'scripts/emulate_native_aoa.py','scripts/emulate_native_aoa_config.py',str(Path(__file__).relative_to(ROOT))}
    for name in ('staging/native-aoa-host/manifest.json','staging/native-aoa-config/manifest.json'):
        m=json.loads((ROOT/name).read_text());deps.update(m['source_sha256']);deps.update((name,m['flat'],m['elf']))
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'cases':cases,'case_count':len(cases),
      'code_bytes':bm['flat_bytes'],'context_bytes':vm.bulk_bytes,'RX_TX_buffer_bytes_each':4096,
      'source_sha256':{name:sha(name) for name in sorted(deps)},
      'compiled_ARMv6_code_executed':True,'simultaneous_RX_TX_borrows_verified_offline':True,
      'copied_TX_partial_progress_and_RX_backpressure_verified_offline':True,
      'terminal_completion_controller_writes_and_events_are_fixtures':True,
      'old_handshake_and_config_artifacts_unchanged':True,
      'real_controller_USB_cache_ZLP_framing_TLS_phone_or_AA_verified':False,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'New freestanding bulk context executes on ARM1176 alongside preserved handshake/config binaries. '
        'Independent synthetic byte vectors and terminal events validate full duplex, owned data, partial '
        'OUT, short/zero IN, RX backpressure, error/cancel/disconnect/timeouts and borrow release. '
        'HAL writes input buffers in the fixture, not real USB/DMA. Page bounds/canaries/code protected, '
        'no measured performance/physical host/current phone/cache/ZLP/framing/TLS/UI/audio/install proof. '
        'Single actor, one child, fresh/quiescent lifetime and same-port binding remain caller contracts.'}
    name='evidence/firmware-analysis/native-aoa-bulk-emulation.json';(ROOT/name).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':name,'cases':len(cases),'code_bytes':bm['flat_bytes'],
      'context_bytes':vm.bulk_bytes,'dependencies':len(deps),'device_io':False}))
if __name__=='__main__':main()
