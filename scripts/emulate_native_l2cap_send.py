#!/usr/bin/env python3
"""Execute stock signaling replies through L2CAP allocation and TX queue.

Valid dynamic LCIDs and the L2CAP kernel/credit fixtures are explicit. Native
send, record allocator, queue linking and scheduler wrapper execute. The OS
event submission is intercepted; no radio, device I/O or delivery is proved.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_R5
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_avdtp_control import CHANNELS,REGS,STACK,STATE,CONTEXT
from emulate_native_music_dispatch import DispatchVM

L2_MUTEX=0xf69594
ENTITY=0x3a96f7c
TX=0x3a974ec
HEAD,TAIL,FREE,SCHEDULED=0xf6957f,0xf69580,0xf69582,0xf6957e
LCID=0x40
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class SendVM(DispatchVM):
    def __init__(self,stock,build,variant='table_and_bounds'):
        super().__init__(stock,build,variant)
        self.l2_held=False;self.l2_lock_error=0;self.l2_unlock_error=0
        self.l2_locks=[];self.native_sends=[];self.os_events=[]
        self.uc.mem_map(0x3a96000,0x2000)
        self.uc.mem_write(0x3a96000,b'\xa5'*0x2000)
        self.uc.mem_write(ENTITY,bytes(88*10))
        self.uc.mem_write(ENTITY+6,struct.pack('<H',LCID))
        self.uc.mem_write(ENTITY+0x14,struct.pack('<H',672))
        self.uc.mem_write(ENTITY+0x1e,b'\x05')
        self.uc.mem_write(ENTITY+0x25,b'\xff')
        self.entities_expected=bytes(self.uc.mem_read(ENTITY,880))
        self.uc.mem_write(TX,bytes(52*50))
        for i in range(50):self.uc.mem_write(TX+i*52+0x2f,b'\xff')
        self.uc.mem_protect(0xf69000,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        for a,b in [(0xf6957c,b'\0'),(SCHEDULED,b'\0'),(HEAD,b'\xff'),(TAIL,b'\xff'),
                    (FREE,struct.pack('<H',50)),(0xf69584,struct.pack('<H',4)),
                    (0xf69586,struct.pack('<H',8)),(0xf69598,bytes(4)),
                    (0xf695b0,struct.pack('<H',1))]:self.uc.mem_write(a,b)
        self.l2_data_expected=bytes(self.uc.mem_read(0xf69000,4096))
        self.uc.mem_write(CHANNELS,struct.pack('<H',LCID))

    def hook(self,uc,address,size,unused):
        r=[uc.reg_read(reg) for reg in REGS]
        if address in [0x5a78d6,0x5a77e6,0x5a7886,0x5a78cc]:
            item=self.native_sends[-1]
            item['native_written_payload_bytes']=struct.unpack('<H',uc.mem_read(item['output_pointer'],2))[0]
            item['native_return_before_epilogue']=uc.reg_read(UC_ARM_REG_R5) if address==0x5a78d6 else None
        if address in [0x5523de,0x5523fc] and r[0]==L2_MUTEX:
            operation='lock' if address==0x5523de else 'unlock'
            assert self.l2_held==(operation=='unlock')
            error=self.l2_lock_error if operation=='lock' else self.l2_unlock_error
            self.l2_locks.append({'operation':operation,'error':error,
                'AVDTP_mutex_already_held':self.mutex_held})
            if error>=0:self.l2_held=operation=='lock'
            self.executed.add(address);self.ret(error&0xffffffff);return
        if address==0x5a7794:
            channel,n,p,written=r
            assert 6<=n<=32 and STACK<=written and written+2<=STACK+0xf000
            wire=bytes(uc.mem_read(p+4,n-4)).hex()
            item={'channel':channel,'buffer_bytes_with_reserved_prefix':n,
                'wire_hex':wire,'output_pointer':written,'state_before_send':self.byte(STATE+0x12),
                'pending_before_send':self.byte(STATE+0x13)}
            self.native_sends.append(item);self.replies.append(dict(item))
            self.events.append('send');self.executed.add(address);return # Execute original body.
        if address==0x5524f6 and TX<=r[0] and r[0]+r[2]<=TX+52*50:
            assert self.l2_held and 0<r[2]<=32 and (r[0]-TX)%52==0
            uc.mem_write(r[0],bytes(uc.mem_read(r[1],r[2])))
            self.executed.add(address);self.ret(r[0]);return
        if address==0x60faec:
            assert self.l2_held and r==[0,0x60bb2d,0,0]
            self.os_events.append({'args':r,'queue_before_submission':self.queue(),
                'operation':'OS_event_submission_fixture','return':0})
            self.executed.add(address);self.ret();return
        super().hook(uc,address,size,unused)

    def queue(self):
        rows=[];index=self.byte(HEAD)
        while index!=255:
            assert 0<=index<50 and index not in [r['index'] for r in rows]
            base=TX+52*index;p=self.word(base+0x20)
            n=struct.unpack('<H',self.uc.mem_read(base+0x24,2))[0]
            reserved=struct.unpack('<H',self.uc.mem_read(base+0x26,2))[0]
            assert 4<=n<=32 and reserved==4 and p==base
            rows.append({'index':index,'channel_index':struct.unpack('<H',self.uc.mem_read(base+0x28,2))[0],
                'type':self.byte(base+0x2f),'next':self.byte(base+0x30),
                'buffer_bytes':n,'reserved_prefix_bytes':reserved,
                'wire_hex':bytes(self.uc.mem_read(p+reserved,n-reserved)).hex(),
                'copied_into_native_record':True})
            index=rows[-1]['next']
        return rows

    def guards(self):
        # During parent construction no L2CAP fixture exists yet.
        if not hasattr(self,'l2_data_expected'):return super().guards()
        raw=self.data_images.pop(0xf69000)
        try:super().guards()
        finally:self.data_images[0xf69000]=raw
        current=bytes(self.uc.mem_read(0xf69000,4096))
        mutable={a-0xf69000 for a in [0xf6957c,SCHEDULED,HEAD,TAIL,FREE,FREE+1]}
        assert all(a==b or i in mutable for i,(a,b) in enumerate(zip(current,self.l2_data_expected)))
        assert bytes(self.uc.mem_read(ENTITY,880))==self.entities_expected
        for a,b in [(0x3a96000,ENTITY),(ENTITY+880,TX),(TX+52*50,0x3a98000)]:
            assert bytes(self.uc.mem_read(a,b-a))==b'\xa5'*(b-a)

    def wire(self,payload):
        self.dispatch_entries=[];self.native_sends=[];self.l2_locks=[];self.os_events=[]
        assert not self.l2_held
        result=self.invoke('native_received_wire_to_actual_L2CAP_queue',0x50bbb8,
            [LCID,0,len(payload)],thumb=True,payload=payload,pointer_arg=1)
        assert not self.l2_held
        result.update(wire_input=payload.hex(),TX_queue=self.queue(),L2CAP_locks=list(self.l2_locks),
            OS_event_submissions=list(self.os_events),native_sends=list(self.native_sends),
            actual_native_L2CAP_send_executed=0x5a7890 in self.executed,
            actual_native_allocator_executed=0x644758 in self.executed,
            actual_native_queue_link_executed=0x6447c0 in self.executed,
            actual_native_scheduler_wrapper_executed=0x60d6f0 in self.executed,
            native_compiled_dispatch_entries=list(self.dispatch_entries))
        return result


def main():
    stock=NativeImage();build=json.loads((ROOT/'staging/native-music-endpoint/manifest.json').read_text())
    cases=[]
    def fresh(variant='table_and_bounds'):return SendVM(stock,build,variant)
    def check(name,vm,result,checks):
        assert all(checks.values()),(name,checks,result)
        vm.guards();cases.append({'name':name,'passed':True,'checks':checks,'result':result})
    for signal in [0,11,12,13,63]:
        vm=fresh();r=vm.wire(bytes([0x10,signal]));q=r['TX_queue']
        check('unknown_'+str(signal)+'_unchanged_in_actual_native_queue',vm,r,{
            'native_send_allocator_link_and_scheduler_execute':all(r[k] for k in
                ['actual_native_L2CAP_send_executed','actual_native_allocator_executed',
                 'actual_native_queue_link_executed','actual_native_scheduler_wrapper_executed']),
            'original_1000_not_corrected_by_L2CAP':q[0]['wire_hex']=='1000',
            'native_copied_payload_not_entry_only_capture':q[0]['copied_into_native_record'],
            'native_written_payload_bytes2':r['native_sends'][0]['native_written_payload_bytes']==2,
            'distinct_mutex_nested_under_AVDTP':all(x['AVDTP_mutex_already_held'] for x in r['L2CAP_locks']),
            'no_actual_radio_or_delivery_claim':True})
    vm=fresh();a=vm.wire(bytes.fromhex('100204'));b=vm.wire(bytes.fromhex('f00204'))
    check('two_replies_link_actual_native_queue_and_copy_after_stack_reuse',vm,b,{
        'both_native_copied_records_remain':[(x['index'],x['next'],x['wire_hex']) for x in b['TX_queue']]==
            [(0,1,'12020100070600003fff0235'),(1,255,'f2020100070600003fff0235')],
        'scheduler_event_once_while_marked_pending':len(a['OS_event_submissions'])==1 and not b['OS_event_submissions'],
        'original_free_count48':struct.unpack('<H',vm.uc.mem_read(FREE,2))[0]==48})
    for name,variant,payload,expected in [
        ('stock_capabilities','stock','100204','120201000603800000070600003fff0235'),
        ('owned_capabilities','table_and_bounds','100204','12020100070600003fff0235'),
        ('bad_codec_preaccept_reject','table_and_bounds','1003040801000706000221150235','13030729'),
        ('valid_config_accept','table_and_bounds','1003040801000706000021150235','1203')]:
        vm=fresh(variant);r=vm.wire(bytes.fromhex(payload))
        check(name+'_actual_native_queue',vm,r,{'native_queued_payload_matches_expected':r['TX_queue'][0]['wire_hex']==expected,
            'copied_into_record':r['TX_queue'][0]['copied_into_native_record'],
            'native_send_return_bytes':r['native_sends'][0]['native_written_payload_bytes']==len(bytes.fromhex(expected))})
    deps=[Path(__file__),ROOT/'scripts/emulate_native_music_dispatch.py',ROOT/'scripts/emulate_native_music_endpoint.py',
        ROOT/'scripts/emulate_avdtp_lifecycle.py',ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/analyze_native_sections.py']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'case_count':len(cases),'all_passed':True,'cases':cases,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'build_source_sha256':build['source_sha256'],'component_manifest_sha256':sha(ROOT/'staging/native-music-endpoint/manifest.json'),
        'device_io':False,'firmware_modified_on_device':False,'accepted_loader_verified':False,
        'actual_radio_delivery_or_phone_behavior_verified':False,
        'unknown_reply_1000_survives_native_send_allocation_copy_and_queue':True,
        'limitations':'Valid LCID40/native entity state5/MTU672/kernel locks/credits are fixtures, not live values. Original L2CAP send, allocator, copy, link and scheduler wrapper execute; memcpy and OS event submission intercepted. Replies <=32 bytes copied into native records, larger borrowed-buffer lifetime and lower ACL/L2CAP header generation not tested. Native entry output byte count and queue insertion are not radio delivery. Component address/dispatch patches remain VM-only and no device install candidate.'}
    path=ROOT/'evidence/firmware-analysis/native-l2cap-send-emulation.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),'all_passed':True}))


if __name__=='__main__':main()
