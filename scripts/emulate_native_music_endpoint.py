#!/usr/bin/env python3
"""Custom ARM endpoint creation plus stock SDP/AVDTP consumers, offline only.

SEP/descriptor contents are produced by compiled provider after original boot
initialization. Kernel mutexes, PSM registration and signaling connection remain
fixtures. There is no installed loader, live radio or recovered stock SEP API.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_avdtp_control import ControlVM,STATE,DESCRIPTORS,CHANNELS,CONTEXT,REGS,CONFIG,RETURN,CALLBACK,STACK,INPUT
from emulate_avdtp_lifecycle import LifecycleVM,PEER,MEDIA_LCID
from emulate_native_music_gate import SAVED_REGS,signed

CONTROL=0x3a7c108;RECORD=CONTROL+7*12
HEAP=0x09004000;OUTPUT=0x09005000
AVDTP_MUTEX=0xf50098;DB_MUTEX=0xf50088
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class EndpointVM(LifecycleVM):
    def __init__(self,stock,build):
        super().__init__(stock)
        self.base=build['base'];self.symbols=build['symbols']
        self.endpoint_code=(ROOT/build['flat']).read_bytes()
        self.uc.mem_map(self.base,(len(self.endpoint_code)+4095)&~4095)
        self.uc.mem_write(self.base,self.endpoint_code)
        self.uc.mem_protect(self.base,(len(self.endpoint_code)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.bss=self.symbols['__bss_start'];self.bss_bytes=build['BSS_bytes']
        self.uc.mem_map(self.bss,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(self.bss,b'\xa5'*4096);self.uc.mem_write(self.bss,bytes(self.bss_bytes))
        # Initial zero-filled core BSS; no registered-SEP starting fixture.
        self.uc.mem_write(CONTEXT,bytes(DESCRIPTORS+36-CONTEXT))
        self.uc.mem_map(0x3a7c000,4096)
        self.uc.mem_write(0x3a7c000,b'\xa5'*4096)
        self.uc.mem_write(CONTROL,bytes(14*12))
        # Readonly exact startup-mapped data, except two original SDP fields.
        self.data_images={}
        for page in range(0xf00000,0xf73000,4096):
            if page==0xf50000:continue
            try:raw=stock.read(stock.runtime_to_load(page,4096),4096)
            except ValueError:break
            self.uc.mem_map(page,4096);self.uc.mem_write(page,raw)
            if page==0xf42000:
                self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            else:self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ)
            self.data_images[page]=raw
        for page in [HEAP,OUTPUT]:
            self.uc.mem_map(page,4096);self.uc.mem_write(page,b'\xa5'*4096)
        self.locks_initialized={DB_MUTEX}  # Existing DB kernel object fixture.
        self.lock_error={};self.unlock_error={}
        self.psm_register_error=0;self.psm_events=[];self.lock_events=[]
        self.allocations=[];self.allocation_fail_remaining=0;self.frees=[];self.boot_steps=[];self.calls=[]
        self.entry_calls=[];self.active_input=None
        self.serializer_ABI=[]

    def observe_state_write(self,uc,access,address,size,value,unused):
        if address<STATE+96 and address+size>STATE:
            for i in range(3):
                if address<STATE+i*32+0x14 and address+size>STATE+i*32+0x12:
                    pc=uc.reg_read(UC_ARM_REG_PC)
                    assert 0x50000<=pc<0xcb179c or self.base<=pc<self.base+len(self.endpoint_code)
                    self.sep_state_writes.append({'instruction':hex(pc),'address':hex(address),
                        'bytes':size,'value':value,'writer':'compiled_provider' if pc>=self.base else 'original_firmware'})

    def hook(self,uc,address,size,unused):
        r=[uc.reg_read(reg) for reg in REGS];sp=uc.reg_read(UC_ARM_REG_SP)
        if address in [0x607f9c,0x5747b4,0x5748e4,0x574acc,0x5756ac,0x5d8ed8,0x5a6928]:
            self.entry_calls.append(hex(address))
        if address==0x5a6928:
            self.serializer_ABI.append(r+[self.word(sp),self.word(sp+4)])
        if address==0x55238e:
            assert r[0]==AVDTP_MUTEX and r[1]==0
            self.locks_initialized.add(r[0]);self.ret()
        elif address==0x5523de:
            assert r[0] in self.locks_initialized and not self.mutex_held,(hex(r[0]),self.mutex_held)
            error=self.lock_error.get(r[0],0)
            self.lock_events.append({'operation':'lock','object':hex(r[0]),'result':error})
            if error>=0:self.mutex_held=True;self.events.append('lock')
            self.ret(error&0xffffffff)
        elif address==0x5523fc:
            assert self.mutex_held and r[0] in self.locks_initialized
            error=self.unlock_error.get(r[0],0)
            self.lock_events.append({'operation':'unlock','object':hex(r[0]),'result':error})
            if error>=0:self.mutex_held=False;self.events.append('unlock')
            self.ret(error&0xffffffff)
        elif address==0x50c138:
            assert r[0]==25 and STACK<=r[1] and r[1]+0x34<=STACK+0xf000
            uc.mem_write(r[1],bytes(0x34));uc.mem_write(r[1],struct.pack('<I',25))
            self.psm_events.append({'operation':'default_PSM_configuration','PSM':25});self.ret()
        elif address==0x50c150:
            assert STACK<=r[0] and r[0]+0x34<=STACK+0xf000
            words=struct.unpack('<13I',uc.mem_read(r[0],0x34))
            assert words[:5]==(25,0x50b989,0x50b5c5,0x50b3dd,0x50b1f9)
            self.psm_events.append({'operation':'register_PSM_fixture','words':list(words),'return':self.psm_register_error})
            self.ret(self.psm_register_error)
        elif address==0x5524da:
            assert 0<r[0]<=32
            self.uc.mem_write(HEAP,b'\xa5'*4096)
            self.allocations.append(r[0])
            if self.allocation_fail_remaining:
                self.allocation_fail_remaining-=1;self.ret(0)
            else:self.ret(HEAP+4096-32)
        elif address==0x5524ee:
            assert r[0]==HEAP+4096-32;self.frees.append(r[0]);self.ret()
        elif address==0x5524f6:
            dest,src,n=r[:3]
            assert n<=64
            assert any(STATE+i*32+0x14<=dest and dest+n<=STATE+i*32+0x18 for i in range(3)) or \
                HEAP<=dest and dest+n<=HEAP+4096 or OUTPUT<=dest and dest+n<=OUTPUT+4096
            uc.mem_write(dest,bytes(uc.mem_read(src,n)));self.ret(dest)
        elif address==0x5a7794:
            channel,n,p=r[:3]
            assert 6<=n<=32 and ((STACK<=p and p+n<=STACK+0xf000) or
                (p==HEAP+4096-32 and n<=self.allocations[-1]))
            self.replies.append({'channel':channel,'wire_hex':bytes(uc.mem_read(p+4,n-4)).hex(),
                'state_before_send':self.byte(STATE+0x12),'pending_before_send':self.byte(STATE+0x13)})
            self.events.append('send');self.ret(self.send_error)
        else:super().hook(uc,address,size,unused)
        self.executed.add(address)

    def pools(self):
        return bytes(self.uc.mem_read(CONTEXT,DESCRIPTORS+36-CONTEXT))

    def publication(self):return self.word(self.symbols['music_endpoint_publication'])

    def guards(self):
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        assert bytes(self.uc.mem_read(self.base,len(self.endpoint_code)))==self.endpoint_code
        assert bytes(self.uc.mem_read(0xf50000,4096))==self.global_data
        for page,raw in self.data_images.items():
            actual=bytes(self.uc.mem_read(page,4096))
            if page==0xf42000:assert actual[:0xe3c]==raw[:0xe3c] and actual[0xe40:]==raw[0xe40:]
            else:assert actual==raw
        assert bytes(self.uc.mem_read(self.bss+self.bss_bytes,4096-self.bss_bytes))==b'\xa5'*(4096-self.bss_bytes)
        assert bytes(self.uc.mem_read(0x3a88000,CONTEXT-0x3a88000))==b'\xa5'*(CONTEXT-0x3a88000)
        end=DESCRIPTORS+36
        assert bytes(self.uc.mem_read(end,0x3a8a000-end))==b'\xa5'*(0x3a8a000-end)
        assert bytes(self.uc.mem_read(0x3a7c000,CONTROL-0x3a7c000))==b'\xa5'*(CONTROL-0x3a7c000)
        end=CONTROL+14*12
        assert bytes(self.uc.mem_read(end,0x3a7d000-end))==b'\xa5'*(0x3a7d000-end)
        if self.allocations:
            size=self.allocations[-1]
            assert bytes(self.uc.mem_read(HEAP,4096-32))==b'\xa5'*(4096-32)
            assert bytes(self.uc.mem_read(HEAP+4096-32+size,32-size))==b'\xa5'*(32-size)

    def invoke(self,name,entry,args=(),*,thumb=False,payload=None,pointer_arg=None,held=False,ending_held=None):
        self.mutex_held=held
        self.replies=[];self.callbacks=[];self.events=[];self.executed=set();self.entry_calls=[];self.serializer_ABI=[]
        self.transport_events=[];self.sep_state_writes=[];self.lock_events=[]
        args=list(args)
        if payload is not None:
            assert 0<len(payload)<=4096
            self.input_start=INPUT+4096-len(payload)
            self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            self.uc.mem_write(self.input_start,payload)
            self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ)
            args[pointer_arg]=self.input_start
        sp=STACK+0xf000;self.uc.mem_write(sp,struct.pack('<I',args[4] if len(args)>4 else 0))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        saved=[0x11220000+i*0x111 for i in range(8)]
        for reg,value in zip(SAVED_REGS,saved):self.uc.reg_write(reg,value)
        for reg,value in zip(REGS,args+[0]*4):self.uc.reg_write(reg,value)
        before=self.pools();before_sdp=bytes(self.uc.mem_read(CONTROL,14*12))
        self.uc.emu_start(entry|int(thumb),RETURN+2,timeout=2000000,count=100000)
        assert self.uc.reg_read(UC_ARM_REG_PC)==RETURN and self.uc.reg_read(UC_ARM_REG_SP)==sp
        assert self.mutex_held==(held if ending_held is None else ending_held)
        assert [self.uc.reg_read(r) for r in SAVED_REGS]==saved
        if payload is not None:assert bytes(self.uc.mem_read(self.input_start,len(payload)))==payload
        self.guards()
        r=self.snapshot(name)
        r.update(return_value=signed(self.uc.reg_read(REGS[0])),replies=list(self.replies),
            entry_calls=list(self.entry_calls),lock_operations=list(self.lock_events),
            native_serializer_six_argument_ABI=list(self.serializer_ABI),
            stock_pools_unchanged=before==self.pools(),SDP_records_unchanged=before_sdp==bytes(self.uc.mem_read(CONTROL,14*12)),
            SDP_audio_sink_active=struct.unpack('<H',self.uc.mem_read(RECORD+4,2))[0],
            publication_state=self.publication(),mutex_held_on_return=self.mutex_held,
            compiled_stock_code_initialized_data_input_BSS_heap_core_SDP_guards_SP_saved_registers_intact=True)
        self.calls.append(r);return r

    def boot(self):
        self.boot_steps.append(self.invoke('original_AVDTP_mutex_initializer',0x4ccfb4,thumb=True))
        # Boot's native store clears the global application callback.
        self.uc.mem_protect(0xf50000,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.boot_steps.append(self.invoke('original_AVDTP_boot_initializer',0x4ccc3c,thumb=True))
        self.uc.mem_protect(0xf50000,4096,unicorn.UC_PROT_READ)
        self.boot_steps.append(self.invoke('original_SDP_boot_initializer',0x5d7588,thumb=True))
        assert all(self.byte(STATE+i*32+0x12)==0 for i in range(3))
        assert self.word(RECORD)==0x90007 and self.byte(RECORD+4)==0

    def signaling_fixture(self):
        # Transport remains simulated; do not write SEP or codec descriptors.
        self.uc.mem_write(CONTEXT+0x13,b'\x00\xff\xff'+PEER)
        self.uc.mem_write(CHANNELS,struct.pack('<H',0x1234)+bytes([0,0,0,0x10,0,0]))

    def prepare(self,callback=CALLBACK|1,mtu=672,ending_held=None):
        return self.invoke('compiled_endpoint_prepare',self.symbols['music_endpoint_prepare'],
            [callback,mtu],ending_held=ending_held)

    def publish(self,seid=1,callback=CALLBACK|1,ending_held=None):
        return self.invoke('compiled_endpoint_publish',self.symbols['music_endpoint_publish'],
            [seid,callback],ending_held=ending_held)

    def discover(self):return self.invoke('original_Discover',0x5747b4,[0,1,1,0,0],thumb=True,held=True)
    def capabilities(self,seid=1,*,original=False,signal=2,transaction=1,payload=None):
        payload=bytes([seid<<2]) if payload is None else payload
        return self.invoke('original_GetCapabilities' if original else 'compiled_capability_dispatch',
            0x5748e4 if original else self.symbols['music_endpoint_capabilities'],
            [0,signal,transaction,0,len(payload)],thumb=original,payload=payload,pointer_arg=3,held=True)
    def gate(self,payload=CONFIG):return self.invoke('compiled_preaccept_gate',
        self.symbols['music_configuration_gate'],[0,3,1,0,len(payload)],
        payload=payload,pointer_arg=3,held=True)

    def signal(self,signal,payload):
        self.mutex_held=True;self.transport_events=[];self.sep_state_writes=[]
        result=ControlVM.invoke(self,signal,payload)
        result.update(self.snapshot('signal_'+str(signal)))
        self.mutex_held=False;self.guards()
        self.history.append(result);return result

    def class_attribute(self):
        self.uc.mem_write(OUTPUT,b'\xa5'*4096)
        self.uc.mem_write(OUTPUT,struct.pack('<H',1))
        self.uc.mem_write(OUTPUT+4,bytes(4))
        r=self.invoke('original_SDP_service_class_attribute',0x5d8ed8,
            [0x90007,OUTPUT,OUTPUT+4096-16,16,OUTPUT+4],thumb=True)
        n=self.word(OUTPUT+4)
        assert n<=16
        r.update(attribute_bytes=bytes(self.uc.mem_read(OUTPUT+4096-16,n)).hex(),attribute_length=n)
        assert bytes(self.uc.mem_read(OUTPUT+8,4096-24))==b'\xa5'*(4096-24)
        assert bytes(self.uc.mem_read(OUTPUT+4096-16+n,16-n))==b'\xa5'*(16-n)
        return r


def main():
    build=json.loads((ROOT/'staging/native-music-endpoint/manifest.json').read_text())
    for p,h in build['source_sha256'].items():assert sha(ROOT/p)==h,p
    assert sha(ROOT/build['flat'])==build['flat_sha256'] and sha(ROOT/build['elf'])==build['elf_sha256']
    stock=NativeImage();cases=[]
    def fresh():
        vm=EndpointVM(stock,build);vm.boot();return vm
    def check(name,vm,checks):
        assert all(checks.values()),(name,checks,vm.calls[-1])
        vm.guards();cases.append({'name':name,'passed':True,'checks':checks,
            'boot_steps':vm.boot_steps,'PSM_transport_fixtures':vm.psm_events,'calls':vm.calls,'stock_lifecycle':vm.history})

    vm=fresh();vm.signaling_fixture();before=vm.discover();hidden=vm.class_attribute()
    prepared=vm.prepare();after=vm.discover();original_caps=vm.capabilities(original=True)
    caps=vm.capabilities();published=vm.publish();visible=vm.class_attribute()
    check('original_boot_compiled_endpoint_stock_SDP_Discover_and_capabilities',vm,{
        'boot_has_no_registered_SEP':before['replies'][0]['wire_hex']=='1201',
        'compiled_provider_creates_SEID1':prepared['return_value']==1 and any(w['writer']=='compiled_provider' and w['value']==1 for w in prepared['native_SEP_state_writes']),
        'stock_Discover_consumes_created_endpoint':after['replies'][0]['wire_hex']=='12010408',
        'stock_capabilities_read_module_static_SBC':caps['replies'][0]['wire_hex']=='12020100070600003fff0235',
        'fixed_stock_HeaderCompression_offer_removed_only_for_owned_endpoint':original_caps['replies'][0]['wire_hex']==
            '120201000603800000070600003fff0235' and '0x5a6928' in caps['entry_calls'] and '0x5748e4' not in caps['entry_calls'],
        'original_SDP_enable_only_at_publication':prepared['SDP_records_unchanged'] and published['SDP_audio_sink_active']==1 and
            published['return_value']==0 and published['publication_state']==1 and '0x607f9c' in published['entry_calls'],
        'inactive_SDP_query_fails_before_publication':hidden['return_value']!=0 and hidden['attribute_length']==0,
        'original_SDP_query_returns_AudioSink_class':visible['return_value']==0 and visible['attribute_bytes']=='350319110b',
        'provider_publication_does_not_nest_mutexes':[e['object'] for e in published['lock_operations']]==
            [hex(AVDTP_MUTEX),hex(AVDTP_MUTEX),hex(DB_MUTEX),hex(DB_MUTEX)]})

    vm=fresh();vm.signaling_fixture();vm.prepare();vm.publish();accepted=vm.gate()
    opened=vm.signal(6,b'\x04');vm.incoming();vm.config_request();ready=vm.config_confirm()
    start=vm.signal(7,b'\x04');media=vm.media(b'provider-chain-no-decoder-fixture')
    reset=vm.native('disconnect_notification',0x50be1c,[MEDIA_LCID]);again=vm.gate()
    check('compiled_registration_gate_original_media_lifecycle_and_reconfiguration',vm,{
        'created_endpoint_accepted':accepted['state']==2 and accepted['replies'][0]['wire_hex']=='1203',
        'actual_original_ready_and_stream':opened['pending']==2 and ready['original_ready_helper_executed'] and
            ready['state']==4 and start['state']==8 and media['callbacks'][0]['status']==0,
        'reset_keeps_registration_callback_and_gate':reset['original_reset_executed'] and reset['state']==1 and
            again['state']==2 and again['replies'][0]['wire_hex']=='1203',
        'registered_local_MTU_preserved':struct.unpack('<H',vm.uc.mem_read(STATE+12,2))[0]==672})
    vm=fresh();vm.signaling_fixture();vm.prepare();r=vm.gate(bytes.fromhex('040801000706000221150235'))
    check('compiled_registration_already_claims_preaccept_gate',vm,{
        'reject_before_original_config':['0x5756ac']==r['entry_calls'] and r['replies'][0]['wire_hex']=='13030729',
        'no_stock_state_or_callback':r['stock_pools_unchanged'] and not r['callbacks'] and r['state']==1})
    vm=fresh();vm.prepare();r=vm.prepare();check('duplicate_callback_owner_not_allocated_twice',vm,{
        'duplicate_error':r['return_value']==-39 and r['stock_pools_unchanged']})
    vm=fresh();vm.signaling_fixture();a=vm.prepare();b=vm.prepare(CALLBACK+0x21);c=vm.prepare(CALLBACK+0x41)
    full=vm.prepare(CALLBACK+0x61);d=vm.discover()
    check('three_compiled_endpoints_and_full_pool',vm,{
        'three_distinct_SEIDs':[a['return_value'],b['return_value'],c['return_value']]==[1,2,3],
        'no_fourth_slot':full['return_value']==-32 and full['stock_pools_unchanged'],
        'stock_Discover_three_audio_sinks':d['replies'][0]['wire_hex']=='1201040808080c08'})
    vm=fresh();vm.uc.mem_write(STATE,struct.pack('<I',CALLBACK+0x101));vm.uc.mem_write(STATE+0x12,b'\x01')
    foreign=bytes(vm.uc.mem_read(STATE,32));r=vm.prepare()
    check('foreign_active_endpoint_preserved_choose_next_slot',vm,{
        'choose_SEID2':r['return_value']==2,'foreign_bytes_unchanged':bytes(vm.uc.mem_read(STATE,32))==foreign})
    vm=fresh();vm.uc.mem_write(DESCRIPTORS,struct.pack('<I',0x12345678));r=vm.prepare()
    check('foreign_descriptor_pointer_not_overwritten',vm,{
        'choose_SEID2':r['return_value']==2,'foreign_pointer_preserved':vm.word(DESCRIPTORS)==0x12345678})
    for name,cb,mtu in [('null_callback',0,672),('MTU47',CALLBACK|1,47),('MTU4097',CALLBACK|1,4097)]:
        vm=fresh();r=vm.prepare(cb,mtu);check('invalid_'+name,vm,{
            'reject_before_lock_or_state':r['return_value']==-30 and r['stock_pools_unchanged'] and not r['lock_operations']})
    for mtu in [48,4096]:
        vm=fresh();r=vm.prepare(mtu=mtu);check('local_receive_MTU_'+str(mtu),vm,{
            'explicit_MTU_stored':r['return_value']==1 and struct.unpack('<H',vm.uc.mem_read(STATE+12,2))[0]==mtu})
    vm=fresh();vm.lock_error[AVDTP_MUTEX]=-1;r=vm.prepare()
    check('prepare_lock_failure_no_registration',vm,{'fails_without_writes':r['return_value']==-31 and r['stock_pools_unchanged']})
    vm=fresh();vm.uc.mem_write(vm.symbols['music_gate_bindings'],struct.pack('<I',0x1234));before=vm.pools();r=vm.prepare()
    check('gate_claim_failure_restores_complete_prior_endpoint_and_descriptor',vm,{
        'rollback_on_claim_failure':r['return_value']==-33 and vm.pools()==before,
        'foreign_gate_claim_retained':vm.word(vm.symbols['music_gate_bindings'])==0x1234,
        'no_provider_owner_added':vm.word(vm.symbols['music_endpoint_owners'])==0})
    vm=fresh();r=vm.publish();check('publication_without_preparation_rejected',vm,{
        'no_SDP_change':r['return_value']==-34 and r['SDP_records_unchanged']})
    vm=fresh();vm.prepare();vm.uc.mem_write(RECORD+4,b'\x01\x00');r=vm.publish()
    check('foreign_active_AudioSink_SDP_not_adopted',vm,{'foreign_record_not_reenabled':r['return_value']==-35 and r['SDP_records_unchanged']})
    vm=fresh();vm.prepare();vm.publish();r=vm.publish()
    check('duplicate_publication_rejected',vm,{'not_republished':r['return_value']==-36 and r['SDP_records_unchanged']})
    vm=fresh();vm.prepare();vm.lock_error[DB_MUTEX]=-1;r=vm.publish()
    vm.lock_error.clear();retry=vm.publish()
    check('SDP_lock_failure_keeps_prepared_endpoint_then_retry_publishes',vm,{
        'native_DB_error_preserved':r['return_value']==0x2503 and r['SDP_audio_sink_active']==0 and r['publication_state']==0,
        'retry_after_lock_failure':retry['return_value']==0 and retry['publication_state']==1})
    vm=fresh();vm.prepare();vm.unlock_error[DB_MUTEX]=-1;r=vm.publish(ending_held=True)
    check('SDP_unlock_failure_records_uncertain_publication_no_rollback',vm,{
        'native_unlock_error':r['return_value']==0x2504,
        'record_was_enabled':r['SDP_audio_sink_active']==1,
        'uncertainty_retained':r['publication_state']==2 and r['mutex_held_on_return']})
    vm=fresh();vm.unlock_error[AVDTP_MUTEX]=-1;r=vm.prepare(ending_held=True)
    check('prepare_unlock_failure_keeps_endpoint_and_owner_pinned',vm,{
        'unlock_error_not_rollback':r['return_value']==-38 and r['state']==1 and r['mutex_held_on_return'],
        'ownership_retained':vm.word(vm.symbols['music_endpoint_owners'])==CALLBACK|1 and
            vm.word(vm.symbols['music_gate_bindings'])==CALLBACK|1})
    vm=fresh();vm.signaling_fixture();vm.prepare();vm.prepare(CALLBACK+0x21);vm.prepare(CALLBACK+0x41)
    r=vm.capabilities(3,transaction=15)
    check('third_owned_endpoint_transaction15_and_six_argument_serializer_ABI',vm,{
        'SBC_without_HeaderCompression':r['replies'][0]['wire_hex']=='f2020100070600003fff0235',
        'native_serializer_exact_ABI':r['native_serializer_six_argument_ABI']==[[15,2,0x11,0,2,0]]})
    vm=fresh();vm.signaling_fixture();vm.prepare();vm.gate();r=vm.capabilities(signal=4)
    check('owned_GetConfiguration_delegates_selected_codec_to_stock',vm,{
        'stock_handler_and_selected_bytes':'0x5748e4' in r['entry_calls'] and
            r['replies'][0]['wire_hex']=='120401000706000021150235'})
    vm=fresh();vm.signaling_fixture()
    vm.uc.mem_write(STATE+32,struct.pack('<I',CALLBACK+0x101));vm.uc.mem_write(STATE+32+0x12,b'\x01')
    vm.uc.mem_write(DESCRIPTORS+12,struct.pack('<I',vm.symbols['music_endpoint_sbc_caps'])+bytes([4,0,0,0,1,0,0,0]))
    original=vm.capabilities(2,original=True);r=vm.capabilities(2)
    check('normal_unowned_GetCapabilities_keeps_original_policy_and_wire',vm,{
        'unchanged_original_offer':r['replies']==original['replies'] and '0x5748e4' in r['entry_calls'],
        'no_stock_pool_change':r['stock_pools_unchanged']})
    for name,offset,value in [('callback',STATE,struct.pack('<I',CALLBACK+0x101)),
        ('descriptor',DESCRIPTORS,bytes(4))]:
        vm=fresh();vm.signaling_fixture();vm.prepare();vm.uc.mem_write(offset,value);r=vm.capabilities()
        check('stale_owned_capability_'+name+'_fails_closed',vm,{
            'no_foreign_serialization_or_reply':r['return_value']==-40 and not r['replies'] and not r['entry_calls'] and r['stock_pools_unchanged']})
    for name,payload,wire in [('length2',bytes([4,0]),'130211'),('reserved_bits',bytes([5]),'130201')]:
        vm=fresh();vm.signaling_fixture();vm.prepare();r=vm.capabilities(payload=payload)
        check('owned_capability_'+name+'_native_reject',vm,{
            'wire_and_no_pool_change':r['replies'][0]['wire_hex']==wire and r['stock_pools_unchanged'] and
                r['entry_calls']==['0x5756ac']})
    vm=fresh();vm.signaling_fixture();vm.prepare();vm.uc.mem_write(STATE+0x12,b'\x00');r=vm.capabilities()
    check('owned_capability_inactive_state_rejected',vm,{
        'inactive_native_reject':r['replies'][0]['wire_hex']=='130212' and r['stock_pools_unchanged']})
    vm=fresh();vm.signaling_fixture();vm.prepare();vm.allocation_fail_remaining=1;r=vm.capabilities()
    check('owned_capability_allocator_failure_native_reject',vm,{
        'original_serializer_error_converted_to_reject':r['replies'][0]['wire_hex']=='130231' and
            r['entry_calls']==['0x5a6928','0x5756ac'] and not vm.frees and r['stock_pools_unchanged']})

    deps=[Path(__file__),ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/emulate_avdtp_lifecycle.py',
        ROOT/'scripts/emulate_native_music_gate.py',ROOT/'scripts/analyze_native_sections.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'staging/native-music-endpoint/manifest.json',
        ROOT/build['flat'],ROOT/build['elf'],ROOT/'evidence/firmware-analysis/sdp-service-templates.json']
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},'build_source_sha256':build['source_sha256'],
        'compiled_code_bytes':build['flat_bytes'],'BSS_bytes':build['BSS_bytes'],'cpu_model':'ARM1176',
        'case_count':len(cases),'cases':cases,'all_passed':True,
        'SEP_descriptors_created_by_compiled_provider_not_registered_SEP_starting_fixture':True,
        'original_boot_SDP_enable_attribute_query_AVDTP_Discover_caps_and_lifecycle_executed':True,
        'owned_capability_dispatch_removes_fixed_stock_HeaderCompression_offer':True,
        'stock_serializer_six_argument_ABI_checked':True,
        'original_endpoint_registration_API_recovered':False,'dispatcher_installed_or_real_radio_endpoint_verified':False,
        'actual_kernel_mutex_PSM_registration_or_signaling_connection_verified':False,
        'App_menu_loader_module_unload_decoder_DAC_phone_speaker_verified':False,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'limitations':'Custom exact-image private-ABI provider, not a recovered stock SEP registration API. Fresh boot BSS is supplied then original AVDTP/SDP init executes. Kernel mutex objects/PSM registration/signaling transport and L2CAP callbacks remain simulated. Compiled creation precedes original consumers. Caller chooses preaccept entry, no dispatcher/loader installed. Single actor, exclusive Audio Sink record ownership and code/callback/capability pinning until reboot required. No unregister/unload or actual scheduling proof. Error uncertainty retains endpoint or SDP activity, never interpreted as rollback or safe unloading. No decoder/output/App/UI/phone or new device proof.'}
    target=ROOT/'evidence/firmware-analysis/native-music-endpoint-emulation.json'
    target.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'cases':len(cases),'code_bytes':build['flat_bytes'],'device_io':False}))


if __name__=='__main__':main()
