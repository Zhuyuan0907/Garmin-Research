#!/usr/bin/env python3
"""One VM: original outer loader -> compiled bootstrap -> stock wire/TX.

Only directory/storage/kernel/initialized radio inventories are fixtures.
Eight MAIN pages are expressly made writable for the guest experiment; guest
code, not host table rewiring, installs the eight checked changes. This says
nothing about device MMU/cache/pinning/package acceptance or physical playback.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_tts_vpm import sha,require
from analyze_native_loader import IMAGE,DESCRIPTOR,STUBS
from emulate_native_voice_outer import OuterVM
from emulate_native_vpm_filesystem import STACK,RETURN,REGS,DRIVE,REGION
from emulate_native_loader import simulate
from emulate_avdtp_control import STATE,CONTEXT,CHANNELS,DESCRIPTORS
from emulate_avdtp_lifecycle import PEER,MEDIA_LCID
from emulate_native_music_endpoint import CONTROL,RECORD,AVDTP_MUTEX,DB_MUTEX
from emulate_native_l2cap_send import ENTITY,TX,HEAD,TAIL,FREE,SCHEDULED,L2_MUTEX,LCID

BUILD='staging/native-music-loaded/manifest.json'
INPUT=0x09000000
HEAP=0x09004000
OUTPUT=0x09005000


def signed(v):return v if v<0x80000000 else v-0x100000000


class LoadedMusicVM(OuterVM):
    def __init__(self,stock,build):
        self.build=build;self.sym={k:v['address'] for k,v in build['symbols'].items()}
        self.radio_locks={};self.radio_lock_errors={};self.lock_events=[]
        self.psm_events=[];self.cache_events=[];self.callbacks=[];self.sends=[];self.os_events=[]
        self.dispatch_entries=[];self.transport_events=[];self.patch_writes=[];self.calls_native=[]
        self.music_boundary_sites={0x221d2c,0x55238e,0x5523de,0x5523fc,0x50c138,0x50c150,
               0x5525bc,0x5524da,0x5524ee,0x5524f6,0x5a7794,0x60faec,
               0x525f1c,0x544bc4,0x525560,0x5450a4,
               self.sym['native_music_callback'],self.sym['music_endpoint_capabilities'],
               self.sym['music_configuration_gate'],self.sym['music_reply_dispatch']}
        super().__init__(stock,[{'name':'Chinese_Big5_MeiLing.vpm',
            'data':(ROOT/build['package']).read_bytes()}],selected_voice='mei-lingb')
        for a,n in [(0x3a88000,0x2000),(0x3a7c000,4096),(0x3a96000,0x2000),
                    (INPUT,4096),(HEAP,4096),(OUTPUT,4096)]:
            self.uc.mem_map(a,n);self.uc.mem_write(a,b'\xa5'*n)
        self.uc.mem_write(CONTEXT,bytes(DESCRIPTORS+36-CONTEXT))
        self.uc.mem_write(CONTROL,bytes(14*12))
        self.uc.mem_write(ENTITY,bytes(880));self.uc.mem_write(TX,bytes(2600))
        self.uc.mem_write(ENTITY+6,struct.pack('<H',LCID))
        self.uc.mem_write(ENTITY+0x14,struct.pack('<H',672))
        self.uc.mem_write(ENTITY+0x1e,b'\x05');self.uc.mem_write(ENTITY+0x25,b'\xff')
        for i in range(50):self.uc.mem_write(TX+i*52+0x2f,b'\xff')
        for a,b in [(0xf6957c,b'\0'),(SCHEDULED,b'\0'),(HEAD,b'\xff'),(TAIL,b'\xff'),
                    (FREE,struct.pack('<H',50)),(0xf69584,struct.pack('<H',4)),
                    (0xf69586,struct.pack('<H',8)),(0xf69598,bytes(4)),(0xf695b0,struct.pack('<H',1))]:
            self.uc.mem_write(a,b)
        self.radio_locks[DB_MUTEX]=False;self.radio_locks[L2_MUTEX]=False
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_main_write)

    def byte(self,a):return self.uc.mem_read(a,1)[0]

    def observe_main_write(self,uc,access,a,n,value,_):
        if 0x50000<=a<0xcb179c:
            pc=uc.reg_read(UC_ARM_REG_PC)
            require(self.build['extension_base']<=pc<self.sym['__app_code_end'],
                    'MAIN guest write outside loaded module')
            require(any(p['address']<=a and a+n<=p['address']+p['length']
                        for p in self.build['patch_plan']),'Guest wrote undeclared MAIN site')
            self.patch_writes.append({'PC':hex(pc),'address':hex(a),'bytes':n,'value':value})

    def observe(self,uc,address,size,unused):
        # Do not read four registers on every original loader instruction.
        if address not in self.music_boundary_sites:return super().observe(uc,address,size,unused)
        self.visits[address]+=1;r=[uc.reg_read(reg) for reg in REGS];sp=uc.reg_read(UC_ARM_REG_SP)
        if address==0x221d2c:
            uc.ctl_remove_cache(IMAGE,DESCRIPTOR)
            uc.ctl_remove_cache(0x50000,0xcb179c)
            self.cache_events.append({'operation':'cache_maintenance_fixture','module_and_MAIN_VM_cache_invalidated':True})
            self.ret();return
        if address==0x55238e:
            require(r[:2]==[AVDTP_MUTEX,0],'Unexpected AVDTP mutex initializer')
            self.radio_locks[r[0]]=False;self.ret();return
        if address in [0x5523de,0x5523fc]:
            obj=r[0];acquire=address==0x5523de
            require(obj in self.radio_locks and self.radio_locks[obj]!=acquire,'Unbalanced radio mutex')
            error=self.radio_lock_errors.get(obj,0) if acquire else 0
            self.lock_events.append({'object':hex(obj),'acquire':acquire,'result':error,
                'AVDTP_already_held':self.radio_locks.get(AVDTP_MUTEX,False)})
            if error>=0:self.radio_locks[obj]=acquire
            self.ret(error);return
        if address in [0x50c138,0x50c150]:
            p=r[1] if address==0x50c138 else r[0]
            require(STACK-0x2000<=p and p+52<=STACK,'PSM configuration outside original loader stack')
            if address==0x50c138:
                require(r[0]==25,'Unexpected PSM');uc.mem_write(p,struct.pack('<I',25)+bytes(48))
            else:
                words=struct.unpack('<13I',uc.mem_read(p,52))
                require(words[:5]==(25,0x50b989,0x50b5c5,0x50b3dd,0x50b1f9),'PSM ABI changed')
                self.psm_events.append({'registration_fixture':list(words)})
            self.ret();return
        if address==0x5525bc:self.ret();return
        if address==0x5524da:
            require(0<r[0]<=32,'Unexpected Bluetooth allocation');self.ret(HEAP+4096-32);return
        if address==0x5524ee:
            require(r[0]==HEAP+4096-32,'Unexpected Bluetooth free');self.ret();return
        if address==0x5524f6:
            d,s,n=r[:3]
            require(n<=64 and (HEAP<=d and d+n<=HEAP+4096 or OUTPUT<=d and d+n<=OUTPUT+4096 or
                TX<=d and d+n<=TX+2600 or
                any(STATE+i*32+0x14<=d and d+n<=STATE+i*32+0x18 for i in range(3))),
                'Unexpected Bluetooth memcpy boundary')
            uc.mem_write(d,bytes(uc.mem_read(s,n)));self.ret(d);return
        if address==0x5a7794:
            require(6<=r[1]<=32 and STACK-0x2000<=r[3] and r[3]+2<=STACK,
                    'Unexpected native L2CAP output ABI')
            self.sends.append({'lcid':r[0],'wire_hex':bytes(uc.mem_read(r[2]+4,r[1]-4)).hex()})
            return # Native send, allocator/link and scheduler wrapper execute.
        if address==0x60faec:
            require(r==[0,0x60bb2d,0,0] and self.radio_locks[L2_MUTEX],'Unexpected OS event')
            self.os_events.append({'args':r,'submission_is_fixture':True});self.ret();return
        if address in [0x525f1c,0x544bc4,0x525560,0x5450a4]:
            self.transport_events.append({'entry':hex(address),'args':r})
            self.ret();return
        if address==self.sym['native_music_callback']:
            n=self.word(sp)
            require(not self.radio_locks[AVDTP_MUTEX] and n<=4096,'Callback lock/length changed')
            self.callbacks.append({'event':r[0],'status':r[1],'length':n,
                'payload_hex':bytes(uc.mem_read(r[3],n)).hex() if n else '',
                'executes_loaded_native_code':True})
            return # No callback return stub: execute compiled ARM callback.
        self.dispatch_entries.append({'entry':hex(address),'args':r+[self.word(sp)]})

    def invoke(self,address,args=(),*,arm=False,payload=None,pointer_arg=None):
        args=list(args)
        if payload is not None:
            require(0<len(payload)<=4096,'Input fixture length')
            self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            self.input_start=INPUT+4096-len(payload);self.uc.mem_write(self.input_start,payload)
            self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ);args[pointer_arg]=self.input_start
        self.returned=False;self.uc.mem_write(STACK,struct.pack('<I',args[4] if len(args)>4 else 0))
        self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        for reg,v in zip(REGS,args+[0]*4):self.uc.reg_write(reg,v)
        self.uc.emu_start(address|int(not arm),RETURN+2,count=200000,timeout=5000000)
        require(self.returned and self.uc.reg_read(UC_ARM_REG_SP)==STACK,'Native integration did not return')
        require(not any(self.radio_locks.values()) and not any(self.mutexes.values()),'Mutex retained')
        if payload is not None:require(bytes(self.uc.mem_read(self.input_start,len(payload)))==payload,'Input modified')
        result=signed(self.uc.reg_read(REGS[0]));self.calls_native.append({'entry':hex(address),'result':result})
        return result

    def boot(self):
        for a in [0x4ccfb4,0x4ccc3c,0x5d7588]:self.invoke(a)
        require(self.word(RECORD)==0x90007 and self.byte(RECORD+4)==0,'Original SDP did not initialize')
        require(all(self.byte(STATE+i*32+0x12)==0 for i in range(3)),'Boot preseeded a SEP')

    def signaling_fixture(self):
        self.uc.mem_write(CONTEXT+0x13,b'\x00\xff\xff'+PEER)
        self.uc.mem_write(CHANNELS,struct.pack('<H',LCID)+bytes([0,0,0,0x10,0,0]))

    def state(self):
        values=struct.unpack('<6Ii3I',self.uc.mem_read(self.sym['music_component_state'],40))
        names=['entered','patches_installed','local_seid','published','callbacks','media_dropped',
               'bootstrap_result','last_event','last_status','last_length']
        return dict(zip(names,values))

    def main_matches(self,*,patched):
        for a,raw in self.code_images:
            expect=bytearray(raw)
            if patched and a==0x50000:
                for p in self.build['patch_plan']:
                    o=p['address']-a;expect[o:o+p['length']]=bytes.fromhex(p['after'])
            require(bytes(self.uc.mem_read(a,len(raw)))==expect,'Unexpected MAIN/conditional-code change')

    def load(self,*,writable=True):
        enum=self.enumerate();self.verify_released()
        require(len(enum['registry'])==1,'New package not enumerated')
        require(self.mount(),'Original outer mount failed')
        status,h=self.open('dllimg.bin');require(status==0,'DLL open failed')
        binary=self.read_file(h);self.close(h)
        require(sha(binary)==self.build['combined_sha256'],'Original full readback failed')
        self.call(0xfea50,(DRIVE,0));self.call(0x2d32de,(REGION,));self.verify_released()
        if writable:
            for page in {p['address']&~4095 for p in self.build['patch_plan']}:
                self.uc.mem_protect(page,4096,unicorn.UC_PROT_ALL)
        self.allow_module_execution=True;ram=self.build['combined_ram_bytes']
        self.uc.mem_write(IMAGE,b'\xa5'*ram)
        self.call(0x240498,(0,0))
        require(self.init_calls==1 and self.loader_return==11,'Selector did not return original11')
        for page in {p['address']&~4095 for p in self.build['patch_plan']}:
            self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        original=(ROOT/self.build['original_binary']).read_bytes()
        original_ram=struct.unpack_from('<I',original,4)[0]
        control,report=simulate(self.stock,'original_voice',module_bytes=original,
            module_ram_bytes=original_ram,poison_module_ram=True,return_session=True)
        require(bytes(self.uc.mem_read(IMAGE+12,original_ram-12))==
                bytes(control.mem_read(IMAGE+12,original_ram-12)),'Original runtime changed after relink')
        require(bytes(self.uc.mem_read(STUBS,480))==bytes(control.mem_read(STUBS,480)),
                'Original40 trampolines changed')
        require(struct.unpack('<Iii',self.uc.mem_read(self.sym['app_component_state'],12))==(1,11,0),
                'Preserving decoder entry failed')
        for table,names in [('app_component_api',self.build['private_api']),('music_component_api',self.build['music_api'])]:
            require(list(struct.unpack('<12I',self.uc.mem_read(self.sym[table],48)))==[self.sym[n] for n in names],
                    'Relinked API table changed')
        self.main_matches(patched=bool(self.state()['patches_installed']))
        self.uc.mem_protect(self.build['extension_base'],0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.load_proof={'loader_result':11,'INIT_calls':1,'native_full_readback_bytes':len(binary),
            'native_full_readback_sha256':sha(binary),'original40_and_full_original_runtime_preserved':True,
            'private12_and_music12_linked_and_initialized':True,'original_control_result':report['status'],
            'guest_MAIN_write_bytes':sum(w['bytes'] for w in self.patch_writes),'state':self.state(),
            'module_within_original_3MiB':IMAGE+ram<=DESCRIPTOR,'main_writability_is_fixture':writable}
        return self.load_proof

    def queue(self):
        rows=[];i=self.byte(HEAD)
        while i!=255:
            require(0<=i<50 and i not in [r['index'] for r in rows],'TX chain invalid')
            b=TX+i*52;p=self.word(b+0x20);n=struct.unpack('<H',self.uc.mem_read(b+0x24,2))[0]
            require(p==b and 6<=n<=32,'TX small packet not copied')
            rows.append({'index':i,'wire_hex':bytes(self.uc.mem_read(p+4,n-4)).hex()})
            i=self.byte(b+0x30)
        return rows

    def wire(self,raw):
        before=len(self.sends);result=self.invoke(0x50bbb8,[LCID,0,len(raw)],payload=raw,pointer_arg=1)
        return {'result':result,'new_sends':self.sends[before:],'queue':self.queue(),
                'state':self.byte(STATE+0x12),'pending':self.byte(STATE+0x13)}

    def guards(self):
        self.main_matches(patched=bool(self.state()['patches_installed']))
        require(not any(self.radio_locks.values()),'Radio mutex held')
        for a,b in [(0x3a88000,CONTEXT),(DESCRIPTORS+36,0x3a8a000),
                    (0x3a7c000,CONTROL),(CONTROL+168,0x3a7d000),
                    (0x3a96000,ENTITY),(ENTITY+880,TX),(TX+2600,0x3a98000)]:
            require(bytes(self.uc.mem_read(a,b-a))==b'\xa5'*(b-a),'Radio pool guard changed')
        require(bytes(self.uc.mem_read(self.sym['__app_code_end'],
                self.sym['__app_zero_start']-self.sym['__app_code_end']))==
                b'\xa5'*(self.sym['__app_zero_start']-self.sym['__app_code_end']),
                'Extension code-to-BSS gap changed')


def main():
    build=json.loads((ROOT/BUILD).read_text())
    for p,h in build['source_sha256'].items():require(sha((ROOT/p).read_bytes())==h,'Build source changed: '+p)
    stock=NativeImage();cases=[]
    def record(name,vm,checks,extra=None):
        require(all(checks.values()),name+': '+str(checks));vm.guards()
        cases.append({'name':name,'passed':True,'checks':checks,'load':vm.load_proof,
            'calls':vm.calls_native,'callbacks':vm.callbacks,'queue':vm.queue(),
            'guest_patch_writes':vm.patch_writes,'extra':extra or {}})
        print(json.dumps({'case':name,'passed':True}),flush=True)
    vm=LoadedMusicVM(stock,build);vm.boot();load=vm.load();vm.signaling_fixture()
    caps=vm.wire(bytes.fromhex('100204'));unknown=vm.wire(bytes.fromhex('a03f'))
    bad=vm.wire(bytes.fromhex('1003040801000706000221150235'))
    accepted=vm.wire(bytes.fromhex('1003040801000706000021150235'))
    cfg=vm.wire(bytes.fromhex('100404'));opened=vm.wire(bytes.fromhex('100604'))
    vm.invoke(0x50b988,[0,MEDIA_LCID,0],payload=PEER,pointer_arg=0)
    config=bytearray(12);struct.pack_into('<H',config,8,1008)
    vm.invoke(0x50b3dc,[MEDIA_LCID,0],payload=bytes(config),pointer_arg=1)
    vm.invoke(0x50b1f8,[MEDIA_LCID,0]);ready=vm.byte(STATE+0x12)
    started=vm.wire(bytes.fromhex('100704'))
    vm.invoke(0x50bbb8,[MEDIA_LCID,0,16],payload=b'not-yet-decoded!!',pointer_arg=1)
    media=vm.state();vm.invoke(0x50be1c,[MEDIA_LCID]);again=vm.wire(bytes.fromhex('1003040801000706000021150235'))
    duplicate=vm.invoke(vm.sym['native_music_start'],arm=True)
    record('native_outer_load_bootstrap_owned_wire_lifecycle_and_TX_same_VM',vm,{
        'guest_bootstrap_installs8sites40bytes':load['guest_MAIN_write_bytes']==40 and load['state']['bootstrap_result']==0,
        'provider_callback_is_loaded_ARM_entry':vm.word(STATE)==vm.sym['native_music_callback'],
        'SDP_audio_sink_published_by_loaded_module':load['state']['published']==1 and vm.byte(RECORD+4)==1,
        'supported_caps_exclude_HeaderCompression':caps['new_sends'][0]['wire_hex']=='12020100070600003fff0235',
        'unknown_transaction_and_signal_preserved':unknown['new_sends'][0]['wire_hex']=='a13f',
        'wrong_codec_rejected_before_accept':bad['new_sends'][0]['wire_hex']=='13030729',
        'valid_config_and_GetConfiguration':accepted['new_sends'][0]['wire_hex']=='1203' and cfg['new_sends'][0]['wire_hex'].startswith('1204'),
        'real_ready_start_media_callback_executes':ready==4 and started['state']==8 and media['last_event']==0xf1,
        'native_media_explicitly_dropped_not_playback':media['media_dropped']==1,
        'disconnect_reconfigure_original_flow':again['state']==2 and again['new_sends'][0]['wire_hex']=='1203',
        'duplicate_start_retains_pinned_ownership':duplicate==-48,
        'original_allocator_queue_scheduler_executed':all(vm.visits[a]>0 for a in [0x644758,0x6447c0,0x60d6f0]),
        'no_fixture_callback_return_stub':all(c['executes_loaded_native_code'] for c in vm.callbacks)},
        {'caps':caps,'unknown':unknown,'bad':bad,'accepted':accepted,'opened':opened,'media_state':media})
    vm=LoadedMusicVM(stock,build);load=vm.load()
    record('load_without_completed_SDP_boot_preserves_voice_and_MAIN',vm,{
        'TTS11_and_original40_preserved':load['loader_result']==11,
        'music_not_started_until_ready':load['state']['bootstrap_result']==-47 and load['guest_MAIN_write_bytes']==0,
        'no_registered_SEP_or_publication':load['state']['local_seid']==0 and load['state']['published']==0})
    vm.boot()
    for page in {p['address']&~4095 for p in build['patch_plan']}:vm.uc.mem_protect(page,4096,unicorn.UC_PROT_ALL)
    recovered=vm.invoke(vm.sym['native_music_start'],arm=True)
    for page in {p['address']&~4095 for p in build['patch_plan']}:vm.uc.mem_protect(page,4096,5)
    record('same_loaded_module_start_after_native_boot_without_reload',vm,{
        'deferred_start_succeeds':recovered==0 and vm.state()['published']==1,
        'entry_still_loaded_once':vm.init_calls==1 and vm.state()['entered']==1,
        'guest_writes40bytes_only':sum(w['bytes'] for w in vm.patch_writes)==40})
    vm=LoadedMusicVM(stock,build);vm.load();vm.boot()
    last=build['patch_plan'][-1];a=last['address']+last['length']-1
    original=bytes(vm.uc.mem_read(a,1));vm.uc.mem_write(a,bytes([original[0]^1]))
    rejected=vm.invoke(vm.sym['native_music_start'],arm=True)
    require(rejected==-46 and not vm.patch_writes,'Preflight wrote before validating last site')
    vm.uc.mem_write(a,original)
    record('last_site_mismatch_preflight_makes_no_partial_MAIN_changes',vm,{
        'mismatch_rejected_before_first_write':rejected==-46 and not vm.patch_writes,
        'no_endpoint_or_publication':vm.state()['local_seid']==0 and vm.state()['published']==0,
        'loader_was_not_repeated':vm.init_calls==1})
    for name,setup,want in [
        ('occupied_SEP_slots_do_not_publish_or_overwrite', 'busy',-32),
        ('AVDTP_lock_failure_does_not_create_endpoint','lock',-31),
        ('foreign_active_AudioSink_does_not_claim_publication','active',-35)]:
        vm=LoadedMusicVM(stock,build);vm.boot()
        if setup=='busy':
            for i in range(3):vm.uc.mem_write(STATE+i*32+0x12,b'\x01')
        elif setup=='lock':vm.radio_lock_errors[AVDTP_MUTEX]=-7
        else:vm.uc.mem_write(RECORD+4,b'\x01\x00')
        load=vm.load()
        record(name,vm,{'expected_bootstrap_error':load['state']['bootstrap_result']==want,
            'original_voice_still11':load['loader_result']==11,'no_owned_publication':load['state']['published']==0,
            'dispatch_remains_pinned_not_unloaded':load['state']['patches_installed']==1})
    # Real RX failure control: guest bootstrap cannot install hooks on RX MAIN.
    vm=LoadedMusicVM(stock,build);vm.boot()
    try:vm.load(writable=False)
    except RuntimeError as error:
        require('UC_ERR_WRITE_PROT' in str(error),'Wrong RX control failure')
        vm.main_matches(patched=False)
        cases.append({'name':'RX_MAIN_guest_write_fault_control','passed':True,
            'error':str(error),'physical_MAIN_writability_not_inferred':True})
    else:raise ValueError('RX control failed to block guest writes')
    deps=[Path(__file__),ROOT/'scripts/emulate_native_voice_outer.py',ROOT/'scripts/emulate_native_voice_selection.py',
          ROOT/'scripts/emulate_native_voice_registry.py',ROOT/'scripts/emulate_native_voice_metadata.py',
          ROOT/'scripts/emulate_native_vpm_filesystem.py',ROOT/'scripts/emulate_native_loader.py',
          ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_tts_vpm.py',
          ROOT/'scripts/analyze_native_loader.py']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'case_count':len(cases),'all_passed':True,'cases':cases,'build_manifest':BUILD,
        'build_manifest_sha256':sha((ROOT/BUILD).read_bytes()),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in deps},
        'original_outer_loader_and_native_bootstrap_wire_TX_same_VM':True,
        'guest_installs_MAIN_sites_no_host_dispatch_rewiring':True,
        'linked_music_code_in_original_voice_reservation':True,
        'native_callback_executes_but_media_is_explicitly_dropped':True,
        'MAIN_writability_cache_kernel_radio_storage_are_fixtures':True,
        'original40_exports_preserved':True,'device_io':False,'device_install_candidate':False,
        'real_package_acceptance_verified':False,'native_phone_or_speaker_playback_verified':False,
        'limits':'Original outer filesystem/registry/selection/loader execute; storage/initialized inventory/kernel/cached settings are fixtures. New compiled entry runs provider, eight-site dispatch installation, SDP publication then native received-message/real small TX allocator/queue/scheduler wrapper and lifecycle to loaded ARM callback in SAME VM. MAIN write permission and cache synchronization are explicit fixtures, RX control faults. Media deliberately dropped; session/local receiveMTU guards/decoder/PCM workers not wired. No device install/actual App/UI/phone/radio/DAC/lifetime/reload/unload/concurrency proof.'}
    path=ROOT/'evidence/firmware-analysis/native-music-loaded-emulation.json'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),'all_passed':True}))


if __name__=='__main__':main()
