#!/usr/bin/env python3
"""Stock AVDTP configuration/start/suspend and pending Open, offline only.

Registered endpoints and real L2CAP connections are NOT supplied by this test.
Synthetic SEP/channel/context RAM is explicit; stock parsers/allocators,
state transitions and callback veneers execute without instruction changes.
"""
from datetime import datetime, timezone
import hashlib,json,struct
from pathlib import Path

import unicorn
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED

STATE,DESCRIPTORS,CHANNELS,CONTEXT=0x3a88ef0,0x3a89058,0x3a88f50,0x3a88eb8
RETURN,CALLBACK,STACK,INPUT=0x10000,0x10010,0x02000000,0x02100000
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
CONFIG=bytes.fromhex('040801000706000021150235')


class ControlVM:
    def __init__(self,stock,*,initial_state=1,pending=0,all_channels_used=False,callback_enabled=True):
        self.uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.stock=stock
        section=next(s for s in stock.copies if s['runtime_start']==0x50000)
        start=section['runtime_start'];size=(section['size']+4095)&~4095
        self.code=stock.read(start,section['size'])
        self.uc.mem_map(start,size)
        self.uc.mem_write(start,self.code)
        self.uc.mem_protect(start,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        for base,size in [(RETURN,4096),(STACK,0x10000),(INPUT,4096),(0x3a88000,0x2000)]:
            self.uc.mem_map(base,size)
        self.uc.mem_write(0x3a88000,b'\xa5'*0x2000)
        self.uc.mem_write(CONTEXT,bytes(DESCRIPTORS+36-CONTEXT))
        self.uc.mem_write(STATE,struct.pack('<I',CALLBACK|1 if callback_enabled else 0))
        self.uc.mem_write(STATE+0xf,b'\xff')
        self.uc.mem_write(STATE+0x12,bytes([initial_state,pending]))
        self.uc.mem_write(CONTEXT+0x13,b'\x00')
        self.uc.mem_write(CONTEXT+0x14,b'\xff')
        self.uc.mem_write(CONTEXT+0x16,bytes.fromhex('010203040506'))
        self.uc.mem_write(CHANNELS,struct.pack('<H',0x1234))
        if all_channels_used:
            for index in range(1,12):
                self.uc.mem_write(CHANNELS+index*8,struct.pack('<H',0x40+index))
        self.callback_error=0
        self.send_error=0
        self.mutex_held=True
        self.replies=[];self.callbacks=[];self.events=[];self.executed=set()
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)

    def byte(self,address):return self.uc.mem_read(address,1)[0]
    def word(self,address):return struct.unpack('<I',self.uc.mem_read(address,4))[0]
    def ret(self,value=0):
        self.uc.reg_write(UC_ARM_REG_R0,value)
        self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))
    def hook(self,uc,address,size,unused):
        self.executed.add(address)
        r=[uc.reg_read(reg) for reg in REGS]
        sp=uc.reg_read(UC_ARM_REG_SP)
        if address==RETURN:
            uc.emu_stop()
        elif address==0x5525bc:
            self.ret()
        elif address==0x5523fc:
            assert self.mutex_held
            self.mutex_held=False;self.events.append('unlock');self.ret()
        elif address==0x5523de:
            assert not self.mutex_held
            self.mutex_held=True;self.events.append('lock');self.ret()
        elif address==0x5524f6:
            dest,src,n=r[:3]
            assert STATE+0x14<=dest and dest+n<=STATE+0x18 and n<=4,(dest,n)
            assert self.input_start<=src and src+n<=INPUT+4096
            uc.mem_write(dest,bytes(uc.mem_read(src,n)));self.ret(dest)
        elif address==0x5a7794:
            channel,n,p=r[:3]
            assert STACK<=p and p+n<=STACK+0xf000 and 6<=n<=8
            self.replies.append({'channel':channel,'wire_hex':bytes(uc.mem_read(p+4,n-4)).hex(),
                'state_before_send':self.byte(STATE+0x12),'pending_before_send':self.byte(STATE+0x13)})
            self.events.append('send');self.ret(self.send_error)
        elif address==CALLBACK:
            assert not self.mutex_held,'Native callback ran under synthetic mutex'
            n=self.word(sp)
            assert n<=64
            raw=bytes(uc.mem_read(r[3],n)) if n else b''
            self.callbacks.append({'event':r[0],'status':r[1],
                'handle_hex':bytes(uc.mem_read(r[2],12)).hex(),'payload_hex':raw.hex(),
                'payload_length':n,'state_during_callback':self.byte(STATE+0x12),
                'pending_during_callback':self.byte(STATE+0x13),'mutex_held':False,
                'callback_return_fixture':self.callback_error})
            self.events.append('callback');self.ret(self.callback_error)
        elif address in (0x5524da,0x5524ee):
            raise AssertionError('Unexpected dynamic heap operation in this case')

    def invoke(self,signal,payload,*,callback_error=0,send_error=0):
        assert payload and len(payload)<=64
        self.input_start=INPUT+4096-len(payload)
        self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(self.input_start,payload)
        self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ)
        self.callback_error,self.send_error=callback_error,send_error
        self.replies=[];self.callbacks=[];self.events=[];self.executed=set()
        sp=STACK+0xf000
        self.uc.mem_write(sp,struct.pack('<I',len(payload)))
        self.uc.reg_write(UC_ARM_REG_SP,sp)
        self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        for reg,value in zip(REGS,(0,signal,1,self.input_start)):
            self.uc.reg_write(reg,value)
        handler={3:0x574acc,5:0x574acc,6:0x574f60,7:0x5752cc,9:0x5752cc}[signal]
        self.uc.emu_start(handler|1,RETURN+2,timeout=2000000,count=30000)
        assert self.uc.reg_read(UC_ARM_REG_PC)==RETURN
        assert self.uc.reg_read(UC_ARM_REG_SP)==sp and self.mutex_held
        assert bytes(self.uc.mem_read(self.input_start,len(payload)))==payload
        assert bytes(self.uc.mem_read(0x3a88000,CONTEXT-0x3a88000))==b'\xa5'*(CONTEXT-0x3a88000)
        tail=DESCRIPTORS+36
        assert bytes(self.uc.mem_read(tail,0x3a8a000-tail))==b'\xa5'*(0x3a8a000-tail)
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        return {'signal':signal,'payload_hex':payload.hex(),'replies':self.replies,
            'callbacks':self.callbacks,'event_order':self.events,'state':self.byte(STATE+0x12),
            'pending':self.byte(STATE+0x13),'negotiated_codec_hex':bytes(self.uc.mem_read(STATE+0x14,4)).hex(),
            'native_media_channel_index':self.byte(STATE+0xf),
            'original_parser_executed':0x5a63e4 in self.executed,
            'original_channel_reservation_executed':0x5a6228 in self.executed,
            'original_callback_veneer_executed':bool({0x427588,0x42758e}&self.executed),
            'original_code_input_and_RAM_guards_intact':True,'stack_and_mutex_restored':True}


def main():
    stock=NativeImage();results=[]
    def case(name,vm,signal,payload,wire,state,events,**kwargs):
        r=vm.invoke(signal,payload,**kwargs)
        assert [x['wire_hex'] for x in r['replies']]==[wire],(name,r)
        assert r['state']==state and [x['event'] for x in r['callbacks']]==events,(name,r)
        r.update(name=name,passed=True);results.append(r);return r
    vm=ControlVM(stock)
    r=case('configure_SBC_uses_original_parser_and_channel_reservation',vm,3,CONFIG,'1203',2,[9])
    assert r['negotiated_codec_hex']=='21150235' and r['native_media_channel_index']==1
    assert r['event_order']==['send','unlock','callback','lock']
    r=case('Open_accepts_then_waits_for_real_L2CAP_completion',vm,6,b'\x04','1206',2,[])
    assert r['pending']==2
    r=case('rejected_Start_still_updates_state_after_successful_send',vm,7,b'\x04','13070431',8,[17])
    assert r['pending']==2 and r['callbacks'][0]['pending_during_callback']==6
    # New VM controls deliberately provide post-media-connect state. This is
    # not a claim of running the missing L2CAP completion in the above chain.
    vm=ControlVM(stock,initial_state=4)
    r=case('Start_from_synthetic_ready_state',vm,7,b'\x04','1207',8,[17])
    assert r['pending']==0 and r['callbacks'][0]['pending_during_callback']==4
    case('Suspend_returns_to_ready_state',vm,9,b'\x04','1209',4,[19])
    case('rejected_duplicate_Suspend_still_calls_application',vm,9,b'\x04','13090431',4,[19])
    case('inactive_SEP_configuration_rejected',ControlVM(stock,initial_state=0),3,CONFIG,'13030112',0,[])
    case('missing_MediaTransport_rejected',ControlVM(stock),3,bytes.fromhex('04080706000021150235'),'13030129',1,[])
    case('bad_codec_length_rejected',ControlVM(stock),3,bytes.fromhex('04080100070600002115'),'13030711',1,[])
    case('invalid_remote_SEID_rejected',ControlVM(stock),3,bytes.fromhex('040001000706000021150235'),'13030018',1,[])
    case('busy_SEP_configuration_rejected',ControlVM(stock,pending=1),3,CONFIG,'13030013',1,[])
    case('all_media_channels_reserved_rejects_configuration',ControlVM(stock,all_channels_used=True),3,CONFIG,'13030631',1,[])
    case('callback_return_error_does_not_reject_already_accepted_config',ControlVM(stock),3,CONFIG,'1203',2,[9],callback_error=0xdead)
    case('no_callback_config_still_accepted',ControlVM(stock,callback_enabled=False),3,CONFIG,'1203',2,[])
    case('codec_ID_without_local_decoder_validation_control',ControlVM(stock),3,bytes.fromhex('040801000706000221150235'),'1203',2,[9])
    case('transport_only_config_has_no_codec_but_core_accepts',ControlVM(stock),3,bytes.fromhex('04080100'),'1203',2,[9])
    case('Start_send_failure_does_not_transition',ControlVM(stock,initial_state=4),7,b'\x04','1207',4,[],send_error=0x2930)
    dependencies=[Path(__file__),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'case_count':len(results),'cases':results,'all_passed':True,'cpu_model':'ARM1176',
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dependencies},
        'real_SEP_registration_executed':False,'real_L2CAP_connection_completion_executed':False,
        'original_config_parser_and_channel_reservation_executed':True,
        'configuration_reply_precedes_application_callback':True,
        'callback_return_not_a_configuration_rejection_API':True,
        'rejected_Start_can_transition_and_callback_after_successful_reject_send':True,
        'application_requires_preaccept_codec_policy_and_media_ready_state_fences':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'native_App_or_physical_phone_or_speaker_verified':False,
        'fixtures':['Preinitialized SEP/channel/context pools','log/memcpy/L2CAP send/mutex hooks',
            'Application callback target/return value','Fresh ready-state VM for Start/Suspend'],
        'limitations':'No real SDP/SEP registration, L2CAP completion, negotiated decoder/profile validation, real scheduling/concurrency, module acceptance, native UI or speaker. Open chain stops at pending media connection, never manually advanced and claimed complete. Independent Start controls use synthetic ready state. Native callback payload/handles are transient stack views, not owned persistent storage.'}
    p=ROOT/'evidence/firmware-analysis/avdtp-control-emulation.json'
    p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(p.relative_to(ROOT)),'cases_passed':len(results),'device_io':False}))


if __name__=='__main__':main()
