#!/usr/bin/env python3
"""Execute compiled music policy and use real offline stock lifecycle views.

The fixture driver invokes prevalidation and policy separately. No native hook
is installed and no complete decoder/audio/phone path is claimed.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path

import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_avdtp_control import STATE,CHANNELS,REGS,RETURN,STACK,INPUT,CONFIG
from emulate_avdtp_lifecycle import LifecycleVM,MEDIA_LCID

MANIFEST='staging/native-music-policy/manifest.json'
CONFIG_PAGE,GUARD_PAGE,VIEW_PAGE=0x08c00000,0x08c02000,0x08c04000
CONFIG_OUT,GUARD,VIEW=CONFIG_PAGE+4096-36,GUARD_PAGE+4096-20,VIEW_PAGE+4096-48
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def signed(n):return n if n<0x80000000 else n-0x100000000


class PolicyVM(LifecycleVM):
    def __init__(self,stock):
        super().__init__(stock)
        self.pm=json.loads((ROOT/MANIFEST).read_text())
        for p,h in self.pm['source_sha256'].items():assert sha(p)==h,p
        for p,h in [(self.pm['flat'],self.pm['flat_sha256']),(self.pm['elf'],self.pm['elf_sha256'])]:assert sha(p)==h
        self.policy_code=(ROOT/self.pm['flat']).read_bytes();base=self.pm['base']
        size=(len(self.policy_code)+4095)&~4095
        self.uc.mem_map(base,size);self.uc.mem_write(base,self.policy_code)
        self.uc.mem_protect(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        for page in [CONFIG_PAGE,GUARD_PAGE,VIEW_PAGE]:
            self.uc.mem_map(page,4096);self.uc.mem_write(page,b'\xa5'*4096)
        self.uc.mem_write(GUARD,bytes(20))
        self.policy_results=[];self.last_input=None
        assert [self.call(n) for n in ['music_config_bytes','music_guard_bytes','music_view_bytes']]==[36,20,48]
        self.policy_results=[]

    def call(self,name,*args,readonly=()):
        before=[(p,bytes(self.uc.mem_read(p,n))) for p,n in readonly]
        sp=STACK+0xf000
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        for reg,value in zip(REGS,list(args)+[0]*4):self.uc.reg_write(reg,value)
        pages={p&~4095 for p,n in readonly}
        for p in pages:self.uc.mem_protect(p,4096,unicorn.UC_PROT_READ)
        self.uc.emu_start(self.pm['symbols'][name],RETURN+2,timeout=2000000,count=30000)
        for p in pages:self.uc.mem_protect(p,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        assert self.uc.reg_read(UC_ARM_REG_PC)==RETURN and self.uc.reg_read(UC_ARM_REG_SP)==sp
        assert all(bytes(self.uc.mem_read(p,len(data)))==data for p,data in before)
        assert bytes(self.uc.mem_read(self.pm['base'],len(self.policy_code)))==self.policy_code
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        for page,pointer in [(CONFIG_PAGE,CONFIG_OUT),(GUARD_PAGE,GUARD),(VIEW_PAGE,VIEW)]:
            assert bytes(self.uc.mem_read(page,pointer-page))==b'\xa5'*(pointer-page)
        value=signed(self.uc.reg_read(REGS[0]))
        self.policy_results.append({'function':name,'return':value,
            'native_state':self.byte(STATE+0x12),'native_pending':self.byte(STATE+0x13),
            'code_input_metadata_guards_and_stack_intact':True})
        return value

    def upload(self,data):
        assert data and len(data)<=4096
        self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        p=INPUT+4096-len(data);self.uc.mem_write(p,data)
        self.uc.mem_protect(INPUT,4096,unicorn.UC_PROT_READ)
        self.input_start=p;self.last_input=(p,data)
        return p

    def validate(self,data,local=1):
        pointer=self.upload(data);self.uc.mem_write(CONFIG_OUT,b'\xee'*36)
        code=self.call('music_validate_configuration',pointer,len(data),local,CONFIG_OUT,readonly=[(pointer,len(data))])
        output=bytes(self.uc.mem_read(CONFIG_OUT,36))
        if code<0:assert output==b'\xee'*36
        return code,struct.unpack('<9I',output)

    def bind(self,session=9):return self.call('music_guard_bind',GUARD,session,CONFIG_OUT,readonly=[(CONFIG_OUT,36)])
    def unbind(self,session=9):return self.call('music_guard_unbind',GUARD,session)

    def native_view(self,changes=None):
        index=self.byte(STATE+0xf);assert index<12
        channel=CHANNELS+index*8
        fields=[self.byte(STATE+0x12),self.byte(STATE+0x13),1,self.byte(STATE+0x10),
            index,index,struct.unpack('<H',self.uc.mem_read(channel,2))[0],self.byte(channel+4),self.byte(channel+6),
            self.byte(channel+5),self.word(STATE+0x14),struct.unpack('<H',self.uc.mem_read(STATE+0xc,2))[0]]
        for i,value in (changes or {}).items():fields[i]=value
        self.uc.mem_write(VIEW,struct.pack('<12I',*fields));return fields

    def packet(self,n=128,session=9,changes=None):
        fields=self.native_view(changes)
        return self.call('music_guard_packet',GUARD,session,VIEW,n,readonly=[(GUARD,20),(VIEW,48)]),fields

    def prepared(self):
        assert self.validate(CONFIG)[0]==0
        self.signal(3,CONFIG);assert self.bind()==0
        self.signal(6,b'\x04');self.incoming();self.config_request();self.config_confirm();self.signal(7,b'\x04')


def frame(header=0xbd,bitpool=53,extra=0):
    bands=8 if header&1 else 4;blocks=4*((header>>4&3)+1);mode=header>>2&3;channels=1 if mode==0 else 2
    bits=blocks*bitpool*(channels if mode<=1 else 1)+(bands if mode==3 else 0)
    n=4+bands*channels//2+(bits+7)//8
    return bytes((0x9c,header,bitpool,0))+bytes(n-4+extra)


def main():
    stock=NativeImage();cases=[]
    def record(name,v,expected,result,details=None):
        assert result==expected,(name,result,expected)
        cases.append({'name':name,'passed':True,'expected_return':expected,'actual_return':result,
            'policy_calls':list(v.policy_results),'stock_steps':list(v.history),**(details or {})})
    # Independently labelled codec choices; validate all128 supported selections.
    for freq,rate in [(0x20,44100),(0x10,48000)]:
        for mode,mode_number,channels in [(8,0,1),(4,1,2),(2,2,2),(1,3,2)]:
            for block,blocks in [(0x80,4),(0x40,8),(0x20,12),(0x10,16)]:
                for band,bands in [(8,4),(4,8)]:
                    for allocation,allocation_number in [(2,1),(1,0)]:
                        v=PolicyVM(stock)
                        payload=bytes((4,8,1,0,7,6,0,0,freq|mode,block|band|allocation,2,53))
                        r,c=v.validate(payload)
                        assert c==(1,2,int.from_bytes(payload[-4:],'little'),rate,channels,blocks,bands,allocation_number,mode_number)
                        record('valid_'+payload[-4:].hex(),v,0,r,{'decoded_configuration':list(c)})
    invalid=[('transport_only',bytes.fromhex('04080100'),-12),
        ('codec_only',bytes.fromhex('04080706000021150235'),-12),
        ('AAC_ID_with_SBC_bytes',bytes.fromhex('040801000706000221150235'),-14),
        ('video_media_type',bytes.fromhex('040801000706100021150235'),-14),
        ('nonzero_media_reserved_bits',bytes.fromhex('040801000706010021150235'),-14),
        ('duplicate_transport',CONFIG+b'\x01\x00',-12),
        ('duplicate_codec',CONFIG+CONFIG[4:],-12),('unknown_category',CONFIG+b'\x09\x00',-13),
        ('content_protection_unsupported',CONFIG+b'\x04\x02\x00\x00',-13),
        ('truncated_TLV',CONFIG[:-1],-12),('trailing_single_byte',CONFIG+b'\x01',-12),
        ('transport_has_data',bytes.fromhex('04080101ff0706000021150235'),-12),
        ('local_SEID_reserved_bits',b'\x05'+CONFIG[1:],-11),
        ('remote_SEID_zero',CONFIG[:1]+b'\x00'+CONFIG[2:],-11),
        ('remote_SEID_reserved_bits',CONFIG[:1]+b'\x09'+CONFIG[2:],-11),
        ('remote_SEID63_outside_policy',CONFIG[:1]+b'\xfc'+CONFIG[2:],-11),
        ('wrong_local_SEID',b'\x08'+CONFIG[1:],-11),
        ('zero_frequency',CONFIG[:8]+b'\x01'+CONFIG[9:],-14),
        ('multiple_frequencies',CONFIG[:8]+b'\x31'+CONFIG[9:],-14),
        ('16kHz_outside_selected_policy',CONFIG[:8]+b'\x81'+CONFIG[9:],-14),
        ('multiple_modes',CONFIG[:8]+b'\x23'+CONFIG[9:],-14),
        ('zero_mode',CONFIG[:8]+b'\x20'+CONFIG[9:],-14),
        ('multiple_blocks',CONFIG[:9]+b'\x35'+CONFIG[10:],-14),
        ('multiple_subbands',CONFIG[:9]+b'\x1d'+CONFIG[10:],-14),
        ('multiple_allocations',CONFIG[:9]+b'\x17'+CONFIG[10:],-14),
        ('zero_blocks',CONFIG[:9]+b'\x05'+CONFIG[10:],-14),
        ('minimum_bitpool1',CONFIG[:10]+b'\x01\x35',-14),
        ('maximum_bitpool54_outside_policy',CONFIG[:-1]+b'\x36',-14),
        ('minimum_exceeds_maximum',CONFIG[:10]+b'\x35\x02',-14)]
    for name,data,expected in invalid:
        v=PolicyVM(stock);r,_=v.validate(data)
        record(name,v,expected,r,{'rejection_leaves_output_unchanged':True,'stock_accept_handler_not_called':not v.history})
    for size in [1,129,4096]:
        v=PolicyVM(stock);record('unsupported_body_length_'+str(size),v,-10,v.validate(b'\x00'*size)[0])
    v=PolicyVM(stock);reordered=bytes.fromhex('040807060000211502350100');r,_=v.validate(reordered)
    record('valid_service_order_reversed',v,0,r)
    v=PolicyVM(stock);v.validate(CONFIG)
    for pointer,label in [(0,'null'),(CONFIG_OUT+1,'unaligned'),(INPUT+4096-len(CONFIG),'input_alias')]:
        r=v.call('music_validate_configuration',v.input_start,len(CONFIG),1,pointer,readonly=[(v.input_start,len(CONFIG))])
        record('output_'+label,v,-10,r)
    v=PolicyVM(stock);assert v.validate(CONFIG)[0]==0
    before=bytes(v.uc.mem_read(GUARD,20));assert v.bind(0)==-15 and bytes(v.uc.mem_read(GUARD,20))==before
    assert v.bind(9)==0;before=bytes(v.uc.mem_read(GUARD,20))
    assert v.bind(10)==-16 and v.unbind(8)==-15 and bytes(v.uc.mem_read(GUARD,20))==before
    assert v.unbind()==0;assert v.bind(9)==-15;assert v.bind(10)==0
    record('session_binding_busy_stale_and_monotonic_rebind',v,0,v.unbind(10))
    v=PolicyVM(stock);v.validate(CONFIG);assert v.bind(0xffffffff)==0 and v.unbind(0xffffffff)==0
    record('session_exhaustion_no_wrap_to1',v,-15,v.bind(1))
    v=PolicyVM(stock);v.prepared();r,fields=v.packet()
    assert fields[0:2]==[8,0] and fields[9]==16 and fields[-1]==672
    media=v.media(bytes(range(128)));assert media['callbacks'][0]['status']==0
    record('real_stock_lifecycle_view_allows_registered_fixture_stream',v,0,r,{'native_view':fields})
    v=PolicyVM(stock);v.validate(CONFIG);v.signal(3,CONFIG);v.bind();v.signal(6,b'\x04');v.incoming()
    bad=v.signal(7,b'\x04');media=v.media(b'unsafe');assert bad['replies'][0]['wire_hex']=='13070431' and media['callbacks'][0]['status']==0
    r,fields=v.packet(6);record('compiled_gate_rejects_stock_success_media_with_pending_Open',v,-17,r,{'native_view':fields})
    for index,value,expected,label in [(0,4,-17,'suspended'),(1,4,-17,'pending_Start'),(2,2,-17,'wrong_local'),
        (3,3,-17,'wrong_remote'),(10,0,-17,'wrong_codec'),(4,12,-18,'index12'),(5,2,-18,'different_SEP_channel'),
        (6,1,-18,'reserved_LCID'),(7,0,-18,'signaling_channel'),(8,1,-18,'other_owner'),
        (9,2,-18,'unready_flags'),(9,18,-18,'unready_extra_flags'),(11,0,-19,'no_local_MTU'),
        (11,4097,-19,'MTU_outside_buffer_policy')]:
        v=PolicyVM(stock);v.prepared();r,fields=v.packet(changes={index:value})
        record('native_view_'+label,v,expected,r,{'explicit_snapshot_field_control':index,'native_view':fields})
    for n,expected in [(0,-19),(672,0),(673,-19),(1008,-19)]:
        v=PolicyVM(stock);v.prepared();r,fields=v.packet(n)
        assert bytes.fromhex(v.history[-1]['media_channel_hex'])[2:4]==struct.pack('<H',1008)
        record('local_receive_MTU_boundary_'+str(n),v,expected,r,{'peer_receive_MTU':1008,'local_receive_MTU':672})
    v=PolicyVM(stock);v.prepared();record('stale_callback_session9_vs8',v,-15,v.packet(session=8)[0])
    v=PolicyVM(stock);v.prepared();assert v.unbind()==0
    record('inactive_guard_rejects_otherwise_ready_stock_view',v,-15,v.packet()[0])
    v=PolicyVM(stock);v.prepared();v.native('disconnect_notification',0x50be1c,[MEDIA_LCID]);assert v.unbind()==0
    v.validate(CONFIG);v.signal(3,CONFIG);assert v.bind(10)==0;v.signal(6,b'\x04');v.incoming();v.config_request();v.config_confirm();v.signal(7,b'\x04')
    assert v.packet(session=9)[0]==-15
    record('same_LCID_reconnect_new_session_rejects_captured_old_epoch',v,0,v.packet(session=10)[0])
    for name,data,expected in [('valid_frame',frame(),len(frame())),('multiple_frames_input',frame()+frame(),len(frame())),
        ('bad_sync',b'\x00'+frame()[1:],-14),('different_rate',frame(0xfd),-14),
        ('different_blocks',frame(0xad),-14),('different_mode',frame(0xb9),-14),
        ('different_allocation',frame(0xbf),-14),('different_subbands',frame(0xbc),-14),
        ('too_low_bitpool',frame(bitpool=1),-14),('outside_negotiated_bitpool',frame(bitpool=54),-14),
        ('truncated_frame',frame()[:-1],-19),('truncated_header',frame()[:3],-10)]:
        v=PolicyVM(stock);v.validate(CONFIG);v.bind();p=v.upload(data)
        r=v.call('music_guard_frame',GUARD,9,p,len(data),readonly=[(GUARD,20),(p,len(data))])
        record('SBC_frame_'+name,v,expected,r,{'CRC_checked':False})
    for pool,expected in [(19,-14),(20,len(frame(bitpool=20))),(30,len(frame(bitpool=30))),(31,-14)]:
        v=PolicyVM(stock);selected=CONFIG[:10]+bytes((20,30));assert v.validate(selected)[0]==0 and v.bind()==0
        data=frame(bitpool=pool);p=v.upload(data)
        r=v.call('music_guard_frame',GUARD,9,p,len(data),readonly=[(GUARD,20),(p,len(data))])
        record('narrow_negotiated_bitpool_'+str(pool),v,expected,r,{'negotiated_minimum':20,'negotiated_maximum':30})
    v=PolicyVM(stock);v.validate(CONFIG);v.bind();data=frame();p=v.upload(data)
    record('stale_session_frame_rejected',v,-15,v.call('music_guard_frame',GUARD,8,p,len(data),readonly=[(GUARD,20),(p,len(data))]))
    for pointer,n,label in [(0,12,'null'),(0xfffffff8,12,'wrapping')]:
        v=PolicyVM(stock)
        r=v.call('music_validate_configuration',pointer,n,1,CONFIG_OUT)
        record('input_range_'+label,v,-10,r)
    manifest=json.loads((ROOT/MANIFEST).read_text())
    deps=[Path(__file__),ROOT/'scripts/emulate_avdtp_lifecycle.py',ROOT/'scripts/emulate_avdtp_control.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/MANIFEST,ROOT/manifest['flat'],ROOT/manifest['elf'],
        ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'all_passed':True,'case_count':len(cases),'cases':cases,'valid_SBC_configuration_matrix':128,
        'source_sha256':{str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT))) for p in deps},
        'build_source_sha256':manifest['source_sha256'],'compiled_policy_code_bytes':manifest['flat_bytes'],
        'config_guard_view_bytes':[36,20,48],
        'same_VM_stock_lifecycle_and_compiled_policy_executed':True,
        'prevalidation_fixture_driver_not_real_native_hook':True,
        'native_preaccept_hook_or_real_SDP_SEP_registration_verified':False,
        'physical_decoder_speaker_UI_or_phone_verified':False,
        'CRC_RTP_fragment_jitter_decoder_integration_verified':False,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'limitations':'Application policy subset, not all A2DP/SBC formats. One actor, initialized persistent guard, monotonic non-reused session IDs, coherent locked snapshots, local receive MTU and captured callback session are caller obligations. Python drives policy before stock acceptance and after stock media delivery; no embedded preaccept/packet hook or decoder workers wired. Native LCID alone lacks epoch. Header length/configuration validation does not verify CRC/audio content. No real Bluetooth/OS/UI/module/phone/speaker or hardware-performance proof.'}
    target=ROOT/'evidence/firmware-analysis/native-music-policy-emulation.json'
    target.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'cases_passed':len(cases),'valid_configuration_matrix':128,'device_io':False}))


if __name__=='__main__':main()
