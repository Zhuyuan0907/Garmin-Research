#!/usr/bin/env python3
"""Execute stock AVDTP capability replies with synthetic endpoints only.

No Bluetooth traffic, device RAM access, firmware patches or installation.
The incoming handler and reply serializer execute exact HWID1352/8.00 code;
allocator, memcpy, free, logging and L2CAP send are explicit fixture boundaries.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import unicorn
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
    UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED

HANDLER = 0x5748e4
SERIALIZER = 0x5a6928
REJECT = 0x5756ac
STATE, DESCRIPTORS = 0x3a88ef0, 0x3a89058
RETURN, STACK, INPUT, CODEC, HEAP = 0x10000, 0x02000000, 0x02100000, 0x02200000, 0x02300000
SBC_CAPS = bytes.fromhex('ffff0235')  # All four rates/modes, bitpool 2..53; fixture.


def run(stock, *, slot=0, state=1, seid=1, length=1, codec=SBC_CAPS,
        codec_id=0, descriptor_present=True, sdp_only=False, fail_first_alloc=False,
        signal=2, negotiated=bytes.fromhex('21150235'), negotiated_flags=1):
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
    pages = [0x574000, 0x575000, 0x5a6000, 0x5a7000, 0x552000]
    original = {}
    for page in pages:
        original[page] = stock.read(page, 0x1000)
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, original[page])
        uc.mem_protect(page, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    for page, size in [(RETURN,0x1000),(STACK,0x10000),(INPUT,0x1000),
                       (CODEC,0x1000),(HEAP,0x1000),(0x3a88000,0x2000),(0x3a7c000,0x1000)]:
        uc.mem_map(page, size)
    uc.mem_write(INPUT+0xfff, bytes([seid << 2]))
    uc.mem_write(CODEC+0xffc, codec)
    uc.mem_protect(INPUT,0x1000,unicorn.UC_PROT_READ)
    uc.mem_protect(CODEC,0x1000,unicorn.UC_PROT_READ)
    uc.mem_write(HEAP,b'\xa5'*0x1000)
    sep = STATE+slot*32
    uc.mem_write(sep+0x12,bytes([state]))
    uc.mem_write(sep+0xe,bytes([negotiated_flags]))  # Synthetic transport flags; codec copied separately.
    uc.mem_write(sep+0x14,negotiated)
    uc.mem_write(sep+0x18,bytes([len(negotiated)]))
    descriptor=DESCRIPTORS+slot*12
    uc.mem_write(descriptor, struct.pack('<I',CODEC+0xffc if descriptor_present else 0))
    uc.mem_write(descriptor+4,bytes([len(codec),0,codec_id,0,1]))
    uc.mem_write(0x3a88f50, struct.pack('<H',0x1234))
    if sdp_only:
        uc.mem_write(0x3a7c108+7*12+4,struct.pack('<H',1))
    sp=STACK+0xf000
    uc.mem_write(sp,struct.pack('<I',length))
    uc.reg_write(UC_ARM_REG_SP,sp)
    uc.reg_write(UC_ARM_REG_LR,RETURN|1)
    for reg,value in [(UC_ARM_REG_R0,0),(UC_ARM_REG_R1,signal),
                      (UC_ARM_REG_R2,1),(UC_ARM_REG_R3,INPUT+0xfff)]:
        uc.reg_write(reg,value)
    replies,allocations,frees,visited=[],[],[],set()
    count=0
    buffer=HEAP+0x1000-32
    def ret(value=0):
        uc.reg_write(UC_ARM_REG_R0,value)
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def hook(vm,address,size,data):
        nonlocal count
        count+=1
        if address in (HANDLER,SERIALIZER,REJECT):visited.add(address)
        if address==RETURN:
            vm.emu_stop()
        elif address==0x5524da:
            requested=vm.reg_read(UC_ARM_REG_R0)
            assert 0<requested<=32,requested
            failed=fail_first_alloc and not allocations
            allocations.append({'bytes':requested,'failed':failed})
            ret(0 if failed else buffer)
        elif address==0x5524f6:
            dest,source,n=(vm.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2))
            assert buffer<=dest and dest+n<=buffer+allocations[-1]['bytes']
            vm.mem_write(dest,bytes(vm.mem_read(source,n)))
            ret(dest)
        elif address==0x5524ee:
            assert vm.reg_read(UC_ARM_REG_R0)==buffer
            frees.append(True);ret()
        elif address==0x5525bc:
            ret()
        elif address==0x5a7794:
            channel,n,p=(vm.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2))
            if p==buffer:
                assert allocations and not allocations[-1]['failed'] and 6<=n<=allocations[-1]['bytes']
            else:
                assert STACK<=p and p+n<=sp and 6<=n<=8, (p,n)
            replies.append({'channel':channel,'wire_hex':bytes(vm.mem_read(p+4,n-4)).hex()})
            ret()
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    uc.emu_start(HANDLER|1,RETURN+2,timeout=2000000,count=5000)
    assert uc.reg_read(UC_ARM_REG_PC)==RETURN,'Handler did not return'
    assert len(replies)>=1,'No reply captured'
    assert uc.reg_read(UC_ARM_REG_SP)==sp,'Stack not restored'
    heap=bytes(uc.mem_read(HEAP,0x1000));used=max((a['bytes'] for a in allocations if not a['failed']),default=0)
    assert heap[:0xfe0]==b'\xa5'*0xfe0 and heap[0xfe0+used:]==b'\xa5'*(32-used)
    assert all(bytes(uc.mem_read(p,0x1000))==b for p,b in original.items())
    assert bytes(uc.mem_read(INPUT+0xfff,1))==bytes([seid<<2])
    assert bytes(uc.mem_read(CODEC+0xffc,4))==codec
    return {'reply':replies,'allocations':allocations,'free_calls':len(frees),
        'stock_serializer_executed':SERIALIZER in visited,
        'stock_reject_executed':REJECT in visited,'instructions':count,
        'code_images_and_guard_canaries_intact':True,'stack_restored':True}


def main():
    stock=NativeImage()
    cases=[
      ('inactive_endpoint',{'state':0},'130212'),
      ('SDP_enabled_endpoint_still_inactive',{'state':0,'sdp_only':True},'130212'),
      ('SBC_capabilities_first_endpoint',{},'12020100060380000007060000ffff0235'),
      ('SBC_capabilities_third_endpoint',{'slot':2,'seid':3},'12020100060380000007060000ffff0235'),
      ('missing_request_payload',{'length':0},'130211'),
      ('out_of_range_SEID_zero',{'seid':0},'130212'),
      ('out_of_range_SEID_four',{'seid':4},'130212'),
      ('unsupported_endpoint_state',{'state':64},'130231'),
      ('missing_codec_descriptor',{'descriptor_present':False},'120201000603800000'),
      ('allocator_failure_then_stack_reject',{'fail_first_alloc':True},'130231'),
      ('negotiated_configuration_separate_from_capabilities',{'signal':4,'state':2},'120401000706000021150235'),
      ('negotiated_configuration_category6_bytes',{'signal':4,'state':2,'negotiated_flags':9},'1204010006030000000706000021150235'),
      ('codec_ID_passthrough_does_not_prove_decoder',{'codec_id':2},'12020100060380000007060002ffff0235'),
    ]
    results=[]
    for name,params,expected in cases:
        result=run(stock,**params)
        assert result['reply']==[{'channel':0x1234,'wire_hex':expected}],(name,result)
        result.update(name=name,parameters={k:(v.hex() if isinstance(v,bytes) else v) for k,v in params.items()},
                      expected_wire_hex=expected,passed=True)
        results.append(result)
    dependencies=[Path(__file__),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
         'cpu_model':'ARM1176','Unicorn_version':unicorn.__version__,'handler':hex(HANDLER),
         'serializer':hex(SERIALIZER),'cases':results,'all_passed':True,'case_count':len(results),
         'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dependencies},
         'fixture_boundaries':['Synthetic SEP state/codec descriptors/channel context','Allocator/free/memcpy/log/L2CAP send hooks'],
         'conclusion':'Stock capability serializer can advertise supplied SBC bytes and report separately supplied negotiated bytes. Active SEP/codec data was supplied by fixture; no endpoint registration was executed.',
         'codec_ID_and_codec_info_are_serialized_not_decoded_or_validated':True,
         'local_SEP_registration_verified':False,'SDP_activation_verified_on_device':False,
         'device_io':False,'firmware_modified':False,'device_install_candidate':False,
         'actual_phone_reception_or_speaker_or_UI_verified':False,
         'sources':['https://www.bluetooth.com/specifications/specs/advanced-audio-distribution-profile/'],
         'limitations':'No SetConfiguration/Open/Start lifecycle, SBC decoding or real reception. Codec ID passthrough is not codec support. Heap hooks and synthetic endpoints do not establish stock registration API, live state, physical performance or install acceptance.'}
    p=ROOT/'evidence/firmware-analysis/avdtp-capabilities-emulation.json'
    p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(p.relative_to(ROOT)),'cases_passed':len(results),'device_io':False}))


if __name__=='__main__':main()
