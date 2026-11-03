#!/usr/bin/env python3
"""Execute exact stock audio-method factory and logical format getters.

Synthetic RAM only, no hardware/device audio. The factory's memset is hooked;
its switch, pointer stores and selected format getters run unchanged.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace

FACTORY=0x437764
METHODS=0x02020020
FORMAT=0x02021ff4
RETURN=0x10000
MEMSET=0x35b4f4


def run(stock, kind):
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB); uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
    for page in (0x437000,0x484000,0x48f000):
        uc.mem_map(page,0x1000); uc.mem_write(page,stock.read(page,0x1000))
    uc.mem_map(MEMSET & ~0xfff,0x1000)
    uc.mem_write(MEMSET,struct.pack('<I',0xe12fff1e))
    uc.mem_map(RETURN,0x1000); uc.mem_map(0x02000000,0x10000)
    uc.mem_map(0x02020000,0x1000); uc.mem_map(0x02021000,0x1000)
    uc.mem_write(METHODS-32,b'\xa5'*(32+0x44+32))
    uc.mem_write(FORMAT-32,b'\xa5'*44)
    visits=set(); events=[]
    def observe(emu,address,size,user_data):
        visits.add(address)
        if address==MEMSET:
            dest,count=emu.reg_read(UC_ARM_REG_R0),emu.reg_read(UC_ARM_REG_R1)
            if dest!=METHODS or count!=0x44: raise ValueError('Unexpected factory clear')
            emu.mem_write(dest,bytes(count)); events.append('factory_memset_hook')
        if address==RETURN: emu.emu_stop()
    uc.hook_add(UC_HOOK_CODE,observe)
    def call(address,args):
        uc.reg_write(UC_ARM_REG_SP,0x0200f000); uc.reg_write(UC_ARM_REG_LR,RETURN | 1)
        for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2),args): uc.reg_write(reg,value)
        uc.emu_start(address,RETURN+2,timeout=1000000,count=1000)
        if uc.reg_read(UC_ARM_REG_PC)!=RETURN: raise ValueError('Stock method did not return')
        return uc.reg_read(UC_ARM_REG_R0)
    status=call(FACTORY | 1,(METHODS,kind))
    methods=struct.unpack('<17I',uc.mem_read(METHODS,0x44))
    result=None
    if status==0:
        getter=methods[6]
        if getter not in (0x484c49,0x48f0a5): raise ValueError('Unexpected tested format getter')
        getter_status=call(getter,(0,FORMAT))
        channels,bits,block_align,rate=struct.unpack('<HHII',uc.mem_read(FORMAT,12))
        result={'getter':hex(getter),'status':getter_status,
                'channels':channels,'bits_per_sample':bits,
                'bytes_per_sample_frame':block_align,'sample_rate':rate}
    if bytes(uc.mem_read(METHODS-32,32))!=b'\xa5'*32 or bytes(uc.mem_read(METHODS+0x44,32))!=b'\xa5'*32:
        raise ValueError('Factory changed descriptor canary')
    if bytes(uc.mem_read(FORMAT-32,32))!=b'\xa5'*32:
        raise ValueError('Getter changed format canary')
    return {'kind':kind,'factory_return':status,
            'method_pointer_words':[hex(x) for x in methods],
            'read_method':hex(methods[5]),'format':result,
            'tts_switch_path_executed':0x437846 in visits,
            'hooks':events,'passed':True}


def main():
    stock=NativeImage(); cases=[run(stock,t) for t in (17,1,23)]
    tts,raw,invalid=cases
    if tts['factory_return']!=0 or tts['read_method']!='0x484c05' or not tts['tts_switch_path_executed']:
        raise ValueError('Type17 did not select the previously verified TTS ring reader')
    if tts['format']!={'getter':'0x484c49','status':0,'channels':1,
                       'bits_per_sample':16,'bytes_per_sample_frame':2,'sample_rate':16000}:
        raise ValueError('TTS logical format mismatch')
    if raw['factory_return']!=0 or raw['format']['sample_rate']!=44100:
        raise ValueError('44100 Hz control format mismatch')
    if invalid['factory_return']!=4 or any(int(x,16) for x in invalid['method_pointer_words']):
        raise ValueError('Invalid audio kind was not rejected')
    branch_table=stock.read(0x437780,23)
    if 0x437780+2*branch_table[17]!=0x437846: raise ValueError('Stock switch table mismatch')
    report={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'unicorn_version':unicorn.__version__,'cpu_model':'ARM1176',
            'factory':hex(FACTORY),'audio_kind':17,
            'factory_method_read_offset':20,'factory_method_format_offset':24,
            'tts_reader':'0x484c05','format_getter':'0x484c49',
            'logical_pcm_format':{'sample_rate':16000,'channels':1,'bits':16,'block_align':2},
            'stock_start_routine':'0x33f474','start_registers_audio_kind':17,
            'start_request_callback':'0x270458','cases':cases,'all_passed':True,
            'getter_code_sha256':hashlib.sha256(stock.read(0x484c48,22)).hexdigest(),
            'getter_instructions':trace(stock,0x484c48,40),
            'start_instructions':trace(stock,0x33f474,180),
            'switch_table_hex':branch_table.hex(),'device_io':False,
            'physical_sample_clock_verified':False,'actual_dac_or_speaker_verified':False,
            'limitations':'Original factory and getters prove logical TTS source format and reader selection offline. Factory memset is hooked; descriptors/stack are synthetic. The start request uses type17 but scheduler/priority, actual device mixer format conversion, physical DAC sample clock and audible playback remain unverified. Other factory kinds were not all characterized.'}
    path=ROOT/'evidence/firmware-analysis/native-audio-format-emulation.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(path),'logical_pcm_format':report['logical_pcm_format'],
                      'cases':len(cases),'all_passed':True,'device_io':False}))


if __name__=='__main__': main()
