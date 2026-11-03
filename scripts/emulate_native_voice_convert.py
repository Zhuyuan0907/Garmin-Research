#!/usr/bin/env python3
"""Execute stock AVDTP -> SBC -> converter -> stock PCM, offline only.

Uses original TTS bootstraps/exports and exact stock dispatch/ring code.
Reference PCM comes from upstream libsbc plus an independent absolute-position
convolution. SEP/channel/ring state and OS policies remain synthetic.
"""
from datetime import datetime, timezone
import ctypes
import itertools
import json
import struct

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_loader import simulate
from emulate_native_sbc import (Machine, Reference, INPUT_PAGE, PAGE_BYTES,
                                STACK, RETURN)
from emulate_native_sbc_pcm import HOST_OUTPUT, RING_BYTES
from emulate_native_voice_extension import VoicePcmMachine
from emulate_native_voice_media import sha, packet, counters
from emulate_native_pcm_converter import expected_convolution, unpack
from emulate_avdtp_media import MediaDispatch, HANDLER, LOOKUP, VENEER

BUILD=ROOT/'staging/native-voice-convert-extension-emulation'


class ConvertedMachine(VoicePcmMachine):
    def __init__(self,stock,uc,manifest):
        super().__init__(stock,uc,manifest)
        table=manifest['symbols']['voice_convert_decoder_api']['address']
        values=struct.unpack('<3I',self.uc.mem_read(table,12))
        names=('voice_convert_reset','garmin_sbc_decode_frame','voice_convert_submit_frame')
        for name,address in zip(names,values):
            if address!=manifest['symbols'][name]['address']:
                raise ValueError('Converted local API table differs from manifest')
            self.symbols[name]={'address':address}
        self.symbols['garmin_sbc_reset']=self.symbols['voice_convert_reset']
        self.submit_function='voice_convert_submit_frame'

    def call(self,name,args=(),fifth=None):
        if name!='_stock_media_handler': return super().call(name,args,fifth)
        # Up to15 codec frames plus96-tap FIR processing exceed the base
        # single-frame instruction bound. Retain an explicit packet bound.
        self.counter=0
        self.uc.reg_write(UC_ARM_REG_SP,STACK)
        self.uc.reg_write(UC_ARM_REG_LR,RETURN)
        for register,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):
            self.uc.reg_write(register,value)
        self.uc.emu_start(self.symbols[name]['address'],RETURN,timeout=10000000,count=4000000)
        if self.uc.reg_read(UC_ARM_REG_PC)!=RETURN:
            raise ValueError('Converted stock packet callback exceeded bounded execution')
        self.total_instructions+=self.counter
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value


def deliver(machine,dispatch,data,lcid=0x1234):
    if not 0<len(data)<=PAGE_BYTES-32: raise ValueError('RTP input exceeds guarded page')
    source=INPUT_PAGE+PAGE_BYTES-len(data)
    machine.uc.mem_write(INPUT_PAGE,b'\xa5'*PAGE_BYTES)
    machine.uc.mem_write(source,data)
    machine.symbols['_stock_media_handler']={'address':HANDLER | 1}
    status=machine.call('_stock_media_handler',(lcid,source,len(data)))
    if dispatch.mutex_held: raise ValueError('Dispatch left mutex held')
    if bytes(machine.uc.mem_read(source,len(data)))!=data:
        raise ValueError('Callback changed read-only source')
    machine.verify_ring_guards()
    return status


def drain(machine):
    output=[]
    while machine.queued(): output.append(machine.read(3840))
    return b''.join(output)


def reference_pcm(reference,frames,rate,channels,tables):
    original=b''.join(reference.decode_stream(frames))
    return expected_convolution(unpack(original),rate,channels,tables),original


def routed_stream(machine,dispatch,manifest,frames,wanted,reset=True,groups=(1,4,8,15),options=None):
    dispatch.configure(slot=2,channel_index=11,context_index=1)
    machine.configure(RING_BYTES-64)
    if reset: machine.reset()
    before=counters(machine,manifest); before_events=len(machine.events)
    output=[]; cursor=0; packets=0
    while cursor<len(frames):
        count=min(groups[packets%len(groups)],len(frames)-cursor)
        raw=packet(frames[cursor:cursor+count],packets,**(options or {}))
        if deliver(machine,dispatch,raw)!=0: raise ValueError('Stock dispatch returned failure')
        cursor+=count; packets+=1
        while machine.queued()>=4096: output.append(machine.read(3840))
    output.append(drain(machine)); actual=b''.join(output)
    after=counters(machine,manifest); delta=tuple(a-b for a,b in zip(after[:5],before[:5]))
    if delta!=(packets,packets,0,len(frames),len(wanted)) or after[5]!=0:
        raise ValueError('Packet/frame/PCM counters differ: '+str((delta,len(wanted),after[5])))
    if actual!=wanted: raise ValueError('Converted stock reader samples differ from reference')
    if len(dispatch.calls)!=packets or LOOKUP not in dispatch.visited or VENEER not in dispatch.visited:
        raise ValueError('Original media lookup/veneer/callback was not used')
    if any(c['event']!=0xf1 or c['status']!=0 or c['local_seid']!=3 or c['remote_seid']!=7
           for c in dispatch.calls): raise ValueError('Stock callback ABI mismatch')
    host_calls=sum(e['entry']==hex(HOST_OUTPUT) for e in machine.events[before_events:])
    if host_calls!=len(frames): raise ValueError('Converted frames bypassed original host PCM callback')
    return {'packets':packets,'frames':len(frames),'output_pcm_bytes':len(actual),
            'output_samples':len(actual)//2,'pcm_sha256':sha(actual),
            'upstream_sbc_plus_absolute_convolution_byte_identical':True,
            'stock_host_calls':host_calls,'stock_dispatch_and_reader_executed':True,
            'packet_grouping':list(groups),'rtp_options':options or {},'passed':True}


def check_voice(stock,reference,tables,path):
    manifest=json.loads(path.read_text())
    if not manifest['includes_pcm_conversion']: raise ValueError('Wrong extension variant')
    original=(ROOT/manifest['original_binary']).read_bytes()
    combined=(ROOT/manifest['combined_binary']).read_bytes()
    if sha(original)!=manifest['original_binary_sha256'] or sha(combined)!=manifest['combined_sha256']:
        raise ValueError('Original/converted build changed')
    for source,digest in manifest['source_sha256'].items():
        if sha((ROOT/source).read_bytes())!=digest: raise ValueError('Source changed: '+source)
    original_uc,original_loader=simulate(stock,'original_voice',module_bytes=original,
        module_ram_bytes=manifest['original_ram_bytes'],poison_module_ram=True,return_session=True)
    uc,loader=simulate(stock,'extended_voice',module_bytes=combined,
        module_ram_bytes=manifest['combined_ram_bytes'],poison_module_ram=True,return_session=True)
    old_exports=original_loader['module_export_registration'][-1]
    new_exports=loader['module_export_registration'][-1]
    for field in ('version','export_table','count','targets'):
        if old_exports[field]!=new_exports[field]: raise ValueError('Original TTS export contents changed')
    if new_exports['count']!=40 or original_loader['trampolines_verified']!=loader['trampolines_verified']:
        raise ValueError('Original40 TTS target/import addresses changed')
    extent=manifest['original_ram_bytes']-12
    baseline=bytes(original_uc.mem_read(IMAGE+12,extent))
    if bytes(uc.mem_read(IMAGE+12,extent))!=baseline: raise ValueError('Original TTS RAM differs after initialization')
    init=manifest['symbols']['voice_convert_init_status']['address']
    if struct.unpack('<i',uc.mem_read(init,4))[0]!=0: raise ValueError('Converted entry reset failed')
    machine=ConvertedMachine(stock,uc,manifest)
    callback=manifest['symbols']['voice_extension_media_callback']['address']
    api=manifest['symbols']['voice_extension_media_api']['address']
    if struct.unpack('<I',uc.mem_read(api,4))[0]!=callback: raise ValueError('Local media table changed')
    dispatch=MediaDispatch(stock,uc,callback)
    if counters(machine,manifest)!=(0,0,0,0,0,0): raise ValueError('Media BSS not cleared by entry')
    # First call uses entry-initialized decoder and lazily configures FIR.
    initial_config=dict(frequency=2,mode=3,subbands=1,blocks=3,allocation=0,bitpool=53)
    first=reference.encode(initial_config,frames=1)
    wanted,_=reference_pcm(reference,first,44100,2,tables)
    initialization=routed_stream(machine,dispatch,manifest,first,wanted,reset=False)
    configurations=[]
    for frequency,mode,subbands in itertools.product(range(4),range(4),range(2)):
        config=dict(frequency=frequency,mode=mode,subbands=subbands,
                    blocks=(frequency+mode+subbands)%4,allocation=(frequency+mode)%2,
                    bitpool=53 if subbands else 31)
        rate=(16000,32000,44100,48000)[frequency]; channels=1 if mode==0 else 2
        frames=reference.encode(config,frames=4)
        wanted,source=reference_pcm(reference,frames,rate,channels,tables)
        result=routed_stream(machine,dispatch,manifest,frames,wanted,
            options={'csrc':bool(mode%2),'extension':bool(subbands),'padding':bool(frequency%2)})
        input_samples=len(source)//(2*channels)
        expected_samples=(input_samples*16000+rate-1)//rate
        if result['output_samples']!=expected_samples: raise ValueError('Stream rational count drift')
        configurations.append({'config':config,'rate':rate,'channels':channels,
                               'source_pcm_bytes':len(source),'source_sample_frames':input_samples,
                               'expected_output_samples':expected_samples,**result})
    phone_cases=[]
    for frequency,mode in [(2,3),(3,2)]:
        config=dict(initial_config,frequency=frequency,mode=mode)
        bitpools=[(53,35,60,40)[n%4] for n in range(80)]
        frames=reference.encode(config,frames=80,bitpools=bitpools)
        rate=44100 if frequency==2 else 48000
        wanted,source=reference_pcm(reference,frames,rate,2,tables)
        variable=routed_stream(machine,dispatch,manifest,frames,wanted,
            options={'csrc':True,'extension':True,'padding':True})
        uniform=routed_stream(machine,dispatch,manifest,frames,wanted,groups=(1,))
        if variable['pcm_sha256']!=uniform['pcm_sha256']: raise ValueError('RTP grouping changed FIR state')
        phone_cases.append({'rate':rate,'mode':mode,'bitpools':[53,35,60,40],
                            'grouping_invariant':True,'variable_groups':variable,
                            'single_frame_packets':uniform,'passed':True})
    guards=[]
    frames=reference.encode(initial_config,frames=3)
    fresh,_=reference_pcm(reference,frames[:1],44100,2,tables)
    valid=packet(frames[:1]); bad_crc=frames[1][:3]+bytes([frames[1][3]^1])+frames[1][4:]
    other_config=dict(initial_config,frequency=3)
    other=reference.encode(other_config,frames=1)[0]
    vectors=[
        ('wrong_rtp_version',bytes([valid[0]^0xc0])+valid[1:],-12,0),
        ('short_rtp',valid[:10],-12,0),
        ('zero_frame_count',valid[:12]+b'\x00'+valid[13:],-14,0),
        ('missing_declared_frame',valid[:12]+b'\x02'+valid[13:],-15,0),
        ('truncated_sbc',valid[:-1],-15,0),
        ('invalid_bitpool',valid[:15]+b'\xff'+valid[16:],-15,0),
        ('fragmented',valid[:12]+b'\xc1'+valid[13:],-13,0),
        ('trailing_payload',valid+b'\x00',-17,0),
        ('mixed_packet_formats',packet([frames[0],other]),-16,0),
        ('first_bad_crc',packet([bad_crc]),-6,0),
        ('later_bad_crc_keeps_submitted_prefix',packet([frames[0],bad_crc]),-6,1),
    ]
    for name,raw,error,prefix in vectors:
        dispatch.configure(); machine.configure(); machine.reset()
        before=counters(machine,manifest); before_events=len(machine.events)
        returned=deliver(machine,dispatch,raw)
        after=counters(machine,manifest); out=drain(machine)
        wanted=fresh if prefix else b''
        delta=tuple(a-b for a,b in zip(after[:5],before[:5]))
        if returned!=0 or after[5]!=error or delta!=(1,0,1,prefix,len(wanted)) or out!=wanted:
            raise ValueError('Rejected converted packet mismatch: '+name+str((delta,after[5])))
        host_calls=sum(e['entry']==hex(HOST_OUTPUT) for e in machine.events[before_events:])
        if host_calls!=prefix: raise ValueError('Rejected packet reached PCM beyond its reported prefix')
        guards.append({'name':name,'callback_error':error,'stock_dispatch_return':returned,
                       'submitted_prefix_frames':prefix,'prefix_pcm_reference_identical':True,'passed':True})
    # A CRC error resets both codec and converter. Recovery is checked without
    # any explicit reset, using the original first frame as a fresh stream.
    dispatch.configure(); machine.configure(); machine.reset()
    deliver(machine,dispatch,valid)
    if drain(machine)!=fresh: raise ValueError('Fresh converted prefix mismatch')
    deliver(machine,dispatch,packet([bad_crc]))
    if counters(machine,manifest)[5]!=-6 or machine.queued(): raise ValueError('CRC rejection failed')
    deliver(machine,dispatch,valid)
    if drain(machine)!=fresh: raise ValueError('CRC retained stale converter history/phase')
    guards.append({'name':'crc_recovers_without_explicit_reset','codec_and_fir_history_reset':True,
                   'fresh_pcm_identical':True,'passed':True})
    # A format error must leave synthesis/FIR unchanged for the existing format.
    dispatch.configure(); machine.configure(); machine.reset()
    deliver(machine,dispatch,valid); prefix=drain(machine)
    deliver(machine,dispatch,packet([other]))
    if counters(machine,manifest)[5]!=-5 or machine.queued(): raise ValueError('Cross-packet format change accepted')
    deliver(machine,dispatch,packet([frames[1]])); tail=drain(machine)
    whole,_=reference_pcm(reference,frames[:2],44100,2,tables)
    if prefix+tail!=whole: raise ValueError('Rejected format change advanced converter/synthesis state')
    guards.append({'name':'cross_packet_format_change_rejected_without_state_advance',
                   'callback_error':-5,'continuing_stream_pcm_identical':True,'passed':True})
    for name,setup,lcid,returned,calls,error in [
        ('not_streaming',{'state':1},0x1234,0,1,-11),
        ('unknown_channel',{},0x4567,0x2914,0,None),
        ('channel_mismatch',{'mismatch':True},0x1234,0,0,None)]:
        dispatch.configure(**setup); machine.configure(); machine.reset()
        before=counters(machine,manifest)
        if deliver(machine,dispatch,valid,lcid)!=returned or machine.queued() or len(dispatch.calls)!=calls:
            raise ValueError('Converted state/channel guard failed')
        after=counters(machine,manifest)
        if calls and after[5]!=error: raise ValueError('Wrong state submitted converted PCM')
        if not calls and after!=before: raise ValueError('Dropped channel called converted callback')
        guards.append({'name':name,'stock_dispatch_return':returned,'callbacks':calls,
                       'callback_error':error,'passed':True})
    # Direct new local API checks output metadata, independent of RTP counters.
    machine.configure(); machine.reset()
    status,metadata=machine.submit(frames[0]); output=drain(machine)
    if status!=0 or metadata[:5]!=(len(frames[0]),len(fresh),16000,1,len(fresh)//2) or output!=fresh:
        raise ValueError('Converted API metadata disagrees with output')
    guards.append({'name':'converted_local_api_output_metadata','metadata_first_five':list(metadata[:5]),
                   'output_reference_identical':True,'passed':True})
    if bytes(uc.mem_read(IMAGE+12,extent))!=baseline:
        raise ValueError('SBC/FIR/media/PCM changed original TTS RAM')
    for entry in loader['trampolines_verified']:
        if struct.unpack('<I',uc.mem_read(int(entry['storage'],16),4))[0]!=int(entry['trampoline'],16):
            raise ValueError('Converted pipeline changed TTS import pointer')
        if struct.unpack('<I',uc.mem_read(STUBS+entry['slot']*12+8,4))[0]!=int(entry['target_word'],16):
            raise ValueError('Converted pipeline changed TTS target')
    valid_frames=initialization['frames']+sum(c['frames'] for c in configurations)+sum(
        c['variable_groups']['frames']+c['single_frame_packets']['frames'] for c in phone_cases)
    valid_packets=initialization['packets']+sum(c['packets'] for c in configurations)+sum(
        c['variable_groups']['packets']+c['single_frame_packets']['packets'] for c in phone_cases)
    return {'voice':manifest['voice_package'],'manifest':str(path.relative_to(ROOT)),
            'combined_sha256':manifest['combined_sha256'],'loader':loader,
            'entry_initialized_decoder_and_converter':initialization,
            'configuration_cases':configurations,'phone_stream_cases':phone_cases,'guard_cases':guards,
            'decoded_converted_and_routed_frames':valid_frames,'accepted_valid_stream_packets':valid_packets,
            'original40_export_contents_and_targets_preserved':True,
            'original_import_pointers_and_trampolines_preserved':True,
            'original_ram_after_header_and_tail_identical':True,
            'original_ram_sha256_excluding_header':sha(baseline),
            'all_passed':True,'device_io':False}


def main():
    paths=sorted(BUILD.glob('*/manifest.json'))
    if len(paths)!=3: raise ValueError('Build all3 --media --convert experiments first')
    coefficient_manifest=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    coefficients=(ROOT/coefficient_manifest['coefficient_table']).read_bytes()
    if sha(coefficients)!=coefficient_manifest['coefficient_table_sha256']:
        raise ValueError('Converter coefficients changed')
    tables=json.loads(coefficients)['tables']; stock,reference=NativeImage(),Reference()
    cases=[]
    for path in paths:
        case=check_voice(stock,reference,tables,path); cases.append(case)
        print(json.dumps({'completed_voice':path.parent.name,
                          'valid_frames':case['decoded_converted_and_routed_frames'],
                          'configuration_cases':len(case['configuration_cases']),
                          'guard_cases':len(case['guard_cases']),'passed':True}),flush=True)
    report={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'cases':cases,'original_voice_count':len(cases),'original_exports_preserved_each':40,
            'configuration_cases_each':len(cases[0]['configuration_cases']),
            'guard_cases_each':len(cases[0]['guard_cases']),
            'phone_stream_cases_each':len(cases[0]['phone_stream_cases']),
            'decoded_converted_and_routed_frames':sum(c['decoded_converted_and_routed_frames'] for c in cases),
            'accepted_valid_stream_packets':sum(c['accepted_valid_stream_packets'] for c in cases),
            'output_format':{'rate':16000,'channels':1,'bits':16},
            'input_formats':'SBC16/32/44.1/48kHz, mono/dual/stereo/joint,4/8 subbands; block/allocation varied',
            'reference':'Upstream libsbc2.1 decode plus independent absolute-position Q15 convolution',
            'all_passed':True,'device_io':False,'audible_output':False,
            'native_avdtp_sbc_converter_stock_pcm_dataflow_verified_offline':True,
            'endpoint_and_channel_state_synthetic':True,'ring_state_synthetic':True,'os_policies_hooked':True,
            'real_endpoint_registration_and_bluetooth_reception_verified':False,
            'hardware_speaker_verified':False,'physical_sample_clock_verified':False,
            'real_time_performance_measured':False,'navigation_concurrency_verified':False,
            'modified_vpm_generated':False,'signature_acceptance_verified':False,
            'native_on_device_verified':False,'speech_synthesis_verified':False,'device_install_candidate':False,
            'limitations':'Original stock loader/bootstrap40-export registration, media handler/LCID lookup/BX R7, compiled SBC/FIR callback and stock PCM writer/reader execute offline. Code/data/RAM tail and original40 pointers/targets match unmodified initialization. Matrix covers all rates/modes/subbands while blocks/allocation rotate; not every tuple. Source SBC PCM matches upstream; conversion matches independent absolute-position convolution. Real SEP negotiation/lifecycle, jitter/reorder/loss/fragments, concurrent navigation, OS backpressure/scheduling, real hardware timing/speaker and modified VPM acceptance remain unverified. FIR tail is not flushed; late CRC may leave already-submitted prefix. This is not an installed native App.'}
    output=ROOT/'evidence/firmware-analysis/native-voice-convert-emulation.json'
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(output),'voices':len(cases),
                      'frames':report['decoded_converted_and_routed_frames'],
                      'accepted_packets':report['accepted_valid_stream_packets'],
                      'all_passed':True,'device_io':False}),flush=True)


if __name__=='__main__': main()
