#!/usr/bin/env python3
"""Stock media dispatch -> appended RTP/SBC callback -> stock PCM, offline.

Endpoint/channel RAM is synthetic; registration, Bluetooth transport, OS
policies, actual DAC/speaker and modified VPM acceptance are not tested.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_loader import simulate
from emulate_native_sbc import (Machine, Reference, INPUT_PAGE, PAGE_BYTES)
from emulate_native_sbc_pcm import RING_BYTES, HOST_OUTPUT
from emulate_native_voice_extension import VoicePcmMachine
from emulate_avdtp_media import MediaDispatch, HANDLER, LOOKUP, VENEER

BUILD=ROOT/'staging/native-voice-media-extension-emulation'


def sha(data): return hashlib.sha256(data).hexdigest()


def packet(frames, sequence=0, csrc=False, extension=False, padding=False):
    flags=0x80 | (int(csrc)*2) | (int(extension)*0x10) | (int(padding)*0x20)
    prefix=struct.pack('!BBHII', flags, 96, sequence & 0xffff, sequence*128, 1)
    if csrc: prefix+=struct.pack('!2I', 0x11111111, 0x22222222)
    if extension: prefix+=struct.pack('!HHI', 0x1234, 1, 0xabcdef01)
    data=prefix+bytes([len(frames)])+b''.join(frames)
    if padding: data+=b'\x00\x00\x00\x04'
    return data


def deliver(machine, dispatch, data, lcid=0x1234):
    if not 0 < len(data) <= PAGE_BYTES-32: raise ValueError('Packet exceeds guarded test page')
    source=INPUT_PAGE+PAGE_BYTES-len(data)
    machine.uc.mem_write(INPUT_PAGE,b'\xa5'*PAGE_BYTES)
    machine.uc.mem_write(source,data)
    machine.symbols['_stock_media_handler']={'address':HANDLER | 1}
    returned=Machine.call(machine,'_stock_media_handler',(lcid,source,len(data)))
    if dispatch.mutex_held: raise ValueError('Stock handler left mutex held')
    if bytes(machine.uc.mem_read(source,len(data)))!=data:
        raise ValueError('Callback changed read-only RTP input')
    machine.verify_ring_guards()
    return returned


def counters(machine, manifest):
    address=manifest['symbols']['voice_media_stats']['address']
    return struct.unpack('<5Ii', machine.uc.mem_read(address,24))


def check_voice(stock,reference,path):
    manifest=json.loads(path.read_text())
    combined=(ROOT/manifest['combined_binary']).read_bytes()
    original=(ROOT/manifest['original_binary']).read_bytes()
    if sha(combined)!=manifest['combined_sha256'] or sha(original)!=manifest['original_binary_sha256']:
        raise ValueError('Voice media build changed')
    for source,digest in manifest['source_sha256'].items():
        if sha((ROOT/source).read_bytes())!=digest: raise ValueError('Source changed: '+source)
    original_uc,original_loader=simulate(stock,'original_voice',module_bytes=original,
        module_ram_bytes=manifest['original_ram_bytes'],poison_module_ram=True,return_session=True)
    uc,loader=simulate(stock,'extended_voice',module_bytes=combined,
        module_ram_bytes=manifest['combined_ram_bytes'],poison_module_ram=True,return_session=True)
    for key in ('version','export_table','count','targets'):
        if original_loader['module_export_registration'][-1][key]!=loader['module_export_registration'][-1][key]:
            raise ValueError('Original export contents changed')
    if original_loader['trampolines_verified']!=loader['trampolines_verified']:
        raise ValueError('Original TTS import/trampoline layout changed')
    if loader['module_export_registration'][-1]['count']!=40: raise ValueError('Expected forty stock APIs')
    # Header changes are intentional; every original byte after it, including
    # RAM tail, must match the unmodified bootstrap's state in this experiment.
    extent=manifest['original_ram_bytes']-12
    baseline=bytes(original_uc.mem_read(IMAGE+12,extent))
    if bytes(uc.mem_read(IMAGE+12,extent))!=baseline: raise ValueError('Original TTS RAM changed')
    machine=VoicePcmMachine(stock,uc,manifest)
    callback=manifest['symbols']['voice_extension_media_callback']['address']
    api=manifest['symbols']['voice_extension_media_api']['address']
    if struct.unpack('<I',uc.mem_read(api,4))[0]!=callback: raise ValueError('Local callback table changed')
    dispatch=MediaDispatch(stock,uc,callback)
    if counters(machine,manifest)!=(0,0,0,0,0,0): raise ValueError('Media BSS not cleared by entry')
    config=dict(frequency=0,mode=0,subbands=1,blocks=3,allocation=0,bitpool=31)
    cases=[]
    for name,options,frame_count in [
        ('plain_multiframe',{},60),('csrc',{'csrc':True},30),
        ('extension',{'extension':True},30),('padding',{'padding':True},30),
        ('csrc_extension_padding',{'csrc':True,'extension':True,'padding':True},30)]:
        frames=reference.encode(config,frames=frame_count)
        wanted=reference.decode_stream(frames)
        dispatch.configure(slot=2,channel_index=11,context_index=1)
        machine.configure(RING_BYTES-64); machine.reset()
        before=counters(machine,manifest); output=[]; position=0; packets=0
        before_events=len(machine.events)
        while position<len(frames):
            count=min((1,4,8,15)[packets%4],len(frames)-position)
            raw=packet(frames[position:position+count],packets,**options)
            if deliver(machine,dispatch,raw)!=0: raise ValueError('Stock dispatch returned error')
            packets+=1; position+=count
            # Retain at least one 256-byte frame until the final drain.
            while machine.queued()>=4096: output.append(machine.read(3840))
        while machine.queued(): output.append(machine.read(3840))
        after=counters(machine,manifest)
        delta=tuple(a-b for a,b in zip(after[:5],before[:5]))
        if delta!=(packets,packets,0,frame_count,len(b''.join(wanted))) or after[5]!=0:
            raise ValueError('Media counters disagree with dispatched stream')
        if b''.join(output)!=b''.join(wanted): raise ValueError('Stock media -> PCM output differs')
        calls=dispatch.calls
        if len(calls)!=packets or any(c['event']!=0xf1 or c['status']!=0 or
             c['local_seid']!=3 or c['remote_seid']!=7 for c in calls):
            raise ValueError('Stock dispatch callback ABI changed')
        if LOOKUP not in dispatch.visited or VENEER not in dispatch.visited:
            raise ValueError('Stock lookup/callback veneer not executed')
        host_calls=sum(e['entry']==hex(HOST_OUTPUT) for e in machine.events[before_events:])
        if host_calls!=frame_count: raise ValueError('Missing original host PCM calls')
        cases.append({'name':name,'rtp_options':options,'packets':packets,
                      'frames':frame_count,'pcm_bytes':len(b''.join(output)),
                      'pcm_sha256':sha(b''.join(output)),'reference_byte_identical':True,
                      'stock_dispatch_callback_veneer_and_pcm_executed':True,
                      'stock_host_calls':host_calls,'counter_deltas':list(delta),'passed':True})
    frames=reference.encode(config,frames=3); wanted=reference.decode_stream(frames)
    valid=packet(frames[:1]); guards=[]
    stereo=reference.encode(dict(config,frequency=2,mode=3,bitpool=53),frames=1)[0]
    corrupt=frames[1][:3]+bytes([frames[1][3]^1])+frames[1][4:]
    test_vectors=[
        ('wrong_rtp_version',bytes([valid[0]^0xc0])+valid[1:],-12,0),
        ('short_rtp',valid[:10],-12,0),
        ('zero_frame_count',valid[:12]+b'\x00'+valid[13:],-14,0),
        ('declared_missing_frame',valid[:12]+b'\x02'+valid[13:],-15,0),
        ('truncated_sbc',valid[:-1],-15,0),
        ('truncated_csrc',b'\x8f'+valid[1:12],-12,0),
        ('oversized_extension',b'\x90'+valid[1:12]+b'\x00\x01\xff\xff'+valid[12:],-12,0),
        ('zero_padding',b'\xa0'+valid[1:]+b'\x00',-12,0),
        ('oversized_padding',b'\xa0'+valid[1:]+b'\xff',-12,0),
        ('fragmented',valid[:12]+b'\xc1'+valid[13:],-13,0),
        ('reserved_payload_bit',valid[:12]+b'\x11'+valid[13:],-14,0),
        ('trailing_payload',valid+b'\x00',-17,0),
        ('stereo_44100_requires_conversion',packet([stereo]),-16,0),
        ('first_frame_bad_crc',packet([corrupt]),-6,0),
        ('later_bad_crc_records_submitted_prefix',packet([frames[0],corrupt]),-6,1),
    ]
    for name,raw,wanted_error,prefix in test_vectors:
        dispatch.configure(); machine.configure(); machine.reset()
        before=counters(machine,manifest); before_events=len(machine.events)
        if deliver(machine,dispatch,raw)!=0: raise ValueError('Dispatch unexpectedly propagates codec result')
        after=counters(machine,manifest)
        expected_pcm=b''.join(wanted[:prefix]); actual=[]
        while machine.queued(): actual.append(machine.read(3840))
        if b''.join(actual)!=expected_pcm: raise ValueError('Rejected packet prefix differs: '+name)
        delta=tuple(a-b for a,b in zip(after[:5],before[:5]))
        if delta!=(1,0,1,prefix,len(expected_pcm)) or after[5]!=wanted_error:
            raise ValueError('Rejection/counter mismatch: '+name+str((delta,after[5])))
        host_calls=sum(e['entry']==hex(HOST_OUTPUT) for e in machine.events[before_events:])
        if host_calls!=prefix: raise ValueError('Unexpected output on rejected packet: '+name)
        guards.append({'name':name,'callback_error':wanted_error,
                       'stock_dispatch_return':0,'submitted_prefix_frames':prefix,
                       'stock_host_calls':host_calls,'passed':True})
    for name,setup,lcid,wanted_return,error,calls in [
        ('not_streaming_status_rejected',{'state':1},0x1234,0,-11,1),
        ('unknown_channel_not_dispatched',{},0x4567,0x2914,0,0),
        ('channel_mismatch_not_dispatched',{'mismatch':True},0x1234,0,0,0)]:
        dispatch.configure(**setup); machine.configure(); machine.reset()
        before=counters(machine,manifest)
        returned=deliver(machine,dispatch,valid,lcid)
        after=counters(machine,manifest)
        if returned!=wanted_return or machine.queued()!=0 or len(dispatch.calls)!=calls:
            raise ValueError('State/channel rejection failed: '+name)
        if calls and after[5]!=error: raise ValueError('Wrong state accepted media')
        if not calls and after!=before: raise ValueError('Dropped channel reached callback')
        guards.append({'name':name,'stock_dispatch_return':returned,
                       'media_callbacks':calls,'callback_error':error,
                       'submitted_prefix_frames':0,'passed':True})
    if bytes(uc.mem_read(IMAGE+12,extent))!=baseline:
        raise ValueError('Media pipeline changed original TTS code/data/RAM tail')
    for entry in loader['trampolines_verified']:
        if struct.unpack('<I',uc.mem_read(int(entry['storage'],16),4))[0]!=int(entry['trampoline'],16):
            raise ValueError('Media callback changed stock TTS pointer')
        if struct.unpack('<I',uc.mem_read(STUBS+entry['slot']*12+8,4))[0]!=int(entry['target_word'],16):
            raise ValueError('Media callback changed stock TTS trampoline target')
    return {'voice':manifest['voice_package'],'manifest':str(path.relative_to(ROOT)),
            'combined_sha256':manifest['combined_sha256'],'loader':loader,
            'cases':cases,'guard_cases':guards,'frames':sum(c['frames'] for c in cases),
            'packets':sum(c['packets'] for c in cases),
            'original_40_exports_and_import_trampolines_preserved':True,
            'original_ram_after_header_byte_identical':True,
            'original_ram_sha256_excluding_header':sha(baseline),
            'local_compiled_callback_table_verified':True,'media_bss_cleared_by_entry':True,
            'all_passed':True,'device_io':False}


def main():
    paths=sorted(BUILD.glob('*/manifest.json'))
    if len(paths)!=3: raise ValueError('Build all three --media voice experiments first')
    stock,reference=NativeImage(),Reference()
    cases=[check_voice(stock,reference,path) for path in paths]
    report={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'cases':cases,'original_voice_count':len(cases),'original_exports_preserved_each':40,
            'decoded_and_routed_frames':sum(c['frames'] for c in cases),
            'accepted_rtp_packets':sum(c['packets'] for c in cases),
            'rtp_format_cases_each':len(cases[0]['cases']),
            'guard_cases_each':len(cases[0]['guard_cases']),
            'all_passed':True,'device_io':False,'audible_output':False,
            'endpoint_and_channel_state_synthetic':True,'os_policies_hooked':True,
            'real_sep_registration_verified':False,'real_bluetooth_reception_verified':False,
            'modified_vpm_generated':False,'signature_acceptance_verified':False,
            'native_on_device_verified':False,'speech_synthesis_verified':False,
            'device_install_candidate':False,
            'local_reference_sources':['sources/deep-research/bluez-alsa-4.3.1/src/rtp.h',
                                       'sources/deep-research/bluez-alsa-4.3.1/src/a2dp-sbc.c'],
            'limitations':'Stock incoming L2CAP handler/LCID lookup/BX R7 call the appended compiled callback, which parses unfragmented RTP/SBC and submits only 16 kHz mono frames through the stock PCM host callback/reserve/commit/reader. Original 40 export contents, import/trampoline targets and original RAM except 12-byte header match unmodified initialization. Endpoint and ring state are synthetic; no registration/negotiation, real Bluetooth input, jitter/reorder/loss handling, lifecycle or concurrent navigation is tested. A later CRC failure can leave a submitted prefix; stock dispatch itself ignores callback errors. OS priority/channel scheduling controlled. Real sample clock/DAC/speaker and modified VPM/SIG acceptance unverified. This is not a native App or installable binary.'}
    output=ROOT/'evidence/firmware-analysis/native-voice-media-emulation.json'
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(output),'original_voices':len(cases),
                      'decoded_and_routed_frames':report['decoded_and_routed_frames'],
                      'accepted_rtp_packets':report['accepted_rtp_packets'],
                      'guard_cases_each':report['guard_cases_each'],'all_passed':True,'device_io':False}))


if __name__=='__main__': main()
