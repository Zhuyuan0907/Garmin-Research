#!/usr/bin/env python3
"""NEW compressed RTP/SBC -> typed FIFO -> native scheduled source build.

Generate sources and HOST reference fixtures only. No VM, device or build.
All old compiled/proof sources remain immutable. The simulated RTP input is
explicit data, not a claim of installed AVDTP or an actual phone connection.
"""
import ast
import hashlib
import json
import struct
import sys
import tarfile
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
SYNC=ROOT/'staging/native-player-mixer-sync'
HANDOFF=ROOT/'staging/native-player-mixer-handoff'
sys.path.insert(0,str(ROOT/'scripts'))
from emulate_native_sbc import Reference
from emulate_native_pcm_converter import expected_convolution,unpack

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,s):
    with p.open('x') as f:f.write(s)
def once(s,a,b):
    assert s.count(a)==1,a[:100]
    return s.replace(a,b,1)
def packet(frames,sequence):
    return bytes([0x80,0x60])+struct.pack('>HII',sequence,sequence*256,0x13520008)+bytes([len(frames)])+b''.join(frames)

def main():
    reference=Reference()
    tables_path=ROOT/'staging/native-pcm-converter/coefficients.json'
    tables=json.loads(tables_path.read_text())['tables']
    header=['/* Compressed-only immutable offline RTP input fixtures. */',
        'struct mp_packet_input { const uint8_t *data; uint32_t bytes; };',
        'struct mp_stream_input { const struct mp_packet_input *packets; uint32_t count; };']
    streams=[]
    for stream_index,(frequency,mode) in enumerate(((0,0),(2,3),(3,2))):
        config=dict(frequency=frequency,mode=mode,subbands=1,blocks=3,allocation=0,bitpool=31)
        frames=reference.encode(config,frames=12)
        raw=reference.decode_stream(frames)
        rate=(16000,32000,44100,48000)[frequency]; channels=1 if mode==0 else 2
        all_pcm=expected_convolution(unpack(b''.join(raw)),rate,channels,tables)
        # Streaming causal output count equals ceil(input_frames*16000/rate).
        rows=[]
        for i in range(6):
            payload=packet(frames[2*i:2*i+2],i)
            start=((2*i*128*16000+rate-1)//rate)*2
            end=(((2*i+2)*128*16000+rate-1)//rate)*2
            pcm=all_pcm[start:end]
            fresh_raw=reference.decode_stream(frames[2*i:2*i+2])
            fresh_pcm=expected_convolution(unpack(b''.join(fresh_raw)),rate,channels,tables)
            name=f'mp_s{stream_index}_p{i}'
            header.append('static const uint8_t '+name+'[]={'+','.join(hex(v) for v in payload)+'};')
            rows.append(dict(name=name,packet_hex=payload.hex(),packet_sha256=hashlib.sha256(payload).hexdigest(),
                frames_hex=[v.hex() for v in frames[2*i:2*i+2]],
                expected_continuous_PCM_hex=pcm.hex(),expected_after_reset_PCM_hex=fresh_pcm.hex()))
        header.append('static const struct mp_packet_input mp_s'+str(stream_index)+'[]={'+
            ','.join('{'+r['name']+',sizeof('+r['name']+')}' for r in rows)+'};')
        bad=bytearray(packet(frames[8:10],99))
        second=13+len(frames[8]);bad[second+3]^=1
        badname=f'mp_s{stream_index}_bad_crc'
        header.append('static const uint8_t '+badname+'[]={'+','.join(hex(v) for v in bad)+'};')
        streams.append(dict(index=stream_index,rate=rate,channels=channels,config=config,packets=rows,
            bad_later_frame_CRC_packet_hex=bad.hex(),bad_CRC_name=badname))
    header.append('static const struct mp_stream_input mp_streams[]={'+
        ','.join('{mp_s'+str(i)+',6}' for i in range(3))+'};')
    header.append('static const struct mp_packet_input mp_bad_packets[]={'+
        ','.join('{'+s['bad_CRC_name']+',sizeof('+s['bad_CRC_name']+')}' for s in streams)+'};')
    save(BASE/'compressed_input_fixtures_v1.h','\n'.join(header)+'\n')
    fixture=dict(all_passed=True,HOST_reference_only=True,compressed_fixture_is_not_phone_or_AVDTP_input=True,
        reference_library=str(reference.library_path),reference_library_sha256=sha(reference.library_path),
        reference_version=reference.version,coefficient_sha256=sha(tables_path),streams=streams,
        source_sha256={str((ROOT/'scripts'/p).relative_to(ROOT)):sha(ROOT/'scripts'/p) for p in
            ['emulate_native_sbc.py','emulate_native_pcm_converter.py']})
    save(BASE/'compressed_input_reference_v1.json',json.dumps(fixture,indent=2)+'\n')

    # Whole-packet speculation is guarded by typed controller leases, and a
    # generation change prevents FIFO publication before and after submit.
    owned=(ROOT/'native/music-continuous/owned_media.c').read_text()
    owned=once(owned,'#include <stdint.h>','#include <stdint.h>\n#include "music_session_guard_v4.h"')
    old='''    if (!owned_media_output_ready()) return -25;
    uint32_t saved=lock(), epoch=media_queue_control.epoch;'''
    owned=once(owned,old,'''    struct mcs_guard *g=mcs_bridge_context;
    struct mcs_event_frame borrow={0};
    if(!g || g->magic!=MCS_MAGIC ||
       g->control->adapters.current_actor(g->control->adapters.context)!=g->owner)
        return MCS_REJECTED;
    int admitted=mcs_event_begin(g,g->generation,UMC_GATE_CONSUMER,&borrow);
    if(admitted)return admitted;
    if(!owned_media_output_ready()){mcs_event_end(g,&borrow);return -25;}
    uint32_t saved=lock(), epoch=media_queue_control.epoch;''')
    old='if (!media_queue_control.running || media_queue_control.epoch!=epoch)'
    assert owned.count(old)==2
    owned=owned.replace(old,'if (!media_queue_control.running || media_queue_control.epoch!=epoch ||\n                !umc_media_current(g->control,&borrow.media))')
    owned=once(owned,'saved=lock(); owned_media_control.busy=0; unlock(saved);\n    return result;',
        'saved=lock(); owned_media_control.busy=0; unlock(saved);\n    mcs_event_end(g,&borrow);\n    return result;')
    save(BASE/'owned_media_typed_v1.c',owned)
    wrapper='''/* Compressed queue processing runs on the real compiled source task.
 * Incoming packet bytes below are explicit offline fixtures, not Bluetooth. */
#include "music_session_guard_v4.h"
#include "owned_media_typed_v1.c"
int aas_pcm_initialize(uint32_t channel)
{ int r=owned_media_init(channel);return r?r:media_queue_begin(); }
int aas_packet_process(const uint8_t *packet,uint32_t bytes)
{ int r=media_queue_callback(0xf1u,0,0,packet,bytes);return r?r:media_queue_step(); }
uint32_t aas_packet_ticket(void){return owned_media_control.last_ticket;}
void aas_pcm_status(uint32_t *p)
{
 p[0]=owned_media_control.initialized;p[1]=owned_media_control.count;
 p[2]=owned_media_control.committed;p[3]=owned_media_control.released;
 p[4]=owned_media_control.last_ticket;p[5]=continuous_media_control.offset;
 p[6]=continuous_media_control.reads;p[7]=continuous_media_control.payload_bytes;
 p[8]=continuous_media_control.silence_bytes;p[9]=continuous_media_control.packets_consumed;
 p[10]=media_queue_control.running;p[11]=media_queue_control.epoch;
}
'''
    save(BASE/'sbc_fifo_session_owner_v1.c',wrapper)
    runtime=(ROOT/'native/sbc-prototype/runtime.c').read_text()
    begin=runtime.index('void *memset(');end=runtime.index('/* libgcc',begin)
    runtime=runtime[:begin]+runtime[end:]
    save(BASE/'sbc_arena_runtime_v1.c',runtime)

    source=(SYNC/'mixer_source_task_sync_v2.c').read_text()
    source=once(source,'#include <string.h>','#include <string.h>\n#include "decoder.h"\n#include "compressed_input_fixtures_v1.h"')
    source=once(source,'extern int aas_pcm_publish(const uint8_t *,uint32_t);',
        'extern int aas_packet_process(const uint8_t *,uint32_t);\nextern uint32_t aas_packet_ticket(void);\nextern int mcs_native_normal_context(void *);')
    source=once(source,'static int16_t input_pcm[256];',
        'volatile uint32_t mp_stream_index,mp_packet_index,mp_input_configured;\nvolatile int32_t mp_last_decode_error;')
    begin=source.index('static void make_pcm(void)');end=source.index('static int send_mixer(',begin)
    source=source[:begin]+'''int mp_select_stream(uint32_t index)
{
    if(index>=3u || mh_source_tcb || aas_guard.magic || mp_input_configured ||
       !mcs_native_normal_context(0))return MCS_REJECTED;
    mp_stream_index=index;mp_input_configured=1;return 0;
}
static int publish_pcm(void)
{
    if(!mp_input_configured || mp_stream_index>=3u ||
       mp_packet_index>=mp_streams[mp_stream_index].count)return MCS_REJECTED;
    const struct mp_packet_input *p=&mp_streams[mp_stream_index].packets[mp_packet_index];
    int r=aas_packet_process(p->data,p->bytes);
    if(r)return r;
    uint32_t ticket=aas_packet_ticket();if(!ticket)return MCS_REJECTED;
    mh_ticket=ticket;mh_pcm_cycle++;mp_packet_index++;return 0;
}
''' +source[end:]
    old='    }else return MCS_REJECTED;'
    source=once(source,old,'''    }else if(command==8u){
        /* Stop must reject a new compressed packet before decoder work. */
        r=publish_pcm();mp_last_decode_error=r;
        if(r>=0)return MCS_REJECTED;
        r=0;
    }else if(command==9u){
        const struct mp_packet_input *p=&mp_bad_packets[mp_stream_index];
        r=aas_packet_process(p->data,p->bytes);mp_last_decode_error=r;
        if(r!=DECODER_CODEC_ERROR)return MCS_REJECTED;
        r=0;
    }else return MCS_REJECTED;''')
    source=once(source,'command>7u','command>9u')
    save(BASE/'mixer_source_sbc_v1.c',source)

    builder=(SYNC/'build_mixer_sync_v2.py').read_text()
    builder=once(builder,"HANDOFF=ROOT/'staging/native-player-mixer-handoff'",
        "HANDOFF=ROOT/'staging/native-player-mixer-handoff'\nSYNC=ROOT/'staging/native-player-mixer-sync'\nSBC=ROOT/'sources/deep-research/sbc-2.1/sbc'")
    for name in ['initializer_sync_bridge_v1.c','initializer_sync_bridge_v1.S','music_session_guard_sync_v1.c']:
        builder=builder.replace("BASE/'"+name+"'","SYNC/'"+name+"'")
    builder=builder.replace("BASE/'mixer_source_task_sync_v2.c'","BASE/'mixer_source_sbc_v1.c'")
    builder=builder.replace("HANDOFF/'pcm_fifo_session_owner_v4.c'","BASE/'sbc_fifo_session_owner_v1.c'")
    builder=once(builder,"out=BASE/'build-v2'","out=BASE/'build-v1'")
    builder=once(builder,"source=[Path(__file__).resolve(),", "source=[Path(__file__).resolve(),BASE/'owned_media_typed_v1.c',BASE/'compressed_input_fixtures_v1.h',")
    additional="SBC/'sbc.c',ROOT/'native/sbc-prototype/decoder.c',ROOT/'native/sbc-prototype/pcm_converter.c',ROOT/'native/sbc-prototype/voice_media.c',BASE/'sbc_arena_runtime_v1.c',"
    needle="FROZEN/'bounded_pull_entry.S',"
    assert builder.count(needle)==2
    builder=builder.replace(needle,needle+additional)
    builder=once(builder,"ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py']",
        "ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',*sorted(SBC.glob('*.h')),ROOT/'sources/deep-research/sbc-2.1.tar.xz',ROOT/'staging/native-pcm-converter/pcm_converter_tables.h',ROOT/'staging/native-pcm-converter/coefficients.json']")
    # Keep ELF parser path independent of appended exact-source dependencies.
    builder=once(builder,"source[-1])","ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')")
    builder=once(builder,"'-I',str(HANDOFF),","'-I',str(HANDOFF),'-I',str(SBC),'-I',str(ROOT/'staging/native-pcm-converter'),")
    builder=once(builder,"worker PT_LOAD FLAGS(6); }","worker PT_LOAD FLAGS(6); packet PT_LOAD FLAGS(6); }")
    builder=once(builder,'KEEP(*(.text.ms_*))','KEEP(*(.text.mp_*)) KEEP(*(.text.ms_*))')
    builder=once(builder,' .ARM.attributes 0 :',
        ' .gather 0x07900000 (NOLOAD) : { *(.gather) } :packet\n .queue_payload 0x07902000 (NOLOAD) : { *(.queue_payload) } :packet\n .ARM.attributes 0 :')
    builder=builder.replace("ROOT/'native/sbc-prototype/media_queue.c'","ROOT/'staging/native-owned-media/owned_queue.c'")
    builder=once(builder,"run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)])",'''extra=[]
  if p.name=='voice_media.c':extra=['-DVOICE_MEDIA_CONVERT=1','-Dvoice_extension_submit_frame=owned_media_submit_frame','-Dvoice_extension_media_callback=owned_packet_parse','-Dvoice_extension_media_api=owned_packet_api','-Dvoice_media_stats=owned_packet_stats']
  run(['arm-linux-gnueabi-gcc',*flags,*extra,'-c',str(p),'-o',str(obj)])''')
    builder=once(builder,"*[str(p)for p in objects],'-o',str(elf)])","*[str(p)for p in objects],'-lgcc','-o',str(elf)])")
    builder=builder.replace("'aas_pcm_publish',", "'aas_packet_process','aas_packet_ticket','mp_select_stream','mp_stream_index','mp_packet_index','mp_last_decode_error',")
    builder=once(builder,"for n in ('garmin_sbc_decode_frame','owned_media_consume','owned_packet_parse','owned_media_api',",
        "for n in ('owned_media_api',")
    builder=once(builder,"symbols=symbols,undefined_symbols=[],raw_PCM_test_producer=True,",
        "symbols=symbols,undefined_symbols=[],raw_PCM_test_producer=False,compiled_SBC_RTP_decode_and_typed_FIFO_producer=True,")
    builder=once(builder,"dump(BASE/'build-v2.json'","dump(BASE/'build-v1.json'")
    # Validate authoritative archive/source equality before compilation.
    builder=once(builder,'def main():\n', '''def main():
 archive=ROOT/'sources/deep-research/sbc-2.1.tar.xz'
 assert sha(archive)=='426633cabd7c798236443516dfa8335b47e004b0ef37ff107e0c7ead3299fcc2'
 import tarfile
 with tarfile.open(archive,'r:xz') as package:
  for p in [SBC/'sbc.c',*sorted(SBC.glob('*.h'))]:
   assert package.extractfile('sbc-2.1/sbc/'+p.name).read()==p.read_bytes()
''')
    ast.parse(builder)
    save(BASE/'build_sbc_sync_v1.py',builder)
    result=dict(all_passed=True,file_only=True,compile_executed=False,guest_executed=False,device_io=False,
        fixture_header_has_compressed_bytes_only=True,full_App_or_phone_or_hardware_verified=False,
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__).resolve(),
            SYNC/'mixer_source_task_sync_v2.c',SYNC/'build_mixer_sync_v2.py',ROOT/'native/music-continuous/owned_media.c',
            ROOT/'native/sbc-prototype/runtime.c',reference.library_path] if p.is_relative_to(ROOT)},
        outputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in [BASE/'owned_media_typed_v1.c',
            BASE/'sbc_fifo_session_owner_v1.c',BASE/'sbc_arena_runtime_v1.c',BASE/'mixer_source_sbc_v1.c',
            BASE/'build_sbc_sync_v1.py',BASE/'compressed_input_fixtures_v1.h',BASE/'compressed_input_reference_v1.json']})
    save(BASE/'source-preparation-v1.json',json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
