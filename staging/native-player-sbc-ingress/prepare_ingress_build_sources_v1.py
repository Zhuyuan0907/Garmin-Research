#!/usr/bin/env python3
"""FILE-only NEW capacity-wake translation unit and compile driver."""
from pathlib import Path
import json, hashlib, ast
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
PREV=ROOT/'staging/native-player-sbc-sync'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def put(p,s):
    with p.open('x') as f:f.write(s)
def replace_one(s,a,b):
    assert s.count(a)==1,a
    return s.replace(a,b)
def main():
    inputs={str(p.relative_to(ROOT)):sha(p) for p in (
        Path(__file__).resolve(),PREV/'owned_media_typed_v2.c',PREV/'build_sbc_sync_v3.py',
        BASE/'sbc_fifo_ingress_owner_v1.c',BASE/'mixer_source_ingress_v1.c')}
    owned=(PREV/'owned_media_typed_v2.c').read_text()
    owned=replace_one(owned,'#include "media_worker.h"',
        '/* Capacity notification belongs to the existing Source actor. */\nextern void sbi_capacity_wake(void);')
    owned=replace_one(owned,
        'int wake=freed && running && media_queue_control.count && media_worker_state.tcb &&\n        !media_worker_state.quit_requested;',
        'int wake=freed && running && media_queue_control.count;')
    owned=replace_one(owned,'if(wake)(void)media_worker_notify_capacity();','if(wake)sbi_capacity_wake();')
    put(BASE/'owned_media_ingress_v1.c',owned)
    build=(PREV/'build_sbc_sync_v3.py').read_text()
    build=replace_one(build,"SYNC=ROOT/'staging/native-player-mixer-sync'", "SYNC=ROOT/'staging/native-player-mixer-sync'\nPREV=ROOT/'staging/native-player-sbc-sync'")
    build=build.replace("BASE/'build-v3'","BASE/'build-v1'")
    build=build.replace("BASE/'build-v3.json'","BASE/'build-v1.json'")
    build=build.replace("BASE/'owned_media_typed_v2.c'","BASE/'owned_media_ingress_v1.c'")
    build=replace_one(build,"BASE/'compressed_input_fixtures_v1.h',",'')
    build=build.replace("BASE/'mixer_source_sbc_v1.c'","BASE/'mixer_source_ingress_v1.c'")
    build=build.replace("BASE/'sbc_fifo_session_owner_v2.c'","BASE/'sbc_fifo_ingress_owner_v1.c'")
    build=build.replace("BASE/'sbc_arena_runtime_v1.c'","PREV/'sbc_arena_runtime_v1.c'")
    build=replace_one(build,'KEEP(*(.text.mp_*))','KEEP(*(.text.sbi_*))')
    build=replace_one(build,"'aas_packet_process','aas_packet_ticket','mp_select_stream','mp_stream_index','mp_packet_index','mp_last_decode_error'",
        "'aas_packet_ticket','aas_media_ingress','sbi_receive_packet','sbi_capacity_wake','sbi_status','mh_started','mh_stream_error','sbi_callbacks','sbi_accepted','sbi_capacity_posts'")
    build=replace_one(build,"for n in ('owned_media_api',", "for n in ('mp_streams','mp_bad_packets','mp_select_stream','input_pcm','owned_media_api',")
    build=replace_one(build,'compiled_SBC_RTP_decode_and_typed_FIFO_producer=True,',
        'compiled_SBC_RTP_decode_and_typed_FIFO_producer=True,compiled_compressed_fixture_or_bootstrap_packet=False,external_ingress_copy_and_Source_event_drain=True,capacity_source_POST=True,Stage1_without_anchor_or_mixer=True,original_SEP_registration_or_phone_ingress_verified=False,')
    ast.parse(build)
    put(BASE/'build_sbc_ingress_v1.py',build)
    outputs={str(p.relative_to(ROOT)):sha(p) for p in (BASE/'owned_media_ingress_v1.c',BASE/'build_sbc_ingress_v1.py')}
    receipt=dict(all_passed=True,FILE_ONLY=True,source_sha256=inputs,output_sha256=outputs,
        compiled_fixture_removed=True,capacity_uses_existing_Source=True,compile_executed=False,
        guest_executed=False,device_io=False,SEP_publication_remoteStart_connection_epoch_warm_system_and_hardware_unverified=True)
    put(BASE/'source-preparation-v1.json',json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
if __name__=='__main__':main()
