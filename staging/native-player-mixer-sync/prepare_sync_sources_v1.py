#!/usr/bin/env python3
"""Create NEW source copies and builder; no compile, guest or device work."""
import ast
import hashlib
import json
from pathlib import Path

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
OLD=ROOT/'staging/native-player-mixer-handoff'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,text):
    with p.open('x') as f:f.write(text)

def main():
    original=OLD/'mixer_source_task_v4.c'
    source=original.read_text()
    source=source.replace('extern struct mcs_guard aas_guard;',
        'extern struct mcs_guard aas_guard;\nextern int ms_validate_completed_sync(void);',1)
    old='mh_handoff_result=mcs_handoff_source_to_mixer(&aas_guard);\n    return mh_handoff_result;'
    assert source.count(old)==1
    source=source.replace(old,'mh_handoff_result=ms_validate_completed_sync();\n    return mh_handoff_result;',1)
    source=source.replace('/* This initializes actual M+64 descriptor/TCB and queues message13; the\n     * lower-priority mixer runs only after this source grants and blocks. */',
        '/* Original3B9B66 queues13 then calls patched3B9C54: CONFIG is granted\n'
        '     * before original46CC7A posts20 and waits for mixer acknowledgement.\n'
        '     * PLAY opens below only after the whole initializer returns. */',1)
    old='}else return MCS_REJECTED;'
    assert source.count(old)==1
    source=source.replace(old,
        '}else if(command==7u){ /* existing originalM+78 synchronization path */\n'
        '        r=((int (*)(uint32_t,uint32_t))0x3b9b67u)(8,0);\n'
        '        if(!r)r=ms_validate_completed_sync();\n'
        '    }else return MCS_REJECTED;',1)
    save(BASE/'mixer_source_task_sync_v1.c',source)
    guard=(OLD/'music_session_guard_v4.c').read_text()
    guard=guard.replace('struct mcs_guard *mcs_bridge_context;',
        'struct mcs_guard *mcs_bridge_context;\nextern volatile uint32_t ms_original_sync_completed;',1)
    old='if(!g->held || g->borrow || g->native_mutation || !actual_mixer_actor(g) ||'
    assert guard.count(old)==1
    guard=guard.replace(old,
        'if(!ms_original_sync_completed || !g->held || g->borrow || g->native_mutation || !actual_mixer_actor(g) ||',1)
    save(BASE/'music_session_guard_sync_v1.c',guard)

    original_builder=OLD/'build_mixer_handoff_v5.py'
    builder=original_builder.read_text()
    builder=builder.replace("out=BASE/'build-v5'","out=BASE/'build-v1'",1)
    builder=builder.replace("ROOT=BASE.parents[1]","ROOT=BASE.parents[1]\nHANDOFF=ROOT/'staging/native-player-mixer-handoff'",1)
    for name in ['audio_session_driver_v4.c','pcm_fifo_session_owner_v4.c',
                 'music_session_guard_v4.h','native_context_v4.c',
                 'pull_bridge_v4.S','memory_output_session_owner_v4.c']:
        builder=builder.replace("BASE/'"+name+"'","HANDOFF/'"+name+"'")
    builder=builder.replace("BASE/'mixer_source_task_v4.c'","BASE/'mixer_source_task_sync_v1.c'")
    builder=builder.replace("BASE/'music_session_guard_v4.c'","BASE/'music_session_guard_sync_v1.c'")
    builder=builder.replace("FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',",
        "FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',BASE/'initializer_sync_bridge_v1.c',BASE/'initializer_sync_bridge_v1.S',")
    builder=builder.replace("'-I',str(BASE),","'-I',str(BASE),'-I',str(HANDOFF),")
    builder=builder.replace('KEEP(*(.text.mh_*))','KEEP(*(.text.ms_*)) KEEP(*(.text.mh_*))',1)
    builder=builder.replace("'source_stack','source_descriptor')",
        "'source_stack','source_descriptor','ms_initializer_sync_bridge','ms_before_original_sync',"
        "'ms_validate_completed_sync','ms_original_sync_completed','ms_sync_entries',"
        "'ms_sync_grants','ms_sync_reuses','ms_sync_rejections','ms_before_result')",1)
    builder=builder.replace("dump(BASE/'build-v5.json'","dump(BASE/'build-v1.json'",1)
    builder=builder.replace('explicit_single_actor_resident_and_wake_fixture=True',
        'original_sync_not_executed_at_compile_time=True,conditional_CONFIG_handoff_before_sync=True,PLAY_closed_until_original_sync_return=True')
    ast.parse(builder)
    save(BASE/'build_mixer_sync_v1.py',builder)
    outputs=[BASE/'mixer_source_task_sync_v1.c',BASE/'music_session_guard_sync_v1.c',
             BASE/'build_mixer_sync_v1.py',BASE/'initializer_sync_bridge_v1.c',BASE/'initializer_sync_bridge_v1.S']
    evidence=dict(all_passed=True,source_sha256={str(p.relative_to(ROOT)):sha(p) for p in
        [Path(__file__).resolve(),original,original_builder,OLD/'music_session_guard_v4.c']},
        generated_sha256={str(p.relative_to(ROOT)):sha(p) for p in outputs},
        compile_executed=False,guest_executed=False,device_io=False,
        new_fourth_call_site_candidate='3B9C54 original46CC7A with originalLR3B9C59',
        original_sync_wait_ack_not_yet_verified=True,full_player_App_or_physical_music=False)
    save(BASE/'source-preparation-v1.json',json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence))

if __name__=='__main__':main()
