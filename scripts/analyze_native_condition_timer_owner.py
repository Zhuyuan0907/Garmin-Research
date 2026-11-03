#!/usr/bin/env python3
"""Original F090A0 timer-task producer and condition-owner consumer."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    image=RuntimeImage(NativeImage())
    ranges=[(0xf6e48,0xf6e68),(0x353d3c,0x353d58),(0x353ab0,0x353ab6),
            (0x353abc,0x353ac2),(0x353d78,0x353e08)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    initializer=functions['0x353d3c'];rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert initializer['unresolved_exits']==[dict(address='0x353d56',reason='Indirect tail or interworking branch',instruction='r3')]
    assert rows[0x353d3c]['instruction']=='push {r4, lr}'and rows[0x353d52]['instruction']=='pop {r4}'and rows[0x353d54]['instruction']=='pop {r3}'
    initializer['unresolved_exits']=[];initializer['returns'].append('0x353d56')
    initializer['balanced_original_LR_epilogue_verified']=True
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    assert image.word(0xf6ebc)==image.word(0x353d60)==0x2d226e0
    assert image.word(0xf6ec0)==0x353d79 and image.word(0xf6ec4)==0x2d22834
    assert rows[0xf6e60]['instruction']=='strb r1, [r0, #0xe]'and rows[0xf6e64]['instruction']=='strb r1, [r0, #0xf]'
    assert rows[0x353d4a]['direct_call']=='0x358bf8'and rows[0x353d50]['instruction']=='str r0, [r1]'
    assert image.word(0x353d64)==image.word(0x353ab8)==image.word(0x3ec6c0)==0xf090a0
    assert rows[0x353d78]['direct_call']=='0x2fd034'and rows[0x353dc0]['direct_call']=='0x2fcf44'
    assert image.word(0x353ac4)==0x2d226f4 and rows[0x353abe]['instruction']=='movs r1, #0x50'
    priorpath=ROOT/'evidence/firmware-analysis/native-mixer-timer-emulation.json';prior=json.loads(priorpath.read_text())
    assert prior['all_passed']and prior['stock_sha256']==EXPECTED
    script=ROOT/'scripts/emulate_native_mixer_timer.py';assert hashlib.sha256(script.read_bytes()).hexdigest()==prior['script_sha256']
    for p,s in prior['dependency_sha256'].items():assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==s,p
    files={Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py',
        ROOT/'scripts/analyze_native_usb_transition.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',priorpath,script}
    files.update(ROOT/p for p in prior['dependency_sha256'])
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(files)},
        complete_bounded_CFG_count=5,functions=functions,
        timer_descriptor_initializer='0xf6e48',timer_descriptor='0x2d226e0',
        exact_original_descriptor_words=['0x353d79','0x0','0x2d22834','0x10000','0x0'],
        timer_TCB_producer='0x353d3c ->0x358bf8 ->original store353D50',
        timer_TCB_global='0xf090a0',expected_native_timer_TCB=hex((0x2d22834-108)&~7),
        timer_task_entry='0x353d78',timer_event_wait='0x2fd034',timer_event_post='0x2fcf44',
        original_condition_constructor_loads_same_timer_TCB_global='0x3ec572 ->literal3EC6C0 ->F090A0',
        condition_owner_distinct_from_current_thread_required_to_test_contention=True,
        workspace_getter='0x353abc',workspace_return_pointer='0x2d226f4',workspace_return_length=80,
        workspace_getter_semantic_role_not_inferred_from_length_alone=True,
        reused_matching_native_timer_evidence=str(priorpath.relative_to(ROOT)),
        reused_native_timer_source_dependencies_verified=25,reused_prior_timer_route_count=len(prior['routes']),
        prior_timer_harness_bookkeeping_code_patch_not_copied_into_current_MAIN=True,
        native_current_idle_ready_task_context_and_actual_Gui_dispatcher_events_still_unverified=True,
        device_io=False,sounds_emitted=False,
        limits='Five bounded exact original CFGs connect condition owner F090A0 to original timer task producer/descriptor/event wait/post. Two earlier timer routes25 dependencies freshly verified and reused as scoped evidence, not rerun or proof of current GUI scheduling. Earlier timer harness patches construction bookkeeping; current whole-MAIN guarded VM must not copy that patch. Equal fictional current/constructor owner in complete6649 memory controls produces native recursive immediate return, not blocking/event delivery. Native timer ownership and real task/idle/ready/context/event integration still require new runtime evidence.')
    path=ROOT/'staging/native-player-reacquire/condition-timer-owner-static-preflight.json';assert not path.exists()
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=5,timer_owner_global='0xf090a0',prior_timer_dependencies_verified=25)))

if __name__=='__main__':main()
