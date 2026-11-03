#!/usr/bin/env python3
"""Original condition constructor/wait ownership gate; offline static evidence."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    image = RuntimeImage(NativeImage())
    ranges = [(0x3ec540,0x3ec588),(0x3ec5c6,0x3ec6a2),(0x3ec6a2,0x3ec6aa),
              (0x6048a4,0x6048ba),(0x6048c8,0x6048d4),(0x358d24,0x358d34)]
    functions = {hex(a):cfg(image,a,b) for a,b in ranges}
    rows = {int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    for entry,tail,push,pops in [
        ('0x3ec540',0x3ec586,'push {r4, r5, r6, lr}',
         [(0x3ec582,'pop {r4, r5, r6}'),(0x3ec584,'pop {r3}')]),
        ('0x3ec5c6',0x3ec6a0,'push {r0, r1, r2, r3, r4, r5, r6, r7, lr}',
         [(0x3ec69a,'add sp, #0x24'),(0x3ec69c,'pop {r4, r5, r6, r7}'),(0x3ec69e,'pop {r3}')])]:
        f=functions[entry]
        assert rows[int(entry,16)]['instruction']==push
        assert f['unresolved_exits']==[dict(address=hex(tail),reason='Indirect tail or interworking branch',instruction='r3')]
        assert all(rows[a]['instruction']==text for a,text in pops) and rows[tail]['instruction']=='bx r3'
        f['unresolved_exits']=[];f['returns'].append(hex(tail))
        f['explicit_balanced_frame_original_LR_popped_to_r3_verified']=True
    wrapper=functions['0x3ec6a2']
    assert wrapper['unresolved_exits']==[dict(target='0x3ec5c6',reason='External branch')]
    wrapper['unresolved_exits']=[];wrapper['resolved_tail_to_included_CFG']='0x3ec5c6'
    assert all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in functions.values())
    assert rows[0x3ec55e]['direct_call']==rows[0x3ec566]['direct_call']=='0x3008a0'
    assert rows[0x3ec56e]['direct_call']=='0x3009a0' and rows[0x3ec578]['direct_call']=='0x300ae4'
    assert rows[0x3ec57e]['direct_call']=='0x21b6dc'
    assert rows[0x3ec5ce]['direct_call']=='0x358d24'
    assert rows[0x3ec5d8]['instruction']=='ldr r0, [r5, #8]' and rows[0x3ec5da]['instruction']=='cmp r0, r4'
    assert rows[0x3ec5dc]['instruction']=='beq #0x3ec5ea' and rows[0x3ec5e6]['direct_call']=='0x23d6e8'
    assert rows[0x6048ce]['direct_call']=='0x3ec6a2' and rows[0x3ec6a4]['instruction']=='mvns r2, r2'
    assert image.word(0x3ec6c0)==0xf090a0 and image.word(0x3ec6c4)==0x6e5d8016
    stage=ROOT/'staging/native-player-dispatcher-bootstrap'
    probe_path=stage/'unowned-condition-failure.json';probe=json.loads(probe_path.read_text())
    fatal=probe['native_fatal_entries'][-1]
    assert fatal['caller']=='0x3ec5ea' and fatal['arguments'][0:2]==['0x6e5d8016','0x2']
    assert len(probe['completed_cases'])==5 and not probe['all_final_guards_passed']
    files=[Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',
           ROOT/'scripts/analyze_native_voice_acceptance.py',ROOT/'scripts/analyze_native_usb_transition.py',
           ROOT/'evidence/firmware-analysis/main_02bd.bin',probe_path]
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        complete_bounded_CFG_count=6,functions=functions,
        original_condition_constructor='0x3ec540',original_condition_wait='0x3ec5c6',
        original_unbounded_wait_wrapper='0x3ec6a2',original_thread_identity_getter='0x358d24',
        condition_constructor_thread_pointer_global='0xf090a0',
        condition_constructor_thread_pointer_literal='0x3ec6c0',
        neighbouring_literal_3EC6C4_is_error_code_not_thread_pointer=True,
        native_owner_gate='Original3EC5D8 loads semaphore+8;3EC5DA compares it with original358D24 identity; mismatch enters fatal23D6E8 at3EC5E6.',
        original_condition_constructor_IRQ_restore_before_return=True,
        native_fatal_captured_before_unconditional_loop=fatal,
        failed_six_control_suite_kept_with_five_completed_cases=True,
        original_mutex_lock_thread_owner_and_wait_schedule_not_recovered=True,
        real_boot_event_dispatch_controller_completion_safe_lifetime_or_device_App_verified=False,
        device_io=False,sounds_emitted=False,
        limits='Six bounded original CFGs, exact balanced LR-return epilogues and original mutex owner rejection. Native3EC540 IRQ restore precedes return. Native3EC6A2 requests indefinite wait, distinct from scoped absent audio-pool3EC6AA failure. No owner field patched, no simulated successful wait/event or dispatcher completion. Real kernel scheduler, thread ownership and initialization order remain open. Six-control runtime suite73611 remains failed; five partial cases are not a full guard pass.')
    path=stage/'condition-owner-static-preflight.json';assert not path.exists()
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=6,original_owner_gate='0x3ec5d8',failed_runtime_session=73611)))

if __name__=='__main__':main()
