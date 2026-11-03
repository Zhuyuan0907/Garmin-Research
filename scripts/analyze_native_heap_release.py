#!/usr/bin/env python3
"""Bounded release callback path; heap deallocation and callback target remain open."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    im=RuntimeImage(NativeImage());release=cfg(im,0x388746,0x3887a2);wrapper=cfg(im,0x3887a2,0x3887a6)
    rows={int(r['address'],16):r for r in release['instructions']}
    assert release['unresolved_exits']==[dict(address='0x3887a0',reason='Indirect tail or interworking branch',instruction='r3')]
    assert rows[0x388746]['instruction']=='push {r3, r4, r5, r6, r7, lr}'
    assert rows[0x38879c]['instruction']=='pop {r3, r4, r5, r6, r7}'and rows[0x38879e]['instruction']=='pop {r3}'
    release['unresolved_exits']=[];release['returns'].append('0x3887a0');release['balanced_original_LR_return_verified']=True
    assert wrapper['unresolved_exits']==[dict(target='0x388746',reason='External branch')]
    wrapper['unresolved_exits']=[];wrapper['resolved_tail_to_included_CFG']='0x388746'
    assert rows[0x38876c]['instruction']=='mvns r1, r0'and rows[0x38876e]['instruction']=='lsls r1, r1, #0x1d'
    assert rows[0x388770]['instruction']=='lsrs r1, r1, #0x1e'and rows[0x388772]['instruction']=='bne #0x38877e'
    assert rows[0x388776]['instruction']=='ldr r1, [r4, #0xc]'and rows[0x38877a]['direct_call']=='0x427582'
    assert rows[0x388766]['direct_call']=='0x3008b0'and rows[0x388780]['direct_call']=='0x3009a0'
    ins=next(im.md.disasm(im.read(0x427582,2),0x427582));assert ins.mnemonic=='bx'and ins.op_str=='r1'
    source=Path(__file__).resolve();out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=2,functions={'0x388746':release,'0x3887a2':wrapper},
        callback_branch_requires_flags_bits1_and2_set=True,low3_flag_truth_table=[dict(flags=n,takes_callback=(n&6)==6)for n in range(8)],
        callback_argument_r0='descriptor+4 masked to eight-byte payload pointer',callback_target_r1='descriptor+0C',
        call_trampoline='0x427582 BX r1',callback_pointer_NULL_check_before_indirect_call=False,
        callback_called_after_mutex_unlock_before_relock=True,core_deallocator='0x388676',
        zero_callback_store_with_flags6_does_not_disable_release_indirect_call=True,
        actual_callback_execution_and_deallocator_or_safe_lifetime_verified=False,device_io=False,sounds_emitted=False,
        limits='Static original release path only. Zeroing callback while flags6 remain keeps the indirect-call branch enabled. Actual heap task/critical sections, callback target, deallocator and release/resize lifetime have not executed.')
    path=ROOT/'staging/native-player-heap-callback/heap-release-static-preflight.json';assert not path.exists(),'Use new namespace'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(complete_CFGs=2,release_null_check=False)))

if __name__=='__main__':main()
