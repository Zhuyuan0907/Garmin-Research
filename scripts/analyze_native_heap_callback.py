#!/usr/bin/env python3
"""Exact descriptor query, callback registration and validation; backup only."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

STAGE=ROOT/'staging/native-player-heap-callback'

def main():
    im=RuntimeImage(NativeImage());ranges=[(0x388af4,0x388b22),(0x388804,0x38882e),
        (0x388e92,0x388ec8),(0x388b22,0x388b24)]
    functions={hex(a):cfg(im,a,b)for a,b in ranges}
    patterns={0x388af4:(0x388b20,'push {r3, r4, r5, r6, r7, lr}',0x388b1c,'pop {r3, r4, r5, r6, r7}',0x388b1e),
        0x388804:(0x38882c,'push {r4, r5, r6, lr}',0x388828,'pop {r4, r5, r6}',0x38882a),
        0x388e92:(0x388ec6,'push {r4, r5, r6, lr}',0x388ec2,'pop {r4, r5, r6}',0x388ec4)}
    for entry,(tail,push,pop_pc,pop,lrpop)in patterns.items():
        f=functions[hex(entry)];rows={int(r['address'],16):r for r in f['instructions']}
        assert rows[entry]['instruction']==push and rows[pop_pc]['instruction']==pop
        assert rows[lrpop]['instruction']=='pop {r3}'and rows[tail]['instruction']=='bx r3'
        assert f['unresolved_exits']==[dict(address=hex(tail),reason='Indirect tail or interworking branch',instruction='r3')]
        f['unresolved_exits']=[];f['returns'].append(hex(tail));f['balanced_original_LR_popped_to_r3_return_verified']=True
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x388b0c]['instruction']=='str r4, [r0, #0xc]'
    assert rows[0x388b10]['instruction']=='movs r2, #2'and rows[0x388b12]['instruction']=='orrs r1, r2'
    assert rows[0x38881c]['instruction']=='lsrs r4, r0, #3'and rows[0x38881e]['instruction']=='lsls r4, r4, #3'
    assert rows[0x388ea2]['instruction']=='cmp r0, #4'and rows[0x388eac]['instruction']=='beq #0x388ec0'
    assert rows[0x388ebc]['direct_call']=='0x23d6e8'and im.word(0x388f48)==0x6e5d8002
    source=Path(__file__).resolve();out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=4,functions=functions,descriptor_fields=dict(pointer_and_low3_flags=4,backlink_address=8,callback_pointer=12),
        original_query_masks_low3_flags=True,registration_sets_flag2_without_clearing_other_bits=True,
        native_validation_requires_low3_flags_at_least4_and_backlink_equal_descriptor=True,
        original_invalid_descriptor_fatal_code='0x6e5d8002',
        original_callback_dispatch_release_resize_or_full_allocator_recovered=False,device_io=False,sounds_emitted=False)
    path=STAGE/'heap-callback-static-preflight.json';assert not path.exists(),'Use new static namespace'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(complete_CFGs=4)))

if __name__=='__main__':main()
