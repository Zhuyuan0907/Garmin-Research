#!/usr/bin/env python3
"""Bounded settings initializer, records, cursor, reader and flash wrappers."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

STAGE=ROOT/'staging/native-player-settings-writer'

def main():
    im=RuntimeImage(NativeImage())
    ranges=[(0x2cbd16,0x2cc2a4),(0x2ca76c,0x2ca82c),(0x2ca82c,0x2caaea),
        (0x2ca6d0,0x2ca716),(0x2ca16a,0x2ca18a),(0x2ca716,0x2ca76c),
        (0x2cab14,0x2cabbc),(0x108c08,0x108c2e),(0x2cabbc,0x2cad0a),
        (0x102598,0x1025bc),(0x1025c2,0x1025f8),(0x102602,0x10262e)]
    functions={hex(a):cfg(im,a,b)for a,b in ranges}
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x2cc0f4]['direct_call']=='0x2ca76c'
    assert rows[0x2ca816]['instruction']=='str r4, [r7, #0x10]'
    assert rows[0x2ca8a4]['instruction']=='ldrh r1, [r0]'
    assert rows[0x2ca9b4]['direct_call']=='0x2ca6d0'
    assert rows[0x2ca9f2]['direct_call']=='0x2ca16a'
    assert rows[0x102626]['direct_call']=='0x26a43a'
    assert im.word(0x2cbf3c)==0xf06ef4
    source=Path(__file__).resolve()
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=len(functions),functions=functions,
        original_initializer='0x2cbd16',original_cursor_initializer='0x2ca76c',
        original_setter='0x2ca82c',original_record_reader='0x2cabbc',
        original_header_commit='0x2ca16a',settings_global='0xf06ef4',
        fields=dict(ready_byte=3,logical_sector_count_u16=6,physical_sector_count_u16=8,
            writer_cursor_pointer=16,current_logical_index=20,free_bytes=24),
        lower_storage_bank=13,lower_inventory='0x26a2d0',lower_sector_geometry='0x26a40a',
        lower_erase='0x26a3e2',lower_program='0x26a43a',auxiliary_bank34_read='0x26a300',
        erased_first_header_13bit_length_align4_can_skip8192_before_state_probe=True,
        physical_geometry_board_driver_or_kernel_mutex_ownership_recovered=False,
        callees_and_indirect_calls_not_recursively_recovered=True,device_io=False,sounds_emitted=False)
    p=STAGE/'settings-writer-static-preflight.json';assert not p.exists(),'Use new namespace'
    p.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(complete_CFGs=len(functions))))

if __name__=='__main__':main()
