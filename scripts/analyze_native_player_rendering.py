#!/usr/bin/env python3
"""Exact stock painting/clipping call paths; backup-only static analysis."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    ranges=[(0x549baa,0x549f24),(0x3766e4,0x376bb8),
        (0x43866e,0x438672),(0x438672,0x438688),
        (0x2db816,0x2db88a),(0x2db88a,0x2db976),
        (0x3857b0,0x38582e),(0x38582e,0x385978),
        (0x4dd93e,0x4ddb00),(0x4de302,0x4deaa0)]
    functions={hex(a):cfg(image,a,b) for a,b in ranges}
    assert all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in functions.values())
    grid={int(r['address'],16):r for r in functions['0x549baa']['instructions']}
    assert grid[0x549bb2]['instruction']=='ldrb r0, [r4, #9]'
    assert grid[0x549ef8]['instruction']=='b #0x549f18'
    assert grid[0x549f1c]['direct_call']=='0x3766e4'
    base={int(r['address'],16):r for r in functions['0x3766e4']['instructions']}
    assert base[0x376780]['instruction']=='ldrb r0, [r0, r5]'
    assert base[0x376b1c]['instruction']=='movs r0, #1'
    assert base[0x376b20]['instruction']=='ble #0x376b28'
    assert base[0x376b26]['instruction']=='bgt #0x376b2c'
    assert base[0x376b3a]['instruction']=='ldr r2, [r0, #8]'
    output=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        functions=functions,complete_bounded_CFG_count=len(functions),
        Grid_normal_mode_branches_to_original_child_painter='0x549f18 -> 0x3766e4',
        base_skips_child_hidden_byte_offset='0x84',
        base_child_paint_requires_positive_clipped_width_and_height=True,
        base_calls_child_virtual_slot2=True,
        canvas_vtable='0xc1943c',canvas_get_clip_virtual9='0x43866f',
        canvas_get_clip_returns_object_plus='0x3c',canvas_reset_clip_virtual10='0x438673',
        canvas_reset_clip_copies_origin_from_object_B4_B8_and_dimensions_78_7C=True,
        rectangle_paint_color_path_calls_ARM_driver='0x3979e4',
        original_Label_cached_bitmap_draw='0x3857b0 -> Canvas virtual14 -> 0x2db976',
        original_Label_bitmap_preparation='0x38582e -> 0x43808c',
        native_font_render_input_calls='0x4de302 -> 0x26659e',
        native_font_render_flags8_branch='0x2665d0 -> 0x13cf46',
        native_font_render_flags8_does_not_require_branch14EC9C=True,
        original_flags8_branch_instructions=[dict(address=hex(i.address),instruction=i.mnemonic+' '+i.op_str)
            for i in stock.instructions(0x2665bc,0x2665e8)],
        original_font_and_GUI_rendering_executed=False,actual_display_verified=False,
        device_io=False,sounds_emitted=False,
        source_sha256={str(Path(__file__).resolve().relative_to(ROOT)):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        limits='Bounded static instruction paths only. Callees/driver are not recursively executed here. Font loading does not prove rasterization, pixels, UI thread/root, modified package acceptance or device display.')
    path=ROOT/'staging/native-player-rendering/stock-draw-preflight.json'
    path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=len(functions),output=str(path.relative_to(ROOT)),device_io=False)))


if __name__=='__main__':main()
