#!/usr/bin/env python3
"""Exact MainMenu/PageManager call paths and default settings branch; offline."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    image=RuntimeImage(NativeImage())
    ranges=[(0x40434c,0x405340),(0x405340,0x4053e6),(0x38e696,0x38e6f6),
        (0x38e358,0x38e614),(0x2cabbc,0x2cad0a),(0x2cad0a,0x2cad5e),
        (0x26dd02,0x26e0b0),(0x1f471e,0x1f473c),(0x4a2a4c,0x4a2b14),(0x4a2b14,0x4a2b62),
        (0x1076d8,0x1076f2),(0x2de1f2,0x2de20e),(0x2db540,0x2db584),
        (0x5aee20,0x5aee82),(0x2db4e2,0x2db510),(0x2db510,0x2db540),
        (0x23d6e8,0x23d780),(0x3ec5c6,0x3ec6a2),(0x3ec6aa,0x3ec6ae),
        (0x3b4ba8,0x3b4c34),(0x38e15e,0x38e284),(0x38e2d4,0x38e358),
        (0x353a9c,0x353aa2)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    wait=functions['0x3ec5c6'];wait_rows={int(r['address'],16):r for r in wait['instructions']}
    assert wait['unresolved_exits']==[dict(address='0x3ec6a0',reason='Indirect tail or interworking branch',instruction='r3')]
    assert wait_rows[0x3ec5c6]['instruction']=='push {r0, r1, r2, r3, r4, r5, r6, r7, lr}'
    assert wait_rows[0x3ec69a]['instruction']=='add sp, #0x24'
    assert wait_rows[0x3ec69c]['instruction']=='pop {r4, r5, r6, r7}'
    assert wait_rows[0x3ec69e]['instruction']=='pop {r3}' and wait_rows[0x3ec6a0]['instruction']=='bx r3'
    # Exact balanced frame: pushed LR is popped to r3 and used as the return.
    # The generic helper does not resolve register-return tails on its own.
    wait['unresolved_exits']=[];wait['returns'].append('0x3ec6a0')
    wait['explicit_balanced_stack_pop_r3_original_LR_return_verified']=True
    wrapper=functions['0x3ec6aa']
    assert wrapper['unresolved_exits']==[dict(target='0x3ec5c6',reason='External branch')]
    wrapper['resolved_tail_to_included_CFG']='0x3ec5c6';wrapper['unresolved_exits']=[]
    for entry,f in functions.items():
        assert not f['unresolved_exits']and not f['instruction_limit_reached'],(entry,f['unresolved_exits'])
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x404c36]['direct_call']=='0x546c94'and rows[0x4053be]['direct_call']=='0x40434c'
    assert rows[0x38e6dc]['direct_call']=='0x38e358'
    assert rows[0x26dd2c]['literal_value']=='0x100d'and rows[0x26dd34]['direct_call']=='0x2cad0a'
    assert rows[0x26dd3c]['instruction']=='str r6, [r7, #0x30]'
    assert rows[0x1076e2]['instruction']=='ldr r1, [r1, #0x10]'
    assert rows[0x1076e4]['instruction']=='str r1, [r4]'
    assert image.word(0x107798)==0x101e8080 and image.word(0x107790)==0xf08f94
    assert image.word(0x2db584)==0x34a5614
    assert rows[0x2db572]['instruction']=='str r0, [r4, #0x10]'
    assert rows[0x2db574]['instruction']=='str r0, [r0]'
    assert rows[0x23d77e]['instruction']=='b #0x23d77e'
    assert rows[0x3ec5e6]['direct_call']=='0x23d6e8'
    assert rows[0x3b4c10]['direct_call']=='0x3ec6aa'
    assert rows[0x3b4c2c]['instruction']=='movs r4, #0xff'
    assert image.word(0xba1034)==0x6e5d8016 and image.word(0xba1038)==0xc6d70a
    assert image.word(0x353aa4)==0xf09098 and rows[0x353a9e]['instruction']=='ldr r0, [r1]'
    source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=len(functions),functions=functions,
        PageMainMenu_constructor='0x40434c',constructor_Grid_call='0x404c36',controller='0x405340',
        manager_registration='0x38e696 ->0x38e358',Page_vtable='0xc03f98',
        Page_first20_virtual_entries=[hex(image.word(0xc03f98+4*n))for n in range(20)],
        setting100D_original_negative_read_defaults_field30_to_zero=True,
        execution_budget_stop_PC25456C_is_original_PNG_scanline_filter_not_a_kernel_wait=True,
        GPS_indicator_vtable='0xc0df64',GPS_indicator_RTTI='N3GUI18GpsSignalIndicatorE',
        GPS_satellite_count_provider_veneer='0x4590da',missing_GPS_driver_table_global='0xf429e4',
        GPS_callback_table_slot='0x3c',
        hardware_counter_entry='0x1076d8',hardware_counter_read_PC='0x1076e2',
        hardware_counter_word_address='0x101e8090',hardware_counter_output_written_through_r0=True,
        hardware_counter_status_byte='0xf08f95',
        original_display_list_initializer='0x2db540',display_list_global='0x34a5614',
        original_initializer_constructs_self_linked_sentinel=True,
        native_fatal_code16='0x6e5d8016',native_fatal_code16_text='Cond var used with unowned smphr, r0=task ID, r1=cond, r2=smphr',
        original_audio_pool_condition_wait='0x3b4c10 ->0x3ec6aa ->0x3ec5c6',
        absent_audio_pool_wait_nonzero_original_index_return='0xff',
        original_kernel_clock_entry='0x353a9c',kernel_clock_word='0xf09098',
        original_PNG_filter_dispatcher_computed_branch_unresolved_not_in_complete_CFG_count=True,
        original_PNG_filter_prefix=[dict(address=hex(i.address),instruction=i.mnemonic+' '+i.op_str)
            for i in image.md.disasm(image.read(0x25446a,32),0x25446a)],
        native_controller_or_root_executed=False,device_io=False,sounds_emitted=False,
        limits='Bounded static paths only. No native Page/root return, boot settings/resource map, actual UI thread/display, package acceptance or physical App/music is established.')
    path=ROOT/'staging/native-player-mainmenu/MainMenu-root-settings-preflight.json';path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(complete_CFGs=len(functions),output=str(path.relative_to(ROOT)))))

if __name__=='__main__':main()
