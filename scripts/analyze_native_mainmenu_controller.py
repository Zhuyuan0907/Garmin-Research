#!/usr/bin/env python3
"""Recover exact original MainMenu lookup/create/register controller branches."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    image=RuntimeImage(NativeImage())
    ranges=[(0x405340,0x4053e6),(0x38ee28,0x38eeec),(0x2da69e,0x2da6e0),(0x389970,0x389976)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    for entry,function in functions.items():
        assert not function['unresolved_exits']and not function['instruction_limit_reached'],entry
    rows={int(row['address'],16):row for function in functions.values()for row in function['instructions']}
    assert image.word(0x405458)==0x404560
    raw=image.read(0x404560,26);name=raw.decode('utf-16le').rstrip('\0')
    assert name=='PageMainMenu'
    assert rows[0x405344]['instruction']=='movs r0, #0'
    assert rows[0x40537a]['instruction']=='ldr r0, [sp]'
    assert rows[0x40537e]['instruction']=='beq #0x405382'
    assert rows[0x405380]['instruction']=='movs r4, #0'
    assert rows[0x405384]['instruction']=='bne #0x4053dc'
    assert rows[0x4053b4]['direct_call']=='0x3954cc'and image.word(0x40545c)==0x3f04
    assert rows[0x4053be]['direct_call']=='0x40434c'and rows[0x4053d2]['direct_call']=='0x38e696'
    assert rows[0x4053d8]['direct_call']=='0x2da69e'
    assert rows[0x38ee94]['instruction']=='adds r1, #0xff'and rows[0x38ee96]['instruction']=='adds r1, #0xd'
    assert rows[0x38ee98]['direct_call']=='0x366ba4'and rows[0x38eea0]['direct_call']=='0x36710a'
    assert rows[0x38eee4]['instruction']=='str r7, [r0]'and rows[0x38eee6]['instruction']=='str r7, [r0, #4]'
    assert rows[0x2da6a6]['instruction']=='strb r0, [r6]'
    assert rows[0x2da6ae]['direct_call']=='0x4565c6'
    source=Path(__file__).resolve();main=ROOT/'evidence/firmware-analysis/main_02bd.bin'
    prior=ROOT/'staging/native-player-mainmenu/MainMenu-root-settings-preflight.json'
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [source,main,prior]},
        complete_bounded_CFG_count=4,functions=functions,
        original_controller='0x405340',controller_input_object_argument_used=False,
        lookup_key_address='0x404560',lookup_key_UTF16=name,original_manager_getter='0x393a2c',
        original_manager_name_lookup='0x38ee28',lookup_page_name_member_offset=0x10c,
        lookup_no_match_clears_original_8byte_output_holder=True,
        matching_existing_Page_branch_skips_new_ctor_registration_and_2DA69E=True,
        absent_Page_branch_allocates_bytes=0x3f04,original_general_ctor='0x40434c',
        original_root_registration='0x38e696',original_registration_arguments_category_and_optional_parent=[0,0],
        post_registration_original_entry='0x2da69e',post_registration_original_call='0x4565c6',
        native_controller_full_final_guards_foreground_or_device_App_verified=False,
        device_io=False,sounds_emitted=False,
        limits='Four bounded exact static CFGs and native UTF16 key only. No public App API, actual boot/kernel/foreground, accepted package, Page lifetime or audio semantics established. Lookup reads Page+10C name via original string routines; full native lookup/registration execution remains separate development work.')
    path=ROOT/'staging/native-player-mainmenu-controller/controller-static-preflight.json';path.parent.mkdir(exist_ok=True)
    assert not path.exists(),'Use a new proof namespace'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=4,lookup_key=name,output=str(path.relative_to(ROOT)))))

if __name__=='__main__':main()
