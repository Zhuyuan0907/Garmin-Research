#!/usr/bin/env python3
"""Exact resource-reference ABI, appended stock GIR inventory and MainMenu CFG.

Backup only. Does not claim a boot resource inventory, visible icon or App.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct
from analyze_native_sections import NativeImage,ROOT,EXPECTED,BASE
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

STAGE=ROOT/'staging/native-player-resources'
RESOURCE_LOAD=0x114d828

def main():
    stock=NativeImage();image=RuntimeImage(stock)
    ranges=[(0x3894ac,0x3894b4),(0x3894b4,0x3894f0),(0x3894f0,0x389530),
        (0x389530,0x389544),(0x389544,0x389556),(0x389556,0x38957a),
        (0x38957a,0x3895b6),(0x3895b6,0x3895c2),(0x3895c2,0x3895e8),
        (0x1c853a,0x1c8560),(0x41b15a,0x41b198),(0x41b198,0x41b1c2),
        (0x41c298,0x41c3da),(0x41c3da,0x41c694),(0x41d31c,0x41d39a),
        (0x41c91c,0x41c944),(0x41cc46,0x41ccd8),(0x40434c,0x405340)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    for a,f in functions.items():
        assert not f['unresolved_exits'] and not f['instruction_limit_reached'],(a,f['unresolved_exits'])
    ctor={int(r['address'],16):r for r in functions['0x40434c']['instructions']}
    assert ctor[0x40435c]['literal_value']=='0xc03f98'
    assert ctor[0x404c36]['direct_call']=='0x546c94'
    assert ctor[0x404c30]['literal_value']=='0x39b0'
    rtti=image.word(0xc03f98-4);name=image.read(image.word(rtti+4),64).split(b'\0')[0].decode()
    assert name=='N3GUI12PageMainMenuE'
    length=stock.word(RESOURCE_LOAD+0x1c);raw=stock.read(RESOURCE_LOAD,length)
    payload_length=stock.word(RESOURCE_LOAD+0x14);payload=stock.read(RESOURCE_LOAD,payload_length)
    assert raw[:8]==b'gir\0\0\0\0\0' and struct.unpack_from('<I',raw,8)[0]==19
    section=struct.unpack_from('<I',raw,0x20)[0]
    assert raw[section:section+8]==b'girimg\0\0'
    _,bucket_base,bucket_bytes,count,buckets=struct.unpack_from('<5I',raw,section+8)
    assert bucket_bytes==buckets*4 and count==3503 and buckets==2048
    entries={};chains=[]
    for bucket in range(buckets):
        offset=struct.unpack_from('<I',raw,bucket_base+4*bucket)[0];seen=set()
        while offset:
            assert offset not in seen and offset+168<=len(raw)
            seen.add(offset)
            values=struct.unpack_from('<42I',raw,offset)
            token,next_offset=values[:2]
            assert token%buckets==bucket
            assert offset not in entries
            variants=[dict(width=values[(0x10+76*v)//4],height=values[(0x14+76*v)//4],
                metadata_words=list(values[(0x18+76*v)//4:(0x18+76*v+60)//4]),
                locator=hex(values[(0xa0+4*v)//4]))for v in range(2)]
            entries[offset]=dict(offset=hex(offset),hash=hex(token),variants=variants)
            offset=next_offset
        if seen:chains.append(dict(bucket=bucket,entries=len(seen)))
    # Header's declared count differs from live bucket reachability. Preserve
    # both; do not call the linked inventory the entire declared resource set.
    assert len(entries)==3426
    known_hash=0x8a56eac
    selected=next(r for r in entries.values()if int(r['hash'],16)==known_hash)
    source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        functions=functions,complete_bounded_CFG_count=len(functions),
        ResourceRef_size_bytes=8,ResourceRef_fields=['hash32','owned_ASCII_name_pointer'],
        original_hash_ctor='0x3894ac',original_name_ctor='0x3894b4',
        original_copy='0x3894f0',original_copy_ctor='0x389530',original_destructor='0x389544',
        original_name_to_hash_conversion='0x389556',original_resolve='0x3895c2',
        only_word1_is_dynamically_owned=True,word0_is_not_a_constant_ASCII_pointer=True,
        old_player_constant_pointer_is_an_unresolved_numeric_resource_hash=True,
        old_emulation_proofs_preserved_not_semantic_icon_success=True,
        general_PageMainMenu=dict(original_constructor_entry='0x40434c',vtable='0xc03f98',
            RTTI=hex(rtti),typename=name,embedded_Grid_offset='0x39b0',
            Grid_constructor_call_site='0x404c36',call_site_is_not_constructor_entry=True,
            original_constructor_executed=False,actual_root_controller_executed=False),
        appended_GIR=dict(load_address=hex(RESOURCE_LOAD),directory_bytes=length,
            directory_SHA256=hashlib.sha256(raw).hexdigest(),source_bytes=payload_length,
            source_SHA256=hashlib.sha256(payload).hexdigest(),format_version=19,
            outside_verified_startup_copy_regions=True,image_section_offset=hex(section),
            image_bucket_count=buckets,image_entry_count_declared=count,
            image_entry_count_bucket_reachable=len(entries),entry_bytes=168,
            variant_bytes=76,descriptor_output_bytes=84,chains=chains,entries=list(entries.values()),
            original_MainMenu_selected_hash=selected),
        device_io=False,sounds_emitted=False,native_resource_registration_executed=False,
        native_nonempty_icon_rendering_verified=False,
        limits='Static exact backup analysis. Appended GIR is not mapped by startup copies. Boot registration location, live resource inventory, image decoding/rendering, general Page root/controller and accepted modified package are unverified. Historical CString wording and404C36 constructor shorthand are corrected, not rewritten.')
    STAGE.mkdir(exist_ok=True);target=STAGE/'resource-ABI-and-MainMenu-preflight.json'
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(target.relative_to(ROOT)),complete_CFGs=len(functions),
        resource_bytes=length,image_entries_declared=count,image_entries_reachable=len(entries),
        selected=selected,general_PageMainMenu=result['general_PageMainMenu'])))

if __name__=='__main__':main()
