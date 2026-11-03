#!/usr/bin/env python3
"""Original MainMenu caller and stock compressed-resource buffer provenance."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    stock=NativeImage();image=RuntimeImage(stock)
    ranges=[(0x405340,0x4053e6),(0x11a254,0x11a27e),(0x18af10,0x18b060)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x4053b2]['literal_value']=='0x3f04' and rows[0x4053be]['direct_call']=='0x40434c'
    assert rows[0x4053d2]['direct_call']=='0x38e696'
    assert rows[0x18afd8]['instruction']=='adds r5, #0xff'
    assert rows[0x18afda]['instruction']=='lsls r1, r1, #0xd'
    assert rows[0x18afe2]['direct_call']=='0x36d2a2'
    assert rows[0x11a25c]['instruction']=='adds r0, r0, #4'
    assert rows[0x11a262]['direct_call']=='0x38853c'
    strings=[r['string']for r in functions['0x18af10']['instructions']if 'string'in r]
    assert 'zlib memory error'in strings and 'zlib version error'in strings
    xrefs=[]
    for region in stock.copies:
        if region['runtime_start']not in [0x50000,0x04400000]:continue
        data=stock.read(region['load_start'],region['size']);words=struct.unpack('<'+'H'*(len(data)//2),data)
        for n,h in enumerate(words[:-1]):
            following=words[n+1]
            if h&0xf800==0xf000 and following&0xf800==0xf800:
                disp=((h&2047)<<12)|((following&2047)<<1)
                if disp&0x400000:disp-=0x800000
                address=region['runtime_start']+2*n;target=address+4+disp
                if target in [0x40434c,0x41cc46]:
                    instructions=list(image.md.disasm(image.read(address,4),address,count=1))
                    assert len(instructions)==1 and instructions[0].mnemonic=='bl'
                    xrefs.append(dict(call_site=hex(address),target=hex(target),
                        instruction=instructions[0].mnemonic+' '+instructions[0].op_str,
                        candidate_only_not_recovered_caller_CFG=True))
    source=Path(__file__).resolve();result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=3,functions=functions,original_MainMenu_caller='0x405340',
        original_constructor_call='0x4053be',original_Page_allocation_bytes=0x3f04,
        original_manager_root_registration_call='0x4053d2 ->0x38e696',actual_root_registration_executed=False,
        compressed_resource_buffer_original_entries=['0x18afe2','0x36d2a2','0x11a254'],
        buffer_requested_bytes=8196,allocator_caller='0x11a266',
        compression_function_original_strings=strings,
        historical_XML_buffer_key_names_do_not_identify_an_XML_parser=True,
        scanned_BL_candidates=xrefs,device_io=False,sounds_emitted=False,
        limits='Bounded static call paths.8192+4 buffer is original compressed-stream storage; do not infer XML from prior variable names. MainMenu constructor/caller/root and actual boot GIR placement have not executed. Raw BL scan also covers data in code-copy regions; candidates require enclosing caller CFG before a boot claim.')
    path=ROOT/'staging/native-player-resources/resource-cache-and-MainMenu-caller-preflight.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=3,Page_allocation_bytes=0x3f04,BL_candidates=xrefs)))

if __name__=='__main__':main()
