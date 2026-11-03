#!/usr/bin/env python3
"""Resolve metadata label veneer and the next generic file-open dispatch.

Backup-only bounded CFG analysis. Conditional runtime code is addressed via
the exact startup copy table, not raw bytes at the same numerical offset.
This does not prove VPM/SIG acceptance, initialize driver tables or touch USB.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_audio_registration import sha


class RuntimeImage:
    def __init__(self,stock):
        self.stock=stock;self.md=stock.md
    def read(self,address,length):
        return self.stock.read(self.stock.runtime_to_load(address,length),length)
    def word(self,address):
        return struct.unpack('<I',self.read(address,4))[0]


def wide(image,address):
    raw=image.read(address,256)
    end=next(n for n in range(0,len(raw),2) if raw[n:n+2]==b'\0\0')
    return raw[:end].decode('utf-16le')


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    assert image.word(0x366abc)==0xe51ff004 and image.word(0x366ac0)==0x04401035
    assert image.word(0x448f588)==0xe51ff004 and image.word(0x448f58c)==0x359821
    assert image.word(0x448fd18)==0xe51ff004 and image.word(0x448fd1c)==0x38756b
    fn=trace(image,0x4401034,1200)
    assert fn['unresolved_exits']==[{'address':'0x440112e','reason':'Computed PC; needs switch analysis'}]
    table=list(image.read(0x4401130,13))
    assert table==[29,28,6,27,26,25,24,23,22,21,20,19,18]
    records={int(r['address'],16):r for r in fn['instructions']}
    cases=[]
    for n,offset in enumerate(table):
        target=0x4401132+offset*2
        t=trace(image,target,300)
        assert not t['instruction_limit_reached']
        assert all(r['reason']=='External branch' and r.get('target')=='0x4401154'
                   for r in t['unresolved_exits']),t['unresolved_exits']
        for r in t['instructions']:
            if 'address_value' in r and int(r['address_value'],16)>=0x4401300:
                r['utf16_literal']=wide(image,int(r['address_value'],16))
            records[int(r['address'],16)]=r
        literals=[r['utf16_literal'] for r in t['instructions'] if 'utf16_literal' in r]
        cases.append({'selector':n,'table_entry':offset,'target':hex(target),
                      'display_literals':literals,'instructions':t['instructions']})
    calls={r['direct_call'] for r in records.values() if 'direct_call' in r}
    assert calls=={'0x448f588','0x448fd18'}
    product_ids=[{'address':hex(a),'id':wide(image,a)}
                 for a in range(0x44011cc,0x4401338,28)]
    assert len(product_ids)==13 and product_ids[10]['id']=='006-D0563-00'
    direct_functions={hex(a):trace(image,a,1200) for a in
        (0x31d09a,0x31d032,0x31cfe4,0x1fdc0c,0x24e790,0x359820,0x38756a)}
    assert all(not x['instruction_limit_reached'] and not x['unresolved_exits']
               for x in direct_functions.values())
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in
            (Path(__file__),ROOT/'scripts/analyze_native_sections.py',
             ROOT/'scripts/analyze_sdp_activation.py')},
        'metadata_postprocess':{'arm_veneer':'0x366abc','target_word':'0x04401035',
            'runtime_thumb_function':'0x04401034',
            'load_address':hex(stock.runtime_to_load(0x4401034,4)),
            'conditional_copy_region':next(r for r in stock.copies if r['runtime_start']<=0x4401034<r['runtime_end']),
            'live_copy_flag_or_execution_verified':False,
            'reads_product_identifier_offset':'0x6c2','writes_display_offsets':['0x460','0x4f6'],
            'product_id_literals':product_ids,'cases':cases,'unknown_id_selector':13,
            'unknown_id_returns_without_label_change':True,
            'resolved_switch_address':'0x0440112e','resolved_switch_targets':13,
            'all_reachable_direct_call_targets':sorted(calls),
            'compare_veneer_target':'0x359820','format_veneer_target':'0x38756a',
            'purpose_supported_by_literals_and_calls':'Product-ID based voice display-name normalization',
            'module_checksum_or_signature_enforcement_found_here':False,
            'complete_original_loader_signature_policy_proven_absent':False,
            'instructions':list(sorted(records.values(),key=lambda r:int(r['address'],16)))},
        'generic_file_open':{'entry':'0x31d09a','path_parser':'0x31d032',
            'path_syntax':'1..3 decimal UTF16 drive digits followed by :/; value <=255',
            'file_object_allocator':'0x31cfe4','file_object_bytes':72,
            'open_dispatch':'0x1fdc0c','drive_lookup':'0x24e790',
            'drive_count_address':'0xf001a8','drive_table_pointer_address':'0xf001ac',
            'drive_record_stride':64,'driver_ops_pointer_offset':24,
            'open_indirect_call':'0x1fdcb8','open_function_from_ops_offset':0,
            'truncate_or_additional_op_indirect_call':'0x1fdd74',
            'additional_function_from_ops_offset':24,
            'actual_voice_drive_ops_or_mount_initialization_identified':False,
            'signature_enforcement_verified':False},
        'functions':direct_functions,'device_io':False,'vpm_mounted':False,
        'device_install_candidate':False,
        'limits':'The metadata veneer resolves into conditional startup-backed code and all13 label switch cases. It normalizes display names; this does not settle other VPM/checksum/SIG checks.31D09A is a generic file-open wrapper whose filesystem-specific handlers are indirect and initialized at runtime. Driver registration, actual mounted VPM ops, signature checks and package acceptance remain unverified.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-acceptance-static.json'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'metadata_cases':13,
                     'filesystem_handler_still_indirect':True,'device_io':False}))


if __name__=='__main__':main()
