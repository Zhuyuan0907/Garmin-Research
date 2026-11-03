#!/usr/bin/env python3
"""Record stock voice-selection/mount/metadata paths; backup-only analysis.

This does not mount a real VPM, run its filesystem checker or determine
signature enforcement. Voice IDs and filenames use UTF-16 code units.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR
from analyze_sdp_activation import trace


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wide(image, address, limit=255):
    raw=image.read(address,2*limit)
    end=next((n for n in range(0,len(raw),2) if raw[n:n+2]==b'\0\0'),len(raw))
    return raw[:end].decode('utf-16le')


def main():
    image=NativeImage()
    entries=(0x240498,0x2741f4,0x273abc,0x2745cc,0x273e52,
             0x2747cc,0x1d8514,0x2d3166,0x275590,0x274acc,
             0x274a8a,0x3598b8,0x2754ca,0x1fb304)
    functions={hex(a):trace(image,a,1600) for a in entries}
    for a in entries:
        assert not functions[hex(a)]['instruction_limit_reached'],hex(a)
        for row in functions[hex(a)]['instructions']:
            if 'address_value' in row:
                address=int(row['address_value'],16)
                raw=image.read(address,4)
                if raw[1]==0 and raw[3]==0:
                    row['utf16_string']=wide(image,address)
    def instruction(address, expected):
        row=next(i for i in image.instructions(address,address+4) if i.address==address)
        assert row.mnemonic+' '+row.op_str==expected,(hex(address),row.mnemonic,row.op_str)
    instruction(0x2405ec,'ldrb r1, [r4, #6]')
    instruction(0x2405ee,'ldr r0, [r4, #8]')
    instruction(0x2405f0,'bl #0x240498')
    instruction(0x274216,'movs r2, #0x14')
    instruction(0x27421a,'bl #0x3598b8')
    instruction(0x3598be,'adds r1, r1, #2')
    instruction(0x3598c0,'adds r0, r0, #2')
    instruction(0x3598c2,'subs r2, r2, #1')
    instruction(0x3598c8,'ldrh r3, [r1]')
    instruction(0x3598cc,'strh r3, [r0]')
    instruction(0x273ada,'movs r2, #0xff')
    instruction(0x273ade,'bl #0x3598b8')
    assert wide(image,0x275814)=='<dll_chksum>'
    assert wide(image,0x2757f8)=='</dll_chksum>'
    assert wide(image,0x2757f0)=='%i'
    assert image.word(0x275830)==0x764
    assert image.word(0x275c4c)==0x2758ac
    assert image.read(0x2758ac,12)==b'dllinfo.txt\0'
    assert image.word(0x23c4d8)==IMAGE and image.word(0x23c4d4)==DESCRIPTOR
    zero=next(r for r in image.zeros if not r['conditional'] and
              r['runtime_start']<=IMAGE and DESCRIPTOR+52<=r['runtime_end'])
    dispatcher=[{'address':hex(i.address),'instruction':i.mnemonic+' '+i.op_str}
                for i in image.instructions(0x2405ec,0x2405fa)]
    evidence=ROOT/'evidence/firmware-analysis/tts-vpm-containers.json'
    rows=json.loads(evidence.read_text())['containers']
    voices=[]
    for row in rows:
        if not row['native_module_container']:continue
        module=row['module'];used=module['image_header_ram_bytes']
        voices.append({'voice_package':row['file'],'original_file_bytes':module['image_header_file_bytes']
                      if 'image_header_file_bytes' in module else row['files']['DLLIMG.BIN']['size'],
                      'original_ram_bytes':used,'reservation_headroom_bytes':0x300000-used,
                      'extracted_binary':module['extracted_binary'],
                      'binary_sha256':row['files']['DLLIMG.BIN']['sha256']})
    dep_paths=(Path(__file__),ROOT/'scripts/analyze_native_sections.py',
               ROOT/'scripts/analyze_native_loader.py',ROOT/'scripts/analyze_sdp_activation.py',evidence)
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in dep_paths},
      'functions':functions,'dispatcher_selection_case':dispatcher,
      'voice_selection_message':{'opcode_offset':0,'opcode_bytes':2,'selection_opcode':1,
          'slot_offset':6,'slot_bytes':1,'voice_index_offset':8,'voice_index_bytes':4,
          'caller':'0x2405f0','target':'0x240498','ui_caller_or_user_app_button_identified':False},
      'selection_to_mount_to_loader':[
          {'entry':'0x240498','action':'Resolve voice index to volume ID with2741F4; require nonempty ID, successful2747CC, then DLL initializer23C3C4 return11. Store voice index atF095AC+4; failure storesFF.'},
          {'entry':'0x2741f4','action':'Under0344CF00 mutex, look up voice record handle273A84, lock388804, copy20 UTF16 code units fromrecord+0x3FC, unlock.'},
          {'entry':'0x2747cc','action':'Find ID2745CC/273E52; copy filename273ABC; nonempty filename goes to1D8514. Returns mount result.222A34 failure emits diagnostic409 without clearing saved nonzero return.'},
          {'entry':'0x1d8514','action':'Slot recordF09638+0x20+slot*42, byte+8 mapping index.2D3166(0,index,filename) must return0; translated driveFE648 must differ from80; thenFEA50(drive,1).'},
          {'entry':'0x2d3166','action':'Mapped region manager uses0105EAA4 mutex;0105E424 states stride2 and0105E624 regions stride36; calls31D09A on filename in modes23/21. Lower filesystem checker not analyzed/executed here.'}],
      'voice_record_fields':{'filename':{'offset':0,'copied_utf16_units':255,'maximum_copied_bytes':510},
          'volume_id':{'offset':0x3fc,'copied_utf16_units':20,'maximum_copied_bytes':40,
                       'copy_is_16_bit_not_byte_memcpy':True},
          'dll_metadata_checksum':{'offset':0x764,'parse_format':'%i','parser_call':'0x27544a',
                                   'tag':'<dll_chksum>','checksum_enforcement_verified':False}},
      'dllinfo_parser':{'entry':'0x275590','file':'dllinfo.txt','file_name_address':'0x2758ac',
          'metadata_parser':'0x274acc','tag_finder':'0x274a8a',
          'checksum_tag_value_stored_in_record_not_acceptance_proof':True,
          'license_helper':'0x2754ca','license_helper_uses_unl_not_dllimg_sig':True,
          'metadata_postprocess_arm_call':'0x366abc','postprocess_semantics_verified':False},
      'fixed_original_dll_reservation':{'start':IMAGE,'end':DESCRIPTOR,'bytes':0x300000,
          'descriptor_start':DESCRIPTOR,'covered_by_original_unconditional_startup_zero':zero,
          'not_inferred_from_unused_global_bss':True,'live_ram_read_or_physical_ram_capacity_verified':False},
      'voices':voices,'device_io':False,'vpm_mounted':False,'signature_enforcement_verified':False,
      'device_install_candidate':False,
      'limits':'Bounded static Thumb CFG traces; indirect UI callers, lower31D09A checker and ARM366ABC semantics remain unknown. DLL metadata CRC field exists, but no signature/acceptance conclusion. No VPM changes, flash or native execution.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-mount-static.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'functions':len(entries),
                     'voice_id_utf16_units':20,'voice_id_bytes':40,'device_io':False}))


if __name__=='__main__':main()
