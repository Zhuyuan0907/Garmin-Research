#!/usr/bin/env python3
"""Disambiguate generic FAT files from legacy embedded DSKIMG volumes.

Exact Taiwan MAIN, startup-backed runtime addresses, bounded Thumb CFGs.
No device I/O, RAM probing or writes to a voice package.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_loader import scan_calls
from analyze_sdp_activation import trace


def require(condition,message):
    if not condition: raise ValueError(message)


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    entries=(0x217488,0x2174b2,0x24e968,0x24e790,0x24e83a,
             0x31e60e,0x21b8f0,0x39e998,0x39e9e6,0x3a1318,
             0x2d3166,0xfe648,0xfea50,0xfeb36,0x1e86ce,0x1e8046,
             0x1fb304,0x2fba70,0x2fb988,0x122fbc,0x123f6c,
             0x11d678,0x123920,0x3324b8,0x1fb3a2,0x3c44bc)
    functions={hex(a):trace(image,a,2000) for a in entries}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in functions.values()),'Unresolved bounded CFG')
    def instruction(address, expected):
        row=next(image.md.disasm(image.read(address,4),address,count=1))
        require(row.mnemonic+' '+row.op_str==expected,hex(address))
    instruction(0x21b912,'bl #0x31e60e')
    instruction(0x21b916,'bl #0x39e998')
    instruction(0x39e99e,'bl #0x2174b2')
    instruction(0x31e654,'bl #0x24e968')
    instruction(0x39edd8,'str r0, [r6, #0x18]')
    instruction(0x39eddc,'str r0, [r6, #0x1c]')
    instruction(0x1e899c,'bl #0x1e8046')
    instruction(0xfea9e,'bl #0x1e86ce')
    instruction(0x1fb37e,'bl #0x2fba70')
    instruction(0x1e8082,'bl #0xfeb36')
    instruction(0xfebbc,'bl #0x2d3380')
    instruction(0x1fb3c0,'bl #0x3324b8')
    instruction(0x332514,'bl #0x123920')
    require(image.word(0x39ed84)==0x86df64,'Type descriptor literal differs')
    descriptor=list(struct.unpack('<6I',image.read(0x86df64,24)))
    require(descriptor==[4,0,0x39e9e7,0x3a1a0b,0,0x39ef8b], 'Type1 callbacks differ')
    require(image.word(0x39f1d4)==0x86df7c and image.word(0x39f1d8)==0x86df9c,
            'FAT operation table literals differ')
    file_ops=list(struct.unpack('<8I',image.read(0x86df7c,32)))
    require(file_ops[0]==0x3a1319,'FAT open target differs')
    require(image.read(0xb9decb,7)==b'DSKIMG\0' and image.read(0xb9dec4,7)==b'DSDIMG\0',
            'Container magic literals differ')
    require(image.read(0xb9ded2,8)==b'GARMIN\0\0','Vendor magic differs')
    mapping=list(image.read(0xf00114,99));require(mapping[7]==99,'Expected original7->99 mapping')
    import hashlib
    dependencies={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (Path(__file__),ROOT/'scripts/analyze_native_sections.py',
                               ROOT/'scripts/analyze_native_voice_acceptance.py',
                               ROOT/'scripts/analyze_native_loader.py',
                               ROOT/'scripts/analyze_sdp_activation.py')}
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
         'source_sha256':dependencies,'functions':functions,
         'generic_outer_filesystem':{
             'initializer':'0x21b8f0','generic_file_table_init':'0x31e60e',
             'drive_registry_init':'0x24e968','drive_count_global':'0xf001a8',
             'drive_array_pointer_global':'0xf001ac','drive_record_bytes':64,
             'boot_drive_array':'0x1057888','boot_drive_count':2,
             'type_registry':'0x1057810','type_record_bytes':24,'type_count':5,
             'type_register':'0x2174b2','type1_setup':'0x39e998',
             'type1_descriptor':'0x86df64','type1_words':[hex(v) for v in descriptor],
             'type1_mount':'0x39e9e6','type1_file_ops':'0x86df7c',
             'type1_file_open':'0x3a1318','type1_other_ops':'0x86df9c',
             'driver_file_ops_pointer_offset':24,
             'file_ops_targets':[hex(v) for v in file_ops],
             'purpose':'Generic FAT-backed external files; not the embedded DLL member filesystem',
             'actual_device_drive_tables_read':False},
         'mapped_region_clarification':{
             'entry':'0x2d3166','opens_whole_voice_filename_with_modes':['0x23','0x21'],
             'generic_open':'0x31d09a','legacy_drive_translation':'0xfe648',
             'mapping_array':'0xf00114','array_entries':99,
             'original_drive7_maps_to_region99':True,
             'file_cache_wrapper':'0xfea50',
             'actual_remount_before_cache_filename':'0x1e86ce',
             'DSKIMG_parser_called_by_actual_remount':'0x1e8046',
             'earlier_2D3166_mount_label_was_only_mapped_file_setup':True,
             'emulation_does_not_execute_outer_generic_open_or_region_setup':True},
         'embedded_container_filesystem':{
             'context':'0xf7b3dc','volume_array_pointer_offset':28,
             'base_drive_count_offset':32,'volume_record_bytes':116,
             'volume_partitions_per_base_drive':4,'file_object_bytes':44,
             'parser':'0x1e8046','supported_magic':['DSKIMG','DSDIMG'],
             'sector_size_required':512,'vendor_magic':'GARMIN',
             'sector_read_wrapper':'0xfeb36','mapped_region_byte_read':'0x2d3380',
             'file_open_mutex_wrapper':'0x2fba70','file_open':'0x2fb988',
             'ASCII_8dot3_name_parser':'0x122fbc','directory_search':'0x123f6c',
             'directory_sector_cache':'0x11d678','file_allocation_translation':'0x123920',
             'byte_read':'0x3324b8','loader_fopen_callback':'0x1fb304',
             'loader_fread_callback':'0x1fb3a2','path_syntax':'ASCII decimal drive:name.ext; uppercase8+3 padded directory key',
             'synthetic_emulation_drive_mapping_uses_original_slot7':True,
             'actual_live_voice_slot_or_full_voice_selection_not_verified':True},
         'normal_region_direct_call_scan':scan_calls(stock,{0x2174b2,0x24e968,0x31e60e,0x1e8046}),
         'signature_enforcement_verified':False,'device_io':False,
         'device_install_candidate':False,
         'limits':'Bounded static Thumb control flow in exact startup-backed regions. Type1 FAT registration and the distinct legacy embedded DSKIMG path are identified. Direct scan covers normal Thumb BL only; conditional/ARM/indirect callers are not excluded. Live inventories, outer device file open, high-level metadata/selection/checksum/SIG policy and accepted modified packages remain unverified.'}
    path=ROOT/'evidence/firmware-analysis/native-vpm-filesystem-static.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'functions':len(functions),
                      'FAT_open':hex(file_ops[0]),'embedded_DSK_parser':'0x1e8046','device_io':False}))


if __name__=='__main__':main()
