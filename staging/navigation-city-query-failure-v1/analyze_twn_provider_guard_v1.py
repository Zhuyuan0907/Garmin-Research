#!/usr/bin/env python3
"""Bounded read-only selection proof for exact Taiwan HWID1352/SW800 MAIN.

This is static instruction evidence. It neither substitutes the filesystem/map
enumerator nor claims a physical address query has executed successfully.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

HERE = Path(__file__).resolve().parent
im = NativeImage()
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def rd(address, length):
    try:
        load = im.runtime_to_load(address, length)
    except ValueError:
        load = address
    return im.read(load, length)


def word(address):
    return struct.unpack('<I', rd(address, 4))[0]


def ins(start, end):
    return [dict(pc=hex(i.address), bytes=i.bytes.hex(),
                 instruction=i.mnemonic + ' ' + i.op_str)
            for i in cs.disasm(rd(start, end - start), start)]


def exact(address, raw):
    found = rd(address, len(bytes.fromhex(raw))).hex()
    if found != raw:
        raise ValueError(f'Original instruction mismatch {address:#x}: {found}')
    return dict(address=hex(address), actual_bytes=found, checked=True)


def main():
    # Real ARM veneers, not guessed function names or patched destinations.
    veneers = []
    for address, target in [(0x448F6E8, 0x3F01B7),
                            (0x448E768, 0x32DEFD),
                            (0x448EF78, 0x3F019F),
                            (0x448EDB8, 0x3F025F),
                            (0x448EDA8, 0x3F022F)]:
        exact(address, '04f01fe5')
        if word(address + 4) != target:
            raise ValueError('Veneer target mismatch')
        veneers.append(dict(address=hex(address), arm_opcode='e51ff004',
                            readonly_target=hex(target)))
    asserts = [exact(a, b) for a, b in [
        (0x44144D2, 'a348'),       # literal950 ->r0
        (0x44144D4, '7af048e9'),   # real codepage helper veneer
        (0x32DF7C, '208d'),       # ldrh r0,[r4,#28]
        (0x32DF7E, '0899'),       # ldr r1,[sp,#20], savedrequestedcp
        (0x32DF80, '8842'),       # cmp r0,r1
        (0x32DF82, '30d1'),       # bne cleanup/nextmap
        (0x2CC4EA, '1522'),       # fileoffset0x15
        (0x2CC4FC, '188d'),       # firsthalfword of read8bytes
        (0x2CC4FE, '2885'),       # ctxcodepage+28
        (0x440DD42, '0128'),      # country/platformglobal==1 branch
        (0x440DD54, '0228'),      # ==2 required forTwnctor
        (0x440DD60, 'fff774ff'),  # exactTwnctorcall
    ]]
    if word(0x4414760) != 950 or word(0x4414764) != 1252:
        raise ValueError('Codepage literals mismatch')
    if rd(0x2CC86C, 5) != b'.MDR\0' or rd(0x32E028, 5) != b'.SRT\0':
        raise ValueError('Extension literal mismatch')
    if word(0x440DF10) != 0x5431A94:
        raise ValueError('Factory global pointer mismatch')
    if word(0x440DF08) != 0x47030C8:
        raise ValueError('Twn vtable literal mismatch')

    # Region predicatecase0 is a numeric fourrectangle test. Geographic names
    # below are an interpretation using semicircle conversion, not a hook or
    # an executed liveGPS/sourcequery. Its original signed comparisons are
    # strict on all four rectangle edges.
    if word(0x3F0274) != 0x8AB734:
        raise ValueError('Case0rectangle pointer mismatch')
    rects = [struct.unpack_from('<4i', rd(0x8AB734, 64), p)
             for p in range(0, 64, 16)]
    regions = []
    for raw, interpretation in zip(rects, ['Taiwan_main_island', 'Penghu',
                                         'Kinmen', 'Matsu']):
        hi_y, lo_x, lo_y, hi_x = raw
        regions.append(dict(raw_signed_words=raw,
                            interpretation=interpretation,
                            latitude_bounds_if_semicircles=[lo_y*360/2**32,
                                                          hi_y*360/2**32],
                            longitude_bounds_if_semicircles=[lo_x*360/2**32,
                                                           hi_x*360/2**32]))
    windows = [
        ('selector', 0x44144C8, 0x441452A),
        ('factory', 0x440DD1A, 0x440DD90),
        ('Twn_constructor', 0x440DC4C, 0x440DC68),
        ('region_wrapper', 0x3F01B6, 0x3F01CE),
        ('region_predicate', 0x3F00E0, 0x3F019E),
        ('map_codepage_eligibility', 0x32DEFC, 0x32E00A),
        ('MDR_open_and_header_read', 0x2CC44C, 0x2CC508),
    ]
    traces = []
    for name, start, end in windows:
        raw = rd(start, end-start)
        try:
            load = im.runtime_to_load(start, len(raw))
            copied = True
        except ValueError:
            load, copied = start, False
        traces.append(dict(name=name, runtime_start=hex(start),
                           runtime_end_exclusive=hex(end),
                           load_start=hex(load), startup_copied=copied,
                           bytes_sha256=hashlib.sha256(raw).hexdigest(),
                           instructions=ins(start, end)))
    cp_proof = HERE/'city-prefix-original-instruction-proof-v1.json'
    resource = ROOT/'staging/navigation-search-encoding-v1/reference/MDRHeader.java'
    result = dict(
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        stock_MAIN_sha256=EXPECTED, exact_HardwareID=1352,
        software_version='8.00', bounded_static_checks_passed=True,
        device_IO=False, physical_query_verified_here=False,
        live_RAM_selected_manager_observed=False,
        full_map_enumeration_executed=False,
        original_instruction_windows=traces, verified_original_opcodes=asserts,
        verified_ARM_veneers=veneers,
        selector=dict(address='0x044144c8',
            branch0=dict(region_wrapper='0x003f01b6', region_case=0,
                         requested_MDR_codepage=950,
                         literal_address='0x04414760', return_on_success=0),
            other_branches=[dict(requested_MDR_codepage=932, result=1),
                            dict(requested_MDR_codepage=936, result=2),
                            dict(requested_MDR_codepage=1252, result=3)],
            fallback_result=4),
        Twn_factory=dict(address='0x0440dd1a',
            required_selector_result=0, required_global_address='0x05431a94',
            required_global_halfword=2, constructor='0x0440dc4c',
            vtable='0x047030c8',
            initial_filebacked_global_halfword=struct.unpack('<H',rd(0x5431A94,2))[0],
            initial_filebacked_global_is_live_value=False),
        codepage_helper=dict(address='0x0032defc',
            map_enumerator='0x0032c6b0', enumeration_flags='0x43',
            map_record_validation='0x0032c4fe',
            MDR_context_loader='0x002cdaac',
            MDR_file_opener='0x002cc44c', MDR_extension_at='0x002cc86c',
            MDR_header_read_offset='0x15', MDR_header_read_bytes=8,
            codepage_context_offset='0x28',
            sort_id1_context_offset='0x2a', sort_id2_context_offset='0x2c',
            equality_addresses=['0x0032df7c','0x0032df7e','0x0032df80','0x0032df82'],
            additional_nonzero_context_fields=['0x2c0','0x2b8'],
            additional_record_predicate='0x0032c940',
            SRT_open_failure_not_fatal_to_return_true=True,
            SRT_path='0x0032dfa8 -> 0x002cc3e0 -> 0x0023ce92',
            extra_field_semantics_not_yet_proven=True),
        region_predicate=dict(address='0x003f00e0',case0_table='0x008ab734',
            caller_position_snapshot='0x003221a4',
            representation_conversion='0x00378380; representation_tag0x17',
            comparisons='signed strict lo_y<y<hi_y and lo_x<x<hi_x',
            geographic_interpretation_is_inference=True, rectangles=regions),
        reference=dict(official_source_url='https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip',
            local_MDRHeader_source=str(resource.relative_to(ROOT)),
            sha256=hashlib.sha256(resource.read_bytes()).hexdigest(),
            scope='readFileHeader is unsupported; writeFileHeader writesCP/id1/id2 at applicationheader0x15'),
        existing_frozen_city_prefix_probe=dict(path=str(cp_proof.relative_to(ROOT)),
            sha256=hashlib.sha256(cp_proof.read_bytes()).hexdigest(),rerun=False),
        inference='CP65001 standalone candidate cannot satisfy exact950 equality in this eligibility branch. OriginalCP950 native assets can restore this prerequisite, consistent with human fieldA/B. This does not prove every street/house search uses this branch or has2026 data.',
        limits=[
            'Conditional runtimecopy hardwareflag and poststartup globalvalue are not read from liveGarminRAM.',
            'Two additionalMDR contextfields, recordpredicate and enumerationflags remain semantically unidentified.',
            'Originaladdress completion -> selectedMDR/TWNHWM/TWNJAI lookup -> destination chain is not yet demonstrated.',
            'Changing a keyboard/map codepageheader or factoryguard alone is not a supported update/fix.',
            'No sealedmap/prototype/source/classes or USB files were modified.',
        ])
    out = HERE/'native-Twn-provider-guard-proof-v1.json'
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),static_checks_passed=True,
                         requested_MDR_codepage=950,device_IO=False,
                         physical_query_verified=False)))


if __name__ == '__main__':
    main()
