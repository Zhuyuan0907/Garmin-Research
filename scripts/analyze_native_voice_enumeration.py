#!/usr/bin/env python3
"""Locate outer enumeration callers of the executed VPM metadata check."""
from datetime import datetime, timezone
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_loader import scan_calls
from analyze_sdp_activation import trace
from emulate_native_vpm_filesystem import sha, require


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    entries = (0x1d854e, 0x1d897c, 0x1d8514, 0x274992, 0x274978, 0x278194,
               0x102d32, 0x04400054, 0x04400542, 0x044004fc)
    functions = {hex(a): trace(image, a, 2000) for a in entries}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in functions.values()), 'Unresolved enumeration CFG')
    def instruction(address, expected):
        ins = next(image.md.disasm(image.read(address, 4), address, count=1))
        require(ins.mnemonic+' '+ins.op_str == expected, hex(address))
    for address, expected in {
        0x1d8632: 'bl #0x275590', 0x1d8638: 'beq #0x1d868a',
        0x1d8a12: 'bl #0x275590', 0x1d8a18: 'beq #0x1d8a66',
        0x1d8644: 'bl #0x278194', 0x1d8a32: 'bl #0x278194',
        0x1d8792: 'bl #0x274992', 0x1d8a62: 'bl #0x274992',
        0x274988: 'blx #0x39129c', 0x27498c: 'str r6, [r4, #0x34]',
        0x27498e: 'str r5, [r4, #0x30]',
        0x2781a8: 'cmp r0, r1', 0x2781ac: 'blx #0x462b28',
    }.items():
        instruction(address, expected)
    require(image.word(0x27820c) == 0xa1e, 'Predicate comparison literal changed')
    require(image.word(0x462b28) == 0xe51ff004 and
            image.word(0x462b2c) == 0x04400055, 'Secondary ARM veneer changed')
    callers = scan_calls(stock, {0x275590})
    require(callers['0x275590'] == ['0x1d8632', '0x1d8a12'],
            'Normal Thumb metadata caller candidates changed')
    paths = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
             ROOT/'scripts/analyze_native_voice_acceptance.py',
             ROOT/'scripts/analyze_native_loader.py',
             ROOT/'scripts/analyze_sdp_activation.py',
             ROOT/'scripts/emulate_native_vpm_filesystem.py']
    result = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
        'functions': functions, 'normal_Thumb_BL_metadata_call_candidates': callers,
        'metadata_callers': ['0x1d854e', '0x1d897c'],
        'metadata_failure_skips_registration': True,
        'metadata_success_alone_is_insufficient_for_registration': True,
        'additional_checks': {
            'record_type_offset': '0x760',
            'type1_acceptance_predicate': '0x278194',
            'predicate_query': '0x102d32',
            'predicate_query_u16_cache': '0xf070fc',
            'predicate_query_storage_key': '0x13a',
            'predicate_compares_first_u16_to': '0xa1e',
            'predicate_secondary_ARM_call': '0x462b28',
            'secondary_startup_backed_Thumb': '0x04400054',
            'secondary_data_pointer_query': '0x044004fc',
            'secondary_data_pointer': '0x0691ce40',
            'secondary_reads_byte_offset': '0x20',
            'secondary_comparison': '0x4c',
            'secondary_lazy_cache_flag': '0x05400000',
            'meaning_of_query_and_secondary_predicate_verified': False,
            'second_path_name_or_duplicate_helper': '0x2745cc',
            'registration': '0x274992', 'record_copy': '0x274978',
            'record_bytes': 1912, 'preserved_private_offsets': ['0x770', '0x774'],
        },
        'outer_enumeration_executed': False, 'live_predicate_result_verified': False,
        'device_io': False, 'device_install_candidate': False,
        'limits': 'Ten complete bounded static Thumb CFGs and instruction/literal assertions. Two normal Thumb BL candidates call stock275590 and skip registration on failure. They also test record type and a platform predicate before native sorted registry insertion. The first query reads/caches u16 storage key13A; secondary ARM veneer resolves through exact startup copy to conditional code comparing config byte+20 to4C. Those fields semantic meaning/live values remain unknown; no full enumerator execution or modified-package acceptance is claimed. Direct call scan does not exclude indirect, ARM or conditional-copy callers.'
    }
    path = ROOT/'evidence/firmware-analysis/native-voice-enumeration-static.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'evidence': str(path.relative_to(ROOT)), 'static_CFGs': len(functions),
                      'metadata_callers': 2, 'outer_enumeration_executed': False}))


if __name__ == '__main__':
    main()
