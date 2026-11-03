#!/usr/bin/env python3
"""Bounded original AP LBL public-header source for separate native parser."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-LBL-header-v1'
HELPER = ROOT / 'staging/navigation-AP-mapmetadata-v1/read_AP_mapmetadata.py'
METADATA = ROOT / 'staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json'


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'AP-LBL-header-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    need(ref(HELPER)['sha256'] == '31c9ec231ab862ab6477c5399b5a79139e7536284120a9f23629e16935cf8ffb',
         'Frozen bounded IMG reader source changed')
    need(ref(METADATA)['sha256'] == '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753',
         'Frozen GMP/public mapmetadata source changed')
    metadata = json.loads(METADATA.read_text())
    offset = metadata['GMP_public_header']['seven_pointer_values_at25'][2]
    need(offset == 874, 'Original LBL pointer changed')
    module = types.ModuleType('frozen_bounded_IMG_reader')
    module.__dict__['__file__'] = str(HELPER)
    exec(compile(HELPER.read_text(), str(HELPER), 'exec'), module.__dict__)
    image = module.BoundedIMG()
    try:
        record, raw = image.read('I053061A.GMP', offset, 661, 'original_LBL_public_header_661bytes')
        need(struct.unpack_from('<H', raw)[0] == 661 and raw[2:12] == b'GARMIN LBL' and raw[13] == 0,
             'Unexpected or protected LBL public header')
        obs = {'u32_LE_at21': struct.unpack_from('<I', raw, 21)[0],
            'u32_LE_at25': struct.unpack_from('<I', raw, 25)[0], 'u8_at29': raw[29], 'u8_at30': raw[30],
            'u16_LE_at170': struct.unpack_from('<H', raw, 170)[0],
            'u16_LE_at172': struct.unpack_from('<H', raw, 172)[0],
            'u16_LE_at174': struct.unpack_from('<H', raw, 174)[0]}
        need(obs['u16_LE_at170'] == 950 and obs['u8_at30'] == 10,
             'Public LBL encoding differs from frozen original stock catalog')
        need(sum(r['bytes'] for r in image.log) == 54933, 'Read budget differs')
        image.close()
        proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
            'scope': 'Only original AP 661-byte LBL public header; no pointed strings or label payload yet.',
            'dependencies': [ref(HELPER), ref(METADATA)], 'source_map': metadata['original_map'],
            'public_LBL_header': {**record, 'field_observations': obs,
                'u8_projection': list(raw),
                'u16_LE_even_projection': list(struct.unpack('<330H', raw[:660])),
                'u32_LE_even_projection': list(struct.unpack('<165I', raw[:660]))},
            'actual_map_read_log': image.log, 'public_header_bytes_read': 661,
            'pointed_text_or_label_payload_bytes_read': 0, 'total_map_bytes_read_including_FAT': 54933,
            'source_stat_unchanged': True, 'whole_map_digest_repeated': False,
            'original_native_parser_executed_here': False, 'label_references_treated_as_bare_file_offsets': False,
            'label_text_or_coordinate_semantics_confirmed_here': False,
            'stock_map_or_DB_modified': False, 'unlock_or_decryption_performed': False,
            'device_IO': False, 'physical_search_or_routing_verified_here': False,
            'all_bounded_source_checks_passed': True}
        with target.open('x') as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'field_observations': obs,
            'public_header_bytes_read': 661, 'pointed_text_or_label_payload_bytes_read': 0,
            'all_bounded_source_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
