#!/usr/bin/env python3
"""Read only the first min(128,size) bytes of six original AP carrier spans."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-provider-bodyheaders-v1'
DIRECTORY = ROOT / 'staging/navigation-AP-provider-records-v1/AP-provider-records-evidence.json'
READER = ROOT / 'staging/navigation-AP-provider-records-v1/read_AP_provider_records.py'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'AP-provider-bodyheaders-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    need(ref(DIRECTORY)['sha256'] == '32aae3c125bc21ae71d81997d4b7d481cd08686e4b42683b51501adc8b7121dd',
         'Sealed provider-directory evidence changed')
    need(ref(READER)['sha256'] == 'e1844c7ab21e7804e151b865dff5db271eca2a501f31c46d54b72f5b492e3e4e',
         'Sealed readonly range-reader changed')
    directory = json.loads(DIRECTORY.read_text())
    # Compile the frozen helper in memory: no __pycache__ or predecessor edits.
    module = types.ModuleType('frozen_AP_readonly_reader')
    module.__file__ = str(READER)
    exec(compile(READER.read_text(), str(READER), 'exec'), module.__dict__)
    image = module.ReadonlyMDR(ROOT / directory['source_map']['path'])
    before_payload = len(image.read_log)
    try:
        observations = []
        for row in directory['provider_directory']['records']:
            ordinal = row['ordinal_zero_based']
            words = row['u32_LE']
            start, size = words[:2]
            count = min(128, size)
            raw, mapping = image.logical_read(start, count, 'provider_span_' + str(ordinal) + '_prefix')
            observations.append({
                'directory_ordinal': ordinal, 'directory_words_u32_LE': words,
                'candidate_MDR_offset': start, 'candidate_span_size': size,
                'bytes_read': count, 'hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                'FAT_mapping': mapping, 'u8': list(raw),
                'u16_LE': list(struct.unpack('<' + str(len(raw) // 2) + 'H', raw)),
                'u16_BE': list(struct.unpack('>' + str(len(raw) // 2) + 'H', raw)),
                'u32_LE': list(struct.unpack('<' + str(len(raw) // 4) + 'I', raw)),
                'u32_BE': list(struct.unpack('>' + str(len(raw) // 4) + 'I', raw)),
                'first_byte': raw[0], 'first_u16_LE': struct.unpack_from('<H', raw)[0],
                'byte13_raw': raw[13],
                'raw_bytes2_to12_hex': raw[2:12].hex(),
                'raw_bytes2_to12_printable': raw[2:12].decode('ascii', 'backslashreplace'),
                'printable_runs': [{'offset': match.start(), 'text': match.group().decode('ascii')}
                                   for match in re.finditer(rb'[\x20-\x7E]{4,}', raw)],
                'first_u16_equals_directory_word2': struct.unpack_from('<H', raw)[0] == words[2],
                'signature_semantics_confirmed': False,
                'XOR_or_decryption_attempted': False,
                'offset_length_interpretation_native_consumer_confirmed': False,
            })
        need(len(observations) == 6 and sum(r['bytes_read'] for r in observations) == 768,
             'Six-prefix budget differs')
        payload_reads = image.read_log[before_payload:]
        need(sum(r['bytes'] for r in payload_reads) == 768, 'Actual prefix body read exceeds budget')
        matching = [r['directory_ordinal'] for r in observations if r['first_u16_equals_directory_word2']]
        common = [{'offset_in_prefix': offset, 'value': observations[0]['u8'][offset]}
                  for offset in range(128)
                  if len({r['u8'][offset] for r in observations}) == 1]
        evidence = {
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'source_sha256': ref(Path(__file__))['sha256'],
            'dependencies': [ref(DIRECTORY), ref(READER)],
            'scope': 'Original AP six numerical spans, first 128 bytes each; no full carrier, codec decode or unlocking.',
            'source_map': directory['source_map'],
            'MDR_component': image.component_name, 'MDR_component_bytes': image.component_bytes,
            'observations': observations,
            'common_prefix_byte_observations': common,
            'first_u16_matches_directory_third_DWORD_ordinals': matching,
            'all_six_third_DWORD_are_header_lengths_confirmed_by_native': False,
            'file_signature_format_named_by_this_probe': False,
            'read_log': image.read_log,
            'body_content_bytes_read': 768,
            'total_actual_map_bytes_read': sum(r['bytes'] for r in image.read_log),
            'large_span_remaining_bytes_read': False,
            'provider_records_or_old_proofs_modified': False,
            'XOR_or_decryption_attempted': False, 'unlocked': False,
            'device_IO': False, 'stock_map_modified': False, 'raw_map_copied': False,
            'house_number_position_or_route_reference_decoded': False,
            'physical_search_or_routing_proven': False,
            'all_bounded_read_checks_passed': True,
        }
        need(evidence['total_actual_map_bytes_read'] < 65536, 'Metadata plus body budget exceeded')
        image.close()
        evidence['source_map_stat_unchanged'] = True
        with target.open('x') as out:
            json.dump(evidence, out, ensure_ascii=False, indent=2)
            out.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'body_content_bytes_read': 768, 'total_actual_map_bytes_read': evidence['total_actual_map_bytes_read'],
            'first_u16_matches_directory_word2': matching,
            'signatures': [r['raw_bytes2_to12_printable'] for r in observations],
            'all_bounded_read_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
