#!/usr/bin/env python3
"""Read-only extraction of the verified Taiwan HWID 1352 GCD container."""
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'evidence/live-device/GUPDATE.GCD'
OUT = ROOT / 'evidence/firmware-analysis'
STOCK_SHA256 = '8513f805d3c57ec99aefa1f085f4861197eed4e2ae1d6428076f8762d71f7819'
FIELD_NAMES = {(10, 0): 'xor', (10, 16): 'record_id', (11, 0): 'erase_flag',
               (21, 32): 'length', (9, 16): 'hwid', (13, 16): 'software_version'}
WIDTHS = {0: 1, 16: 2, 32: 4, 64: 31}


def descriptor(schema, body):
    result = {}
    pos = 0
    for field, kind in schema:
        if kind == 80:
            if field != 3:
                raise ValueError('Unknown descriptor terminator')
            break
        width = WIDTHS[kind]
        value = body[pos:pos+width]
        if len(value) != width:
            raise ValueError('Truncated descriptor')
        result[FIELD_NAMES.get((field, kind), f'field_{field}_{kind}')] = int.from_bytes(value, 'little') if width <= 4 else value.hex()
        pos += width
    if pos != len(body):
        raise ValueError('Descriptor length disagrees with its schema')
    return result


def image_header(body):
    jump, end, hwid, version = struct.unpack_from('<4I', body)
    if jump == 0xe59ff008:
        entry = struct.unpack_from('<I', body, 16)[0]
        base = entry - 20
    elif jump == 0xe59ff00c:
        entry = struct.unpack_from('<I', body, 20)[0]
        base = entry - 24
    else:
        raise ValueError('Unexpected stock ARM entry instruction')
    marker = end - base
    if body[marker-2:marker+6] != b'\xff\xff\x5a\xa5\xff\xff\xff\xff':
        raise ValueError('Image end-marker address does not match its bytes')
    values = [struct.unpack_from('<H', body, pointer-base)[0] for pointer in (hwid, version)]
    if values != [1352, 800]:
        raise ValueError('Image product/version pointers disagree with the device')
    result = {'load_address': base, 'entry_point': entry, 'end_marker_address': end,
              'end_marker_offset': marker, 'hwid_pointer': hwid, 'version_pointer': version,
              'hwid': values[0], 'software_version': values[1], 'address_checks_verified': True}
    if jump == 0xe59ff00c:
        lend = struct.unpack_from('<I', body, 16)[0]
        result['lend_offset'] = lend
        result['lend_verified'] = body[lend:lend+4] == b'LEND'
    return result


def main():
    data = SOURCE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != STOCK_SHA256 or data[:8] != b'GARMINd\x00':
        raise ValueError('Input differs from the verified stock Taiwan firmware')
    pos = 8
    records = []
    payloads = collections.defaultdict(list)
    rebuilt = bytearray(data[:8])
    metadata = []
    schema = []
    descriptors = {}
    checkpoints = []
    cumulative_sum = sum(data[:8])
    while pos + 4 <= len(data):
        start = pos
        kind, size = struct.unpack_from('<HH', data, pos)
        pos += 4
        if kind == 0xffff:
            if size:
                raise ValueError('Non-empty end marker')
            rebuilt.extend(data[start:])
            break
        if pos + size > len(data):
            raise ValueError(f'Truncated record at {start:#x}')
        body = data[pos:pos+size]
        cumulative_sum += sum(data[start:pos+size])
        records.append({'offset': start, 'type': kind, 'length': size})
        payloads[kind].append(body)
        if kind in (6, 7):
            entry = {'offset': start, 'type': kind, 'bytes_hex': body.hex()}
            if kind == 6:
                if len(body) % 2:
                    raise ValueError('Odd descriptor schema size')
                schema = list(zip(body[::2], body[1::2]))
            if kind == 7:
                fields = descriptor(schema, body)
                if (fields.get('hwid'), fields.get('software_version')) != (1352, 800):
                    raise ValueError('Unexpected product/version descriptor')
                entry['fields'] = fields
                descriptors[fields['record_id']] = fields
            metadata.append(entry)
        if kind == 1:
            verified = size == 1 and cumulative_sum % 256 == 0
            checkpoints.append({'offset': start, 'length': size, 'cumulative_sum_mod_256': cumulative_sum % 256, 'verified': verified})
            if not verified:
                raise ValueError('Stock GCD checkpoint checksum failed')
        rebuilt.extend(data[start:pos+size])
        pos += size
    else:
        raise ValueError('Missing end marker')
    if bytes(rebuilt) != data:
        raise ValueError('Round-trip record reconstruction failed')
    OUT.mkdir(exist_ok=True)
    regions = []
    for kind, label in [(8, 'boot'), (0x2bd, 'main')]:
        body = b''.join(payloads[kind])
        if not body:
            raise ValueError(f'Missing {label} region')
        if len(body) != descriptors[kind]['length'] or descriptors[kind].get('xor', 0) != 0:
            raise ValueError('Unexpected stock stream length/obfuscation')
        target = OUT / f'{label}_{kind:04x}.bin'
        target.write_bytes(body)
        padding = (-len(body)) % 256
        checksum = {'sum_mod_256': sum(body) % 256, 'implicit_ff_padding_bytes': padding,
                    'padded_sum_mod_256': (sum(body) + padding * 255) % 256,
                    'status': 'verified' if label == 'main' and sum(body) % 256 == 0 else 'rule_not_established_for_this_boot_image'}
        regions.append({'label': label, 'gcd_record_type': kind, 'file': str(target), 'records': len(payloads[kind]), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'descriptor': descriptors[kind], 'checksum': checksum, 'header': image_header(body), 'prefix_hex': body[:64].hex()})
    types = [{'type': kind, 'records': len(chunks), 'payload_bytes': sum(map(len,chunks))} for kind,chunks in payloads.items()]
    manifest = {'captured_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'source': str(SOURCE), 'source_bytes': len(data), 'source_sha256': digest, 'format': '8-byte magic; little-endian u16 type/u16 length records; 0xffff end marker', 'record_count': len(records), 'round_trip_sha256': hashlib.sha256(rebuilt).hexdigest(), 'round_trip_identical': True, 'types': types, 'metadata': metadata, 'checkpoints': checkpoints, 'regions': regions, 'end_marker_offset': pos-4, 'trailer_bytes': len(data)-pos, 'trailer_sha256': hashlib.sha256(data[pos:]).hexdigest(), 'trailer_note': '260 trailing bytes retained unchanged; signature/checksum meaning not yet proven', 'source_device_modified': False, 'references': ['https://github.com/naturalgeek/garmin-flash-tool/blob/main/extract_main_region.py', 'https://www.memotech.franken.de/FileFormats/Garmin_GCD_Format.pdf', 'https://www.memotech.franken.de/FileFormats/Garmin_BIN_Format.pdf'], 'records': records}
    (OUT / 'layout.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'record_count': len(records), 'round_trip_identical': True, 'checkpoints_verified': len(checkpoints), 'regions': [{k:r[k] for k in ('label','bytes','records','checksum','header')} for r in regions]},ensure_ascii=False))


if __name__ == '__main__':
    main()
