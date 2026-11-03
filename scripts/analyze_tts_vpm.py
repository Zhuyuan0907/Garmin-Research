#!/usr/bin/env python3
"""Read-only allocation checks/extraction for the backed-up TTS VPM images.

DSKIMG directory parsing follows the same allocation layout already checked
for our map image. Audio-only AUDIMG VPM files are inventoried, not parsed.
All output stays in local research evidence, and no navigator file is written.
"""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

from analyze_native_sections import ROOT

BACKUP = ROOT / 'backups/20261002T154458Z/files/Voice'
OUT = ROOT / 'evidence/firmware-analysis/voice-modules'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition: raise ValueError(message)


def parse_image(data):
    require(data[0] == 0 and data[0x10:0x17] == b'DSKIMG\0', 'Unexpected TTS image')
    require(data[0x41:0x48] == b'GARMIN\0' and data[510:512] == b'\x55\xaa', 'IMG header mismatch')
    exponent = data[0x61] + data[0x62]
    require(9 <= exponent <= 16, 'Invalid allocation exponent')
    block_bytes = 1 << exponent
    require(len(data) % block_bytes == 0, 'Partial image allocation block')
    first = data[0x40] * 512
    root = data[first:first+512]
    require(root[0] == 1 and root[16] == 3, 'Missing directory allocation')
    end = struct.unpack_from('<I', root, 12)[0]
    require(first+512 <= end <= len(data) and end % 512 == 0, 'Directory extent invalid')
    files, directory_blocks = {}, []
    previous, expected_part = None, 0
    for offset in range(first, end, 512):
        entry = data[offset:offset+512]
        if entry[0] == 0: continue
        require(entry[0] == 1, 'Unknown directory entry marker')
        name = entry[1:9].decode('ascii').rstrip()
        extension = entry[9:12].decode('ascii').rstrip()
        size = struct.unpack_from('<I', entry, 12)[0]
        part = struct.unpack_from('<H', entry, 17)[0]
        blocks, padding = [], False
        for value in struct.unpack_from('<240H', entry, 32):
            if value == 65535: padding = True
            else:
                require(not padding and value < len(data)//block_bytes, 'Invalid allocation entry')
                blocks.append(value)
        if entry[16] == 3:
            require(not name and not extension, 'Unexpected metadata entry name')
            directory_blocks.extend(blocks)
            previous = None
            continue
        key = name + '.' + extension
        if part == 0:
            require(key not in files and size > 0 and blocks, 'Duplicate/empty image file')
            files[key] = {'bytes': size, 'blocks': [], 'parts': 0, 'directory_offsets': []}
            previous, expected_part = key, 0
        require(key == previous and part == expected_part, 'Out-of-order continuation')
        require(part == 0 or size == 0, 'Continuation has independent size')
        files[key]['blocks'].extend(blocks)
        files[key]['parts'] += 1
        files[key]['directory_offsets'].append(offset)
        expected_part += 1
    require(set(directory_blocks) == set(range((end+block_bytes-1)//block_bytes)),
            'Directory allocation differs from its extent')
    require(len(set(directory_blocks)) == len(directory_blocks), 'Repeated directory allocation')
    owner = {block: '<directory>' for block in directory_blocks}
    for key, record in files.items():
        require(len(record['blocks']) == (record['bytes']+block_bytes-1)//block_bytes,
                'File allocation does not match length: ' + key)
        for block in record['blocks']:
            require(block not in owner, 'Overlapping image allocation: ' + key)
            owner[block] = key
        record['content'] = b''.join(data[n*block_bytes:(n+1)*block_bytes]
                                     for n in record['blocks'])[:record['bytes']]
        record['sha256'] = sha(record['content'])
    return files, {'block_bytes': block_bytes, 'directory_start': first, 'directory_end': end,
                   'allocated_blocks': len(owner), 'allocation_overlap': False}


def arm_branch_target(data, offset):
    word = struct.unpack_from('<I', data, offset)[0]
    require(word & 0xff000000 == 0xea000000, 'Expected unconditional ARM entry branch')
    immediate = (word & 0xffffff) << 2
    if immediate & 0x2000000: immediate -= 0x4000000
    target = offset+8+immediate
    require(0 <= target < len(data), 'Entry branch outside component')
    return target


def main():
    rows = []
    OUT.mkdir(parents=True, exist_ok=True)
    for path in sorted(BACKUP.glob('*.vpm')):
        data = path.read_bytes()
        row = {'file': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': sha(data)}
        if data[:6] == b'AUDIMG':
            row.update(format=data[:9].decode('ascii'), native_module_container=False,
                       parsed=False)
            rows.append(row)
            continue
        files, allocation = parse_image(data)
        row.update(format='DSKIMG TTS VPM', native_module_container=True, allocation=allocation,
                   files={k: {field: value for field, value in item.items() if field != 'content'}
                          for k, item in files.items()})
        destination = OUT / path.stem
        destination.mkdir(exist_ok=True)
        for key in ('DLLINFO.TXT', 'DLLIMG.BIN', 'DLLIMG.SIG'):
            require(key in files, 'Missing expected TTS component ' + key)
            output = destination / key
            output.write_bytes(files[key]['content'])
            require(sha(output.read_bytes()) == files[key]['sha256'], 'Extraction readback mismatch')
        info = files['DLLINFO.TXT']['content'].decode('ascii')
        tags = {match[1]: match[2] for match in re.finditer(r'<([a-z_]+)>([^<]*)</\1>', info)}
        image = files['DLLIMG.BIN']['content']
        expected_sum = int(tags['dll_chksum'], 0)
        actual_sum = sum(image) & 0xffffffff
        require(expected_sum == actual_sum, 'TTS DLL checksum mismatch')
        ram_bytes, file_bytes = struct.unpack_from('<2I', image, 4)
        require(file_bytes == len(image) and len(image) <= ram_bytes <= 0x300000,
                'DLL image header size mismatch')
        first = arm_branch_target(image, 0)
        veneer = arm_branch_target(image, first)
        require(image[veneer:veneer+12] == struct.pack('<3I', 0xe59fc004, 0xe08cc00f, 0xe12fff1c),
                'Unexpected PIC ARM-to-Thumb entry veneer')
        delta = struct.unpack_from('<i', image, veneer+12)[0]
        thumb = veneer+12+delta
        require(thumb & 1 and 0 <= thumb & ~1 < len(image), 'PIC Thumb entry invalid')
        row['module'] = {'extracted_binary': str((destination/'DLLIMG.BIN').relative_to(ROOT)),
                         'metadata': tags, 'image_header_ram_bytes': ram_bytes,
                         'image_header_file_bytes': file_bytes,
                         'byte_sum': hex(actual_sum), 'metadata_checksum_matches': True,
                         'first_branch_offset': first, 'pic_veneer_offset': veneer,
                         'thumb_entry_offset': thumb,
                         'signature_present': True, 'signature_bytes': files['DLLIMG.SIG']['bytes'],
                         'signature_validation_algorithm_identified': False,
                         'modified_image_acceptance_verified': False}
        rows.append(row)
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'containers': rows,
              'tts_container_count': sum(r['native_module_container'] for r in rows),
              'device_io': False, 'backup_modified': False,
              'limitations': 'Container allocation, extraction, native entry bytes and additive checksum are verified from the original backup. SIG files exist, but enforcement/algorithm is not established here. DLL presence does not prove a modified voice package will mount or execute, or that the two-export decoder module preserves TTS behavior.'}
    path = ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'voice_files': len(rows),
                      'tts_containers': report['tts_container_count'],
                      'module_checksums_verified': report['tts_container_count'], 'device_io': False}))


if __name__ == '__main__':
    main()
