"""Compare actual small IMG metadata and MDR directories, without native I/O."""
import hashlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-actual-AP-profile-regression-matrix-v1'
SOURCES = {
    'stock': ('backups/20261002T154458Z/files/.System/gmapprom1.img', 96739328, '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'),
    'healthy_country_v2': ('staging/navigation-country-native-candidate-v2/gmapprom1.img', 128356352, '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'),
    'regressing_country_v3': ('staging/navigation-country-native-lane-candidate-v3/gmapprom1.img', 153346048, '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'),
    'offline_v3_expanded4k': ('staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled', 153337856, 'cc019c5f83c7fce442d0a6b64d8cc216dbc39e1cfa08dfe3f57c757f3bdfbfe9'),
    'offline_one_new_street': ('staging/navigation-new-street-v2-4k-offline-prototype-v2/new-street-v2-original4k-experiment.img.disabled', 132173824, '26a47f00fc84de49cf107df5b50504ff62849cb61d384e2d97b236aca400b8f9'),
}
PINS = {
    'staging/navigation-country-native-cpu-v2/proof.json': '8b254737914ca994fca3eacad0a06546f4a078b6eb4599921c10beb32a47f2cc',
    'staging/navigation-country-native-lane-candidate-v3/proof.json': 'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0',
    'staging/navigation-v3-expanded4k-offline-isolation-v1/proof.json': '7b5315087aebfda01db11d72bc206aaba23780031d90b92edcfcee3c0188c41a',
    'staging/navigation-new-street-v2-4k-offline-prototype-v2/proof.json': 'a03ba7d4a5a01138c5109610224be3aeec07f767632cf0aec70b3d793573b576',
    'staging/navigation-v3-gmp-first-virtual-image-verification-v1/proof.json': 'cc4f07d774f8d679268b8cd2517ed5c6f10a0863c6b03f2819bd93964b2baac9',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def save(name, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    (OUT / name).chmod(0o444)
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def inspect(path, expected_size):
    before = stat(path)
    assert before[2] == expected_size
    with path.open('rb') as stream:
        prefix = stream.read(4608)
        assert len(prefix) == 4608 and prefix[4096] == 1
        metadata_size = struct.unpack_from('<I', prefix, 4108)[0]
        assert 4608 <= metadata_size <= 100000
        metadata = prefix + stream.read(metadata_size - len(prefix))
        assert len(metadata) == metadata_size
        header = metadata[:512]
        block = 1 << (header[0x61] + header[0x62])
        assert block in (4096, 8192) and metadata_size % block == 0
        files = {}
        for at in range(4608, metadata_size, 512):
            row = metadata[at:at + 512]
            if not row[0]:
                assert not any(row)
                continue
            assert row[0] == 1
            name = row[1:9].decode('ascii') + '.' + row[9:12].decode('ascii')
            entry = files.setdefault(name, dict(size=None, blocks=[], parts=0))
            part = struct.unpack_from('<H', row, 17)[0]
            assert part == entry['parts']
            entry['parts'] += 1
            size = struct.unpack_from('<I', row, 12)[0]
            if not part:
                entry['size'] = size
            else:
                assert size == 0
            blocks = list(struct.unpack_from('<240H', row, 32))
            first_end = blocks.index(65535) if 65535 in blocks else len(blocks)
            assert all(x == 65535 for x in blocks[first_end:])
            entry['blocks'].extend(blocks[:first_end])
        assert len(files) == 6
        mdr = files['00004171.MDR']
        logical = mdr['size'] - 120
        left = 120
        directory = bytearray()
        while left:
            index, within = divmod(logical, block)
            n = min(left, block - within)
            stream.seek(mdr['blocks'][index] * block + within)
            raw = stream.read(n)
            assert len(raw) == n
            directory.extend(raw); left -= n; logical += n
        tables = []
        for level, at in enumerate(range(0, 120, 20), 1):
            row = bytes(directory[at:at + 20])
            start, size, stride = struct.unpack_from('<III', row)
            assert stride >= 68 and start + size <= mdr['size'] - 120
            tables.append(dict(level=level, start=start, bytes=size, stride=stride,
                               count=size * 8 // stride, opaque_parameter_bytes=row[12:].hex(),
                               exact_row_hex=row.hex()))
        gmp = files['I053061A.GMP']
        result = dict(path=str(path.relative_to(ROOT)), image_bytes=expected_size,
            source_stat_before=before, source_stat_after=stat(path), source_handles_closed=True,
            actual_IMG_bytes_read=metadata_size + 120, metadata_bytes=metadata_size,
            metadata_SHA256=sha(metadata), header_SHA256=sha(header), block_bytes=block,
            opaque_header_byte_0F=header[0x0F], header_uint16_at_63=struct.unpack_from('<H', header, 0x63)[0],
            header_uint32_at_1CA=struct.unpack_from('<I', header, 0x1CA)[0],
            block_count_interpretation_bytes=struct.unpack_from('<H', header, 0x63)[0] * block,
            sector_count_interpretation_bytes=struct.unpack_from('<I', header, 0x1CA)[0] * 512,
            opaque_header_geometry_fields_not_validated=True,
            MDR_logical_bytes=mdr['size'], GMP_logical_bytes=gmp['size'],
            GMP_first_physical_byte=gmp['blocks'][0] * block,
            exact_actual_MDR_directory_hex=bytes(directory).hex(), tables=tables)
    assert stat(path) == before
    return result, header


def main():
    assert not OUT.exists()
    pins = {}
    for path, digest in PINS.items():
        raw = (ROOT / path).read_bytes()
        assert sha(raw) == digest
        pins[path] = dict(bytes=len(raw), sha256=digest)
    profiles, headers = {}, {}
    for name, (path, size, inherited_sha) in SOURCES.items():
        profile, header = inspect(ROOT / path, size)
        profile['complete_source_SHA_inherited_not_recomputed'] = inherited_sha
        profiles[name], headers[name] = profile, header
    v2, v3 = profiles['healthy_country_v2'], profiles['regressing_country_v3']
    v2_parameters = [(t['stride'], t['opaque_parameter_bytes']) for t in v2['tables']]
    v3_parameters = [(t['stride'], t['opaque_parameter_bytes']) for t in v3['tables']]
    assert v2_parameters == v3_parameters
    assert v2['tables'][2]['stride'] == 112 and v3['tables'][2]['stride'] == 112
    assert profiles['stock']['tables'][2]['stride'] == 111
    assert v2['tables'][3]['count'] == 3781594 and v3['tables'][3]['count'] == 4896236
    assert v2['tables'][3]['count'] < 1 << 22 < v3['tables'][3]['count']
    assert profiles['offline_v3_expanded4k']['exact_actual_MDR_directory_hex'] == v3['exact_actual_MDR_directory_hex']
    assert headers['offline_one_new_street'] == headers['healthy_country_v2']
    OUT.mkdir(mode=0o700)
    saved = [save('producer-source.py', Path(__file__).read_bytes()), save('input-proof-pins.json', pins),
             save('actual-profile-comparison.json', profiles)]
    diffs = {name: [i for i, (a, b) in enumerate(zip(headers['healthy_country_v2'], header)) if a != b]
             for name, header in headers.items()}
    result = dict(schema='actual-small-AP-metadata-regression-axis-comparison/v1',
        all_assigned_checks_passed=True, actual_IMG_bytes_read=sum(p['actual_IMG_bytes_read'] for p in profiles.values()),
        five_actual_small_metadata_and_directory_reads=True,
        stock_L3_stride=111, healthy_country_v2_L3_stride=112, regressing_v3_L3_stride=112,
        same_six_directory_stride_and_parameter_profiles_v2_v3=True,
        v2_v3_L3_width_change_is_not_a_regression_axis=True,
        old_root_task_width22_111_country_v2_assumption_incorrect=True,
        L4_total_crosses_2_to_22=True, actual_2_to_22_limit_enforced_by_renderer=False,
        header_changed_byte_offsets_relative_to_healthy_v2=diffs,
        observed_remaining_v3_changes=['4KiB-to8KiBcontainer and opaque header/geometry bytes',
            'larger MDR/table counts and patched/cloned address subtrees',
            'GMP physical offset moves above128MiB; complete GMP logical bytes inherited identical',
            'native map admission/cache/rendering effects not executed'],
        profile_matrix='actual-profile-comparison.json',
        full_original_CPU_renderer_query_or_device_executed=False,
        v3_rootcause_proven=False, v3_regression_fixed=False,
        device_IO=False, new_IMG_or_package_created=False, installable=False,
        existing_sealed_sources_unchanged=True, full_goal_complete=False,
        next='Retain actual country-v2 profile for a minimal one-family data comparison; do not manufacture a22-to23width test.',
        limits=['Small metadata and actual directory comparison, not a full component content audit.',
                'The two header count arithmetic interpretations are observations; their enforcement/meaning and opaque checksum rule are unknown.',
                'Existing physical display controls and complete component hashes are inherited from their separate original evidence.'])
    saved.append(save('proof.json', result))
    save('sealed-files.json', dict(files=saved, all_assigned_checks_passed=True, installable=False, device_IO=False))
    print(json.dumps(dict(all_assigned_checks_passed=True, actual_IMG_read_bytes=result['actual_IMG_bytes_read'],
        actual_v2_v3_same_directory_profile=True, L3_strides=[111,112,112], rootcause_proven=False, device_IO=False)))


if __name__ == '__main__':
    main()
