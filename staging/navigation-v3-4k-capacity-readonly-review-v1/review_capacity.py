#!/usr/bin/env python3
"""Bounded read-only v3 AP geometry review; no image/USB/closed-suite writes."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
READS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def state(path):
    s = path.stat()
    return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns, 'links': s.st_nlink}


def read(relative, maximum, expected=None, only=None):
    path = ROOT / relative
    before = state(path)
    assert only is not None or before['bytes'] <= maximum
    with path.open('rb') as stream:
        raw = stream.read(only if only is not None else maximum + 1)
    assert len(raw) <= maximum and (only is None or len(raw) == only)
    after = state(path)
    assert before == after
    if expected is not None:
        assert sha(raw) == expected
    READS.append({'path': relative, 'actual_bytes_read': len(raw), 'sha256_of_read_bytes': sha(raw),
                  'full_file_read': only is None, 'stat_before': before, 'stat_after': after})
    return raw


def row(instructions, address):
    return next(r for r in instructions if r['address'] == address)


def save(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (HERE / name).open('xb') as f:
        assert f.write(raw) == len(raw)
    return sha(raw)


def main():
    assert not (HERE / 'proof.json').exists()
    paths = {
        'stock_AP': 'backups/20261002T154458Z/files/.System/gmapprom1.img',
        'country_v2': 'staging/navigation-country-native-candidate-v2/gmapprom1.img',
        'lane_v3': 'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img',
        'Search_v2': 'staging/navigation-repair-v2/package/Map/Taiwan_OSM_SearchRepair_v2.img',
    }
    headers = {}
    baseline = None
    for name, path in paths.items():
        h = read(path, 512, only=512)
        assert h[16:23] == b'DSKIMG\0' and h[65:72] == b'GARMIN\0'
        if baseline is None:
            baseline = h
        headers[name] = {'path': path, 'file_bytes': READS[-1]['stat_before']['bytes'],
            'header_sha256': sha(h), 'block_bytes': 1 << (h[97] + h[98]),
            'exponents': [h[97], h[98]], 'byte_0x0F': h[15],
            'u16_fields': {hex(at): struct.unpack_from('<H', h, at)[0] for at in (0x18, 0x1a, 0x1c, 0x5d, 0x5f, 0x63)},
            'partition_sectors': struct.unpack_from('<I', h, 0x1ca)[0],
            'changed_header_offsets_vs_stock': [{'offset': hex(at), 'stock': a, 'actual': b}
                for at, (a, b) in enumerate(zip(baseline, h)) if a != b],
            'whole_image_sha_not_reexecuted': True}
    assert headers['stock_AP']['block_bytes'] == headers['country_v2']['block_bytes'] == 4096
    assert not headers['country_v2']['changed_header_offsets_vs_stock']
    assert headers['lane_v3']['block_bytes'] == 8192
    assert headers['Search_v2']['u16_fields']['0x63'] == 64371 > 32768
    plan = json.loads(read('staging/navigation-country-native-lane-candidate-v3/capacity-plan.json', 2_000_000))
    assert plan['image_bytes'] == 153346048 and plan['sizes']['00004171.MDR'] == 149220356
    counts = {name: (n + 4095) // 4096 for name, n in plan['sizes'].items()}
    rows = 1 + sum((n + 239) // 240 for n in counts.values())
    metadata = ((4096 + rows * 512 + 4095) // 4096) * 4096
    blocks = metadata // 4096 + sum(counts.values())
    image_bytes = blocks * 4096
    assert (rows, metadata, blocks, image_bytes) == (161, 90112, 37436, 153337856)
    assert 32768 < blocks < 65535 and plan['sizes']['00004171.MDR'] > 134217728
    static = json.loads(read('evidence/firmware-analysis/native-vpm-filesystem-static.json', 400_000,
        '79a1fe38ed0d0020663e8787ed0e65638e64beea51c4ab78d91f7e89d32a339b'))
    parser, allocation = static['functions']['0x1e8046'], static['functions']['0x123920']
    assert not parser['instruction_limit_reached'] and not parser['unresolved_exits']
    assert not any(r.get('literal_value') == '0x8000' for r in parser['instructions'])
    parser_addresses = ['0x1e8304', '0x1e8306', '0x1e8308', '0x1e830a', '0x1e830c', '0x1e8316',
                        '0x1e85d4', '0x1e85d6', '0x1e85da', '0x1e85dc']
    allocation_addresses = ['0x1239d6', '0x1239d8', '0x1239da', '0x123a44', '0x123a46']
    assert row(parser['instructions'], '0x1e8316')['instruction'] == 'strh r3, [r6, r1]'
    assert row(allocation['instructions'], '0x1239d6')['instruction'] == 'ldrh r6, [r0, #0x20]'
    assert row(allocation['instructions'], '0x1239d8')['literal_value'] == '0xffff'
    assert row(allocation['instructions'], '0x123a46')['instruction'] == 'lsls r6, r0'
    for path, expected, maximum in [
        ('staging/navigation-native-general-writer-v1/native_ap_writer.py', 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8', 20000),
        ('staging/navigation-native-img-8k-writer-v1/ap_8k_writer.py', 'f4c870f2494d82f93a64f3de70b215c3ae38a85263f977016093c2fef46c1716', 12000),
        ('sources/maps/format-reference/ImgHeader.java', '9d9a95c9c6f1d11ba04359ac7974d38ace0466e31c4f3a8c938383cf27f17dab', 15000),
        ('staging/navigation-country-native-lane-cpu-v3/HANDOFF.md', 'c842b701f355a5979f818232949cec1f1d9415028701fed9a4739060ee327faf', 5000),
    ]:
        read(path, maximum, expected)
    for receipt in READS:
        assert state(ROOT / receipt['path']) == receipt['stat_before']
    result = {
        'schema': 'read-only-AP-v3-4KiB-capacity-review/v1',
        'all_assigned_checks_passed': True, 'read_only_analysis': True,
        'new_IMG_or_component_written': False, 'closed_suite_or_native_CPU_reexecuted': False,
        'USB_or_device_accessed': False, 'sealed_installer_modified': False,
        'canonical_report_or_service_modified': False, 'all_read_sources_unchanged_during_review': True,
        'headers': headers,
        'existing_4KiB_limit': {
            'declared_blocks': 32768, 'declared_sectors': 262144, 'declared_capacity_bytes': 134217728,
            'origin': 'Original AP header profile, reused by StreamIMG/min(blocks*4096,sectors*512) and the explicit4K adapter.',
            'universal_format_or_OS_or_native_CPU_limit_proved': False,
            'Search_v2_exceeds_32768_blocks': True,
            'Search_v2_device_rendering_success': 'Parent-provided current physical observation; not reexecuted by this review.',
        },
        'whole_v3_payload_as_4KiB_arithmetic': {
            'six_component_logical_sizes_unchanged': plan['sizes'], 'component_block_counts': counts,
            'directory_rows': rows, 'metadata_bytes': metadata, 'blocks': blocks,
            'image_bytes': image_bytes, 'minimum_partition_sectors': image_bytes // 512,
            'uint16_block_numbers_below_0xFFFF_sentinel': True,
            'bytes_above_original_128MiB_profile': image_bytes - 134217728,
            'MDR_alone_exceeds_original_capacity': True,
            'dedicated_expanded_4KiB_profile_required': True,
            'existing_guards_may_not_be_relaxed': True,
            'this_is_not_a_container_or_device_acceptance_proof': True,
        },
        'native_static_evidence': {
            'shared_embedded_DSKIMG_parser': '0x1e8046',
            'header_0x63_unsigned16_loading_and_allocation_bound': [row(parser['instructions'], a) for a in parser_addresses],
            'allocation_16bit_load_sentinel_and_shift': [row(allocation['instructions'], a) for a in allocation_addresses],
            'explicit_32768_constant_seen_in_closed_parser': False,
            'scope': 'Shared embedded DSKIMG/VPM parser and allocation translator identified in prior original-CPU experiments; AP high-level admission/checksum policy is not proved identical.',
        },
        'checksum_and_geometry_policy': {
            'stock_byte_0x0F': 219, 'v2_byte_0x0F': 219, 'v3_byte_0x0F': 0,
            'current_v3_header_changes_vs_stock': headers['lane_v3']['changed_header_offsets_vs_stock'],
            'stock_AP_checksum_rule_or_high_level_enforcement_known': False,
            'mkgmap_reference_zero_policy_is_not_target_AP_acceptance_proof': True,
            'safe_expanded4KiB_install_candidate_already_available': False,
            'next_scope': 'A separate exact expanded4KiB profile must specify and validate all geometry fields, preserve opaque fields/byte0x0F policy, prove header/FAT/high-block translation using original reader controls, and retain exact rollback. No arbitrary checksum is to be synthesized.',
        },
        'closed_v3_CPU_scope': 'IMG geometry/FAT mapped by Python strict_ap8k_reader; original CPU only MDR header/directory, finite packed prefixes and LBL fragments. No complete AP IMG admission, getter/query/UI or rendering.',
        'physical_causation': {
            'parent_observation': 'Searchv2 roads appear alone, disappear with v3 AP, reappear when original CN roads are also enabled.',
            '8KiB_geometry_as_sole_cause_proved': False,
            'other_live_candidates': ['Expanded MDR/COW structure and high first-child values', 'Map-layer registry, ownership or priority interactions', 'Opaque header/checksum/admission policy'],
        },
        'minimum_restore_and_AB': [
            'Use only existing sealed v3 --rollback to restore exact stock AP; full readback and safe unmount.',
            'Cold-start with stock AP plus Searchv2 and original CN unchecked; observe one road-rendering case. Keep CN available as a recovery layer.',
            'If restored baseline works and user is available, the already-sealed 4KiB v2 can separate expanded MDR/layer effects from the v3-specific COW and geometry changes.',
            'After a new expanded4KiB profile is independently checked, compare identical v3 six-component logical payloads at 4KiB versus 8KiB with the same layer selections. This is the geometry-focused A/B; it is not ready now.',
        ],
        'read_receipts': READS, 'actual_IMG_header_bytes_read_total': 2048,
        'source_sha256': sha(Path(__file__).read_bytes()),
    }
    digest = save('proof.json', result)
    print(json.dumps({'all_assigned_checks_passed': True, 'proof_sha256': digest,
                      'IMG_header_bytes_read': 2048, 'expanded4KiB_arithmetic_blocks': blocks,
                      'expanded4KiB_arithmetic_bytes': image_bytes, 'device_IO': False}))


if __name__ == '__main__':
    main()
