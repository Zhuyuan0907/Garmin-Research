"""Real metadata-only placement control; no complete IMG or installer changes."""
import hashlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-v3-gmp-first-metadata-control-v1'
BASE = ROOT / 'staging/navigation-v3-expanded4k-offline-isolation-v1'
PINS = {
    'proof.json': '7b5315087aebfda01db11d72bc206aaba23780031d90b92edcfcee3c0188c41a',
    'plan.json': '8c45831edac70c2b17b187136acf38f8767eb7c617f59afd38dd9c9156fda5f0',
    'sealed-files.json': '8cdbc17f8c8bf8f3210de5d08208c92148fdd23ece02d6cb5008d790c23ddf0d',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def save(name, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    (OUT / name).chmod(0o444)
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(data), sha256=sha(data))


def decode_metadata(raw, plan):
    """Decode actual FAT rows independently of the proposed placement map."""
    assert len(raw) == plan['metadata_bytes']
    assert raw[4096] == 1 and struct.unpack_from('<I', raw, 4108)[0] == len(raw)
    root_blocks = struct.unpack_from('<240H', raw, 4128)
    assert root_blocks[:plan['metadata_blocks']] == tuple(range(plan['metadata_blocks']))
    assert all(b == 65535 for b in root_blocks[plan['metadata_blocks']:])
    components = {c['name']: c for c in plan['component_allocations']}
    found, owned, rows = {}, set(range(plan['metadata_blocks'])), []
    name_by_key = {name.replace('.', '').encode(): name for name in components}
    for pos in range(4608, len(raw), 512):
        row = raw[pos:pos + 512]
        if not row[0]:
            assert not any(row)
            continue
        assert row[0] == 1 and row[1:12] in name_by_key
        name = name_by_key[row[1:12]]
        entry = found.setdefault(name, dict(size=None, blocks=[], rows=[]))
        part = struct.unpack_from('<H', row, 17)[0]
        assert part == len(entry['rows'])
        size = struct.unpack_from('<I', row, 12)[0]
        if part == 0:
            entry['size'] = size
        else:
            assert size == 0
        ended = False
        for block in struct.unpack_from('<240H', row, 32):
            if block == 65535:
                ended = True
                continue
            assert not ended and plan['metadata_blocks'] <= block < plan['image_blocks']
            assert block not in owned
            owned.add(block); entry['blocks'].append(block)
        entry['rows'].append(pos); rows.append((pos, name, part))
    assert len(found) == 6 and owned == set(range(plan['image_blocks']))
    for name, value in found.items():
        reference = components[name]
        assert value['size'] == reference['logical_bytes']
        assert len(value['blocks']) == reference['block_count']
        assert len(value['rows']) == reference['fat_parts']
    return found, rows


def main():
    assert not OUT.exists()
    values = []
    for name, expected in PINS.items():
        raw = (BASE / name).read_bytes()
        assert sha(raw) == expected
        values.append(json.loads(raw))
    proof, plan, seal = values
    assert proof['all_assigned_checks_passed'] and not proof['installable']
    assert plan['metadata_bytes'] == 90112 and plan['image_blocks'] == 37436
    source = ROOT / proof['output']
    frozen = next(x for x in seal['files'] if x['path'] == proof['output'])
    before = identity(source)
    assert before == frozen['frozen_stat']
    with source.open('rb') as stream:
        original = stream.read(plan['metadata_bytes'])
        assert len(original) == plan['metadata_bytes']
    parsed, rows = decode_metadata(original, plan)
    for c in plan['component_allocations']:
        assert parsed[c['name']]['blocks'] == list(range(c['first_block'], c['end_block_exclusive']))
    old_order = [c['name'] for c in plan['component_allocations']]
    gmp_name = 'I053061A.GMP'
    new_order = [gmp_name] + [name for name in old_order if name != gmp_name]
    counts = {c['name']: c['block_count'] for c in plan['component_allocations']}
    placement, cursor = {}, plan['metadata_blocks']
    for name in new_order:
        placement[name] = (cursor, cursor + counts[name])
        cursor += counts[name]
    assert cursor == plan['image_blocks']
    proposed = bytearray(original)
    for pos, name, part in rows:
        begin, end = placement[name]
        blocks = list(range(begin, end))[part * 240:(part + 1) * 240]
        struct.pack_into('<240H', proposed, pos + 32, *blocks, *([65535] * (240 - len(blocks))))
    decoded, proposed_rows = decode_metadata(bytes(proposed), plan)
    assert proposed_rows == rows and proposed[:4608] == original[:4608]
    allowed = set()
    for pos, name, part in rows:
        assert proposed[pos:pos + 32] == original[pos:pos + 32]
        allowed.update(range(pos + 32, pos + 512))
        begin, end = placement[name]
        assert decoded[name]['blocks'] == list(range(begin, end))
    changed = [at for at, (old, new) in enumerate(zip(original, proposed)) if old != new]
    assert changed and all(at in allowed for at in changed)
    old_start = parsed[gmp_name]['blocks'][0] * 4096
    new_start = decoded[gmp_name]['blocks'][0] * 4096
    new_end = (decoded[gmp_name]['blocks'][-1] + 1) * 4096
    assert old_start == 149417984 and new_start == 90112 and new_end < 134217728
    assert identity(source) == before
    OUT.mkdir(mode=0o700)
    saved = [save('original-metadata.bin', original), save('gmp-first-metadata.bin.disabled', bytes(proposed))]
    result = dict(schema='actual-expanded4k-metadata-placement-control/v1', all_assigned_checks_passed=True,
        input_pins=PINS, source=str(source.relative_to(ROOT)), source_identity=before,
        source_full_SHA_inherited_not_rehashed=proof['output_sha256'], actual_IMG_bytes_read=len(original),
        original_physical_component_order=old_order, proposed_physical_component_order=new_order,
        directory_identity_order_and_opaque_fields_unchanged=True,
        only_FAT_block_vector_bytes_changed=True, changed_bytes=len(changed),
        original_GMP_start_byte=old_start, proposed_GMP_start_byte=new_start, proposed_GMP_allocated_end=new_end,
        proposed_component_block_ranges={name: list(placement[name]) for name in old_order},
        all_37436_blocks_owned_once=True, all_six_logical_sizes_and_part_ordinals_preserved=True,
        header_checksum_CHS_capacity_and_all_MDR_data_not_modified=True,
        metadata_verified=True, complete_relocated_IMG_created=False,
        component_content_not_read_or_reverified_in_this_scope=True,
        metadata_cannot_be_installed_alone=True, physical_128MiB_guard_hypothesis_proved=False,
        original_mount_registry_renderer_not_executed=True, v3_regression_fixed=False,
        device_IO=False, installable=False, public_download_or_installer_modified=False,
        current_device_v2_unchanged=True, full_goal_complete=False,
        next='If needed, compose a distinct disabled full image using these physical allocations; then original-reader checks. Actual device display remains a separate future test when user returns.')
    saved.append(save('proof.json', result))
    save('sealed-files.json', dict(files=saved, installable=False, source_handles_closed=True))
    print(json.dumps(dict(all_assigned_checks_passed=True, checkpoint=str(OUT.relative_to(ROOT)),
        source_IMG_bytes_read=len(original), complete_IMG_created=False,
        proposed_GMP_range=[new_start, new_end], device_IO=False)))


if __name__ == '__main__':
    main()
