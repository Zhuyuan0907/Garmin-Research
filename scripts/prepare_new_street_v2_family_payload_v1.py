"""Source-bound finite new street payload on the physically usable country v2.

This creates no complete IMG, MDR, GMP or installation package. Original v2
child pointers must be copied from v2, never from the larger v3 prototype.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-native-new-street-v2-family-payload-v1'
PINS = {
    'staging/navigation-country-native-candidate-v2/mdr-plan.json': '24fa18995041eb0b1036bbfcb66a2c159f7ae00b791e51243c7936368d320e53',
    'staging/navigation-country-native-candidate-v2/stream-write-receipt.json': 'd0a005a6ff897ac83c86479bc0172a599d38f2735c61ee0bd95f2217e04eb0f3',
    'staging/navigation-native-new-street-source-example-v1/candidate.json': 'd26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c',
    'staging/navigation-beitun-district-geometry-v1/source-membership.json': 'd624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84',
    'staging/navigation-native-new-street-family-payload-v1/proof.json': 'ff51c96544d01de68a4630fe25490e3d9857005d0f308c5796bfedbe058eab6d',
    'staging/navigation-native-new-street-family-payload-v1/LBL-label-extension.bin': '81dac673af5537f6d84cae7befb9e08b26f7104caa782093dde2f118c2c4b071',
    'staging/navigation-native-new-street-family-payload-v1/LBL-header-pointer-size.bin': 'b06e3c84ab2e5b35055e7f7d0bcc52fd95c63319b3e2088784fe1b657777f183',
}
NAMES = ('00004171.MD2', '00004171.MDR', '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def bind(name):
    path = ROOT / name
    before = identity(path)
    need(before[2] <= 3_100_000, 'Explicit small prerequisite bound')
    data = path.read_bytes()
    need(sha(data) == PINS[name] and identity(path) == before, 'Pinned unchanged prerequisite: ' + name)
    return data


def pack(values, widths):
    value = offset = 0
    for item, width in zip(values, widths):
        need(type(item) is int and 0 <= item < 1 << width, 'Packed unsigned field bounds')
        value |= item << offset
        offset += width
    return value.to_bytes((offset + 7) // 8, 'little')


def unpack(value, widths):
    result = []
    for width in widths:
        result.append(value & ((1 << width) - 1))
        value >>= width
    need(value == 0, 'No unaccounted significant record bits')
    return result


def save(name, value):
    data = value if type(value) is bytes else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as f:
        need(f.write(data) == len(data), 'Full artifact write')
        f.flush()
        os.fsync(f.fileno())
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(data), sha256=sha(data))


class FiniteV2:
    def __init__(self, receipt):
        self.path = ROOT / 'staging/navigation-country-native-candidate-v2/gmapprom1.img'
        self.before = identity(self.path)
        need(self.before[2] == receipt['image_bytes'] == 128356352 and not self.path.stat().st_mode & 0o222,
             'Exact readonly physically tested v2 image identity')
        self.f = self.path.open('rb')
        self.reads = []
        try:
            h = self.physical(0, 512, 'actual_v2_header')
            need(h[16:23] == b'DSKIMG\0' and h[65:72] == b'GARMIN\0' and h[510:] == b'\x55\xaa', 'IMG signatures')
            need(h[97:99] == b'\x09\x03' and h[15] == 219 and
                 struct.unpack_from('<H', h, 99)[0] == 32768 and
                 struct.unpack_from('<I', h, 458)[0] == 262144, 'Original 4K/128MiB geometry')
            directory = h[64] * 512
            root = self.physical(directory, 512, 'actual_v2_root')
            end = struct.unpack_from('<I', root, 12)[0]
            need(directory == 4096 and end == receipt['directory_end'] == 73728 and
                 root[0] == 1 and root[1:12] == b' ' * 11 and root[16] == 3, 'Exact root extent')
            data = self.physical(directory + 512, end - directory - 512, 'actual_v2_FAT_rows')
            self.components = {}
            owned = set(range(end // 4096))
            current = None
            for offset in range(0, len(data), 512):
                row = data[offset:offset + 512]
                if row[0] == 0:
                    need(row == bytes(512), 'Unused FAT row is zero')
                    continue
                need(row[0] == 1 and row[16] != 3, 'Active file FAT')
                name = row[1:9].decode('ascii').rstrip() + '.' + row[9:12].decode('ascii').rstrip()
                part = struct.unpack_from('<H', row, 17)[0]
                size = struct.unpack_from('<I', row, 12)[0]
                if part == 0:
                    need(name in NAMES and name not in self.components and size > 0, 'Exact unique component')
                    self.components[name] = dict(bytes=size, blocks=[], parts=0)
                    current = name
                c = self.components[name]
                need(name == current and part == c['parts'] and (part == 0 or size == 0), 'Contiguous component parts')
                sentinel = False
                blocks = []
                for block in struct.unpack_from('<240H', row, 32):
                    if block == 65535:
                        sentinel = True
                    else:
                        need(not sentinel and block not in owned and (block + 1) * 4096 <= self.before[2], 'Unique finite FAT block')
                        owned.add(block)
                        blocks.append(block)
                need(blocks, 'Nonempty continuation')
                c['blocks'].extend(blocks)
                c['parts'] += 1
            need(tuple(self.components) == NAMES and len(owned) * 4096 == self.before[2], 'All six components/blocks owned')
            for pin in receipt['components']:
                c = self.components[pin['name']]
                need(c['bytes'] == pin['bytes'] and c['parts'] == pin['parts'] and
                     len(c['blocks']) == (c['bytes'] + 4095) // 4096, 'Sealed actual component allocation')
        except BaseException:
            self.f.close()
            raise

    def physical(self, offset, n, purpose):
        need(0 <= offset <= offset + n <= self.before[2] and n <= 73728, 'Finite physical read')
        self.f.seek(offset)
        data = self.f.read(n)
        need(len(data) == n, 'Full actual image read')
        self.reads.append(dict(purpose=purpose, offset=offset, bytes=n, sha256=sha(data)))
        return data

    def logical(self, name, offset, n, purpose):
        c = self.components[name]
        need(0 <= offset <= offset + n <= c['bytes'] and n <= 8192, 'Finite component read')
        out = bytearray()
        for cursor in range(offset, offset + n):
            if cursor == offset or cursor % 4096 == 0:
                block, within = divmod(cursor, 4096)
                count = min(offset + n - cursor, 4096 - within)
                out.extend(self.physical(c['blocks'][block] * 4096 + within, count, purpose))
        return bytes(out)

    def close(self):
        self.f.close()
        need(identity(self.path) == self.before, 'Source image unchanged')


def main():
    need(not OUT.exists(), 'New independent payload namespace')
    plan = json.loads(bind('staging/navigation-country-native-candidate-v2/mdr-plan.json'))
    receipt = json.loads(bind('staging/navigation-country-native-candidate-v2/stream-write-receipt.json'))
    source = json.loads(bind('staging/navigation-native-new-street-source-example-v1/candidate.json'))
    district = json.loads(bind('staging/navigation-beitun-district-geometry-v1/source-membership.json'))
    inherited_labels = json.loads(bind('staging/navigation-native-new-street-family-payload-v1/proof.json'))
    extension = bind('staging/navigation-native-new-street-family-payload-v1/LBL-label-extension.bin')
    label_header = bind('staging/navigation-native-new-street-family-payload-v1/LBL-header-pointer-size.bin')
    need(source['streettext'] == '敦富六街' and source['house_label'] == '368號' and
         source['raw24'] == district['raw24'] == [1127253, 5625400] and
         source['source_ids'] == district['source_ids'] == [8280986017] and
         district['sourcepoint_inside_explicit_source_district'] and
         district['exact_quantized_raw24_inside_same_source_district'], 'Exact independently qualified source')
    need(district['source_district_relation_id'] == 2959946 and district['native_district']['low28_id'] == 74,
         'Exact district identity')
    tables = {i: row for i, row in enumerate(plan['new_tables'], 1)}
    need(tables[3]['count'] == 47870 and tables[3]['stride'] == 112 and tables[4]['count'] == 3781594,
         'Actual v2 table profile')
    need((inherited_labels['street_label_ref'], inherited_labels['house_label_ref']) == (475679, 2967) and
         struct.unpack('<II', label_header) == (3812824, 3805448), 'Reuse exact closed source label binding, not v3 records')
    image = FiniteV2(receipt)
    try:
        clones = image.logical('00004171.MDR', tables[3]['start'] + (12924 - 1) * 14, 441 * 14, 'actual_v2_Beitun_L3_family')
        flags_seen = {}
        for at in range(0, len(clones), 14):
            value = int.from_bytes(clones[at:at + 14], 'little')
            f, n, flags = (value >> 20) & 0x7fffff, (value >> 43) & 0xfff, (value >> 55) & 511
            next_level = flags & 7
            need(value & 1 and next_level in (4, 5, 6) and f >= 1 and n >= 1 and f + n - 1 <= tables[next_level]['count'],
                 'Each cloned v2 street retains valid actual v2 child pointers')
            flags_seen[str(flags)] = flags_seen.get(str(flags), 0) + 1
        low, shift = divmod((74 - 1) * 122, 8)
        window = image.logical('00004171.MDR', tables[2]['start'] + low, (shift + 122 + 7) // 8, 'actual_v2_L2_ID74')
        old_value = (int.from_bytes(window, 'little') >> shift) & ((1 << 122) - 1)
        widths = (1, 19, 19, 16, 10, 9, 24, 24)
        values = unpack(old_value, widths)
        need(values == [1, 24068, 24067, 12924, 441, 3, 1126994, 5624389], 'Current v2 original district context')
        changed = list(values)
        changed[3:5] = [47871, 442]
        patch = pack(changed, widths)
        need((int.from_bytes(patch, 'little') ^ old_value) & ~(((1 << 26) - 1) << 39) == 0,
             'Only L2 first/count fields change')
        street = pack([1, 475679, tables[4]['count'] + 1, 1, 4, *source['raw24']], (1, 19, 23, 12, 9, 24, 24))
        house = pack([1, (1 << 19) - 1, 2967, 0, 0, 0, *source['raw24']], (1, 19, 19, 22, 10, 9, 24, 24))
        reads = list(image.reads)
        stat_before = list(image.before)
    finally:
        image.close()
    new_mdr_bytes = plan['new_size'] + len(clones) + len(street) + len(house)
    new_gmp_bytes = 3812824 + 3805448
    sizes = [new_mdr_bytes if c['name'] == '00004171.MDR' else new_gmp_bytes if c['name'] == 'I053061A.GMP' else c['bytes'] for c in receipt['components']]
    rows = 1 + sum(((n + 4095) // 4096 + 239) // 240 for n in sizes)
    metadata = ((4096 + rows * 512 + 4095) // 4096) * 4096
    final_bytes = metadata + sum(((n + 4095) // 4096) * 4096 for n in sizes)
    need(final_bytes <= 134217728, 'One proposed street fits original 4K declared profile')
    OUT.mkdir()
    artifacts = [save('L3-family-append.bin', clones + street), save('L4-house-append.bin', house),
                 save('L2-patch-record.bin', patch), save('LBL-label-extension.bin', extension),
                 save('LBL-header-pointer-size.bin', label_header)]
    proof = dict(schema='source-bound-country-v2-new-street-family-payload/v1', created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True, script_sha256=sha(Path(__file__).read_bytes()), prerequisite_pins=PINS,
        actual_v2_source_SHA_inherited='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
        actual_v2_stat_before=stat_before, actual_v2_source_stat_unchanged=True, actual_IMG_read_log=reads,
        actual_IMG_bytes_read=sum(r['bytes'] for r in reads), original_v2_family_copied_verbatim=441,
        clone_flags_seen=flags_seen, source_street=source['streettext'], source_house=source['house_label'], source_ids=source['source_ids'],
        source_raw24=source['raw24'], source_and_raw24_in_exact_source_district=True, source_alias_or_official_street_verified=False,
        district_membership_evidence='staging/navigation-beitun-district-geometry-v1/source-membership.json',
        new_street_ID=48312, new_family_first=47871, new_L4_house_ID=3781595, final_L3_count=48312,
        v3_L3_or_child_pointers_reused=False, L2_first_count_patch_only=True, L2_initial_bit_shift=shift,
        proposed_MDR_bytes=new_mdr_bytes, proposed_GMP_bytes=new_gmp_bytes,
        proposed_complete_4K_IMG_bytes=final_bytes, proposed_metadata_bytes=metadata, proposed_FAT_rows=rows,
        original_declared_capacity_bytes=134217728, original_4K_declared_profile_capacity_fits=True,
        original_checksum_or_CHS_not_modified_here=True, current_device_v2_untouched=True, artifacts=artifacts,
        complete_MDR_GMP_IMG_SQLite_or_bundle_created=False, native_CPU_or_frontend_query_executed=False,
        device_IO=False, installable=False, full_Taiwan_update_complete=False,
        limits=['Finite payloads and allocation calculation only; no actual full new container or rollback composition.',
                'New street coordinates come from a single source house; not a measured street centroid or official-name verification.',
                'Full JAI prototype and native frontend are separate; host FTS is not original UI acceptance.',
                'The original v2 child pointers are retained; closed v3-family payload cannot be substituted.',
                'Current v2 limited physical controls passed historically; this new-street prototype has no physical acceptance.'])
    saved = save('proof.json', proof)
    print(json.dumps(dict(all_passed=True, proof=saved, actual_IMG_bytes_read=proof['actual_IMG_bytes_read'],
                         proposed_4K_IMG_bytes=final_bytes, installable=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
