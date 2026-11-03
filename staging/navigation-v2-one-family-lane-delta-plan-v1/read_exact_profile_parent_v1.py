#!/usr/bin/env python3
"""Bounded ordinary AP/FAT/MDR/LBL reads; no tree sweep, CPU or writer execution."""
import hashlib
import json
import struct
import traceback
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-v2-one-family-lane-delta-plan-v1'
LIMIT = 2 * 1024 * 1024
NAMES = ('00004171.MD2', '00004171.MDR', '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS')
PROFILE = [([16,9,24,19,1,10,0,0],[1,1],122), ([16,9,24,19,1,10,0,0],[1,1],122),
           ([23,9,24,19,1,12,0,0],[1,0],112), ([22,9,24,19,1,10,0,0],[1,1],128),
           ([21,9,24,19,1,9,0,0],[1,1],126), ([0,0,24,19,1,0,0,0],[1,0],68)]
CURRENT_DIR = ('83fa6707500100007a000000c18441c90a000000'
               '14e667076f1400007a000000c18441c90a000000'
               '30ac5d07e4390a0070000000c1845d490c000000'
               '906ec203a03d9b0380000000c18459c90a000000'
               '4d584101431681027e000000c18455c909000000'
               '1c0340003155010144000000c184014000000000')
SOURCES = [('v2', 'staging/navigation-country-native-candidate-v2', 4096,
            '659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766',
            '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
            [22,343,47870,3781594,2667573,1984066]),
           ('v3', 'staging/navigation-country-native-lane-candidate-v3', 8192,
            'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335',
            '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
            [22,343,47870,4896236,3077845,2062771])]
DEPENDENCIES = [('staging/navigation-country-native-lane-independent-review-v3/review_actual_v3.py',
                 'e4b5cebe1f805e4569929fa43111efd92aed8af560993b619a89c17c8a8acb56'),
                ('staging/navigation-native-current-profile-cow-writer-v1/current_profile_cow_writer.py',
                 '71673de65c6e94da664ad8bc8b81307c37a6dfbf94d819eebfa888274b688c9e')]
READS = []
PINS = []
RESULTS = {}


def need(test, reason):
    if not test:
        raise ValueError(reason)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def load_pin(rel, digest):
    p = ROOT / rel
    before = stat(p)
    raw = p.read_bytes()
    need(sha(raw) == digest and stat(p) == before, 'Normal-file pin/stat mismatch: ' + rel)
    PINS.append({'path': rel, 'bytes': len(raw), 'sha256': digest, 'stat_before': before, 'stat_after': stat(p)})
    return raw


class Image:
    # Adapted read-only allocation mapping from sealed independent Image8K.
    # Explicit block_bytes permits actual v2 4K and actual v3 8K; not a writer.
    def __init__(self, name, p, block_bytes):
        self.name, self.path, self.block_bytes = name, p, block_bytes
        self.before = stat(p)
        self.size = self.before[2]
        self.f = p.open('rb')
        need(self.size > 0 and self.size % block_bytes == 0, 'Whole physical blocks')
        h = self.physical(0, 512, 'actual AP header')
        self.header = h
        need(h[0] == 0 and h[16:23] == b'DSKIMG\0' and h[65:72] == b'GARMIN\0' and h[510:512] == b'\x55\xaa', 'AP markers/XOR0')
        need((h[97], h[98]) == (9, 3 if block_bytes == 4096 else 4), 'Actual block exponent profile')
        blocks = struct.unpack_from('<H', h, 99)[0]
        sectors = struct.unpack_from('<I', h, 458)[0]
        self.capacity = blocks * block_bytes
        need(blocks == 32768 and self.capacity == sectors * 512 and self.size <= self.capacity, 'Coherent declared capacity')
        start = h[64] * 512
        need(512 <= start < self.size, 'Root directory start')
        root = self.physical(start, 512, 'actual root DIR row')
        need(root[0] == 1 and root[1:12] == b' ' * 11 and root[16] == 3 and struct.unpack_from('<H', root, 17)[0] == 0, 'Canonical root DIR')
        end = struct.unpack_from('<I', root, 12)[0]
        need(start + 512 <= end <= min(self.size, 1000000) and end % block_bytes == 0, 'Bounded aligned metadata extent')
        need(self.blocks(root) == tuple(range(end // block_bytes)), 'Metadata allocation exact')
        directory = root + self.physical(start + 512, end - start - 512, 'actual bounded FAT allocation rows')
        owners = {n: '<metadata>' for n in range(end // block_bytes)}
        components, order, last = {}, [], None
        for at in range(512, len(directory), 512):
            row = directory[at:at + 512]
            if row[0] == 0:
                need(row == bytes(512), 'Unused FAT row zero')
                continue
            need(row[0] == 1 and row[16] != 3, 'Allocated component row')
            name = row[1:9].decode('ascii').rstrip(' ') + '.' + row[9:12].decode('ascii').rstrip(' ')
            part = struct.unpack_from('<H', row, 17)[0]
            size = struct.unpack_from('<I', row, 12)[0]
            if part == 0:
                need(name not in components and size > 0, 'Unique component')
                components[name] = {'size': size, 'blocks': [], 'part_count': 0}
                order.append(name)
                last = name
            need(name == last and part == components[name]['part_count'], 'Ordered FAT continuation')
            need(part == 0 or size == 0, 'Continuation size zero')
            ids = self.blocks(row)
            need(bool(ids), 'Nonempty allocated part')
            for b in ids:
                need(b not in owners, 'No overlapping block allocation')
                owners[b] = name
            components[name]['blocks'].extend(ids)
            components[name]['part_count'] += 1
        need(tuple(order) == NAMES, 'Exact six component names/order')
        for c in components.values():
            need(len(c['blocks']) == (c['size'] + block_bytes - 1) // block_bytes, 'Logical allocation count')
            need(c['part_count'] == (len(c['blocks']) + 239) // 240, 'Allocation part count')
        need(set(owners) == set(range(self.size // block_bytes)), 'No unallocated physical blocks')
        self.components = components
        self.metadata_start, self.metadata_end = start, end

    def blocks(self, row):
        result, sentinel = [], False
        for b in struct.unpack_from('<240H', row, 32):
            if b == 65535:
                sentinel = True
            else:
                need(not sentinel and b < self.size // self.block_bytes, 'Block after sentinel/outside image')
                result.append(b)
        return tuple(result)

    def physical(self, at, n, reason):
        need(type(at) is int and type(n) is int and 0 <= at <= at + n <= self.size, 'Physical range bounds')
        need(sum(x['bytes'] for x in READS) + n <= LIMIT, 'Global 2MiB IMG read budget')
        self.f.seek(at)
        b = self.f.read(n)
        need(len(b) == n, 'Complete actual physical read')
        READS.append({'source': self.name, 'path': str(self.path.relative_to(ROOT)), 'physical_offset': at,
                      'bytes': n, 'SHA256': sha(b), 'purpose': reason})
        return b

    def logical(self, name, at, n, reason):
        c = self.components[name]
        need(0 <= at <= at + n <= c['size'], 'Logical range bounds')
        result, cursor = bytearray(), at
        while cursor < at + n:
            ordinal, within = divmod(cursor, self.block_bytes)
            amount = min(at + n - cursor, self.block_bytes - within)
            result.extend(self.physical(c['blocks'][ordinal] * self.block_bytes + within, amount,
                                       reason + '; ' + name + ' logical ' + str(cursor)))
            cursor += amount
        return bytes(result)

    def close(self):
        self.f.close()
        need(self.before == stat(self.path), 'Actual IMG stat changed')


def decode_parent(raw, initial_shift, table):
    value = int.from_bytes(raw, 'little') >> initial_shift & ((1 << table['stride']) - 1)
    widths, refs = table['widths'], table['refs']
    cursor, result = 0, {}
    for name, width, on, isref in [('mapordinal', widths[4], True, False),
          ('secondary_ref', widths[3], bool(refs[1]), True), ('primary_ref', widths[3], bool(refs[0]), True),
          ('first_child', widths[0], bool(widths[0]), False), ('child_count', widths[5], bool(widths[5]), False),
          ('raw_flags', widths[1], bool(widths[1]), False), ('raw_location_a', widths[2], bool(widths[2]), False),
          ('raw_location_b', widths[2], bool(widths[2]), False)]:
        v = value >> cursor & ((1 << width) - 1) if on else None if isref else 0
        result[name] = None if on and isref and v == (1 << width) - 1 else v
        cursor += width if on else 0
    need(cursor == table['stride'], 'Full descriptor-based bit decode')
    result.update({'raw_record_value': value, 'raw_record_hex': raw.hex(), 'initial_bit_shift': initial_shift,
                   'next_level': result['raw_flags'] & 7})
    return result


def inspect(tag, rel, block_bytes, seal_digest, inherited_IMG_digest, counts, parent_record):
    seal = json.loads(load_pin(rel + '/sealed-files.json', seal_digest))
    path = ROOT / rel / 'gmapprom1.img'
    pin = next(x for x in seal['files'] if x['path'] == str(path.relative_to(ROOT)))
    need(pin['sha256'] == inherited_IMG_digest, 'Inherited full IMG digest identity')
    before = stat(path)
    need(before[:4] == pin['stat_at_seal'][:4], 'IMG device/inode/size/mtime from prior seal')
    im = None
    try:
        im = Image(tag, path, block_bytes)
        header = im.logical('00004171.MDR', 0, 772, 'actual MDR header')
        need(header[2:12] == b'GARMIN MDR' and struct.unpack_from('<H', header)[0] == 772, 'MDR header')
        start, size, item, flag = struct.unpack_from('<4I', header, 600)
        need((size, item, flag) == (120, 20, 1) and start + size == im.components['00004171.MDR']['size'], 'Six-entry DIR/EOF')
        directory = im.logical('00004171.MDR', start, size, 'actual120-byte MDR DIR')
        if tag == 'v2':
            need(directory.hex() == CURRENT_DIR, 'Actual v2 directory equals sealed current-profile constant')
        tables = {}
        for level in range(1, 7):
            a, b, stride, w, x = struct.unpack_from('<5I', directory, (level - 1) * 20)
            widths = [w >> 18 & 63, w >> 24 & 63, w >> 12 & 63, w >> 6 & 63, w & 63, x & 63, x >> 11 & 63, x >> 17 & 63]
            refs = [w >> 30 & 1, w >> 31 & 1]
            count = b * 8 // stride
            need((widths, refs, stride) == PROFILE[level - 1] and count == counts[level - 1], 'Actual unchanged profile/count')
            need(b == (count * stride + 7) // 8, 'Table exact significant-bit length')
            tables[str(level)] = {'level': level, 'start': a, 'bytes': b, 'count': count,
                'stride': stride, 'widths': widths, 'refs': refs, 'directory_hex': directory[(level - 1) * 20:level * 20].hex()}
        cursor = tables['6']['start']
        for level in [6,5,4,3,2,1]:
            t = tables[str(level)]
            need(t['start'] == cursor, 'Contiguous table suffix')
            cursor += t['bytes']
        need(cursor == start, 'Tables close at DIR')
        level, ID = parent_record >> 28, parent_record & 0xfffffff
        need(level == 3 and 1 <= ID <= tables['3']['count'], 'Exact parent record ID bounds')
        t = tables['3']
        bit = (ID - 1) * t['stride']
        byte, shift = divmod(bit, 8)
        raw = im.logical('00004171.MDR', t['start'] + byte, (shift + t['stride'] + 7) // 8, 'actual exact L3 stock parent record')
        parent = decode_parent(raw, shift, t)
        need(parent['mapordinal'] == 1, 'Parent AP mapordinal')
        next_level = parent['next_level']
        need(4 <= next_level <= 6 and parent['child_count'] > 0, 'Parent nonempty actual lower range')
        need(1 <= parent['first_child'] <= parent['first_child'] + parent['child_count'] - 1 <= tables[str(next_level)]['count'], 'Actual parent child range bounds')
        gmp = im.logical('I053061A.GMP', 0, 57, 'actual GMP header for existing label')
        need(gmp[2:12] == b'GARMIN GMP' and struct.unpack_from('<H', gmp)[0] == 57, 'GMP header')
        lbl_at = struct.unpack_from('<7I', gmp, 25)[2]
        lbl = im.logical('I053061A.GMP', lbl_at, 661, 'actual LBL descriptor')
        need(lbl[2:12] == b'GARMIN LBL' and struct.unpack_from('<H', lbl)[0] == 661, 'LBL header')
        pool_start, pool_size = struct.unpack_from('<II', lbl, 21)
        label_shift = lbl[29]
        need((pool_start, pool_size, label_shift, lbl[30], struct.unpack_from('<H', lbl, 170)[0]) == (6566,3805432,3,10,950), 'Existing exact CP950 label descriptor')
        ref = parent['primary_ref']
        need(ref is not None and 0 <= ref << label_shift < pool_size, 'Actual parent labelref within pool')
        text = im.logical('I053061A.GMP', pool_start + (ref << label_shift), min(64, pool_size - (ref << label_shift)), 'actual exact parent CP950 labelref')
        end = text.find(b'\0')
        need(end >= 0, 'Bounded label NUL')
        label = text[:end].decode('cp950')
        need(label == '昌平路二段', 'Actual exact stock parent label; no nearest or alias')
        parent.update({'record': parent_record, 'ID': ID, 'level': level,
                       'label': label, 'label_ref_actual': ref, 'label_CP950_hex': text[:end].hex(),
                       'logical_record_offset': t['start'] + byte})
        (OUT / (tag + '-actual120-directory.bin')).write_bytes(directory)
        (OUT / (tag + '-actual512-header.bin')).write_bytes(im.header)
        return {'path': rel + '/gmapprom1.img', 'inherited_full_SHA256_not_recomputed': inherited_IMG_digest,
            'source_stat_before': before, 'source_stat_after': stat(path),
            'prior_seal_stat_at_seal': pin['stat_at_seal'], 'ctime_change_not_semantic_modification': before[4] != pin['stat_at_seal'][4],
            'block_bytes': block_bytes, 'physical_IMG_bytes': im.size, 'capacity_declaration_bytes': im.capacity,
            'AP_header_SHA256': sha(im.header), 'raw_AP_header_hex': im.header.hex(),
            'metadata_start': im.metadata_start, 'metadata_end': im.metadata_end,
            'MDR_bytes': im.components['00004171.MDR']['size'], 'DIR_logical_offset': start,
            'DIR_bytes': 120, 'DIR_hex': directory.hex(), 'DIR_SHA256': sha(directory),
            'actual_tables': tables, 'exact_parent_record': parent,
            'selected_L4_L5_L6_records_traversed': 0, 'target_house_matching_attempted': False,
            'full_GMP_or_label_pool_unchanged_scope': 'Inherited prior whole-component proofs; this scope reads exact descriptor and parent text only.'}
    finally:
        if im:
            im.close()


def main():
    for rel, pin in DEPENDENCIES:
        load_pin(rel, pin)
    source_proof = json.loads((OUT / 'proof.json').read_text())
    need(source_proof['failed_gate_holds'] == ['floor_unit_absent'], 'Keep actual source failure gate')
    parent_record = source_proof['exact_stock_parent']['record']
    for args in SOURCES:
        RESULTS[args[0]] = inspect(*args, parent_record)
    need(RESULTS['v2']['actual_tables']['3']['widths'][0] == RESULTS['v3']['actual_tables']['3']['widths'][0] == 23, 'Actual v2/v3 L3 first width23')
    need(RESULTS['v2']['actual_tables']['3']['stride'] == RESULTS['v3']['actual_tables']['3']['stride'] == 112, 'Actual v2/v3 L3 stride112')
    report = {'schema': 'bounded_actual_v2_v3_DIR_exact_parent_metadata/v1',
        'assigned_metadata_reads_passed': True, 'results': RESULTS, 'ordinary_dependency_and_seal_pins': PINS,
        'actual_IMG_read_bytes': sum(r['bytes'] for r in READS), 'actual_IMG_read_operations': len(READS),
        'global_IMG_budget_bytes': LIMIT, 'actual_read_journal': READS,
        'source_group_floor_hold_not_overridden': True, 'family_delta_plan_completed': False,
        'native_CPU_instructions': 0, 'new_IMG_or_payload_created': False,
        'errata': {'prior_parent_task_assumption': 'current-v2 L3 width22/stride111',
            'actual_v2_and_v3': 'L3 first-child width23/stride112; 22/111 is original stock, not current-v2',
            'current_v2_descriptor_preserved': True, 'no_global_width_change_planned': True,
            'v3_L4_count_crossing_2_power22_not_a_width_delta_or_root_cause': True},
        'width_arithmetic_only': {'L3_first_child_max_23bit': (1 << 23) - 1,
            'v2_L4_count': RESULTS['v2']['actual_tables']['4']['count'],
            'v3_L4_count': RESULTS['v3']['actual_tables']['4']['count'],
            'selected_family_appended_counts': None, 'new_total_counts': None,
            'requested_v2_single_family_image_capacity': None,
            'reason': 'Target group is held by20 separate-floor/unit source nodes; exact subtree/house coordinate match and clone/remap not attempted.'}}
    write('actual-profile-parent-proof.json', report)
    print(json.dumps({'status': 'actual_DIR_and_exact_parent_checked_source_still_held',
        'actual_IMG_bytes': report['actual_IMG_read_bytes'], 'read_operations': len(READS),
        'v2_DIR_SHA256': RESULTS['v2']['DIR_SHA256'], 'v3_DIR_SHA256': RESULTS['v3']['DIR_SHA256'],
        'L3_first_width_both': 23, 'L3_stride_both': 112,
        'v2_exact_parent': RESULTS['v2']['exact_parent_record'], 'v3_exact_parent': RESULTS['v3']['exact_parent_record'],
        'source_still_held': True, 'subtree_records_traversed': 0, 'native_CPU_instructions': 0}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        write('actual-profile-parent-failure.json', {'error': str(exc), 'traceback': traceback.format_exc(),
            'results_completed': RESULTS, 'ordinary_pins': PINS, 'actual_read_journal': READS,
            'actual_IMG_bytes': sum(x['bytes'] for x in READS), 'global_IMG_limit': LIMIT,
            'native_CPU_instructions': 0, 'family_delta_completed': False})
        raise
