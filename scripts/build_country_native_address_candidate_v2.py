#!/usr/bin/env python3
"""Compose a new 4K country+Kaohsiung+flat-city candidate; drop one proved outlier.

All frozen inputs remain unchanged. Significant-bit concatenation, remapped
parent/new-leaf metadata, then physical candidate readback are distinct stages.
No CPU, device, package, publishing or source-PBF operations are performed.
"""
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import itertools
import json
import mmap
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-country-native-candidate-v2'
COUNTRY = ROOT / 'staging/navigation-country-native-house-merge-v1'
KH = ROOT / 'staging/navigation-kaohsiung-native-house-merge-v1'
FLAT = ROOT / 'staging/navigation-flat-city-native-house-merge-v1'
WRITER = ROOT / 'staging/navigation-native-multilevel-mdr-writer-v1'
REVIEW = ROOT / 'staging/navigation-country-merge-independent-review-v1'
GEOMETRY = ROOT / 'staging/navigation-country-city-geometry-v1'
SOURCE = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
SEAL_PINS = {
    COUNTRY / 'sealed-files.json': '92577ed46a3bc321a5580b06262f5a74d1d82be9af673186848905a9446afd10',
    KH / 'sealed-files.json': '9700bd027bdf9f6e4c181ce2207b28e371ba070b86707cce146943d606f02234',
    WRITER / 'file-seal-v1.json': '72b01ddfae4e7727bd115512639fc00ba917b562fe7be9b963bdd5e4de9c902a',
    REVIEW / 'sealed-files.json': '19d42e984a15d9f32a8e7d19770925708675d6dce8a876ac77233c796d9c93ff',
    FLAT / 'sealed-files.json': '7919a4faf55abe2e89845b5e0d919717ab2e9ddb856517d0ac95588b5f18e263',
}
WRITER_SHA = '3508e01e8ba6e3fd3388322c8da575f2dff96a4f1dd836b15eeaa25bd88e3958'
REVIEW_SHA = 'c23c40cb82bb73a601bbb5949db0752cc03b763f66cd564f39706224cc98ccea'
CITY_SHA = 'cd44ea3aba74357480487ab83cf228232bdf0fc99821d7bf39fd58bbcd50cfc5'
STRIDES = {4: 128, 5: 126, 6: 68}
DROP = dict(nativeStreetID=6676, level=4, new_lowID=2382209, city='桃園市', house_label='810號',
            source_coordinate_strings=['24.9285209', '121.058782'], raw24=[1161753, 5641748])
INPUTS = {}


def need(ok, message):
    if not ok: raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha(data): return hashlib.sha256(data).hexdigest()


def sha_file(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def stat(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def bind(path, digest=None, size=None):
    before = stat(path)
    if size is not None: need(before[2] == size, 'Pinned input size: ' + str(path))
    actual = sha_file(path)
    if digest is not None: need(actual == digest, 'Pinned input hash: ' + str(path))
    need(stat(path) == before, 'Input changed while binding')
    INPUTS[str(path)] = dict(path=str(path.relative_to(ROOT)), bytes=before[2], sha256=actual, stat_before=list(before))
    return actual


def saved(path, value):
    raw = value if isinstance(value, bytes) else canonical(value) + b'\n'
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'Complete small write'); stream.flush(); os.fsync(stream.fileno())
    return dict(path=path.name, bytes=len(raw), sha256=sha(raw))


def saved_ranges(path, rows):
    hashed=hashlib.sha256();amount=0
    with path.open('xb') as stream:
        def write(raw):
            nonlocal amount
            need(stream.write(raw)==len(raw),'Complete selected row write');hashed.update(raw);amount+=len(raw)
        write(b'[\n')
        for index,row in enumerate(rows):
            if index:write(b',\n')
            write(canonical(row))
        write(b'\n]\n');stream.flush();os.fsync(stream.fileno())
    return dict(path=path.name,bytes=amount,sha256=hashed.hexdigest(),rows=len(rows))


def module(path, digest, name):
    bind(path, digest)
    spec = importlib.util.spec_from_file_location(name, path)
    imported = importlib.util.module_from_spec(spec); sys.modules[name] = imported; spec.loader.exec_module(imported)
    return imported


def load_dependencies():
    seals = {}
    for path, expected in SEAL_PINS.items():
        bind(path, expected); seals[path.parent] = json.loads(path.read_text())
    inputs = {}
    for directory in (COUNTRY, KH, FLAT):
        rows = {row['path']: row for row in seals[directory]['files']}
        for name in ('proof.json', 'selected-street-ranges.json', 'new-house-records.jsonl.gz',
                     'appended-level4.bin', 'appended-level5.bin', 'appended-level6.bin'):
            row = rows[name]; bind(directory / name, row['sha256'], row['bytes'])
        proof = json.loads((directory / 'proof.json').read_text())
        need(proof['all_assigned_checks_passed'], 'Successful frozen merge')
        inputs[directory] = proof
    for row in seals[WRITER]['files']:
        bind(ROOT / row['path'], row['sha256'], row['bytes'])
    writer = module(WRITER / 'multilevel_mdr_writer.py', WRITER_SHA, 'country_v2_sealed_multilevel_writer')
    bind(REVIEW / 'proof.json', REVIEW_SHA)
    review = json.loads((REVIEW / 'proof.json').read_text())
    need(review['all_assigned_checks_passed'] and review['quantized_point_city_membership_outliers'] == [DROP], 'Unique proved v1 grid outlier')
    bind(GEOMETRY / 'city-geometries.json', CITY_SHA)
    geos = json.loads((GEOMETRY / 'city-geometries.json').read_text())
    need(len(geos) == 21 and '高雄市' not in geos, 'Original complete city scope')
    engine = module(ROOT / 'scripts/prepare_taichung_city_geometry_v1.py',
                    '2fff38c613a41017553f8a59978b85811fce6b118b6db87cfc07fe1e17d74101', 'candidate_v2_city_engine')
    kh_policy = module(KH / 'merge_policy.py',
                       next(row['sha256'] for row in seals[KH]['files'] if row['path'] == 'merge_policy.py'), 'candidate_v2_kh_policy')
    validator = kh_policy.district_validator()
    # Pin every frozen district prerequisite consumed by that validator.
    district_dir = ROOT / 'staging/navigation-kaohsiung-district-geometry-v1'
    bind(district_dir / 'sealed-files.json', '3cffbeb8246e8f87428ce1fe376f1b2de1922f37d6386575be993a7c56095541')
    for name in ('district_membership.py', 'district-geometries.json', 'source-membership.json', 'proof.json'):
        bind(district_dir / name)
    flat_dir=ROOT/'staging/navigation-flat-city-district-geometry-v1'
    bind(flat_dir/'sealed-files.json','a022c04e9192c011cc2502068bc46d1d767e64f246e70ec32737432ede814948')
    for name in ('dataset-pins.json','district-geometries.json','source-membership.json','proof.json'):
        bind(flat_dir/name)
    flat_api=module(flat_dir/'source_district_membership.py',
        '91c023c6d9dedd8ca0e55d95d0575fe443e277edfdde236fe50bbada648acedb','candidate_v2_flat_source_district_api')
    return writer, inputs, geos, engine, kh_policy, validator, flat_api.SourceDistrictMembership()


def extract(wire, bit, width):
    byte, shift = divmod(bit, 8)
    n = (shift + width + 7) // 8
    need(byte + n <= len(wire), 'Packed input record bounds')
    return (int.from_bytes(wire[byte:byte+n], 'little') >> shift) & ((1 << width)-1)


def significant_hash(values, width):
    digest = hashlib.sha256()
    for value in values: digest.update(value.to_bytes((width+7)//8, 'little'))
    return digest.hexdigest()


def tight_hash(values, width):
    acc, pending, digest = 0, 0, hashlib.sha256(); buffer = bytearray()
    for value in values:
        acc |= value << pending; pending += width
        while pending >= 8:
            buffer.append(acc & 255); acc >>= 8; pending -= 8
    if pending: buffer.append(acc)
    digest.update(buffer); return digest.hexdigest()


def decoded(value, level):
    def f(at, width): return (value >> at) & ((1 << width)-1)
    need(f(0, 1) == 1, 'Native mapordinal1')
    if level == 4:
        need(f(1,19) == 524287 and f(39,22) == f(61,10) == f(71,9) == 0, 'L4 new leaf fields')
        return f(20,19), [f(80,24),f(104,24)]
    if level == 5:
        need(f(1,19) == 524287 and f(39,21) == f(60,9) == f(69,9) == 0, 'L5 new leaf fields')
        return f(20,19), [f(78,24),f(102,24)]
    return f(1,19), [f(20,24),f(44,24)]


def signed24(value):
    need(type(value) is int and 0 <= value < 1 << 24, 'Unsigned raw24')
    return value - (1 << 24) if value & (1 << 23) else value


def rational_covers(geometry, raw24):
    y, x = (Fraction(signed24(value)*360*10000000, 1 << 24) for value in raw24)
    for rings in geometry.polygons:
        outer = rings[0].test(x,y)
        if outer == 2: return True
        if not outer: continue
        holes = [ring.test(x,y) for ring in rings[1:]]
        if 2 in holes or 1 not in holes: return True
    return False


def norm(value):
    import unicodedata
    return unicodedata.normalize('NFKC', value or '').strip().replace('臺','台')


class Membership:
    def __init__(self, geos, engine, kh_policy, validator, flat_validator):
        self.rows = {norm(name): row for name,row in geos.items()}
        self.engine, self.kh_policy, self.validator = engine, kh_policy, validator
        self.flat_validator=flat_validator

    @lru_cache(maxsize=2)
    def city(self, name):
        need(name in self.rows, 'Known complete source city')
        return self.engine.CityGeometry(self.rows[name]['geometry'])

    def assess(self, row, source_merge):
        lat, lon = row['coordinate_strings']
        need(Decimal(lat).is_finite() and Decimal(lon).is_finite() and -90 <= Decimal(lat) <= 90 and
             -180 <= Decimal(lon) < 180, 'Bounded source coordinate')
        expected = [int((Decimal(point)*Decimal(1<<24)/Decimal(360)).to_integral_value(rounding=ROUND_HALF_UP)) & 0xffffff for point in (lat,lon)]
        need(expected == row['raw24'], 'Actual source point nearest raw24 unchanged')
        if source_merge=='flat_city_v1':
            need(row['city'] in {'台北市','基隆市','新竹市','嘉義市'} and row['district'] is None and
                 row['native_district_record'] is None and row['native_district_verified'] is False,
                 'Four original city-to-street layouts retain null native district')
            source=self.flat_validator.assess(row['source_city'],row['source_district'],lat,lon)
            pair=self.flat_validator.assess_source_and_raw24(row['source_city'],row['source_district'],lat,lon,row['raw24'])
            need(pair.get('native_city')==row['city'] and pair.get('native_district_record') is None and
                 pair['native_district_verified'] is False,'Literal source district does not fabricate native district')
            need(all(member['raw_address'][1]==row['source_district'] for member in row['source_members']),
                 'All flat source members declare the same literal district')
            return source['eligible'],pair.get('quantized_point_inside',False),dict(
                scope='literal_source_district_with_original_native_city_to_street_layout',
                relation_id=source.get('source_relation_id'),source_district=row['source_district'],
                native_district_record=None,native_district_verified=False,
                source_inside=source['eligible'],quantized_inside=pair.get('quantized_point_inside',False))
        if source_merge == 'kaohsiung_v1':
            source = self.validator.assess(row['city'],row['district'],lat,lon)
            quantized = self.kh_policy.quantized_assess(self.validator,row['city'],row['district'],row['raw24'])
            return source['eligible'], quantized['eligible'], dict(scope='exact_complete_district',
                relation_id=source.get('source_relation_id'),source_inside=source['eligible'],quantized_inside=quantized['eligible'])
        name = norm(row['city']); geometry = self.city(name)
        source_inside = geometry.covers(lat,lon); quantized_inside = rational_covers(geometry,row['raw24'])
        return source_inside, quantized_inside, dict(scope='complete_city_under_original_host_name_policy',
            relation_id=self.rows[name]['source_relation_id'],source_inside=source_inside,quantized_inside=quantized_inside)


class GzipLedger:
    def __init__(self, path):
        self.path, self.raw = path, path.open('xb')
        self.stream = gzip.GzipFile(filename='',mode='wb',fileobj=self.raw,mtime=0,compresslevel=6)
        self.digest, self.rows = hashlib.sha256(), 0

    def add(self, row):
        data = canonical(row) + b'\n'; self.stream.write(data); self.digest.update(data); self.rows += 1

    def finish(self):
        self.stream.close(); self.raw.flush(); os.fsync(self.raw.fileno()); self.raw.close()
        return dict(path=self.path.name,bytes=self.path.stat().st_size,sha256=sha_file(self.path),
                    rows=self.rows,uncompressed_sha256=self.digest.hexdigest())


def input_ledger(path, expected):
    plain = hashlib.sha256(); count = 0
    with gzip.open(path,'rb') as stream:
        for line in stream:
            plain.update(line); count += 1; yield json.loads(line)
    need(count == expected['rows'] and plain.hexdigest() == expected['uncompressed_sha256'], 'Source new ledger EOF/count/plain hash')


def identity(row):
    # Every input provenance field is retained; only remapped structural fields
    # and v2 annotations are excluded from this immutable source identity.
    ignore = {'new_lowID','appended_bit_offset','v2_combined_append_bit_offset','source_merge','previous_lowID',
              'remap_delta','previous_appended_bit_offset','previous_combined_append_bit_offset','candidate_v2_membership'}
    return {key:value for key,value in row.items() if key not in ignore}


def bit_splice(segments):
    """LSB-first bounded chunks; only segment final high padding is discarded.

    Each segment is (path, start_byte, declared_significant_bits). Partial bytes
    carry across segment boundaries and are flushed only once per final table.
    """
    carry = pending = 0
    for path,start,bits in segments:
        need(type(bits) is int and bits >= 0 and start >= 0,'Explicit bit segment')
        amount = (bits+7)//8
        need(start+amount <= path.stat().st_size,'Segment bounds')
        remaining = bits
        with path.open('rb') as stream:
            stream.seek(start)
            while remaining:
                size = min(65536,(remaining+7)//8)
                raw = stream.read(size); need(len(raw)==size,'Complete bit segment chunk')
                valid = min(remaining,size*8); value = int.from_bytes(raw,'little')
                need(value >> valid == 0,'Nonzero source segment final padding')
                combined = carry | (value << pending); available = pending + valid
                whole = available//8; encoded = combined.to_bytes((available+7)//8,'little')
                if whole: yield encoded[:whole]
                pending = available%8; carry = combined >> (whole*8); remaining -= valid
    if pending: yield bytes([carry])


def write_append(path, segments, records, width):
    digest = hashlib.sha256(); amount = 0
    with path.open('xb') as stream:
        for chunk in bit_splice(segments):
            need(stream.write(chunk)==len(chunk),'Complete spliced output write'); digest.update(chunk); amount += len(chunk)
        stream.flush(); os.fsync(stream.fileno())
    bits = records*width
    need(amount==(bits+7)//8,'Whole-table splice bit count')
    return dict(path=path.name,bytes=amount,sha256=digest.hexdigest(),record_count=records,
                record_bits=width,bit_length=bits,unused_final_high_bits=(-bits)%8,final_padding_zero=True)


def digest(chunks):
    total, hashed = 0, hashlib.sha256()
    for data in chunks: total += len(data); hashed.update(data)
    return dict(bytes=total,sha256=hashed.hexdigest())


def verify_candidate(writer, source, target, plan, receipt, ranges, ledger_artifact, append_artifacts,
                     membership, label, original_counts, expected_identity):
    """Read the completed physical IMG, not supplier or buffered producer data."""
    by_name={row['name']:row for row in receipt['components']}
    component_checks=[];table_checks=[];groups_checked=Counter();leaves_checked=Counter()
    def read(image,start,length):return b''.join(image.iter_component('00004171.MDR',offset=start,length=length))
    original_tables={index+1:row for index,row in enumerate(plan.old_tables)}
    new_tables={index+1:row for index,row in enumerate(plan.new_tables)}
    selected={row['nativeStreetID']:row for row in ranges}
    need(len(selected)==len(ranges),'Selected parent IDs unique')
    with target.open('rb') as cf:
        candidate=writer.core.StreamIMG(cf)
        need(candidate.prefix==source.prefix and candidate.order==source.order and candidate.capacity==source.capacity,
             'Original container header, authors, geometry and component names preserved')
        need(target.stat().st_size==receipt['image_bytes'],'Actual complete image bytes')
        for name in candidate.order:
            actual=digest(candidate.iter_component(name))
            need(actual=={key:by_name[name][key] for key in ('bytes','sha256')},'Full physical component hash')
            if name!='00004171.MDR':need(actual==digest(source.iter_component(name)),'Original other five logical components unchanged')
            component_checks.append(dict(name=name,**actual,unchanged_from_stock=name!='00004171.MDR'))
        header=read(candidate,0,772)
        need(header==plan.header and struct.unpack_from('<4I',header,600)==(plan.new_directory_start,120,20,1),'Actual new MDR header/directory descriptor')
        need(read(candidate,plan.new_directory_start,120)==plan.directory,'Actual six-table directory')
        need(new_tables[3]['stride']==112 and new_tables[3]['widths'][0]==23,'Widened L3 profile')
        for level in (4,5,6):
            old,new=original_tables[level],new_tables[level]
            prefix=digest(source.iter_component('00004171.MDR',offset=old['start'],length=old['bytes']))
            actual_prefix=digest(candidate.iter_component('00004171.MDR',offset=new['start'],length=old['bytes']))
            need(actual_prefix==prefix,'Complete original L4/L5/L6 byte prefix')
            artifact=append_artifacts[f'level{level}']
            actual_append=digest(candidate.iter_component('00004171.MDR',offset=new['start']+old['bytes'],length=artifact['bytes']))
            need(actual_append=={key:artifact[key] for key in ('bytes','sha256')},'Actual significant-bit-spliced append hash')
            need(new['count']==old['count']+artifact['record_count'],'Actual appended table count')
            table_checks.append(dict(level=level,original_count=old['count'],new_count=new['count'],
                                     original_byte_prefix=prefix,actual_append=actual_append,original_prefix_unchanged=True))
        unknown_start,unknown_bytes=772,original_tables[6]['start']-772
        need(digest(source.iter_component('00004171.MDR',offset=unknown_start,length=unknown_bytes))==
             digest(candidate.iter_component('00004171.MDR',offset=unknown_start,length=unknown_bytes)),'Original unknown MDR prefix')
        suffix_bytes=plan.old_directory_start-original_tables[2]['start']
        need(read(source,original_tables[2]['start'],suffix_bytes)==read(candidate,new_tables[2]['start'],suffix_bytes),
             'Original L2/L1 and real lookahead unchanged')
        need(read(candidate,new_tables[2]['start'],4)==plan.L2_lookahead,'No artificial L2 lookahead inserted')
        old_l3=read(source,original_tables[3]['start'],original_tables[3]['bytes'])
        actual_l3=read(candidate,new_tables[3]['start'],new_tables[3]['bytes'])
        for index in range(47870):
            previous=extract(old_l3,index*111,111)
            expected=(previous&((1<<42)-1))|((previous>>42)<<43)
            if row:=selected.get(index+1):
                mask=((1<<35)-1)<<20
                expected=(expected&~mask)|(row['new_first']<<20)|(row['new_count']<<43)
            need(int.from_bytes(actual_l3[index*14:index*14+14],'little')==expected,'Every original/widened/selected L3 field')
        need(sha_file(OUT/'kept-new-house-records.jsonl.gz')==ledger_artifact['sha256'],'Fresh kept ledger compressed hash')
        identity_digest=hashlib.sha256();old_records_compared=0;kept_count=0;new_positions=Counter();prev_source_order=0
        groups=itertools.groupby(input_ledger(OUT/'kept-new-house-records.jsonl.gz',ledger_artifact),
                                 key=lambda row:(row['next_level'],row['nativeStreetID']))
        for row,group in itertools.zip_longest(ranges,groups):
            need(row is not None and group is not None,'Every actual selected group/new ledger matching')
            key,members=group;level=row['next_level'];width=STRIDES[level]
            need(key==(level,row['nativeStreetID']),'Actual metadata/ledger original source order')
            bit=(row['new_first']-1)*width;byte,shift=divmod(bit,8)
            actual_bytes=read(candidate,new_tables[level]['start']+byte,(shift+row['new_count']*width+7)//8)
            values=[extract(actual_bytes,shift+index*width,width) for index in range(row['new_count'])]
            need(significant_hash(values,width)==row['new_significant_records_sha256'] and tight_hash(values,width)==row['new_group_tight_packed_sha256'],
                 'Every new physical group significant/tight hash')
            inserted=set();members=list(members)
            need(len(members)==row['new_integer_house_count'],'Every actual new leaf count per group')
            for leaf in members:
                need(leaf['source_merge']==row['source_merge'],'Actual source_merge parent binding')
                source_order={'country_v1':0,'kaohsiung_v1':1,'flat_city_v1':2}[leaf['source_merge']]
                need(source_order>=prev_source_order,'Original country ledger, then KH, then flat ledger order');prev_source_order=source_order
                previous=leaf['previous_lowID']
                delta=-1 if level==4 and (source_order>0 or previous>DROP['new_lowID']) else 0
                need(leaf['remap_delta']==delta and leaf['new_lowID']==previous+delta,'Every exact low-ID remapping')
                need(not (source_order==0 and level==4 and previous==DROP['new_lowID']),'Excluded row absent from kept provenance')
                need(leaf['appended_bit_offset']==leaf['v2_combined_append_bit_offset']==(leaf['new_lowID']-original_counts[level]-1)*width,
                     'Every remapped new offset in combined stream')
                position=leaf['new_lowID']-row['new_first']
                need(0<=position<len(values) and position not in inserted,'Every actual leaf unique/in group')
                inserted.add(position)
                value=values[position]
                need(value==int.from_bytes(bytes.fromhex(leaf['payload']),'little'),'Every physical new leaf payload unchanged')
                reference,point=decoded(value,level)
                need(reference==leaf['primary_ref'] and point==leaf['raw24'] and label(reference)==leaf['house_label'],
                     'Every actual new leaf ref/raw24/stock label')
                source_in,quantized_in,decision=membership.assess(leaf,leaf['source_merge'])
                need(source_in and quantized_in and decision==leaf['candidate_v2_membership'],'Every actual kept source and grid point membership')
                need(sorted({node for member in leaf['source_members'] for node in member['source_ids']})==leaf['source_ids'] and
                     [member['group_id'] for member in leaf['source_members']]==leaf['source_group_ids'],'Every actual full source provenance set')
                need(all(tuple(map(Decimal,member['coordinate_strings']))==tuple(map(Decimal,leaf['coordinate_strings']))
                         for member in leaf['source_members']),'Every actual source member Decimal point')
                identity_digest.update(canonical(identity(leaf))+b'\n');kept_count+=1;leaves_checked[level]+=1
                new_positions[(level,((leaf['new_lowID']-1)*width)%8)]+=1
            old_bit=(row['original_first']-1)*width;old_byte,old_shift=divmod(old_bit,8)
            old_bytes=read(source,original_tables[level]['start']+old_byte,(old_shift+row['original_count']*width+7)//8)
            original=[extract(old_bytes,old_shift+index*width,width) for index in range(row['original_count'])]
            retained=[value for index,value in enumerate(values) if index not in inserted]
            need(original==retained and significant_hash(original,width)==row['original_significant_records_sha256'],
                 'Every actual original group record bits/order/flags/coords/childrefs unchanged')
            if row['nativeStreetID']==DROP['nativeStreetID']:
                need(level==4 and row['new_count']==11 and row['new_integer_house_count']==2,'Excluded parent exact derived count')
                need(DROP['house_label'] not in [label((value>>20)&524287) for value in original],'Excluded value was not a stock exact address')
            old_records_compared+=len(original);groups_checked[level]+=1
        need(kept_count==ledger_artifact['rows']==130637 and identity_digest.hexdigest()==expected_identity,
             'Every kept source identity/full ledger count')
        need(sum(groups_checked.values())==len(ranges)==18823,'All selected actual groups checked')
    return dict(component_checks=component_checks,table_checks=table_checks,
        groups_checked_by_level=dict(groups_checked),new_leaf_counts_by_level=dict(leaves_checked),
        every_old_selected_group_record_directly_compared=old_records_compared,
        every_kept_new_source_identity_sha256=identity_digest.hexdigest(),kept_new_leaf_count=kept_count,
        actual_new_bit_shifts={str(level):sorted({shift for (lev,shift) in new_positions if lev==level}) for level in STRIDES},
        actual_new_bit_shift_counts={f'{level}:{shift}':count for (level,shift),count in new_positions.items()},
        candidate_native_CPU_executed=False,device_IO=False)


def main():
    need(OUT.exists() and not (OUT/'proof.json').exists() and not (OUT/'gmapprom1.img').exists(),
         'New v2 namespace with capacity preflight only')
    started = datetime.now(timezone.utc).isoformat()
    writer, proofs, geos, engine, kh_policy, validator, flat_validator = load_dependencies()
    membership = Membership(geos,engine,kh_policy,validator,flat_validator)
    ranges = {directory:json.loads((directory/'selected-street-ranges.json').read_text()) for directory in (COUNTRY,KH,FLAT)}
    original_counts = {int(k):v for k,v in proofs[COUNTRY]['original_counts'].items()}
    need(proofs[KH]['original_counts'] == proofs[COUNTRY]['original_counts'],'Same original record prefixes')
    need(proofs[KH]['starting_country_v1_counts'] == proofs[COUNTRY]['proposed_counts'],'KH starts after frozen v1')
    need(proofs[FLAT]['starting_country_v1_plus_KH_counts']==proofs[KH]['proposed_counts'] and
         proofs[FLAT]['original_counts']==proofs[COUNTRY]['original_counts'],'Flat follows frozen v1 plus KH')
    all_selected=[row['nativeStreetID'] for directory in (COUNTRY,KH,FLAT) for row in ranges[directory]]
    need(len(all_selected)==len(set(all_selected))==18823,'Actual three-source parent union unique/disjoint')
    streams, maps = {}, {}
    for directory in (COUNTRY,KH,FLAT):
        for level in (4,5,6):
            artifact = proofs[directory]['artifacts'][f'level{level}']
            need(artifact['bit_length']==artifact['record_count']*STRIDES[level] and
                 artifact['bytes']==(artifact['bit_length']+7)//8,'Input packed dimensions')
            f=(directory/artifact['path']).open('rb');streams[(directory,level)]=f
            maps[(directory,level)]=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
            if artifact['bit_length']%8:need(maps[(directory,level)][-1]>>(artifact['bit_length']%8)==0,'Input final padding')
    # Only bounded original container metadata and existing label pool are read
    # before a candidate is written. Full component/prefix checks happen after.
    source_before=stat(SOURCE)
    kept=GzipLedger(OUT/'kept-new-house-records.jsonl.gz')
    selected_output=[];cursor={4:0,5:0,6:0};counts=Counter();identity_digest=hashlib.sha256()
    dropped=None;drop_bit=None;input_row_counts={};kept_by_level=Counter();kept_by_source=Counter()
    with SOURCE.open('rb') as sf:
        source=writer.core.StreamIMG(sf)
        adapter=writer.ContainerAdapter.original_4k(source)
        need(source.capacity==134217728 and adapter.kind=='original4K','Explicit original 4K adapter')
        pool=b''.join(source.iter_component('I053061A.GMP',offset=6566,length=3805432))
        @lru_cache(maxsize=65536)
        def label(reference):
            need(type(reference)is int and 0<=reference<524287 and reference*8<len(pool),'Original house ref')
            at=reference*8;end=pool.find(b'\0',at,min(len(pool),at+512));need(end>=0,'Original label termination')
            return pool[at:end].decode('cp950',errors='strict')
        for directory,source_merge in ((COUNTRY,'country_v1'),(KH,'kaohsiung_v1'),(FLAT,'flat_city_v1')):
            proof=proofs[directory]
            groups=iter(itertools.groupby(input_ledger(directory/'new-house-records.jsonl.gz',proof['artifacts']['new_records']),
                key=lambda row:(row['next_level'],row['nativeStreetID'])))
            source_cursor={4:0,5:0,6:0};processed_rows=0
            for old_range in ranges[directory]:
                group=next(groups,None);need(group is not None,'Selected source parent has new leaf group')
                key,members=group;level=old_range['next_level'];width=STRIDES[level]
                need(key==(level,old_range['nativeStreetID']),'Input selected/ledger parent order')
                rows=list(members);processed_rows+=len(rows)
                need(len(rows)==old_range['new_integer_house_count'],'Input parent new leaf count')
                need(old_range['appended_bit_offset']==source_cursor[level],'Source groups continuous at true packed bits')
                values=[extract(maps[(directory,level)],old_range['appended_bit_offset']+index*width,width)
                    for index in range(old_range['new_count'])]
                need(significant_hash(values,width)==old_range['new_significant_records_sha256'] and
                     tight_hash(values,width)==old_range['new_group_tight_packed_sha256'],'Actual bound source group bytes/hashes')
                source_cursor[level]+=old_range['new_count']*width
                new_range=dict(old_range,source_merge=source_merge,previous_new_first=old_range['new_first'],
                    previous_new_count=old_range['new_count'],previous_appended_bit_offset=old_range['appended_bit_offset'],
                    previous_appended_record_ordinal=old_range['appended_record_ordinal'])
                new_range['appended_bit_offset']=cursor[level]
                new_range['appended_record_ordinal']=cursor[level]//width
                new_range['v2_combined_append_bit_offset']=cursor[level]
                new_range['new_first']=original_counts[level]+cursor[level]//width+1
                inserted=set();dropped_position=None;emitted_rows=[]
                for row in rows:
                    old_pos=(row['appended_bit_offset']-old_range['appended_bit_offset'])//width
                    need(row['appended_bit_offset']>=old_range['appended_bit_offset'] and
                         (row['appended_bit_offset']-old_range['appended_bit_offset'])%width==0 and
                         0<=old_pos<len(values) and old_pos not in inserted,'Exact unique input leaf offset')
                    inserted.add(old_pos)
                    need(row['new_lowID']==old_range['new_first']+old_pos,'Original new ID and position')
                    raw=bytes.fromhex(row['payload']);value=int.from_bytes(raw,'little')
                    need(value>>width==0 and value==values[old_pos],'Input leaf actual source packed payload')
                    reference,point=decoded(value,level)
                    need(reference==row['primary_ref'] and point==row['raw24'] and label(reference)==row['house_label'],'Actual payload/ref/raw24/stock text')
                    need(row['city']==old_range['city'] and row['district']==old_range['district'] and row['street']==old_range['street'],'Input leaf native names')
                    source_in,quantized_in,decision=membership.assess(row,source_merge)
                    need(source_in,'Every new source point stays in verified source geometry')
                    is_drop=(source_merge=='country_v1' and level==4 and row['new_lowID']==DROP['new_lowID'])
                    if is_drop:
                        need(dropped is None and row['nativeStreetID']==DROP['nativeStreetID'] and row['city']==DROP['city'] and
                             row['house_label']==DROP['house_label'] and row['coordinate_strings']==DROP['source_coordinate_strings'] and
                             row['raw24']==DROP['raw24'] and not quantized_in,'Exact unique proved outlier provenance and membership')
                        dropped=dict(source_merge=source_merge,source_row=row,source_selected_range=old_range,
                                     actual_primary_ref=reference,actual_stock_label=label(reference),membership=decision,
                                     actual_source_packed_payload_equal=True,drop_only_new_leaf_not_stock_record=True)
                        dropped_position=old_pos;drop_bit=row['appended_bit_offset'];counts['dropped_known_grid_outlier']+=1
                        continue
                    need(quantized_in,'Unexpected additional raw24 geometry outlier; stop instead of silently dropping')
                    previous=row['new_lowID']
                    delta=-1 if level==4 and (source_merge!='country_v1' or previous>DROP['new_lowID']) else 0
                    new_row=dict(row,source_merge=source_merge,previous_lowID=previous,remap_delta=delta,
                        previous_appended_bit_offset=row['appended_bit_offset'],candidate_v2_membership=decision)
                    new_row['new_lowID']=previous+delta
                    # Input KH combined offset remains a source provenance field.
                    # The canonical v2 local append stream uses this new offset.
                    new_row['appended_bit_offset']=(new_row['new_lowID']-original_counts[level]-1)*width
                    new_row['v2_combined_append_bit_offset']=new_row['appended_bit_offset']
                    need(identity(new_row)==identity(row),'Every non-remapped original source field preserved')
                    emitted_rows.append(new_row)
                    counts['kept_new_house_records']+=1;kept_by_level[level]+=1;kept_by_source[source_merge]+=1
                retained=[value for index,value in enumerate(values) if index not in inserted]
                need(len(retained)==old_range['original_count'] and significant_hash(retained,width)==old_range['original_significant_records_sha256'],
                     'Original significant bytes and relative order held intact')
                if dropped_position is not None:
                    need(dropped_position in inserted,'Drop was a new leaf only')
                    values=[value for index,value in enumerate(values) if index!=dropped_position]
                    new_range['new_count']-=1;new_range['new_integer_house_count']-=1
                    new_range['new_significant_records_sha256']=significant_hash(values,width)
                    new_range['new_group_tight_packed_sha256']=tight_hash(values,width)
                    new_range['excluded_new_leaf_count']=1
                else:new_range['excluded_new_leaf_count']=0
                need(len(values)==new_range['new_count'] and len(emitted_rows)==new_range['new_integer_house_count'],'Derived new parent count')
                for row in emitted_rows:
                    position=(row['appended_bit_offset']-new_range['appended_bit_offset'])//width
                    need(0<=position<len(values) and values[position]==int.from_bytes(bytes.fromhex(row['payload']),'little'),'Remapped leaf stays in exact group position')
                    kept.add(row);identity_digest.update(canonical(identity(row))+b'\n')
                cursor[level]+=len(values)*width;counts['original_cloned_records_preserved']+=len(retained)
                selected_output.append(new_range)
            need(next(groups,None) is None,'Source ledger completely consumed and hash checked')
            need(processed_rows==proof['artifacts']['new_records']['rows'],'Complete original new-row provenance count')
            for level in STRIDES:need(source_cursor[level]==proof['artifacts'][f'level{level}']['bit_length'],'Complete actual source append groups')
            input_row_counts[source_merge]=processed_rows
            print(json.dumps(dict(source_merge_finished=source_merge,source_rows=processed_rows,kept_counts=dict(kept_by_source)),ensure_ascii=False),flush=True)
        need(dropped is not None and counts['dropped_known_grid_outlier']==1 and drop_bit%128==0,'Exactly one outlier removed')
        ledger_artifact=kept.finish()
        saved(OUT/'dropped-quantized-city-outlier.json',dropped)
        selected_artifact=saved_ranges(OUT/'merged-selected-street-ranges.json',selected_output)
        append_counts={level:cursor[level]//STRIDES[level] for level in STRIDES}
        need(all(cursor[level]%STRIDES[level]==0 for level in STRIDES),'Record-aligned significant streams')
        derived_counts={level:original_counts[level]+append_counts[level] for level in STRIDES}
        need(derived_counts=={4:3781594,5:2667573,6:1984066} and len(selected_output)==18823 and
             ledger_artifact['rows']==sum(input_row_counts.values())-1==130637,
             'Derived sealed input totals equal intended new scope')
        need(append_counts[4]==sum(p['artifacts']['level4']['record_count'] for p in proofs.values())-1 and
             all(append_counts[level]==sum(p['artifacts'][f'level{level}']['record_count'] for p in proofs.values()) for level in (5,6)),
             'Exactly one L4 significant record removed, no hidden other changes')
        paths={level:OUT/f'combined-appended-level{level}.bin' for level in STRIDES}
        def supplier(path):
            def chunks():
                with path.open('rb') as stream:
                    while raw:=stream.read(65536):yield raw
            return chunks
        # Suppliers are declared before files exist; planning never consumes
        # them. Capacity is bound before writing either new appends or the IMG.
        appends={level:writer.PackedAppend(level,append_counts[level],cursor[level],supplier(paths[level])) for level in STRIDES}
        changes=tuple(writer.SelectedRange(row['nativeStreetID'],row['new_first'],row['new_count'],row['next_level'],row['original_flags']) for row in selected_output)
        plan=writer.plan_multilevel_mdr(adapter.mdr_source,appends=appends,selected_ranges=changes)
        prepared=plan.bind_container(adapter)
        need(prepared.capacity_plan['image_bytes']<=source.capacity and adapter.kind=='original4K','4K capacity bound before all binary output')
        saved(OUT/'mdr-plan.json',plan.report)
        saved(OUT/'explicit-container-capacity-plan.json',prepared.capacity_plan)
        combined_artifacts={}
        for level,width in STRIDES.items():
            old=proofs[COUNTRY]['artifacts'][f'level{level}'];kh=proofs[KH]['artifacts'][f'level{level}'];flat=proofs[FLAT]['artifacts'][f'level{level}']
            if level==4:
                byte=drop_bit//8
                segments=[(COUNTRY/old['path'],0,drop_bit),(COUNTRY/old['path'],byte+16,old['bit_length']-drop_bit-128),
                          (KH/kh['path'],0,kh['bit_length']),(FLAT/flat['path'],0,flat['bit_length'])]
            else:segments=[(COUNTRY/old['path'],0,old['bit_length']),(KH/kh['path'],0,kh['bit_length']),(FLAT/flat['path'],0,flat['bit_length'])]
            combined_artifacts[f'level{level}']=write_append(paths[level],segments,append_counts[level],width)
        target=OUT/'gmapprom1.img'
        with target.open('xb') as stream:
            receipt=prepared.repack_stream(stream);stream.flush();os.fsync(stream.fileno())
        saved(OUT/'stream-write-receipt.json',receipt)
        actual=verify_candidate(writer,source,target,plan,receipt,selected_output,ledger_artifact,combined_artifacts,
                                membership,label,original_counts,identity_digest.hexdigest())
        need(stat(SOURCE)==source_before,'Original source stat unchanged')
        for path,row in INPUTS.items():
            need(stat(Path(path))==tuple(row['stat_before']),'Frozen dependency metadata unchanged')
            row['stat_after']=list(stat(Path(path)));row['stat_unchanged']=True
        source_log=GzipLedger(OUT/'source-read-log.jsonl.gz')
        for row in source.read_log:source_log.add(row)
        source_log_artifact=source_log.finish()
    for wire in maps.values():wire.close()
    for stream in streams.values():stream.close()
    file_hash=sha_file(target)
    proof=dict(schema='country-existing-street-native-candidate/v2',created_utc=datetime.now(timezone.utc).isoformat(),
        started_utc=started,all_assigned_checks_passed=True,candidate_path=str(target.relative_to(ROOT)),
        candidate_bytes=target.stat().st_size,candidate_sha256=file_hash,new_integer_house_records=ledger_artifact['rows'],
        updated_original_streets=len(selected_output),proposed_table_counts=derived_counts,
        original_4K_container_geometry_capacity_and_header_prefix_unchanged=True,explicit_8K_adapter_or_checksum_rules_used=False,
        other_five_components_unchanged=True,original_JAI_and_licenses_unchanged=True,
        original_L6_L5_L4_full_byte_prefixes_preserved=True,original_unknown_MDR_prefix_and_L2_L1_bytes_preserved=True,
        new_L3_fields_all_47870_checked=True,merged_groups_all_18823_readback_checked=True,
        kept_new_leaf_payload_ref_raw24_and_provenance_all_130637_readback_checked=True,
        kept_source_and_quantized_points_cover_same_verified_source_city_or_KH_district=True,
        original_groups_significant_bits_and_relative_order_preserved=True,
        exact_one_proved_v1_raw24_city_outlier_dropped=True,stock_coordinates_changed=False,
        new_coordinates_or_payloads_changed=False,v1_and_KH_input_seals_unchanged=True,
        country_v1_KH_selected_parent_intersection_count=0,
        all_three_source_selected_parent_intersections_count=0,
        input_new_rows_by_source=input_row_counts,kept_new_rows_by_source=dict(kept_by_source),kept_new_rows_by_level=dict(kept_by_level),
        drop_original_lowID=DROP['new_lowID'],drop_parent_ID=DROP['nativeStreetID'],drop_house_label=DROP['house_label'],
        kept_ledger_order='country v1 original order minus exactly one row, followed by KH, then flat-city original order',
        ledger_modified_original_keys=['new_lowID','appended_bit_offset'],
        ledger_added_keys=['source_merge','previous_lowID','remap_delta','previous_appended_bit_offset','candidate_v2_membership','v2_combined_append_bit_offset'],
        KH_original_combined_append_bit_offset_retained_as_source_provenance=True,
        four_flat_native_city_to_street_layouts_retained_with_null_district=True,
        flat_source_district_membership_is_not_native_district_hierarchy=True,
        preserved_original_source_identity_sha256=identity_digest.hexdigest(),counts=dict(counts),
        merged_selected_ranges=selected_artifact,kept_new_records=ledger_artifact,combined_append_artifacts=combined_artifacts,
        groups_checked_by_level=actual['groups_checked_by_level'],component_checks=actual['component_checks'],
        table_checks=actual['table_checks'],original_group_significant_bits_readback_checked=True,
        source_read_log=source_log_artifact,readback=actual,source_inputs=list(INPUTS.values()),
        build_source_sha256=sha_file(Path(__file__)),capacity_preflight_sha256=sha_file(OUT/'capacity-preflight.json'),
        native_CPU_executed=False,device_IO=False,device_installed=False,full_Taiwan_native_address_update_complete=False,
        limits=['Existing original streets and missing positive integer existing-label house leaves only; new streets/admins, subnumbers, unresolved source conflicts and incomplete districts remain held.',
                'Country v1 points use its complete-city geometry scope under existing host name policy; KH uses exact complete-district geometry; flat cities use literal source districts while keeping original native city-to-street and null district. Whole-country native district verification is not claimed.',
                'Raw24 nearest-grid policy is inherited host policy; original stock compiler rounding, entrances, native frontend comparator/query/UI and physical route acceptance are not proved.',
                'Original exact-house positions and every original significant record are preserved; no broad coordinate refresh.',
                'Native CPU, rollback/install package, physical search/routing and complete country update remain separate.'])
    saved(OUT/'proof.json',proof)
    for path in OUT.iterdir():
        if path.is_file() and path.stat().st_mode&0o222:path.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,candidate_bytes=target.stat().st_size,candidate_sha256=file_hash,
        new_houses=ledger_artifact['rows'],streets=len(selected_output),proposed_counts=derived_counts,device_installed=False)),flush=True)


if __name__=='__main__':main()
