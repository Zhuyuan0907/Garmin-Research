#!/usr/bin/env python3
"""Corrected original source binding, without rerunning synthetic/CPU suites."""
import datetime
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
WRITER = ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
WRITER_SHA = 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
ROSTER = ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
ANCHORS = {
    1:dict(name='三合街',next_level=6,first=1,count=1),
    2:dict(name='六和街',next_level=5,first=1,count=10),
    180:dict(name='湖海路二段',next_level=5,first=36011,count=34),
    278:dict(name='北投路二段',next_level=5,first=52194,count=21),
    16707:dict(name='民權路',next_level=4,first=904706,count=84),
}


def sha(raw):return hashlib.sha256(raw).hexdigest()


def need(ok,message):
    if not ok:raise AssertionError(message)


def fields(raw,ID,width):
    position = (ID-1)*(89+width)
    result = []
    for n in [1,19,width,12,9,24,24]:
        value = 0
        for bit in range(n):
            value |= ((raw[(position+bit)//8]>>((position+bit)%8))&1)<<bit
        position += n
        result.append(value)
    return result


def main():
    output = HERE/'corrected-original-L3-writer-source-proof-v2.json'
    need(not output.exists(),'Refuse overwrite corrected terminal scope')
    writer_raw = WRITER.read_bytes()
    need(sha(writer_raw) == WRITER_SHA,'Sealed writer changed')
    spec = importlib.util.spec_from_file_location('sealed_writer_corrected_source',WRITER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    source_path = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
    before = source_path.stat()
    roster_stat = ROSTER.stat()
    roster_identity = [roster_stat.st_dev,roster_stat.st_ino,roster_stat.st_size,roster_stat.st_mtime_ns,roster_stat.st_ctime_ns]
    roster_raw = ROSTER.read_bytes()
    roster_sha = sha(roster_raw)
    named = {}
    with gzip.open(ROSTER,'rt') as roster:
        for line in roster:
            row = json.loads(line)
            if row['level'] != 3:continue
            ID = row['low28_id']
            need(type(ID) is int and 1 <= ID <= 47870 and ID not in named,'Named roster duplicate/outside L3ID')
            name = row['raw_name']
            need(isinstance(name,str) and name,'Named roster empty name')
            named[ID] = row
    with source_path.open('rb') as f:
        image = module.StreamIMG(f)
        header_public = b''.join(image.iter_component('00004171.MDR',offset=0,length=32))
        need(header_public[2:12] == b'GARMIN MDR' and struct.unpack_from('<H',header_public)[0] == 772,
             'Original public MDR header differs')
        descriptor = b''.join(image.iter_component('00004171.MDR',offset=600,length=12))
        directory_start,directory_bytes,item_bytes = struct.unpack('<3I',descriptor)
        need(directory_bytes == 120 and item_bytes == 20,'Original directory descriptor shape differs')
        directory = b''.join(image.iter_component('00004171.MDR',offset=directory_start,length=directory_bytes))
        words = struct.unpack_from('<5I',directory,40)
        start,size,stride,w,x = words
        count,remainder = divmod(size*8,stride)
        widths = [(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
        flags = [(w>>30)&1,(w>>31)&1]
        need((start,size,stride,count) == (91983716,664197,111,47870),'Real original L3 source assertion failed')
        need(widths == [22,9,24,19,1,12,0,0] and flags == [1,0],'Real original L3 profile differs')
        table = b''.join(image.iter_component('00004171.MDR',offset=start,length=size))
        converted = module.rewrite_l3_width23(table)
        need(len(converted.table) == 670180 and converted.old_unused_tail_bits == 6,'Corrected L3 output sizes differ')
        old_digest,new_digest = hashlib.sha256(),hashlib.sha256()
        all_categories,named_categories,anchor_cases = {},{},[]
        for ID in range(1,count+1):
            a,b = fields(table,ID,22),fields(converted.table,ID,23)
            need(a == b,'Correct original L3 fields/ID changed:'+str(ID))
            old_digest.update(struct.pack('<7I',*a));new_digest.update(struct.pack('<7I',*b))
            level = a[4]&7
            all_categories[level] = all_categories.get(level,0)+1
            if ID in named:
                named_categories[level] = named_categories.get(level,0)+1
            if ID in ANCHORS:
                witness = ANCHORS[ID]
                need((level,a[2],a[3]) == (witness['next_level'],witness['first'],witness['count']),
                     'Independent known original ID anchor differs:'+str(ID))
                need(ID in named and named[ID]['raw_name'] == witness['name'],'Independent named roster anchor differs:'+str(ID))
                anchor_cases.append(dict(one_based_ID=ID,name=witness['name'],original_wire_fields=a,
                    converted_wire_fields=b,independent_expected_anchor=witness,named_roster_record=named[ID]))
        need(named_categories == {4:20107,5:19036,6:8710},'Named original roster categories differ from independent witness')
        need(len(named) == 47853 and sum(named_categories.values()) == len(named),'Named roster count differs')
        need(old_digest.digest() == new_digest.digest(),'Corrected independent field digests differ')
        used = count*stride%8
        actual_tail = table[-1]>>used
        need(converted.old_unused_tail_value == actual_tail,'Original true tail value differs from retained metadata')
        after = source_path.stat()
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Original AP changed')
        read_log = image.read_log
    need(sha(ROSTER.read_bytes()) == roster_sha,'Named roster changed during proof')
    roster_after = ROSTER.stat()
    need(roster_identity == [roster_after.st_dev,roster_after.st_ino,roster_after.st_size,roster_after.st_mtime_ns,roster_after.st_ctime_ns],
         'Named roster stat changed')
    result = dict(schema='native-AP-L3-corrected-source/v2',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=sha(Path(__file__).read_bytes()),sealed_purewriter=dict(path=str(WRITER.relative_to(ROOT)),sha256=WRITER_SHA),
        v1_erratum=dict(path=str((HERE/'v1-source-offset-erratum.json').relative_to(ROOT)),
            sha256=sha((HERE/'v1-source-offset-erratum.json').read_bytes())),
        source=dict(path=str(source_path.relative_to(ROOT)),map_bytes=before.st_size,map_stat_unchanged=True,
            public_header32_hex=header_public.hex(),MDR_descriptor_offset=600,MDR_descriptor_hex=descriptor.hex(),
            directory_offset=directory_start,directory_bytes=directory_bytes,directory_item_bytes=item_bytes,directory_hex=directory.hex(),
            original_L3_start_derived_from_directory=start,original_L3_span_bytes=size,record_bits=stride,record_count=count,
            division_unused_remainder_bits=remainder,widths=widths,reference_flags=flags,
            correct_table_sha256=sha(table),original_last_byte_hex=table[-1:].hex(),original_unused_tail_bits=6,
            original_unused_tail_value=actual_tail,source_offset_not_from_candidate=True),
        conversion=dict(purewriter_invocations=1,correct_original_table_reads=1,selected_changes=0,output_bytes=len(converted.table),
            output_sha256=sha(converted.table),original_records_independently_preserved=count,original_fields_digest=old_digest.hexdigest(),
            converted_fields_digest=new_digest.hexdigest(),all_flags_counts_refs_coordinates_and_IDs_equal=True,
            output_table_saved_as_binary=False,reader_lookahead_bytes=4,lookahead_inside_declared_table=False,
            original_unused_tail_value_retained_in_metadata=converted.old_unused_tail_value),
        named_roster=dict(path=str(ROSTER.relative_to(ROOT)),sha256=roster_sha,parsed_to_gzip_EOF=True,named_L3_count=len(named),
            stat=roster_identity,stat_unchanged=True,
            expected_named_categories={'4':20107,'5':19036,'6':8710},actual_named_categories=named_categories,
            actual_all47870_categories=all_categories,unnamed_record_count=count-len(named)),
        independent_known_ID_anchors=anchor_cases,all_corrected_source_checks_passed=True,
        actual_original_read_log=read_log,total_original_bytes_read=sum(r['bytes']for r in read_log),
        old_synthetic26controls_or_container_suite_replayed=False,CPU_suite_executed=False,
        frozen_v1_files_or_purewriter_modified=False,whole_IMG_or_MAIN_read_or_copy=False,
        device_IO=False,canonical_or_ZIP_mutation=False,complete_Taiwan_update=False,installable=False,
        limits=['Corrected proof supersedes every v1 original-L3 source/classification/tail claim. V1 synthetic-only evidence remains scoped separately.',
            'The sealed purewriter ran once on the correct original table; no selected updates or original full IMG repacking executed.',
            'Named roster categories cover47853namedIDs;17remainingrecords are classified separately, not silently called streets.',
            'Correct source/bit preservation is not a complete MDR assembler, native query, nationwide candidate or device acceptance proof.'])
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),all_passed=True,
        original_L3_start=start,records=count,named_categories=named_categories,all_categories=all_categories,
        true_original_tail_value=actual_tail,total_original_bytes_read=result['total_original_bytes_read']),ensure_ascii=False))


if __name__ == '__main__':main()
