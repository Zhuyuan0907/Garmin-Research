#!/usr/bin/env python3
"""Read actual new appends once; independent extraction and native-grid rounding."""
from collections import Counter
from decimal import Decimal
from fractions import Fraction
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(payload):return hashlib.sha256(payload).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def module(path,digest,name):
    need(sha(path.read_bytes())==digest,'Pinned read-only code')
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj)
    return obj


def getbits(raw,at,width):
    byte,shift=divmod(at,8);length=(shift+width+7)//8
    need(at>=0 and byte+length<=len(raw),'Actual significant record bounds')
    return (int.from_bytes(raw[byte:byte+length],'little')>>shift)&((1<<width)-1)


def fields(value,level):
    if level==6:
        return {'mapordinal':value&1,'secondary_ref':524287,'primary_ref':(value>>1)&524287,
                'first_child':0,'child_count':0,'flags':0,'raw24':[(value>>20)&0xffffff,(value>>44)&0xffffff]}
    if level==4:firstbits,countbits=22,10
    else:firstbits,countbits=21,9
    flagat=39+firstbits+countbits
    return {'mapordinal':value&1,'secondary_ref':(value>>1)&524287,'primary_ref':(value>>20)&524287,
            'first_child':(value>>39)&((1<<firstbits)-1),'child_count':(value>>(39+firstbits))&((1<<countbits)-1),
            'flags':(value>>flagat)&511,'raw24':[(value>>(flagat+9))&0xffffff,(value>>(flagat+33))&0xffffff]}


def round24(text):
    f=Fraction(text)*(1<<24)/360;sign=-1 if f<0 else 1;f=abs(f)
    n,rem=divmod(f.numerator,f.denominator)
    if 2*rem>=f.denominator:n+=1
    return (sign*n)&0xffffff


def record_hash(values,width):
    h=hashlib.sha256()
    for value in values:h.update(value.to_bytes((width+7)//8,'little'))
    return h.hexdigest()


class Hashed:
    def __init__(self,file):self.file=file;self.count=0;self.digest=hashlib.sha256()
    def read(self,n=-1):
        raw=self.file.read(n);self.count+=len(raw);self.digest.update(raw);return raw


def main():
    need(not (HERE/'output-readback-proof.json').exists(),'New output readback only')
    proof_path=HERE/'proof.json';proof_raw=proof_path.read_bytes();proof=json.loads(proof_raw)
    need(proof['all_assigned_checks_passed'],'Completed append producer')
    metadata=json.loads((HERE/'preflight.json').read_text())
    need(sha((HERE/'preflight.json').read_bytes())==proof['preflight_sha256'],'Pinned metadata preflight')
    native={r['low28_id']:r for r in json.loads((HERE/'native-flat-roster.json').read_text())}
    binding=metadata['native_flat_roster_file']
    need(sha((HERE/'native-flat-roster.json').read_bytes())==binding['sha256'],'Pinned flat roster subset')
    api_binding=metadata['geometry_API_binding']
    validator=module(ROOT/api_binding['path'],api_binding['sha256'],'flat_append_readback_source_API').SourceDistrictMembership()
    starts={int(k):v for k,v in proof['starting_country_v1_plus_KH_counts'].items()}
    widths={4:128,5:126,6:68};bins={};inputs=[]
    for level in widths:
        item=proof['artifacts'][f'level{level}'];path=HERE/item['path'];before=stat(path);raw=path.read_bytes()
        need(len(raw)==item['bytes'] and sha(raw)==item['sha256'] and stat(path)==before,'Actual append bytes/hash/immutable')
        valid=item['record_count']*widths[level];padding=len(raw)*8-valid
        need(valid==item['bit_length'] and padding==item['unused_final_high_bits'] and 0<=padding<8,'Actual append exact bit accounting')
        need(not padding or raw[-1]>>(8-padding)==0,'Actual final high padding zero')
        bins[level]=raw;inputs.append(dict(item,stat_before=before,stat_after=stat(path)))
    item=proof['artifacts']['selected_ranges'];path=HERE/item['path'];before=stat(path);raw=path.read_bytes()
    need(len(raw)==item['bytes'] and sha(raw)==item['sha256'] and stat(path)==before,'Actual selected range file pinned')
    ranges=json.loads(raw);need(len(ranges)==item['rows'],'Actual selected rows count')
    by_ID={};ordinals=Counter()
    for r in ranges:
        level=r['next_level'];ID=r['nativeStreetID'];original=native[ID]
        need(ID not in by_ID and r['native_street_record']==original['record'],'Unique original street record')
        need([r['city'],r['district'],r['street']]==[original['city'],None,original['street']]
             and r['native_district_record'] is None and r['native_district_verified'] is False,'Original flat names/null district')
        need([r['original_first'],r['original_count'],r['original_flags'],level]==
             [original['first_child'],original['child_count'],original['child_level_and_flags'],original['next_level']],
             'Exact original hierarchy source')
        need(r['original_flags'] in (4,5,6),'Unknown parent flags not generated')
        need(r['index_base_count_pin']==starts[level] and r['appended_record_ordinal']==ordinals[level]
             and r['appended_bit_offset']==ordinals[level]*widths[level]
             and r['relative_new_first']==ordinals[level]+1 and r['new_first']==starts[level]+r['relative_new_first'],
             'Actual group relative/base/bit positions')
        need(r['new_count']==r['original_count']+r['new_integer_house_count']<=4095,'Actual parent count bound')
        by_ID[ID]=r;ordinals[level]+=r['new_count']
    need(all(ordinals[level]==proof['artifacts'][f'level{level}']['record_count'] for level in widths),'All table bits covered once by ranges')
    # One additional bounded original label-pool read proves numeric order and
    # every output ref; no old street groups or source address ledger are reread.
    code={r['path']:r for r in metadata['code_bindings']}
    reader_path='staging/navigation-native-general-writer-v1/native_ap_writer.py'
    core=module(ROOT/reader_path,code[reader_path]['sha256'],'flat_readback_original_StreamIMG_only')
    AP=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img';apbefore=stat(AP)
    with AP.open('rb') as file:
        image=core.StreamIMG(file)
        def read(name,at,count):return b''.join(image.iter_component(name,offset=at,length=count))
        lbl=read('I053061A.GMP',874,176)
        need(lbl[2:12]==b'GARMIN LBL' and struct.unpack_from('<II',lbl,21)==(6566,3805432)
             and lbl[29:31]==bytes([3,10]) and struct.unpack_from('<H',lbl,170)[0]==950,'Actual original label profile')
        pool=read('I053061A.GMP',6566,3805432)
        need(sha(pool)==proof['original_label_pool_sha256'],'Original label pool identical to producer read')
        label_read_log=list(image.read_log)
    need(stat(AP)==apbefore,'Original image immutable during bounded labels readback')
    cache={}
    def label(ref):
        need(type(ref)is int and 0<=ref<524287 and ref*8<len(pool),'Stock ref inside bounded label pool')
        if ref not in cache:
            start=ref*8;end=pool.find(b'\0',start,min(start+512,len(pool)))
            need(end>=start,'Stock label NUL')
            cache[ref]=pool[start:end].decode('cp950',errors='strict')
        return cache[ref]
    inserted={ID:set() for ID in by_ID};new_level=Counter();new_city=Counter();source_member_count=0
    seen_IDs=set();seen_groups=set();seen_nodes=set();seen_targets=set();plain=hashlib.sha256();count=0
    item=proof['artifacts']['new_records'];path=HERE/item['path'];before=stat(path)
    with path.open('rb') as file:
        reader=Hashed(file)
        with gzip.GzipFile(fileobj=reader) as stream:
            for line in stream:
                plain.update(line);count+=1;r=json.loads(line);ID=r['nativeStreetID'];level=r['next_level'];width=widths[level]
                group=by_ID[ID];stock=native[ID];position=r['appended_bit_offset'];value=getbits(bins[level],position,width)
                d=fields(value,level)
                need(r['record_bits']==width and position==(r['relative_new_lowID']-1)*width and
                     r['new_lowID']==starts[level]+r['relative_new_lowID'] and r['index_base_count_pin']==starts[level],
                     'Every actual relative lowID/bit position/base')
                need(group['appended_bit_offset']<=position<group['appended_bit_offset']+group['new_count']*width and
                     (position-group['appended_bit_offset'])%width==0,'True new record inside intended actual street group')
                need(int.from_bytes(bytes.fromhex(r['payload']),'little')==value and len(bytes.fromhex(r['payload']))==(width+7)//8,
                     'Actual packed payload exact ledger match')
                need(d['mapordinal']==1 and d['secondary_ref']==524287 and d['first_child']==d['child_count']==d['flags']==0,
                     'Actual numeric new leaf profile')
                need(d['primary_ref']==r['primary_ref'] and label(d['primary_ref'])==r['house_label'] and
                     re.fullmatch(r'[1-9][0-9]*號',r['house_label']),'Actual stock text ref exact integer label')
                need(d['raw24']==r['raw24']==[round24(x) for x in r['coordinate_strings']], 'Independent exact Fraction point encoding')
                need([r['city'],r['district'],r['street']]==[stock['city'],None,stock['street']] and
                     [r['old_child_first'],r['old_child_count'],r['old_parent_flags']]==[stock['first_child'],stock['child_count'],stock['child_level_and_flags']],
                     'Every output exact original flat hierarchy')
                need(r['native_district_record'] is None and r['native_district_verified'] is False,'No invented native district record')
                key=(level,r['new_lowID']);target=(ID,r['house_label'])
                need(key not in seen_IDs and target not in seen_targets,'Actual new lowIDs and targets unique')
                seen_IDs.add(key);seen_targets.add(target)
                relative=(position-group['appended_bit_offset'])//width
                need(relative not in inserted[ID],'Every actual insertion position unique');inserted[ID].add(relative)
                flat_nodes=[];flat_groups=[]
                need(len(r['source_members'])==len(r['source_member_decisions']) and r['source_members'],'Complete per-member provenance/decision')
                for m,decision in zip(r['source_members'],r['source_member_decisions']):
                    source_member_count+=1;nodes=m['source_ids'];gid=m['group_id']
                    need(type(gid)is int and gid>0 and gid not in seen_groups,'New source groups positive unique')
                    need(len(nodes)==m['source_node_count'] and nodes and all(type(i)is int and i>0 for i in nodes)
                         and len(nodes)==len(set(nodes)) and not seen_nodes.intersection(nodes),'Full positive unique OSM provenance')
                    need(tuple(map(Decimal,m['coordinate_strings']))==tuple(map(Decimal,r['coordinate_strings'])),'All member Decimal points identical')
                    need(m['raw_address'][1]==r['source_district'],'One explicitly declared source district per target')
                    actual=validator.assess_source_and_raw24(m['raw_address'][0],m['raw_address'][1],*m['coordinate_strings'],r['raw24'])
                    need(actual==decision and actual['eligible'] and actual['source_city']==r['source_city'] and
                         actual['native_city']==stock['city'] and actual['native_district_verified'] is False,
                         'Every persisted member decision revalidated source/native24 same source district')
                    need(type(m['separate_floor_unit_source_nodes'])is int and 0<=m['separate_floor_unit_source_nodes']<=len(nodes)
                         and type(m['embedded_floor_unit_first_source_flag'])is bool,'Bounded floor/unit metadata')
                    seen_groups.add(gid);seen_nodes.update(nodes);flat_nodes.extend(nodes);flat_groups.append(gid)
                need(flat_nodes==r['source_ids'] and flat_groups==r['source_group_ids'],'All source member IDs exactly persisted, without truncation')
                new_level[level]+=1;new_city[r['city']]+=1
        need(reader.count==item['bytes'] and reader.digest.hexdigest()==item['sha256'] and
             plain.hexdigest()==item['uncompressed_sha256'],'New output complete gzip EOF/dual hash')
    need(stat(path)==before and count==item['rows']==4500,'New ledger complete and immutable')
    old_count=0;flag_counts=Counter();nested=noninteger=0;group_hash_count=0
    for ID,group in by_ID.items():
        level=group['next_level'];width=widths[level];positions=inserted[ID]
        need(len(positions)==group['new_integer_house_count'],'All new positions accounted in each group')
        values=[getbits(bins[level],group['appended_bit_offset']+i*width,width) for i in range(group['new_count'])]
        retained=[v for i,v in enumerate(values) if i not in positions]
        need(len(retained)==group['original_count'] and record_hash(retained,width)==group['original_significant_records_sha256'],
             'Every cloned old significant bit and old relative order match source proof')
        need(record_hash(values,width)==group['new_significant_records_sha256'],'Actual complete merged group record hash')
        start=group['appended_bit_offset'];byte,shift=divmod(start,8);length=(shift+group['new_count']*width+7)//8
        rawint=(int.from_bytes(bins[level][byte:byte+length],'little')>>shift)&((1<<(group['new_count']*width))-1)
        tight=rawint.to_bytes((group['new_count']*width+7)//8,'little')
        need(sha(tight)==group['new_group_tight_packed_sha256'],'Actual packed group bit shift/hash, independent extraction')
        names=[label(fields(v,level)['primary_ref']) for v in values]
        anchors=[int(m.group()) for name in names if (m:=re.match(r'^[0-9]+',name))]
        need(anchors and anchors==sorted(anchors),'Actual merged base-number order')
        old_names=[label(fields(v,level)['primary_ref']) for v in retained]
        for i in positions:need(names[i] not in old_names,'Every declared new exact house absent in preserved original group')
        for value,name in zip(retained,old_names):
            d=fields(value,level);flag_counts[d['flags']]+=1;nested+=bool(d['child_count'])
            noninteger+=not bool(re.fullmatch(r'[1-9][0-9]*號',name))
        old_count+=len(retained);group_hash_count+=1
    need(old_count==proof['counts']['cloned_original_records']==142146 and group_hash_count==889,'Complete retained originals/groups readback')
    need(dict(new_level)=={4:3552,5:936,6:12},'All actual new counts by level')
    result={'schema':'flat-native-city-actual-append-output-readback/v1','all_assigned_new_readback_checks_passed':True,
        'producer_proof_sha256':sha(proof_raw),'readback_script_sha256':sha(Path(__file__).read_bytes()),
        'actual_append_file_bindings':inputs,'complete_new_record_gzip_EOF_sha_plain_sha':True,
        'new_records_independently_decoded':count,'new_records_by_level':dict(new_level),'new_records_by_city':dict(new_city),
        'source_members':source_member_count,'positive_unique_source_group_IDs':len(seen_groups),'positive_unique_OSM_IDs':len(seen_nodes),
        'every_member_source_and_raw24_geometry_decision_revalidated':True,'native_district_record_null_and_unverified':True,
        'all_new_original_stock_GMP_text_refs_exact':True,'all_actual_merged_numeric_order_checked':True,
        'all_new_exact_house_labels_absent_original_groups':True,'old_records_preserved_actual_significant_hash_and_order':old_count,
        'original_groups_actual_output_reviewed':group_hash_count,'old_nonnumeric_or_subnumber_label_records':noninteger,
        'old_nested_records':nested,'old_raw_flag_counts':dict(flag_counts),
        'actual_only_final_high_padding_zero':True,'local_relative_IDs_valid_under_explicit_rebase_contract':True,
        'additional_original_label_pool_bytes_read':len(pool),'additional_original_image_read_log':label_read_log,
        'additional_original_image_bytes_read':sum(r['bytes'] for r in label_read_log),
        'additional_original_image_stat_before':apbefore,'additional_original_image_stat_after':stat(AP),
        'original_old_groups_or_source_address_ledgers_reread':False,'closed_suites_rerun':False,
        'IMG_CPU_device_canonical_ZIP_modified':False,'full_Taiwan_update_complete':False,
        'scope':'Actual output bits and provenance; original 3.8MB label pool read for independent numeric/ref checks. Original significant hashes use completed producer bounded source reads, not another old-groups pass.'}
    (HERE/'output-readback-proof.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_new_readback_checks_passed':True,'new_rows':count,'old_records':old_count,'groups':group_hash_count,
        'source_OSM_IDs':len(seen_nodes),'old_nested_records':nested,'old_flag_counts':dict(flag_counts),
        'output_readback_proof_sha256':sha((HERE/'output-readback-proof.json').read_bytes())},ensure_ascii=False))


if __name__=='__main__':main()
