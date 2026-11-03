#!/usr/bin/env python3
"""One bounded original JAI family and stock L2 pointer snapshot, immutable."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sqlite3
import struct
import jai_scope as s

DB=s.ROOT/'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
AP=s.ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'


def main():
    p=argparse.ArgumentParser();p.add_argument('--city',required=True);p.add_argument('--district',required=True);p.add_argument('--prototype-street',required=True);args=p.parse_args()
    inputs=[];s.load('staging/navigation-stock-address-schema-v1/analysis-file-seal.json',inputs)
    schema=json.loads(s.load('staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json',inputs));stock=schema['databases']['jai']
    s.need(schema['all_readonly_structural_checks_passed'],'Original sealed schema checks');encode,decode=s.codec(inputs)
    s.load('staging/navigation-firmware-address-v1/analysis-file-seal.json',inputs)
    dispatch=json.loads(s.load('staging/navigation-firmware-address-v1/address-dispatch-evidence.json',inputs))
    before=s.stat(DB);s.need(before[2]==stock['bytes'],'Inherited backup DB size');queries=[];steps=0
    with DB.open('rb')as f:s.need(s.sha(f.read(4096))==stock['header_4096_sha256'],'Sealed original first4096bytes')
    con=sqlite3.connect(DB.resolve().as_uri()+'?mode=ro&immutable=1',uri=True);con.execute('PRAGMA query_only=ON');con.execute('PRAGMA mmap_size=0');con.execute('PRAGMA cache_size=-256')
    def progress():
        nonlocal steps
        steps+=1000
        if steps>3000000:raise RuntimeError('Bounded original SQL instruction budget')
        return 0
    con.set_progress_handler(progress,1000)
    def select(sql,params=(),limit=1100):
        qplan=list(con.execute('EXPLAIN QUERY PLAN '+sql,params));rows=list(con.execute(sql,params));s.need(len(rows)<=limit,'Bounded returned SQL rows')
        queries.append(dict(sql=sql,args=params,result_rows=len(rows),query_plan=qplan));return rows
    actual_schema=select("SELECT type,name,sql FROM sqlite_master WHERE name IN ('japan_addr_family','japan_addr_info','japan_addr_index_8','japan_addr_prefix','japan_addr_segments') ORDER BY name",limit=5)
    expected={r['name']:r['sql']for r in stock['schema']if r['type']=='table'}
    s.need(all(expected[name]==sql for typ,name,sql in actual_schema)and len(actual_schema)==5,'Exact original relevant SQL schema')
    families=select('SELECT parent_record,the_first_record FROM japan_addr_family ORDER BY the_first_record',limit=400)
    def interval(parent):
        hits=[(i,f)for i,f in enumerate(families)if f[0]==parent];s.need(len(hits)==1,'One family for actual parent');i,(_,first)=hits[0]
        end=families[i+1][1]if i+1<len(families)else(3<<28)|47871
        return first,end
    city_old=next(r for r in stock['city_record_witnesses']if r['index_record']==encode(args.city));city_record=city_old['record'];city_id=city_old['id']
    s.need(city_record==0x10000008,'Finite actual index_8 city scope only')
    actualcity=select('SELECT id,index_record,record FROM japan_addr_info WHERE id=?',(city_id,),1)[0]
    s.need(actualcity==(city_id,encode(args.city),city_record),'Exact selected stock city');city_first,city_end=interval(city_record)
    districts=select('SELECT id,index_record,record FROM japan_addr_info WHERE record>=? AND record<? AND record>>28=2 ORDER BY record LIMIT 60',(city_first,city_end),60)
    selected=[r for r in districts if r[1]==encode(args.district)];s.need(len(selected)==1,'Exact literal district in exact selected city family');district_id,district_token,parent=selected[0]
    first,end=interval(parent);s.need(first>>28==end>>28==3 and 0<end-first<1023,'Single bounded middle street family; no width expansion')
    infos=select('SELECT id,index_record,record FROM japan_addr_info WHERE record>=? AND record<? ORDER BY record LIMIT 1024',(first,end),1023)
    s.need(infos and all(r[2]>>28==3 for r in infos),'Actual selected street info rows');lo=min(r[0]for r in infos);hi=max(r[0]for r in infos)
    fts=select('SELECT rowid,index_record,record_info FROM japan_addr_index_8 WHERE record_info>=? AND record_info<? ORDER BY rowid LIMIT 4097',(lo<<8,(hi+1)<<8),4096)
    IDs={r[0]for r in infos};fts=[r for r in fts if r[2]>>8 in IDs]
    s.need(all((r[2]&240)==48 for r in fts),'Old selected FTS levels3');s.need(fts,'Selected old FTS rows')
    maximum=select('SELECT id FROM japan_addr_info ORDER BY id DESC LIMIT 1',limit=1)[0][0]
    metadata={name:select('SELECT * FROM '+name,limit=2)for name in ['garmin_metadata','jai_metadata','jai_map_id']}
    prefix_witnesses=[]
    for char in dict.fromkeys([args.prototype_street[0],decode(infos[0][1])[0]]):
        token=encode(char);found=select('SELECT prefix_id,index_record,seg_id FROM japan_addr_prefix WHERE index_record=? LIMIT 3',(token,),2)
        witness=dict(character=char,index_record=token,prefix_rows=found,exact_original_prefix_available=bool(found))
        if found:
            prefix_id,_,seg_id=found[0];length=select('SELECT length(segment) FROM japan_addr_segments WHERE seg_id=?',(seg_id,),1)[0][0]
            s.need(0<length<=4096,'Tiny actual prefix-selected segment blob only')
            blob=select('SELECT segment FROM japan_addr_segments WHERE seg_id=?',(seg_id,),1)[0][0]
            witness.update(segment_bytes=length,segment_sha256=s.sha(blob),segment_hex=blob.hex(),
                raw_u16_pairs_if_aligned=[list(v)for v in struct.iter_unpack('<HH',blob)]if len(blob)%4==0 else None,
                u16_pair_or_pointer_meanings_not_established=True)
        prefix_witnesses.append(witness)
    con.close();s.need(s.stat(DB)==before,'Original DB immutable stat after selected queries')
    reader=s.stock_reader(inputs);ap_before=s.stat(AP)
    with AP.open('rb')as f:
        image=reader['StockImage'](f);tables,descriptor=reader['derive_tables'](image);native_parent=reader['read_record'](image,tables,2,parent&0xfffffff)
        s.need((native_parent['next_level'],native_parent['first_child'],native_parent['child_count'])==(3,first&0xfffffff,end-first),'Actual original L2 range equals complete selected JAI family')
        readbytes=sum(r['bytes']for r in image.log);s.need(readbytes<=100000,'Bounded original AP metadata +one actual L2 record')
        apreads=image.log
    s.need(s.stat(AP)==ap_before,'Original AP immutable stat')
    rows=[dict(info_id=i,index_record=token,record=record,label=decode(token))for i,token,record in infos]
    for row in rows:s.need(encode(row['label'])==row['index_record'],'Selected old info token lossless')
    frows=[dict(rowid=i,index_record=token,record_info=packed,decoded_text=decode(token),low_byte=packed&255)for i,token,packed in fts]
    result=dict(schema='bounded-original-JAI-family-snapshot/v1',all_assigned_checks_passed=True,inputs=inputs,
        original_DB=dict(path=str(DB.relative_to(s.ROOT)),stat_before=before,stat_after=s.stat(DB),full_SHA_inherited_not_recomputed=True,
            sql_read_mode='mode=ro&immutable=1;query_only=ON;mmap_size=0',SQL_queries=queries,SQL_instruction_progress_budget=3000000,SQL_steps_rounded=steps,
            exact_page_reads_captured_externally_by_strace=True),original_AP=dict(path=str(AP.relative_to(s.ROOT)),stat_before=ap_before,stat_after=s.stat(AP),actual_bounded_reads=apreads,actual_read_bytes=readbytes),
        actual_relevant_schema=actual_schema,metadata=metadata,original_families=families,city=dict(label=args.city,record=city_record,info_id=city_id,index_record=actualcity[1]),
        district=dict(label=args.district,record=parent,info_id=district_id,index_record=district_token),selected_family_first=first,selected_family_end=end,
        selected_original_physical_L3_count=end-first,selected_named_info_rows=len(rows),old_info_rows=rows,old_FTS8_rows=frows,
        selected_FTS8_low_byte_counts=dict(Counter(r['low_byte']for r in frows)),old_max_info_id=maximum,
        actual_tiny_prefix_segment_witnesses=prefix_witnesses,
        inherited_segment2_six_infoID_suffix_links=next(r for r in stock['segment_samples']if r['seg_id']==2),
        actual_original_L2_fields=native_parent,original_directory_descriptor=descriptor,L3_count=tables[2]['count'],
        recorded_native_SQL_strings=[r for r in dispatch['sql_table']if r['offset']in['0x8','0xc','0x10','0x18','0x2c','0x30']],
        source_or_actual_new_street_not_selected_here=True,native_CPU_or_query_UI_device_tested=False,original_DB_or_AP_modified=False)
    artifact=s.save('original-family-snapshot.json',result)
    print(json.dumps(dict(all_assigned_checks_passed=True,city=args.city,district=args.district,physical_L3_count=end-first,named_info_rows=len(rows),FTS_rows=len(frows),snapshot=artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
