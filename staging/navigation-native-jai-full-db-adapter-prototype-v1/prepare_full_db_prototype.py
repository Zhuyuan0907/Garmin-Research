#!/usr/bin/env python3
"""Actual complete stock-JAI copy + selected adapter, full logical row review.

No original SQLite connection/mutation, firmware/IMG/device or address extraction.
Original bytes are read once to create the expressly authorized modified offline
prototype. Existing selected-adapter controls are referenced, never rerun.
"""
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import struct

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent
STOCK=ROOT/'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
OUTPUT=HERE/'TWNJAI-offline-prototype.sqlite'
EXPECTED_STOCK_SHA='924da136873f24b2ca044a06bcf2f37e2549638f4ff1b71b71306e20ddbc8074'
INPUTS=[]
PRAGMAS=['page_size','encoding','user_version','schema_version','application_id','auto_vacuum']
EXPECTED_PRAGMAS=dict(page_size=1024,encoding='UTF-8',user_version=0,schema_version=97,application_id=0,auto_vacuum=0)


def need(condition,message):
    if not condition:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def signature(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path,maximum,expected=None):
    before=signature(path);need(before[2]<=maximum,'Small input cap '+str(path))
    raw=path.read_bytes();after=signature(path);need(before==after,'Immutable small input')
    if expected:need(sha(raw)==expected,'Pinned input '+str(path))
    INPUTS.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
                       stat_before=before,stat_after=after,stat_unchanged=True))
    return raw


def load(path,maximum,expected=None):return json.loads(read(path,maximum,expected))


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def add_row(h,row):
    h.update(b'R'+struct.pack('<I',len(row)))
    for cell in row:
        if cell is None:tag=b'N';raw=b''
        elif type(cell)is int:tag=b'I';raw=str(cell).encode('ascii')
        elif type(cell)is float:tag=b'F';raw=struct.pack('<d',cell)
        elif type(cell)is str:tag=b'T';raw=cell.encode('utf-8')
        elif type(cell)is bytes:tag=b'B';raw=cell
        else:raise TypeError('Unsupported logical cell '+str(type(cell)))
        h.update(tag+struct.pack('<Q',len(raw))+raw)


def hash_rows(rows):
    h=hashlib.sha256();count=0
    for row in rows:add_row(h,row);count+=1
    return dict(rows=count,logical_sha256=h.hexdigest())


def quoted(name):return '"'+name.replace('"','""')+'"'


def tables(con):
    return list(con.execute("SELECT rowid,type,name,tbl_name,rootpage,sql FROM sqlite_master ORDER BY rowid"))


def pragmas(con):return {name:con.execute('PRAGMA '+name).fetchone()[0] for name in PRAGMAS}


def storage(con):
    return {name:con.execute('PRAGMA '+name).fetchone()[0] for name in ['page_count','freelist_count','journal_mode']}


def all_table_hashes(con,schema):
    result={}
    for _,typ,name,_,_,sql in schema:
        if typ!='table':continue
        need(not sql or 'WITHOUT ROWID' not in sql.upper(),'Known original rowid schema only')
        result[name]=hash_rows(con.execute('SELECT rowid,* FROM '+quoted(name)+' ORDER BY rowid'))
    return result


def geometry_review(candidate):
    admin=load(ROOT/'staging/navigation-road-coverage-v1/taiwan-admin-selection.json',410000)
    rows=[r for r in admin['relations'] if r.get('name')=='北屯區']
    need(len(rows)==1 and rows[0]['id']==2959946,'Exact saved source Beitun relation metadata')
    country=load(ROOT/'staging/navigation-country-city-geometry-v1/city-geometries.json',3200000)
    kh=load(ROOT/'staging/navigation-kaohsiung-district-geometry-v1/district-geometries.json',1000000)
    flat=load(ROOT/'staging/navigation-flat-city-district-geometry-v1/district-geometries.json',500000)
    tcproof=load(ROOT/'staging/navigation-taichung-city-geometry-v1/proof.json',6000)
    need(set(country)>={'臺中市'} and '北屯區' not in country,'Existing country export contains city polygons only')
    need(kh['city']=='高雄市' and '北屯區' not in kh['districts'],'Existing KH district scope only')
    need('臺中市' not in flat['source_cities'] and '台中市' not in flat['source_cities'], 'Existing flat district scope excludes Taichung')
    need(tcproof['geometry_sha256']==candidate['geometry_gate']['geometry_sha256'],'Inherited complete Taichung city geometry identity')
    return dict(schema='existing-local-Beitun-geometry-evidence-gap/v1',
        actual_metadata_relation_id=2959946,actual_saved_relation_metadata=rows[0],
        inspected_existing_geometry_datasets=dict(country_city_count=len(country),
            country_geometry_keys=list(country),KH_district_count=len(kh['districts']),
            flat_source_city_keys=list(flat['source_cities']),flat_district_count=flat['district_count']),
        complete_Beitun_polygon_found=False,sourcepoint_Beitun_district_gate='not_proved_no_existing_exported_polygon',
        raw24_Beitun_district_gate='not_proved_no_existing_exported_polygon',
        inherited_source_and_raw24_complete_Taichung_city_gate=candidate['geometry_gate'],
        exact_gap='Relation2959946 metadata exists, but these existing exports supply no complete北屯區 ring coordinates or relation-level closure proof. No polygon union or city polygon substituted.',
        source_PBF_opened_or_exported=False,web_browsed=False,district_boundary_guessing=False,
        inherited_city_gate_rerun=False,geometry_all_checks_passed=False,
        inventory_scope='Existing local named Taiwan administrative geometry JSON artifacts; no global completeness claim about all filesystem contents.')


def main():
    started=datetime.now(timezone.utc).isoformat()
    source_stage=ROOT/'staging/navigation-native-jai-new-street-plan-v1'
    seal=load(source_stage/'sealed-files.json',12000,
        '08692c6c8355a09947d3e721115400719ac69b90a7ff7d159bf1bb406aebdc6d')
    pins={r['path']:r for r in seal['files']}
    def source(name,limit):
        p=source_stage/name;pin=pins[str(p.relative_to(ROOT))]
        value=load(p,limit,pin['sha256']);need(INPUTS[-1]['bytes']==pin['bytes'],'Sealed input length');return value
    snapshot=source('original-family-snapshot.json',350000)
    plan=source('one-family-new-street-plan.json',120000)
    prior_seal=load(ROOT/'staging/navigation-native-jai-prefix-consumer-v1/sealed-files.json',6000,
        '8351b270f6d3834cd5eb71a794d70b00a646ab138a147f738bba4f0ee2f58cfd')
    candidate=load(ROOT/'staging/navigation-native-new-street-source-example-v1/candidate.json',11000,
        'd26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c')
    api_path=ROOT/'staging/navigation-native-jai-prefix-consumer-v1/selected_family_adapter.py'
    read(api_path,12000,'c86004ab302f3cdb624289e0e576f958acf73bfdc1150c6f6f3fa6d350640216')
    spec=importlib.util.spec_from_file_location('sealed_selected_family_adapter',api_path)
    api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
    geometry=geometry_review(candidate)
    geometry_artifact=save('Beitun-existing-geometry-gap.json',geometry)

    need(not OUTPUT.exists(),'Fresh single authorized offline prototype path')
    original_before=signature(STOCK);need(original_before[2]==12743680,'Exact original JAI byte count')
    h=hashlib.sha256();copied=0
    with STOCK.open('rb') as original, OUTPUT.open('xb') as target:
        while True:
            raw=original.read(65536)
            if not raw:break
            target.write(raw);h.update(raw);copied+=len(raw)
        target.flush();os.fsync(target.fileno())
    original_after_copy=signature(STOCK)
    need(original_before==original_after_copy and copied==12743680 and h.hexdigest()==EXPECTED_STOCK_SHA,
         'One exact immutable source-byte copy, original never opened by SQLite')
    OUTPUT.chmod(0o600)
    with OUTPUT.open('rb') as f:before_header=f.read(100)
    need(before_header[:16]==b'SQLite format 3\0','Original SQLite header')
    con=sqlite3.connect(OUTPUT)
    con.execute('PRAGMA mmap_size=0')
    try:
        before_pragmas=pragmas(con)
        need(before_pragmas==EXPECTED_PRAGMAS,'Exact known original format/pragmas; no adaptation or relaxation')
        before_storage=storage(con);schema_before=tables(con);before_hashes=all_table_hashes(con,schema_before)
        need(before_hashes['japan_addr_info']['rows']==48218,'Complete actual original info rows')
        print(json.dumps(dict(phase='complete_original_copy_and_logical_baseline',tables=len(before_hashes),
                              original_bytes_copied=copied,page_size=before_pragmas['page_size']),ensure_ascii=False),flush=True)
        selected_ids={r['info_id'] for r in snapshot['old_info_rows']}
        mappings={r['old_record']:r['new_record'] for r in plan['complete_old_physical_order_mapping']}
        new=plan['new_street']
        info_expected=hashlib.sha256();other_info_before=hashlib.sha256();selected_verified=0
        for row in con.execute('SELECT rowid,* FROM japan_addr_info ORDER BY rowid'):
            rowid,info_id,token,record=row
            if info_id in selected_ids:
                add_row(info_expected,(rowid,info_id,token,mappings[record]));selected_verified+=1
            else:add_row(info_expected,row);add_row(other_info_before,row)
        need(selected_verified==441,'All441 explicit remap preimages accounted for')
        add_row(info_expected,(new['info_id'],new['info_id'],new['index_record'],new['record']))
        family_rows=list(con.execute('SELECT rowid,* FROM japan_addr_family ORDER BY rowid'))
        family_expected=[]
        for rowid,parent,first in family_rows:
            if parent==plan['parent_record']:family_expected.append((plan['new_family_first'],parent,plan['new_family_first']))
            else:family_expected.append((rowid,parent,first))
        family_expected_digest=hash_rows(sorted(family_expected))
        other_family_before=hash_rows(r for r in family_rows if r[1]!=plan['parent_record'])
        fts_before_hasher=hashlib.sha256();max_fts_rowid=0
        for row in con.execute('SELECT rowid,* FROM japan_addr_index_8 ORDER BY rowid'):
            add_row(fts_before_hasher,row);max_fts_rowid=row[0]
        content_before_hasher=hashlib.sha256()
        for row in con.execute('SELECT rowid,* FROM japan_addr_index_8_content ORDER BY rowid'):add_row(content_before_hasher,row)
        host_query='SELECT id,index_record,record FROM japan_addr_info WHERE id IN (SELECT record_info >> 8 FROM japan_addr_index_8 WHERE index_record MATCH ?) ORDER BY id'
        old_same_name=list(con.execute(host_query,(new['index_record'],)))
        adapter_result=api.apply_selected_family_relocation(con,snapshot,plan)
        need(adapter_result['new_FTS_rowid']==max_fts_rowid+1,'Exactly one new FTS append rowid')
        add_row(fts_before_hasher,(adapter_result['new_FTS_rowid'],new['index_record'],new['record_info']))
        add_row(content_before_hasher,(adapter_result['new_FTS_rowid'],adapter_result['new_FTS_rowid'],new['index_record'],new['record_info']))
        after_pragmas=pragmas(con);after_storage=storage(con);schema_after=tables(con)
        need(schema_before==schema_after and before_pragmas==after_pragmas,'Exact SQLite schema and persistent original pragmas')
        after_hashes=all_table_hashes(con,schema_after)
        allowed_tables={'japan_addr_info','japan_addr_family','japan_addr_index_8','japan_addr_index_8_content',
                        'japan_addr_index_8_segdir','japan_addr_index_8_segments'}
        need(set(before_hashes)==set(after_hashes),'All original logical tables present, none created/dropped')
        preserved=[]
        for name in before_hashes:
            if name not in allowed_tables:
                need(before_hashes[name]==after_hashes[name],'Whole untouched logical table '+name);preserved.append(name)
        need(after_hashes['japan_addr_info']==dict(rows=48219,logical_sha256=info_expected.hexdigest()),'All441 remaps+1new and no other info changes')
        need(after_hashes['japan_addr_family']==family_expected_digest,'Only one exact selected family remap')
        need(after_hashes['japan_addr_index_8']==dict(rows=before_hashes['japan_addr_index_8']['rows']+1,
             logical_sha256=fts_before_hasher.hexdigest()),'All original complete index8 tuples exact plus1new')
        need(after_hashes['japan_addr_index_8_content']==dict(rows=before_hashes['japan_addr_index_8_content']['rows']+1,
             logical_sha256=content_before_hasher.hexdigest()),'All original index8 content rows exact plus1new')
        other_info_after=hash_rows(row for row in con.execute('SELECT rowid,* FROM japan_addr_info ORDER BY rowid')
            if row[1] not in selected_ids and row[1]!=new['info_id'])
        need(other_info_after['logical_sha256']==other_info_before.hexdigest(),'All nonselected info rows exact')
        other_family_after=hash_rows(row for row in con.execute('SELECT rowid,* FROM japan_addr_family ORDER BY rowid')
            if row[1]!=plan['parent_record'])
        need(other_family_before==other_family_after,'All nonselected family rows exact')
        host_result=list(con.execute(host_query,(new['index_record'],)))
        need(host_result==sorted(old_same_name+[(new['info_id'],new['index_record'],new['record'])]),'Actual complete-host FTS match adds exact newstreet only')
        parent=con.execute('SELECT parent_record FROM japan_addr_family WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 1',(new['record'],)).fetchone()[0]
        grandparent=con.execute('SELECT parent_record FROM japan_addr_family WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 1',(parent,)).fetchone()[0]
        need(parent==snapshot['district']['record'] and grandparent==snapshot['city']['record'],'Actual complete-host original predecessor chain')
        quick=list(con.execute('PRAGMA quick_check'));need(quick==[('ok',)],'Actual complete modified SQLite quick_check')
        print(json.dumps(dict(phase='actual_full_DB_adapter_and_all_table_preservation_passed',preserved_full_tables=len(preserved),
                              complete_old_index8_rows=before_hashes['japan_addr_index_8']['rows'],new_info=new['info_id']),ensure_ascii=False),flush=True)
    finally:con.close()
    with OUTPUT.open('rb') as f:after_header=f.read(100)
    # Storage-history words are inspected, not patched or called format equality.
    allowed_header_offsets=set(range(24,40))|set(range(92,100))
    changes=[dict(offset=i,before=a,after=b,storage_history_word=i in allowed_header_offsets)
             for i,(a,b) in enumerate(zip(before_header,after_header)) if a!=b]
    need(all(r['storage_history_word'] for r in changes),'No static SQLite format/encoding/schema header change')
    out_hash=hashlib.sha256();output_bytes=0
    with OUTPUT.open('rb') as f:
        for raw in iter(lambda:f.read(65536),b''):out_hash.update(raw);output_bytes+=len(raw)
    need(signature(STOCK)==original_before,'Original exact source stat remains unchanged after all prototype work')
    need(not any(HERE.glob('TWNJAI-offline-prototype.sqlite-*')),'No surviving journal/WAL/SHM')
    tables_artifact=save('full-logical-table-preservation.json',dict(schema='full-JAI-logical-table-preservation/v1',
        all_assigned_preservation_checks_passed=True,before=before_hashes,after=after_hashes,
        all_nonselected_info_rows=other_info_after,all_nonselected_family_rows=other_family_after,
        exactly_preserved_complete_tables=preserved,allowed_changed_tables=sorted(allowed_tables),
        selected_info_rows_remapped=441,new_info_rows=1,old_complete_FTS8_tuples_preserved=before_hashes['japan_addr_index_8']['rows'],
        new_FTS8_tuples=1,original_selected_1444_FTS8_tuples_preserved=True,
        selected_index8_internal_segdir_segments_may_change_only_as_FTS3_insert_implementation=True,
        sqlite_master_exact_rows_preserved=True,sqlite_master_typed_logical_hash=hash_rows(schema_before),
        original_persistent_pragmas=before_pragmas,after_persistent_pragmas=after_pragmas,
        original_storage=before_storage,after_storage=after_storage,
        original_header100_hex=before_header.hex(),after_header100_hex=after_header.hex(),
        changed_header_bytes=changes,static_header_fields_preserved=True,
        storage_header_words_not_patched=True,host_new_exact_name_results=host_result,
        predecessor_chain=[new['record'],parent,grandparent],quick_check=quick,
        hash_encoding='Ordered rowid,* cells with explicit NULL/int/IEEE754float/text/blob tags and byte lengths; FTS shadow metadata equality is required outside selected index8.'))
    proof=dict(schema='full-original-JAI-selected-family-offline-prototype/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_execution_and_preservation_checks_passed=True,
        complete_geometry_gate_passed=False,source_inputs=INPUTS,script_sha256=sha(Path(__file__).read_bytes()),
        original=dict(path=str(STOCK.relative_to(ROOT)),bytes=copied,actual_copy_stream_sha256=h.hexdigest(),
                      stat_before=original_before,stat_after=signature(STOCK),stat_unchanged=True,
                      original_content_read_passes_for_copy=1,open_mode='rb',SQLite_original_connection_opened=False),
        modified_offline_prototype=dict(path=str(OUTPUT.relative_to(ROOT)),bytes=output_bytes,sha256=out_hash.hexdigest(),
                                       complete_original_content_copy_before_declared_mutation=True,install_candidate=False),
        adapter_result=adapter_result,full_logical_table_preservation=tables_artifact,
        existing_geometry_gap=geometry_artifact,geometry_status='complete_Beitun_polygon_not_available_in_inspected_existing_exports',
        synthetic_transaction_failure_guards_inherited_not_replayed='staging/navigation-native-jai-prefix-consumer-v1/adapter-control-proof.json',
        original_page_size1024_retained=True,old_partial_sandbox_page4096_not_used=True,
        prefixes_segments_and_all_other_metadata_tables_exact=True,
        source_alias_historical_name_official_newroad_unverified=True,native_frontend_query_UI_not_proved=True,
        true_native_prefix_case_executed=False,device_IO=False,IMG_or_PBF_or_address_ledger_opened=False,
        sealed_source_candidate_or_report_mutated=False,no_install_bundle_created=True,
        full_Taiwan_native_update_complete=False,all_database_handles_closed=True,
        limits=['Actual complete original DB content was copied once for this expressly authorized modified offline prototype; source backup remained read-only and unchanged.',
                'Only441 original info-record keys, one family start and1new info/FTS8 row change. Selected index8 internal index segment pages may change; all other complete tables and old logical FTS tuples are exact.',
                'Persistent pragmas, schema and garmin/jai metadata are exact; storage counters and last-writer stamp changes are disclosed, not silently patched.',
                'The actual complete-host query is a host SQLite result, not native caller/prefix fallback/keyboard/UI/device acceptance.',
                'Relation2959946 metadata lacks an existing complete exported北屯 polygon; source/raw24 district gate and historical alias remain unverified.'])
    proof_artifact=save('proof.json',proof)
    print(json.dumps(dict(all_assigned_execution_and_preservation_checks_passed=True,
        complete_geometry_gate_passed=False,modified_offline_prototype=proof['modified_offline_prototype'],
        old_complete_index8_rows_preserved=before_hashes['japan_addr_index_8']['rows'],
        exactly_preserved_complete_tables=len(preserved),proof=proof_artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
