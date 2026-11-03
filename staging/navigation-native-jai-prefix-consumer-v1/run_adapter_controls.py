#!/usr/bin/env python3
"""New selected-scope adapter controls, on explicit multi-table host fixtures.

Actual441/1444 source rows are copied as small JSON inputs; unrelated synthetic
rows demonstrate the old whole-index assumption is gone. No original DB copy,
device, historical test main or old suite is executed.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent
SOURCE=ROOT/'staging/navigation-native-jai-new-street-plan-v1'
INPUTS=[]


def sha(raw):return hashlib.sha256(raw).hexdigest()


def signature(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path,limit,expected=None):
    before=signature(path);assert before[2]<=limit
    with path.open('rb') as handle:raw=handle.read(limit+1)
    after=signature(path);assert before==after and len(raw)==before[2]
    if expected:assert sha(raw)==expected
    INPUTS.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
                       stat_before=before,stat_after=after,stat_unchanged=True))
    return raw


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def main():
    started=datetime.now(timezone.utc).isoformat()
    seal=json.loads(read(SOURCE/'sealed-files.json',12000,
        '08692c6c8355a09947d3e721115400719ac69b90a7ff7d159bf1bb406aebdc6d'))
    pins={r['path']:r for r in seal['files']}
    def original(name,limit):
        p=SOURCE/name;key=str(p.relative_to(ROOT));pin=pins[key]
        raw=read(p,limit,pin['sha256']);assert len(raw)==pin['bytes'];return json.loads(raw)
    snapshot=original('original-family-snapshot.json',350000)
    plan=original('one-family-new-street-plan.json',120000)
    source_seal=json.loads(read(ROOT/'staging/navigation-native-new-street-source-example-v1/sealed-files.json',10000,
        'a7f469ff3b4c9acc562ba92560f4645f77977ccc234a379fdb9f88b11d8c58d3'))
    source_candidate=json.loads(read(ROOT/'staging/navigation-native-new-street-source-example-v1/candidate.json',11000,
        'd26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c'))
    payload_seal=json.loads(read(ROOT/'staging/navigation-native-new-street-family-payload-v1/sealed-files.json',10000))
    payload_pin=next(r for r in payload_seal['files'] if r['path'].endswith('/proof.json'))
    payload_proof=json.loads(read(ROOT/payload_pin['path'],60000,payload_pin['sha256']))
    spec=importlib.util.spec_from_file_location('new_selected_family_adapter',HERE/'selected_family_adapter.py')
    api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
    api_raw=read(HERE/'selected_family_adapter.py',14000)
    assert len(snapshot['old_info_rows'])==441 and len(snapshot['old_FTS8_rows'])==1444
    assert plan['new_street']['label']==source_candidate['streettext']=='敦富六街'
    assert plan['new_street']['record']==(3<<28)|48312 and plan['final_L3_count']==48312
    tables=['japan_addr_info','japan_addr_family','japan_addr_index_8','japan_addr_index_1',
            'japan_addr_prefix','japan_addr_segments','unrelated_metadata']
    selected_ids={r['info_id'] for r in snapshot['old_info_rows']}
    cases=[]

    def make_fixture(path=None):
        con=sqlite3.connect(':memory:' if path is None else path)
        for sql in api.SCHEMAS.values():con.execute(sql)
        con.executemany('INSERT INTO japan_addr_family VALUES (?,?)',snapshot['original_families'])
        rows=[snapshot['city'],snapshot['district']]+snapshot['old_info_rows']
        con.executemany('INSERT INTO japan_addr_info VALUES (?,?,?)',
            [(r['info_id'],r['index_record'],r['record']) for r in rows])
        con.execute('INSERT INTO japan_addr_info VALUES (1,?,?)',('syntheticothercity',0x10000001))
        con.execute('INSERT INTO japan_addr_info VALUES (?,?,?)',
            (snapshot['old_max_info_id'],'syntheticotherstreet',(3<<28)|snapshot['L3_count']))
        con.executemany('INSERT INTO japan_addr_index_8(rowid,index_record,record_info) VALUES (?,?,?)',
            [(r['rowid'],r['index_record'],r['record_info']) for r in snapshot['old_FTS8_rows']])
        con.executemany('INSERT INTO japan_addr_index_8(rowid,index_record,record_info) VALUES (?,?,?)',[
            (500001,'syntheticothercity',(1<<8)|17),
            (500002,'syntheticotherstreet',(snapshot['old_max_info_id']<<8)|49),
            (500003,'syntheticsuffix',(snapshot['old_max_info_id']<<8)|48)])
        con.execute('CREATE VIRTUAL TABLE japan_addr_index_1 USING FTS3(index_record TEXT,record_info INTEGER)')
        con.execute('INSERT INTO japan_addr_index_1(rowid,index_record,record_info) VALUES (1,?,?)',('otherindexsentinel',273))
        con.execute('CREATE TABLE japan_addr_prefix(prefix_id INTEGER PRIMARY KEY,index_record TEXT,seg_id INTEGER)')
        con.execute('CREATE INDEX japan_addr_prefix_index ON japan_addr_prefix(index_record)')
        con.execute('CREATE TABLE japan_addr_segments(seg_id INTEGER PRIMARY KEY,segment BLOB)')
        old_prefix=next(r for r in snapshot['actual_tiny_prefix_segment_witnesses'] if r['character']=='一')
        con.executemany('INSERT INTO japan_addr_prefix VALUES (?,?,?)',old_prefix['prefix_rows'])
        con.execute('INSERT INTO japan_addr_segments VALUES (?,?)',(1116,bytes.fromhex(old_prefix['segment_hex'])))
        con.execute('CREATE TABLE unrelated_metadata(key TEXT PRIMARY KEY,value BLOB)')
        con.execute('INSERT INTO unrelated_metadata VALUES (?,?)',('license-and-unknown-metadata',b'original-fixture-metadata\x00\xff'))
        con.commit();return con

    def state(con):
        return {t:list(con.execute('SELECT rowid,* FROM '+t+' ORDER BY rowid')) for t in tables}

    def digest(value):
        return sha(json.dumps(value,ensure_ascii=False,sort_keys=True,default=lambda x:{'blob_hex':x.hex()}).encode())

    con=make_fixture()
    before=state(con)
    result=api.apply_selected_family_relocation(con,snapshot,plan)
    after=state(con)
    expected_records={r['old_record']:r['new_record'] for r in plan['complete_old_physical_order_mapping']}
    for old in before['japan_addr_info']:
        rowid,info_id,token,record=old
        found=next(r for r in after['japan_addr_info'] if r[1]==info_id)
        assert found==(rowid,info_id,token,expected_records.get(record,record))
    assert len(after['japan_addr_info'])==len(before['japan_addr_info'])+1
    oldfts=before['japan_addr_index_8'];oldrowids={r[0] for r in oldfts}
    assert [r for r in after['japan_addr_index_8'] if r[0] in oldrowids]==oldfts
    assert len(after['japan_addr_index_8'])==len(oldfts)+1
    for table in ['japan_addr_index_1','japan_addr_prefix','japan_addr_segments','unrelated_metadata']:
        assert before[table]==after[table]
    old_other_info=[r for r in before['japan_addr_info'] if r[1] not in selected_ids]
    new_other_info=[r for r in after['japan_addr_info'] if r[1] not in selected_ids and r[1]!=plan['new_street']['info_id']]
    assert old_other_info==new_other_info
    old_other_families=[r for r in before['japan_addr_family'] if r[1]!=plan['parent_record']]
    new_other_families=[r for r in after['japan_addr_family'] if r[1]!=plan['parent_record']]
    assert old_other_families==new_other_families
    query='SELECT id,index_record,record FROM japan_addr_info WHERE id IN (SELECT record_info >> 8 FROM japan_addr_index_8 WHERE index_record MATCH ?)'
    host_result=list(con.execute(query,(plan['new_street']['index_record'],)))
    assert host_result==[(plan['new_street']['info_id'],plan['new_street']['index_record'],plan['new_street']['record'])]
    token=next(r for r in snapshot['actual_tiny_prefix_segment_witnesses'] if r['character']=='敦')['index_record']
    assert list(con.execute('SELECT prefix_id,seg_id FROM japan_addr_prefix WHERE index_record=?',(token,)))==[]
    cases.append(dict(name='actual441_info_1444_selected_FTS_plus_unrelated_tables_and_FTS_rows',passed=True,
        result=result,total_old_index8_rows=len(oldfts),all1447_old_logical_index8_rows_preserved=True,
        all_other_table_rows_preserved=True,other_info_rows_preserved=len(old_other_info),
        other_family_rows_preserved=len(old_other_families),host_new_exact_name_result=host_result,
        source_prefix_dun_still_absent=True,host_FTS_success_is_not_native_frontend_success=True))
    con.close()

    def refusal_case(name,change=None,authorizer=None):
        con=make_fixture()
        if change:change(con);con.commit()
        before=state(con)
        if authorizer:con.set_authorizer(authorizer)
        error=None
        try:api.apply_selected_family_relocation(con,snapshot,plan)
        except (api.ScopeRefusal,sqlite3.DatabaseError) as ex:error=type(ex).__name__+': '+str(ex)
        if authorizer:con.set_authorizer(None)
        assert error and not con.in_transaction and state(con)==before
        cases.append(dict(name=name,passed=True,refusal=error,all_logical_tables_exact_unchanged=True,
                          whole_fixture_before_after_digest=digest(before)))
        con.close()

    refusal_case('extra_selected_infoID_FTS_tuple_rejected',lambda c:c.execute(
        'INSERT INTO japan_addr_index_8(rowid,index_record,record_info) VALUES (600001,?,?)',
        ('unlistedselectedsuffix',(next(iter(selected_ids))<<8)|49)))
    firstfts=snapshot['old_FTS8_rows'][0]
    refusal_case('corrupt_selected_FTS_preimage_rejected',lambda c:c.execute(
        'UPDATE japan_addr_index_8 SET index_record=? WHERE rowid=?',('corruptselectedtoken',firstfts['rowid'])))
    refusal_case('new_global_info_ID_collision_rejected',lambda c:c.execute(
        'INSERT INTO japan_addr_info VALUES (?,?,?)',(plan['new_street']['info_id'],'existingidcollision',0x30000001)))
    refusal_case('new_record_key_range_collision_rejected',lambda c:c.execute(
        'UPDATE japan_addr_info SET record=? WHERE id=1',(plan['new_family_first'],)))
    refusal_case('mutation_target_trigger_rejected_before_write',lambda c:c.execute(
        "CREATE TRIGGER unwanted_metadata_update AFTER UPDATE ON japan_addr_info BEGIN UPDATE unrelated_metadata SET value='changed'; END"))
    denied=[]
    def deny_new_FTS(action,arg1,arg2,database,trigger):
        if action==sqlite3.SQLITE_INSERT and arg1=='japan_addr_index_8':
            denied.append(dict(action=action,table=arg1));return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    refusal_case('FTS_insert_authorizer_failure_rolls_back441_remaps_family_and_newinfo',authorizer=deny_new_FTS)
    assert len(denied)==1
    with tempfile.TemporaryDirectory(prefix='readonly-source-fixture-',dir=HERE) as temp:
        path=Path(temp)/'fixture.sqlite';con=make_fixture(path);con.close()
        original_raw=path.read_bytes();ro=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
        ro.execute('PRAGMA query_only=ON');before=state(ro);error=None
        try:api.apply_selected_family_relocation(ro,snapshot,plan)
        except sqlite3.DatabaseError as ex:error=type(ex).__name__+': '+str(ex)
        assert error and not ro.in_transaction and state(ro)==before
        ro.close();assert path.read_bytes()==original_raw
        cases.append(dict(name='read_only_fixture_connection_cannot_mutate',passed=True,refusal=error,
                          fixture_bytes=len(original_raw),before_after_sha256=sha(original_raw),exact_file_bytes_unchanged=True))
    assert len(cases)==8

    rawtable=read(HERE/'SQL-table-window.bin',512)
    rawtext=read(HERE/'SQL-text-window.bin',512)
    tablebase=0x0457d600;textbase=0x04708200;sqltable=0x0457d644
    sqlrows=[]
    for offset,expected in [(0x2c,0x047082a2),(0x30,0x04708268)]:
        pointer=struct.unpack_from('<I',rawtable,sqltable+offset-tablebase)[0];assert pointer==expected
        text=rawtext[pointer-textbase:].split(b'\0',1)[0].decode('ascii')
        sqlrows.append(dict(table_runtime=hex(sqltable),table_offset=hex(offset),SQL_pointer_runtime=hex(pointer),SQL_text=text))
    witnesses=snapshot['actual_tiny_prefix_segment_witnesses']
    diagnostic=dict(schema='native-JAI-prefix-segment-finite-diagnostic/v1',
        actual_original_SQL_table_entries=sqlrows,source_name='敦富六街',source_group_ids=source_candidate['source_group_ids'],
        source_ids=source_candidate['source_ids'],exact_original_prefix_witnesses=witnesses,
        actual_MAIN_content_bytes_read=12288,MAIN_full_hash_inherited_not_recomputed=True,
        inspected_code_runtime_ranges=[['0x04423400','0x04426000']],
        literal_code_candidates_are_not_verified_full_CFG_or_callers=True,
        prefix_segment_entry_or_original_consumer_not_located_within_this_budget=True,
        true_native_CPU_case_executed=False,
        minimum_remaining_gap=['Locate actual reachable native caller of SQL table+0x2C and +0x30.',
            'Execute no-prefix branch and one accepted stock prefix/segment branch before defining a blob serializer.',
            'Distinguish84-byte 一 u16-pair segment witness from older102-byte chained-infoID suffix witness; no format unification inferred.',
            'Establish native full frontend invocation, token/keyboard normalization and page state; exact host FTS match alone is insufficient.'],
        no_native_UI_failure_from_missing_prefix_alone_claimed=True,
        selected_adapter_does_not_write_prefix_segments=True,source_alias_and_district_geometry_still_held=True)
    diagnostic_artifact=save('prefix-segment-diagnostic.json',diagnostic)
    result_artifact=save('adapter-control-proof.json',dict(schema='selected-family-adapter-new-controls/v1',
        all_assigned_checks_passed=True,actual_source_selected_info_rows=441,actual_source_selected_FTS_rows=1444,
        controls=cases,all_controls_passed=True,synthetic_other_rows_and_tables=True,
        complete_original_DB_never_opened_or_copied=True,new_module_source_sha256=sha(api_raw),
        old_writer_or_tests_executed=False,production_original_DB_complete_adapter_certified=False))
    proof=dict(schema='native-JAI-prefix-and-selected-adapter-scope/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        source_inputs=INPUTS,script_sha256=sha(Path(__file__).read_bytes()),
        diagnostic=diagnostic_artifact,adapter_controls=result_artifact,
        strict_existing_source_and_plan_bound=True,current_family_payload_proof_inherited_only=True,
        source_alias_and_district_geometry_unverified=True,selected_scope_fullDB_rows_safety_API_prepared=True,
        actual_original_DB_opened_or_copied=False,source_PBF_or_node_or_address_ledger_read=False,
        current_v3_or_closed_source_mutated=False,original_prefix_native_consumer_proved=False,
        native_UI_or_query_or_device_acceptance_proved=False,device_IO=False,install_candidate=False,
        native_full_Taiwan_update_complete=False,
        limits=['New offline host adapter for explicit selected441 info/1444FTS preimages; complete original DB deployment is not certified.',
                'FTS3 internal shadow pages may change; preservation checks concern logical old rows, other tables and metadata.',
                'Unrelated logical rows preserved by constrained DML and trigger refusal; tested on explicit small multi-table fixture, not a full original DB copy.',
                'No prefix/segment serializer, original native prefix caller, UI/keyboard/page execution or installation supplied.',
                'Known source example remains pending alias/district geometry, not verified official new road.'])
    proof_artifact=save('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,controls=len(cases),
                          actual_original_MAIN_bounded_bytes=12288,original_DB_opened=False,
                          original_prefix_consumer_proved=False,proof=proof_artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
