#!/usr/bin/env python3
"""Actual old441-street JAI family with a source-name-backed new FTS8 entry."""
from collections import Counter
from pathlib import Path
import json
import sqlite3
import jai_scope as s
import jai_family_writer as w

HERE=Path(__file__).resolve().parent
SNAPSHOT_SHA='929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6'


def predecessor(con,record):
    rows=list(con.execute('SELECT parent_record FROM japan_addr_family WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 0,1',(record,)))
    s.need(len(rows)==1,'One original SQL predecessor family');return rows[0][0]


def query(con,token):
    return list(con.execute('SELECT id,index_record,record FROM japan_addr_info WHERE id IN(SELECT record_info>>8 FROM japan_addr_index_8 WHERE index_record MATCH ?)ORDER BY id',('"'+token+'*"',)))


def main():
    raw=(HERE/'original-family-snapshot.json').read_bytes();s.need(s.sha(raw)==SNAPSHOT_SHA,'One completed immutable original family capture')
    snapshot=json.loads(raw);inputs=[];encode,decode=s.codec(inputs);street='敦富六街'
    s.need(snapshot['district']['label']=='北屯區'and snapshot['city']['label']=='台中市','Source literal candidate same exact selected city/district')
    plan=w.relocation_plan(snapshot,street,encode(street),current_L3_count=snapshot['L3_count'],new_info_id=snapshot['old_max_info_id']+1,full_name_low_byte=49)
    path=HERE/'JAI-family-FTS8-prototype.sqlite';con=w.make_sandbox(path,snapshot)
    oldfamilies=list(con.execute('SELECT parent_record,the_first_record FROM japan_addr_family ORDER BY the_first_record'))
    before_queries={r['info_id']:query(con,r['index_record'])for r in snapshot['old_info_rows']}
    s.need(not query(con,encode(street)),'New exactname absent from sandbox baseline before writer')
    report=w.apply_relocation(con,snapshot,plan);mapping={r['old_record']:r['new_record']for r in plan['complete_old_physical_order_mapping']}
    for row in snapshot['old_info_rows']:
        ID=row['info_id'];expected=[(i,t,mapping[r])for i,t,r in before_queries[ID]]
        s.need(query(con,row['index_record'])==expected,'Every selected old name host FTSresult has identical IDs/tokens with intended recordremap')
        actual=con.execute('SELECT id,index_record,record FROM japan_addr_info WHERE id=?',(ID,)).fetchone()
        s.need(actual==(ID,row['index_record'],mapping[row['record']]),'Every old named info preimage retained except explicit StreetID remap')
        s.need(predecessor(con,actual[2])==plan['parent_record'],'Every old named clone reached through new sole family')
    new=plan['new_street'];s.need(query(con,new['index_record'])==[(new['info_id'],new['index_record'],new['record'])],'Actual exact newname FTS3 lookup')
    s.need(decode(new['index_record'])==street and encode(street)==new['index_record'],'Sealed hostcodec newname exact UTF8token roundtrip')
    chain=[new['record']];current=new['record']
    while current>>28>1:
        current=predecessor(con,current);chain.append(current)
    s.need(chain==[new['record'],snapshot['district']['record'],snapshot['city']['record']],'Original SQL-shape newstreet→district→city chain')
    afterfamilies=list(con.execute('SELECT parent_record,the_first_record FROM japan_addr_family ORDER BY the_first_record'))
    untouched={p:f for p,f in oldfamilies if p!=plan['parent_record']};s.need({p:f for p,f in afterfamilies if p!=plan['parent_record']}==untouched,'All other original family boundaries unchanged')
    s.need(con.execute('SELECT COUNT(*)FROM japan_addr_info WHERE record>=?AND record<?',(plan['old_family_first'],plan['old_family_end'])).fetchone()[0]==0,'Retired original selected range has no stale info targets')
    s.need(con.execute('SELECT COUNT(*)FROM japan_addr_family WHERE parent_record=?',(plan['parent_record'],)).fetchone()[0]==1,'Exactly one selected family remains')
    quick=list(con.execute('PRAGMA quick_check'));s.need(quick==[('ok',)],'Small created SQLite quickcheck')
    newfts=list(con.execute('SELECT rowid,index_record,record_info FROM japan_addr_index_8 WHERE record_info>>8=?',(new['info_id'],)))
    s.need(len(newfts)==1,'One explicitly declared exact full-name FTS row only');con.close()
    fullnames=Counter(r['low_byte']for r in snapshot['old_FTS8_rows']if r['index_record']==next(i['index_record']for i in snapshot['old_info_rows']if i['info_id']==r['record_info']>>8))
    plan.update(source_name_only_provenance=dict(source='early bounded sourceagent candidate notice',source_group_id=37506,source_node_id=8280986017,
        raw_address=['臺中市','北屯區',street,'368'],source_coordinates_or_geometry_not_used_in_this_SQL_writer=True,
        exact_source_full_provenance_geometry_seal_is_separate=True,physical_new_road_or_official_alias_status_not_established=True))
    plan_artifact=s.save('one-family-new-street-plan.json',plan)
    proof=dict(schema='actual-original-family-newstreet-SQLite-sandbox/v1',all_assigned_checks_passed=True,
        source_sha256=s.sha(Path(__file__).read_bytes()),writer_sha256=s.sha((HERE/'jai_family_writer.py').read_bytes()),helper_sha256=s.sha((HERE/'jai_scope.py').read_bytes()),
        inputs=inputs,original_snapshot_sha256=SNAPSHOT_SHA,prototype=dict(path=str(path.relative_to(s.ROOT)),bytes=path.stat().st_size,sha256=s.sha(path.read_bytes()),
            original_DB_complete_copy=False,contains_only_families_city_district_selected_oldinfos_and_FTS8=True,installable=False),plan=plan_artifact,
        actual_host_checks=dict(old_named_infos=441,old_FTS_rows=report['old_FTS_rows_preserved'],new_FTS_rows=report['new_FTS_rows'],
            every_old_FTS_query_ID_and_token_preserved_with_intended_recordmap=True,every_old_named_clone_parent_correct=True,new_exactname_query=True,
            complete_new_record_family_chain=chain,other_family_rows_unchanged=True,no_stale_selected_oldinfo_targets=True,SQLite_quick_check=quick),
        old_fullname_FTS_low_byte_counts=dict(fullnames),explicit_new_fullname_lowbyte49_observed_policy_only=True,
        original_tiny_prefix_entry_for_new_firstchar_absent=True,required_missing_prefix_entry_character='敦',
        old_prefix_segment_infoIDs_do_not_need_renumber=True,new_prefix_and_segment_writer_implemented=False,
        new_name_full_original_CPU_codec_not_rerun=True,native_query_or_UI_or_device_not_tested=True,
        current_v3_IMG_and_sealed_proofs_not_opened_or_modified=True,original_DB_or_MAP_not_modified=True,new_MDR_or_LBL_not_generated=True,
        native_write_ready=False,full_newstreet_writer_complete=False,full_Taiwan_native_update_complete=False,
        limits=['Actual SQLite host sandbox for one selected original family and exact FTS8 name only; not a complete TWNJAI.db or install candidate.',
            '441 physical L3 clones plusone newstreet and L2 first/count patch are required; currentv3 payloads must be preserved by a later current-profile writer.',
            'L2 first16/count10 stay unchanged and fit this442-record family; no wholecountry width/capacity claim.',
            'Prefix character敦 is absent in original prefix table; new prefix/segment serializer/native consumer path remains unimplemented.',
            'FTS lowbyte0x31 is explicit observed simple-fullstreet prototype policy; full lowflag/native iterator/query semantics remain unproved.',
            'Source name/provenance is separate from historicalalias/physicalnewroad validation; coordinates/geometry were not used or rerun.'])
    artifact=s.save('sandbox-proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,old_named_infos=441,old_FTS_rows=report['old_FTS_rows_preserved'],new_street_record=new['record'],new_lowID=new['record']&0xfffffff,new_info_id=new['info_id'],L2_patch=plan['required_L2_patch'],prototype=proof['prototype'],proof=artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
