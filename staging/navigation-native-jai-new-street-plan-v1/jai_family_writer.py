#!/usr/bin/env python3
"""Small JAI family relocation + exact full-name FTS3 insertion primitive.

Writes only caller-owned SQLite sandbox/new DB; not a complete JAI/IMG updater.
Preserves existing info IDs and full existing FTS tuples. Prefix/segment new-name
serialization, raw low-flag policy and native UI acceptance remain unproved.
"""
from pathlib import Path
import json
import sqlite3
import jai_scope as s

FAMILY='CREATE TABLE japan_addr_family (parent_record INTEGER UNIQUE, the_first_record INTEGER PRIMARY KEY)'
INFO='CREATE TABLE japan_addr_info (id INTEGER PRIMARY KEY, index_record TEXT, record INTEGER)'
FTS='CREATE VIRTUAL TABLE japan_addr_index_8 USING FTS3 (index_record TEXT, record_info INTEGER)'


def relocation_plan(snapshot,street_text,encoded_text,*,current_L3_count,new_info_id,full_name_low_byte):
    """Explicit complete physical family order is old order then one new record."""
    s.need(snapshot['all_assigned_checks_passed'],'Completed actual family snapshot')
    s.need(type(current_L3_count)is int and current_L3_count==snapshot['L3_count'],'Explicit current L3 count matches finite stock-same-count source')
    s.need(type(street_text)is str and 1<=len(street_text)<=64 and '\0'not in street_text and all(c.isalpha()for c in encoded_text),'Explicit bounded exact street token')
    s.need(street_text not in {r['label']for r in snapshot['old_info_rows']},'No exact old name collision within selected family')
    s.need(type(new_info_id)is int and new_info_id==snapshot['old_max_info_id']+1 and new_info_id<=0x7fffffff>>8,'New explicit stable global info ID fits signed native integer')
    s.need(full_name_low_byte==49 and(full_name_low_byte in snapshot['selected_FTS8_low_byte_counts']or
        str(full_name_low_byte)in snapshot['selected_FTS8_low_byte_counts']),'Only explicit observed fullstreet lowbyte0x31 prototype policy')
    oldfirst=snapshot['selected_family_first'];oldend=snapshot['selected_family_end'];count=oldend-oldfirst;first=current_L3_count+1;total=count+1
    s.need(0<count<=1022 and first+total-1<=65535 and total<=1023,'Unchanged L2 first16/count10 capacity; no implicit widening')
    s.need(snapshot['district']['record']>>28==2 and oldfirst>>28==oldend>>28==3,'Existing level2 parent/level3 family only')
    mappings=[dict(old_record=oldfirst+i,new_record=(3<<28)|(first+i),old_lowID=(oldfirst&0xfffffff)+i,new_lowID=first+i,
        has_named_info=any(r['record']==oldfirst+i for r in snapshot['old_info_rows']))for i in range(count)]
    newrecord=(3<<28)|(first+count)
    return dict(schema='one-complete-JAI-street-family-relocation-plan/v1',parent_record=snapshot['district']['record'],
        old_family_first=oldfirst,old_family_end=oldend,new_family_first=(3<<28)|first,new_family_end=newrecord+1,
        old_physical_L3_count=count,new_physical_L3_count=total,complete_old_physical_order_mapping=mappings,
        old_info_ids_remain_stable=True,old_FTS_record_info_and_rowids_remain_stable=True,
        new_street=dict(label=street_text,index_record=encoded_text,info_id=new_info_id,record=newrecord,record_info=(new_info_id<<8)|full_name_low_byte,
            low_byte_policy='Explicit observed existing fullstreet0x31 host-prototype policy; complete native lowflag semantics not proved.'),
        required_L2_patch=dict(first_child=first,child_count=total,next_level=snapshot['actual_original_L2_fields']['next_level'],
            unchanged_full_flags=snapshot['actual_original_L2_fields']['child_level_and_flags'],first_width=16,count_width=10),
        final_L3_count=current_L3_count+total,physical_L3_old_prefix_retained=True,
        current_profile_L3_clone_payloads_required_not_generated=True,old_removed_family_gap_has_no_selected_info_targets=True,
        new_prefix_segments_supported=False,new_MDR_or_LBL_generated=False,native_write_ready=False)


def make_sandbox(path,snapshot):
    path=Path(path);s.need(not path.exists(),'New caller-owned sandbox path only');con=sqlite3.connect(path)
    con.execute('PRAGMA page_size=4096');con.execute(FAMILY);con.execute(INFO);con.execute(FTS)
    con.executemany('INSERT INTO japan_addr_family VALUES (?,?)',snapshot['original_families'])
    for row in [snapshot['city'],snapshot['district']]:
        token=row['index_record']
        con.execute('INSERT INTO japan_addr_info VALUES (?,?,?)',(row['info_id'],token,row['record']))
    con.executemany('INSERT INTO japan_addr_info VALUES (?,?,?)',[(r['info_id'],r['index_record'],r['record'])for r in snapshot['old_info_rows']])
    con.executemany('INSERT INTO japan_addr_index_8(rowid,index_record,record_info) VALUES (?,?,?)',[(r['rowid'],r['index_record'],r['record_info'])for r in snapshot['old_FTS8_rows']])
    con.commit();return con


def apply_relocation(con,snapshot,plan):
    """Atomic record-key remap, single family update, one exact full-name FTS row."""
    expected={r['old_record']:r['new_record']for r in plan['complete_old_physical_order_mapping']}
    s.need(len(expected)==plan['old_physical_L3_count'],'Every physical old slot explicitly mapped, including unnamed gaps')
    s.need(plan['parent_record']==snapshot['district']['record']and plan['old_family_first']==snapshot['selected_family_first']and
        list(expected)==list(range(snapshot['selected_family_first'],snapshot['selected_family_end'])),'Exact selected family ownership/order')
    s.need(list(expected.values())==list(range(plan['new_family_first'],plan['new_family_first']+len(expected)))and
        plan['new_street']['record']==plan['new_family_first']+len(expected),'Complete contiguous remap followed by one newstreet')
    new=plan['new_street'];oldfts=list(con.execute('SELECT rowid,index_record,record_info FROM japan_addr_index_8 ORDER BY rowid'))
    s.need(oldfts==[(r['rowid'],r['index_record'],r['record_info'])for r in snapshot['old_FTS8_rows']],'Exact old FTS rows before atomic mutation')
    with con:
        for row in snapshot['old_info_rows']:
            changed=con.execute('UPDATE japan_addr_info SET record=? WHERE id=? AND index_record=? AND record=?',
                (expected[row['record']],row['info_id'],row['index_record'],row['record']));s.need(changed.rowcount==1,'Exact old row preimage')
        changed=con.execute('UPDATE japan_addr_family SET the_first_record=? WHERE parent_record=? AND the_first_record=?',
            (plan['new_family_first'],plan['parent_record'],plan['old_family_first']));s.need(changed.rowcount==1,'One existing family preimage updated')
        con.execute('INSERT INTO japan_addr_info VALUES (?,?,?)',(new['info_id'],new['index_record'],new['record']))
        con.execute('INSERT INTO japan_addr_index_8(index_record,record_info) VALUES (?,?)',(new['index_record'],new['record_info']))
    oldrowids=[r[0]for r in oldfts];after=list(con.execute('SELECT rowid,index_record,record_info FROM japan_addr_index_8 ORDER BY rowid'))
    s.need([r for r in after if r[0]in oldrowids]==oldfts,'All old FTS IDs/token/packed info unchanged')
    return dict(old_FTS_rows_preserved=len(oldfts),new_FTS_rows=len(after)-len(oldfts),single_family_row_updated=True,
        all_old_named_info_IDs_tokens_stable=True,SQLite_atomic_transaction=True,complete_original_DB_not_copied=True)
