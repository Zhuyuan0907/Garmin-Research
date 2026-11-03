#!/usr/bin/env python3
"""New small synthetic FTS3/family controls; no original DB/IMG opened."""
import copy
import json
from pathlib import Path
import sqlite3
import jai_scope as s
import jai_family_writer as w

HERE=Path(__file__).resolve().parent;inputs=[];encode,decode=s.codec(inputs);checks=[]


def need(ok,message):
    if not ok:raise AssertionError(message)


def snapshot():
    old=[dict(info_id=10,index_record=encode('甲路'),record=(3<<28)|10,label='甲路'),dict(info_id=12,index_record=encode('乙路'),record=(3<<28)|12,label='乙路')]
    return dict(all_assigned_checks_passed=True,L3_count=20,old_max_info_id=50,city=dict(info_id=1,record=(1<<28)|8,index_record=encode('台中市')),
        district=dict(info_id=2,record=(2<<28)|9,index_record=encode('原區')),selected_family_first=(3<<28)|10,selected_family_end=(3<<28)|13,
        old_info_rows=old,old_FTS8_rows=[dict(rowid=5,index_record=old[0]['index_record'],record_info=(10<<8)|49),dict(rowid=8,index_record=old[1]['index_record'],record_info=(12<<8)|49)],
        original_families=[[(1<<28)|8,(2<<28)|9],[(2<<28)|8,(3<<28)|1],[(2<<28)|9,(3<<28)|10],[(2<<28)|10,(3<<28)|13]],
        selected_FTS8_low_byte_counts={49:2},actual_original_L2_fields=dict(next_level=3,child_level_and_flags=3))


def plan(x=None,**options):
    x=x or snapshot();args=dict(current_L3_count=x['L3_count'],new_info_id=x['old_max_info_id']+1,full_name_low_byte=49);args.update(options)
    return w.relocation_plan(x,'新增路',encode('新增路'),**args)


def rejects(name,callback):
    try:callback()
    except(ValueError,sqlite3.IntegrityError):checks.append(dict(name=name,rejected=True,passed=True));return
    raise AssertionError(name+' should reject')


def makescope(x):
    con=sqlite3.connect(':memory:');con.execute(w.FAMILY);con.execute(w.INFO);con.execute(w.FTS)
    con.executemany('INSERT INTO japan_addr_family VALUES (?,?)',x['original_families'])
    con.executemany('INSERT INTO japan_addr_info VALUES (?,?,?)',[(r['info_id'],r['index_record'],r['record'])for r in x['old_info_rows']])
    con.executemany('INSERT INTO japan_addr_index_8(rowid,index_record,record_info)VALUES(?,?,?)',[(r['rowid'],r['index_record'],r['record_info'])for r in x['old_FTS8_rows']]);con.commit();return con


x=snapshot();p=plan();con=makescope(x);before=list(con.execute('SELECT rowid,index_record,record_info FROM japan_addr_index_8 ORDER BY rowid'))
report=w.apply_relocation(con,x,p)
need(report['old_FTS_rows_preserved']==2,'Old two FTS records preserved')
for r in x['old_info_rows']:
    found=list(con.execute('SELECT id,index_record,record FROM japan_addr_info WHERE id IN(SELECT record_info>>8 FROM japan_addr_index_8 WHERE index_record MATCH ?)',('"'+r['index_record']+'*"',)))
    expected=p['new_family_first']+(r['record']-p['old_family_first']);need(found==[(r['info_id'],r['index_record'],expected)],'Exact original SQL shape retained info ID/newrecord')
    parent=con.execute('SELECT parent_record FROM japan_addr_family WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 0,1',(expected,)).fetchone()[0];need(parent==p['parent_record'],'Actual new selected family ownership')
new=p['new_street'];need(list(con.execute('SELECT index_record,record FROM japan_addr_info WHERE id IN(SELECT record_info>>8 FROM japan_addr_index_8 WHERE index_record MATCH ?)',('"'+new['index_record']+'*"',)))==[(new['index_record'],new['record'])],'Exactnewname host FTS3 lookup')
need(p['complete_old_physical_order_mapping'][1]['has_named_info']is False,'Unlabelled physical slot preserved in complete clone order')
need(con.execute('SELECT COUNT(*)FROM japan_addr_family WHERE parent_record=?',(p['parent_record'],)).fetchone()[0]==1,'One sameparent family only')
need(con.execute('SELECT COUNT(*)FROM japan_addr_info WHERE record>=?AND record<?',(p['old_family_first'],p['old_family_end'])).fetchone()[0]==0,'No stale selected infos in retired old physical range')
checks.append(dict(name='actual SQLite FTS3 query oldinfo remap/newname + unnamed gap + one family + old FTS preservation',passed=True,rejected=False))
rejects('disjoint second family sameparent',lambda:con.execute('INSERT INTO japan_addr_family VALUES (?,?)',(p['parent_record'],(3<<28)|30)))
con.rollback();con.close()
rejects('implicit current L3 count',lambda:plan(current_L3_count=21))
rejects('reused existing info ID',lambda:plan(new_info_id=50))
rejects('unknown low flag policy',lambda:plan(full_name_low_byte=48))
y=snapshot();y['L3_count']=65533
rejects('unchanged L2 first16 overflow',lambda:plan(y))
y=snapshot();y['selected_family_end']=y['selected_family_first']+1023
rejects('unchanged L2 count10 overflow',lambda:plan(y))
y=snapshot();y['old_info_rows'][0]['label']='新增路'
rejects('existing exact street name',lambda:plan(y))
rejects('signed native record_info overflow',lambda:plan(dict(snapshot(),old_max_info_id=0x7fffffff>>8)))
y=snapshot();con=makescope(y);broken=plan();broken['parent_record']+=1
rejects('wrong parent ownership',lambda:w.apply_relocation(con,y,broken));con.close()
y=snapshot();con=makescope(y);broken=plan();broken['complete_old_physical_order_mapping'][0]['new_record']+=1
rejects('duplicate/noncontiguous cloned IDs',lambda:w.apply_relocation(con,y,broken));con.close()
y=snapshot();con=makescope(y);con.execute('UPDATE japan_addr_info SET record=record+1 WHERE id=12');con.commit();before_rows=list(con.execute('SELECT * FROM japan_addr_info ORDER BY id'))
rejects('atomic preimage mismatch rolls back earlier modified row',lambda:w.apply_relocation(con,y,plan()))
need(list(con.execute('SELECT * FROM japan_addr_info ORDER BY id'))==before_rows,'Failure entire remap rollback');con.close()
result=dict(schema='new-JAI-family-writer-synthetic-controls/v1',all_assigned_checks_passed=True,control_count=len(checks),controls=checks,
    writer_sha256=s.sha((HERE/'jai_family_writer.py').read_bytes()),source_sha256=s.sha(Path(__file__).read_bytes()),inputs=inputs,
    actual_original_DB_IMG_CPU_or_device_not_opened=True,SQLite_version=sqlite3.sqlite_version,FTS3_module_actually_executed=True)
s.save('new-writer-controls.json',result);print(json.dumps(dict(all_assigned_checks_passed=True,controls=len(checks),writer_sha256=result['writer_sha256'])),flush=True)
