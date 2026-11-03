#!/usr/bin/env python3
"""Host-only selected-family JAI/FTS8 mutation API, not an install adapter.

Unlike the closed small sandbox writer, this validates only the explicit selected
info-ID scope of index_8. Other logical FTS rows/tables are permitted and receive
no DML. The complete original DB format and native prefix/segment frontend are
not supplied here. Caller owns a NEW offline DB connection; originals are never
opened, copied or selected by this module.
"""
import re
import sqlite3

SCHEMAS = {
    'japan_addr_family': 'CREATE TABLE japan_addr_family (parent_record INTEGER UNIQUE, the_first_record INTEGER PRIMARY KEY)',
    'japan_addr_info': 'CREATE TABLE japan_addr_info (id INTEGER PRIMARY KEY, index_record TEXT, record INTEGER)',
    'japan_addr_index_8': 'CREATE VIRTUAL TABLE japan_addr_index_8 USING FTS3 (index_record TEXT, record_info INTEGER)',
}


class ScopeRefusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ScopeRefusal(message)


def sql_shape(text):
    return re.sub(r'\s+', ' ', text.strip().rstrip(';')).casefold()


def compile_selected_plan(snapshot, plan):
    """Validate explicit integer spaces, complete physical order and exact names."""
    require(snapshot.get('all_assigned_checks_passed') is True, 'Unverified selected source snapshot')
    require(plan.get('schema') == 'one-complete-JAI-street-family-relocation-plan/v1', 'Unsupported plan schema')
    old_first = snapshot['selected_family_first']
    old_end = snapshot['selected_family_end']
    require(type(old_first) is type(old_end) is int and old_first >> 28 == old_end >> 28 == 3,
            'Explicit level3 physical source range required')
    mappings = plan['complete_old_physical_order_mapping']
    require(0 < old_end - old_first <= 1022 and len(mappings) == old_end - old_first,
            'Complete bounded selected physical range')
    expected = {m['old_record']: m['new_record'] for m in mappings}
    require(len(expected) == len(mappings) and list(expected) == list(range(old_first, old_end)),
            'Physical old order/gaps must be explicit')
    new_first = plan['new_family_first']
    require(type(new_first) is int and new_first >> 28 == 3 and
            list(expected.values()) == list(range(new_first, new_first + len(mappings))),
            'Complete contiguous target family order')
    require(plan['old_family_first'] == old_first and plan['old_family_end'] == old_end and
            plan['parent_record'] == snapshot['district']['record'], 'Selected parent ownership/preimage')
    new = plan['new_street']
    require(new['record'] == new_first + len(mappings) and plan['new_family_end'] == new['record'] + 1,
            'Exactly one new street after all physical copies')
    require((new_first & 0x0fffffff) == snapshot['L3_count'] + 1 and
            plan['final_L3_count'] == (new['record'] & 0x0fffffff) <= 65535,
            'Pinned source L3 tail and unchanged district first16 capacity')
    require(plan['new_physical_L3_count'] == len(mappings) + 1 <= 1023 and
            plan['old_physical_L3_count'] == len(mappings), 'Unchanged district count10 capacity')
    require(plan['required_L2_patch']['first_child'] == (new_first & 0x0fffffff) and
            plan['required_L2_patch']['child_count'] == len(mappings) + 1 and
            plan['required_L2_patch']['unchanged_full_flags'] == snapshot['actual_original_L2_fields']['child_level_and_flags'],
            'Plan linked to required physical district patch, not generated here')
    require(type(new['info_id']) is int and new['info_id'] == snapshot['old_max_info_id'] + 1
            and new['info_id'] <= 0x7fffffff >> 8 and
            new['record_info'] == (new['info_id'] << 8) | 49, 'Stable info ID and explicit observed0x31 policy')
    require(isinstance(new['label'], str) and 0 < len(new['label']) <= 64 and '\0' not in new['label'] and
            isinstance(new['index_record'], str) and new['index_record'].isalpha(), 'Bounded literal new text/token')
    old_info = snapshot['old_info_rows']
    require(len(old_info) <= len(mappings) and len({r['info_id'] for r in old_info}) == len(old_info),
            'Unique explicit selected named info rows')
    require(all(r['record'] in expected for r in old_info) and
            new['label'] not in {r['label'] for r in old_info}, 'Named rows belong to selected physical range; exact new label absent')
    ids = tuple(sorted(r['info_id'] for r in old_info))
    require(ids and all(type(x) is int and 0 < x <= 0x7fffffff >> 8 for x in ids), 'Bounded native info integer IDs')
    old_fts = [(r['rowid'], r['index_record'], r['record_info']) for r in snapshot['old_FTS8_rows']]
    require(len(old_fts) <= 4096 and old_fts == sorted(old_fts) and len({r[0] for r in old_fts}) == len(old_fts)
            and all((r[2] >> 8) in ids for r in old_fts), 'Exact selected FTS rowids/token/packed info scope')
    return expected, ids, old_fts


def apply_selected_family_relocation(connection, snapshot, plan):
    """Atomic selected-scope remap without a whole-index equality assumption.

    Uses a fresh BEGIN IMMEDIATE transaction. Any preimage, schema, collision or
    write failure rolls back all earlier updates. Only selected info.record,
    its one family start, one new info row and one new index_8 logical row can
    change. Application triggers on those tables/shadows are rejected. Prefix,
    segments, metadata, all other tables and old logical FTS rows receive no DML.
    This API intentionally supplies neither an original DB copier nor CLI.
    """
    require(isinstance(connection, sqlite3.Connection) and not connection.in_transaction,
            'Fresh caller-owned SQLite connection with no transaction')
    expected, ids, old_fts = compile_selected_plan(snapshot, plan)
    placeholders = ','.join('?' for _ in ids)
    selected_fts_sql = ('SELECT rowid,index_record,record_info FROM japan_addr_index_8 '
                        'WHERE (record_info >> 8) IN (' + placeholders + ') ORDER BY rowid LIMIT ?')
    new = plan['new_street']
    began = False
    try:
        connection.execute('BEGIN IMMEDIATE'); began = True
        for name, wanted in SCHEMAS.items():
            rows = list(connection.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)))
            require(len(rows) == 1 and isinstance(rows[0][0], str) and sql_shape(rows[0][0]) == sql_shape(wanted),
                    'Exact supported table schema: ' + name)
        triggers = list(connection.execute("SELECT name,tbl_name FROM sqlite_master WHERE type='trigger' AND "
            "(tbl_name IN ('japan_addr_info','japan_addr_family','japan_addr_index_8') OR tbl_name GLOB 'japan_addr_index_8_*') LIMIT 1"))
        require(not triggers, 'Application triggers on mutation targets/shadows are unsupported')
        require(list(connection.execute('SELECT parent_record,the_first_record FROM japan_addr_family WHERE parent_record=?',
                     (plan['parent_record'],))) == [(plan['parent_record'], plan['old_family_first'])], 'Exact selected family preimage')
        actual_info = list(connection.execute('SELECT id,index_record,record FROM japan_addr_info WHERE id IN (' +
            placeholders + ') ORDER BY id', ids))
        wanted_info = sorted((r['info_id'], r['index_record'], r['record']) for r in snapshot['old_info_rows'])
        require(actual_info == wanted_info, 'Exact selected named info preimages')
        actual_physical_scope = list(connection.execute('SELECT id,index_record,record FROM japan_addr_info WHERE record>=? AND record<? ORDER BY id LIMIT ?',
            (plan['old_family_first'], plan['old_family_end'], len(wanted_info) + 1)))
        require(actual_physical_scope == wanted_info, 'No unlisted named row in selected physical old range')
        require(list(connection.execute(selected_fts_sql, ids + (len(old_fts) + 1,))) == old_fts,
                'Exact selected info-ID FTS8 scope; unrelated rows allowed')
        require(not connection.execute('SELECT 1 FROM japan_addr_info WHERE id=? LIMIT 1', (new['info_id'],)).fetchone(),
                'New global info ID collision')
        require(connection.execute('SELECT max(id) FROM japan_addr_info').fetchone()[0] == snapshot['old_max_info_id'],
                'Exact source maximum info ID pin')
        require(not connection.execute('SELECT 1 FROM japan_addr_info WHERE record>=? AND record<? LIMIT 1',
                (plan['new_family_first'], plan['new_family_end'])).fetchone(), 'New physical record-key range collision')
        require(not connection.execute('SELECT 1 FROM japan_addr_family WHERE the_first_record>=? AND the_first_record<? LIMIT 1',
                (plan['new_family_first'], plan['new_family_end'])).fetchone(), 'New family-start range collision')
        for row in snapshot['old_info_rows']:
            changed = connection.execute('UPDATE japan_addr_info SET record=? WHERE id=? AND index_record=? AND record=?',
                (expected[row['record']], row['info_id'], row['index_record'], row['record']))
            require(changed.rowcount == 1, 'Selected exact row update')
        changed = connection.execute('UPDATE japan_addr_family SET the_first_record=? WHERE parent_record=? AND the_first_record=?',
            (plan['new_family_first'], plan['parent_record'], plan['old_family_first']))
        require(changed.rowcount == 1, 'Only selected family start changed')
        connection.execute('INSERT INTO japan_addr_info(id,index_record,record) VALUES (?,?,?)',
                           (new['info_id'], new['index_record'], new['record']))
        inserted = connection.execute('INSERT INTO japan_addr_index_8(index_record,record_info) VALUES (?,?)',
                                      (new['index_record'], new['record_info']))
        new_rowid = inserted.lastrowid
        require(list(connection.execute(selected_fts_sql, ids + (len(old_fts) + 1,))) == old_fts,
                'All selected old FTS tuples retained exactly')
        require(list(connection.execute('SELECT rowid,index_record,record_info FROM japan_addr_index_8 WHERE rowid=?', (new_rowid,))) ==
                [(new_rowid, new['index_record'], new['record_info'])], 'Exact one new logical FTS tuple')
        connection.commit(); began = False
        return dict(schema='selected-family-JAI-FTS8-adapter-result/v1',
                    selected_old_info_rows=len(ids), selected_old_FTS_rows=len(old_fts),
                    old_logical_FTS_rows_updated_or_deleted=0, new_info_rows=1, new_FTS_rows=1,
                    new_FTS_rowid=new_rowid, single_family_row_updated=True,
                    whole_index_equality_required=False, atomic_committed=True,
                    all_other_logical_rows_preserved_by_DML_scope=True,
                    prefix_segment_tables_written=False, full_original_DB_adapter_certified=False,
                    native_frontend_or_device_acceptance_proved=False, install_candidate=False)
    except BaseException:
        if began:
            connection.rollback()
        raise
