#!/usr/bin/env python3
"""Finite genuine JAI consumers, explicit host SQLite and libc boundary fixtures.

No original firmware read: only the already captured 64 KiB runtime window.
No UI result fabrication. Stops before result materialization/page/IMG linkage.
"""
import hashlib
import json
import re
import sqlite3
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
BASE = 0x04420000
DB_REL = 'staging/navigation-native-jai-full-db-adapter-prototype-v1/TWNJAI-offline-prototype.sqlite'
PINS = {
    'staging/navigation-firmware-address-v1/address-dispatch-evidence.json': 'ec01bf743cf465c3d6008542e143e5b07eb4208845b2fbf7a3c0f6242a55d92a',
    'staging/navigation-native-jai-new-street-plan-v1/one-family-new-street-plan.json': '559542283481387c8fdde24b45f79bdf49e5cfbcacd4a4ca400c61869badd72d',
    'staging/navigation-native-jai-full-db-adapter-prototype-v1/sealed-files.json': 'd0eb0b2d7a8ff73e138a1a3c2f8417922bb416195f743b4a0a80dfbda729209b',
    'staging/navigation-native-jai-prefix-consumer-v1/SQL-table-window.bin': '60b8a502db6f7239c1b5633bed0a4d970ac337f79530ffef22ad5e48ca4179d4',
    'staging/navigation-native-jai-prefix-consumer-v1/SQL-text-window.bin': '5d13c507e04520c10eda9557a179174b2841aa3168724d8728e219d96ede8949',
    'staging/navigation-native-jai-prefix-consumer-v1/prefix-segment-name-observation.json': '42f928367366f505d998ade5eb8a13bc06a7978902b49d079c9ed750b1decf1b',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def save(name, value):
    p = HERE / name
    with p.open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def load(rel, inputs):
    p = ROOT / rel
    before = stat(p)
    need(before[2] < 350000, 'Bounded small source input')
    raw = p.read_bytes()
    need(sha(raw) == PINS[rel] and stat(p) == before, 'Exact sealed small source identity')
    inputs.append(dict(path=rel, bytes=len(raw), sha256=sha(raw), stat_before=before,
                       stat_after=stat(p), stat_unchanged=True))
    return raw


class Guest:
    OBJ = 0x02100000
    DATA = 0x02200000
    STACK = 0x02006000
    SENTINEL = 0x02300000
    PREFIX = 0x9010
    SEGMENT14 = 0x9014
    SEGMENT18 = 0x9018
    DYNAMIC = 0x9100

    def __init__(self, code, sql_table, sql_entries, con, name, token,
                 caller=None, flag=1, level=3, bind_failure=False):
        self.name = name
        self.token = token
        self.caller = caller
        self.bind_failure = bind_failure
        self.con = con
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.u.mem_map(BASE, 65536, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_write(BASE, code)
        self.u.mem_protect(BASE, 65536, UC_PROT_READ | UC_PROT_EXEC)
        # Genuine code and stack are separated by unmapped guards. External
        # veneer landing pages are fixtures: no firmware implementation there.
        self.u.mem_map(0x02001000, 0x7000, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_map(self.OBJ, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_map(self.DATA, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_map(self.SENTINEL, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_map(0x0448E000, 0x2000, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_map(0x0457D000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_write(0x0457D600, sql_table)
        self.u.mem_protect(0x0457D000, 0x1000, UC_PROT_READ)
        self.u.mem_map(0x04708000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        for ent in sql_entries:
            self.u.mem_write(int(ent['pointer_runtime'], 16), ent['text'].encode('ascii') + b'\0')
        self.u.mem_protect(0x04708000, 0x1000, UC_PROT_READ)
        self.alloc_at = self.DATA + 0x800
        self.token_ptr = self.DATA
        self.out = self.DATA + 0x200
        self.u.mem_write(self.token_ptr, token.encode('ascii') + b'\0')
        self.w32(self.DATA + 0x300, 8)  # one actual city index_8, synthetic object
        self.w32(self.DATA + 0x304, level)
        self.w32(self.OBJ, 0x9000)
        self.w32(self.OBJ + 0x10, self.PREFIX)
        self.w32(self.OBJ + 0x14, self.SEGMENT14)
        self.w32(self.OBJ + 0x18, self.SEGMENT18)
        self.u.mem_write(self.OBJ + 0x1C, b'\x01')
        self.w32(self.OBJ + 0x34, 1)
        self.w32(self.OBJ + 0x38, self.DATA + 0x300)
        self.w32(self.OBJ + 0x48, self.DATA + 0x304)
        self.w32(self.OBJ + 0x4C, 1 if level is not None else 0)
        self.u.mem_write(self.OBJ + 0x50, bytes([flag]))
        self.w32(self.OBJ + 0x54, 0)
        self.w32(self.OBJ + 0x58, 16)
        self.statements = {
            self.PREFIX: dict(sql=next(x['text'] for x in sql_entries if x['offset'] == '0x2c'), bindings={}),
            self.SEGMENT14: dict(sql=next(x['text'] for x in sql_entries if x['offset'] == '0x30'), bindings={}),
            self.SEGMENT18: dict(sql=next(x['text'] for x in sql_entries if x['offset'] == '0x30'), bindings={}),
        }
        self.events = []
        self.addresses = []
        self.steps = 0
        self.stop_reason = None
        self.prefix_native_return = None
        self.query_results = []
        self.fixture_rows_executed = 0
        self.u.reg_write(UC_ARM_REG_SP, self.STACK)
        self.u.reg_write(UC_ARM_REG_LR, self.SENTINEL | 1)
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def r(self, n):
        return self.u.reg_read([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3][n])

    def w32(self, addr, value):
        self.u.mem_write(addr, struct.pack('<I', value & 0xFFFFFFFF))

    def read32(self, addr):
        return struct.unpack('<I', self.u.mem_read(addr, 4))[0]

    def cstr(self, addr):
        need(addr != 0, 'Fixture receives nonnull string pointer')
        out = bytearray()
        for i in range(1536):
            c = bytes(self.u.mem_read(addr + i, 1))
            if c == b'\0':
                return bytes(out).decode('ascii')
            out.extend(c)
        raise ValueError('Fixture string bound')

    def alloc(self, raw):
        addr = self.alloc_at
        self.alloc_at = (addr + len(raw) + 3) & ~3
        need(self.alloc_at < self.DATA + 0x4000, 'Bounded fixture data')
        self.u.mem_write(addr, raw)
        return addr

    def ret(self, value=0):
        self.u.reg_write(UC_ARM_REG_R0, value)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def hook(self, uc, address, size, _):
        self.steps += 1
        need(self.steps <= 6000, 'Finite guest instruction cap')
        if BASE <= address < BASE + 65536:
            self.addresses.append(address)
        if address == self.SENTINEL:
            self.stop_reason = 'native_function_return'
            uc.emu_stop()
            return
        if address in (0x04424F82, 0x044257A4):
            self.prefix_native_return = self.r(0)
            self.events.append(dict(kind='original_prefix_return', address=hex(address), status=self.r(0)))
        if self.caller and address == 0x04424D4E:
            self.stop_reason = 'stock_prefix_segment_branch_before_blob_consumer'
            self.events.append(dict(kind='original_segment_helper_entry', address=hex(address),
                                    seg_id=self.r(1), statement_address=hex(self.r(0))))
            uc.emu_stop()
            return
        if self.caller == 0x04424F14 and address == 0x044251EA:
            self.stop_reason = 'native_fallback_first_info_id_before_materializer'
            uc.emu_stop()
            return
        if self.caller == 0x04425726 and address == 0x044259FA:
            self.stop_reason = 'native_fallback_first_record_before_materializer'
            uc.emu_stop()
            return
        if not (0x0448E000 <= address < 0x04490000):
            need(BASE <= address < BASE + 65536, 'Only genuine window or assigned boundary fixtures execute')
            return
        r0, r1, r2, r3 = [self.r(i) for i in range(4)]
        sp = uc.reg_read(UC_ARM_REG_SP)
        if address == 0x0448F6C0:  # explicit reset fixture; implementation not emulated
            s = self.statements[r0]
            s.pop('rows', None)
            s.pop('row', None)
            s['bindings'] = {}
            self.events.append(dict(kind='fixture_reset', handle=r0))
            self.ret()
        elif address in (0x0448E050, 0x0448F9C0):
            value = self.cstr(r2) if address == 0x0448E050 else r2
            self.events.append(dict(kind='fixture_bind_text' if address == 0x0448E050 else 'fixture_bind_integer',
                                    handle=r0, native_zero_based_slot=r1, value=value))
            if self.bind_failure and r0 == self.PREFIX:
                self.ret(1)
            else:
                self.statements[r0]['bindings'][r1] = value
                self.ret()
        elif address == 0x0448F9E0:
            sql = self.cstr(r1)
            # Host EXPLAIN validates actual complete SQLite syntax. This is a
            # fixture for the external prepare veneer, not original SQLite.
            placeholders = sql.count('?')
            explanation = list(self.con.execute('EXPLAIN QUERY PLAN ' + sql, (None,) * placeholders))
            need(len(explanation) <= 32 and 'japan_addr_index_8' in sql, 'Bounded selected city query')
            self.statements[self.DYNAMIC] = dict(sql=sql, bindings={})
            self.w32(r2, self.DYNAMIC)
            self.events.append(dict(kind='original_built_sql_host_prepare_fixture', sql=sql,
                                    native_SQL_pointer=hex(r1), host_query_plan=explanation))
            self.ret()
        elif address == 0x0448F9D0:
            s = self.statements[r0]
            if 'rows' not in s:
                params = tuple(s['bindings'][i] for i in range(s['sql'].count('?')))
                cursor = self.con.execute(s['sql'], params)
                rows = cursor.fetchmany(129)
                cursor.close()
                need(len(rows) <= 128, 'Bounded host SQL rows, no scan materialized')
                s['rows'] = rows
                s['position'] = 0
                self.fixture_rows_executed += len(rows)
                printable = [[dict(blob_bytes=len(v), blob_sha256=sha(v)) if isinstance(v, bytes) else v for v in row] for row in rows]
                event = dict(kind='actual_readonly_complete_DB_SQL_fixture', handle=r0, sql=s['sql'],
                             bindings=list(params), row_count=len(rows), rows=printable)
                self.events.append(event)
                if r0 == self.DYNAMIC:
                    self.query_results.append(event)
            p = s['position']
            if p == len(s['rows']):
                self.events.append(dict(kind='fixture_step', handle=r0, native_status=5, actual_host_row=None))
                self.ret(5)
            else:
                s['row'] = s['rows'][p]
                s['position'] += 1
                self.events.append(dict(kind='fixture_step', handle=r0, native_status=4, row_position=p))
                self.ret(4)
        elif address in (0x0448F9C8, 0x0448F9B8, 0x0448F6B0, 0x0448F6B8):
            value = self.statements[r0]['row'][r1]
            if address == 0x0448F9C8:
                need(isinstance(value, int), 'Actual integer column')
                self.events.append(dict(kind='fixture_column_integer', handle=r0, column=r1, value=value))
                self.ret(value)
            elif address == 0x0448F9B8:
                need(isinstance(value, str), 'Actual text column')
                ptr = self.alloc(value.encode('ascii') + b'\0')
                self.events.append(dict(kind='fixture_column_text', handle=r0, column=r1, value=value))
                self.ret(ptr)
            elif address == 0x0448F6B0:
                need(isinstance(value, bytes), 'Actual blob column')
                self.ret(len(value))
            else:
                need(isinstance(value, bytes) and len(value) <= 4096, 'Bounded actual blob column')
                self.ret(self.alloc(value))
        elif address == 0x0448FFA0:
            self.ret(len(self.cstr(r0)))
        elif address == 0x0448FE78:
            need(r2 <= 1536, 'Bounded memcpy fixture')
            uc.mem_write(r0, bytes(uc.mem_read(r1, r2)))
            self.ret(r0)
        elif address == 0x0448FB70:
            fmt = self.cstr(r1)
            specs = re.findall(r'%[sd]', fmt)
            need(len(specs) <= 5, 'Only observed bounded format ABI')
            args = [r2, r3] + [self.read32(sp + 4 * i) for i in range(max(0, len(specs) - 2))]
            values = []
            for spec, arg in zip(specs, args):
                values.append(self.cstr(arg) if spec == '%s' else (arg if arg < 0x80000000 else arg - 0x100000000))
            raw = (fmt % tuple(values)).encode('ascii')
            need(len(raw) < 1024, 'Bounded snprintf-equivalent fixture')
            uc.mem_write(r0, raw + b'\0')
            self.events.append(dict(kind='fixture_string_format', original_format_address=hex(r1),
                                    format=fmt, result=raw.decode('ascii')))
            self.ret(len(raw))
        elif address == 0x0448FFC8:
            need(r1 == 1000, 'Exact observed memzero size125 shifted3')
            uc.mem_write(r0, bytes(r1))
            self.ret(r0)
        elif address == 0x0448FA00:
            handle = self.read32(r0)
            self.events.append(dict(kind='fixture_statement_finalize', handle=handle))
            self.w32(r0, 0)
            self.ret()
        else:
            raise ValueError('Unassigned boundary fixture ' + hex(address))

    def run(self, kind):
        u = self.u
        if kind == 'prefix':
            entry = 0x04424E4E
            regs = [self.OBJ, self.token_ptr, self.out, self.out + 4]
            self.w32(self.STACK, self.out + 8)
        elif kind == 'segment':
            entry = 0x04424D4E
            regs = [self.OBJ + 0x18, 1116, self.out, self.out + 4]
        else:
            entry = self.caller
            if entry == 0x04424F14:
                regs = [self.OBJ, self.token_ptr, 1, self.out]
            else:
                regs = [self.OBJ, self.OBJ, self.token_ptr, 0]
                self.w32(self.STACK, self.out)
        for reg, value in zip([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3], regs):
            u.reg_write(reg, value)
        u.emu_start(entry | 1, 0, timeout=1000000, count=6000)
        need(self.stop_reason is not None, 'Explicit finite guest stop')
        output = dict(name=self.name, entry=hex(entry), input_encoded_token=self.token,
                      guest_initialized_object_is_fixture=True, instruction_count=self.steps,
                      stop_reason=self.stop_reason, native_return_r0=u.reg_read(UC_ARM_REG_R0),
                      original_prefix_return_status=self.prefix_native_return,
                      actual_SQL_fixture_rows=self.fixture_rows_executed,
                      native_code_addresses=[hex(a) for a in sorted(set(self.addresses))], events=self.events)
        if kind == 'prefix':
            output.update(found_byte=bytes(u.mem_read(self.out, 1))[0],
                          prefix_id=struct.unpack('<H', u.mem_read(self.out + 4, 2))[0],
                          seg_id=struct.unpack('<H', u.mem_read(self.out + 8, 2))[0])
        if kind == 'segment':
            length = self.read32(self.out)
            ptr = self.read32(self.out + 4)
            blob = bytes(u.mem_read(ptr, length))
            output.update(actual_segment_bytes=length, actual_segment_sha256=sha(blob),
                          segment_output_pointer=hex(ptr))
        return output


def main():
    started = datetime.now(timezone.utc).isoformat()
    inputs = []
    code_p = HERE / 'JAI-runtime-code-64KiB.bin'
    code_stat = stat(code_p)
    code = code_p.read_bytes()
    need(len(code) == 65536 and sha(code) == 'b005aec81bfca0987931b9565437b68deb47974ccb81f8cfd8e03297433fa04d', 'Exact already captured runtime window')
    dispatch = json.loads(load('staging/navigation-firmware-address-v1/address-dispatch-evidence.json', inputs))
    plan = json.loads(load('staging/navigation-native-jai-new-street-plan-v1/one-family-new-street-plan.json', inputs))
    db_seal = json.loads(load('staging/navigation-native-jai-full-db-adapter-prototype-v1/sealed-files.json', inputs))
    sql_table = load('staging/navigation-native-jai-prefix-consumer-v1/SQL-table-window.bin', inputs)
    sql_window = load('staging/navigation-native-jai-prefix-consumer-v1/SQL-text-window.bin', inputs)
    observation = json.loads(load('staging/navigation-native-jai-prefix-consumer-v1/prefix-segment-name-observation.json', inputs))
    sql_entries = dispatch['sql_table']
    need(len(sql_entries) == 18, 'Complete inherited actual SQL table')
    for ent in sql_entries:
        addr = int(ent['pointer_runtime'], 16)
        off = int(ent['offset'], 16)
        need(struct.unpack('<I', sql_table[0x44 + off:0x48 + off])[0] == addr, 'Actual table bytes match inherited literal')
        if 0x04708200 <= addr < 0x04708400:
            need(sql_window[addr - 0x04708200:].split(b'\0')[0] == ent['text'].encode('ascii'), 'Literal actual bytes cross-check')
    db_entry = next(x for x in db_seal['files'] if x['path'] == DB_REL)
    db_path = ROOT / DB_REL
    db_before = stat(db_path)
    need(db_before[2] == db_entry['bytes'] == 12745728 and (db_path.stat().st_mode & 0o777) == 0o444, 'Exact frozen full offline prototype')
    con = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA query_only=ON')
    con.execute('PRAGMA cache_size=64')
    cases = []
    try:
        for token, status, found in [('tkfadgj', 3, 0), ('tkhcoep', 0, 1)]:
            g = Guest(code, sql_table, sql_entries, con, 'actual_prefix_' + token, token)
            row = g.run('prefix')
            need(row['native_return_r0'] == status and row['found_byte'] == found, 'Genuine prefix ABI status')
            if found:
                need((row['prefix_id'], row['seg_id']) == (28, 1116), 'Actual stock prefix IDs materialized')
            cases.append(row)
        g = Guest(code, sql_table, sql_entries, con, 'actual_prefix_bind_failure', 'tkfadgj', bind_failure=True)
        row = g.run('prefix')
        need(row['native_return_r0'] == 1 and not any(x['kind'] == 'fixture_step' for x in row['events']), 'Native bind failure returns1 without SQL step')
        cases.append(row)
        g = Guest(code, sql_table, sql_entries, con, 'stock_segment1116_actual_blob_output', 'tkhcoep')
        row = g.run('segment')
        need(row['native_return_r0'] == 0 and row['actual_segment_bytes'] == 84 and row['actual_segment_sha256'] == '39e98d312e5461bf159fde445a3db0742f6f8823dd6d7bab1f8dc99334361a08', 'Genuine segment helper retrieves actual stock blob')
        cases.append(row)
        # Two real consumers, not host-created frontend branch results. Host
        # SQL fixtures read actual complete DB only after genuine native prepare
        # and bind calls; results returned to native column consumers.
        for caller in [0x04424F14, 0x04425726]:
            for label, token in [('敦-prefix-with-five-old-plus-one-prototype', 'tkfadgj'),
                                 ('敦富六街-prototype-full-token', plan['new_street']['index_record'])]:
                g = Guest(code, sql_table, sql_entries, con, label + '-' + hex(caller), token, caller=caller)
                row = g.run('caller')
                need(row['original_prefix_return_status'] == 3 and row['stop_reason'].startswith('native_fallback_first_'), 'Genuine missing-prefix caller takes fallback and consumes first column row')
                q = next(x for x in row['events'] if x['kind'] == 'actual_readonly_complete_DB_SQL_fixture' and x['handle'] == g.DYNAMIC)
                normalized_SQL = re.sub(r'\s+', ' ', q['sql'])
                need(q['bindings'] == ['"' + token + '*"', 1, 3] and '(record_info & 15) = ?' in normalized_SQL and '((record_info >> 4) & 15) IN (?)' in normalized_SQL, 'Original token wildcard and observed nibble filters: ' + json.dumps(q))
                expected_ids = {r['info_id'] for r in observation['actual_original_named_rows_starting_Dun']} | {plan['new_street']['info_id']}
                expected = expected_ids if token == 'tkfadgj' else {plan['new_street']['info_id']}
                if caller == 0x04424F14:
                    need({r[1] for r in q['rows']} == expected, 'Actual complete prototype oldfive/new info IDs')
                else:
                    actual_info = [con.execute('SELECT id FROM japan_addr_info WHERE record=?', (r[1],)).fetchone()[0] for r in q['rows']]
                    need(set(actual_info) == expected, 'Actual complete prototype oldfive/new native records')
                cases.append(row)
            g = Guest(code, sql_table, sql_entries, con, 'level2-filter-empty-' + hex(caller), plan['new_street']['index_record'], caller=caller, level=2)
            row = g.run('caller')
            need(row['original_prefix_return_status'] == 3 and row['stop_reason'] == 'native_function_return' and row['native_return_r0'] == 0, 'Wrong nibble level native caller completes empty')
            need(any(e['kind'] == 'actual_readonly_complete_DB_SQL_fixture' and e['handle'] == g.DYNAMIC and e['row_count'] == 0 for e in row['events']), 'Actual host SQLite filter refuses prototype street under2')
            cases.append(row)
            g = Guest(code, sql_table, sql_entries, con, 'stock-prefix-keeps-segment-branch-' + hex(caller), 'tkhcoep', caller=caller)
            row = g.run('caller')
            need(row['original_prefix_return_status'] == 0 and row['stop_reason'] == 'stock_prefix_segment_branch_before_blob_consumer', 'Stock prefix follows segment path')
            need(not any(e['kind'] == 'original_built_sql_host_prepare_fixture' for e in row['events']), 'No fallback SQL on stock prefix before segment branch')
            cases.append(row)
        # Source name itself is exact; official/historical alias still held.
    finally:
        con.close()
    need(stat(db_path) == db_before and stat(code_p) == code_stat, 'All actual DB and captured code sources immutable')
    static = {}
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    windows = [('prefix_consumer',0x4E4E,0x4EC0),('segments_blob_consumer',0x4D4E,0x4DA4),
               ('prefix_caller_ID_entry',0x4F14,0x4FAA),('prefix_caller_ID_fallback',0x512C,0x5294),
               ('prefix_caller_record_entry',0x5726,0x57D4),('prefix_caller_record_fallback',0x5942,0x5A82),
               ('query_builder',0x4A84,0x4C9C),('upstream_encoded_token_wrapper',0x5572,0x55E0),
               ('prefix_and_segment_statement_initializer_suffix',0x606C,0x613A)]
    for name, start, end in windows:
        raw = code[start:end]
        static[name] = dict(start=hex(BASE+start),end=hex(BASE+end),bytes=len(raw),sha256=sha(raw),
                            instructions=[dict(address=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(raw,BASE+start)])
    callers = []
    targets = {'#0x4424e4e','#0x4424f14','#0x4425726','#0x4425572','#0x44254c0'}
    for off in range(0,len(code)-4,2):
        ins = next(md.disasm(code[off:off+4],BASE+off,count=1),None)
        if ins and ins.mnemonic in ('bl','blx') and ins.op_str in targets:
            callers.append(dict(address=hex(ins.address),mnemonic=ins.mnemonic,target=ins.op_str))
    save('native-consumer-static-ABI.json', dict(schema='genuine-JAI-consumer-ABI-static/v1',
        window_sha256=sha(code),fragments=static,bounded_direct_calls=callers,
        complete_CFG_or_full_UI_entry_not_claimed=True))
    save('actual-native-guest-cases.json', dict(schema='genuine-JAI-consumer-with-explicit-SQL-fixtures/v1',
        all_assigned_checks_passed=True,case_count=len(cases),cases=cases,
        original_code_executed=True,native_sqlite_engine_executed=False,
        host_sqlite_complete_modified_offline_DB_used=True,guest_object_and_stack_are_fixtures=True,
        token_codec_execution_inherited_not_replayed=True,
        frontend_full_result_UI_materialization_executed=False,device_IO=False))
    proof = dict(schema='bounded-native-JAI-prefix-fallback-ABI-proof/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        actual_new_MAIN_bytes_read=65536,MAIN_cap_reached=True,no_MAIN_read_by_this_runner=True,
        actual_code=dict(path=str(code_p.relative_to(ROOT)),bytes=len(code),sha256=sha(code),
                         runtime_start=hex(BASE),runtime_end=hex(BASE+65536),stat_before=code_stat,stat_after=stat(code_p)),
        source_inputs=inputs,full_DB_fixture=dict(path=DB_REL,bytes=db_before[2],
            inherited_sealed_sha256=db_entry['sha256'],whole_DB_hash_not_recomputed=True,
            open_mode='readonly mode=ro&immutable=1; PRAGMA query_only=ON',
            stat_before=db_before,stat_after=stat(db_path),stat_unchanged=True,handles_closed=True),
        native_prefix_ABI=dict(entry='0x04424E4E',r0='initialized JAI object',r1='nonnull encoded query token C string',
            r2='found uint8 output',r3='prefix_id uint16 output',stack_arg0='seg_id uint16 output',
            object_statement_offset=16,success_status=0,missing_row_status=3,error_status=1),
        observed_statement_initializer=dict(SQL_table='0x0457D644',prefix_table_offset='0x2C',prefix_handle_object_offset='0x10',
            segment_table_offset='0x30',segment_handle_object_offsets=['0x14','0x18']),
        actual_native_case_count=len(cases),total_guest_instruction_count=sum(r['instruction_count'] for r in cases),
        both_true_native_callers_prefix_DONE_to_FTS_fallback=True,
        no_prefix_alone_proves_frontend_failure=False,
        original_record_info_filter_observed=dict(info_id_shift=8,low_nibble_mask=15,
            native_filter_value_from_object_byte_0x50=1,following_nibble_shift=4,
            following_nibble_mask=15,following_nibble_values_from_object_0x48_0x4C=[3],
            observed_fullstreet_0x31_passes=True,general_lowflag_semantics_not_claimed=True),
        true_query_builder_string_and_bind_execution=True,
        original_native_SQL_engine_or_filesystem_executed=False,
        native_frontend_UI_keyboard_page_reachability_verified=False,
        full_query_result_materializer_and_IMG_access_verified=False,
        source_example='敦富六街368號 / source node8280986017 / source group37506',
        source_geometry_gate_inherited_separate_sealed_scope='staging/navigation-beitun-district-geometry-v1',
        official_alias_or_physical_newroad_verified=False,install_candidate=False,
        whole_Taiwan_update_complete=False,no_IMG_PBF_device_report_mutation=True,
        closed_previous_suites_replayed=False,all_guest_and_database_handles_closed=True,
        boundary_fixtures=dict(SQL=['reset','prepare syntax via host EXPLAIN','zero-based text/integer bind',
            'host actual readonly SELECT step maps ROW=4,DONE=5','integer/text/blob column','finalize'],
            libc=['bounded string length','bounded memcpy','observed format arguments sprintf-equivalent','bounded memzero']),
        script_sha256=sha(Path(__file__).read_bytes()),limits=[
            'Consumers are genuine unmodified original code; external SQLite/libc veneers are declared host fixtures, not native implementations.',
            'Full offline DB is the previously sealed selected-family prototype; oldfive labels retain originalinfo IDs but records are relocated.',
            'Singlechar prefix miss is optional for these observed callers because status3 takes genuine FTS fallback.',
            'Guest stops before result materializer; physical UI success, full frontend startup/caller reachability and IMG cross-file linkage remain unverified.',
            'Stock segment blob fetched exactly; downstream blob serialization and all segment record semantics are not established.',
            'Official street name and historical alias remain held; separate source OSM district/source/raw24 geometry passed without proving official alias.',
            'No general prefix table rewrite or new prefix serializer is supplied.' ])
    save('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,case_count=len(cases),
        guest_instructions=proof['total_guest_instruction_count'],DB_stat_unchanged=True,handles_closed=True),ensure_ascii=False))


if __name__ == '__main__':
    main()
