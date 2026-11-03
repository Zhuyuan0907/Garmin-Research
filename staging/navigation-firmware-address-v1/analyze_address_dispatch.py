#!/usr/bin/env python3
"""Bounded, read-only address dispatch analysis of exact HWID 1352 / SW 8.00.

Inputs stay in the verified backup / MAIN locations. Only small metadata,
instruction traces and this directory's reports are written. No device I/O,
NT payload decoding, database mutation or installable firmware is involved.
"""
from collections import deque
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R4,
                              UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                              UC_ARM_REG_PC, UC_ARM_REG_LR)

DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
CATALOG = ROOT / 'staging/navigation-map-layers-v1/layer-inventory.json'
BRANCHES = {'b', 'beq', 'bne', 'bhs', 'blo', 'bhi', 'bls', 'bge', 'blt',
            'bgt', 'ble', 'bmi', 'bpl', 'bvs', 'bvc'}


def sha(path):
    with path.open('rb') as f:
        h = hashlib.sha256()
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


class Image:
    def __init__(self):
        self.stock = NativeImage()
        self.md = self.stock.md

    def read(self, address, size):
        return self.stock.read(self.stock.runtime_to_load(address, size), size)

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]

    def text(self, address, limit=512):
        return self.read(address, limit).split(b'\0', 1)[0].decode('ascii')

    def veneer(self, address):
        try:
            first, target = struct.unpack('<II', self.read(address, 8))
        except ValueError:
            return None
        return hex(target) if first == 0xe51ff004 else None

    def describe(self, i):
        row = {'runtime_address': hex(i.address),
               'load_address': hex(self.stock.runtime_to_load(i.address, i.size)),
               'bytes': bytes(i.bytes).hex(),
               'instruction': i.mnemonic + ' ' + i.op_str}
        if i.mnemonic == 'ldr' and len(i.operands) == 2:
            op = i.operands[1]
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                pool = ((i.address + 4) & ~3) + op.mem.disp
                row.update(literal_runtime_address=hex(pool),
                           literal_value=hex(self.word(pool)))
        if i.mnemonic in ('bl', 'blx'):
            if i.operands[0].type == ARM_OP_IMM:
                target = i.operands[0].imm
                row['direct_call'] = hex(target)
                via = self.veneer(target)
                if via:
                    row['stock_arm_veneer_target'] = via
            else:
                row['unresolved_indirect_call'] = True
        return row

    def cfg(self, start, end):
        pending, rows, exits = deque([start]), {}, []
        while pending:
            address = pending.popleft()
            if address in rows:
                continue
            if not start <= address < end:
                exits.append({'target': hex(address), 'reason': 'out of bound'})
                continue
            if len(rows) >= 1600:
                raise ValueError('Bounded instruction limit exceeded')
            i = next(self.md.disasm(self.read(address, 4), address, count=1), None)
            if i is None:
                raise ValueError('Undecodable reachable instruction')
            rows[address] = self.describe(i)
            if i.mnemonic in BRANCHES:
                pending.append(i.operands[0].imm)
                if i.mnemonic == 'b':
                    continue
            elif i.mnemonic == 'pop' and 'pc' in i.op_str:
                continue
            elif i.mnemonic == 'bx':
                if i.op_str != 'lr':
                    exits.append({'address': hex(address), 'reason': 'indirect tail'})
                continue
            elif i.mnemonic not in ('bl', 'blx') and ARM_REG_PC in i.regs_access()[1]:
                exits.append({'address': hex(address), 'reason': 'computed PC unresolved'})
                continue
            pending.append(address + i.size)
        return {'entry': hex(start), 'bound_end': hex(end),
                'instructions': [rows[a] for a in sorted(rows)],
                'unresolved_exits': exits, 'recursive_callees_not_executed': True}


def direct_candidates(image, targets):
    """Candidates only; listed caller windows below prove selected call sites."""
    result = {hex(a): [] for a in targets}
    for sec in image.stock.copies:
        if sec['runtime_start'] not in (0x50000, 0x4400000, 0x5400000):
            continue
        raw = image.stock.read(sec['load_start'], sec['size'])
        for off in range(0, len(raw) - 3, 2):
            high, low = struct.unpack_from('<HH', raw, off)
            kind = low & 0xf800
            if high & 0xf800 != 0xf000 or kind not in (0xf800, 0xe800):
                continue
            delta = ((high & 0x7ff) << 12) | ((low & 0x7ff) << 1)
            if delta & 0x400000:
                delta -= 0x800000
            target = sec['runtime_start'] + off + 4 + delta
            if kind == 0xe800:
                target &= ~3
            if target in targets:
                result[hex(target)].append(hex(sec['runtime_start'] + off))
    return result


def rtti_vtable(image, table, slots):
    typeinfo = image.word(table - 4)
    name_address = image.word(typeinfo + 4)
    return {'vtable_runtime': hex(table), 'typeinfo_runtime': hex(typeinfo),
            'type_name_runtime': hex(name_address),
            'type_name_load': hex(image.stock.runtime_to_load(name_address)),
            'type_name': image.text(name_address),
            'entries': [{'offset': hex(i * 4), 'function_pointer': hex(image.word(table + i * 4))}
                        for i in range(slots)]}


def map_id_loop_case(image, name, db_ids, requested_ids, expected):
    """Execute untouched stock loop; SQLite results and caller RAM are fixtures."""
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for base, size in ((0x4425000, 0x2000), (0x448f000, 0x1000)):
        uc.mem_map(base, size)
        uc.mem_write(base, image.read(base, size))
    uc.mem_map(0x2100000, 0x2000)
    uc.mem_map(0x2200000, 0x2000)
    sp = 0x2201000
    uc.mem_write(sp + 0x20, struct.pack('<I', 0x2100000))
    if requested_ids:
        uc.mem_write(0x2100000, struct.pack('<' + 'I' * len(requested_ids), *requested_ids))
    for reg, value in ((UC_ARM_REG_SP, sp), (UC_ARM_REG_R4, 0),
                       (UC_ARM_REG_R5, 0x2100800), (UC_ARM_REG_R6, len(requested_ids)),
                       (UC_ARM_REG_R7, 0)):
        uc.reg_write(reg, value)
    state = {'row': -1, 'instructions': 0, 'stopped': False}

    def hook(machine, address, size, data):
        state['instructions'] += 1
        if address in (0x4425eaa, 0x4425ec2):
            state.update(stopped=True, end_address=hex(address),
                         status=machine.reg_read(UC_ARM_REG_R4),
                         matching_rows=machine.reg_read(UC_ARM_REG_R7))
            machine.emu_stop()
            return
        if address not in (0x448f9d0, 0x448f958, 0x448f9c8):
            return
        if address == 0x448f9d0:
            state['row'] += 1
            value = 4 if state['row'] < len(db_ids) else 5
        elif address == 0x448f958:
            value = 0
        else:
            value = db_ids[state['row']]
        machine.reg_write(UC_ARM_REG_R0, value)
        machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x4425e4f, 0, count=5000)
    passed = state['stopped'] and state['status'] == expected
    if not passed:
        raise ValueError('Stock map-id loop case failed: ' + name)
    return {'name': name, 'database_map_ids': db_ids, 'requested_map_ids': requested_ids,
            'expected_status': expected, 'passed': passed, **state}


def main():
    image = Image()
    sources_before = {str(DB.relative_to(ROOT)): sha(DB),
                      str(CATALOG.relative_to(ROOT)): sha(CATALOG),
                      'evidence/firmware-analysis/main_02bd.bin': EXPECTED}
    con = sqlite3.connect(DB.as_uri() + '?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA query_only=ON')
    tables = list(con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'"))
    indexes = [name for name, sql in tables if sql and sql.startswith('CREATE VIRTUAL TABLE')]
    db_info = {
        'path': str(DB.relative_to(ROOT)), 'sha256': sources_before[str(DB.relative_to(ROOT))],
        'bytes': DB.stat().st_size,
        'garmin_metadata': list(con.execute('SELECT * FROM garmin_metadata')),
        'jai_metadata': list(con.execute('SELECT * FROM jai_metadata')),
        'jai_map_ids': [row[0] for row in con.execute('SELECT map_id FROM jai_map_id')],
        'row_counts': {name: con.execute('SELECT count(*) FROM "' + name + '"').fetchone()[0]
                       for name in ('japan_addr_info', 'japan_addr_prefix', 'japan_addr_segments',
                                    'japan_addr_level_one', 'japan_addr_family')},
        'fts3_tables': indexes,
    }
    encoded, total, unusual = 0, 0, []
    for value, in con.execute('SELECT index_record FROM japan_addr_info'):
        total += 1
        if re.fullmatch(r'(?:tk[a-p]{5})+', value or ''):
            encoded += 1
        elif len(unusual) < 3:
            unusual.append(value)
    db_info['index_encoding_observation'] = {
        'rows': total, 'rows_matching_repeated_tk_plus_five_a_to_p': encoded,
        'limited_nonmatching_samples': unusual,
        'first_public_sample': con.execute('SELECT index_record FROM japan_addr_info ORDER BY id LIMIT 1').fetchone()[0],
        'encoder_and_unicode_semantics_not_identified': True,
    }
    con.close()
    catalog = json.loads(CATALOG.read_text())
    db_info['map_matches'] = [
        {'stock_path': m['path'], 'description': m['description'],
         'stock_sha256': m['backup_verified_sha256'], 'mps': product}
        for m in catalog['stock_maps'] for product in m['mps_maps']
        if product['hex_map_number'] in db_info['jai_map_ids']]

    functions = {
        'manager_factory': (0x440dd1a, 0x440dd90),
        'region_format_selector': (0x44144c8, 0x441452a),
        'format_map_guard': (0x32defc, 0x32e00a),
        'map_id_top_bit_guard': (0x32c940, 0x32c9d2),
        'base_manager_constructor': (0x440dae8, 0x440db56),
        'twn_manager_constructor': (0x440dc4c, 0x440dc68),
        'twn_depth_dispatch': (0x440efde, 0x440f006),
        'jai_map_database_init': (0x4425dc6, 0x442613c),
        'jai_database_enumerator': (0x442614a, 0x4426228),
        'jai_boolean_init_wrapper': (0x4419374, 0x441939a),
        'jai_query_builder': (0x4424a84, 0x4424c9c),
        'jai_caller_map_id_array': (0x4422448, 0x442250c),
    }
    cfgs = {name: image.cfg(*bounds) for name, bounds in functions.items()}
    sql_table = [{'offset': hex(offset), 'pointer_runtime': hex(image.word(0x457d644 + offset)),
                  'pointer_load': hex(image.stock.runtime_to_load(image.word(0x457d644 + offset))),
                  'text': image.text(image.word(0x457d644 + offset))}
                 for offset in range(0, 0x48, 4)]
    query_caller = [image.describe(i) for i in image.md.disasm(image.read(0x442598e, 0x36), 0x442598e)]
    proof = [
        map_id_loop_case(image, 'AP singleton accepted', [5441050], [5441050], 0),
        map_id_loop_case(image, 'different map singleton rejected', [5441050], [70000001], 3),
        map_id_loop_case(image, 'AP and another requested id need both DB rows', [5441050], [5441050, 70000001], 3),
        map_id_loop_case(image, 'two matching DB ids accepted', [5441050, 70000001], [70000001, 5441050], 0),
        map_id_loop_case(image, 'first unmatched DB row stops scan', [70000001, 5441050], [5441050], 3),
    ]
    assertions = [
        {'status': 'confirmed_static', 'claim': 'Address manager creation has conditional provider dispatch, not a single unconditional JAI call.',
         'evidence': ['manager_factory', 'region_format_selector', 'base_manager_constructor', 'twn_manager_constructor'],
         'detail': 'Selector checks region guard plus format constants 950, 932, 936, 1252; otherwise enum 4 allocates base GUI::PrefectureManager. Enum 0 reads runtime halfword 0x5431A94; 1 creates WeakPrefectureManager and 2 creates PrefectureManagerTwn.'},
        {'status': 'confirmed_static', 'claim': 'The 950-format guard also requires a matching map-id record with its top bit set.',
         'evidence': ['format_map_guard', 'map_id_top_bit_guard'],
         'detail': '0x32DF7C..82 compares loaded record halfword +0x28 with the supplied format constant; 0x32DF84..90 calls 0x32C940 with low 28 bits of the map ID and requires true. 0x32C9AC..AE returns the matching record bit 31. UI checkbox ownership of this flag is unresolved.'},
        {'status': 'confirmed_static_and_bounded_emulation', 'claim': 'JAI database initialization checks caller-supplied map IDs against jai_map_id.',
         'evidence': ['jai_map_database_init', 'jai_database_enumerator', 'jai_boolean_init_wrapper', 'map_id_loop_emulation'],
         'detail': 'SQL table +4 is prepared at 0x4425E36; map_id column at 0x4425E74 is compared to caller array at 0x4425E80..92. In the clean row path a first unrequested DB ID or unmatched requested-count returns status 3. Only this stock loop is emulated; database enumeration, UI and maps are not.'},
        {'status': 'confirmed_backup', 'claim': 'The original TWNJAI database depends on Address Point map 0x53061A, not main road map 0x533A5C.',
         'evidence': ['db_info.map_matches'],
         'detail': 'jai_map_id contains 5441050, matching gmapprom1.img MPS hex_map_number and I053061A.GMP. The main and address layers are complementary stock products; this is not evidence that their original simultaneous selection conflicts.'},
        {'status': 'confirmed_static', 'claim': 'A JAI query path uses FTS MATCH against a partitioned japan_addr_index table and prepares/binds the actual SQL.',
         'evidence': ['sql_table', 'jai_query_caller_window', 'jai_query_builder'],
         'detail': '0x442599A..B6 loads query table +8/+C/+10/+14 then calls 0x4424A84 at 0x44259BC. 0x4424C1C prepares the built SQL, 0x4424C36 binds text through veneer 0x448E050. Observed DB tk tokens are not decoded; origin and meaning of the query transformation remain unknown.'},
        {'status': 'unresolved', 'claim': 'Cannot yet establish that the fallback base manager specifically searches OSM MDR, or that selected Taiwan address searches always use JAI.',
         'evidence': ['twn_depth_dispatch'],
         'detail': 'TWN depth dispatch chooses virtual method +0x48 or base helper 0x440E844, but the provider from its shared object and MDR search implementation are not resolved. Runtime profile, optional-copy startup flag and actual checkbox state are unavailable.'},
    ]
    plan = [
        {'case': 'A: updated OSM only', 'selection': 'New OSM on; both old CN and Address Point off. Basemap/timezone left as device normally handles them.',
         'record': 'Cold restart; Taiwan/Taichung shown in Address menu; exact entry 民權路; timed candidates and full selected name; separately Where To > POI spell-name on the same exact text.',
         'purpose': 'Tests the actual alternate provider and OSM address vs POI paths; default manager existence alone does not establish OSM MDR success.'},
        {'case': 'B: original stock pair only', 'selection': 'New OSM off; both original CN and Address Point on.',
         'record': 'Repeat identical city/street entry and restart procedure, limit each wait to 60 seconds and record timeout instead of waiting hours.',
         'purpose': 'Keeps the JAI map dependency consistent and tests original search/keyboard behavior as one complementary product pair.'},
        {'case': 'C: original main only, diagnostic if A/B differs', 'selection': 'New OSM off; original main CN on; original Address Point off.',
         'record': 'Repeat only the same address query after cold restart.',
         'purpose': 'Tests whether this Address Point/JAI provider changes results; not recommended as the final stock configuration.'},
    ]
    output = {
        'checked_at_local': datetime.now().astimezone().isoformat(),
        'scope': {'hardware_id': 1352, 'software_version': 800, 'device_io': False,
                  'static_analysis': True, 'bounded_stock_loop_emulation': True,
                  'source_files_copied': False, 'installer_or_package_modified': False},
        'input_sha256_before': sources_before, 'db_info': db_info,
        'source_runtime_mappings': image.stock.copies,
        'sql_table_runtime': '0x457d644', 'sql_table': sql_table,
        'rtti_vtables': [rtti_vtable(image, 0x47021bc, 23),
                        rtti_vtable(image, 0x47030c8, 23),
                        rtti_vtable(image, 0x470367c, 25),
                        rtti_vtable(image, 0x4703420, 6)],
        'functions': cfgs, 'jai_query_caller_window': query_caller,
        'direct_call_candidates_not_exhaustive': direct_candidates(image, {0x4425dc6, 0x442614a, 0x4419374, 0x44144c8}),
        'map_id_loop_emulation': {'all_passed': True, 'cases': proof,
             'scope': 'Untouched instructions 0x4425E4E until 0x4425EAA/EC2; three SQLite veneers return fixture rows. Synthetic caller map-ID RAM, no file/device reads from emulated firmware. Stops before allocation, metadata parsing or query execution.'},
        'assertions': assertions, 'physical_ab_plan': plan,
        'limitations': ['No physical device, live RAM, checkbox flag writer, country-selection state or search timing observed.',
                        'Optional runtime code comes from exact startup mappings; live copy flag is not established.',
                        'Bounded functions leave indirect virtual providers and callees unresolved.',
                        'The tk encoder and original Taiwanese search sort/transliteration semantics are not identified.',
                        'No NT payload unlocked or decoded; no DB/SIG/firmware changed; no repair success claim.'],
    }
    sources_after = {path: sha(ROOT / path) for path in sources_before}
    if sources_after != sources_before:
        raise ValueError('A read-only source changed during analysis')
    output['input_sha256_after'] = sources_after
    output['source_files_unchanged'] = True
    OUT.mkdir(exist_ok=True)
    path = OUT / 'address-dispatch-evidence.json'
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output': str(path.relative_to(ROOT)),
                      'source_files_unchanged': True, 'emulation_cases': len(proof),
                      'all_passed': True, 'bytes': path.stat().st_size}))


if __name__ == '__main__':
    main()
