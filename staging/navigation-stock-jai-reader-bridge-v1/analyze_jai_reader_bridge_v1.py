#!/usr/bin/env python3
"""Exact static JAI->packed-reader bridge plus three partial CPU handoffs.

Actual backup scalar reads are host SQLite mode=ro&immutable. No native SQL
success stub, old reader/codec rerun, UI, packed body execution or device I/O.
"""
import hashlib
import json
import mmap
from pathlib import Path
import sqlite3
import struct
from datetime import datetime, timezone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TARGET = OUT / 'original-JAI-record-to-packed-reader-bridge-proof-v1.json'
FRAGMENTS = OUT / 'original-JAI-record-to-reader-static-fragments-v1.json'
DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
DELTA = 57525300
RAM = 0x09010000
SP = 0x0900E000
GP = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]


def need(value, label):
    if not value:
        raise ValueError(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    need(not TARGET.exists() and not FRAGMENTS.exists(), 'new outputs only')
    sections = json.loads((ROOT / 'evidence/firmware-analysis/native-sections.json').read_text())
    copy = next(x for x in sections['copies'] if x['runtime_start'] == 0x04400000)
    need(copy['relocation_delta'] == DELTA, 'frozen exact conditional MAIN copy')
    plan_path = ROOT / 'staging/navigation-native-AP-packed-reader-v1/original-packed-reader-plan-proof-v1.json'
    need(digest(plan_path.read_bytes()) == 'ef3c9b8373aa8fd1471843ef9c08a33c62f39659fd204cb76380921e06de7042',
         'completed original reader-plan dependency')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    fragments = {}
    instruction_map = {}
    ranges = {
        'outer_query_and_result_collection_handoff': (0x04422806, 0x04422846),
        'query_collection_JAI_adapter_call': (0x044222C4, 0x044222EA),
        'JAI_adapter': (0x0441950C, 0x04419546),
        'JAI_query_wrapper_call': (0x04425CA2, 0x04425CDA),
        'SQL_row_column_to_materializer': (0x04425884, 0x044258D2),
        'SQL_builder_record_info_shift8': (0x04424AD2, 0x04424AE4),
        'materializer_key_split': (0x0442533E, 0x04425356),
        'materializer_result_copy_call': (0x04425434, 0x0442544A),
        'result_tuple_copy': (0x044249DC, 0x044249FC),
        'result_group_construction': (0x04421EAC, 0x04421EDC),
        'result_tuple_to_constructor': (0x04421F0A, 0x04421F20),
        'descriptor_constructor_to_reader': (0x04421DB4, 0x04421DD4),
        'descriptor_field_stores': (0x04421DDC, 0x04421E12),
        'descriptor_getter_to_reader': (0x044B2976, 0x044B298C),
    }
    with MAIN.open('rb') as handle, mmap.mmap(handle.fileno(), 0,
                                             access=mmap.ACCESS_READ) as image:
        def read(address, length):
            need(copy['runtime_start'] <= address and address + length <= copy['runtime_end'],
                 'bounded conditional-copy read')
            offset = address - DELTA - 0x50000
            return bytes(image[offset:offset + length])

        for name, (start, end) in ranges.items():
            raw = read(start, end - start)
            rows = list(md.disasm(raw, start))
            need(sum(x.size for x in rows) == len(raw), name + ' decode coverage')
            fragments[name] = {'runtime_start': hex(start), 'load_start': hex(start - DELTA),
                               'bytes': len(raw), 'sha256': digest(raw), 'raw_hex': raw.hex(),
                               'instructions': [{'address': hex(x.address),
                                                 'instruction': x.mnemonic + ' ' + x.op_str}
                                                for x in rows]}
            instruction_map.update({x.address: (x.mnemonic, x.op_str) for x in rows})
        guards = {
            0x04422816: ('bl', '#0x442217e'),
            0x0442283E: ('add', 'r2, sp, #0x28'),
            0x04422842: ('bl', '#0x4421e5a'),
            0x044222E6: ('bl', '#0x441950c'),
            0x04419534: ('bl', '#0x4425c3a'),
            0x04425CD6: ('bl', '#0x4425726'),
            0x044258A0: ('blx', '#0x448f9c8'),
            0x044258B4: ('str', 'r0, [sp, #0xc]'),
            0x044258CE: ('bl', '#0x4425304'),
            0x04424ADC: ('movs', 'r3, #8'),
            0x04425340: ('str', 'r2, [sp, #0x68]'),
            0x04425342: ('lsrs', 'r2, r4, #0x1c'),
            0x04425344: ('str', 'r2, [r6]'),
            0x04425346: ('lsls', 'r2, r4, #4'),
            0x04425348: ('lsrs', 'r2, r2, #4'),
            0x0442534A: ('str', 'r2, [r6, #4]'),
            0x04425444: ('bl', '#0x44249b4'),
            0x044249EE: ('ldm', 'r1, {r1, r2, r3}'),
            0x044249F0: ('stm', 'r7!, {r1, r2, r3}'),
            0x04421F0A: ('ldr', 'r1, [r6]'),
            0x04421F10: ('str', 'r1, [sp]'),
            0x04421F16: ('ldr', 'r3, [r6, #4]'),
            0x04421F1C: ('bl', '#0x4421db4'),
            0x04421DC6: ('ldr', 'r1, [sp, #0x70]'),
            0x04421DCA: ('movs', 'r2, r7'),
            0x04421DD0: ('bl', '#0x44b10e4'),
            0x04421E04: ('str', 'r0, [r6, #4]'),
            0x04421E06: ('movs', 'r0, #0x24'),
            0x04421E08: ('strb', 'r0, [r6, #8]'),
            0x04421E10: ('strb', 'r7, [r6, #9]'),
            0x044B297A: ('ldrb', 'r0, [r0, #9]'),
            0x044B2980: ('lsrs', 'r2, r2, #0x1a'),
            0x044B2982: ('ldr', 'r1, [r0, #4]'),
            0x044B2984: ('subs', 'r2, r2, #2'),
            0x044B2988: ('bl', '#0x44b10e4'),
        }
        for address, expected in guards.items():
            need(instruction_map.get(address) == expected, 'exact static guard ' + hex(address))
        sql_fragments = []
        for start in (0x0470819B, 0x047083C4, 0x047081F2):
            raw = read(start, 160).split(b'\0', 1)[0]
            sql_fragments.append({'runtime': hex(start), 'load': hex(start - DELTA),
                                  'text': raw.decode('ascii'), 'sha256': digest(raw)})
        # Preserve the exact query scalar conversion veneer without naming an
        # unverified external symbol. It is an original integer-column helper.
        integer_veneer = read(0x0448F9C8, 8)
        need(integer_veneer[:4] == bytes.fromhex('04f01fe5'), 'original ARM column veneer')
        column_target = struct.unpack('<I', integer_veneer[4:])[0]

        connection = sqlite3.connect(DB.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
        scalars = []
        for info_id, expected in ((12987, 0x10000008), (16765, 0x20000058), (16786, 0x30004143)):
            row = connection.execute('SELECT id,index_record,record FROM japan_addr_info WHERE id=?',
                                     (info_id,)).fetchone()
            need(row is not None and row[2] == expected, 'actual underlying stock DB scalar')
            scalars.append({'info_id': row[0], 'index_record': row[1], 'record': row[2],
                            'record_hex': hex(row[2]), 'underlying_read': 'actual host readonly SQLite parameterized SELECT'})
        connection.close()
        cases = []
        for scalar in scalars:
            native = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            native.ctl_set_cpu_model(UC_CPU_ARM_1176)
            pages = []
            for page in (0x04425000, 0x04421000):
                raw = read(page, 4096)
                native.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
                native.mem_write(page, raw)
                pages.append({'runtime': hex(page), 'load': hex(page - DELTA),
                              'sha256': digest(raw)})
            native.mem_map(0x09000000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
            phases = []
            instructions = []
            stores = []
            fixtures = []
            current = ''
            pc = 0

            def snap():
                return {'GP16': [native.reg_read(x) for x in GP],
                        'CPSR': native.reg_read(UC_ARM_REG_CPSR)}

            def code(_uc, address, size, _data):
                nonlocal pc
                pc = address
                instructions.append({'phase': current, 'pc': hex(address),
                                     'opcode_hex': bytes(native.mem_read(address, size)).hex()})

            def store(_uc, access, address, size, value, _data):
                stores.append({'phase': current, 'pc': hex(pc), 'address': hex(address),
                               'size': size, 'value': value, 'before_hex': bytes(native.mem_read(address, size)).hex(),
                               'GP16': snap()['GP16'], 'CPSR': native.reg_read(UC_ARM_REG_CPSR)})

            def fixture(address, data, purpose):
                native.mem_write(address, data)
                fixtures.append({'address': hex(address), 'hex': data.hex(), 'purpose': purpose})

            def phase(name, start, end, registers):
                nonlocal current
                current = name
                native.reg_write(UC_ARM_REG_CPSR, 0x3F)
                native.reg_write(UC_ARM_REG_SP, SP)
                for i, reg in enumerate(GP[:13]):
                    native.reg_write(reg, 0x11000000 + i * 0x1111)
                for reg, value in registers.items():
                    native.reg_write(reg, value)
                before = snap()
                native.emu_start(start | 1, end, timeout=1000000, count=1000)
                after = snap()
                need(after['GP16'][15] == end, 'actual partial endpoint')
                phases.append({'name': name, 'entry': hex(start), 'end': hex(end),
                               'full_function_return': False, 'before': before, 'after': after})
                return after

            native.hook_add(UC_HOOK_CODE, code)
            native.hook_add(UC_HOOK_MEM_WRITE, store)
            tuple_address = RAM + 0x1000
            fixture(tuple_address, struct.pack('<3I', 0, 0, 0xFFFFFFFF),
                    'explicit output tuple storage; third field outside key split scope')
            phase('original_SQL_materializer_key_split', 0x0442533E, 0x0442534E,
                  {UC_ARM_REG_R4: scalar['record'], UC_ARM_REG_R6: tuple_address})
            level, low_id, third = struct.unpack('<3I', bytes(native.mem_read(tuple_address, 12)))
            need(level == scalar['record'] >> 28 and low_id == scalar['record'] & 0x0FFFFFFF,
                 'original CPU split of actual DB scalar')
            directory, manager = RAM + 0x6000, RAM + 0x5000
            fixture(SP + 0x50, struct.pack('<I', directory), 'declared directory pointer in parent caller frame')
            fixture(SP + 0x78, struct.pack('<I', manager), 'declared manager pointer in parent caller frame')
            setup = phase('original_tuple_to_descriptor_constructor_arguments',
                          0x04421F0A, 0x04421F1C,
                          {UC_ARM_REG_R6: tuple_address, UC_ARM_REG_R0: SP + 0x2C})
            argument_level = struct.unpack('<I', bytes(native.mem_read(SP, 4)))[0]
            argument_low_id = setup['GP16'][3]
            need(argument_level == level and argument_low_id == low_id,
                 'actual original caller forwards split tuple')
            fixture(SP + 0x70, struct.pack('<I', argument_low_id),
                    'constructor saved-r3 frame scalar taken from actual prior CPU argument')
            reader = phase('original_constructor_arguments_before_packed_reader_call',
                           0x04421DC6, 0x04421DD0,
                           {UC_ARM_REG_R5: setup['GP16'][1], UC_ARM_REG_R7: argument_level})
            need(reader['GP16'][0] == directory and reader['GP16'][1] == low_id and
                 reader['GP16'][2] == level,
                 'actual original reader argument preparation from SQL scalar split')
            cases.append({'underlying_DB_scalar': scalar, 'actual_tuple_words': [level, low_id, third],
                          'actual_original_reader_arguments': {'r0_directory': hex(reader['GP16'][0]),
                              'r1_one_based_lowID': reader['GP16'][1], 'r2_level': reader['GP16'][2],
                              'r3_output': hex(reader['GP16'][3])},
                          'all_partial_checks_passed': True, 'phases': phases,
                          'actual_instructions': instructions, 'actual_CPU_stores': stores,
                          'explicit_fixture_writes': fixtures, 'original_RX_pages': pages,
                          'packed_reader_executed': False, 'native_SQL_result_stub': False,
                          'constructor_full_return': False})
    FRAGMENTS.write_text(json.dumps({'schema': 'original-JAI-reader-static-fragments/v1',
        'conditional_startup_copy': copy, 'fragments': fragments, 'SQL_fragments': sql_fragments,
        'integer_column_veneer': {'runtime': '0x0448F9C8', 'raw_hex': integer_veneer.hex(),
                                 'target': hex(column_target)}}, ensure_ascii=False, indent=2) + '\n')
    result = {
        'schema': 'original-JAI-record-to-packed-reader-bridge-proof/v1',
        'created_utc': datetime.now(timezone.utc).isoformat(), 'all_bounded_checks_passed': True,
        'source_sha256': digest(Path(__file__).read_bytes()),
        'static_fragments': str(FRAGMENTS.relative_to(ROOT)),
        'static_fragments_sha256': digest(FRAGMENTS.read_bytes()),
        'inputs': {'MAIN': str(MAIN.relative_to(ROOT)), 'MAIN_sha256_inherited': sections['stock_sha256'],
                   'MAIN_new_full_rehash': False, 'database': str(DB.relative_to(ROOT)),
                   'database_mode': 'ro&immutable=1', 'old_reader_plan': str(plan_path.relative_to(ROOT)),
                   'old_reader_plan_sha256': digest(plan_path.read_bytes()), 'old_reader_rerun': False},
        'static_chain': [
            '04422816 calls0442217E with r2=SP+28 result collection; same outer function04422842 calls04421E5A with r2=SP+28.',
            '0442217E calls0441950C at044222E6; adapter calls04425C3A; wrapper calls04425726.',
            '04425726 calls original integer-column veneer0448F9C8 with column1 at044258A0; stores returned logical record in materializer stack argument at044258B4; calls04425304 at044258CE.',
            '04425304 stores level=record>>28 and lowID=record&0x0FFFFFFF in a12-byte tuple; final04425444 calls044249B4 to copy tuples.',
            '04421E5A iterates result groups and tuples;04421F0A loads tuple level into stackarg5,04421F16 loads tuple lowID into r3;04421F1C calls04421DB4.',
            '04421DB4 saves caller lowID at SP+70 and level into r7, then04421DD0 calls044B10E4 with r1=lowID/r2=level.',
            'After reader and underlying metadata association succeed,04421E04 stores descriptor+4=lowID,04421E08 stores descriptor+8=0x24,04421E10 stores descriptor+9=(level+2)|packed_flags.',
            'Original descriptor getter044B2976 extracts descriptor+9 low6bits then subtracts2, loads descriptor+4, and044B2988 calls the same reader.',
        ],
        'record_info_boundary': 'FTS record_info>>8 is used by original SQL string fragments to select japan_addr_info.id; the returned japan_addr_info.record is the separate packed logical key split here. These integers are not interchangeable.',
        'descriptor_contract': {'type_byte_plus8': '0x24', 'record_word_plus4': 'one-based low28 ID',
                                'level_byte_plus9_low6': 'level+2; getter masks0x3F and subtracts2',
                                'upper_flag_bits': 'derived from packed reader output flags; semantics unclaimed'},
        'actual_partial_CPU_cases': cases,
        'totals': {'actual_underlying_DB_scalar_reads': len(scalars), 'partial_cases': len(cases),
                   'original_instructions': sum(len(x['actual_instructions']) for x in cases),
                   'CPU_stores': sum(len(x['actual_CPU_stores']) for x in cases),
                   'full_function_returns': 0, 'packed_body_reads': 0,
                   'exact_static_opcode_guards': len(guards)},
        'scope': {'native_key_split_and_argument_blocks_executed': True,
                  'static_SQL_to_constructor_chain_identified': True,
                  'complete_SQL_query_executed': False, 'native_SQL_success_stubs': False,
                  'full_descriptor_constructor_executed': False, 'native_bitreader_executed': False,
                  'UI_or_keyboard_caller_verified': False, 'hardware_verified': False,
                  'AP_house184_payload_decoded': False, 'map_DB_canonical_writes': False,
                  'old_codec_family_or_reader_scopes_rerun': False},
        'limits': ['Partial CPU phases have explicit caller/storage/register fixtures and seam handoffs; no continuous complete query or constructor execution is claimed.',
                   'The actual underlying scalar reads are host readonly SQLite. No native SQL helper is forced to return these values or success.',
                   'Directory pointers are synthetic inputs, never dereferenced in these phases; execution stops before the original packed reader branch.',
                   'Static original field stores prove the key layout; successful metadata association and complete descriptor initialization remain unexecuted.',
                   'The full UI/address caller, selected map manager and native house/provider handling remain outside this proof.']}
    TARGET.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'proof': str(TARGET.relative_to(ROOT)), 'proof_sha256': digest(TARGET.read_bytes()),
                      'source_sha256': result['source_sha256'],
                      'static_fragments_sha256': result['static_fragments_sha256'],
                      'totals': result['totals'], 'all_bounded_checks_passed': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
