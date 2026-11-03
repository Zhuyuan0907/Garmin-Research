#!/usr/bin/env python3
"""New finite execution of original stock UTF-8/token helper instructions.

Explicit synthetic caller RAM / stacks, and file-backed demand-loaded MAIN
pages. No UI, SQLite native provider, whole boot, device, or conversion hooks.
"""
import gzip
import hashlib
import json
import mmap
from pathlib import Path
import struct
from datetime import datetime, timezone
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import UC_HOOK_MEM_UNMAPPED, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
PRIOR = ROOT / 'staging/navigation-stock-fts-codec-v1/stock-fts-token-codec-proof-v1.json'
PROOF = OUT / 'native-fts-token-codec-proof-v1.json'
TRACE = OUT / 'native-fts-token-codec-trace-v1.json.gz'
ERROR = OUT / 'native-fts-token-codec-error-v1.json'
GP = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]
STACK = 0x09000000
RAM = 0x09010000
RETURN = 0x08D00000
IDENTITY = 0x06921D64
CONTEXT = 0x06921E64
DELTA = 57525300


def need(value, label):
    if not value:
        raise ValueError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    need(not any(p.exists() for p in (PROOF, TRACE, ERROR)), 'new outputs only')
    prior = json.loads(PRIOR.read_text())
    section = json.loads((ROOT / 'evidence/firmware-analysis/native-sections.json').read_text())
    native = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    native.ctl_set_cpu_model(UC_CPU_ARM_1176)
    events = []
    instructions = []
    mapped = []
    call_name = ''
    instruction_pc = 0
    native.mem_map(STACK, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    native.mem_map(RAM, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    native.mem_map(0x06921000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    native.mem_map(RETURN, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    native.mem_write(RETURN, b'\x00\xbf')
    handle = MAIN.open('rb')
    image = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)

    def snapshot():
        return {'gp16': [native.reg_read(reg) for reg in GP],
                'CPSR': native.reg_read(UC_ARM_REG_CPSR)}

    def backing(address):
        matches = [row for row in section['copies']
                   if row['runtime_start'] <= address < row['runtime_end']]
        need(len(matches) == 1, 'file-backed address ' + hex(address))
        row = matches[0]
        return row['load_start'] + address - row['runtime_start']

    def load_page(_uc, access, address, size, value, _data):
        page = address & ~0xFFF
        offset = backing(page) - 0x50000
        need(0 <= offset and offset + 4096 <= len(image), 'exact source page bounds')
        native.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        raw = bytes(image[offset:offset + 4096])
        native.mem_write(page, raw)
        mapped.append({'runtime_page': hex(page), 'load_page': hex(offset + 0x50000),
                       'sha256': sha(raw), 'bytes': 4096})
        return True

    def observe(_uc, address, size, _data):
        nonlocal instruction_pc
        instruction_pc = address
        instructions.append({'call': call_name, 'pc': address, 'size': size,
                             'opcode_hex': bytes(native.mem_read(address, size)).hex(),
                             'CPSR': native.reg_read(UC_ARM_REG_CPSR)})

    def store(_uc, access, address, size, value, _data):
        events.append({'call': call_name, 'instruction_pc': instruction_pc,
                       'address': address, 'size': size,
                       'value': value & ((1 << (size * 8)) - 1),
                       'before_hex': bytes(native.mem_read(address, size)).hex(),
                       'gp16': [native.reg_read(reg) for reg in GP],
                       'CPSR': native.reg_read(UC_ARM_REG_CPSR)})

    native.hook_add(UC_HOOK_MEM_UNMAPPED, load_page)
    native.hook_add(UC_HOOK_CODE, observe)
    native.hook_add(UC_HOOK_MEM_WRITE, store)
    endpoints = []
    fixture_writes = []

    def fixture(address, data, purpose):
        before = bytes(native.mem_read(address, len(data)))
        native.mem_write(address, data)
        fixture_writes.append({'address': address, 'bytes': len(data),
                               'before_hex': before.hex(), 'after_hex': data.hex(),
                               'purpose': purpose})

    def call(name, entry, arguments=(), end=RETURN, full_return=True, extra_regs=None):
        nonlocal call_name
        call_name = name
        # Every call has its own explicit caller context. No suspended native
        # task/context_restore, original boot, or concurrent callbacks claimed.
        native.reg_write(UC_ARM_REG_CPSR, 0x3F)
        for i, reg in enumerate(GP[:13]):
            native.reg_write(reg, 0x11000000 + i * 0x1111)
        native.reg_write(UC_ARM_REG_SP, STACK + 0xFF00)
        native.reg_write(UC_ARM_REG_LR, RETURN | 1)
        for i, value in enumerate(arguments):
            native.reg_write(GP[i], value)
        for reg, value in (extra_regs or {}).items():
            native.reg_write(reg, value)
        before = snapshot()
        start_instructions, start_stores = len(instructions), len(events)
        native.emu_start(entry | 1, end, timeout=10_000_000, count=150_000)
        after = snapshot()
        need(after['gp16'][15] == end, name + ' actual endpoint')
        if full_return:
            need(after['gp16'][4:12] == before['gp16'][4:12], name + ' callee-saved')
            need(after['gp16'][13] == before['gp16'][13], name + ' original SP return')
        row = {'name': name, 'entry': hex(entry), 'end': hex(end),
               'full_original_function_return': full_return,
               'before': before, 'after': after,
               'instructions': len(instructions) - start_instructions,
               'CPU_stores': len(events) - start_stores}
        endpoints.append(row)
        return after['gp16'][0]

    try:
        # Original initializer suffix, only the identity/key-copy loop. The
        # prior SQLite object initialization/status is an explicit caller input.
        # Stop before the actual KSA call, then invoke that original helper with
        # the key buffer and identity table produced by these instructions.
        call('original_initializer_key_identity_suffix', 0x4425B64, (0,),
             end=0x4425B7E, full_return=False)
        key_buffer = STACK + 0xFF04
        need(bytes(native.mem_read(IDENTITY, 256)) == bytes(range(256)),
             'original identity table CPU writes')
        key128 = bytes(image[0xEA1258 - 0x50000:0xEA1258 - 0x50000 + 128])
        need(bytes(native.mem_read(key_buffer, 256)) == key128 * 2,
             'original repeated fixed key CPU writes')
        need(call('original_key_schedule', 0x4425AE8, (key_buffer, CONTEXT)) == 0,
             'original KSA full return')
        scheduled = bytes(native.mem_read(CONTEXT, 258))
        need(scheduled[-2:] == b'\0\0', 'original context index bytes')

        # UTF-8 scalar iteration and conversion run original MAIN functions via
        # their real code. No conversion/copy/strlen/iterator hook or replacement.
        names = ['台中市', '民權路', '中區']
        real_tokens = {row['decoded_text']: row['index_record']
                       for row in prior['city_witnesses']}
        for query in prior['bounded_FTS8_host_controls']:
            for witness in query['witnesses']:
                real_tokens[witness['source_info_decoded_text']] = witness['source_info_index_record']
        family = json.loads((ROOT / 'staging/navigation-stock-fts-codec-v1/stock-taichung-FTS-family-links-v2.json').read_text())
        for row in family['district_interval']['districts']:
            real_tokens[row['decoded_text']] = row['index_record']
        cases = []
        for name_index, name in enumerate(names):
            source = RAM + 0x1000 + name_index * 0x100
            iterator = RAM + 0x2000 + name_index * 0x100
            raw_name = name.encode('utf-8')
            fixture(source, raw_name + b'\0', 'explicit caller UTF-8 name from selected stock plaintext')
            fixture(iterator, bytes(32), 'explicit caller iterator storage')
            call(name + '/original_UTF8_iterator_initialize', 0x2114FC,
                 (source, 0, 65001, iterator))
            initial_iterator = bytes(native.mem_read(iterator, 24))
            need(struct.unpack('<H', initial_iterator[20:22])[0] == 65001,
                 'original iterator stores actual CP65001')
            units = []
            generated = ''
            for char_index, character in enumerate(name):
                expected_bytes = character.encode('utf-8')
                record = bytes(native.mem_read(iterator, 24))
                position = struct.unpack('<I', record[12:16])[0]
                width = struct.unpack('<I', record[16:20])[0]
                raw_current = call(name + f'/char{char_index}/original_current_unit',
                                   0x2114A6, (iterator,))
                converted = call(name + f'/char{char_index}/original_UTF8_unit_convert',
                                 0x2118D2, (raw_current, 65001))
                actual_bytes = struct.pack('<I', converted)[:width]
                need(actual_bytes == expected_bytes, 'actual original UTF-8 converted Chinese unit')
                need(bytes(native.mem_read(position, width)) == expected_bytes,
                     'original iterator actual byte boundary')
                unit_buffer = RAM + 0x3000 + char_index * 0x100
                fixture(unit_buffer, actual_bytes + bytes(16 - len(actual_bytes)),
                        'caller copies actual original converter return bytes into encoder buffer')
                need(call(name + f'/char{char_index}/original_token_encode',
                          0x442545A, (unit_buffer, width)) == 0, 'original byte encoder return')
                token = bytes(native.mem_read(unit_buffer, 2 * width + 1)).decode('ascii')
                need(bytes(native.mem_read(CONTEXT, 258)) == scheduled,
                     'encoder copies and preserves shared scheduled context')
                generated += token
                length_word = RAM + 0x4000
                fixture(length_word, bytes(4), 'explicit caller decoded length output word')
                need(call(name + f'/char{char_index}/original_token_decode',
                          0x4424356, (unit_buffer, length_word)) == 0,
                     'original byte decoder return')
                length = struct.unpack('<I', bytes(native.mem_read(length_word, 4)))[0]
                decoded_bytes = bytes(native.mem_read(unit_buffer, length))
                need(length == width and decoded_bytes == actual_bytes,
                     'actual original token decoder bytes equal converter bytes')
                need(bytes(native.mem_read(CONTEXT, 258)) == scheduled,
                     'decoder preserves shared scheduled context')
                units.append({'character': character, 'width': width, 'position': position,
                              'original_current_r0': raw_current,
                              'original_converter_r0': converted,
                              'actual_input_hex': actual_bytes.hex(), 'actual_token': token,
                              'actual_decoded_hex': decoded_bytes.hex(),
                              'original_iterator_before': record.hex()})
                call(name + f'/char{char_index}/original_iterator_next',
                     0x2112E0, (iterator,))
            need(generated == real_tokens[name], 'actual original encoder matches selected DB token')
            need(call(name + '/original_final_current_unit', 0x2114A6, (iterator,)) == 0,
                 'actual original iterator exhausted')
            cases.append({'name': name, 'actual_generated_token': generated,
                          'frozen_DB_token': real_tokens[name], 'all_passed': True,
                          'initial_iterator': initial_iterator.hex(), 'units': units})
        trace = {'schema': 'native-fts-token-codec-trace/v1',
                 'explicit_fixture_writes': fixture_writes, 'original_instructions': instructions,
                 'actual_CPU_stores': events, 'actual_terminal_snapshots': endpoints,
                 'file_backed_pages': mapped}
        with gzip.open(TRACE, 'wt', encoding='utf-8') as stream:
            json.dump(trace, stream, ensure_ascii=False, separators=(',', ':'))
        payload = {
            'schema': 'native-fts-token-codec-proof/v1',
            'created_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True,
            'source_sha256': sha(Path(__file__).read_bytes()),
            'trace': str(TRACE.relative_to(ROOT)), 'trace_sha256': sha(TRACE.read_bytes()),
            'scope': {'isolated_original_ARM1176_CPU_execution': True,
                      'native_byte_encoder_decoder': True,
                      'native_UTF8_iterator_and_converter': True,
                      'conversion_hooks': False, 'copy_or_string_hooks': False,
                      'provider_SQLite_constructor_full_return': False,
                      'full_text_encoder_044254C0_return': False,
                      'UI_address_query_caller_verified': False,
                      'native_family_consumer_verified': False,
                      'native_AP_house184_payload': False,
                      'physical_device_or_MAP_DB_writes': False,
                      'whole_old_MAIN_backup_rehash': False,
                      'prior_city_FTS_family_suite_rerun': False},
            'declared_inputs': {
                'MAIN': str(MAIN.relative_to(ROOT)),
                'MAIN_sha256_inherited': section['stock_sha256'],
                'conditional_startup_copy_mapping': 'explicit file-backed runtime code input; live hardware startup flag unobserved',
                'caller_RAM_stack_and_context_storage': 'synthetic mapped storage, not original boot or native heap allocation',
                'initializer_suffix_r0': '0, declared successful prior-object status for key loop; prior SQLite constructor not executed',
                'character_handoff': 'host test caller copies actual original UTF-8 converter result into mutable byte encoder buffer',
                'selected_stock_token_reference': str(PRIOR.relative_to(ROOT))},
            'input_contract': {
                'byte_encoder': '0x0442545A: r0 mutable byte buffer, r1 byte length; caller capacity at least2*len+2, context0x06921E64 initialized',
                'byte_decoder': '0x04424356: r0 mutable token string, r1 output length word',
                'text_encoder_static_CP_literal': {'runtime': '0x044258F0', 'value': 65001},
                'original_iterator': '0x2114FC: r0 input bytes,r1=0 nul-terminated,r2=65001,r3 iterator storage',
                'original_converter': '0x2118D2: raw current unit r0, encoding65001 r1; selected Chinese output bytes match selected plaintext',
                'query_input_normalization_remaining': 'selected Chinese UTF-8 helper path proved; complete address query caller/keyboard preprocessing and Latin normalization not proved'},
            'totals': {'cases': len(cases), 'characters': sum(len(row['units']) for row in cases),
                       'original_instructions': len(instructions), 'CPU_stores': len(events),
                       'full_original_helper_returns': sum(row['full_original_function_return'] for row in endpoints),
                       'partial_initializer_suffixes': 1, 'file_backed_pages': len(mapped)},
            'cases': cases, 'scheduled_context_sha256': sha(scheduled),
            'final_context_hex': scheduled.hex(), 'terminal_snapshots': endpoints,
            'limits': ['No full 0x044254C0 allocator/text-encoder execution or complete SQLite/provider initialization.',
                       'No original UI/address caller, native house lookup, physical Garmin query, stock map update writer, or firmware installation.',
                       'Store trace is actual emulator CPU observations; this task does not claim an independent complete instruction/store replay verifier.']}
        PROOF.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'proof': str(PROOF.relative_to(ROOT)), 'proof_sha256': sha(PROOF.read_bytes()),
                          'source_sha256': payload['source_sha256'], 'trace_sha256': payload['trace_sha256'],
                          'totals': payload['totals'], 'all_passed': True}, ensure_ascii=False))
    except Exception as exc:
        failure = {'schema': 'native-fts-token-codec-error/v1',
                   'created_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': False,
                   'source_sha256': sha(Path(__file__).read_bytes()), 'error': repr(exc),
                   'call': call_name, 'instruction_pc': hex(instruction_pc),
                   'snapshot': snapshot(), 'original_instructions': instructions,
                   'CPU_stores': events, 'fixture_writes': fixture_writes,
                   'endpoints': endpoints, 'file_backed_pages': mapped}
        ERROR.write_text(json.dumps(failure, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'error': str(ERROR.relative_to(ROOT)), 'sha256': sha(ERROR.read_bytes()),
                          'exception': repr(exc), 'call': call_name, 'all_passed': False}, ensure_ascii=False))
        raise
    finally:
        image.close()
        handle.close()


if __name__ == '__main__':
    main()
