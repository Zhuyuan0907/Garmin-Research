#!/usr/bin/env python3
"""Frozen peer AP LBL byte input and original parser/address/DBCS fragments.

No IMG reads, complete registry/getter/SQL/UI execution, guessed reader success,
unlocks, old proofs replay, or full MAIN digest or copies.
"""
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
PROOF = OUT / 'original-AP-LBL-selected-labels-proof-v1.json'
PEER_PROOF = 'staging/navigation-AP-LBL-target-strings-v1/AP-target-label-windows-evidence.json'
PEER_SHA256 = '2ed1ad21962955ade1f9cd2b84bfdc02604930f4d0dc7aacb34b72d2b508f414'
GP = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC]
CTX, INPUT, OUTPUT, SP = 0x09001000, 0x09002000, 0x09003000, 0x0900E000


def need(ok, label):
    if not ok:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def snapshot(u):
    return {'GP16': [u.reg_read(r) for r in GP], 'CPSR': u.reg_read(UC_ARM_REG_CPSR)}


def parser_case(read, header):
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM_1176)
    code = read(0x002CF000, 0x1000)
    u.mem_map(0x002CF000, 0x1000)
    u.mem_write(0x002CF000, code)
    u.mem_protect(0x002CF000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    u.mem_map(0x09000000, 0x10000)
    instructions, stores, stop = [], [], [None]
    def observe(uc, pc, size, unused):
        if pc == stop[0]:
            uc.emu_stop()
            return
        need(0x002CF000 <= pc < 0x002D0000, 'original parser field-store only')
        instructions.append({'pc': hex(pc), 'opcode_hex': bytes(uc.mem_read(pc, size)).hex(),
                             'before': snapshot(uc)})
    def store(uc, access, address, size, value, unused):
        stores.append({'pc': hex(uc.reg_read(UC_ARM_REG_PC)), 'address': hex(address),
                       'bytes': size, 'value': value, 'before': snapshot(uc),
                       'preimage_hex': bytes(uc.mem_read(address, size)).hex()})
    u.hook_add(UC_HOOK_CODE, observe)
    u.hook_add(UC_HOOK_MEM_WRITE, store)
    u.reg_write(UC_ARM_REG_CPSR, 0x3F)
    u.reg_write(UC_ARM_REG_SP, SP)
    u.reg_write(UC_ARM_REG_R7, CTX + 0x340)
    u.mem_write(SP + 0x14, header[21:31])
    before = snapshot(u)
    stop[0] = 0x002CF45C
    u.emu_start(0x002CF44A | 1, stop[0] + 2, count=100, timeout=100000)
    after = snapshot(u)
    u.mem_write(SP + 0x14, header[170:192])
    second_before = snapshot(u)
    stop[0] = 0x002CF842
    u.emu_start(0x002CF83C | 1, stop[0] + 2, count=100, timeout=100000)
    second_after = snapshot(u)
    need(after['GP16'][15] == 0x002CF45C and second_after['GP16'][15] == 0x002CF842,
         'actual parser fragment endpoints')
    fields = {'LBL_header_GMP_offset': 874,
              'label_start': struct.unpack('<I', bytes(u.mem_read(CTX + 0x364, 4)))[0],
              'label_size': struct.unpack('<I', bytes(u.mem_read(CTX + 0x368, 4)))[0],
              'shift': bytes(u.mem_read(CTX + 0x345, 1))[0],
              'encoding': bytes(u.mem_read(CTX + 0x346, 1))[0],
              'codepage': struct.unpack('<H', bytes(u.mem_read(CTX + 0x34C, 2)))[0]}
    fields['multiplier'] = 1 << fields['shift']
    need((fields['label_start'], fields['label_size'], fields['shift'], fields['encoding'], fields['codepage']) ==
         (6566, 3805432, 3, 10, 950), 'actual original parser metadata stores from peer header')
    need(bytes(u.mem_read(0x002CF000, 0x1000)) == code, 'actual parser RX readback unchanged')
    return {'actual_metadata_fields': fields, 'instructions': instructions, 'CPU_stores': stores,
            'phases': [{'entry': '0x002CF44A', 'stop_before': '0x002CF45C', 'before': before,
                        'after': after, 'full_function_return': False},
                       {'entry': '0x002CF83C', 'stop_before': '0x002CF842', 'before': second_before,
                        'after': second_after, 'full_function_return': False}],
            'original_RX_4096_sha256': sha(code), 'actual_final_RX_sha256': sha(bytes(u.mem_read(0x002CF000, 0x1000))),
            'fixture_scope': 'Actual peer header+21/10bytes and header+170/22bytes staged as explicit parser input; synthetic stack/output object; complete seek/read/parser not executed.'}


def fragment_case(read, reference, fields, window):
    """Two original partial blocks; all seams/storage are explicit inputs."""
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM_1176)
    code = read(0x044C0000, 0x2000)
    u.mem_map(0x044C0000, 0x2000)
    u.mem_write(0x044C0000, code)
    u.mem_protect(0x044C0000, 0x2000, UC_PROT_READ | UC_PROT_EXEC)
    u.mem_map(0x09000000, 0x10000)
    for off, raw in ((0x340 + 5, bytes([fields['shift']])),
                     (0x340 + 6, bytes([fields['encoding']])),
                     (0x340 + 12, struct.pack('<H', fields['codepage'])),
                     (0x340 + 0x24, struct.pack('<2I', fields['label_start'], fields['label_size']))):
        u.mem_write(CTX + off, raw)
    u.mem_write(SP + 0x64, struct.pack('<I', CTX))
    u.mem_write(SP + 0x60, struct.pack('<I', CTX + 0x340))
    instructions, stores, stop = [], [], [None]
    def observe(uc, pc, size, unused):
        if pc == stop[0]:
            uc.emu_stop()
            return
        need(0x044C0000 <= pc < 0x044C2000, 'declared original fragment only')
        instructions.append({'pc': hex(pc), 'opcode_hex': bytes(uc.mem_read(pc, size)).hex(),
                             'before': snapshot(uc)})
    def store(uc, access, address, size, value, unused):
        stores.append({'pc': hex(uc.reg_read(UC_ARM_REG_PC)), 'address': hex(address),
                       'bytes': size, 'value': value, 'before': snapshot(uc),
                       'preimage_hex': bytes(uc.mem_read(address, size)).hex()})
    u.hook_add(UC_HOOK_CODE, observe)
    u.hook_add(UC_HOOK_MEM_WRITE, store)
    u.reg_write(UC_ARM_REG_CPSR, 0x3F)
    for reg, value in ((UC_ARM_REG_SP, SP), (UC_ARM_REG_R0, reference),
                       (UC_ARM_REG_R1, reference), (UC_ARM_REG_R3, 0x340),
                       (UC_ARM_REG_R4, 0)):
        u.reg_write(reg, value)
    before = snapshot(u)
    stop[0] = 0x044C0F08
    u.emu_start(0x044C0ED6 | 1, stop[0] + 2, count=100, timeout=100000)
    address_after = snapshot(u)
    actual_offset = struct.unpack('<I', bytes(u.mem_read(SP + 0x48, 4)))[0]
    need(actual_offset == fields['label_start'] + (reference << fields['shift']) and
         u.reg_read(UC_ARM_REG_R4) == 0, 'actual original address calculation and bounds')
    split_index = len(instructions)
    # Enter original encoding-10 byte loop with a real bounded source window;
    # this is explicit staged input, not a successful file-I/O helper stub.
    u.mem_write(INPUT, window)
    u.mem_write(OUTPUT, b'\xA5' * 128)
    for off, value in ((0x20, INPUT), (0x24, len(window)), (0x34, 0),
                       (0x54, 0), (0x58, 0), (0x5C, 127), (0x50, 0)):
        u.mem_write(SP + off, struct.pack('<I', value))
    for reg, value in ((UC_ARM_REG_SP, SP), (UC_ARM_REG_R5, OUTPUT),
                       (UC_ARM_REG_R6, 0), (UC_ARM_REG_R7, 0)):
        u.reg_write(reg, value)
    u.reg_write(UC_ARM_REG_CPSR, 0x3F)
    copy_before = snapshot(u)
    stop[0] = 0x044C1088
    u.emu_start(0x044C10AC | 1, stop[0] + 2, count=2000, timeout=100000)
    copy_after = snapshot(u)
    count = u.reg_read(UC_ARM_REG_R6)
    output = bytes(u.mem_read(OUTPUT, count + 1))
    need(output.endswith(b'\0') and output == window.split(b'\0', 1)[0] + b'\0',
         'actual original encoding10 CP950 byte copy and NUL')
    need(copy_after['GP16'][15] == stop[0], 'actual partial loop endpoint')
    need(bytes(u.mem_read(0x044C0000, 0x2000)) == code, 'actual original label RX readback unchanged')
    return {'reference': reference, 'actual_GMP_offset': actual_offset,
            'actual_original_output_hex': output.hex(),
            'host_CP950_display_of_actual_native_output': output[:-1].decode('cp950', errors='strict'),
            'phases': [{'entry': '0x044C0ED6', 'stop_before': '0x044C0F08', 'before': before,
                        'after': address_after, 'full_function_return': False},
                       {'entry': '0x044C10AC', 'stop_before': '0x044C1088', 'before': copy_before,
                        'after': copy_after, 'full_function_return': False}],
            'instructions': instructions, 'address_phase_instructions': split_index,
            'CPU_stores': stores, 'original_RX_8192_sha256': sha(code),
            'actual_final_RX_sha256': sha(bytes(u.mem_read(0x044C0000, 0x2000))),
            'fixture_scope': 'Synthetic stack/output/metadata storage; metadata values from actual LBL header, actual bounded window staged before original CP950 byte loop; no I/O return hook.'}


def main():
    need(not PROOF.exists(), 'new output only')
    dependency_paths = [
        ('staging/navigation-native-AP-text-reference-v1/original-text-reference-consumer-proof-v1.json',
         '64087eb40410d38f630c8da85b0e8377bd1e67c643d1c8f7112d83b00da5b480'),
        ('staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json',
         '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753'),
        ('staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json',
         'dd14408a357d5587d8a4c4d72f4eb3f70b21296c1022bc95e35ad6afba606a7e'),
    ]
    deps = []
    for path, expected in dependency_paths:
        raw = (ROOT / path).read_bytes()
        need(sha(raw) == expected, 'frozen selected dependency ' + path)
        deps.append({'path': path, 'sha256': sha(raw), 'old_scope_not_replayed': True})
    need(PEER_PROOF is not None and PEER_SHA256 is not None, 'sealed source peer input required')
    peer_raw = (ROOT / PEER_PROOF).read_bytes()
    need(sha(peer_raw) == PEER_SHA256, 'frozen peer LBL source dependency')
    peer = json.loads(peer_raw)
    deps.append({'path': PEER_PROOF, 'sha256': PEER_SHA256,
                 'old_scope_not_replayed': True, 'actual_source_IMG_read_by_peer_only': True})
    textproof = json.loads((ROOT / dependency_paths[0][0]).read_text())
    cases = [x for x in textproof['actual_original_fragment_cases']
             if x['explicit_synthetic_context_codepage'] == 950]
    need([x['original_pregetter_call']['selected_reference'] for x in cases] == [12, 14, 206],
         'actual selected native CP950 references')
    before_main = stat(MAIN)
    fragments = []
    with MAIN.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
        def read(a, n):
            load = a - 57525300 if 0x04400000 <= a < 0x0470CE18 else a
            need(0x50000 <= load and load + n <= 0x50000 + len(image), 'exact mapped MAIN fragment')
            return bytes(image[load - 0x50000:load - 0x50000 + n])
        ranges = [(0x1AFB4E, 0x52), (0x2BF5F4, 8), (0x2CF3D0, 0xA4),
                  (0x2CF810, 0x34), (0x044C1780, 0x14), (0x044C1972, 0xC),
                  (0x044C1A3A, 4), (0x044C1B26, 0x2A), (0x044C0ED6, 0x32),
                  (0x044C0F1A, 0x14), (0x044C0F38, 0x20), (0x044C10AC, 0xF4),
                  (0x044C11A0, 0x18), (0x044C11B8, 0x14), (0x044C1084, 4)]
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        for a, n in ranges:
            raw = read(a, n)
            fragments.append({'runtime': hex(a), 'bytes': n, 'sha256': sha(raw), 'raw_hex': raw.hex(),
                'instructions': [] if a in (0x2BF5F4, 0x044C11A0) else
                [{'pc': hex(i.address), 'opcode_hex': i.bytes.hex(),
                  'instruction': i.mnemonic + ' ' + i.op_str} for i in md.disasm(raw, a)]})
        need(read(0x2BF5F4, 8).hex() == '04f01fe50f174c04', 'original veneer to 044C170F')
        table = read(0x044C1794, 8)
        # ADD PC at1792 uses PC1796, distinct from data-table start1794.
        need(0x044C1796 + table[5] * 2 == 0x044C1976 and
             read(0x044C1976, 2).hex() == '60e0', 'kind5 forwarding branch')
        encoding_table = read(0x044C1014, 7)
        need(0x044C1014 + 2 * encoding_table[4] == 0x044C10AC,
             'original encoding10 native byte loop table')
        labels = []
        record = json.loads((ROOT / dependency_paths[2][0]).read_text())['public_LBL_header']
        header = bytes.fromhex(record['hex'])
        need(sha(header) == record['sha256'] and struct.unpack_from('<H', header)[0] == 661 and
             header[2:12] == b'GARMIN LBL' and header[13] == 0, 'frozen actual AP LBL header')
        parser = parser_case(read, header)
        fields = parser['actual_metadata_fields']
        start, size = fields['label_start'], fields['label_size']
        need(874 + 661 <= start < start + size <= 3812824, 'actual absolute GMP label extent')
        for case in cases:
            ref = case['original_pregetter_call']['selected_reference'] & 0x003FFFFF
            offset = start + (ref << fields['shift'])
            witness = next(x for x in peer['cases'] if x['selected_reference'] == ref)
            window = bytes.fromhex(witness['hex'])
            need(witness['GMP_logical_offset'] == offset and sha(window) == witness['sha256'] and
                 0 < len(window) <= 128 and b'\0' in window, 'actual selected bounded peer window')
            cpu = fragment_case(read, ref, fields, window)
            need(cpu['host_CP950_display_of_actual_native_output'] == witness['host_strict_CP950_display'],
                 'original partial DBCS bytes match separate actual source window display')
            labels.append({'parent_level': case['parent_explicit_level'],
                           'parent_one_based_ID': case['parent_lowID'],
                           'mapordinal': case['original_pregetter_call']['mapordinal'],
                           'LBL_byte_witness': witness, 'actual_partial_CPU': cpu})
    need(stat(MAIN) == before_main, 'original MAIN unchanged')
    out = {'schema': 'stock-AP-LBL-selected-labels/v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
           'source_sha256': sha(Path(__file__).read_bytes()), 'dependencies': deps,
           'scope': 'Frozen peer original AP GMP LBL header/three small source windows; original partial parser-field/address/CP950 byte-copy fragments, no new IMG reads.',
           'all_bounded_checks_passed': True, 'actual_LBL_header': record, 'actual_header_fields': fields,
           'actual_partial_parser_CPU': parser, 'selected_labels': labels, 'static_original_fragments': fragments,
           'static_ABI': {'kind7': '1AFC7C→1AFB3E; r1 pair=[mapordinal,reference], r2 out buffer,r3 capacity; metadata from359038 then ctx+3F4 pointer.',
                          'kind5': '2BF5F4 veneer→044C170E; r0 map object,r1 reference address,r2=5,r3 output buffer; stackarg5 capacity,arg6 flags,arg7 aux.',
                          'label_reader': '044C0E9A r0 map object,r1 reference,r2 output buffer,r3 capacity; stackarg5 flags,arg6 next-offset output,arg7 aux.',
                          'address': 'For selected nonnegative refs: GMP absolute labelStart + ((reference & 0x003FFFFF) << header[29]); bounds checked against labelStart+labelSize.',
                          'encoding': 'Header encoding10 uses original DBCS-preserving byte loop; CP950 bytes are retained, host cp950 decode supplies display only.'},
           'actual_IMG_bytes_read_here': 0, 'original_MAIN_stat_unchanged': True,
           'totals': {'selected_real_labels': len(labels),
                      'original_partial_instructions': len(parser['instructions']) + sum(len(x['actual_partial_CPU']['instructions']) for x in labels),
                      'CPU_stores': len(parser['CPU_stores']) + sum(len(x['actual_partial_CPU']['CPU_stores']) for x in labels),
                      'full_function_returns': 0},
           'full_map_registry_or_getter_or_SQL_or_UI_executed': False, 'file_IO_return_hook': False,
           'child184_label_verified': False, 'native_full_text_conversion_verified': False,
           'whole_MAP_MAIN_or_old_suite_digest_repeated': False, 'device_IO': False,
           'unlock_or_authorization_bypass': False, 'stock_MAP_or_DB_or_canonical_writes': False,
           'limits': ['Partial native cases declare synthetic frame/storage and actual-header-derived metadata input, not a complete loaded map object.',
                      'Native file seek/read, mapregistry and kind7 full getter are not executed; bounded host FAT reads supply actual bytes explicitly.',
                      'Three selected references do not establish any house184 child reference or stock updating writer.',
                      'The stock codepage display may use 台 rather than 臺; label identity here is observed bytes, not query normalization proof.']}
    PROOF.write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'proof': str(PROOF.relative_to(ROOT)), 'proof_sha256': sha(PROOF.read_bytes()),
                      'labels': [{'reference': x['actual_partial_CPU']['reference'],
                                  'GMP_offset': x['actual_partial_CPU']['actual_GMP_offset'],
                                  'text': x['actual_partial_CPU']['host_CP950_display_of_actual_native_output']} for x in labels],
                      'fields': fields, 'totals': out['totals'], 'IMG_bytes_read_here': 0},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
