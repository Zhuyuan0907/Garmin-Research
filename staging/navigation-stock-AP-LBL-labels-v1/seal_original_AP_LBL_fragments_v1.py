#!/usr/bin/env python3
"""Independent FILE-only selected opcode/store/output checks; no CPU rerun."""
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_REG, ARM_OP_MEM

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
PROOF = OUT / 'original-AP-LBL-selected-labels-proof-v2.json'
SOURCE = OUT / 'probe_original_AP_LBL_fragments_v2.py'
REVIEW = OUT / 'original-AP-LBL-fragments-FILE-verification-v1.json'
SEAL = OUT / 'original-AP-LBL-fragments-file-seal-v1.json'
LEDGER = OUT / 'original-AP-LBL-fragments-source-output-ledger-v1.json'
RECEIPT = OUT / 'native-LBL-fragments-v2-terminal-tool-receipt.json'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, label):
    if not ok:
        raise ValueError(label)


def main():
    need(not any(p.exists() for p in (REVIEW, SEAL, LEDGER, RECEIPT)), 'new outputs only')
    raw = PROOF.read_bytes()
    need(sha(raw) == '844c772259a711b85ab57f04bf324e623e47ba8216fc97663c8ace26ca674157',
         'completed native v2 proof')
    proof = json.loads(raw)
    need(proof['source_sha256'] == sha(SOURCE.read_bytes()) and proof['all_bounded_checks_passed'],
         'completed source and proof all bounded checks')
    need(proof['actual_IMG_bytes_read_here'] == 0 and proof['totals']['full_function_returns'] == 0,
         'partial native scope')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    register_index = {**{'r' + str(i): i for i in range(13)}, 'sp': 13, 'lr': 14, 'pc': 15}
    register_index['sb'], register_index['sl'], register_index['fp'], register_index['ip'] = 9, 10, 11, 12
    source_count, store_count, output_count = 0, 0, 0
    source_pages = {}
    with MAIN.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
        def code(pc, length):
            load = pc - 57525300 if 0x04400000 <= pc < 0x0470CE18 else pc
            need(0x50000 <= load and load + length <= 0x50000 + len(image), 'bounded original code read')
            return bytes(image[load - 0x50000:load - 0x50000 + length])
        runs = [proof['actual_partial_parser_CPU']] + [x['actual_partial_CPU'] for x in proof['selected_labels']]
        for run in runs:
            trace_lookup = set()
            for row in run['instructions']:
                pc, opcode = int(row['pc'], 16), bytes.fromhex(row['opcode_hex'])
                need(opcode == code(pc, len(opcode)), 'actual trace opcode equals exact MAIN bytes')
                state = row['before']
                need(len(state['GP16']) == 16 and state['GP16'][15] == pc, 'actual instruction snapshot PC/GP16')
                trace_lookup.add((pc, tuple(state['GP16']), state['CPSR']))
                source_count += 1
            output = bytearray(b'\xA5' * 128)
            for store in run['CPU_stores']:
                pc = int(store['pc'], 16)
                state = store['before']
                need((pc, tuple(state['GP16']), state['CPSR']) in trace_lookup,
                     'actual store state equals original pre-instruction snapshot')
                insn = next(md.disasm(code(pc, 4), pc))
                size = {'str': 4, 'strh': 2, 'strb': 1}.get(insn.mnemonic)
                need(size == store['bytes'] and insn.operands[0].type == ARM_OP_REG and
                     insn.operands[1].type == ARM_OP_MEM and not insn.writeback,
                     'selected original simple STR/STRH/STRB opcode')
                mem = insn.operands[1].mem
                reg_value = lambda reg: state['GP16'][register_index[insn.reg_name(reg)]]
                effective = (reg_value(mem.base) + mem.disp + (reg_value(mem.index) if mem.index else 0)) & 0xFFFFFFFF
                value = reg_value(insn.operands[0].reg) & ((1 << (8 * size)) - 1)
                need(effective == int(store['address'], 16) and value == store['value'],
                     'independent actual CPU store EA/value calculation')
                if 0x09003000 <= effective < 0x09003080:
                    pos = effective - 0x09003000
                    need(bytes(output[pos:pos + size]).hex() == store['preimage_hex'],
                         'selected output CPU-store preimage chain')
                    output[pos:pos + size] = value.to_bytes(size, 'little')
                    output_count += 1
                store_count += 1
            need(all(not x['full_function_return'] for x in run['phases']), 'partial endpoints only')
            if 'actual_original_output_hex' in run:
                actual = bytes.fromhex(run['actual_original_output_hex'])
                need(bytes(output[:len(actual)]) == actual and run['actual_byte_copy_and_termination_passed'] and
                     run['actual_native_byte_counter_includes_first_NUL'] == len(actual) - 1 and
                     actual.endswith(b'\0\0'), 'actual output bytes independent store reconstruction/double NUL')
                base, count = 0x044C0000, 0x2000
                baseline = run['original_RX_8192_sha256']
                need(run['phases'][-1]['after']['GP16'][15] == 0x044C1088, 'actual DBCS partial endpoint')
            else:
                base, count = 0x002CF000, 0x1000
                baseline = run['original_RX_4096_sha256']
                need(run['phases'][-1]['after']['GP16'][15] == 0x002CF842, 'actual parser partial endpoint')
            source_pages.setdefault(hex(base), sha(code(base, count)))
            need(baseline == source_pages[hex(base)] == run['actual_final_RX_sha256'],
                 'actual serialized final RX readback equals exact original page digest')
    need(source_count == 1067 and store_count == 87, 'frozen actual totals')
    now = datetime.now(timezone.utc).isoformat()
    REVIEW.write_text(json.dumps({'schema': 'original-AP-LBL-fragments-FILE-verification/v1',
        'created_utc': now, 'all_selected_FILE_checks_passed': True, 'FILE_ONLY': True,
        'original_instruction_opcode_checks': source_count, 'independent_CPU_store_EA_value_checks': store_count,
        'output_store_preimage_and_reconstruction_checks': output_count,
        'exact_small_MAIN_RX_page_hashes': source_pages,
        'selected_outputs': [{'reference': x['actual_partial_CPU']['reference'],
             'actual_GMP_offset': x['actual_partial_CPU']['actual_GMP_offset'],
             'actual_native_output_hex': x['actual_partial_CPU']['actual_original_output_hex'],
             'host_CP950_display': x['actual_partial_CPU']['host_CP950_display_of_actual_native_output']}
             for x in proof['selected_labels']],
        'complete_instruction_semantic_replay': False, 'complete_registry_getter_SQL_UI': False,
        'child184_label_verified': False, 'new_CPU_or_IMG_or_device_execution': False,
        'whole_MAIN_MAP_backup_or_old_suite_digest_repeated': False,
        'scope': 'Exact opcodes/pre-GP store EA/value, selected output preimage chain/reconstruction, partial endpoint GP16, original/final RX digests only.'},
        ensure_ascii=False, indent=2) + '\n')
    RECEIPT.write_text(json.dumps({'schema': 'actual-terminal-tool-receipt/native-LBL-fragments/v2',
        'created_utc': now, 'terminal': True, 'actual_exit_code': 0, 'actual_completion_chunk_id': 'a91c47',
        'session_id': None, 'command': 'python3 staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
        'source': str(SOURCE.relative_to(ROOT)), 'source_sha256': sha(SOURCE.read_bytes()),
        'proof': str(PROOF.relative_to(ROOT)), 'proof_sha256': sha(PROOF.read_bytes()),
        'scope': 'Partial original parser/address/DBCS fragments using actual frozen peer source bytes; no IMG reads or complete getter/query.'},
        ensure_ascii=False, indent=2) + '\n')
    files = [SOURCE, Path(__file__), PROOF, REVIEW, RECEIPT,
             OUT / 'read_AP_LBL_labels_v1.py', OUT / 'native-LBL-fragments-v1-terminal-failure-receipt.json']
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in files}
    LEDGER.write_text(json.dumps({'schema': 'original-AP-LBL-fragments-source-output-ledger/v1',
        'created_utc': now, 'source_sha256': {k: v for k, v in hashes.items() if k.endswith('.py')},
        'output_sha256': {k: v for k, v in hashes.items() if not k.endswith('.py')},
        'source_dependencies': proof['dependencies'],
        'no_old_full_hash_or_suite_rerun': True}, ensure_ascii=False, indent=2) + '\n')
    SEAL.write_text(json.dumps({'schema': 'original-AP-LBL-fragments-file-seal/v1', 'created_utc': now,
        'all_selected_FILE_checks_passed': True, 'files': hashes,
        'ledger': str(LEDGER.relative_to(ROOT)), 'ledger_sha256': sha(LEDGER.read_bytes()),
        'FILE_scope': 'Selected opcode/store/output readback, no CPU rerun.',
        'native_scope': proof['totals'], 'complete_registry_getter_SQL_UI': False,
        'child184_label_verified': False, 'device_or_canonical_writes': False},
        ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(SEAL.relative_to(ROOT)), 'seal_sha256': sha(SEAL.read_bytes()),
        'review_sha256': sha(REVIEW.read_bytes()), 'ledger_sha256': sha(LEDGER.read_bytes()),
        'actual_probe_receipt_sha256': sha(RECEIPT.read_bytes()),
        'probe_source_sha256': sha(SOURCE.read_bytes()), 'sealer_source_sha256': sha(Path(__file__).read_bytes()),
        'original_opcode_checks': source_count, 'CPU_store_EA_value_checks': store_count,
        'output_store_checks': output_count}, ensure_ascii=False))


if __name__ == '__main__':
    main()
