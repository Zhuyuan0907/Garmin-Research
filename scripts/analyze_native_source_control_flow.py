#!/usr/bin/env python3
"""Exact central request table and output callback distinction; static only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_output_driver import instructions


def main():
    stock = NativeImage()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    pre = list(md.disasm(stock.read(0x3b9fb0, 12), 0x3b9fb0))
    assert [(i.address, i.mnemonic) for i in pre] == [
        (0x3b9fb0, 'cmp'), (0x3b9fb2, 'bhs'), (0x3b9fb4, 'adr'),
        (0x3b9fb6, 'ldrb'), (0x3b9fb8, 'adds'), (0x3b9fba, 'add')]
    assert pre[0].operands[1].imm == 13 and pre[-1].op_str == 'pc, r3'
    table_address, pc_base = 0x3b9fbc, 0x3b9fbe
    # The branch base is ADD-PC's address+4, not the ADR table address.
    table = stock.read(table_address, 13)
    expected = {1: 0x3b9c5e, 2: 0x3b9d82, 3: 0x3b96d8, 4: 0x3b9d62,
                5: 0x3b9d0e, 6: 0x3b972a, 7: 0x3b9dfc, 8: 0x3b9dc2, 10: 0x3b9958}
    cases = []
    for opcode, offset in enumerate(table):
        target = pc_base+2*offset
        code = list(md.disasm(stock.read(target, 14), target))
        calls = [i.operands[0].imm for i in code if i.mnemonic == 'bl' and
                 i.operands[0].type == ARM_OP_IMM]
        if opcode in expected:
            assert expected[opcode] in calls
        else:
            assert target == 0x3ba024 and 0x3b96b8 in calls
        cases.append({'opcode': opcode, 'dispatch_target': hex(target),
                      'calls_first14_bytes': [hex(p) for p in calls],
                      'instructions': instructions(stock, target, 14)})
    allocation_return = list(md.disasm(stock.read(0x1d8c58, 4), 0x1d8c58))
    assert len(allocation_return) == 1 and allocation_return[0].mnemonic == 'bl' and \
        allocation_return[0].operands[0].imm == 0x2f998e
    assert stock.read(0x2f99a4, 2) == bytes.fromhex('0e22')
    callback_post = list(md.disasm(stock.read(0x2f99be, 4), 0x2f99be))
    assert len(callback_post) == 1 and callback_post[0].mnemonic == 'bl' and \
        callback_post[0].operands[0].imm == 0x37bce4
    callback_global = stock.word(0x2f9d38)
    assert callback_global == 0x034e5378
    dependencies = ('scripts/analyze_native_sections.py', 'scripts/analyze_native_output_driver.py')
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'dependency_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in dependencies},
        'central_dispatcher': '0x3b9f84', 'table_address': hex(table_address),
        'computed_branch_pc_base': hex(pc_base), 'table_hex': table.hex(), 'cases': cases,
        'driver_outcomes11_and12_dispatch_to_ack_only': True,
        'default_ack_helper': '0x3b96b8',
        'original_output_allocation_callback': {'caller': '0x1d8c58', 'callback': '0x2f998e',
            'mixer_records_base': hex(callback_global), 'mixer_stride': 304,
            'channel_from_descriptor_first_signed_byte': True,
            'publishes_descriptor_at_mixer_offset0': True,
            'posts_start_message14_at': '0x2f99be'},
        'stop_request_case': {'opcode': 3, 'helper': '0x3b96d8',
            'issues_driver_stop_wrapper': '0x46cc36', 'moves_source_state_to5': True,
            'does_not_itself_prove_scratch_provider_list_retired': True},
        'stop_completion_case': {'opcode': 7, 'helper': '0x3b9dfc',
                                 'executed_in_this_static_inventory': False},
        'traces': {'output_callback': instructions(stock, 0x2f998e, 58),
                   'output_allocation_callback_callsite': instructions(stock, 0x1d8c42, 30),
                   'stop_request': instructions(stock, 0x3b96d8, 82)},
        'all_checks_passed': True, 'static_only': True, 'device_io': False,
        'device_install_candidate': False,
        'limitations': 'Exact HWID1352/software8.00 static instructions. Central opcodes11/12 share the default synchronous acknowledgment case; they are not per-channel mixer START14. Original allocation helper1D8B74 calls2F998E, which publishes the descriptor and posts14. Runtime input validation, valid task/descriptor lifetime, real allocator/format/arbitration/DAC/resampler/DMA/end/drain and production callbacks still require execution. Stop3/state5 and completion7 identified, not a verified automatic cleanup/next-source lifecycle. No real module/UI/SEP/phone/speaker/navigation/Google Maps or install candidate.'}
    p = ROOT/'evidence/firmware-analysis/native-source-control-flow.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_checks_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
