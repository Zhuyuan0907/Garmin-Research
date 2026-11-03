#!/usr/bin/env python3
"""Backup-only exact GUI worker construction and condition-notification CFGs.

This adds a new static proof namespace. It does not run a loader/emulator,
replace frozen evidence, infer zero-BSS contents, or perform device I/O.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct

from capstone.arm import (ARM_CC_AL, ARM_INS_B, ARM_INS_BL, ARM_INS_BLX,
                          ARM_INS_BX, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC)
from analyze_native_sections import ROOT, NativeImage, EXPECTED


class FileBackedRuntimeImage:
    def __init__(self, stock):
        self.stock = stock
        self.md = stock.md

    def read(self, address, length):
        return self.stock.read(self.stock.runtime_to_load(address, length), length)

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def thumb_cfg(image, entry, segments, popped_lr_tail=None, included_tail=None):
    """Follow local branches only; calls are recorded, never executed."""
    pending = deque([entry])
    seen, returns, indirect_calls, external = {}, [], [], []
    while pending:
        address = pending.popleft()
        if address in seen:
            continue
        if included_tail is not None and address == included_tail:
            external.append(dict(target=hex(address), resolved_to_included_CFG=True))
            continue
        assert any(lo <= address < hi for lo, hi in segments), hex(address)
        assert len(seen) < 3000
        ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
        assert ins is not None, hex(address)
        row = dict(address=hex(address), instruction=ins.mnemonic+' '+ins.op_str)
        seen[address] = row
        if ins.mnemonic == 'ldr' and ins.operands[-1].type == ARM_OP_MEM:
            operand = ins.operands[-1].mem
            if operand.base == ARM_REG_PC:
                literal = ((address+4) & ~3)+operand.disp
                row.update(literal_address=hex(literal), literal_value=hex(image.word(literal)))
        if ins.mnemonic == 'adr':
            row['address_value'] = hex(((address+4) & ~3)+ins.operands[-1].imm)
        if ins.id in (ARM_INS_BL, ARM_INS_BLX):
            if ins.operands[0].type == ARM_OP_IMM:
                row['direct_call'] = hex(ins.operands[0].imm)
            else:
                row['indirect_call_register'] = ins.op_str
                indirect_calls.append(hex(address))
        elif ins.id == ARM_INS_B:
            assert ins.operands[0].type == ARM_OP_IMM
            pending.append(ins.operands[0].imm)
            if ins.cc == ARM_CC_AL:
                continue
        elif ins.id == ARM_INS_BX:
            if ins.op_str == 'lr':
                row['terminal'] = 'original_LR_return'
            else:
                assert address == popped_lr_tail and ins.op_str == 'r3', row
                pop = next(image.md.disasm(image.read(address-2, 4), address-2, count=1))
                assert pop.mnemonic+' '+pop.op_str == 'pop {r3}'
                row['terminal'] = 'original_saved_LR_popped_to_r3_return'
            returns.append(hex(address))
            continue
        elif ins.mnemonic == 'pop' and ARM_REG_PC in ins.regs_access()[1]:
            row['terminal'] = 'original_saved_PC_return'
            returns.append(hex(address))
            continue
        elif ARM_REG_PC in ins.regs_access()[1]:
            raise ValueError('Unresolved PC write '+hex(address))
        pending.append(address+ins.size)
    return dict(entry=hex(entry), allowed_code_segments=[dict(start=hex(a), end=hex(b)) for a,b in segments],
                instructions=[seen[a] for a in sorted(seen)], returns=returns,
                resolved_included_tails=external, indirect_calls=indirect_calls,
                unresolved_exits=[], instruction_limit_reached=False,
                calls_not_recursively_executed=True, static_instructions_only=True)


def utf16_string(image, address):
    raw = image.read(address, 128)
    end = next(n for n in range(0, len(raw), 2) if raw[n:n+2] == b'\0\0')
    return raw[:end].decode('utf-16le')


def main():
    stock = NativeImage()
    image = FileBackedRuntimeImage(stock)
    specs = [
        (0x5d2130, [(0x5d2130,0x5d215c)], None, None),
        (0x5d215c, [(0x5d215c,0x5d21b8)], None, None),
        (0x5d21b8, [(0x5d21b8,0x5d2232)], None, None),
        (0x5d2104, [(0x5d2104,0x5d2126)], None, None),
        (0x5d2126, [(0x5d2126,0x5d2130)], None, None),
        (0x5d2232, [(0x5d2232,0x5d2530),(0x5d2624,0x5d2718)], None, None),
        (0x4aecd8, [(0x4aecd8,0x4aecea)], None, None),
        (0x261c98, [(0x261c98,0x261cce)], None, None),
        (0x261d28, [(0x261d28,0x261d5c)], None, None),
        (0x261d5c, [(0x261d5c,0x261e04)], None, None),
        (0x4aed02, [(0x4aed02,0x4aed38)], None, None),
        (0x261e12, [(0x261e12,0x261e1c)], None, None),
        (0x6048a4, [(0x6048a4,0x6048ba)], None, None),
        (0x6048c8, [(0x6048c8,0x6048d4)], None, None),
        (0x6048de, [(0x6048de,0x6048e8)], None, None),
        (0x3ec498, [(0x3ec498,0x3ec4fa)], 0x3ec4f8, None),
        (0x3ec540, [(0x3ec540,0x3ec588)], 0x3ec586, None),
        (0x3ec5c6, [(0x3ec5c6,0x3ec6a2)], 0x3ec6a0, None),
        (0x3ec6a2, [(0x3ec6a2,0x3ec6aa)], None, 0x3ec5c6),
        (0x310400, [(0x310400,0x31040c)], None, None),
        (0x31040c, [(0x31040c,0x310418)], None, None),
        (0x5d28de, [(0x5d28de,0x5d28e8)], None, None),
        (0x5d28e8, [(0x5d28e8,0x5d28fe)], None, None),
        (0x5d28fe, [(0x5d28fe,0x5d2916)], None, None),
        (0x5d291c, [(0x5d291c,0x5d2942)], None, None),
    ]
    functions = {hex(a):thumb_cfg(image,a,segs,lr,tail) for a,segs,lr,tail in specs}
    rows = {int(r['address'],16):r for fn in functions.values() for r in fn['instructions']}
    expected_calls = {
        0x5d214a:0x5d2232, 0x5d2160:0x5d2130,
        0x5d221c:0x358bf8, 0x5d2224:0x2fbbbe, 0x5d222c:0x2fcf44,
        0x5d2708:0x5d21b8, 0x5d270e:0x5d2104,
        0x5d211a:0x4aecd8, 0x5d2120:0x261d5c,
        0x4aece0:0x261c98, 0x261cb8:0x6048a4,
        0x261de8:0x358bf8, 0x261df0:0x2fcf44, 0x261df8:0x6048c8,
        0x261d38:0x310400, 0x261d44:0x6048de, 0x261d4a:0x31040c,
        0x6048ce:0x3ec6a2, 0x6048e2:0x3ec498,
        0x3ec4ba:0x3009a0, 0x3ec4d2:0x2fcf44, 0x3ec4ea:0x3008b0,
        0x3ec63e:0x300bb8, 0x3ec644:0x300bb8, 0x3ec670:0x300a14,
        0x3ec68e:0x3009a0,
    }
    for pc, target in expected_calls.items():
        assert rows[pc]['direct_call'] == hex(target), hex(pc)
    assert rows[0x5d252e]['instruction'] == 'b #0x5d2624'
    assert rows[0x5d21f4]['literal_value'] == '0x5d215d'
    assert rows[0x261dbc]['literal_value'] == '0x261d29'
    assert rows[0x5d21ba]['literal_value'] == '0xaac'
    assert rows[0x5d21de]['literal_value'] == '0xb04'
    assert rows[0x5d21fa]['literal_value'] == '0x4b04'
    assert rows[0x5d2170]['instruction'] == 'lsls r0, r4, #0x1e'
    assert rows[0x5d21a0]['instruction'] == 'lsls r0, r4, #0x16'
    assert rows[0x3ec4ce]['instruction'] == 'movs r1, #8'
    assert rows[0x3ec4cc]['instruction'] == 'str r5, [r0, #4]'
    assert rows[0x261d3e]['instruction'] == 'strb r0, [r4, #4]'
    assert rows[0x261d56]['instruction'] == 'movs r0, #2'

    # An explicit straight-line slice of the mixed-mode builder's Thumb body.
    # This is field evidence only, not a recursively complete builder CFG.
    kernel_rows = [dict(address=hex(i.address), instruction=i.mnemonic+' '+i.op_str)
                   for i in image.md.disasm(image.read(0x358c40,0xa8),0x358c40)]
    kernel_by_pc = {int(r['address'],16):r for r in kernel_rows}
    kernel_expected = {
        0x358c4c:'ldr r0, [r4, #4]', 0x358c4e:'str r0, [r5, #8]',
        0x358c50:'ldrb r2, [r4, #0xc]', 0x358c62:'strb r2, [r5, #0x14]',
        0x358c64:'ldrb r0, [r4, #0xd]', 0x358c66:'strb r0, [r5, #0x13]',
        0x358c68:'ldrb r0, [r4, #0xe]', 0x358c6a:'strb r0, [r5, #0x10]',
        0x358c6c:'strb r0, [r5, #0x11]', 0x358c8a:'ldr r0, [r4, #0x10]',
        0x358c8c:'str r0, [r5, #0x1c]', 0x358cba:'ldr r1, [r4]',
        0x358cbc:'push {r1}', 0x358cd2:'str r5, [r1]',
    }
    for pc, text in kernel_expected.items():
        assert kernel_by_pc[pc]['instruction'] == text

    thread_vtable = [hex(image.word(0xc1b5b0+4*n)) for n in range(3)]
    assert thread_vtable == ['0x4aeceb','0x4aecf3','0x4aed03']
    labels = [dict(address=hex(a),encoding='UTF-16LE',text=utf16_string(image,a))
              for a in [0x5d2544,0x261e30]]
    assert [r['text'] for r in labels] == ['Dispatcher','Thread']
    labels.append(dict(address='0x6048e8',encoding='ASCII',text=image.read(0x6048e8,32).split(b'\0',1)[0].decode('ascii')))
    assert labels[-1]['text'] == '&mCond'
    failure_path = ROOT/'staging/native-player-kernel-context/dispatcher-multithread-mutex-scope-terminal-failure.json'
    prior = json.loads(failure_path.read_text())
    assert [r['TCB'] for r in prior['native_all_task_insertions']][-2:] == ['0x8804fb8','0x88092b0']
    assert prior['kernel_restores'][-1]['saved_PC'] == '0x5d215d'
    assert prior['native_lower_wait_operations'][-1]['original_wait_not_replaced_with_success']
    dependencies = [Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',
                    ROOT/'evidence/firmware-analysis/main_02bd.bin',failure_path]
    result = dict(
        updated_utc=datetime.now(timezone.utc).isoformat(), exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        complete_bounded_Thumb_CFG_count=len(functions),functions=functions,
        constructor_discontiguous_tail=dict(branch='0x5d252e',target='0x5d2624',return_instruction='0x5d2716',
            skipped_literal_pool=dict(start='0x5d2530',end='0x5d2624'),
            ordered_producers=['0x5d2708 -> 0x5d21b8','0x5d270e -> 0x5d2104 -> 0x261d5c'],
            singleton_pointer_published_only_after_constructor_return='0x5d214e'),
        labels=labels, original_thread_vtable=dict(address='0xc1b5b0',first_three_words=thread_vtable,
            run_slot_offset=8,run_target='0x4aed02',run_callsite='0x261d54'),
        symbolic_native_descriptor_stores=dict(
            values_are_static_expressions_not_live_RAM_reads=True,
            dispatcher=dict(producer='0x5d21b8',object_symbol='D',descriptor='D+0xaac',
                descriptor_words={'0':'0x5d215d','4':'D+0x4b04','8':'D+0x4b04','12':'0x055c1408','16':'D+0xac0'},
                metadata='D+0xac0',metadata_name_literal='0x5d2544',metadata_stack_base='D+0xb04',
                metadata_stack_words=4096,stack_bytes=16384,native_TCB_result_slot='D+0xaa8',
                current_and_base_priority=92,descriptor_word1_is_not_an_ordinary_entry_argument=True,
                worker='0x5d215c',builder_call='0x5d221c',registry_call='0x5d2224',boot_post='0x5d222c event0x10'),
            thread=dict(producer='0x261d5c',object_symbol='T',constructor='0x261c98',
                constructor_arguments={'stack_words':4096,'priority_provider':0},
                descriptor='T+0xc',descriptor_words={'0':'0x261d29','4':'0 when T+0xa4 provider is NULL; otherwise provider virtual slot8 result',
                    '8':'*(T+0x48)+4*(*(T+0x4c))','12':'0x055c0000 when provider is NULL; otherwise low two bytes are provider virtual slots12/16',
                    '16':'T+0x20'},metadata='T+0x20',metadata_name_literal='0x261e30',metadata_object_word_offset=32,
                metadata_stack_base_slot='T+0x28',metadata_stack_words_slot='T+0x2c',current_and_base_priority=92,
                native_TCB_result_slot='T+8',worker='0x261d28',builder_call='0x261de8',boot_post='0x261df0 event0x10',
                producer_wait='0x261df8 -> 0x6048c8(T+0x6c)',provider_values_not_read_from_zero_BSS=True)),
        kernel_builder_field_slice=dict(entry='0x358c40',end='0x358ce8',instructions=kernel_rows,
            descriptor_C_to_TCB_14='0x358c50/0x358c62',descriptor_D_to_TCB_13='0x358c64/0x358c66',
            descriptor_E_to_TCB_base_and_current_priority='0x358c68/0x358c6a/0x358c6c',
            descriptor_10_to_TCB_1C='0x358c8a/0x358c8c',descriptor_word1_to_TCB8='0x358c4c/0x358c4e',
            exact_builder_complete_CFG_or_execution_claimed=False),
        dispatcher_worker=dict(first_call_requires_global_singleton_lock='0x5d2160 -> 0x5d2130 -> 0x351bd0',
            queued_work_event_mask='0x2',queue_reader_boundary='0x37bc00',callback_vtable_slot_offset=8,
            callback_callsite='0x5d218e',callback_mutex='D+0xae8',wait_boundary='0x5d21a4 -> 0x2fd034',
            exit_event_mask='0x200',exit_sets_byte='D+0xaa4',queue_reader_and_native_initial_mailbox_helper_not_recursively_recovered=True),
        condition_notification_path=dict(
            waiting_controller_path=['0x261d5c locks T+0x50','0x261df8 calls 0x6048c8(T+0x6c)',
                '0x6048ce tail-wrapper 0x3ec6a2','0x3ec63e/0x3ec644 native full release auxiliary mutex then T+0x54',
                '0x3ec670 calls native lower wait 0x300a14(condition=T+0x70)','0x3ec68e reacquires T+0x54'],
            other_worker_path=['0x261d28 reads current TCB metadata+0x20 to obtain T',
                '0x261d38 locks T+0x50 via native virtual mutex','0x261d3e stores T+4=1',
                '0x261d44 calls 0x6048de(T+0x6c)','0x6048e2 calls 0x3ec498(T+0x70)',
                '0x3ec4ba locks condition+0x1c','0x3ec4c6/0x3ec4c8 pops condition+0x0c linked waiter node',
                '0x3ec4cc clears waiter node+4','0x3ec4d2 native-posts waiting TCB event8',
                '0x3ec4ea unlocks condition+0x1c','0x261d4a unlocks T+0x50',
                '0x261d54 invokes original derived run 0x4aed02'],
            second_worker_does_not_request_global_singleton_before_initial_notification=True,
            potential_controller_preemption_before_second_worker_mutex_unlock_requires_native_contention_progress=True,
            constructor_condition_initial_owner_from_original_pointer='0x3ec572 reads 0xf090a0; 0x3ec578 calls 0x300ae4',
            no_runtime_notify_or_wake_or_global_cycle_claimed=True),
        post_notification_thread_run=dict(entry='0x4aed02',
            loop_dependencies=['0x32c078 stack record','0x261e12 -> 0x353be4(1)',
                               'byte at zero-BSS address0xf08c87 nonzero','0x2ddb28 return nonzero','stack record byte+4 equals4'],
            after_gates_call='0x3316ec(0x249)',zero_BSS_gate_contents_not_read_or_assumed=True),
        prior_runtime_reference=dict(path=str(failure_path.relative_to(ROOT)),sha256=sha(failure_path),
            scope='Separate immutable partial run35440 inserted two extra original TCBs and resumed dispatcher entry. It stopped before this worker global C++ mutex body; second worker execution was not proved in that run.',
            GUI_extra_TCBs=['0x8804fb8','0x88092b0'],second_TCB_entry_is_static_producer_inference_not_prior_runtime_observation=True),
        all_assertions_passed=True,device_io=False,sounds_emitted=False,firmware_modified=False,
        install_candidate=False,real_GUI_boot_or_schedule_or_condition_notification_verified=False,
        limitations='Twenty-five bounded exact Thumb CFGs plus a labelled kernel-builder Thumb field slice. Calls/virtual slots and symbolic descriptor stores are static evidence, not emulation. Original helper bodies for initial mailbox, queue operations, kernel post/lower wait/priority and hardware-facing Thread::run callees are not recursively completed here. BSS pointers are addresses, never presumed file-backed values. The second worker has an original notify path that avoids the global singleton lock before notification; neither a deadlock nor actual unblocking/constructor completion follows from static reachability. Runtime task-scoped mutex/condition scheduling remains a separate probe. No device I/O, firmware write, foreground App, direct-phone music, accepted VPM/SIG or safe unload claim.')
    path = ROOT/'staging/native-player-task-mutex/gui-worker-boot-preflight.json'
    assert not path.exists(), 'Static proof namespace must be new'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(path.relative_to(ROOT)),sha256=sha(path),
                         complete_Thumb_CFGs=len(functions),second_worker='0x261d28',native_notify='0x3ec498',device_io=False)))


if __name__ == '__main__':
    main()
