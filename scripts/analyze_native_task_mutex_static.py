#!/usr/bin/env python3
"""Bounded original mutex, waiter, priority and scheduler static preflight.

Read-only firmware analysis for exact Taiwan HWID1352 / SW8.00. No emulation,
device access or firmware writes. This is deliberately not a complete kernel.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX,
                          ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC, ARM_CC_AL)
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_mutex_owner import mixed_cfg
from analyze_native_kernel_context import resolve


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded(image, start, mode, segments, hops=None, tails=None,
            literal_tails=None, external=None):
    """Resolve local paths and explicit PC arithmetic, retaining callee limits."""
    hops, tails = hops or {}, tails or {}
    literal_tails, external = literal_tails or {}, external or {}
    decoders = {name: Cs(CS_ARCH_ARM, CS_MODE_THUMB if name == 'Thumb'
                        else CS_MODE_ARM) for name in ['Thumb', 'ARM']}
    for decoder in decoders.values():
        decoder.detail = True
    todo = deque([(start, mode)])
    seen, ends, outside, indirect = {}, [], [], []
    while todo:
        address, mode = todo.popleft()
        if (address, mode) in seen:
            continue
        assert len(seen) < 512
        assert any(lo <= address < hi and m == mode for lo, hi, m in segments), (hex(address), mode)
        ins = next(decoders[mode].disasm(image.read(address, 4), address, count=1))
        row = dict(address=hex(address), mode=mode,
                   instruction=ins.mnemonic + ' ' + ins.op_str)
        seen[address, mode] = row
        if address in tails:
            assert row['instruction'] == tails[address]
            row['resolved_terminal'] = ('saved_native_task_context_dispatch'
                                        if ins.mnemonic == 'movs'
                                        else 'original_LR_return')
            ends.append(hex(address))
            continue
        if address in literal_tails:
            target, producer, word_address, expected_ins = literal_tails[address]
            assert row['instruction'] == expected_ins
            p = next(decoders[mode].disasm(image.read(producer, 4), producer, count=1))
            assert p.mnemonic == 'ldr' and p.operands[-1].type == ARM_OP_MEM
            assert p.operands[-1].mem.base == ARM_REG_PC
            literal = ((producer + 4) & ~3) + p.operands[-1].mem.disp
            assert literal == word_address and image.word(literal) == target
            row.update(resolved_tail_target=hex(target & ~1),
                       tail_target_mode='Thumb' if target & 1 else 'ARM',
                       verified_literal_producer=hex(producer),
                       literal_address=hex(literal), literal_value=hex(target))
            ends.append(hex(address))
            continue
        if ins.id in [ARM_INS_BL, ARM_INS_BLX]:
            if ins.operands[0].type == ARM_OP_IMM:
                row.update(direct_call=hex(ins.operands[0].imm),
                           call_target_mode=('ARM' if mode == 'Thumb' else 'Thumb')
                           if ins.id == ARM_INS_BLX else mode)
            else:
                row['unresolved_indirect_callee'] = ins.op_str
                indirect.append(hex(address))
        elif ins.id == ARM_INS_B:
            target = ins.operands[0].imm
            if target in external:
                row['known_external_tail'] = external[target]
                outside.append(hex(target))
            else:
                todo.append((target, mode))
            if ins.cc == ARM_CC_AL:
                continue
        elif ins.id == ARM_INS_BX:
            assert address in hops, (hex(address), row['instruction'])
            target, target_mode, producer = hops[address]
            if ins.op_str == 'pc':
                computed = (address + 4) & ~3
                assert target_mode == 'ARM'
            else:
                p = next(decoders[mode].disasm(image.read(producer, 4), producer, count=1))
                if p.mnemonic == 'adr':
                    computed = ((producer + 4) & ~3) + p.operands[-1].imm
                else:
                    assert mode == 'ARM' and p.mnemonic == 'add'
                    assert p.operands[1].reg == ARM_REG_PC
                    computed = producer + 8 + p.operands[-1].imm
                assert target_mode == ('Thumb' if computed & 1 else 'ARM')
            assert computed & ~1 == target
            row.update(explicit_interworking_target=hex(target),
                       target_mode=target_mode,
                       verified_target_producer=hex(producer)
                       if producer else 'architectural Thumb PC')
            todo.append((target, target_mode))
            continue
        elif ARM_REG_PC in ins.regs_access()[1]:
            raise ValueError('Unresolved local PC write ' + hex(address))
        if (ins.mnemonic == 'ldr' and ins.operands[-1].type == ARM_OP_MEM
                and ins.operands[-1].mem.base == ARM_REG_PC):
            literal = (address + 8 if mode == 'ARM' else (address + 4) & ~3) + ins.operands[-1].mem.disp
            row.update(literal_address=hex(literal), literal_value=hex(image.word(literal)))
        todo.append((address + ins.size, mode))
    return dict(entry=hex(start), entry_mode=mode if not seen else next(iter(seen))[1],
                instructions=[seen[key] for key in sorted(seen)],
                returns_or_resolved_tail_dispatch=ends,
                known_external_tails=outside,
                unresolved_indirect_callee_sites=indirect,
                unresolved_local_exits=[], instruction_limit_reached=False)


def main():
    main_path = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
    assert sha(main_path) == EXPECTED
    image = RuntimeImage(NativeImage())
    functions = {}
    owner_specs = [
        (0x3009a0, [(0x3009a0,0x3009a8,'Thumb'),(0x3009a8,0x3009bc,'ARM'),(0x3009bc,0x3009f8,'Thumb'),(0x3009f8,0x300a04,'ARM'),(0x300a04,0x300a0c,'Thumb')],
         {0x3009a6:(0x3009a8,'ARM',0x3009a4,'adr r3, #0'),0x3009b8:(0x3009bc,'Thumb',0x3009b4,'add r3, pc, #1'),0x3009f6:(0x3009f8,'ARM',0x3009f4,'adr r2, #0'),0x300a00:(0x300a04,'Thumb',0x3009fc,'add r2, pc, #1')},0x300a0a),
        (0x3008b0, [(0x3008b0,0x3008b8,'Thumb'),(0x3008b8,0x3008cc,'ARM'),(0x3008cc,0x300918,'Thumb'),(0x300918,0x300924,'ARM'),(0x300924,0x30092c,'Thumb')],
         {0x3008b6:(0x3008b8,'ARM',0x3008b4,'adr r3, #0'),0x3008c8:(0x3008cc,'Thumb',0x3008c4,'add r3, pc, #1'),0x300914:(0x300918,'ARM',0x300912,'adr r2, #4'),0x300920:(0x300924,'Thumb',0x30091c,'add r2, pc, #1')},0x30092a),
        (0x300ae4, [(0x300ae4,0x300af4,'Thumb'),(0x300af4,0x300b08,'ARM'),(0x300b08,0x300b74,'Thumb'),(0x300b74,0x300b80,'ARM'),(0x300b80,0x300b88,'Thumb')],
         {0x300af0:(0x300af4,'ARM',0x300aee,'adr r2, #4'),0x300b04:(0x300b08,'Thumb',0x300b00,'add r2, pc, #1'),0x300b70:(0x300b74,'ARM',0x300b6e,'adr r2, #4'),0x300b7c:(0x300b80,'Thumb',0x300b78,'add r2, pc, #1')},0x300b86),
    ]
    for start, segments, hops, tail in owner_specs:
        functions[hex(start)] = mixed_cfg(image, start, segments, hops, tail)
    specs = [
        (0x3008a0,'Thumb',[(0x3008a0,0x3008b0,'Thumb')],{}, {0x3008ae:'bx lr'},{}),
        (0x300bb8,'Thumb',[(0x300bb8,0x300c28,'Thumb')],{}, {0x300c26:'bx r3'},{}),
        (0x300a14,'Thumb',[(0x300a14,0x300a28,'Thumb'),(0x300a28,0x300a3c,'ARM'),(0x300a3c,0x300a94,'Thumb'),(0x300a94,0x300aa0,'ARM'),(0x300aa0,0x300ac8,'Thumb'),(0x300ac8,0x300ad4,'ARM'),(0x300ad4,0x300adc,'Thumb')],
         {0x300a24:(0x300a28,'ARM',0x300a22),0x300a38:(0x300a3c,'Thumb',0x300a34),0x300a90:(0x300a94,'ARM',0x300a8e),0x300a9c:(0x300aa0,'Thumb',0x300a98),0x300ac4:(0x300ac8,'ARM',0x300ac2),0x300ad0:(0x300ad4,'Thumb',0x300acc)}, {0x300ada:'bx r3'},{}),
        (0x300d08,'Thumb',[(0x300d08,0x300d44,'Thumb'),(0x300d44,0x300d80,'ARM'),(0x300d80,0x300dce,'Thumb')],
         {0x300d40:(0x300d44,'ARM',0x300d3e),0x300d7c:(0x300d80,'Thumb',0x300d78)}, {0x300dcc:'bx r3'},{}),
        (0x358e70,'Thumb',[(0x358e70,0x358e7c,'Thumb'),(0x358e7c,0x358eb8,'ARM'),(0x358eb8,0x358ebe,'Thumb')],
         {0x358e7a:(0x358e7c,'ARM',0x358e78),0x358eb4:(0x358eb8,'Thumb',0x358eb0)}, {0x358ebc:'bx lr'},{}),
        (0x358ec4,'ARM',[(0x358ec4,0x358ecc,'ARM'),(0x358ecc,0x358ee0,'Thumb'),(0x358ee0,0x358f0c,'ARM')],
         {0x358ec8:(0x358ecc,'Thumb',0x358ec4),0x358edc:(0x358ee0,'ARM',None)}, {0x358f08:'movs pc, lr'},{}),
        (0x300b90,'Thumb',[(0x300b90,0x300bb6,'Thumb')],{}, {0x300bb4:'bx lr'},{}),
        (0x358f74,'Thumb',[(0x358f74,0x358fa0,'Thumb')],{}, {0x358f9e:'bx r3'},
         {0x358f98:(0x358f15,0x358f8e,0x358fa0,'bx ip')}),
        (0x358f14,'Thumb',[(0x358f14,0x358f6a,'Thumb')],{}, {0x358f68:'bx lr'},
         {0x358f66:(0x300cb9,0x358f64,0x358f70,'bx r3')}),
        (0x300cb8,'Thumb',[(0x300cb8,0x300d04,'Thumb')],{}, {},
         {0x300cfc:(0x358f75,0x300cf6,0x300d04,'bx r3')}),
        (0x300c2c,'Thumb',[(0x300c2c,0x300c34,'Thumb'),(0x300c34,0x300c48,'ARM'),(0x300c48,0x300ca0,'Thumb'),(0x300ca0,0x300cac,'ARM'),(0x300cac,0x300cb4,'Thumb')],
         {0x300c32:(0x300c34,'ARM',0x300c30),0x300c44:(0x300c48,'Thumb',0x300c40),0x300c9e:(0x300ca0,'ARM',0x300c9c),0x300ca8:(0x300cac,'Thumb',0x300ca4)}, {0x300cb2:'bx r3'},{}),
        (0x353d68,'Thumb',[(0x353d68,0x353d74,'Thumb')],{}, {},
         {0x353d70:(0x353e49,0x353d6e,0x353d74,'bx r3')}),
        (0x353e48,'Thumb',[(0x353e48,0x353e9c,'Thumb')],{}, {0x353e9a:'bx lr'},{}),
        (0x353a40,'Thumb',[(0x353a40,0x353a48,'Thumb'),(0x353a48,0x353a5c,'ARM'),(0x353a5c,0x353a88,'Thumb'),(0x353a88,0x353a94,'ARM'),(0x353a94,0x353a98,'Thumb')],
         {0x353a44:(0x353a48,'ARM',0x353a42),0x353a58:(0x353a5c,'Thumb',0x353a54),0x353a84:(0x353a88,'ARM',0x353a82),0x353a90:(0x353a94,'Thumb',0x353a8c)}, {0x353a96:'bx lr'},{}),
        (0x3ec5c6,'Thumb',[(0x3ec5c6,0x3ec6a2,'Thumb')],{}, {0x3ec6a0:'bx r3'},{}),
        (0x358d24,'Thumb',[(0x358d24,0x358d34,'Thumb')],{}, {0x358d32:'bx lr'},{}),
        (0x3ec498,'Thumb',[(0x3ec498,0x3ec4fa,'Thumb')],{}, {0x3ec4f8:'bx r3'},{}),
        (0x3ec4fa,'Thumb',[(0x3ec4fa,0x3ec540,'Thumb')],{}, {0x3ec53e:'bx r3'},{}),
        (0x3ec540,'Thumb',[(0x3ec540,0x3ec588,'Thumb')],{}, {0x3ec586:'bx r3'},{}),
        (0x3ec588,'Thumb',[(0x3ec588,0x3ec5c6,'Thumb')],{}, {0x3ec5c4:'bx r3'},{}),
        (0x310400,'Thumb',[(0x310400,0x31040c,'Thumb')],{}, {0x31040a:'pop {r4, pc}'},{}),
        (0x31040c,'Thumb',[(0x31040c,0x310418,'Thumb')],{}, {0x310416:'pop {r4, pc}'},{}),
        (0x21b6cc,'ARM',[(0x21b6cc,0x21b6dc,'ARM')],{}, {0x21b6d8:'bx lr'},{}),
        (0x21b6dc,'ARM',[(0x21b6dc,0x21b6e4,'ARM')],{}, {0x21b6e0:'bx lr'},{}),
        (0x20b8ce,'Thumb',[(0x20b8ce,0x20b8d0,'Thumb')],{}, {0x20b8ce:'bx lr'},{}),
        (0x20ebd4,'ARM',[(0x20ebd4,0x20ebe0,'ARM')],{}, {0x20ebdc:'bx lr'},{}),
    ]
    for start, mode, segments, hops, tails, literal_tails in specs:
        functions[hex(start)] = bounded(image, start, mode, segments, hops, tails, literal_tails)
    functions['0x2fcf44'] = resolve(image,0x2fcf44,'ARM',
        [(0x2fcf44,0x2fcf6c,'ARM'),(0x2fcf6c,0x2fcfb0,'Thumb'),(0x2fcfb0,0x2fcfec,'ARM'),(0x2fcfec,0x2fd01c,'Thumb'),(0x2fd01c,0x2fd028,'ARM'),(0x2fd028,0x2fd02c,'Thumb')],
        {0x2fcf68:(0x2fcf6c,'Thumb',0x2fcf64),0x2fcfac:(0x2fcfb0,'ARM',0x2fcfaa),0x2fcfe8:(0x2fcfec,'Thumb',0x2fcfe4),0x2fd01a:(0x2fd01c,'ARM',0x2fd018),0x2fd024:(0x2fd028,'Thumb',0x2fd020)},
        {0x2fd02a:'bx lr'},
        {0x2fce38:'Known external interrupt-marker alternate; not recursively covered here'})
    rows = {int(row['address'],16): row for fn in functions.values() for row in fn['instructions']}
    expected_rows = {
        0x300d0e:'add r7, sp, #0', 0x300d10:'str r1, [r7, #8]',
        0x300d16:'str r6, [r7, #4]', 0x300d30:'str r0, [r7]',
        0x300d32:'str r7, [r2]', 0x300d36:'str r2, [r1]',
        0x300d38:'str r5, [r6]', 0x300d3c:'strb r2, [r6, #0x16]',
        0x300d64:'str sp, [r6, #0xc]', 0x300d98:'ldr r3, [r7, #4]',
        0x300bd6:'str r3, [r0, #8]', 0x300bda:'str r1, [r2, #4]',
        0x300bde:'str r2, [r0, #0xc]', 0x300be8:'str r1, [r0, #4]',
        0x300bea:'str r0, [r1]', 0x300c0e:'str r1, [r3]',
        0x300c10:'str r3, [r0]', 0x300c14:'strb r0, [r3, #0x16]',
        0x300d82:'lsrs r0, r0, #0x1d', 0x358f14:'strb r1, [r0, #0x11]',
        0x300b94:'ldr r2, [r1, #0x18]', 0x300b96:'lsrs r2, r2, #0x1d',
        0x358f7c:'ldrb r1, [r4, #0x10]', 0x358f84:'ldrb r1, [r4, #0x11]',
        0x300a46:'str r2, [r5, #8]', 0x300a62:'strh r0, [r5, #0x14]',
        0x3ec634:'strb r0, [r4, #0x11]', 0x3ec650:'strb r0, [r4, #0x11]',
        0x3ec4cc:'str r5, [r0, #4]', 0x3ec5b2:'str r2, [r1, #4]',
    }
    assert all(rows[address]['instruction'] == text for address,text in expected_rows.items())
    call_graph = {}
    external_callees = set()
    for key, fn in functions.items():
        direct = sorted({r['direct_call'] for r in fn['instructions'] if 'direct_call' in r})
        tails = sorted({r['resolved_tail_target'] for r in fn['instructions'] if 'resolved_tail_target' in r})
        graph_targets = direct + tails
        covered = [target for target in graph_targets if target in functions]
        uncovered = [target for target in graph_targets if target not in functions]
        external_callees.update(uncovered)
        call_graph[key] = dict(direct_calls=direct, resolved_literal_tail_targets=tails,
                              callees_with_bounded_original_body=covered,
                              callees_outside_this_preflight=uncovered)
    assert external_callees == {'0x23d6e8'}
    source_files = [Path(__file__).resolve(), ROOT/'scripts/analyze_native_sections.py',
                    ROOT/'scripts/analyze_native_voice_acceptance.py',
                    ROOT/'scripts/analyze_native_mutex_owner.py',
                    ROOT/'scripts/analyze_native_kernel_context.py',
                    ROOT/'scripts/analyze_native_usb_transition.py', main_path]
    result = dict(
        updated_utc=datetime.now(timezone.utc).isoformat(), MAIN_sha256=EXPECTED,
        source_sha256={str(path.relative_to(ROOT)):sha(path) for path in source_files},
        complete_bounded_CFG_count=len(functions),
        verified_mode_transition_count=sum('explicit_interworking_target' in row
                                           for fn in functions.values() for row in fn['instructions']),
        verified_literal_tail_count=sum('resolved_tail_target' in row
                                        for fn in functions.values() for row in fn['instructions']),
        functions=functions, call_graph=call_graph,
        recursive_call_graph_bound='Mutex/condition plus waiter-priority propagation, original context save/restore and timer arm/disarm helper bodies. Diagnostic23D6E8 is recorded only; timer service dispatch, scheduler IRQ exit, task cancellation/exit, full boot and hardware services are not complete.',
        layouts={
            'mutex': {'bytes':24,'next_owned':0,'previous_owned_link_pointer':4,'owner_TCB':8,
                      'waiter_head':12,'recursion_u16':20,'classification_byte':22},
            'waiter': {'location':'blocked task stack, r7=SP at300D0E','bytes':12,
                       'next':0,'task_TCB_or_zero_after_transfer':4,'saved_contention_r1':8,
                       'temporary_lifetime':'resident until original300D08 returns; fullrelease must not dereference after caller stack lifetime ends'},
            'TCB': {'ready_next_or_blocked_mutex':0,'mailbox':4,'saved_context_SP':12,
                    'base_priority_u8':16,'effective_priority_u8':17,'state_u8':22,
                    'context_format_u8':23,'flags':24,'owned_mutex_head':32,
                    'priority_inheritance_enable_mask':'0x10000000'},
            'globals': {'ready_head_current_selection':'0xf09090','all_tasks_head':'0xf0908c'},
        },
        caller_ABI={
            '0x3009a0':'r0=mutex; immediate or recursively owned returns0; contention returns0 when stack waiter+4 was cleared, ordinary mutex fullrelease also transfers owner; condition signal/broadcast is a separate marker-clear route and does not transfer token owner; outside wake path returns1',
            '0x3008b0':'r0=mutex; recursive depth>0 decrements only; unowned diagnostic; final release with waiter delegates fullrelease and reschedule; body does not compare owner against current',
            '0x300bb8':'r0=mutex; expects valid owned-list links and owner; clears all recursion, removes owned link, transfers to head waiter, clears waiter+4, inserts transferred mutex into new owner list, readies eligible waiter and recomputes old owner priority',
            '0x300a14':'r0=mutex, r1=deadline or duration, r2=contention metadata, r3 bit0=relative-time flag; immediate/recursive0, unavailable relative0 timeout2; relativeFFFFFFFF indefinite; timed path arms timer type2 on local stack then calls original contention and removes pending timer',
            '0x300ae4':'r0=mutex,r1=requested owner TCB; explicit native ownership transfer; request==old owner no-op; terminated target state80 instead unlocks; nonzero recursion diagnostic',
            '0x358e70':'r0=currently executing old TCB; if current selected head differs, save this caller context and restore selected native context; resumed original save continuation returns later',
            '0x358f14':'r0=TCB,r1=new effective priority; ready reorder or blocked-mutex waiter reorder with propagation',
            '0x358f74':'r0=TCB; min(base priority, all owned-mutex head-waiter priorities) where flag bit28 permits inheritance',
            '0x310400':'C++ method r0 points four bytes before native mutex; BL3009A0 return continuation310408',
            '0x31040c':'C++ unlock method r0+4; BL3008B0 return continuation310414',
            '0x3ec5c6':'r0=condition,r1=mutex,r2=deadline/duration,r3=mode; save current identity once; owner validation, auxiliary condition+28 lock, full releases, native lower wait, priority recompute and original mutex reacquisition',
            '0x3ec498':'r0=condition; condition broadcast locks auxiliary condition+28 at3EC4BA continuation3EC4BE, removes every waiter/clears marker and posts event8, finally unlocks auxiliary at3EC4EA continuation3EC4EE',
            '0x3ec588':'r0=condition; single signal removes only head waiter, clears its marker then originalpost(TCB,8); does not transfer condition native token owner',
        },
        waiter_order={
            'ascending_numeric_effective_priority':True,'equal_priority_FIFO_insertion':True,
            'contended_ready_removal':'300D34/300D36',
            'blocked_TCB_sem_reference_and_state4':'300D38/300D3C',
            'waiter_insert':'300D30/300D32',
            'waiter_transfer_owner':'300BD4/300BD6',
            'waiter_mutex_transfer_marker_clear':'300BD8/300BDA',
            'condition_signal_marker_clear_without_owner_transfer':'3EC5B0/3EC5B2; broadcast3EC4CA/3EC4CC',
            'new_owned_list_insert':'300BE2..300BF0',
            'wake_ready_insert':'300BFA..300C14, only if state&0x81==0',
            'outside_wake_cleanup':'300D98..300DC4 removes own waiter if marker stillnonzero, recomputes original owner priority and returns1',
            'priorities':'Lower byte value is earlier. Priority propagation traverses old owner TCB, its blocked mutex waiter queue and owner chain through358F14/300CB8/358F74.',
        },
        observer_invariants=[
            'Index pending mutex/condition operation stacks by native entry TCB; nested native calls on that same TCB remain LIFO while another task can retain independent suspended operations.',
            'Capture entry owner, LR continuation, original SP/frame and TCB before native mutation; F09090 may alreadyselect a different ready task while CPU still executes oldtask stack until358EC4.',
            'Track actual running task through native saved-context store and358EC4 destination, never relabel an old operation from the current head after queue mutation.',
            'All owner, recursion, owned-list, waiter, ready and priority changes must be guest original instructions; observer journal and logical counters may reflect exact observed native state only.',
            'A nonzero owner must be a declared native TCB and occur exactly once as an owned mutex node with coherent previous-link pointer; head previous pointer is ownerTCB+32.',
            'A blocked mutex state4 TCB has TCB+0=mutex; its waiter node is on its live resident stack, refers to that TCB at+4 and occurs exactly once in sem+12 priority queue.',
            'Fullrelease may be called by one task and transfer owner to another; node+4=0 plus new owner/list stores proves transfer, while no caller return or hardware playback is inferred.',
            'Contention return0 alone proves marker-clear only: condition signal/broadcast also clears waiter+4 while leaving token ownerunchanged; lowercondition success must not demand conditiontoken owner==waiter.',
            'Normal unlock with no waiter clears owner and removes owned list; stale sem next/prev words are permissible because body does notzero them.',
            'Recursive count is unsigned16 and counts extra acquisitions; observer must read native halfword, never invent saturation/overflow guard not present in originalbody.',
            'Resume returns must match original saved LR and frame of originating task, including lower wait, context save and native lock epilogues; scheduler dispatch is a task transition, not anordinary function return.',
            'Condition wait intentionally sets effective priority0 and temporarily masks TCB flagbit28 around two fullreleases, then restores both before lowerwait; journal transient states instead of requiring fixedpriority.',
            'Retained condition-token observations must be keyed by condition and native owner lifetime rather than one globallyassumed owner; validate legitimate signaling route separately.',
            'Preserve native queue ordering/priority recursion and ready state checks; no host fakewake, counter sweep, owner store or task context restore.',
        ],
        original_caller_and_mode_context={
            'GUI_worker_entry':'0x5d215c Thumb; original5D2160 calls5D2130',
            'singleton_lock_route':'5D2136→351BD0 RAII guard→indirect method→310400→3009A0',
            'method_callee_runtime_resolution':'RAII method is indirect; static wrapper bytes alone do notprove live vtable target.35440 terminal evidence separately identifies nativecaller310408.',
            'GUI_all_task_insertion':'Prior runtime evidence PC358CD2 nativeinsertions, not assertedfrom this static artifact',
        },
        precise_original_return_sites={
            'native_lock':'300A08 pop{r3};300A0A bx r3',
            'native_unlock':'300928 pop{r3};30092A bx r3',
            'native_fullrelease':'300C24 pop{r3};300C26 bx r3',
            'native_lower_wait':'300AD4 addSP0x18;300AD6 pop{r4,r5,r6};300AD8 pop{r3};300ADA bx r3. Does notvisit300A0A.',
            'native_contention':'300DCA pop{r3};300DCC bx r3',
            'native_condition_wait':'3EC69E pop{r3};3EC6A0 bx r3',
            'native_broadcast':'3EC4F6 pop{r3};3EC4F8 bx r3',
            'native_single_signal':'3EC5C2 pop{r3};3EC5C4 bx r3',
            'context_restore':'358F08 MOVS PC,LR dispatches savedtask, notordinary caller return',
        },
        original_fullrelease_callers_in_covered_CFGs=[
            {'call':'0x300906','continuation':'0x30090a','mode':'Thumb','purpose':'native finalunlock with waiters'},
            {'call':'0x300c6a','continuation':'0x300c6e','mode':'Thumb','purpose':'taskcleanup ownedlist/classification selection'},
            {'call':'0x3ec63e','continuation':'0x3ec642','mode':'Thumb','purpose':'conditionauxiliary fullrelease'},
            {'call':'0x3ec644','continuation':'0x3ec648','mode':'Thumb','purpose':'associatedordinary mutex fullrelease'},
        ],
        fullrelease_callsite_inventory_is_whole_firmware_exhaustive=False,
        broadcast_native_lock_callers={
            'lock_call':'0x3ec4ba','lock_continuation_LR':'0x3ec4bf',
            'unlock_call':'0x3ec4ea','unlock_continuation_LR':'0x3ec4ef',
            'argument':'condition+0x1c nativeauxiliary mutex','mode':'Thumb',
            'marker_clear_and_event':'Original3EC4CC clears waiter+4;3EC4D2 BLX normalARM2FCF44(TCB,8). Restore/saveIRQtoken aroundeach event opportunity; auxiliarymutex remains held until finalunlock.',
        },
        complete_kernel_or_interrupt_exit_verified=False,
        new_runtime_execution=False, device_io=False, sounds_emitted=False,
        install_candidate=False,
        limits='Bounded exact original CFG and field/store preflight only. It expands the earlier immediate-owner and normal-context CFGs through nativewaiter transfer, priority propagation and timedwait helpers, but does not run a new multi-task runtime or prove deadlock freedom, waiter cancellation, IRQexit, safe reclamation, boot services, full dispatcher/App or hardware behavior.')
    path = ROOT/'staging/native-player-task-mutex/task-mutex-static-preflight.json'
    assert not path.exists(), 'Never overwrite earlier task proof'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(artifact=str(path.relative_to(ROOT)),
                         complete_bounded_CFG_count=len(functions),
                         verified_mode_transitions=result['verified_mode_transition_count'],
                         verified_literal_tails=result['verified_literal_tail_count'],
                         device_io=False, new_runtime_execution=False)))


if __name__ == '__main__':
    main()
