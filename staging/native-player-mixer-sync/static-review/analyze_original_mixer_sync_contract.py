#!/usr/bin/env python3
"""File-only contract: original cold mutex/condition -> native mixer ACK8.

No VM imports, guest execution, device operations, canonical writes or edits to
prior evidence. Decode exact MAIN and reuse the frozen bounded mixed CFG.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX,
                          ARM_CC_AL, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC)

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / 'original-mixer-sync-cold-initialization-contract.json'
PRIOR = 'staging/native-player-task-mutex/task-mutex-static-preflight.json'
PRIOR_SHA = 'ce58164830245667cfd0d805b97e0abd609239c354ffc3f1bcd7ee82cc1f878d'
R, M, T = 0x034E7F48, 0x034E5CF8, 0x02D227C8


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def main():
    assert not OUTPUT.exists(), 'New outputs only; previous artifact immutable'
    n = NativeImage()
    assert sha(ROOT / 'evidence/firmware-analysis/main_02bd.bin') == EXPECTED
    assert sha(ROOT / PRIOR) == PRIOR_SHA
    prior = json.loads((ROOT / PRIOR).read_text())
    dependencies = dict(prior['source_sha256'])
    dependencies[PRIOR] = PRIOR_SHA
    for p, expected in dependencies.items():
        assert sha(ROOT / p) == expected, p
    md = {name: Cs(CS_ARCH_ARM, mode) for name, mode in
          [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]}
    for decoder in md.values():
        decoder.detail = True

    def decode(pc, mode='Thumb'):
        i = next(md[mode].disasm(n.read(pc, 4), pc, count=1))
        row = dict(address=hex(pc), mode=mode, opcode_hex=i.bytes.hex(),
                   size=i.size, instruction=i.mnemonic + ' ' + i.op_str)
        if i.mnemonic == 'ldr' and i.operands[-1].type == ARM_OP_MEM and i.operands[-1].mem.base == ARM_REG_PC:
            a = (pc + 8 if mode == 'ARM' else (pc + 4) & ~3) + i.operands[-1].mem.disp
            row.update(literal_address=hex(a), literal_value=hex(n.word(a)))
        if i.mnemonic == 'adr':
            a = ((pc + 4) & ~3) + i.operands[-1].imm
            row['computed_address'] = hex(a)
        return i, row

    reused = {}
    selected = ['0x3008a0', '0x3009a0', '0x3008b0', '0x300ae4',
                '0x300a14', '0x300bb8', '0x300d08', '0x3ec540',
                '0x3ec498', '0x3ec5c6', '0x358d24', '0x2fcf44',
                '0x358e70', '0x358ec4', '0x358f74', '0x358f14',
                '0x300b90', '0x300cb8', '0x21b6cc', '0x21b6dc']
    for entry in selected:
        fn = prior['functions'][entry]
        verified = []
        for old in fn['instructions']:
            _, row = decode(int(old['address'], 16), old['mode'])
            assert row['instruction'] == old['instruction'], old
            verified.append(dict(old, opcode_hex=row['opcode_hex'], size=row['size']))
        reused[entry] = dict(instructions=verified, frozen_CFG_source=PRIOR,
                            frozen_CFG_source_sha256=PRIOR_SHA,
                            local_CFG_already_bounded=True,
                            callee_recursion_is_not_complete_kernel=True)

    def bounded(start, end, returns=(), external_tails=()):
        queue, seen, terminal, calls = deque([start]), {}, [], []
        while queue:
            pc = queue.popleft()
            if pc in seen:
                continue
            assert start <= pc < end and len(seen) < 512, hex(pc)
            i, row = decode(pc)
            seen[pc] = row
            if pc in returns or (i.mnemonic == 'pop' and 'pc' in i.op_str):
                terminal.append(dict(PC=hex(pc), kind='original_return'))
                continue
            if i.id in (ARM_INS_BL, ARM_INS_BLX):
                assert i.operands[0].type == ARM_OP_IMM
                row.update(direct_call=hex(i.operands[0].imm),
                           target_mode='ARM' if i.id == ARM_INS_BLX else 'Thumb',
                           normalized_continuation=hex(pc+i.size),
                           architectural_LR=hex((pc+i.size)|1))
                calls.append(dict(PC=hex(pc), target=row['direct_call'],
                                  normalized_continuation=row['normalized_continuation']))
            elif i.id == ARM_INS_B:
                target = i.operands[0].imm
                if start <= target < end:
                    row['local_branch_target'] = hex(target)
                    queue.append(target)
                else:
                    assert target in external_tails, (hex(pc), hex(target))
                    row['bounded_external_tail'] = hex(target)
                    terminal.append(dict(PC=hex(pc), kind='original_external_tail', target=hex(target)))
                if i.cc == ARM_CC_AL:
                    continue
            elif i.id == ARM_INS_BX or ARM_REG_PC in i.regs_access()[1]:
                raise AssertionError('Unresolved PC write ' + hex(pc))
            queue.append(pc + i.size)
        return dict(entry=hex(start), declared_range=[hex(start), hex(end)],
                    mode='Thumb', instructions=[seen[p] for p in sorted(seen)],
                    calls=calls, returns_or_bounded_tails=terminal,
                    local_exits_resolved=True, callees_not_recursively_complete=True)

    specs = [(0xF6E48,0xF6E68,(0xF6E66,),()),
             (0x353D3C,0x353D58,(0x353D56,),()),
             (0x26A016,0x26A0D0,(),()),
             (0x3B9B66,0x3B9C5E,(),()),
             (0x46CC7A,0x46CD08,(),()),
             (0x30ED08,0x30ED10,(0x30ED0E,),()),
             (0x30ED10,0x30ED1A,(),()),
             (0x30ED1A,0x30ED24,(),()),
             (0x30ED24,0x30ED30,(),()),
             (0x30ED30,0x30ED7C,(),()),
             (0x3EC6A2,0x3EC6AA,(),(0x3EC5C6,)),
             (0x3EC6AA,0x3EC6AE,(),(0x3EC5C6,)),
             (0x353A9C,0x353AA2,(0x353AA0,),()),
             (0x2FA2A6,0x2FA2E8,(),(0x2FA588,))]
    new = {hex(a): bounded(a,b,c,d) for a,b,c,d in specs}
    rows = {int(r['address'],16):r for f in new.values() for r in f['instructions']}
    rows.update({int(r['address'],16):r for f in reused.values() for r in f['instructions']})
    expected = {0x3008A2:'str r1, [r0]',0x3008AC:'str r1, [r0, #0x14]',
                0x353D42:'str r0, [r1]',0x353D46:'str r0, [r1]',0x353D50:'str r0, [r1]',
                0xF6E60:'strb r1, [r0, #0xe]',0xF6E64:'strb r1, [r0, #0xf]',
                0x46CCB4:'str r5, [sp, #0x48]',0x30ED08:'strh r1, [r0]',
                0x30ED26:'strh r1, [r0]',0x3EC4CC:'str r5, [r0, #4]',
                0x300D32:'str r7, [r2]',0x300D64:'str sp, [r6, #0xc]',
                0x300BDA:'str r1, [r2, #4]',0x300A6E:'beq #0x300ab8',
                0x300D9A:'movs r0, #0',0x3EC634:'strb r0, [r4, #0x11]'}
    for pc, text in expected.items():
        assert rows[pc]['instruction'] == text, (hex(pc),rows[pc])
    literals = {0xF6EBC:0x02D226E0,0xF6EC0:0x353D79,0xF6EC4:0x02D22834,
                0x353D58:0xF09098,0x353D5C:0xF0909C,0x353D60:0x02D226E0,
                0x353D64:0xF090A0,0x3EC6B0:0xD4475B83,0x3EC6C0:0xF090A0,
                0x46CDD4:0x034E5378,0x46CDD8:0x07FFFFFF,0x30EE88:0x07FFFFFF}
    assert all(n.word(a)==v for a,v in literals.items())
    zero = next(z for z in n.zeros if not z['conditional'] and
                z['runtime_start'] <= T and R+0xA4 <= z['runtime_end'])
    assert zero['runtime_start'] <= 0x02D22000 and 0x02D23000 <= zero['runtime_end']

    # Both compiled versions are immutable input evidence; V2 fixes only the
    # public-command admission bound that made V1 command7 unreachable.
    builds = {}
    for name in ('build-v1.json','build-v2.json'):
        p = HERE.parent / name
        b = json.loads(p.read_text())
        dependencies[str(p.relative_to(ROOT))] = sha(p)
        for path, h in b['source_sha256'].items():
            assert sha(ROOT/path)==h,path
            if path in dependencies:
                assert dependencies[path]==h,path
            dependencies[path]=h
        assert sha(ROOT/b['ELF'])==b['ELF_sha256']
        dependencies[b['ELF']] = b['ELF_sha256']
        builds[name]=dict(ELF=b['ELF'],ELF_sha256=b['ELF_sha256'],
                          build_only_claims=b['guest_executed'] is False)
    v1=(HERE.parent/'mixer_source_task_sync_v1.c').read_text()
    v2=(HERE.parent/'mixer_source_task_sync_v2.c').read_text()
    assert 'command>6u' in v1 and 'command>7u' in v2
    assert v2==v1.replace('command>6u','command>7u')
    c=(HERE.parent/'initializer_sync_bridge_v1.c').read_text()
    a=(HERE.parent/'initializer_sync_bridge_v1.S').read_text()
    guard=(HERE.parent/'music_session_guard_sync_v1.c').read_text()
    assert 'push {r0-r3,r4,lr}' in a and 'pop {r0-r3,r4,lr}' in a
    assert 'mov r3,lr' in a and '0x46cc7b' in a
    assert 'ms_original_sync_completed=0;' in c and 'ms_original_sync_completed=1;' in c
    assert '!ms_original_sync_completed ||' in guard
    assert v2.index('0x3b9b67u)(8,0);if(r)return r;') < v2.index('mh_handoff_result=ms_validate_completed_sync();')
    dependencies[str(Path(__file__).resolve().relative_to(ROOT))] = sha(Path(__file__).resolve())
    dependencies['scripts/probe_native_condition_timer_owner.py'] = sha(ROOT/'scripts/probe_native_condition_timer_owner.py')

    raw_calls=[]
    def call(pc, entry, pointer, function, role):
        row=rows[pc]
        assert int(row['direct_call'],16)==entry
        raw_calls.append(dict(PC=hex(pc),entry=hex(entry),continuation=hex(pc+4),
                              LR=hex((pc+4)|1),pointer=pointer,
                              tag={'debug_name_plus16':'0 for direct cold recipe; original full26A016 assigns native string pointer',
                                   'classification_plus22':'native byte, cold0; no host retag'},
                              containing_function=hex(function),role=role,
                              opcode_hex=row['opcode_hex']))
    for pc,offset in [(0x26A03A,0x1C8),(0x26A04C,0x1E0),(0x26A058,0xC),(0x26A064,0x58),(0x26A072,0x144)]:
        call(pc,0x3008A0,f'R(channel)+{offset:#x}; channel8={R+offset:#x}',0x26A016,'raw24 cold initialization, 18-record loop')
    for pc,offset in [(0x3EC55E,0),(0x3EC566,0x1C)]:
        call(pc,0x3008A0,f'condition+{offset:#x}; channel8={R+0x70+offset:#x}',0x3EC540,'condition internal24 constructor')
    for pc,pointer,fn,role in [(0x30ED14,f'{R+0x58:#x}',0x30ED10,'external wait/ACK shared mutex'),
                              (0x3EC56E,f'{R+0x70:#x}',0x3EC540,'token initial acquisition before native Timer transfer'),
                              (0x3EC618,f'{R+0x8C:#x}',0x3EC5C6,'wait backend'),
                              (0x3EC68E,f'{R+0x58:#x}',0x3EC5C6,'wait epilog external reacquisition'),
                              (0x3EC4BA,f'{R+0x8C:#x}',0x3EC498,'broadcast backend')]:
        call(pc,0x3009A0,pointer,fn,role)
    for pc,pointer,fn,role in [(0x30ED1E,f'{R+0x58:#x}',0x30ED1A,'external caller unlock'),
                              (0x3EC4EA,f'{R+0x8C:#x}',0x3EC498,'broadcast backend unlock')]:
        call(pc,0x3008B0,pointer,fn,role)

    names=[]
    for pc,target in [(0x26A068,R+0x68),(0x26A08A,R+0x80),(0x26A08E,R+0x9C)]:
        address=int(rows[pc]['computed_address'],16)
        text=n.read(address,100).split(b'\0',1)[0].decode('ascii')
        names.append(dict(producer_PC=hex(pc),literal_address=hex(address),
                          string=text,channel8_store_address=hex(target)))

    result=dict(
        all_passed=True,proof_kind='exact-byte static source/cold-input/ABI contract, no runtime proof',
        updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_platform={'HWID':1352,'software':'8.00','region':'Taiwan'},
        source_sha256=dict(sorted(dependencies.items())),
        assertions={'exact_MAIN_and_all_input_hashes':True,'frozen_mixed_CFG_rows_redecoded':True,
                    'new_local_CFG_exits_resolved':True,'Timer_cold_literals_and_stores':True,
                    'raw_initializer_and_lock_callsite_bytes':True,'V2_command7_only_source_delta':True,
                    'compiled_sync_wrapper_argument_LR_preservation_source_review':True,
                    'CONFIG_before_wait_PLAY_after_full_initializer_return_source_order':True},
        counts={'new_bounded_local_CFGs':len(new),'reused_bounded_mixed_CFGs':len(reused),
                'new_reachable_instructions':sum(len(f['instructions'])for f in new.values()),
                'redecoded_reused_instructions':sum(len(f['instructions'])for f in reused.values()),
                'raw_mutex_call_rows':len(raw_calls)},
        new_bounded_CFGs=new,reused_bounded_mixed_CFGs=reused,
        verified_literal_words={hex(a):hex(v)for a,v in literals.items()},
        raw_mutex_calls=raw_calls,original_debug_name_producers=names,
        layouts=dict(prior['layouts'],condition={'bytes':52,'token_mutex':0,'magic_word':24,
                 'magic':'0xd4475b83','backend_mutex':28},
                 flag={'bytes':12,'flags_u16':0,'unused_uninitialized_padding':2,
                       'external_mutex_pointer':4,'condition_pointer':8},
                 message20={'bytes':12,'type_byte':0,'channel_byte':1,
                            'unused_uninitialized_padding_bytes':[2,3],
                            'unused_uninitialized_word':4,'flag_pointer_word':8}),
        cold_recipe={'declared_ordinary_boot_actor':'existing native-built controller/current normal context, F09094=0',
                     'preconditions':['No previous Timer: F090A0=0; no live timed nodes: F0909C=0',
                         'F09098 is cold input and may be reset only during this one-time Timer creation',
                         '52-byte condition magic is not D4475B83; no live token/waiter/owned list may be reset',
                         'Original358BF8 bookkeeping/opaque services remain explicit input boundaries'],
                     'ordered_calls':[{'entry':'0xf6e49','r0_r3':'unused',
                         'writes':'descriptor02D226E0..02D226F4 only'},
                         {'entry':'0x353d3d','r0_r3':'unused','calls_original_builder_at':'0x353d4a',
                          'builder_LR':'0x353d4f','publishes_Timer_at':'0x353d50'},
                         {'entry':'0x3008a1','r0':hex(R+0x58),'r1_r3':'unused',
                          'return_r0':'unchanged mutex pointer, not success code0'},
                         {'entry':'0x3ec541','r0':hex(R+0x70),'r1_r3':'unused',
                          'return_r0':'original saved IRQ/CPSR flags restored by21B6DC, not status0'}],
                     'Timer_descriptor_words':['0x353d79','0x0','0x2d22834','0x10000','0x0'],
                     'Timer_stack_range':['0x2d226f4','0x2d22834'],'Timer_declared_stack_bytes':320,
                     'Timer_TCB_range':['0x2d227c8','0x2d22834'],'Timer_TCB_bytes':108,
                     'Timer_builder_52byte_context_is_inside_declared_stack':True,
                     'Timer_priority_from_descriptor':1,'Timer_register_or_POST_in_initializer':False,
                     'minimal_Timer_RW_mapping':['0x2d22000','0x2d23000'],
                     'minimal_sem_condition_byte_ranges':[[hex(R+0x58),hex(R+0x70)],
                                                          [hex(R+0x70),hex(R+0xA4)]],
                     'native_startup_zero_recipe_covering_inputs':zero,
                     'host_seeded_owner_or_ack_allowed':False,
                     'direct_caller_scope':'Direct declared boot calls reproduce narrow actual native constructors. They are not a claim that full26A016 executed.',
                     'original26A016_scope':'18 records, five raw24 mutexes and two52 conditions each; subsequently269F6C loop,277E4C,30EE62,4379B0. Do not reset existing listeners or conditions to rerun it.'},
        ctor_endpoint={'external_mutex':'owner0/waiter0/recursion0/all24 initially0 for direct cold call',
                       'condition_token':'owner nativeTimer02D227C8/waiter0/recursion0; owned next=previousTimerHead; prevlink=Timer+32',
                       'condition_backend':'owner0/waiter0/recursion0; original initializer all24zero',
                       'condition_magic':'D4475B83 atR+88',
                       'current_controller_ownedhead':'restored original owned list after300AE4 transfer',
                       'Timer_ownedhead':'R+70 -> prior Timer owned chain; retained, not reset/unlocked'},
        next_call={'source_actor':'actual native source TCB after compiled bootstrap; priority12',
                   'entry':'original3B9B67(channel8,r1=0)',
                   'original_sync_call_PC':'0x3b9c54','original_sync_return_PC':'0x3b9c58',
                   'sync_LR':'0x3b9c59','sync_entry':'0x46cc7b',
                   'sync_r0_r1_r2':[hex(R),1,0],'sync_r3':'incoming unspecified and preserved by wrapper',
                   'sync_frame_bytes':96,'flag_pointer':'original46CC7A entrySP-96+0x34',
                   'message20_pointer':'original46CC7A entrySP-96+0x40',
                   'timeout_sentinel':'0x07ffffff',
                   'original_sync_return_r0':0,
                   'original_initializer_return_r0':'saved status stack[0], normal0; wrapper preserves original returned value',
                   'second_hardware_wait_branch':'r2=0 skips46CCDE..46CCFE; no HAM synchronization claim'},
        infinite_wait_path={'flag_initial_value':1,'desired_ack_mask':8,
                            'wait_calls':['30ED38->353A9C readsF09098 only','30ED4A->3EC6A2',
                                          '3EC6A2 setsr2=FFFFFFFF,r3=1 ->3EC5C6',
                                          '3EC670->300A14(token,r1=FFFFFFFF,r2=0,r3=1)',
                                          '300A68..6E ->300AB8 ->300D08'],
                            'does_not_arm_or_remove_timednode_for_this_path':True,
                            'timed_3EC6AA_semantics_verified_here':False,
                            'condition_backend_fullrelease_caller':'3EC63E->300BB8/return3EC642',
                            'external_fullrelease_caller':'3EC644->300BB8/return3EC648',
                            'waiter12':'actual source stack; +0next,+4source-or0-afterbroadcast,+8saved_contention_r1',
                            'actual_ACK8_producers':['2FA2D2 reads original message flagptr frommixerSP+20',
                               '2FA2D4->30ED10 locks sameR+58','2FA2DC->30ED24 writesflag8 then3EC498',
                               '3EC4CC clears conditionwaiter+4;3EC4D2 originalPOST(source,8)',
                               '2FA2E2->30ED1A nativeexternalunlock'],
                            'lower_success':'300D98 reads clearedwaiter+4;300D9A setsr0=0;300D9E→300DC6',
                            'condition_epilog':'external3009A0 at3EC68E must really reacquire; condition returns lower0',
                            'flag_wait_return':'30ED4E/70 consumes actualflag8; returnsr0=8'},
        priorities_and_preemption={'numeric_order':'smaller effective priority value runs first',
            'declared_base_priorities':{'Timer':1,'Source':12,'Controller':16,'Mixer':23,'Idle':240},
            'source_flags_inheritance_mask':False,'mixer_flags_inheritance_mask':True,
            'mask':'0x10000000',
            'initial_mixer_POST16':'Source12 continues until it actually waits; controller16 may run beforemixer23',
            'expected_ACK_interleaving':['Source acquiresR+58 then nativecondition fullreleasesexternal andblocks ontokenTimer',
                'Mixer locksR+58 andconditionbackend;broadcastPOST8 may preemptMixer23 withSource12',
                'Source lowerwait returns0 then blocks reacquiringR+58 ownedbyMixer',
                'Mixer inheritance flag permits donation to effective12; originalready/context body must determine actual running task',
                'Mixer resumes broadcastbackendunlock then externalunlock transfersSource, recomputesMixer23',
                'Source may resume beforeMixer rawunlock epilog; both resident frames must survive',
                'Source completes conditionwait/flagwait/native46CC7A and3B9B66 beforecompiledPLAY gate opens'],
            'ready_head_is_not_sole_running_task_provenance':True},
        per_task_guard_requirements=[
            'Track running actor at actual native restore destination; F09094=0 and358D24 current-getter result gate normal path.',
            'Each task preserves its nested lock,300BB8 fullrelease,300A14 lowerwait,300D08 waiter and3EC5C6 condition frames.',
            'Capture GP/SP/LR/caller at entry and actual return; lowerwait epilog300ADA is distinct from lock300A0A.',
            'Retain source flag12 and all queued references until actual46CC7A return. Only original30ED26 writesACK8.',
            'Journal actual24/52/108-byte object images plusready/ALL, resident source/mixer frames andtokenownedchain.',
            'External andbackend released mutex next/prev links may be stale. Validate exact original writer/history, not fabricated zero links.',
            'Timer token owner remainsTimer; tokenrecursion0/queueempty afterACK, Timerownedhead retainscondition.',
            'Endpoint source/mixer/controller ownedheads restore baseline; external/backend owner0/waiter0/recursion0; no live stackwaiter forgotten.',
            'F09098/F0909C and unrelated live timednodes are unchanged after cold initializer for infinite ACK8.',
            'Admit only exact recorded callsites andpointer roles above; nativeACK/ownertransfer/readyinsert/priorityrecompute must execute.'
        ],
        compiled_bridge_review={'builds':builds,'ARM_frame_bytes':24,
            'saved_registers':['r0','r1','r2','r3','r4','lr'],
            'original_LR_given_to_C_as_r3':'3B9C59',
            'IRQ_exclusion':'ms_before_original_sync restores saved IRQ flags before returning; original wait occurs outside exclusion',
            'tail_interworking':'restores args/LR thenBX46CC7B; native return3B9C59 preserved',
            'failure_behavior':'C admission result recorded, but assembly always invokes original sync; PLAY remains fail-closed if validation fails',
            'CONFIG_grant':'only Source owner beforewait; nativeMdescriptor/queue/stack/currentepoch checked; no host Mixer handoff',
            'PLAY_grant':'only compiled Source after actual3B9B66 returns0 andcapability validation; no host completion seed',
            'existing_mixer':'M+78 skipscreation; same matchingcapability accepted without duplicatehandoff',
            'V1_command7_erratum':'process_command implements7 butpublic request rejects>6; preserved immutableV1, no fullV1 existing-path success',
            'V2_correction':'only public command bound>7, source exact-string delta verified; runtime success is outside this static note'},
        scope={'guest_execution':False,'VM_import_or_instantiation':False,'device_io':False,
               'canonical_writes':False,'complete_kernel_or_interrupt_exit_verified':False,
               'native_sync_runtime_verified_by_this_artifact':False,'native_hardware_audio_or_App_verified':False},
        limits=['Static bytes and source review are not dynamic execution or complete kernel proof.',
                'Bookkeeping/opaque allocation/current cold descriptor input boundaries remain explicit; mapped RAM is not physical backing.',
                'This narrow branch uses one Source, one Mixer, one retained Timer condition token, r2=0 and infinite sentinel. Timer clock service, finite timeout, IRQ exit and second hardware synchronization are outside it.',
                'Unexpanded diagnostics23D6E8 and other global-init callees must not be called complete kernel.',
                'Native audio exclusive ownership, STOP_DONE, physical clock/DMA/speaker/phone/UI/App and installability remain unverified.'])
    OUTPUT.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'proof':str(OUTPUT.relative_to(ROOT)),
                      'proof_sha256':sha(OUTPUT),'counts':result['counts'],
                      'guest_execution':False}))


if __name__ == '__main__':
    main()
