#!/usr/bin/env python3
"""Exact backup-only Dispatcher callback and MainMenu foreground preflight.

No loader/emulator, device I/O, guessed BSS reads, or frozen proof changes.
Local CFG completion is distinct from recursive callee or runtime completion.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_CC_AL, ARM_INS_B, ARM_INS_BL, ARM_INS_BLX,
                          ARM_INS_BX, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC)
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage, utf16_string
from analyze_native_loader import scan_calls


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cfg(image, entry, segments, modes=None, external_tails=None):
    modes = modes or {}
    external_tails = external_tails or {}
    decoders = {}
    for mode, flag in [('Thumb', CS_MODE_THUMB), ('ARM', CS_MODE_ARM)]:
        decoders[mode] = Cs(CS_ARCH_ARM, flag)
        decoders[mode].detail = True
    pending, seen, returns, indirect = deque([(entry, 'Thumb')]), {}, [], []
    while pending:
        address, mode = pending.popleft()
        if (address, mode) in seen:
            continue
        assert any(lo <= address < hi for lo, hi in segments), hex(address)
        assert len(seen) < 3000
        ins = next(decoders[mode].disasm(image.read(address, 4), address, count=1), None)
        assert ins is not None, hex(address)
        row = dict(address=hex(address), mode=mode, bytes_hex=ins.bytes.hex(),
                   load_address=hex(image.stock.runtime_to_load(address, ins.size)),
                   instruction=ins.mnemonic+' '+ins.op_str)
        seen[address, mode] = row
        if ins.mnemonic == 'ldr' and ins.operands[-1].type == ARM_OP_MEM:
            operand = ins.operands[-1].mem
            if operand.base == ARM_REG_PC:
                literal = (((address+4) & ~3) if mode == 'Thumb' else address+8)+operand.disp
                row.update(literal_address=hex(literal), literal_value=hex(image.word(literal)))
        if ins.mnemonic == 'adr':
            row['address_value'] = hex(((address+4) & ~3)+ins.operands[-1].imm)
        if ins.id in (ARM_INS_BL, ARM_INS_BLX):
            if ins.operands[0].type == ARM_OP_IMM:
                row['direct_call'] = hex(ins.operands[0].imm)
            else:
                row['indirect_call_register'] = ins.op_str
                indirect.append(hex(address))
        elif ins.id == ARM_INS_B:
            assert ins.operands[0].type == ARM_OP_IMM
            pending.append((ins.operands[0].imm, mode))
            if ins.cc == ARM_CC_AL:
                continue
        elif ins.id == ARM_INS_BX:
            if address in modes:
                target, next_mode = modes[address]
                row['resolved_mode_transition'] = dict(target=hex(target), mode=next_mode)
                pending.append((target, next_mode))
            elif address in external_tails:
                row['resolved_external_tail'] = hex(external_tails[address])
            elif ins.op_str == 'lr':
                row['terminal'] = 'original_LR_return'
                returns.append(hex(address))
            else:
                assert mode == 'Thumb' and ins.op_str == 'r3', row
                pop = next(decoders[mode].disasm(image.read(address-2, 2), address-2))
                assert pop.mnemonic+' '+pop.op_str == 'pop {r3}', row
                row['terminal'] = 'original_saved_LR_popped_to_r3_return'
                returns.append(hex(address))
            continue
        elif ins.mnemonic == 'pop' and ARM_REG_PC in ins.regs_access()[1]:
            row['terminal'] = 'original_saved_PC_return'
            returns.append(hex(address))
            continue
        elif ARM_REG_PC in ins.regs_access()[1]:
            raise ValueError('Unresolved PC write '+hex(address))
        pending.append((address+ins.size, mode))
    return dict(entry=hex(entry), allowed_code_segments=[dict(start=hex(a), end=hex(b)) for a,b in segments],
                instructions=[seen[a] for a in sorted(seen)], returns=returns, indirect_calls=indirect,
                unresolved_exits=[], instruction_limit_reached=False,
                local_CFG_complete=True, callees_not_recursively_executed=True,
                static_only=True)


def descriptor(image, address):
    raw = image.read(address, 20)
    words = struct.unpack('<5I', raw)
    metadata = words[4]
    return dict(address=hex(address), load_address=hex(image.stock.runtime_to_load(address,20)),
                raw_hex=raw.hex(), words=[hex(w) for w in words],
                entry=hex(words[0]), queue_buffer=hex(words[1]), stack_top=hex(words[2]),
                message_width_C=raw[12], slots_D=raw[13], priority_E=raw[14], flags_F=raw[15],
                metadata=hex(metadata), name=utf16_string(image,image.word(metadata)),
                name_pointer=hex(image.word(metadata)), stack_base=hex(image.word(metadata+8)),
                stack_words=image.word(metadata+12), native_TCB_store_observed=False)


def extract(image, start, end, mode='Thumb'):
    md=Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode=='Thumb' else CS_MODE_ARM)
    md.detail=True
    return dict(start=hex(start), end=hex(end), mode=mode,
                instructions=[dict(address=hex(x.address), instruction=x.mnemonic+' '+x.op_str,
                                   bytes_hex=x.bytes.hex())
                              for x in md.disasm(image.read(start,end-start),start)],
                enclosing_caller_CFG_not_claimed=True)


def main():
    image=FileBackedRuntimeImage(NativeImage())
    specs=[
        (0x57458c,[(0x57458c,0x5745d4)]),
        (0x4b571c,[(0x4b571c,0x4b5796)]),
        (0x57475c,[(0x57475c,0x574760)]),
        (0x52353c,[(0x52353c,0x52356c)]),
        (0x609338,[(0x609338,0x60936c)]),
        (0x5d28fe,[(0x5d28fe,0x5d2916)]),
        (0x5d215c,[(0x5d215c,0x5d21b8)]),
        (0x405340,[(0x405340,0x4053e6)]),
        (0x38e696,[(0x38e696,0x38e6f6)]),
        (0x38e358,[(0x38e358,0x38e528),(0x38e538,0x38e614)]),
        (0x38e15e,[(0x38e15e,0x38e284)]),
        (0x390306,[(0x390306,0x3904d2)]),
        (0x3904d2,[(0x3904d2,0x390604),(0x39060e,0x39064c)]),
        (0x38fd60,[(0x38fd60,0x38fdb2)]),
        (0x36bdfc,[(0x36bdfc,0x36be02)]),
        (0x38cdc6,[(0x38cdc6,0x38ce04)]),
        (0x394596,[(0x394596,0x394648)]),
        (0x38f174,[(0x38f174,0x38f212)]),
        (0x400e40,[(0x400e40,0x400e58)]),
        (0x400e66,[(0x400e66,0x400e82)]),
        (0x214ac0,[(0x214ac0,0x214af6)]),
        (0x393a6a,[(0x393a6a,0x393a7a)]),
        (0x324d54,[(0x324d54,0x324d7a)]),
        (0x324b66,[(0x324b66,0x324b74)]),
        (0x3933e0,[(0x3933e0,0x39374c),(0x393784,0x3939fa)]),
        (0x353e48,[(0x353e48,0x353e9c)]),
        (0x353d78,[(0x353d78,0x353de8)]),
        (0x4c0d7c,[(0x4c0d7c,0x4c0db2)]),
    ]
    functions={hex(a):cfg(image,a,segs) for a,segs in specs}
    functions['0x353d68']=cfg(image,0x353d68,[(0x353d68,0x353d72)],
                              external_tails={0x353d70:0x353e48})
    mixed=[
        (0x37bce4,[(0x37bce4,0x37bd6e),(0x37bd70,0x37bd8c)],
         {0x37bd06:(0x37bd08,'ARM'),0x37bd18:(0x37bd1c,'Thumb'),
          0x37bd6c:(0x37bd70,'ARM'),0x37bd78:(0x37bd7c,'Thumb')}),
        (0x37bc00,[(0x37bc00,0x37bc9c)],
         {0x37bc06:(0x37bc08,'ARM'),0x37bc18:(0x37bc1c,'Thumb'),
          0x37bc86:(0x37bc88,'ARM'),0x37bc90:(0x37bc94,'Thumb')}),
        (0x353be4,[(0x353be4,0x353c22),(0x353c24,0x353c6a),(0x353c6c,0x353c7e)],
         {0x353bea:(0x353bec,'ARM'),0x353bfc:(0x353c00,'Thumb'),
          0x353c20:(0x353c24,'ARM'),0x353c5c:(0x353c60,'Thumb'),
          0x353c68:(0x353c6c,'ARM'),0x353c74:(0x353c78,'Thumb')}),
    ]
    for a,segs,modes in mixed:
        functions[hex(a)]=cfg(image,a,segs,modes)
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    calls={0x5745ca:0x46c274,0x4b5758:0x3954cc,0x523554:0x609338,
           0x5d290e:0x37bce4,0x4053be:0x40434c,0x4053d2:0x38e696,
           0x38e6dc:0x38e358,0x38e3ec:0x38e15e,0x394624:0x2fcf44,
           0x3936fc:0x38f174,0x400e4a:0x358bf8,0x400e6e:0x2fcf44,
           0x214ade:0x324d54,0x214ae2:0x324b66,0x37bcfe:0x3009a0,
           0x37bd5c:0x3008b0,0x37bd64:0x300ae4,0x37bc7c:0x3008b0,
           0x37bd80:0x2fcf44,0x353c0a:0x353d68,0x353c60:0x358ec4,
           0x353de0:0x2fcf44,0x4c0da2:0x405340}
    for pc,target in calls.items():
        assert rows[pc]['direct_call']==hex(target),hex(pc)
    assert rows[0x4b5760]['instruction']=='str r6, [r1, #4]'
    assert rows[0x4b575e]['literal_value']=='0xc1b584'
    assert rows[0x57458e]['literal_value']=='0xc1b59c'
    assert rows[0x5d2170]['instruction']=='lsls r0, r4, #0x1e'
    assert rows[0x3936a8]['instruction']=='lsls r0, r4, #0x16'
    assert rows[0x353c1c]['instruction']=='strb r1, [r2, #0x16]'
    assert rows[0x37bcf4]['instruction']=='lsrs r2, r2, #0x1e'
    assert rows[0x37bc6e]['instruction']=='lsrs r0, r0, #0x1e'
    vtables={hex(a):[hex(image.word(a+4*k)) for k in range(n)]
             for a,n in [(0xc1b59c,3),(0xc1b584,4)]}
    assert vtables['0xc1b59c'][2]=='0x52353d'
    assert vtables['0xc1b584'][2:] == ['0x57475d','0x574761']
    manager_slots={hex(o):hex(image.word(0xc02558+o))
                   for o in [0xb0,0xc4,0xdc,0xf0,0x110,0x114,0x12c]}
    assert manager_slots=={'0xb0':'0x394ba3','0xc4':'0x394597','0xdc':'0x38fd61',
                          '0xf0':'0x3933e1','0x110':'0x390307','0x114':'0x3904d3','0x12c':'0x393a6b'}
    tail=extract(image,0x574760,0x574764)
    assert [r['instruction'] for r in tail['instructions']]==['ldr r0, [r0, #4]','bx r0']
    emission=rows[0x609358]['instruction']
    assert emission=='ldr r1, [r1, #0xc]'
    ctor=json.loads((ROOT/'staging/native-player-task-mutex/gui-worker-boot-preflight.json').read_text())
    ctor_rows={int(r['address'],16):r for r in ctor['functions']['0x5d2232']['instructions']}
    assert ctor_rows[0x5d2322]['literal_value']=='0x464'
    assert ctor_rows[0x5d2326]['direct_call']=='0x57458c'
    desc=[descriptor(image,a) for a in [0x9cb854,0x9cb890]]
    assert [d['name'] for d in desc]==['GUI main','GUI io']
    assert [d['priority_E'] for d in desc]==[92,24]
    for a in [0xf0b550,0xf0b55c]:
        assert image.word(a)==0
    for fn in functions.values():
        assert not fn['unresolved_exits'] and not fn['instruction_limit_reached']
    dependencies=[Path(__file__).resolve(), ROOT/'scripts/analyze_native_sections.py',
                  ROOT/'scripts/analyze_native_gui_worker_boot.py',ROOT/'scripts/analyze_native_loader.py',
                  ROOT/'evidence/firmware-analysis/main_02bd.bin',
                  ROOT/'staging/native-player-task-mutex/gui-worker-boot-preflight.json',
                  ROOT/'staging/native-player-task-mutex/gui-worker-boot-erratum-and-inputs.json',
                  ROOT/'staging/native-player-task-mutex/runtime-crosscheck4903.json',
                  ROOT/'staging/native-player-mainmenu/MainMenu-root-settings-preflight.json',
                  ROOT/'staging/native-player-mainmenu-controller/controller-static-preflight.json']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        complete_bounded_local_CFG_count=len(functions),mixed_mode_CFG_count=3,
        functions=functions,callback_vtables=vtables,manager_vtable=hex(0xc02558),
        manager_vtable_slots=manager_slots,
        most_direct_next_input=dict(
            current_scope='Static candidate for a new separately guarded runtime; no new execution here.',
            original_registration_ABI='4B571D(r0=S=D+464,r1=405341); S is an original resident zero-argument signal.',
            original_publication_ABI='5D28FF(r0=D,r1=S); wrapper publishes 8-byte native queue record [S,0].',
            queue_target='D+AA8 -> native Dispatcher TCB',queue_buffer='D+4B04',event=2,
            native_callback_chain=['5D218E BLX S.vtable+8','C1B59C+8=52353D',
                                   '523554 BL609338','60935A BLX holder.vtable+12',
                                   'C1B584+12=574761','574760 ldr r0,[r0,#4]; bx r0',
                                   'holder+4=405341 -> original405340'],
            caller_arguments_are_not_required='405340 first overwrites r0 at405344, and does not consume entry argument registers.',
            no_guest_code_or_vtable_patch_required=True,
            function_adapter_tail=tail,
            original_constructor_member_evidence=[ctor_rows[pc] for pc in [0x5d2322,0x5d2324,0x5d2326]],
            original_diagnostic_example=extract(image,0x5d2c7c,0x5d2c84),
            diagnostic_example_is_not_executed=True,
            input_checks=['Finish pending native background continuations before publication.',
                          'Inventory S.vtable, vector entries and S+1C recursive mutex before registration; do not infer current emptiness from constructor code.',
                          'Keep D, S, holders, Page, manager and voice/resources resident; no teardown/reclaim is established.',
                          'Observe original native queue producer/consumer and callback on Dispatcher TCB/stack; do not invoke405340 from host as proof of dispatch.',
                          'Verify PageMainMenu key lookup, cold constructor/root0 or existing-page branch, frame and visibility after original transition.',
                          'Run scoped full-code/resource/DB/stack guards after the declared endpoint.']),
        queue_native_mutex_scope=dict(
            acquire=dict(call='0x37bcfe',return_caller='0x37bd02',mutex='target TCB+50',
                         caller_stack_word='message source pointer saved at current SP before3009A0'),
            producer_unlock=dict(call='0x37bd5c',return_caller='0x37bd60',mutex='target TCB+50'),
            capacity_owner_transfer=dict(call='0x37bd64',return_caller='0x37bd68',mutex='target TCB+50',r1='target TCB'),
            consumer_unlock=dict(call='0x37bc7c',return_caller='0x37bc80',mutex='current TCB+50',
                                 branch_guard='native mutex owner at+8 equals current TCB'),
            locking_predicate='LSRS#30 carry is original TCB flags bit29; descriptor F is shifted28 at358C9A.',
            Dispatcher_descriptor_F=5,Dispatcher_TCB_bit29=0,
            Dispatcher_original_queue_mutex_branches_expected_taken=False,
            producer_event2_call='0x37bd80',producer_event2_return_caller='0x37bd84',
            fake_queue_or_fake_event_return_used=False),
        Thread_original_timed_block=dict(
            call_chain='4AED16 ->261E12 ->353BE4(r0=1) ->353D68 ->353E48',
            entry_SP_symbol='S',local_base='S-0x20',saved_entry_LR='[S-4]',
            timed_node='S-0x1C (local base+4)',node_layout={'0':'next','4':'native current TCB','8':'deadline','C':'kind2'},
            deadline='u32([F09098]+1)',original_saved_CPSR='S-8 (local base+18)',
            node_registration_return_caller='0x353c0e',node_head='0xf0909c',
            original_saved_context_SP='S-0x54',original_saved_PC='0x353c64',
            context_store='0x353c44 writes nativeSP to currentTCB+C',
            native_state='353C18 current nextlink=8;353C1C current state8; original restore358EC4',
            native_mutex_calls_in_this_sleep_function=[],
            timer_TCB_global='0xf090a0',timer_original_entry='0x353d78',timer_required_event=1,
            timer_due_test='u32(clock-deadline)<0x927C0',
            timed_kind2_expiration='353DDA clears node+4,353DE0 post8 to saved nativeTCB',
            timed_wake_return_caller='0x353de4',
            no_ticking_is_needed_to_demonstrate_initial_native_block=True,
            original_tick_unit_or_hardware_IRQ_proven=False,
            external_hardware_tick_producer_not_recovered_here=True,
            stack_node_and_context_must_remain_resident_while_blocked=True),
        controller_root_and_foreground=dict(
            controller='0x405340',cold_Page_constructor='0x40434c',Page_key='PageMainMenu',
            original_root_call='4053D2 ->38E696(manager,Page,category0,parent0)',
            original_sync_transition_chain=['38E6DC ->38E358','category0 branch38E3B2',
                                            '38E3EC ->38E15E(manager,newPageHolder,oldRootHolder,flag1)',
                                            '38E268 BLX manager.vtable+110=390307',
                                            '3904CC BLX manager.vtable+114=3904D3'],
            manager_category_rect='38CDC6 reads manager+D8+16*category into16-byte rectangle; category0 usesmanager+D8.',
            original_frame_observation='390636 ->377AB8 with Page and original computed frame, or Page virtual+C4 animation/transition method branch.',
            Page_original_visibility_observations=['Page+84','Page+85','Page+DC','Page frame+20..2C'],
            PageMainMenu_vtable='0xc03f98',
            PageMainMenu_original_virtual_slots={hex(o):hex(image.word(0xc03f98+o)) for o in [0x50,0x9c,0xa0,0xac,0xc4]},
            root_catalog_presence_or_controller_return_does_not_prove_visible_foreground=True,
            settings_GIR_font_cache_heap_clock_inputs_remain_required=True,
            rendering_touch_display_driver_or_physical_foreground_not_proven=True),
        original_GUI_main_actor=dict(
            separate_from_Dispatcher=True,creation='400E40 ->358BF8(desc9CB854) ->store400E4E atF0B550',
            boot_create_caller='0x23fef4',boot_start_caller='0x23ff72',
            start='400E66 ->original post16 at400E6E; also registers native exitlistener3CC5C2',
            descriptors=desc,
            main_entry='214AC0 ->393A2C ->manager.vtable+12C=393A6B ->wait16 ->GUIio324D54/post16 ->manager.vtable+F0=3933E1',
            internal_callback_publish='394596 holds manager+E04, enqueues native sharedholder atmanager+E1C, thenpost512 at394624 to[F0B550] ifnonzero',
            internal_callback_consume='3936A8 bit512 ->native E1C list drain and E04 lock/unlock ->3936FC38F174',
            queue_event2_is_distinct='39371E bit2 ->37BC00 reads original 40-byte GUI event records; not Dispatcher8-byte callback object/arg.',
            same_event512_has_different_per_task_meaning='Dispatcher5D21A0 bit512 exits;GUI main3936A8 bit512 drains manager callbacks.',
            creation_of_GUI_main_actor_not_implied_by_singleton_two_workers=True,
            flags_without_actor_do_not_deliver_manager_callback=True,
            initial_F0B550_file_value=dict(runtime='0xf0b550',load=hex(image.stock.runtime_to_load(0xf0b550,4)),
                                         word=0,initialized_data=True,live_or_guest_value_not_read=True),
            initializing_full_GUI_main_loop_is_separate_next_runtime_scope=True,
            broad_boot_startup_or_hardware_calls_not_executed=True),
        direct_Thumb_BL_candidates=scan_calls(image.stock,{0x405340,0x400e40,0x400e66}),
        caller_instruction_windows=[extract(image,0x23fee8,0x23ff82),extract(image,0x37597e,0x375994)],
        raw_BL_scan_excludes_neither_indirect_ARM_nor_conditional_callers=True,
        all_static_assertions_passed=True,new_runtime_executed=False,device_io=False,sounds_emitted=False,
        frozen_source_or_proof_modified=False,firmware_modified=False,install_candidate=False,
        limitations='Original file-backed local CFGs, literals, descriptors and exact callback ABI only. Runtime provenance is not inferred from source. No live BSS/device reads, new dispatch/sleep/GUI-main execution, whole current runtime final guards, visible root, touch/display, physical music or safe callback/module reclamation is established. Calls remain separately bounded; indirect targets are resolved only for the explicit immutable vtables and proposed adapter binding. GUI main broad startup depends on original platform/resource initialization and is not a substitute for the shortest guarded Dispatcher/MainMenu candidate.')
    path=ROOT/'staging/native-player-task-runtime-full/gui-foreground-boot-preflight.json'
    assert not path.exists(),'New proof exists; do not overwrite frozen output'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(path.relative_to(ROOT)),sha256=sha(path),source_sha256=sha(Path(__file__).resolve()),
                          complete_bounded_CFGs=len(functions),mixed_mode_CFGs=3,all_static_assertions_passed=True)))


if __name__=='__main__':
    main()
