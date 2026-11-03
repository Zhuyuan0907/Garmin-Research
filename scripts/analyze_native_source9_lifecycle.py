#!/usr/bin/env python3
"""Exact Taiwan source-9 WAV control/release preflight; static backup only.

Creates a new, non-installable analysis in the task-runtime-full namespace.
Never executes guest instructions, a loader, a Bluetooth service or audio I/O.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import array
import hashlib
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED


OUT = ROOT / 'staging/native-player-task-runtime-full/source9-lifecycle-preflight.json'
BRANCHES = {'b', 'beq', 'bne', 'bhs', 'blo', 'bhi', 'bls', 'bge', 'blt',
            'bgt', 'ble', 'bmi', 'bpl', 'bvs', 'bvc'}
RANGES = [
    (0x36AF4E, 0x36AF68), (0x36AF68, 0x36AF74),
    (0x36AF74, 0x36AFB6), (0x36AFB6, 0x36AFFC),
    (0x36B69A, 0x36B6D4), (0x36B720, 0x36B820),
    (0x270536, 0x27058A), (0x27058A, 0x27060A),
    (0x2709FE, 0x270A56), (0x27734A, 0x27735C),
    (0x277596, 0x277674), (0x277674, 0x277696),
    (0x277720, 0x277740), (0x2777B4, 0x2777F0),
    (0x277C6A, 0x277D26), (0x277D26, 0x277E20),
    (0x30EDD4, 0x30EDFE), (0x30EDFE, 0x30EE56),
    (0x3B9676, 0x3B967C), (0x388676, 0x388746),
    (0x388746, 0x3887A2), (0x3887A2, 0x3887A6),
    (0x388AF4, 0x388B22), (0x388E92, 0x388EC8),
    (0x388E32, 0x388E92), (0x38856E, 0x388676),
    (0x3880BC, 0x388144), (0x673D00, 0x673ED6),
    (0x5193C8, 0x51943E),
]


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


class RuntimeImage:
    def __init__(self, stock):
        self.stock = stock
        self.md = stock.md

    def read(self, address, length):
        return self.stock.read(self.stock.runtime_to_load(address, length), length)

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]


def row(image, ins):
    value = {'address': hex(ins.address), 'bytes': ins.bytes.hex(),
             'instruction': ins.mnemonic + ' ' + ins.op_str}
    if ins.mnemonic in ('bl', 'blx') and ins.operands[0].type == ARM_OP_IMM:
        value['direct_call'] = hex(ins.operands[0].imm)
        value['callee_mode'] = 'ARM' if ins.mnemonic == 'blx' else 'Thumb'
    if (ins.mnemonic == 'ldr' and len(ins.operands) == 2 and
            ins.operands[1].type == ARM_OP_MEM and
            ins.operands[1].mem.base == ARM_REG_PC):
        pointer = ((ins.address + 4) & ~3) + ins.operands[1].mem.disp
        value.update(literal_address=hex(pointer), literal_value=hex(image.word(pointer)))
    if ins.mnemonic == 'adr' and ins.operands[-1].type == ARM_OP_IMM:
        value['address_value'] = hex(((ins.address + 4) & ~3) + ins.operands[-1].imm)
    return value


def cfg(image, start, end):
    pending, seen, exits, returns = deque([start]), {}, [], []
    while pending:
        address = pending.popleft()
        if address in seen:
            continue
        if not start <= address < end:
            exits.append({'target': hex(address), 'reason': 'external branch'})
            continue
        assert len(seen) < 3000, 'bounded static instruction limit'
        ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
        assert ins is not None, hex(address)
        value = row(image, ins)
        seen[address] = value
        if ins.mnemonic in ('bl', 'blx'):
            if ins.operands[0].type != ARM_OP_IMM:
                value['indirect_call_unresolved'] = True
        elif ins.mnemonic in BRANCHES:
            assert ins.operands[0].type == ARM_OP_IMM
            pending.append(ins.operands[0].imm)
            if ins.mnemonic == 'b':
                continue
        elif ins.mnemonic == 'pop' and 'pc' in ins.op_str:
            returns.append(hex(address))
            continue
        elif ins.mnemonic == 'bx':
            if ins.op_str == 'lr':
                returns.append(hex(address))
            elif (ins.op_str == 'r3' and
                  seen.get(address - 2, {}).get('instruction') == 'pop {r3}'):
                returns.append(hex(address))
                value['original_LR_popped_to_r3_return'] = True
            else:
                exits.append({'address': hex(address), 'reason': 'indirect branch',
                              'instruction': ins.op_str})
            continue
        elif ARM_REG_PC in ins.regs_access()[1]:
            exits.append({'address': hex(address), 'reason': 'computed PC'})
            continue
        pending.append(address + ins.size)
    return {'entry': hex(start), 'bound_end': hex(end), 'entry_mode': 'Thumb',
            'backed_instruction_bytes_sha256': hashlib.sha256(
                b''.join(bytes.fromhex(seen[a]['bytes']) for a in sorted(seen))).hexdigest(),
            'instructions': [seen[a] for a in sorted(seen)], 'returns': returns,
            'unresolved_exits': exits, 'static_limit_reached': False,
            'callees_and_indirect_targets_not_recursively_executed': True}


def callers(stock, targets):
    """Verify candidates in all startup-backed non-data copy regions.

    This is a direct encoding inventory, not a complete code/data classification.
    Data resembling branches and indirect/overlay calls remain separate limits.
    """
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm.detail = True
    result = {hex(target): [] for target in targets}
    regions = []
    for section in stock.copies:
        if section['runtime_start'] == 0xF00000:
            continue
        base = section['runtime_start']
        raw = stock.read(section['load_start'], section['size'])
        regions.append({'runtime_start': hex(base), 'load_start': hex(section['load_start']),
                        'bytes': len(raw), 'conditional': section['conditional'],
                        'sha256': hashlib.sha256(raw).hexdigest()})
        half = array.array('H', raw[:len(raw) // 2 * 2])
        for index in range(len(half) - 1):
            upper, lower = half[index], half[index + 1]
            suffix = lower & 0xF800
            if upper & 0xF800 != 0xF000 or suffix not in (0xF800, 0xE800):
                continue
            displacement = ((upper & 0x7FF) << 12) | ((lower & 0x7FF) << 1)
            if displacement & 0x400000:
                displacement -= 0x800000
            address = base + index * 2
            target = (address + 4 + displacement if suffix == 0xF800 else
                      ((address + 4) & ~3) + (displacement & ~3))
            if target not in targets:
                continue
            ins = next(stock.md.disasm(raw[index * 2:index * 2 + 4], address, count=1), None)
            if (ins and ins.mnemonic in ('bl', 'blx') and
                    ins.operands[0].type == ARM_OP_IMM and ins.operands[0].imm == target):
                result[hex(target)].append({'address': hex(address), 'caller_mode': 'Thumb',
                                           'instruction': ins.mnemonic + ' ' + ins.op_str})
        for index, word in enumerate(array.array('I', raw[:len(raw) // 4 * 4])):
            is_blx = word & 0xFE000000 == 0xFA000000
            if not is_blx and word & 0x0F000000 != 0x0B000000:
                continue
            displacement = (word & 0xFFFFFF) << 2
            if displacement & 0x2000000:
                displacement -= 0x4000000
            address = base + index * 4
            target = address + 8 + displacement + (2 * ((word >> 24) & 1) if is_blx else 0)
            if target not in targets:
                continue
            ins = next(arm.disasm(raw[index * 4:index * 4 + 4], address, count=1), None)
            if (ins and ins.mnemonic in ('bl', 'blx') and
                    ins.operands[0].type == ARM_OP_IMM and ins.operands[0].imm == target):
                result[hex(target)].append({'address': hex(address), 'caller_mode': 'ARM',
                                           'instruction': ins.mnemonic + ' ' + ins.op_str})
    return result, regions


def main():
    assert not OUT.exists(), 'Preserve existing analysis; use a new namespace.'
    stock = NativeImage()
    image = RuntimeImage(stock)
    functions = {hex(start): cfg(image, start, end) for start, end in RANGES}
    assert functions['0x3887a2']['unresolved_exits'] == [
        {'target': '0x388746', 'reason': 'external branch'}]
    functions['0x3887a2']['unresolved_exits'] = []
    functions['0x3887a2']['resolved_tail_to_included_CFG'] = '0x388746'
    assert all(not f['unresolved_exits'] for f in functions.values())
    rows = {int(r['address'], 16): r for f in functions.values() for r in f['instructions']}
    def instruction(address, text):
        assert rows[address]['instruction'] == text, (hex(address), rows[address])
    def call(address, target):
        assert rows[address]['direct_call'] == hex(target), (hex(address), rows[address])

    veneers = {}
    for address, target in [(0x525F14, 0x27058B), (0x525F0C, 0x2709FF)]:
        assert image.word(address) == 0xE51FF004 and image.word(address + 4) == target
        veneers[hex(address)] = {'mode': 'ARM', 'instruction': 'ldr pc, [pc, #-4]',
                                'target_word': hex(target), 'target_mode': 'Thumb',
                                'target_body': hex(target & ~1),
                                'exact_bytes': image.read(address, 8).hex()}
    call(0x36B80A, 0x30EDFE)
    instruction(0x36B806, 'movs r1, #1')
    instruction(0x36B808, 'movs r0, #2')
    instruction(0x36B766, 'ldr r1, [r0, r4]')
    instruction(0x36B764, 'adds r0, #0x95')
    instruction(0x36B7EC, 'blx r1')
    call(0x36AFAC, 0x30EDD4)
    instruction(0x36AFA8, 'movs r1, #3')
    instruction(0x36AFAA, 'movs r0, #2')
    call(0x30EDF4, 0x37BCE4)
    instruction(0x30EDF8, 'movs r0, r4')
    instruction(0x30EDEC, 'movs r4, #0')
    call(0x30EE3C, 0x37BCE4)
    call(0x30EE46, 0x30ED30)
    instruction(0x2705CC, 'adds r0, #0x85')
    instruction(0x2705D8, 'blx r1')
    instruction(0x2705EC, 'ldr r4, [r4, #0x20]')
    instruction(0x2705F6, 'blx r4')
    assert rows[0x277DD4]['literal_value'] == '0x2777b5'
    assert rows[0x277DB6]['literal_value'] == '0x277c6b'
    assert rows[0x277DEC]['literal_value'] == '0x277379'
    assert rows[0x277DF4]['literal_value'] == '0x27734b'
    call(0x2777CA, 0x277720)
    call(0x277728, 0x277596)
    call(0x277734, 0x277596)
    call(0x277634, 0x3887A2)
    call(0x38877A, 0x427582)
    call(0x38878A, 0x388676)
    call(0x388766, 0x3008B0)
    call(0x388780, 0x3009A0)
    instruction(0x38873C, 'str r0, [r6]')
    instruction(0x38873A, 'movs r0, #0')
    instruction(0x388776, 'ldr r1, [r4, #0xc]')
    assert image.read(0x427582, 2) == bytes.fromhex('0847')
    call(0x673E70, 0x36AFB6)
    call(0x673E7A, 0x525F0C)
    call(0x673E90, 0x525F14)
    call(0x673E98, 0x36B720)
    call(0x673EA4, 0x36AF74)
    instruction(0x673E8C, 'movs r1, #0x16')
    instruction(0x673E8A, 'movs r2, #0xb')
    instruction(0x673E8E, 'movs r0, #9')
    instruction(0x673E80, 'movs r0, #0x26')
    path_address = int(rows[0x673E88]['literal_value'], 16)
    path_bytes = image.read(path_address, 38)
    assert path_bytes.decode('utf-16le').rstrip('\0') == '0:/Garmin/test.wav'
    call(0x519428, 0x53146C)
    call(0x519436, 0x36C00A)
    targets = {0x525F14, 0x27058A, 0x36B720, 0x36AF74,
               0x270536, 0x277D26, 0x388746, 0x388676}
    direct_callers, scan_regions = callers(stock, targets)
    assert any(c['address'] == '0x673e90' for c in direct_callers['0x525f14'])
    assert any(c['address'] == '0x673ea4' for c in direct_callers['0x36af74'])
    proof_paths = [
        'evidence/firmware-analysis/native-output-stop-emulation.json',
        'evidence/firmware-analysis/native-source-controller-emulation.json',
        'evidence/firmware-analysis/native-heap-callback-emulation.json',
        'staging/native-player-heap-callback/heap-release-static-preflight.json',
        'evidence/firmware-analysis/native-music-continuous-emulation.json',
        'staging/native-player-resources/manifest.json',
    ]
    deps = ['scripts/analyze_native_sections.py', 'native/player-resources/player_menu.c',
            'native/player-menu-loaded/entry.c', 'native/sbc-prototype/app_component_entry.c',
            'native/music-continuous/media_coordinator.c',
            'native/music-continuous/memory_output.c'] + proof_paths
    deps.append(str(Path(__file__).resolve().relative_to(ROOT)))
    mapping = image.read(0xACB12C, 18 * 28)
    matches = [index for index in range(18)
               if struct.unpack_from('<I', mapping, index * 28)[0] == 9]
    assert matches == [9], matches
    out = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': {'HWID': 1352, 'software': '8.00', 'MAIN_sha256': EXPECTED},
        'source_sha256': {p: sha(p) for p in sorted(set(deps))},
        'complete_bounded_CFG_count': len(functions), 'functions': functions,
        'veneer_resolution': veneers, 'direct_call_candidates': direct_callers,
        'direct_call_scan_regions': scan_regions,
        'source9_mapping': {'table': '0xACB12C', 'record_bytes': 28,
                            'matched_source_ID_row': matches[0],
                            'matched_ID': 9, 'source_record': hex(0x034E6F08 + 9 * 520),
                            'ID_lookup_must_not_be_replaced_with_generic_order_assumption': True},
        'verified_semantics': {
            'registration': {
                'ARM_entry': '0x525F14', 'Thumb_body': '0x27058A',
                'ABI': 'r0=source/channel ID; r1=kind; r2=flags; r3=parameter bytes; stack:length, metadata, bypass-range-check',
                'WAV_call': {'source_ID': 9, 'kind': 22, 'flags': 11,
                             'parameters_utf16': '0:/Garmin/test.wav', 'parameter_bytes': 38,
                             'metadata': 0, 'bypass_range_check': 0},
                'priority_is_not_the_kind22_argument': True,
                'behavior': 'Under channel+1C8 mutex, calls channel+184 clear-all method, then only on zero result calls channel+160 registration with list indexFFFF. Existing channel9 queue-driver initializer maps these methods to2777B5 and277C6B.',
                'generic_append270458_is_distinct': True,
                'parameter_bytes_copied_by_original277CD6_memcpy': True,
                'active_source_quiescence_not_checked_in_this_wrapper': True,
            },
            'start': {
                'Thumb_call_pointer': '0x36B721', 'body': '0x36B720',
                'behavior': 'Calls source-list start method at channel+194, then original synchronous30EDFE class2/opcode1, returns its response except source record byte2 zero forcesFFFF.',
                'is_stop_or_toggle_or_refresh': False,
                'caller_second_argument0_enables_range_check': True,
            },
            'stop': {
                'Thumb_call_pointer': '0x36AF75', 'body': '0x36AF74',
                'behavior': 'Calls original30EDD4 class2/opcode3 with parameter0 and channel record.',
                'asynchronous': True,
                'post_return0_does_not_verify_queue_send_or_stop_completion': True,
                'verified_reason': '30EDD4 ignores37BCE4 return, returns literal zero; request message completion pointer isNULL.',
                'does_not_clear_queue_or_release_source_nodes': True,
            },
            'query': {
                'busy_query_pointer': '0x36B69B', 'body': '0x36B69A',
                'state_getter': '0x3B9677',
                'busy_condition': 'valid source ID and native source-state byte >1',
                'not_full_quiescence': 'Does not inspect in-flight callbacks, mixer/driver/provider state or foreign source ownership.',
            },
            'clear': {
                'public_Thumb_pointer': '0x270537', 'body': '0x270536',
                'behavior': 'Under channel+1C8 mutex, invokes queue clear-all method at+184; original2777B4 obtains list mutex, loops277596(index0), then zeros head/count and sets queue indicesFFFF.',
                'release_chain': ['0x2777B4', '0x277720', '0x277596', '0x3887A2', '0x388746', '0x388676'],
                'not_an_audio_stop': True,
                'no_active_provider_quiescence_gate_in_clear_wrapper': True,
                'no_direct_free_of_PCM_or_UI_object_is_implied': True,
            },
            'queue_setting': {
                'ARM_entry': '0x525F0C', 'Thumb_body': '0x2709FE',
                'driver_method': 'channel+1A4=0x27734B after the traced initializer',
                'effect': 'Writes supplied second argument as queue-context+1A byte under native channel mutex.',
                'is_stop_or_free': False,
                'semantic_label_of_the_byte_not_recovered': True,
            },
            'heap_release': {
                'callback_dispatch': '0x388746', 'core_release': '0x388676',
                'wrapper': '0x3887A2 copies LR to diagnostic r1 then tails into388746',
                'ABI': 'r0=pointer to an opaque allocation handle; r1=diagnostic caller argument; core r2=validated descriptor',
                'callback_predicate': '(descriptor.pointer_and_flags &6)==6',
                'callback_r0': 'descriptor+4 payload pointer with low3 flags masked',
                'callback_target': 'descriptor+0C, via427582 BX r1',
                'callback_NULL_check': False,
                'callback_outside_heap_mutex_before_relock_and_core_release': True,
                'source_list_and_outer_channel_mutexes_can_still_be_held': True,
                'core_clears_callers_handle_word_to0': True,
                'core_changes_allocator_links_counters_and_can_reclaim_pages': True,
                'core_callees': ['0x388E32', '0x38856E', '0x3880BC'],
                'zero_callback_with_flags6_is_not_unregister': True,
                'is_source_stop_or_safe_module_unload': False,
                'low3_callback_truth_table': [{'flags': n, 'callback': (n & 6) == 6} for n in range(8)],
            },
        },
        'stock_UI_comparison': {
            'diagnostic_handler': '0x673D00',
            'WAV_branch': '0x673E5C',
            'start_branch_sequence': ['36AFB6(mode5)', '525F0C(9,1,0)',
                                      '525F14(9,22,11,path,38,0,0)', '36B720(9,0)'],
            'stop_branch': '673EA0:36AF74(9,0)',
            'native_button_state_is_toggled': True,
            'source9_mode_setter': '36AFB6; on changed mode0/2/5 stops9 and calls277D26(9,0,0); mode1 uses277D26(9,1,0)',
            'mode_setter_can_replace_source_driver_methods': True,
            'current_compiled_player_difference': 'native_player_menu_activate only register/start on every click; it has no mode/set-byte/toggle/stop/ownership/completion path.',
            'ordinary_audio_settings_action': '5193C8 selector0 allocates258C, constructs53146C, publishes through36C00A(parent,child,10); selector1 uses a separate dialog.',
            'ordinary_settings_action_is_not_an_audio_stop_or_generic_App_install_API': True,
        },
        'next_minimum_runtime_controls': [
            {'order': 1, 'test': 'Execute stock source9 mode/queue methods and register copy on native task, preserve current-owner/channel/queue inventory. Exercise occupied foreign source rejection in the new controller; never silently clear a diagnostic/navigation source.'},
            {'order': 2, 'test': 'UI start exactly once; register failure, native START response and initialized/source-state checks must keep controls truthful. Repeated click whileplaying requests stop instead of clear-register-start.'},
            {'order': 3, 'test': 'Execute36AF74 on source9, show queued class2/opcode3 and real actor/output completion. A zero API return and busy queryfalse are insufficient; wait for source-state1 plus inactive source/provider/mixer/driver, no in-flight reader/callback, before explicit serialized270536 clear.'},
            {'order': 4, 'test': 'Original277596 ->3887A2 ->388746 callback ->388676 completes on native task with valid opaque handle/backlink/guard words. Check pre-core callback ordering, descriptor flags6 NULL negative case, reentrant/delayed callback behavior under retained channel/list locks, handlezero and listcount/head updates.'},
            {'order': 5, 'test': 'Prove stop-clear-register-restart and failure recovery with full originalvoice40/private12/player2/code/DB/GUI/stack/canary guards; keep callback/module/font resources resident until future-callback exclusion is established.'},
        ],
        'recommendation_scope': 'Safest proposed control path is exclusive owner -> public asynchronousstop -> native completion/quiescence -> original serialized publicqueueclear -> guarded re-register/start. This ordering is an evidence-based proposal, not a recovered public App contract or a completed source9 runtime/speaker test.',
        'all_static_assertions_passed': True, 'static_only': True,
        'guest_execution_performed': False, 'big_loader_run': False,
        'device_io': False, 'sounds_emitted': False, 'device_install_candidate': False,
        'existing_sources_or_proofs_modified': False,
        'limits': 'Bounded exact-image CFGs and direct-call encoding inventory only. Native file-WAV decoder, source9 hardware/driver completion, full allocator execution, scheduler/concurrency, safe UI teardown/module unload and accepted VPM/SIG remain unverified. The callback/deallocator is generic heap lifetime, not audio stop. Conditional startup regions use exact copy mappings but live flags remain unknown. Callee semantics are scoped to listed functions; direct encodings can exist in data and do not exclude indirect callers. No audio replay, stereo/fidelity work, installation or device I/O.',
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output': str(OUT.relative_to(ROOT)), 'sha256': sha(str(OUT.relative_to(ROOT))),
                      'bounded_CFGs': len(functions), 'source_dependencies': len(out['source_sha256']),
                      'static_assertions_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
