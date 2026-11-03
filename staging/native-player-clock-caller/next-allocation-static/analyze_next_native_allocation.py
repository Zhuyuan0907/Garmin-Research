#!/usr/bin/env python3
"""Bounded file-only analysis of timer-object C++ allocations after native clock.

No VM import, guest execution, device access, canonical edit or allocator hook.
Only exact MAIN code and frozen source/contracts are read.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import json
import struct
from collections import deque
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent
OUT = BASE / 'next-native-allocation-contract.json'
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
EXPECTED = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
COUNT = 0


def require(value, reason):
    global COUNT
    COUNT += 1
    if not value:
        raise ValueError(reason)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


class Image:
    def __init__(self):
        require(sha(MAIN) == EXPECTED, 'Exact Taiwan HWID1352 SW8 MAIN')
        self.blob = MAIN.read_bytes()
        self.md = {False: Cs(CS_ARCH_ARM, CS_MODE_ARM), True: Cs(CS_ARCH_ARM, CS_MODE_THUMB)}
        for md in self.md.values():
            md.detail = True

    def read(self, address, size):
        offset = address - 0x50000
        require(0 <= offset and offset + size <= len(self.blob), 'File-backed span')
        return self.blob[offset:offset + size]

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]

    def instruction(self, pc, thumb):
        rows = list(self.md[thumb].disasm(self.read(pc, 4), pc, count=1))
        require(len(rows) == 1, 'Bounded original instruction: ' + hex(pc))
        return rows[0]

    def cfg(self, name, entry, ranges, thumb=True):
        work, seen, instructions, calls, edges, boundaries = deque([entry]), set(), [], [], [], []
        def inside(pc):
            return any(lo <= pc < hi for lo, hi in ranges)
        while work:
            pc = work.popleft()
            if pc in seen:
                continue
            if not inside(pc):
                boundaries.append(hex(pc))
                continue
            seen.add(pc)
            require(len(seen) <= 420, 'Local CFG cap, no unbounded recursion')
            i = self.instruction(pc, thumb)
            row = dict(PC=hex(pc), Thumb=thumb, opcode_hex=i.bytes.hex(), instruction=i.mnemonic + ' ' + i.op_str)
            if i.mnemonic == 'ldr' and len(i.operands) == 2 and i.operands[1].type == ARM_OP_MEM and i.operands[1].mem.base == ARM_REG_PC:
                literal = ((pc + (4 if thumb else 8)) & ~3) + i.operands[1].mem.disp
                row.update(literal_address=hex(literal), literal_value=hex(self.word(literal)))
            instructions.append(row)
            successors = []
            immediate = i.operands[0].imm if len(i.operands) == 1 and i.operands[0].type == ARM_OP_IMM else None
            if i.mnemonic in ('bl', 'blx'):
                calls.append(dict(PC=hex(pc), continuation=hex(pc + i.size), instruction=row['instruction'],
                    target=hex(immediate) if immediate is not None else None,
                    callee_mode='ARM' if i.mnemonic == 'blx' and immediate is not None else 'Thumb' if i.mnemonic == 'bl' and thumb else 'register target mode unknown'))
                successors = [pc + i.size]
            elif i.mnemonic == 'b':
                require(immediate is not None, 'Direct branch target')
                successors = [immediate]
            elif i.mnemonic.startswith('b') and i.mnemonic != 'bx':
                require(immediate is not None, 'Conditional branch target')
                successors = [pc + i.size, immediate]
            elif i.mnemonic == 'bx' or (i.mnemonic == 'pop' and 'pc' in i.op_str):
                row['terminal_transfer'] = True
            else:
                successors = [pc + i.size]
            for next_pc in successors:
                edges.append([hex(pc), hex(next_pc)])
                work.append(next_pc)
        return dict(name=name, entry=hex(entry), Thumb=thumb, original_ranges=[[hex(lo), hex(hi)] for lo, hi in ranges],
            instructions=sorted(instructions, key=lambda r: int(r['PC'], 16)), direct_or_indirect_calls=calls,
            edges=edges, bounded_exit_addresses=sorted(set(boundaries)),
            direct_calls_are_not_recursively_claimed_executed=True)


def main():
    image = Image()
    source_paths = [MAIN, Path(__file__).resolve(),
        ROOT / 'staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py',
        ROOT / 'staging/native-player-clock-caller/gui-static/clock-caller-observer-v2-contract.json',
        ROOT / 'scripts/probe_native_dispatcher_clock_caller.py',
        ROOT / 'scripts/probe_native_heap_settings_boot.py',
        ROOT / 'scripts/emulate_native_player_menu_loaded.py',
        ROOT / 'staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json']
    source = {rel(p): sha(p) for p in source_paths}
    require(source['staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py'] ==
        '1a3253998dbdee390aa99fadf53e9c2bdc1de806b417d7e3258372ad7780a0b1', 'Frozen clock helper v2 exact identity')
    old_heap = json.loads(source_paths[-1].read_text())
    old_raw_pairs = {(int(r['entry'], 16), int(r['continuation'], 16)) for r in old_heap['raw_mutex_calls']}
    require((0x3009a0, 0x38851c) not in old_raw_pairs and (0x3008b0, 0x388534) not in old_raw_pairs,
        'Allocation wrapper raw callers are absent from old heap table')
    require((0x3009a0, 0x388812) in old_raw_pairs and (0x3008b0, 0x388826) in old_raw_pairs,
        'Pointer-query raw callers exist, with old controller-only actor guard')
    specs = [
        ('C++ allocation ARM veneer', 0x3954cc, [(0x3954cc, 0x3954d4)], False),
        ('SCL malloc thunk', 0x2dc9ea, [(0x2dc9ea, 0x2dc9f4), (0x2dc954, 0x2dc982)], True),
        ('Containing timer-object function', 0x395520, [(0x395520, 0x39578e)], True),
        ('Native allocation mutex wrapper', 0x38850a, [(0x38850a, 0x38853c)], True),
        ('Native heap allocation with inline literal pool excluded', 0x3881bc,
            [(0x3881bc, 0x38846c), (0x38847c, 0x38850a)], True),
        ('Native handle pointer query', 0x388804, [(0x388804, 0x38882e)], True),
        ('Native handle validation', 0x388e92, [(0x388e92, 0x388ec8)], True),
        ('Native descriptor freelist pop', 0x388df2, [(0x388df2, 0x388e32)], True),
        ('Later 48-byte container constructor', 0x362a2c, [(0x362a2c, 0x362a90)], True),
        ('8-byte temporary deleting destructor', 0x38608e, [(0x38608e, 0x386096)], True),
        ('Delete wrapper', 0x386f14, [(0x386f14, 0x386f1c)], True),
        ('Delete ARM veneer', 0x395470, [(0x395470, 0x395478)], False),
        ('SCL free thunk', 0x2dc9ae, [(0x2dc9ae, 0x2dc9c6)], True),
        ('Native query completion', 0x388b22, [(0x388b22, 0x388b24)], True),
    ]
    functions = {hex(entry): image.cfg(name, entry, ranges, thumb) for name, entry, ranges, thumb in specs}
    exact = {0x3954cc:'00c09fe5', 0x3954d0:'1cff2fe1', 0x2dc9ec:'0822', 0x2dc9f0:'7346',
        0x2dc958:'8018', 0x2dc95c:'0092', 0x2dc97e:'ca63', 0x39552e:'3020',
        0x395530:'fff7ccef', 0x395534:'1390', 0x39553e:'0820', 0x395540:'fff7c4ef',
        0x395548:'0160', 0x39554a:'197c', 0x395550:'0171', 0x38851c:'db48',
        0x3884c0:'0460', 0x388448:'4462', 0x388e9a:'08d0', 0x388ec0:'2000',
        0x388804:'70b5', 0x38881a:'4068', 0x38881c:'c408', 0x38881e:'e400'}
    for pc, expected in exact.items():
        require(image.read(pc, len(bytes.fromhex(expected))).hex() == expected, 'Exact original opcode: ' + hex(pc))
    literals = {0x3954d4:0x2dc9eb, 0x2dcacc:0xf070b0, 0x395930:0xc1c0ec,
        0x38846c:0x3a7f170, 0x388894:0x3a7f18c, 0x395478:0x2dc9af}
    for address, expected in literals.items():
        require(image.word(address) == expected, 'Exact original literal: ' + hex(address))
    require(image.word(0xcb8a30) == 0, 'File-backed initialized F070B0 starts0, not zero-BSS')
    require(image.word(0xc1c0ec) == 0 and image.word(0xc1c0f0) == 0x38608f, 'Original 8-byte temporary vtable/deleting destructor')
    formula_controls = []
    for requested in (48, 8):
        for backing in (0x18302000, 0x18302038, 0x18302078):
            x = backing + 4
            pad = ((-x) & 7) & ~3
            returned = x + pad
            require(backing % 8 == 0 and returned == backing + 8 and returned % 8 == 0, 'Original masked pointer query guarantees8-aligned backing')
            require(returned + requested == backing + requested + 8 and returned - 4 == backing + 4,
                'Exact payload length and stored handle prefix')
            formula_controls.append(dict(input_kind='host-only arithmetic; not a live allocation', request=requested,
                lower_request=requested+8, example_backing=hex(backing), returned=hex(returned), handle_prefix=hex(returned-4)))
    raw_scopes = [
        dict(operation='acquire', original_call='0x388518', continuation='0x38851c', actual_LR='0x38851d',
            containing_function='0x38850a', SP='B-40', absent_from_old_table=True),
        dict(operation='release', original_call='0x388530', continuation='0x388534', actual_LR='0x388535',
            containing_function='0x38850a', SP='B-40', absent_from_old_table=True),
        dict(operation='acquire', original_call='0x38880e', continuation='0x388812', actual_LR='0x388813',
            containing_function='0x388804', SP='B-32', absent_from_old_table=False),
        dict(operation='release', original_call='0x388822', continuation='0x388826', actual_LR='0x388827',
            containing_function='0x388804', SP='B-32', absent_from_old_table=False),
    ]
    for row in raw_scopes:
        row.update(pointer='0x3a7f18c', whole_backend_bytes=24, tag='0x388d00', classification_byte22=0,
            actor='actual Dispatcher TCB D == word(F09090); no controller substitution',
            native_initializer='original388BCC ->3008A0/continuation388BD0 then tag store388BD2',
            actual_owner_before_and_after_and_stale_links_must_be_captured=True,
            retained_condition_token_allowed=False)
    contract = dict(all_passed=True, static_only=True, source_sha256=source, exact_MAIN_sha256=EXPECTED,
        exact_target=dict(region='Taiwan', HWID=1352, software='8.00'), bounded_CFG=functions,
        original_instruction_count=sum(len(r['instructions']) for r in functions.values()),
        original_opcode_assertions=len(exact), routine_assertion_count=COUNT,
        host_only_formula_controls=formula_controls,
        runtime_status='Root session5264 was reported live and had not reached3954CC at task assignment. No terminal or actual allocator registers are inputs to this static artifact.',
        allocation_chain=dict(entry='0x3954cc ARM; veneer preserves SP and LR', veneer_literal='0x3954d4=0x2dc9eb',
            thumb_thunk='0x2dc9ea reads word(F070B0), r2=8, r3=callerLR, tails2DC954',
            effective_ABI='r0=request bytes; r1=current F070B0 allocation flags; r2=alignment8; r3=actual original callerLR',
            flags_input=dict(runtime_address='0xf070b0', load_address='0xcb8a30', file_initialized_word=0,
                actual_before_value_required=True, zero_BSS=False, native_setter='0x2dc9fa stores r0; not called or assumed in this scope'),
            alignment='Native388804 returns Q=word(handle+4)&~7. P=((Q+4)+((-(Q+4)&7)&~3))=Q+8.',
            request='original38850A request N+8; return handle H and output stack word H; then original388804(H)',
            stored_prefix=dict(writer='0x2dc97e', address='P-4', value='actual live native handle H', instruction='str r2,[r1,#3c]; r1=P-40'),
            zeroing='None in2DC954/2DC9EA/3954CC. User payload before-bytes remain actual native heap contents.',
            native_query_completion='388B22 is BX LR and is not a pin/unpin lease;2DC954 does not call it.',
            original_return='2DC980 POP{r3,r4,r5,pc} restores B and original Thumb395535/395545 LR'),
        caller_shapes=[
            dict(original_call='0x395530 BLX3954CC', request=48, actual_LR='0x395535', continuation='0x395534', SP='B',
                returned_pointer_symbol='P48', result_store='395534 STR r0,[B+4C]', later_owner_copy='39553C STR r0,[B+28]',
                checked_for_NULL_before_use=False, later_initialization='3955A2 calls362A2C(P48,&stack[B+18],&stack[B+10]); this is a new bounded constructor/allocations, not initialized by malloc'),
            dict(original_call='0x395540 BLX3954CC', request=8, actual_LR='0x395545', continuation='0x395544', SP='B',
                returned_pointer_symbol='P8', checked_for_NULL_before_use=False,
                initial_writes=[dict(PC='0x395548', address='P8', size=4, value='literal395930=C1C0EC'),
                    dict(PC='0x395550', address='P8+4', size=1, value='actual byte at B+30 loaded39554A; no assumed0')],
                untouched_payload_gap='P8+5..P8+7 is not initialized in this prefix',
                lifetime='P8 published to stack B+10 at395556; later3955D0 loads it,3955D6/3955D8 load vtable+4,3955DA BLX ->38608F deleting destructor; return/free not yet admitted')],
        stack_shapes=dict(T='Actual395520 function-entry SP', B='T-128 after PUSH9(36)+SUB5C(92)',
            veneer_and_thunk_entry_SP='B', aligned_allocator_entry_SP='B', aligned_allocator_body_SP_and_output_cell='B-16',
            allocation_wrapper_entry_SP='B-16; caller2DC964, actual LR2DC965', allocation_wrapper_body_SP='B-40',
            heap_allocator_entry_SP='B-40; caller38852C, actual LR38852D', heap_allocator_body_SP='B-96',
            pointer_query_entry_SP='B-16; caller2DC96A, actual LR2DC96B', pointer_query_body_SP='B-32',
            descriptor_validator_body_SP='B-48; caller38881A, actual LR38881B',
            all_SP_values_are_symbolic_until_actual_native_entry_capture=True),
        exact_future_native_raw_scopes=raw_scopes,
        descriptor_and_heap_requirements=dict(
            workspace='3A7F170 whole96 bytes initialized by original388B24/388B6C using explicit root offline extent; no physical heap claim',
            first_fit='3881BC selects an existing free descriptor using bins, removes it388144; a split calls388DF2 for a native24-byte descriptor',
            descriptor_pool='388DF2 pops workspace+0C native24-byte freelist; if empty it calls38806C for a4096-byte page and writes up to170 descriptors',
            descriptor_validation='388E92 requires H nonnull, low3(word(H+4))>=4 and word(word(H+8))==H; invalid branch releases raw then calls23D6E8',
            query='38881A..38881E masks descriptor address low3 before returning backing Q',
            flags0_owner_tracking='If actual flags bit0=0,388444/388448 adds H to actual currentTCB+24(hex) chain; prior H+10 link may be updated. TCB whole108 and old/new whole24 descriptor journals must retain precise provenance.',
            required_before_ranges=['workspace96', 'raw backend24', 'actual D TCB108', 'actual free/native allocated descriptor24', 'selected backing N+8 including tag prefix', 'prior owned-list descriptor24 if present'],
            no_generic_BSS_or_raw_heap_write_allowance=True),
        failure_contract=dict(
            allocator_output_cleared='3881C8/3881CA clears nonnull output cell first; original2DC954 initialized it0 already',
            missing_free_descriptor='3883D6→3884EC; flags-derived branch may call diagnostic23D6E8, then388500 returns r4(0) only if diagnostic returns',
            diagnostic_runtime_semantics_unknown=True,
            no_null_guard='2DC964 immediately queries handle via388804; it does not test returned handle/status. Invalid descriptor enters388E92 diagnostic path. Both395520 callers also do not test NULL.',
            required_behavior_for_next_harness='Unknown/null/diagnostic is a new explicit boundary or terminal failure. Do not host-return0/success, manufacture pointer, or reinterpret as firmware fault.'),
        precise_next_source_boundaries=[
            dict(path='staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py', line=278,
                reason='Existing correct hardstop records request/SP/LR then rejects both exact allocation callers. Frozen helper unchanged.'),
            dict(path='scripts/emulate_native_player_menu_loaded.py', line=79,
                reason='Removing only that stop falls through to inherited raw_allocate: host A5 backing and self.ret(pointer), not original veneer/native heap. Separate future source must intercept dispatch before this provider while preserving unrelated old fixtures.'),
            dict(path='scripts/probe_native_heap_settings_boot.py', line=141,
                reason='exact_raw() requires current actor controller.38850A pairs38851C/388534 absent from11 old raw rows;388804 pairs present but controller-only. New D containing-frame scope needed, parent epilogue/pending ledgers must remain.'),
        ],
        later_unadmitted_boundaries=[
            dict(call='0x3955a2', callee='0x362a2c', inputs='P48, B+18, B+10',
                subsequent_original_allocations=[dict(call='0x362a3c', request=60, continuation='0x362a40'), dict(call='0x362a58', request=16, continuation='0x362a5c')],
                original_failure_checks=False, allowed_by_this_artifact=False),
            dict(call='0x3955da', callee='vtable(P8)+4=38608F when unchanged',
                chain='38608E→386F14 Thumb→BLX395470 ARM→2DC9AE Thumb reads H=P8-4→388746 native free',
                inherited_fixture_free_must_not_be_mixed_with_native_handle_provenance=True, allowed_by_this_artifact=False),
            dict(call='0x3956a6', callee='0x3954cc', request=36, continuation='0x3956aa',
                branch='later timer-record/list route; source-only, not covered by first two callers', allowed_by_this_artifact=False),
        ],
        provenance_cautions=[
            'B+30 and B+2C reserved stack bytes are read before initialized by this bounded function prefix. Their actual before-images must be captured; source alone does not establish zero.',
            'Native heap payload need not equal inherited host A5 raw allocation fixtures. Preserve actual bytes and separate these provider/lifetime types.',
            'Initialized F070B0 file value0 does not establish current runtime flags. Read actual before value under current D and preserve CPU history.',
            'The original containing395520 function includes more allocations, indirect callbacks and list writes. This static CFG is not a runtime closure or permission to admit them.',
        ],
        guest_execution=False, VM_instantiated_or_runner_imported=False, device_io=False,
        allocator_executed_in_current_run=False, constructor_return_or_foreground_or_physical_App_verified=False,
        existing_source_proof_or_canonical_modified=False)
    with OUT.open('x') as stream:
        json.dump(contract, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(all_passed=True, static_only=True, output=rel(OUT), sha256=sha(OUT),
        functions=len(functions), instructions=contract['original_instruction_count'], host_formula_cases=len(formula_controls))))


if __name__ == '__main__':
    main()
