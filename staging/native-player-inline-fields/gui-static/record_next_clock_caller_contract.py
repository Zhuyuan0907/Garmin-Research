#!/usr/bin/env python3
"""Record sealed-file evidence plus a narrow prospective native clock contract.

No VM driver/observer is imported; no guest or device is executed. This keeps
the completed inline prefix separate from the unexecuted new clock body and
the prospective allocations following that read.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, struct, sys

ROOT = Path(__file__).resolve().parents[3]
BASE = 'staging/native-player-inline-fields/'
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB


def sha(path):
    h = hashlib.sha256()
    with (ROOT/path).open('rb') as handle:
        while chunk := handle.read(1024*1024):
            h.update(chunk)
    return h.hexdigest()


def clock_shape(function_sp, clock_word, actor, current, entry_sp, lr):
    """Only the original 395520 -> 353A9C call, never all clock callers."""
    assert actor == current == 0x8804FB8
    assert function_sp % 4 == 0 and function_sp == 0x8804030
    assert entry_sp == function_sp - 128 and lr == 0x39552D
    assert clock_word == 0
    return dict(entry=0x353A9C, call=0x395528, continuation=0x39552C,
                entry_SP=entry_sp, containing_function=0x395520,
                actual_containing_entry_SP=function_sp, native_return_r0=0,
                clock_address=0xF09098, actor=actor, current=current,
                require_Thumb=True, host_tick_or_return_allowed=False)


def main():
    out = BASE+'gui-static/next-clock-caller-contract.json'
    assert not (ROOT/out).exists(), 'Preserve previous contract'
    meta_path = BASE+'runtime/terminal-metadata.json'
    meta = json.loads((ROOT/meta_path).read_text())
    terminal = json.loads((ROOT/meta['probe']).read_text())
    receipt = json.loads((ROOT/meta['terminal_tool_receipt']).read_text())
    actual = receipt['actual_exec_result']
    assert meta['authoritative_terminal_result_received_from_exec'] is True
    assert meta['session_id'] == receipt['session_id'] == 35110
    assert 'session_id' not in actual
    assert meta['actual_exec_chunk'] == actual['chunk_id'] == '1f9e62'
    assert meta['terminal_exit_code'] == actual['exit_code'] == 1
    assert not terminal['completed'] and terminal['cold_prefix_full_guards_passed']
    assert terminal['error'] == 'Dispatcher actor observer: Missing actual containing-function entry 0x38d4be'
    regs = terminal['registers']
    assert regs == dict(r0='0x8804070', r1='0x8811754', r2='0x8804058',
                       r3='0xea60', lr='0x39552d', pc='0x353a9c', sp='0x8803fb0')

    stock = NativeImage()
    decoders = {True: Cs(CS_ARCH_ARM, CS_MODE_THUMB), False: Cs(CS_ARCH_ARM, CS_MODE_ARM)}
    def code(start, count, thumb=True):
        result = []
        for ins in decoders[thumb].disasm(stock.read(start, count), start):
            result.append(dict(PC=hex(ins.address), opcode_hex=ins.bytes.hex(),
                               instruction=ins.mnemonic+' '+ins.op_str, Thumb=thumb))
        assert sum(len(bytes.fromhex(r['opcode_hex'])) for r in result) == count
        return result
    sfs_code = code(0x26DD3E, 0x22)
    wrapper_code = code(0x39578E, 0x2A)
    function_prefix = code(0x395520, 0x32)
    getter = code(0x353A9C, 6)
    veneer = code(0x3954CC, 8, False)
    aligned_api = code(0x2DC9EA, 10)
    assert getter == [dict(PC='0x353a9c', opcode_hex='0149', instruction='ldr r1, [pc, #4]', Thumb=True),
                      dict(PC='0x353a9e', opcode_hex='0868', instruction='ldr r0, [r1]', Thumb=True),
                      dict(PC='0x353aa0', opcode_hex='7047', instruction='bx lr', Thumb=True)]
    assert stock.word(0x353AA4) == 0xF09098
    assert stock.word(0x223A10) == 0xE34
    assert stock.word(0x26E0C4) == 0xEA60
    assert stock.word(0x3954D4) == 0x2DC9EB
    assert stock.word(0x395934) == 0xF720A4
    exact = {int(r['PC'],16): r for r in sfs_code+wrapper_code+function_prefix}
    assert exact[0x26DD5C]['instruction'] == 'bl #0x39578e'
    assert exact[0x3957B2]['instruction'] == 'bl #0x395520'
    assert exact[0x395528] == dict(PC='0x395528', opcode_hex='bef7b8fa', instruction='bl #0x353a9c', Thumb=True)
    assert exact[0x395530]['instruction'] == exact[0x395540]['instruction'] == 'blx #0x3954cc'

    stack = terminal['body_zone_journals'][str(0x8801024)]
    start = int(stack['start'],16)
    before = bytes.fromhex(stack['before_hex'])
    replay = bytearray(before)
    for event in stack['stores']:
        offset = int(event['address'],16)-start
        n = event['size']
        assert 0 <= offset and offset+n <= len(replay)
        assert replay[offset:offset+n].hex() == event['before_hex']
        replay[offset:offset+n] = event['value'].to_bytes(n,'little')
    partial = [r for r in terminal['partial_body_zone_verification'] if r['start'] == stack['start']]
    assert len(partial) == 1 and partial[0]['whole_zone_replayed']
    assert hashlib.sha256(replay).hexdigest() == partial[0]['after_sha256']
    def words(pointer,n):
        return list(struct.unpack('<'+str(n)+'I', replay[pointer-start:pointer-start+4*n]))
    outer_push = [r for r in stack['stores'] if r['PC']=='0x39578e']
    inner_push = [r for r in stack['stores'] if r['PC']=='0x395520']
    assert len(outer_push)==6 and len(inner_push)==9
    for events, low, pc, opcode, values in (
            (outer_push,0x8804030,0x39578E,'f8b5',
             [1,0x3AAED08,0x3AAF828,0,0x3AAF808,0x26DD61]),
            (inner_push,0x880400C,0x395520,'ffb5',
             [0x8804070,0x8811754,0x8804058,0xEA60,0xEA60,0x8804070,0x8804058,1,0x3957B7])):
        for index,(event,value) in enumerate(zip(events,values)):
            assert (int(event['address'],16), event['size'],event['value']) == (low+4*index,4,value)
            assert event['Thumb'] and event['processor_mode']==31 and event['running_task']=='0x8804fb8'
            assert event['opcode_hex']==opcode and stock.read(pc,2).hex()==opcode
    assert words(0x880400C,9) == [r['value'] for r in inner_push]
    assert words(0x8804030,1)==[1] and words(0x8804044,1)==[0x26DD61]
    assert terminal['recent'][-7:] == [hex(p) for p in (0x3957B0,0x3957B2,0x395520,0x395522,0x395524,0x395526,0x395528)]
    sfs = next(r for r in terminal['body_actor_observations']['settings_actor_observer']['frame_history']
               if r['entry']=='0x26dce8')
    assert sfs['SP']==0x8804090 and not sfs['returned']

    bank = terminal['partial_initialized_bank_verification']
    bank_bytes = bytearray.fromhex(terminal['mutable_bank_initial_before_hex'])
    assert hashlib.sha256(bank_bytes).hexdigest()==bank['before_sha256']
    for event in bank['stores']:
        offset = int(event['address'],16)-0xF00000
        n = event['size']
        assert bank_bytes[offset:offset+n].hex()==event['before_hex']
        bank_bytes[offset:offset+n] = event['value'].to_bytes(n,'little')
    assert hashlib.sha256(bank_bytes).hexdigest()==bank['after_sha256']
    clock_events=[r for r in bank['stores'] if int(r['address'],16)<0xF0909C and 0xF09098<int(r['address'],16)+r['size']]
    assert not clock_events and bank_bytes[0x9098:0x909C]==bytes(4)

    valid=(0x8804030,0,0x8804FB8,0x8804FB8,0x8803FB0,0x39552D)
    controls=[dict(name='exact_native_currentD_frame_clock0',accepted=True,shape=clock_shape(*valid))]
    for name,index,value in [('wrong_containing_SP',0,0x8804034),('unreviewed_clock_input',1,20),
                             ('wrong_actor',2,0x9503F90),('wrong_current',3,0x9503F90),
                             ('wrong_call_SP',4,0x8803FB4),('old_manager_caller',5,0x38D913)]:
        args=list(valid);args[index]=value
        try:clock_shape(*args)
        except AssertionError:controls.append(dict(name=name,accepted=False,expected_rejection=True))
        else:raise AssertionError('Pure shape failed to reject '+name)

    parent_path='staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py'
    lines=(ROOT/parent_path).read_text().splitlines()
    assert 'if address==0x353A9C:' in lines[347]
    assert "self._da_frame(0x38D4BE)['SP']" in lines[349]
    assert not terminal['body_actor_observations']['frames'][str(0x38D4BE)]
    old_proof_path=BASE+'gui-static/inline-fields-observed-prefix.json'
    old_proof=json.loads((ROOT/old_proof_path).read_text())
    assert old_proof['all_passed'] and old_proof['both_actual_returns_seen']
    assert old_proof['next_unreviewed_entry'] is None and old_proof['next_unreviewed_writer'] is None
    source=str(Path(__file__).resolve().relative_to(ROOT))
    paths=[source,meta_path,meta['probe'],meta['terminal_tool_receipt'],meta['runner'],meta['runner_snapshot'],
           old_proof_path,BASE+'gui-static/verify_inline_fields_observed_prefix_v2.py',parent_path,
           'staging/native-player-dispatcher-fp/gui-static/dispatcher_actor_shapes.py',
           'scripts/probe_native_mainmenu_controller.py','scripts/emulate_native_player_menu_loaded.py',
           'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin']
    dependencies={p:sha(p) for p in paths}
    for p,h in dependencies.items():
        if p in meta['source_sha256']:assert h==meta['source_sha256'][p]
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=dependencies,
        exact_MAIN_sha256=EXPECTED,all_file_assertions_passed=True,
        static_scope_only=True,guest_execution=False,VM_module_imported_or_instantiated=False,device_io=False,
        source_bound_current_actor_entry_check_passed_before_parent_failure=True,
        authoritative_terminal=dict(session_id=35110,actual_exec_chunk='1f9e62',exit_code=1,
            registers=regs,error=terminal['error'],new_boundary_is_firmware_fault=False),
        sealed_inline_proof_field_erratum=dict(path=old_proof_path,
            next_unreviewed_entry_in_sealed_proof=None,reason='Reader used registers.PC; real schema is registers.pc.',
            proof_was_not_modified=True,actual_terminal_entry='0x353a9c',actual_write_target=None),
        exact_observer_boundary=dict(path=parent_path,line=348,
            failing_frame_lookup_line=350,unconditional_entry='0x353a9c',
            old_function='0x38d4be',old_function_live_frames=0,old_function_already_returned=True,
            old_manager_clock_continuations=['0x38d912','0x38d91e'],
            new_caller='0x395528',new_continuation='0x39552c',
            actual_failure_happens_before_clock_shape_checks_new_caller=True),
        observed_native_call_chain=[dict(entry='0x26dce8',SP='0x8804090',body_SP='0x8804048',delta=72),
            dict(call='0x26dd5c',entry='0x39578e',SP='0x8804048',LR='0x26dd61',body_SP='0x8804030',delta=24,
                native_push=outer_push),
            dict(call='0x3957b2',entry='0x395520',SP='0x8804030',LR='0x3957b7',body_SP='0x8803fb0',delta=128,
                native_push=inner_push,entry_arguments=[regs['r'+str(n)] for n in range(4)],stack_fifth_argument=1),
            dict(call='0x395528',entry='0x353a9c',SP='0x8803fb0',LR='0x39552d',
                original_opcode='bef7b8fa',direct_call=True,original_getter_body_executed_on_this_route=False)],
        argument_provenance=dict(r0='Native SFS bodySP+0x28, pointer0x8804070',
            r1='Actual manager0x8810920 virtual method223A08 returns manager+0xE34=0x8811754',
            r2='Native SFS bodySP+0x10, pointer0x8804058; descriptor produced by212324',
            r3='Literal26E0C4=0xEA60, moved through native wrapperR4; time units are not established',
            fifth='Native3957B0 STRr7,[SP], value1; 395524 reads bodySP+0x80'),
        actual_before_value_replayed_stack=dict(start=stack['start'],bytes=len(before),CPU_stores=len(stack['stores']),
            after_sha256=hashlib.sha256(replay).hexdigest(),matches_actual_after_SHA=True),
        native_clock_input=dict(address='0xf09098',captured_before_hex='00000000',terminal_replayed_hex='00000000',
            cumulative_initialized_bank_CPU_events=len(bank['stores']),clock_CPU_events=clock_events,
            whole_bank_replayed_after_sha256=hashlib.sha256(bank_bytes).hexdigest(),
            native_getter_reads_only=True,clock_host_write_allowed=False,actual_getter_return_observed=False),
        minimum_next_contract=dict(shape=clock_shape(*valid),
            capture_entry_before_execution=['26DCE8 existing SFS frame','39578E with exactLR26DD61/SP=SFSentry−72',
                '395520 with exactLR3957B7/SP=wrapperentry−24'],
            entry='Observe actual353A9C only with caller39552C and live395520 frame/bodySP=T−128; returnTrue bypasses inherited host+20 observer but native three instructions execute.',
            native_actual_return='At39552C require same currentD/Thumb/SP, R0=0, R1=F09098, R2/R3 preserved; immutable bodybytes0149/0868/7047 and literal353AA4=F09098.',
            original_stack_store='39552C STRr0,[SP,#3C] to0x8803FEC, size4/value0; bind native return before admitting result write.',
            no_guest_context_mutation=True,no_synthetic_frame_or_host_return=True,
            old_manager_clock_guards_must_remain=True,all_other_clock_callers_remain_unreviewed=True),
        prospective_allocations=dict(observed_on_new_route=False,
            first=dict(call='0x395530',entry='0x3954cc',ARM_entry=True,return_PC='0x395534',
                SP='0x8803fb0',relative_SP='395520entry−128',R0_request=48,
                result_store_PC='0x395534',result_cell='0x8803ffc'),
            second=dict(call='0x395540',entry='0x3954cc',ARM_entry=True,return_PC='0x395544',
                SP='0x8803fb0',R0_request=8,result_vtable_store_PC='0x395548',vtable_literal='0x395930',vtable='0xc1c0ec'),
            original_API_route='ARM3954CC LDRip,[PC]/BXip literal3954D4=2DC9EB; Thumb2DC9EA selects heap and alignment8 then tailbranches2DC954.',
            current_inherited_provider='LoadedPlayerVM menu_hooks[3954CC] raw_allocate supplies finite guarded backing/host return; not a native heap-allocation proof.',
            strict_followup='Capture exact395520 liveframe/currentD/SP/request/caller before allowing this provider call; each actual original caller continuation must bind unique live length48/8 allocation and guard. Do not broaden393A3E manager allocator scope.',
            scope_admitted_by_this_artifact=False),
        next_after_allocations_unclosed=['3619BC copied descriptor conversion','39132A query and3819D4 conditional allocation',
            '362A2C caller3955A2 container constructor', 'indirect original-descriptor cleanup callbacks'],
        bounded_original_instructions=dict(SFS_after_settings=sfs_code,wrapper=wrapper_code,
            timer_object_constructor_prefix=function_prefix,clock_getter=getter,allocator_ARM_veneer=veneer,
            allocator_aligned_API=aligned_api,manager_E34_accessor=code(0x223A08,6)),
        pure_host_controls=controls,full_dispatcher_body_or_foreground_verified=False,
        constructor_return_verified=False,physical_App_hardware_or_install_verified=False)
    with (ROOT/out).open('x') as handle:
        json.dump(doc,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps(dict(path=out,sha256=sha(out),source_sha256=sha(source),
                         all_file_assertions_passed=True,pure_host_controls=len(controls),guest_execution=False)))


if __name__=='__main__':
    main()
