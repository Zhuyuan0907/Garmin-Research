#!/usr/bin/env python3
"""Resolve bounded native cable-state worker switches from exact stock bytes.

This analysis joins a separate original-code emulation with task descriptor,
switch tables, default callbacks and board-control indirection. Register names
come from a primary MUSB source comparison and remain an inference, not a live
chip identification. No USB host absence or whole-firmware claim is made.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from capstone.arm import ARM_OP_IMM, ARM_REG_PC, ARM_INS_B, ARM_INS_BL, ARM_INS_BLX
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import describe, BRANCHES

SWITCHES = {
    0x323ab0: (0x323ab4,5),
    0x323758: (0x32375c,9),
    0x3237e2: (0x3237e4,9),
    0x322e52: (0x322e54,14),
}


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cfg(image, start, end):
    pending, seen, exits, returns = deque([start]), {}, [], []
    while pending:
        address = pending.popleft()
        if address in seen:
            continue
        if not start <= address < end:
            exits.append({'target':hex(address),'reason':'External branch'})
            continue
        require(len(seen) < 3000, 'Instruction limit reached')
        i = next(image.md.disasm(image.read(address,4),address,count=1),None)
        require(i is not None, 'Undecodable stock instruction')
        row = describe(image,i)
        seen[address] = row
        if address in SWITCHES:
            require(i.mnemonic == 'add' and i.op_str == 'pc, r3', 'Stock switch body differs')
            table, count = SWITCHES[address]
            raw = list(image.read(table,count))
            targets = [address+4+2*b for b in raw]
            row.update(switch_table=hex(table),switch_bytes=raw,
                       switch_targets=[hex(target) for target in targets])
            pending.extend(targets)
            continue
        if i.id in (ARM_INS_BL,ARM_INS_BLX):
            if i.operands[0].type != ARM_OP_IMM:
                row['indirect_call_not_resolved'] = True
        elif i.mnemonic in BRANCHES:
            require(i.operands[0].type == ARM_OP_IMM, 'Unexpected indirect branch')
            pending.append(i.operands[0].imm)
            if i.mnemonic == 'b':
                continue
        elif i.mnemonic == 'pop' and 'pc' in i.op_str:
            returns.append(hex(address))
            continue
        elif i.mnemonic == 'bx':
            if i.op_str == 'lr':
                returns.append(hex(address))
            else:
                exits.append({'address':hex(address),'reason':'Indirect tail or interworking branch',
                              'instruction':i.op_str})
            continue
        elif ARM_REG_PC in i.regs_access()[1]:
            exits.append({'address':hex(address),'reason':'Computed PC not resolved'})
            continue
        pending.append(address+i.size)
    return {'entry':hex(start),'bound_end':hex(end),
            'instructions':[seen[a] for a in sorted(seen)],'returns':returns,
            'unresolved_exits':exits,'instruction_limit_reached':False,
            'indirect_calls_and_callees_not_recursively_executed':True}


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    ranges = [
        (0x332216,0x3322a0),(0x322f0e,0x322f30),(0x322edc,0x322efa),
        (0x323098,0x3230d4),(0x323818,0x3238e0),(0x323a6a,0x323c54),
        (0x3236d4,0x323818),(0x322e2c,0x322e76),(0x3230fc,0x3230fe),
        (0x3230fe,0x323100),(0x21289c,0x2128ac),(0x212740,0x21279c),
        (0x21279c,0x212808),(0x2129f8,0x212a0a),(0x212a1c,0x212a2e),
        (0x332012,0x33202a),
    ]
    functions = {hex(a):cfg(image,a,b) for a,b in ranges}
    expected_open = {'0x21289c','0x2129f8','0x212a1c'}
    require({name for name,f in functions.items() if f['unresolved_exits']} == expected_open,
            'Unexpected bounded flow gaps')
    worker = {int(r['address'],16):r for r in functions['0x323a6a']['instructions']}
    require(worker[0x323ab0]['switch_targets'] ==
            ['0x323aba','0x323ac2','0x323c30','0x323c38','0x323c40'], 'Worker switch differs')
    require(worker[0x323ad8]['direct_call'] == '0x3236d4' and
            worker[0x323ae8]['direct_call'] == '0x322e2c', 'Type-one dispatch differs')
    require(image.word(0x89e194) == 0x323a6b, 'Task descriptor entry differs')
    emu_name = 'evidence/firmware-analysis/native-usb-transition-emulation.json'
    emu = json.loads((ROOT/emu_name).read_text())
    require(emu['all_passed'] and not emu['device_io'], 'Offline transition proof absent')
    for name, expected in emu['source_sha256'].items():
        require(sha((ROOT/name).read_bytes()) == expected, 'Transition proof dependency changed: '+name)
    sources_name = 'sources/native-usb/source-snapshots.json'
    sources = json.loads((ROOT/sources_name).read_text())
    for source in sources['files']:
        require(sha((ROOT/source['path']).read_bytes()) == source['sha256'], 'Primary source changed')
    regs = (ROOT/'sources/native-usb/musb_regs.h').read_text()
    require('#define MUSB_POWER\t\t0x01' in regs and
            '#define MUSB_POWER_SOFTCONN\t0x40' in regs, 'MUSB primary register definition differs')
    deps = {Path(__file__).resolve(),ROOT/emu_name,ROOT/sources_name}
    deps.update(ROOT/name for name in emu['source_sha256'])
    deps.update(ROOT/source['path'] for source in sources['files'])
    for module in list(sys.modules.values()):
        filename = getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent == ROOT/'scripts' and filename.endswith('.py'):
            deps.add(Path(filename).resolve())
    output = {
        'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'functions':functions,
        'task_link':{'initializer':'0x323098','stock_descriptor':'0x89e194',
            'descriptor_entry_word':'0x323a6b','runtime_task_handle_slot':'0xf07104',
            'queue_publication_gate':'0x322edc','queue_send_boundary':'0x37bce4',
            'worker':'0x323a6a','queue_pop_boundary':'0x37bc00',
            'actual_kernel_scheduling_or_queue_delivery_verified':False},
        'type_one_message':{'bytes':6,
            'fields':['kind=1','channel','old_type','new_type','old_predicate','new_predicate'],
            'worker_dispatch':'0x3236d4','when_new_predicate_zero_also_calls':'0x322e2c',
            'publication_wrapper_ignores_queue_helper_return':True,
            'three_identical_candidate_samples_required':True,
            'policy_fixture11_bypasses_publication_gate':True,
            'not_an_actual_phone_USB_host_transfer':True},
        'callbacks':{'channels':4,'types_per_channel':14,'profile_bytes':0x4b40,
            'channel_stride':0x12d0,'type_stride':0x158,'close_offset':4,'open_offset':8,
            'TypeA_Audio_Ethernet_default_callbacks_exact_BX_LR':True,
            'TypeA_TypeB_predicates':{'TypeA':0,'TypeB':1},
            'default_table_does_not_prove_all_other_paths_lack_host_or_audio':True,
            'native_host_enumeration_control_AOA_or_bulk_backend_found_in_this_trace':False},
        'board_control_indirection':{'RAM_vector':'0x2cf4330','bytes':0x70,
            'selector':'0x21289c','selector3_constructor':'0x212740',
            'other_selector_constructor':'0x21279c','selectors_are_fixtures':True,
            'unknown_actual_board_selection_or_target_IO_semantics':True,
            'not_claimed_as_a_USB_host_driver_table':True},
        'register_comparison':{'native_toggle':'0x332012','register':'0x10200001',
            'mask':64,'comparison_source':'sources/native-usb/musb_regs.h',
            'inference':'Offset1/mask0x40 match MUSB POWER.SOFTCONN, not a VBUS drive or host-mode switch.',
            'controller_model_or_live_register_identity_verified':False,
            'device_power_bit_toggle_not_host_AOA_proof':True},
        'primary_sources':sources['files'],'all_assertions_passed':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'scope':'Bounded stock cable-state task/worker with four resolved byte-table switches. '
            'Native debounce/profile/vector construction are separately executed on synthetic state. '
            'Publication/notification/logging are fixtures; task/kernel dequeue and nondefault '
            'callbacks are not executed. MUSB register terminology is a primary-source comparison '
            'inference. No actual host/AOA/VBUS/ADC/speaker/phone or installation.'}
    path = ROOT/'evidence/firmware-analysis/native-usb-transition-static.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'output':str(path.relative_to(ROOT)),'bounded_functions':len(functions),
        'local_flows_resolved':len(functions)-len(expected_open),'resolved_switches':len(SWITCHES),
        'explicit_indirect_or_external_exits':sum(len(f['unresolved_exits']) for f in functions.values()),
        'source_dependencies':len(deps)}))


if __name__ == '__main__':
    main()
