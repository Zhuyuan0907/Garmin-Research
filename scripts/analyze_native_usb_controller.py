#!/usr/bin/env python3
"""Bound stock peripheral IRQ/EP0 control flow; do not infer a host stack."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
import analyze_native_usb_transition as usb_cfg
from analyze_native_display_path import arm_cfg


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    # ADD r3,pc; LDRB r3,[r3,#4] at1BCCEC/EE uses a table at1BCCF4.
    # The computed ADD-PC at1BCCF2 uses1BCCF6 as its branch base.
    assert list(image.read(0x1bccf4,6)) == [98,17,2,61,102,29]
    usb_cfg.SWITCHES[0x1bccf2] = (0x1bccf4,6)
    ranges = [(0x1bb0d6,0x1bb0f8),(0x1bb154,0x1bb176),(0x1bb176,0x1bb210),
        (0x1bb22c,0x1bb2d4),(0x1bcf6c,0x1bd0f2),(0x1bcc12,0x1bcc38),
        (0x1bcc38,0x1bcf6c),(0x1bd120,0x1bd14e),(0x1bd0f2,0x1bd118),
        (0x1bcb40,0x1bcc12),(0x1bcb20,0x1bcb30),(0x1bd118,0x1bd120)]
    functions = {hex(a):usb_cfg.cfg(image,a,b) for a,b in ranges}
    assert all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in functions.values())
    arm = {hex(a):arm_cfg(image,a) for a in (0x21b6cc,0x21b6dc,0x6e4724)}
    assert all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in arm.values())
    veneer = arm_cfg(image,0x307344)
    assert veneer['unresolved_exits'] == [{'target':'0x6e4724','reason':'Outside bounded local range'}]
    init = functions['0x1bb176']['instructions']
    assert next(r for r in init if r['address']=='0x1bb1a0')['literal_value']=='0x10200060'
    assert next(r for r in init if r['address']=='0x1bb1a2')['instruction']=='strb r0, [r7, #3]'
    parser = functions['0x1bcc38']['instructions']
    switch = next(r for r in parser if r['address']=='0x1bccf2')
    assert switch['switch_targets'] == ['0x1bcdbA'.lower(),'0x1bcd18','0x1bccfa','0x1bcd70','0x1bcdc2','0x1bcd30']
    proof_name = 'evidence/firmware-analysis/native-usb-controller-emulation.json'
    proof = json.loads((ROOT/proof_name).read_text())
    assert proof['all_passed'] and not proof['device_io']
    for name,expected in proof['source_sha256'].items():
        assert sha((ROOT/name).read_bytes())==expected,name
    primary_name = 'sources/native-usb/source-snapshots.json'
    primary = json.loads((ROOT/primary_name).read_text())
    for row in primary['files']:
        assert sha((ROOT/row['path']).read_bytes())==row['sha256']
    deps = {Path(__file__).resolve(),ROOT/proof_name,ROOT/primary_name}
    deps.update(ROOT/name for name in proof['source_sha256'])
    deps.update(ROOT/row['path'] for row in primary['files'])
    for module in list(sys.modules.values()):
        name = getattr(module,'__file__',None)
        if name and Path(name).resolve().parent==ROOT/'scripts' and name.endswith('.py'):
            deps.add(Path(name).resolve())
    output = {'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'bounded_Thumb_functions':functions,'bounded_ARM_functions':arm,
        'ARM_FIFO_size_veneer':veneer,
        'device_reset_path':{'IRQ':'0x1bb22c','speed_from_POWER_bit4':True,
            'packet_sizes':'0x1bb0d6','descriptors':'0x1bcf6c','endpoint_init':'0x1bb176',
            'state_reset':'0x1bcb20','actual_host_role_or_reset_on_phone':False},
        'EP0_device_path':{'setup_FIFO_reader':'0x1bcc12','request_dispatch':'0x1bcc38',
            'descriptor_switch':switch,'GET_DESCRIPTOR_request':6,'SET_ADDRESS_request':5,
            'address_saved_pending_then_applied_by':'0x1bd120',
            'data_FIFO_writer':'0x1bcb40','receives_host_requests_not_issues_AOA_to_phone':True,
            'all_USB_standard_requests_or_class_vendor_requests_executed':False,
            'malformed_request_handling_or_validity_of_short_packets_not_verified':True},
        'register_comparison':{'base':'0x10200000','primary':'sources/native-usb/musb_regs.h',
            'offset_names':{'0':'FADDR','1':'POWER','2':'INTRTX','4':'INTRRX','6':'INTRTXE',
                '8':'INTRRXE','0xa':'INTRUSB','0xb':'INTRUSBE','0xe':'INDEX',
                '0x10':'indexed TXMAXP','0x12':'indexed TXCSR/CSR0','0x14':'indexed RXMAXP',
                '0x16':'indexed RXCSR','0x18':'indexed RXCOUNT','0x20':'EP0 FIFO',
                '0x60':'DEVCTL','0x62':'indexed TXFIFOSZ','0x63':'indexed RXFIFOSZ',
                '0x64':'indexed TXFIFOADD','0x66':'indexed RXFIFOADD'},
            'native_literal10200060_used_at_offsets2_3_4_6_not_DEVCTL':True,
            'comparison_is_inference_not_physical_controller_identification':True},
        'all_assertions_passed':True,'device_io':False,'firmware_modified':False,
        'device_install_candidate':False,
        'scope':'Twelve complete local Thumb flows, three complete local ARM helpers and an '
            'explicit ARM branch veneer link stock peripheral speed/reset/descriptor/endpoint/EP0 '
            'paths. Separate22-case proof executes original code on synthetic data/registers with '
            'precise FIFO input/IRQ fixture boundaries. Not hardware identification, real handshake '
            'or USB host/AOA. No whole-firmware host absence, App or phone session claim.'}
    path = ROOT/'evidence/firmware-analysis/native-usb-controller-static.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'output':str(path.relative_to(ROOT)),'Thumb_flows':len(functions),
        'ARM_flows':len(arm),'source_dependencies':len(deps),'descriptor_switch_cases':6}))


if __name__=='__main__':
    main()
