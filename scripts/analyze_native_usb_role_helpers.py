#!/usr/bin/env python3
"""Bound stock role-search candidates, separating electrical-test and host code.

Scans two literal-load shapes in startup-backed regions only. Data/code/mode
ambiguity makes scan hits candidates until confirmed in a local reachable CFG.
No whole-firmware absence, physical register name or USB host claim.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()

def main():
    stock=NativeImage();image=RuntimeImage(stock)
    ranges=[(0x1bb018,0x1bb05e),(0x1bb05e,0x1bb068),(0x1bb068,0x1bb0c0),
      (0x1bb10e,0x1bb154),(0x1bb176,0x1bb210),(0x1bcb40,0x1bcc12),(0x1bcc12,0x1bcc38),
      (0x1c001c,0x1c006c),(0x1c010c,0x1c0156),(0x1c23f4,0x1c2444),
      (0x1bfc42,0x1bfc5e),(0x1bfc5e,0x1bfcde),(0x1c058c,0x1c0594)]
    functions={hex(a):cfg(image,a,b) for a,b in ranges}
    assert all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in functions.values())
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    regions=[];thumb=[];arm=[];raw=[];calls=[]
    targets={0x1bb018,0x1bb05e,0x1bb068,0x1bb10e}
    for region in stock.copies:
        if region['runtime_start'] in (0xf00000,0xffff0000):continue
        b=stock.read(region['load_start'],region['size']);base=region['runtime_start']
        regions.append({k:region[k] for k in ('runtime_start','runtime_end','conditional')})
        for off in range(0,len(b)-4,2):
            h,l=struct.unpack_from('<HH',b,off);address=base+off
            if h&0xf800==0x4800:
                literal=((address+4)&~3)+((h&255)<<2);index=literal-base
                if 0<=index<=len(b)-4:
                    value=struct.unpack_from('<I',b,index)[0]
                    if 0x10200000<=value<0x10200400:
                        r=rows.get(address)
                        proven=bool(r and r.get('literal_address')==hex(literal) and r.get('literal_value')==hex(value))
                        thumb.append({'address':hex(address),'literal':hex(literal),'value':hex(value),
                          'confirmed_in_bounded_reachable_Thumb_CFG':proven})
            if h&0xf800==0xf000 and l&0xf800 in (0xf800,0xe800):
                delta=((h&2047)<<12)|((l&2047)<<1)
                if h&1024:delta-=1<<23
                target=address+4+delta
                if l&0xf800==0xe800:target&=~3
                if target in targets:
                    i=next(stock.md.disasm(b[off:off+4],address,count=1),None)
                    calls.append({'address':hex(address),'target':hex(target),
                      'decoded_instruction':i.mnemonic+' '+i.op_str if i else 'undecoded',
                      'confirmed_in_local_CFG':bool(rows.get(address,{}).get('direct_call')==hex(target))})
        for off in range(0,len(b)-4,4):
            word=struct.unpack_from('<I',b,off)[0];address=base+off
            if 0x10200000<=word<0x10200400:raw.append({'address':hex(address),'value':hex(word),'unvalidated_data_or_instruction':True})
            # Immediate-offset ARM word LDR, Rn=PC, pre-indexed, no writeback.
            # U sign allowed; exclude unconditional-extension encodings and
            # unaligned loads (rotation semantics not assumed).
            if word&0x0f7f0000==0x051f0000 and word>>28!=15:
                literal=address+8+((word&4095) if word&(1<<23) else -(word&4095));index=literal-base
                if literal%4==0 and 0<=index<=len(b)-4:
                    value=struct.unpack_from('<I',b,index)[0]
                    if 0x10200000<=value<0x10200400:
                        arm.append({'address':hex(address),'literal':hex(literal),'value':hex(value),
                          'unvalidated_instruction_candidate':True})
    assert len(thumb)==10 and all(r['confirmed_in_bounded_reachable_Thumb_CFG'] for r in thumb)
    assert not arm and len(raw)==17
    test=functions['0x1bb068']['instructions']
    assert next(r for r in test if r['address']=='0x1bb08c')['literal_value']=='0x8e0aec'
    assert next(r for r in test if r['address']=='0x1bb0ae')['instruction']=='cmp r0, #0x35'
    assert rows[0x1bfc8a]['direct_call']==rows[0x1bfcc6]['direct_call']=='0x1bb018'
    assert rows[0x1bb032]['instruction']=='str r0, [r2, #4]'
    assert rows[0x1bb052]['instruction']=='str r0, [r2, #4]'
    proof_name='evidence/firmware-analysis/native-usb-role-helpers-emulation.json';proof=json.loads((ROOT/proof_name).read_text())
    assert proof['all_passed'] and proof['case_count']==53 and not proof['device_io']
    for name,want in proof['source_sha256'].items():assert sha(name)==want,name
    deps=set(proof['source_sha256'])|{str(Path(__file__).relative_to(ROOT)),proof_name,
      'sources/native-usb-role/source-snapshots.json','scripts/analyze_native_usb_transition.py'}
    for metadata_name in ['sources/native-usb/source-snapshots.json','sources/native-usb-role/source-snapshots.json']:
        for row in json.loads((ROOT/metadata_name).read_text())['files']:
            assert sha(row['path'])==row['sha256'];deps.add(row['path'])
    primary=(ROOT/'sources/native-usb-role/musb_host.c').read_text()
    assert 'txcsr = MUSB_CSR0_H_SETUPPKT | MUSB_CSR0_TXPKTRDY;' in primary and 'len = 8;' in primary
    role_sources={name:json.loads((ROOT/name).read_text()) for name in
      ('sources/native-usb/source-snapshots.json','sources/native-usb-role/source-snapshots.json')}
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
      'all_assertions_passed':True,'source_sha256':{name:sha(name) for name in sorted(deps)},
      'scanned_startup_backed_regions':regions,'literal_search':{'Thumb_PC_relative_candidates':thumb,
      'strict_ARM_PC_relative_candidates':arm,'raw_aligned_words_unvalidated':raw,
      'scope':'Two immediate PC-literal shapes only, code/data/mode not established by the scan. Ten Thumb hits confirmed through local CFGs; no full pointer/ARM computation/indirect/module/global host absence claim.'},
      'bounded_Thumb_functions':functions,'direct_call_scan_candidates':calls,
      'extension_control':{'wrapper':'0x1bb018','getter':'0x1bb05e','address':'0x10200204',
        'width_bytes':4,'bit14_set_or_clear':'R0 nonzero or zero','bits15_16':'low two bits of R1 on enable',
        'bit13':'set if F08E0B nonzero, otherwise preserved','separate_gate_address':'0x101e9000',
        'separate_gate_bit3':'set on enable, preserved on disable',
        'known_local_caller':'0x1bfc5e','caller_uses_temporary_enable_then_disable':True,
        'physical_register_role_UART_mux_ADC_DMA_or_VBUS_unidentified':True,
        'not_equated_to_standard_MUSB_DMA_control':True,
        'primary_DMA_comparison':'Linux HSDMA_BASE200/CONTROL4 also addresses204, but its control is16-bit with defined fields0..9. Native word-width/bits13..16 plus separate gate do not establish that ABI or actual DMA.'},
      'temporary_sample_probe':{'entry':'0x1bfc5e','bank_selector':'0x1bfc42',
        'bank_map':{'0':'0x101fd000','1':'0x101fb000','3':'0x101fe000'},
        'bank_register_offsets':[128,132,136],'unsupported_selector_returns_zero':[2,4],
        'timer_address':'0x101e3044','timer_loops_min_differences':[4,2],
        'timer_loops_have_no_software_iteration_limit_in_local_CFG':True,
        'original_IRQ_save_restore_helpers':['0x21b6cc','0x21b6dc'],
        'success_only_first_bit1_then_second_bit0':True,
        'previous_extension_control_not_fully_restored':True,
        'probe_not_ready_to_call_on_hardware':True,
        'scope':'Bank physical roles and timer units unknown. Timing/status supplied only before original loads. No calibrated ADC, actual bank transitions, pin/UART mode, voltages or host/VBUS proof.'},
      'electrical_test':{'entry':'0x1bb068','caller_veneer':'0x1c058c',
        'selector_to_TESTMODE':{'1':2,'2':4,'3':1,'4':8},
        'primary_names':['TEST_J','TEST_K','TEST_SE0_NAK','TEST_PACKET'],
        'TESTMODE_offset':'0xf','fixed_EP0_packet_address':'0x8e0aec','packet_bytes':53,
        'test_packet_sha256':proof['test_packet_sha256'],'exact_primary_test_pattern_match':True,
        'force_host_bit80_not_set_by_helper':True,
        'packet_path_second_CSR0_OR_mask':'0x0a','initial_CSR0_OR_mask':'0x20',
        'same_numeric_host_setup_mask_does_not_prove_host':True,
        'primary_host_comparison':'Linux host sends8-byte setup with CSR0 host-SETUPPKT8/TXPKTRDY2. Native test helper sends fixed53-byte electrical pattern and selects TESTMODE8. Shared bit values are role-dependent; this is not AOA control data.'},
      'primary_sources':role_sources,'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'actual_host_driver_role_VBUS_or_AOA_verified':False,
      'scope':'Thirteen complete bounded Thumb CFGs, ten confirmed immediate literal references and specific direct-call candidates separate stock electrical tests and temporary extension/probe control from host evidence. '
        'Primary Linux sources used for comparison only; chip/controller identity/register side effects/role still unverified. '
        'No full cross-function/global pointer or module search, live register access, host/VBUS/phone/TLS/UI/audio or install proof. '
        'Host implementation remains open; no whole-firmware absence conclusion.'}
    name='evidence/firmware-analysis/native-usb-role-helpers-static.json'
    (ROOT/name).write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':name,'Thumb_CFGs':len(functions),'confirmed_literal_references':len(thumb),
      'raw_unvalidated_words':len(raw),'strict_ARM_candidates':len(arm),'dependencies':len(deps),'device_io':False}))
if __name__=='__main__':main()
