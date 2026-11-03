#!/usr/bin/env python3
"""Reconstruct the selected2 completed-prefix plus6 new wire controls, FILE only."""
import sys,json,hashlib
from pathlib import Path
from collections import Counter
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
    v4=json.loads((BASE/'guest-v4/terminal-failure.json').read_text())
    v5=json.loads((BASE/'native-reply-admission-v5-six-controls-proof.json').read_text())
    r4=json.loads((BASE/'guest-v4-terminal-tool-receipt.json').read_text())
    r5=json.loads((BASE/'guest-v5-terminal-tool-receipt.json').read_text())
    assert r4['actual_terminal_result']['exit_code']==1 and r5['actual_terminal_result']['exit_code']==0
    assert 'session_id'not in r4['actual_terminal_result']and 'session_id'not in r5['actual_terminal_result']
    assert len(v4['completed_cases'])==2 and v5['all_passed']and v5['case_count']==6
    selected=v4['completed_cases']+v5['cases'];assert len(selected)==8
    m2=json.loads((BASE/'build-v2.json').read_text());m3=json.loads((BASE/'build-v3.json').read_text())
    assert m2['flat_sha256']==m3['flat_sha256']and m2['symbols']==m3['symbols']
    code=(ROOT/m3['flat']).read_bytes();assert hashlib.sha256(code).hexdigest()==m3['flat_sha256']
    native=NativeImage();baseline=native.read(0x50000,0xcb179c-0x50000)
    decoders={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    totals=Counter();sources=dict(v5['source_sha256']);seen_codes={};scope_rows=[]
    sources.update(json.loads((BASE/'guest-v4/inputs-at-run.json').read_text()))
    for entry in selected:
        p=ROOT/entry['path'];assert sha(p)==entry['sha256']
        sources[entry['path']]=entry['sha256'];case=json.loads(p.read_text());assert case['all_passed']
        for variant in case['variants']:
            expected_hash=variant['code_expected_sha256']
            if expected_hash not in seen_codes:
                image=bytearray(baseline)
                for patch in variant['patches']:
                    a=int(patch['address'],16)-0x50000;before=bytes.fromhex(patch['original']);after=bytes.fromhex(patch['replacement'])
                    assert image[a:a+len(before)]==before
                    image[a:a+len(after)]=after
                assert hashlib.sha256(image).hexdigest()==expected_hash
                seen_codes[expected_hash]=bytes(image)
            image=seen_codes[expected_hash]
            for scope in variant['scopes']:
                totals['wire_scopes']+=1;totals['whole_zones']+=len(scope['whole_zones'])
                zones=scope['whole_zones'];replay={k:bytearray.fromhex(v['before_hex'])for k,v in zones.items()}
                for row in scope['journal']:
                    pc=row['PC'];raw=bytes.fromhex(row['opcode_hex'])
                    if m3['base']<=pc<m3['base']+len(code):original=code[pc-m3['base']:pc-m3['base']+len(raw)]
                    else:original=image[pc-0x50000:pc-0x50000+len(raw)]
                    assert original==raw,(hex(pc),row['kind'])
                    k=row['zone'];off=row['address']-zones[k]['address'];n=row['size']
                    assert 0<=off and off+n<=len(replay[k]) and replay[k][off:off+n].hex()==row['before_hex']
                    if row['kind']=='CPU_store':
                        instruction=next(decoders[bool(row['CPSR']&32)].disasm(raw,pc,count=1),None)
                        assert instruction and instruction.size==len(raw) and instruction.mnemonic.startswith(('str','stm','vstr','vstm'))
                        data=row['value'].to_bytes(n,'little');totals['CPU_stores']+=1
                    else:
                        assert row['kind']=='explicit_service_write';data=bytes.fromhex(row['after_hex'])
                        assert pc in (0x5524da,0x5524f6)
                        totals['explicit_service_writes']+=1;totals['explicit_service_bytes']+=n
                    replay[k][off:off+n]=data
                assert all(replay[k].hex()==z['after_hex']for k,z in zones.items())
                for call in scope['actual_native_scope_entries']:
                    assert call['AV_mutex_held']
                assert not scope['nr_scope'][0]
            totals['VM_variants']+=1
        scope_rows.append(dict(name=entry['name'],case_path=entry['path'],sha256=entry['sha256'],prefix_exit1=entry in v4['completed_cases']))
    pending=json.loads((ROOT/next(e['path']for e in selected if e['name']=='Start_pending_Open_rejected')).read_text())
    original,new=pending['variants'];assert not original['strict']and new['strict']
    assert original['result']['state']==8 and new['result']['state']==2
    assert original['result']['pending']==new['result']['pending']==2
    assert original['result']['TX_queue'][-1]['wire_hex']==new['result']['TX_queue'][-1]['wire_hex']=='13070431'
    assert original['result']['callbacks'][0]['event']==17 and not new['result']['callbacks']
    for name in ('Configure_lock_failure','Configure_entity_not_ready'):
        case=json.loads((ROOT/next(e['path']for e in selected if e['name']==name)).read_text())
        original,new=case['variants']
        assert original['result']['state']==new['result']['state']==2
        assert not original['result']['callbacks']and not new['result']['callbacks']
        assert new['nr_scope'][7]==1 and new['nr_scope'][11]==0 and new['nr_scope'][12]!=0
    for p in [Path(__file__),BASE/'build-v2.json',BASE/'build-v3.json',BASE/'guest-v4/terminal-failure.json',
              BASE/'native-reply-admission-v5-six-controls-proof.json',BASE/'guest-v4-terminal-tool-receipt.json',
              BASE/'guest-v5-terminal-tool-receipt.json',BASE/'outer-receive-vs-TX-result-erratum.json']:
        sources[rel(p)]=sha(p)
    assert all(sha(ROOT/p)==h for p,h in sources.items())
    create(BASE/'ROOT-selected-eight-wire-scopes-v1.json',dict(all_passed=True,case_count=8,scope_rows=scope_rows,
           old_completed_prefix_exit1_cases=2,new_exit0_cases=6,guest_rerun=False,whole_v4_suite_passed=False))
    create(BASE/'ROOT-native-reply-admission-file-proof-v1.json',dict(all_passed=True,case_count=8,source_sha256=sources,totals=dict(totals),
           original_rejected_Start_false_state8_and_event17_blocked=True,
           failed_Config_native_state2_preserved_and_application_generation_still_required=True,
           outer_receive_return_is_not_native_send_result=True,native_send_zero_with_written_zero_demonstrated=False,
           opcode_preimage_whole_zones_and_explicit_service_writes_reconstructed=True,
           GP_effective_addresses_or_complete_nonstore_control_flow_reconstructed=False,
           actual_radio_or_remote_session_generation_or_PCM_App_verified=False,new_independent_agent_review=False,
           VM_import_or_execution=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat()))
    print(json.dumps(dict(all_passed=True,case_count=8,totals=dict(totals),native_TX_result_inference_corrected=True,VM=False,device_IO=False)))
if __name__=='__main__':main()
