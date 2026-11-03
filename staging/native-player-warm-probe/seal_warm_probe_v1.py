#!/usr/bin/env python3
"""Seal terminal offline diagnostic results and the exact local candidate."""
import sys,json,hashlib
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
def sha(p):
    h=hashlib.sha256()
    with p.open('rb')as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def read(p):return json.loads(p.read_text())
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
    assert not(BASE/'ROOT-warm-probe-terminal-seal-v1.json').exists()
    proof=read(BASE/'ROOT-file-bundle-proof-v1.json');reader=read(BASE/'candidate-warm-probe-embedded-reader-v1.json');bundle=read(BASE/'local-warm-probe-bundle-manifest-v1.json')
    assert proof['all_passed']and proof['case_count']==8 and not proof['VM_import_or_execution']
    assert reader['all_passed']and reader['actual_original5_loader_callbacks_not_intercepted']and not reader['BIN_file_input_fixture_used']
    assert reader['getter_and_page_input_utf16_hex']=='W7E8\0'.encode('utf-16le').hex()
    assert reader['candidate_sha256']==proof['candidate_sha256']==bundle['candidate_sha256']
    for key,name in [('candidate-reader-v1-terminal-tool-receipt.json','reader'),('FILE-bundle-v1-terminal-tool-receipt.json','FILE')]:
        r=read(BASE/key);assert r['terminal']and r['actual_terminal_result']['exit_code']==0 and 'session_id'not in r['actual_terminal_result']
    n=NativeImage();cold=read(BASE/'guest-v2/cold_zero_audio.json');idle=read(BASE/'guest-v3/original_initialized_idle.json')
    assert idle['actual_sample'][2]==0 and idle['actual_sample'][3]==0
    call=idle['original_initializer_calls_as_explicit_input'][-1];assert call['entry']=='0x277d26'and call['r0']==0
    opcodes={i.address:(i.bytes.hex(),i.mnemonic,i.op_str)for i in n.instructions(0x277d66,0x277d78)}
    assert opcodes[0x277d6e]==('407f','ldrb','r0, [r0, #0x1d]')and opcodes[0x277d70]==('0228','cmp','r0, #2')
    assert opcodes[0x277d74]==('b842','cmp','r0, r7')and opcodes[0x277d76]==('49d0','beq','#0x277e0c')
    contract=dict(all_passed=True,kind='Bounded exact profile no-op branch plus saved explicit input control; no full warm boot claim',
        original_read_profile_byte_offset=0x15d,original_conditional_branch_rows=[dict(PC=k,opcode=v[0],instruction=v[1]+' '+v[2])for k,v in opcodes.items()],
        actual_profile0_return=call,after_profile_callback_pointer=idle['actual_sample'][2],after_profile_type=idle['actual_sample'][3],tag=idle['expected_tag'],
        conclusion='When the stored profile byte already equals requested0 and is not2, original277D26 can return0 without installing callbacks. The saved explicit startup-zero input case shows callback slot remains0. Profile return0 alone cannot establish receiver/source readiness.',
        warm_entry_requirement='Inspect actual callback/profile/condition/channel mapping and ownership; do not reset all18 channels or infer initialization/exclusivity from profile success.',
        native_condition_constructor_remaining='Guest-v2 attempted original3EC540 but inherited raw lock fixture lacked its ownership-transfer/Timer semantics. Retain failure; new observation controls leave condition storage cold instead. Diagnostic reads do not initialize it.',
        source_sha256={rel(p):sha(p)for p in (Path(__file__),BASE/'guest-v3/original_initialized_idle.json',BASE/'guest-v2/terminal-failure.json',ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'scripts/analyze_native_sections.py')},
        guest_executed=False,device_IO=False)
    create(BASE/'profile0-noop-readiness-boundary-contract-v1.json',contract)
    sources={}
    for parent in (proof,reader):
        for p,h in parent['source_sha256'].items():
            assert sha(ROOT/p)==h,p;assert p not in sources or sources[p]==h;sources[p]=h
    for p in BASE.rglob('*'):
        if p.is_file()and '__pycache__'not in p.parts:sources[rel(p)]=sha(p)
    for p in (Path(__file__),ROOT/'scripts/stage_native_warm_probe_voice.py'):sources[rel(p)]=sha(p)
    assert sha(ROOT/bundle['candidate_path'])==bundle['candidate_sha256']and sha(ROOT/bundle['rollback_path'])==bundle['rollback_sha256']
    create(BASE/'ROOT-warm-probe-terminal-seal-v1.json',dict(all_passed=True,source_sha256=sources,case_count=8,exact_original_embedded_reader_additional_scope=1,
        selected_scopes=rel(BASE/'ROOT-selected-eight-diagnostic-scopes-v1.json'),ROOT_FILE_proof=rel(BASE/'ROOT-file-bundle-proof-v1.json'),bundle_manifest=rel(BASE/'local-warm-probe-bundle-manifest-v1.json'),
        candidate_sha256=bundle['candidate_sha256'],rollback_sha256=bundle['rollback_sha256'],totals=proof['totals'],new_independent_agent_review=False,
        failed_guests_preserved=True,device_IO=False,physical_2_10_control_pending=True,physical_new_probe_test_pending=True,native_warm_App_receiver_ownership_music_verified=False,
        updated_utc=datetime.now(timezone.utc).isoformat()))
    print(json.dumps(dict(all_passed=True,source_count=len(sources),case_count=8,embedded_reader_scope=1,totals=proof['totals'],candidate_sha256=bundle['candidate_sha256'],seal_sha256=sha(BASE/'ROOT-warm-probe-terminal-seal-v1.json'),device_IO=False)))
if __name__=='__main__':main()
