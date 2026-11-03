#!/usr/bin/env python3
"""Freeze completed diagnostics, FILE replay, and one local reversible VPM.
No VM import, device, mount, audio, flashing or installation occurs here.
"""
import sys,json,hashlib,struct,collections
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from analyze_tts_vpm import parse_image
from build_native_voice_package_fixture import repack
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
R=0x034e7f48;M=0x034e5378+8*0x130;P=0x034e3cf4;H=0x034e68d8+8*4;IMAGE=0x2d4bb74
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def read(p):return json.loads(p.read_text())
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(v,m):
    if not v:raise AssertionError(m)
def observations(bank):
    a=0x034e3000
    def word(p):return struct.unpack_from('<I',bank,p-a)[0]
    def byte(p):return bank[p-a]
    return [word(R+0x88),byte(R+0x1f8),word(R+0x160),byte(R+0x15d),word(R+0x1ac),struct.unpack_from('<H',bank,R+0x1c0-a)[0],
        byte(R+2),int(not any(bank[R+0xf4-a:R+0xf4-a+68])),word(H),byte(M+0x84),sum(byte(P+i*576+12)==0 for i in range(5)),byte(R+0x1a8)]
def mask(a):return sum(1<<i for i,v in enumerate([a[0]==0xd4475b83,a[1]==8,a[2]==0x277c6b,a[3]==0,a[4]==0xffff,a[5]==0,a[6]==0,a[7]!=0,a[8]==0,a[9]==0,a[10]!=0,a[11]==8])if v)
def main():
    require(not(BASE/'ROOT-file-bundle-proof-v1.json').exists(),'New verifier/namespace needed for any later execution')
    source={}
    def register(p,h=None):
        h=h or sha(p);require(sha(p)==h,'Frozen input '+str(p));key=rel(p);require(key not in source or source[key]==h,'Conflicting frozen source');source[key]=h
    proof=read(BASE/'warm-probe-v3-seven-controls-proof.json');failure=read(BASE/'guest-v2/terminal-failure.json')
    require(proof['all_passed']and proof['case_count']==7 and len(failure['completed_cases'])==1,'Completed prefix and terminal remainder')
    r2=read(BASE/'guest-v2-terminal-tool-receipt.json');r3=read(BASE/'guest-v3-terminal-tool-receipt.json')
    require(r2['actual_terminal_result']['exit_code']==1 and r3['actual_terminal_result']['exit_code']==0,'Actual guest terminal status')
    require('session_id'not in r2['actual_terminal_result']and 'session_id'not in r3['actual_terminal_result'],'No live guest handle')
    selected=[dict(failure['completed_cases'][0],guest_suite_terminal_exit=1),*[dict(c,guest_suite_terminal_exit=0)for c in proof['cases']]]
    require(len(selected)==8 and len(set(c['name']for c in selected))==8,'Eight distinct completed scopes')
    for p,h in proof['source_sha256'].items():register(ROOT/p,h)
    for p in [Path(__file__),BASE/'guest-v2-terminal-tool-receipt.json',BASE/'guest-v3-terminal-tool-receipt.json',BASE/'guest-v1-terminal-tool-receipt.json',BASE/'guest-v2/terminal-failure.json',BASE/'warm-probe-v3-seven-controls-proof.json',BASE/'guest-v1-audio-mapping-erratum.json',BASE/'guest-v2-condition-setup-scope-erratum.json']:
        register(p)
    m=read(BASE/'strict_marker/manifest.json');binary=(ROOT/m['combined_file']).read_bytes();require(sha(ROOT/m['combined_file'])==m['binary_sha256'],'Compiled image')
    n=NativeImage();arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    rows=[];total_stores=total_reads=0
    expected_reads=collections.Counter([(R+0x88,4),(R+0x1f8,1),(R+0x160,4),(R+0x15d,1),(R+0x1ac,4),(R+0x1c0,2),(R+2,1),
        *[(R+0xf4+i,1)for i in range(68)],(H,4),(M+0x84,1),*[(P+i*576+12,1)for i in range(5)],(R+0x1a8,1)])
    for case in selected:
        path=ROOT/case['path'];register(path,case['sha256']);d=read(path);require(d['all_passed'],'Completed diagnostic case')
        zones=d['whole_zone_replay'];replay={k:bytearray.fromhex(v['before_hex'])for k,v in zones.items()}
        for row in d['CPU_write_journal']:
            z=zones[row['zone']];off=row['address']-z['address'];width=row['size']
            require(0<=off and off+width<=z['bytes'],'Journal store within whole zone')
            require(bytes(replay[row['zone']][off:off+width]).hex()==row['before_hex'],'Exact CPU preimage')
            pc=row['pc'];op=bytes.fromhex(row['opcode_hex'])
            actual=binary[pc-IMAGE:pc-IMAGE+len(op)]if m['symbols']['cache_marker_entry']<=pc<IMAGE+len(binary)else n.read(pc,len(op))
            require(actual==op,'Exact stored opcode source')
            ins=list((thumb if row['cpsr']&32 else arm).disasm(op,pc))
            require(len(ins)==1 and (ins[0].mnemonic.startswith('str')or ins[0].mnemonic.startswith('stm')),'Journal instruction is a CPU store')
            replay[row['zone']][off:off+width]=row['value'].to_bytes(width,'little')
        for k,v in zones.items():require(bytes(replay[k]).hex()==v['after_hex'],'Whole-zone final memory '+k)
        bank=bytes.fromhex(zones['native_audio_bank']['before_hex'])
        require(zones['native_audio_bank']['after_hex']==bank.hex()and not d['new_audio_writes'],'Complete audio bank unchanged')
        sample=observations(bank);require(sample==d['reference_native_sample'],'Reference fields reconstructed from frozen native bank')
        reads=d['actual_new_audio_reads'];stores=d['CPU_version_stores']
        if d['actual_sample']is not None:
            require(d['actual_sample']==sample and d['actual_mask']==mask(sample),'New sampled state equals saved native bytes')
            require(collections.Counter((x['address'],x['size'])for x in reads)==expected_reads,'Exactly all83 native diagnostic field reads')
            for row in reads:
                off=row['address']-zones['native_audio_bank']['address']
                require(bank[off:off+row['size']].hex()==row['value_hex'],'Observed native read value')
                pc=row['PC'];op=bytes.fromhex(row['opcode_hex']);require(binary[pc-IMAGE:pc-IMAGE+len(op)]==op,'Compiled read opcode')
                ins=list(arm.disasm(op,pc));require(len(ins)==1 and ins[0].mnemonic.startswith('ldr')and row['CPSR']&0x80,'ARM read under actual IRQ-disabled observation')
            private=bytes(replay['private_state']);start=m['symbols']['marker_state']-zones['private_state']['address']
            require(struct.unpack_from('<I',private,start+52)[0]==mask(sample)and list(struct.unpack_from('<12I',private,start+56))==sample,'Private sample fields from CPU store reconstruction')
            expected=f'W{mask(sample):03X}\0'.encode('utf-16le')
            require(len(stores)==5 and [x['value']for x in stores]==list(struct.unpack('<5H',expected)),'Five actual dynamic UTF16 stores')
            require(bytes(replay['record'])[0x6b8:0x6c2]==expected and d['observed_getter_UTF16_hex']==expected.hex(),'Recorded cache and original getter input')
        else:require(not reads and not stores,'Refused optional probe neither sampled nor changed marker')
        require(len(d['original40_targets'])==40 and all(x['raw_return']==11 for x in d['original_voice_entry']),'Original registration/entry evidence scope')
        total_stores+=len(d['CPU_write_journal']);total_reads+=len(reads)
        rows.append(dict(name=case['name'],path=case['path'],sha256=case['sha256'],CPU_stores=len(d['CPU_write_journal']),native_reads=len(reads),tag=case['tag'],whole_zones=len(zones),guest_suite_terminal_exit=case['guest_suite_terminal_exit']))
    # Build the single local candidate from the same tested compiled payload.
    original_path=ROOT/'backups/20261002T154458Z/files/Voice/Chinese_Big5_MeiLing.vpm';original=original_path.read_bytes();files,g=parse_image(original)
    require(files['DLLIMG.BIN']['sha256']==m['original_sha256'],'Exact original Big5 BIN')
    candidate,recipe=repack(original,binary,checksum=False,zero_signature=False);new,ng=parse_image(candidate)
    require(new['DLLIMG.BIN']['content']==binary and new.keys()==files.keys(),'Exact compiled program and member inventory')
    require(all(new[k]['content']==v['content']for k,v in files.items()if k!='DLLIMG.BIN'),'All other member payloads unchanged')
    require(candidate[:g['directory_start']]==original[:g['directory_start']],'Original outer header unchanged')
    require(binary[12:len(files['DLLIMG.BIN']['content'])]==files['DLLIMG.BIN']['content'][12:],'Original BIN postheader retained')
    require(len(binary)==struct.unpack_from('<I',binary,8)[0]and len(binary)<struct.unpack_from('<I',binary,4)[0]<=0x300000,'Original RAM/file loader contract')
    bundle=BASE/'local-test-bundle-v1';(bundle/'candidate').mkdir(parents=True);(bundle/'rollback').mkdir()
    cp=bundle/'candidate/Chinese_Big5_MeiLing.vpm';rp=bundle/'rollback/Chinese_Big5_MeiLing.vpm'
    with cp.open('xb')as f:f.write(candidate)
    with rp.open('xb')as f:f.write(original)
    register(cp);register(rp);register(original_path)
    manifest=dict(all_passed=True,local_only_reviewable_test_input=True,device_transfer_or_install_performed=False,single_device_target='Voice/Chinese_Big5_MeiLing.vpm',
        exact_target=dict(HWID=1352,SW='8.00',MAIN_sha256=n.data and sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')),
        candidate_path=rel(cp),candidate_sha256=sha(cp),candidate_bytes=len(candidate),rollback_path=rel(rp),rollback_sha256=sha(rp),rollback_bytes=len(original),
        actual_tested_BIN=m['combined_file'],actual_tested_BIN_sha256=m['binary_sha256'],original_DLLINFO_and_SIG_retained_byte_exact=True,signature_forged_or_recomputed=False,
        original_BIN_postheader_retained=True,only_changed_member_payload='DLLIMG.BIN',members_unchanged=[k for k in files if k!='DLLIMG.BIN'],repack_recipe=recipe,
        diagnostic='W plus three hex digits encodes12 audio-state observations at module entry; cached snapshot, not a live monitor or readiness/exclusivity certificate.',
        no_new_audio_calls_or_native_audio_writes=True,physical_new_candidate_acceptance_and_display_unverified=True,physical_original_Aud_Ver_2_10_control_pending=True,
        next_attended_sequence=['Confirm original Aud Ver2.10 after cold restart/MeiLing.','USB mode: one fresh-backup, single-file candidate copy and hash readback, then safe unmount.','Cold restart/MeiLing/Aud Ver: record Wxxx, or original2.10 if optional guard/load did not produce tag.','USB mode: restore original voice, hash readback, safe unmount, then confirm2.10.'],
        installer_or_automatic_device_action=False,device_IO=False,native_App_direct_phone_music_verified=False,source_sha256=source)
    create(BASE/'local-warm-probe-bundle-manifest-v1.json',manifest);register(BASE/'local-warm-probe-bundle-manifest-v1.json')
    create(BASE/'ROOT-selected-eight-diagnostic-scopes-v1.json',dict(all_passed=True,case_count=8,cases=rows,
        selection='One completed cold case from terminal EXIT1 guest-v2, plus seven NEW terminal EXIT0 guest-v3 controls. No completed scope rerun.',
        new_independent_agent_review=False,device_IO=False))
    register(BASE/'ROOT-selected-eight-diagnostic-scopes-v1.json')
    require(not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules),'No guest/VM imported')
    create(BASE/'ROOT-file-bundle-proof-v1.json',dict(all_passed=True,ROOT_FILE_only=True,new_independent_agent_review=False,case_count=8,cases=rows,
        totals=dict(CPU_stores=total_stores,native_field_reads=total_reads,whole_audio_bank_bytes_per_case=0x7000,whole_zones=sum(r['whole_zones']for r in rows)),
        exact_original_and_compiled_store_opcode_preimage_replay=True,whole_native_audio_bank_unchanged=True,
        read_instruction_bytes_and_frozen_memory_values_verified=True,read_effective_register_address_reconstruction_claimed=False,
        single_local_candidate_path=rel(cp),candidate_sha256=sha(cp),rollback_sha256=sha(rp),source_sha256=source,
        limits='FILE proof replays saved stores/whole zones and read opcodes/values; GP effective-address reconstruction and complete non-store controlflow are not covered. Original global/channel/profile input calls are bounded setup with inherited profile raw-mutex services; Condition/Timer construction remains unclosed. No full native warm boot, exclusivity, App/music or new physical acceptance.',
        VM_import_or_execution=False,device_IO=False,physical_candidate_test_pending=True,updated_utc=datetime.now(timezone.utc).isoformat()))
    print(json.dumps(dict(all_passed=True,case_count=8,CPU_stores=total_stores,native_reads=total_reads,candidate_path=rel(cp),candidate_sha256=sha(cp),candidate_bytes=len(candidate),rollback_sha256=sha(rp),device_IO=False)))
if __name__=='__main__':main()
