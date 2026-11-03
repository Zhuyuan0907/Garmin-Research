#!/usr/bin/env python3
"""Exclusive NEW ARM REL + meaningful HOST controls + exact static evidence.
No emulator/guest/device import or operation. Streaming protected hashing.
Successful and failed commands/sources are retained in attempt-v2.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,shutil,subprocess,struct
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
REGISTRY=ROOT/'staging/native-player-inline-fields/previous-audit.json'
EXPECTED_REGISTRY='52f879fb8a67b981b3c3265f5ebecb0804032929e7f321e0e2c92a673d5febde'
MANIFEST=ROOT/'staging/native-player-settings-scope/music-owner/manifest.json'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def newjson(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
def check(rows):
    for p,h in rows.items():assert sha(ROOT/p)==h,p
def command(directory,i,args):
    p=subprocess.run(args,text=True,capture_output=True)
    newjson(directory/f'command-{i}.json',dict(command=args,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr))
    if p.returncode:raise RuntimeError(f'command-{i} exit{p.returncode}: {p.stderr[-1500:]}')
    return p.stdout
def main():
    assert sha(REGISTRY)==EXPECTED_REGISTRY
    protected=json.loads(REGISTRY.read_text())['protected_sources'];assert len(protected)==1363
    print('streaming before1363 protected hashes',flush=True);check(protected)
    m=json.loads(MANIFEST.read_text());check(m['source_sha256']);check(m['artifacts_sha256'])
    directory=OUT/'attempt-v2';directory.mkdir(exist_ok=False)
    snapshot=directory/'source-snapshot';snapshot.mkdir()
    sources=sorted([p for p in OUT.iterdir()if p.is_file() and p.stem.endswith('_v2') and p.suffix in ('.c','.h','.md','.py')]+[OUT/'pull_bridge.S'])
    for p in sources:shutil.copyfile(p,snapshot/p.name)
    newjson(directory/'sources-at-start.json',{rel(p):sha(p)for p in sources})
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-I',str(ROOT/'native/sbc-prototype')]
    names=['music_session_guard_v2.c','memory_output_scope_owner_v2.c','coordinator_scope_owner_v2.c','session_stream_owner_v2.c','native_context_v2.c','pull_bridge.S']
    objects=[];index=0
    for name in names:
        p=OUT/name;o=directory/(p.stem+'.o');objects.append(o)
        command(directory,index,['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(o)]);index+=1
    core=directory/'immutable_control.o';objects.append(core)
    command(directory,index,['arm-linux-gnueabi-gcc',*flags,'-c',str(ROOT/'native/ui-music-control-prototype/ui_music_control.c'),'-o',str(core)]);index+=1
    linked=directory/'session-component-EMULATION-ONLY.rel'
    command(directory,index,['arm-linux-gnueabi-gcc','-nostdlib','-no-pie','-r',*[str(p)for p in objects],'-o',str(linked)]);index+=1
    host=directory/'host-session-controls'
    command(directory,index,['gcc','-std=c11','-O1','-g','-fno-pie','-no-pie','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(OUT/'music_session_guard_v2.c'),str(ROOT/'native/ui-music-control-prototype/ui_music_control.c'),str(OUT/'host_session_controls_v2.c'),'-o',str(host)]);index+=1
    host_output=command(directory,index,[str(host)]);index+=1
    assert host_output.count('\n')==18 and 'PASS 17 HOST groups' in host_output
    newjson(directory/'host-controls.json',dict(groups=host_output.splitlines()[:-1],group_count=17,all_passed=True,terminal_output=host_output,native_instructions_executed=False,STOP_DONE=False,ownership_proof=False,mocks='IRQ/actor/records/provider/native queue/cancel request; real immutable control+NEW guard C'))
    spec=importlib.util.spec_from_file_location('readonly_elf',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    elf=mod.ELF32(linked);assert elf.kind==1
    undefined=sorted(s['name']for s in elf.symbols if s['name'] and s['section_index']==0)
    rd=command(directory,index,['arm-linux-gnueabi-readelf','-h','-s','-r',str(linked)]);index+=1
    (directory/'readelf.txt').write_text(rd)
    assert 'Machine:                           ARM' in rd and 'REL (Relocatable file)' in rd
    sys.path.insert(0,str(ROOT/'scripts'))
    from analyze_native_sections import NativeImage
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
    image=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    windows={}
    for a,n in [(0x270458,0x70),(0x277c6a,0xba),(0x277b38,0x138),(0x277db4,0x18),(0x2f9cca,0x58),(0x2f9e16,0x20),(0x2fa53c,0x42),(0x4379d4,0x38),(0x48edf8,0x16),(0x48ee58,0x46)]:
        raw=image.read(a,n)
        windows[hex(a)]=dict(length=n,bytes_sha256=hashlib.sha256(raw).hexdigest(),instructions=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in md.disasm(raw,a)])
    assert image.word(0x270884)==0xffff
    assert image.read(0x27049a,6).hex()=='08986946c1c1'
    assert image.read(0x2704a8,2).hex()=='2b00'
    assert image.read(0x2704ac,4).hex()=='f549069a'
    assert image.read(0x2f9cca,4).hex()=='f1b58ab0'
    assert image.read(0x2f9e32,4).hex()=='0bb0f0bd'
    assert image.read(0x2fa572,4).hex()=='fff7aafb'
    assert image.word(0x48ef34)==0x34e3cf4 and image.word(0x48ef38)==0xffff
    owner_elf=mod.ELF32(ROOT/m['extension_elf'])
    actual_imports={s:owner_elf.symbol(s)for s in ['source_worker_state','coordinator_state','music_runtime_state','memory_output_control','memory_output_slots','native_ui_music_resident','music_owner_irq_save','music_owner_irq_restore','music_owner_current','music_owner_post','source_worker_entry','native_ui_music_owned_anchor_address']}
    deps=dict(m['source_sha256']);deps.update({rel(p):sha(p)for p in sources});deps.update({rel(p):sha(p)for p in [OUT/'verification.json',OUT/'v1-native-ABI-qualification.json',OUT/'v1-native-ABI-rejection-evidence.json',OUT/'record_queue_ABI_rejection.py']})
    for p in [REGISTRY,MANIFEST,ROOT/m['extension_elf'],ROOT/'scripts/analyze_native_sections.py',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',ROOT/'staging/native-player-global-subobject/music-native/verification.json',ROOT/'staging/native-player-settings-scope/music-owner/native-owner-contract.json']:
        deps[rel(p)]=sha(p)
    check(deps);print('streaming after1363 protected hashes',flush=True);check(protected)
    artifacts={rel(p):sha(p)for p in directory.rglob('*')if p.is_file()}
    d=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
      exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')),
      source_sha256=deps,artifacts_sha256=artifacts,protected_registry=rel(REGISTRY),protected_registry_sha256=sha(REGISTRY),protected_files_verified=1363,
      ARM=dict(path=rel(linked),sha256=sha(linked),machine=40,type='ET_REL',full_image=False,undefined_symbols=undefined,all_unresolved_are_explicit_native_component_boundaries=True),
      host=dict(groups=17,actual_core_and_new_guard=True,ASan_UBSan=True,original_native_instructions=False,fixtures_explicit=True,STOP_DONE=False,certified_native_ownership=False),
      original_opcode_windows=windows,provider_allocator=dict(entry='0x48EE68',output_pointer_r0_from_factory='0x437A02 -> record+0xF0',busy_store='0x48EE8C +0x0C',index_store='0x48EE8E',count=5,stride=576,failure_return=65535,literal='0x48EF38',success_return=0,release='0x48EE58 -> STRB0 +0x0C at48EE64'),
      original_full_pull=dict(entry='0x2F9CCA',input='r0=channel only',prologue_bytes='f1b58ab0',original_frame_bytes=64,continuation='0x2F9CCF',epilogue='0x2F9E32 ADDsp44;2F9E34 POPr4-r7/PC20',direct_caller='0x2FA572 BL2F9CCA',caller_return='0x2FA576',reader_call='0x2F9D1A BLXr3',reader_instance='record+0xF0 at2F9D18',new_wrapper_compiled=True,original_caller_redirected=False,original_return_runtime_verified_here=False),
      actual_frozen_image_symbols_for_future_regenerated_bindings=actual_imports,
      original_queue_ABI=dict(r0='list=record+1A8',r1='literalFFFF from270884 viaLDR2704AC',r2='kind from savedr1 viaLDR2704AE',r3='flags fromr5 viaMOV2704A8',stack=['params','length','metadata'],v1_wrong_ABI_retained_qualified=True,static_mapping_verified=True,native_execution_verified=False),
      concrete_progress=['typed whole-pull callback/media leases plus stale-index rejection','per-channel original7arg RAM queue callback admission with original unavailable8','NEW owning coordinator mutation scopes through complete original return','NEW owning memory reader/selector preserves original staticanchor and complete native release','NEW owning native AV session prepare plus local Stop/event17/F1/consumer gates','captured controller generation before original decoder post'],
      next_native_callsite=dict(PC='0x2704B2',instruction='BLXr6',source='channel8 record+0x160',original_target='0x277C6B',new_target='mcs_queue_bridge via NEW runtime RAM slot store',MAIN_code_patch_required_for_this_slot=False,native_execution_here=False),
      blockers=['original2FA572 directMAIN caller does not reach compiled full-pull bridge; no RAM import/export redirection found','capture_selected currently requires actual source owner; mixer TCB selector callback/handoff unbound','direct277C6A/list277B38/provider48EE68/free48EE58 and reprofile277D26 writers not closed','native exclusivity witness always-200; it never accepts idle/count/coverageflag as proof','NEW full image must replace3 owningobjects/KEEP NEW APIs and remove original unleased API arrays; no fullimage linked here','modified-code VPM/SIG acceptance and physicalApp/directphone/audio remain unknown'],
      flags=dict(no_guest=True,no_Unicorn=True,no_device=True,no_service=True,no_MAIN_patch=True,no_startup_copy_patch=True,no_old_file_edits=True,no_canonical_or_report_writes=True,no_physical_candidate=True,no_STOP_DONE_or_audio_claim=True))
    newjson(OUT/'verification-v2.json',d)
    print(json.dumps(dict(verification=rel(OUT/'verification-v2.json'),sha256=sha(OUT/'verification-v2.json'),ARM_REL_sha256=sha(linked),host_groups=17,protected=1363,unresolved=undefined)))
if __name__=='__main__':main()
