#!/usr/bin/env python3
"""Own bounded evidence review/seal, no source MAIN/IMG or guest execution."""
import hashlib,json,os
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,s):
    if not x:raise ValueError(s)
def stat(p):
    x=p.stat();return[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def j(n):return json.loads((HERE/n).read_text())
def save(n,x):
    with(HERE/n).open('x')as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
    need(not(HERE/'sealed-files.json').exists(),'New own seal only')
    p=j('proof.json');need(p['all_assigned_checks_passed'],'Both finite continuations pass')
    receipts=[j(n)for n in ['initial-capture-receipt.json','additional-capture-receipt.json']];pages=[x for r in receipts for x in r['reads']]
    need(len(pages)==3 and len({x['runtime']for x in pages})==3 and sum(x['bytes']for x in pages)==12288<=24576,'Exact new code cap')
    for x in pages:
        b=(HERE/f"MAIN-page-{x['runtime']:08x}.bin").read_bytes();need(len(b)==4096 and sha(b)==x['sha256'],'Original saved code bytes exact receipt')
    actual=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin');need(actual==p['MAIN_source_stat_before']==p['MAIN_source_stat_after']and all(r['stat_before']==r['stat_after']==actual for r in receipts),'Original immutable stats')
    for low,count,text in [(48312,407,'敦富六街'),(3781595,329,'368號')]:
        c=j(f'actual-continuation-{low}.json');need(c['all_assigned_checks_passed']and c['native_function_return']and c['native_return_r0']==0 and c['invalid_memory']is None and c['unexpected_old_path']is None,'Exact actual return and finite path')
        need(c['instructions']==count and c['entry']=='0x44bff32'and c['text_before']==c['text_after']==text,'Saved original stop continuation, literal preservation')
        expected=['0x49a710','0x49a728','0x44c12d4','0x44c1b4e','0x1afba0','0x44b1590'];need([x['pc']for x in c['observed_native_returns']]==expected,'Native return observation sequence')
        need(all(x['r0']==0 for x in c['observed_native_returns'][1:]),'Original returns0')
        events=c['explicit_fixture_events'];need(len(events)==1 and events[0]['kind']=='explicit_temporary_memory_free_fixture','No unknown/helper/provider/FS return hooks used')
        f=c['ABI_frame_fixture'];raw=bytes.fromhex(f['frame_hex']);need(len(raw)==f['frame_total_bytes']==696 and sha(raw)==f['frame_sha256']and f['not_a_saved_CPU_RAM_snapshot'],'Explicit complete frame fixture identity')
    held=['same_original_guest_resumed','preceding_sealed_3671_3607_instruction_cases_replayed','old_query_IMG_or_CPU_suites_run','actual_FS_getter_prefix_metadata_replayed','source_IMG_or_DB_opened','unknown_native_callee_return_faked','original_MAIN_or_code_patched','actual_uninterrupted_query_vector_to_MDR_to_full_getter','native_cold_provider_registry_or_GMP_initialization','native_SQLite','native_UI','physical_device_acceptance','installable','full_Taiwan_complete']
    need(all(p[k]is False for k in held)and p['callframe_ABI_reconstruction_is_explicit_fixture']and p['new_IMG_bytes_read']==0,'Exact scope limits')
    save('bounded-static-review.json',dict(schema='native-postprocess-saved-evidence-review/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        checks=['three new source pages exact bounded capture identities, original stats unchanged','each case starts original prior stop and returns0 through observed native tails','single declared allocation-free event only, no unknown return hooks','frame696B hash plus explicit non-snapshot flag','plainCP950 literal output unchanged','cold/query/UI/device claims held'],
        new_MAIN_source_bytes_read=0,new_IMG_bytes_read=0,new_guest_cases=0,proof_sha256=sha((HERE/'proof.json').read_bytes())))
    files=[]
    for pth in sorted(HERE.iterdir()):
        if not pth.is_file()or pth.name=='sealed-files.json':continue
        raw=pth.read_bytes();os.chmod(pth,0o444);files.append(dict(path=str(pth.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),stat_at_seal=stat(pth),mode='0444'))
    save('sealed-files.json',dict(schema='native-getter-postprocess-continuation-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,files=files,file_count=len(files),all_source_handles_closed=True,
        no_original_blob_content_read_or_guest_run_by_sealer=True,frame_fixture_scope=True,uninterrupted_query_UI_installable=False))
    os.chmod(HERE/'sealed-files.json',0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,sealed_files=len(files),seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),proof_sha256=sha((HERE/'proof.json').read_bytes()),all_handles_closed=True)))
if __name__=='__main__':main()
