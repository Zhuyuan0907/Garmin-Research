#!/usr/bin/env python3
"""Bounded saved-evidence review and own-scope seal; no guest/source blob reads."""
import hashlib,json,os,struct
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
    need(not(HERE/'sealed-files.json').exists(),'No old seal modification')
    proof=j('proof.json');source=j('actual-source-windows.json');street=j('fixture-development-getter-attempt.json');house=j('actual-house-getter-frontier.json');guard=j('fixture-development-guard-attempt.json')
    captures=[j(n)for n in ['initial-MAIN-capture-receipt.json','additional-MAIN-capture-receipt.json','final-MAIN-capture-receipt.json']]
    pages=[x for c in captures for x in c['reads']];need(len(pages)==16 and len({x['runtime']for x in pages})==16 and sum(x['bytes']for x in pages)==65536,'One64KiB capture set')
    for x in pages:
        b=(HERE/f"MAIN-page-{x['runtime']:08x}.bin").read_bytes();need(len(b)==4096 and sha(b)==x['sha256'],'Every original new page exact receipt')
    native_stat=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin');need(all(c['stat_before']==c['stat_after']==native_stat for c in captures),'MAIN immutable stat only, no content read')
    need(stat(ROOT/proof['candidate']['path'])==proof['candidate']['stat_before']==proof['candidate']['stat_after']==source['candidate_stat'],'Actual IMG immutable stat only')
    reads=source['actual_IMG_read_log'];need(sum(x['bytes']for x in reads)==76129<=131072 and all(x['bytes']>0 and x['physical_offset']+x['bytes']<=132173824 for x in reads),'Actual physical source bounds/count')
    source_index={}
    for x in source['sources']:
        raw=bytes.fromhex(x['hex']);need(len(raw)==x['bytes']and sha(raw)==x['sha256'],'Actual saved byte witness digest')
        need(sum(t['bytes']for t in x['FAT_mapping'])==x['bytes'],'Logical witness actual FAT count')
        source_index[x['component'],x['offset']]=x
    for case,text in [(street,'敦富六街'),(house,'368號')]:
        need(case['invalid_memory']is None and case['native_function_return']is False,'Original getter held at unknown method')
        need(bytes.fromhex(case['output_hex']).split(b'\0',1)[0].decode('cp950')==text,'Actual emitted bytes are complete literal text')
        need(case['frontier']['source_bytes']==case['output_hex'][:64]and case['frontier']['stop_before_original_call']=='0x44bff32'and case['frontier']['actual_original_veneer_target']=='0x0049A711','Exact current true frontier')
        maps=[x for x in case['explicit_fixture_events']if x['kind']=='actual_bottom_FS_window_mapping_fixture'];need(len(maps)==2,'One packed and one label actual map per case')
        for x in maps:
            src=source_index[x['component'],x['offset']];need((x['bytes'],x['sha256'])==(src['bytes'],src['sha256'])and x['guard_page']and not x['realigned'],'FS events refer to exact actual saved source')
        ids=[x for x in case['explicit_fixture_events']if x['kind']=='actual_MDR1_bottom_FS_read_fixture'];need(len(ids)==2 and all(x['offset']==772 and x['bytes']==4 and x['sha256']==source_index['00004171.MDR',772]['sha256']for x in ids),'Metadata requested same actual mapID twice')
        need(case['GMP_CC0_CC4_after']==[0,0],'Original selector reset observed')
    need(house['actual_full_packed_reader_fields_u32'][4:7]==[2967,1127253<<8,5625400<<8],'Original house ref/raw24 rescale output')
    need(guard['invalid']['address']=='0x2ce94c'and guard['instructions']==1664,'Exact negative registry frontier retained')
    for k in ['query_result_vector_consumer_to_MDR_context_actual_connection_verified','full_cold_registry_GMP_parser_initialization','uninterrupted_native_query_to_MDR_and_LBL_getter','native_SQLite','native_UI','physical_acceptance','device_IO','installable','full_Taiwan_complete']:
        need(proof[k]is False,'Held flag:'+k)
    need(proof['all_assigned_checks_passed']and not proof['old_closed_cases_or_suites_reexecuted'],'Correct new finite scope')
    save('bounded-static-review.json',dict(schema='native-getter-saved-evidence-static-review/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        checks=['all16 new MAIN pages exact capture hashes and immutable original stat','one IMG physical read pass within128KiB, immutable source stat','all actual saved hex/sha/FAT byte counts','guest FS maps exact actual record and label windows, no realignment','both original metadata calls use same actual MDR1 mapID','true native selector reset and house packed return0/ref/TRE scaling','literalCP950 outputs and actual unknown formatter frontier','negative registry cleanup frontier preserved','all cold/query/UI/physical completion flags held'],
        new_IMG_MAIN_content_bytes_read=0,new_guest_cases=0,old_cases_or_suites_run=0,source_blob_handles_opened=False,proof_sha256=sha((HERE/'proof.json').read_bytes())))
    # Own namespace only. Source/candidate hardlinks and their inodes never touched.
    files=[]
    for p in sorted(HERE.iterdir()):
        if not p.is_file()or p.name=='sealed-files.json':continue
        b=p.read_bytes();os.chmod(p,0o444);files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),stat_at_seal=stat(p),mode='0444'))
    seal=dict(schema='native-query-provider-getter-frontier-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,file_count=len(files),files=files,
        all_actual_source_handles_closed=True,no_original_MAIN_candidate_IMG_DB_content_read_here=True,unknown_native_return_faked=False,complete_public_getter_return=False,uninterrupted_query_UI_installable=False,scope_completed_as_actual_frontier=True)
    save('sealed-files.json',seal);os.chmod(HERE/'sealed-files.json',0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,sealed_files=len(files),seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),proof_sha256=sha((HERE/'proof.json').read_bytes()),original_IMG_MAIN_stat_unchanged=True,all_handles_closed=True)))
if __name__=='__main__':main()
