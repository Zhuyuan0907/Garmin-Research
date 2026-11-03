#!/usr/bin/env python3
"""Only the remaining house case; preserves preceding actual cases without replay.

The first scope runner captured the IMG once, then exposed a genuine cached
registry cleanup frontier. The already-executed street decoder is preserved.
This finite continuation opens neither original MAIN nor candidate IMG.
"""
import hashlib, importlib.util, json, struct, sys
from datetime import datetime, timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,s):
    if not x:raise ValueError(s)
def stat(p):
    x=p.stat();return[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def read(n,d):
    p=HERE/n;x=stat(p);b=p.read_bytes();need(sha(b)==d and stat(p)==x,'Frozen own source:'+n);return json.loads(b),dict(path=str(p.relative_to(ROOT)),sha256=d,bytes=len(b),stat=x)
def save(n,j):
    with(HERE/n).open('x')as f:json.dump(j,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
    need(not(HERE/'proof.json').exists()and not(HERE/'actual-house-getter-frontier.json').exists(),'Finite new continuation only')
    started=datetime.now(timezone.utc).isoformat()
    source,sourcepin=read('actual-source-windows.json','6f1b4f0c4b66c9df6f35d935ccb8f2c8ead3842bc4f397da13a22924656d82de')
    street,streetpin=read('fixture-development-getter-attempt.json','5aaac4e4bfa1185e3131733a3cc99397f1491455f8c0bbd50162648d27ee13fa')
    guard,guardpin=read('fixture-development-guard-attempt.json','21a5f12710e193c2b7f73f06260650ca8ea97416f69231c96b4d2d8c75a6a38c')
    p=HERE/'probe_actual_provider_getter.py';b=p.read_bytes();need(sha(b)=='a8ddd164df35c997536ec610b7bf2b7839d2a4befaea8bc121873f85d662cc6e','Exact observed first-run source')
    spec=importlib.util.spec_from_file_location('native_actual_getter_fixture_class',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    before=stat(ROOT/m.IMG);need(before==source['candidate_stat'],'Actual frozen source IMG stat pin, no wholehash')
    saved=m.SavedMAIN();machine=m.module('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','frozen_machine_API_only')
    windows={(e['component'],e['offset']):bytes.fromhex(e['hex'])for e in source['sources']if(e['component']=='00004171.MDR'and e['bytes']in[4,18,20])or(e['component']=='I053061A.GMP'and e['offset']>=3812824)}
    need(all(sha(bytes.fromhex(e['hex']))==e['sha256']and len(bytes.fromhex(e['hex']))==e['bytes']for e in source['sources']),'All exact cached actual candidate byte witnesses')
    class HouseGuest(m.Guest):
        def __init__(self,*a,**k):super().__init__(*a,**k);self.observations=[]
        def code(self,u,pc,n,opaque):
            if pc in [0x044B1550,0x001AFB58,0x001F784C,0x0035905C]:
                x=dict(pc=hex(pc),native_r0=self.r(0),native_r1=self.r(1),native_r2=self.r(2),native_r3=self.r(3))
                if pc==0x044B1550:x['actual_packed_record_native_output_hex']=bytes(u.mem_read(u.reg_read(m.UC_ARM_REG_SP)+0x14,32)).hex()
                self.observations.append(x)
            super().code(u,pc,n,opaque)
    guest=HouseGuest(machine,saved,windows,source['metadata'],level=4)
    try:
        result=guest.run(0x044B153A,[m.DIR,3781595,m.OUT,192]);result.update(lowID=3781595,level=4,name='one_remaining_actual_house_full_getter_frontier',observed_native_statuses=guest.observations,source_IMG_opened_in_this_continuation=False,new_MAIN_source_opened_in_this_continuation=False)
        text=bytes.fromhex(result['output_hex']).split(b'\0',1)[0].decode('cp950');need(text=='368號','Actual original complete LBL decoder output')
        result['actual_CP950_text']=text;result['actual_CP950_text_hex']=bytes.fromhex(result['output_hex']).split(b'\0',1)[0].hex()
        need(result['frontier']['stop_before_original_call']=='0x44bff32'and result['invalid_memory']is None,'Genuine unknown formatter stop, no fake return')
        packed=next(x for x in guest.observations if x['pc']=='0x44b1550');need(packed['native_r0']==0,'True full packed-record native return across metadata')
        fields=struct.unpack('<8I',bytes.fromhex(packed['actual_packed_record_native_output_hex']));need(fields[2]==1 and fields[4]==2967 and fields[5:7]==(1127253<<8,5625400<<8),'Actual house map/ref and genuine TRE rescaling')
        result['actual_full_packed_reader_return0']=True;result['actual_full_packed_reader_fields_u32']=list(fields)
        for x in [0x044B10E4,0x0448F740,0x00359038,0x001F7814,0x001EE156,0x0032BE40,0x001AF428,0x001BE518,0x001AFB3E,0x001AFC7C,0x002BF5F4,0x044C170E,0x044C0E9A,0x044BFF18]:need(result['actual_original_entry_visits'].get(hex(x),0)>0,'Unbroken new house chain:'+hex(x))
        save('actual-house-getter-frontier.json',result)
    except Exception as e:
        save('continuation-actual-failure.json',dict(error=repr(e),invalid=guest.invalid,last_original_instructions=guest.trace[-32:],events=guest.events,new_IMG_bytes=0,new_MAIN_bytes=0));raise
    finally:del guest
    need(stat(ROOT/m.IMG)==before,'Candidate immutable after all guests')
    streettext=bytes.fromhex(street['output_hex']).split(b'\0',1)[0].decode('cp950');need(streettext=='敦富六街'and street['invalid_memory']is None,'Prior actual street result retained')
    need(guard['invalid']['address']=='0x2ce94c'and guard['instructions']==1664,'Prior genuine registry cleanup frontier retained')
    caps=[json.loads((HERE/n).read_text())for n in ['initial-MAIN-capture-receipt.json','additional-MAIN-capture-receipt.json','final-MAIN-capture-receipt.json']]
    original=ROOT/'evidence/firmware-analysis/main_02bd.bin';need(stat(original)==caps[0]['stat_before']and all(x['stat_before']==x['stat_after']==stat(original)for x in caps),'Actual original MAIN captures retain exact identity')
    imgbytes=sum(x['bytes']for x in source['actual_IMG_read_log']);need(imgbytes==76129 and imgbytes<=131072,'One actual source IMG read total')
    proof=dict(schema='garmin-native-query-provider-LBL-frontier/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        candidate=dict(path=m.IMG,bytes=before[2],inherited_root_readback_sha256=source['inherited_whole_SHA256'],wholehash_not_repeated=True,stat_before=before,stat_after=stat(ROOT/m.IMG)),
        actual_sources=sourcepin,source_metadata=source['metadata'],original_MAIN_capture_receipts=[str((HERE/n).relative_to(ROOT))for n in ['initial-MAIN-capture-receipt.json','additional-MAIN-capture-receipt.json','final-MAIN-capture-receipt.json']],original_MAIN_stat=stat(original),
        actual_NEW_IMG_bytes_read=imgbytes,actual_NEW_MAIN_bytes_read=65536,IMG_cap_bytes=131072,MAIN_cap_bytes=65536,
        new_source_reads_in_continuation=dict(IMG=0,MAIN=0),whole_source_IMG_MAIN_or_DB_hash_repeated=False,
        dependencies=m.DEPENDENCIES,previous_actual_cases_preserved_without_replay=[streetpin,guardpin],continuation_script_sha256=sha(Path(__file__).read_bytes()),
        initial_actual_guest_attempt_exit1=dict(terminal='44ffc5',exception='unmapped fetch 0x002CE94C after real missing-registry branch chooses status1 and cleanup; initial source capture/finally-close completed',saved_own_source_sha256='a8ddd164df35c997536ec610b7bf2b7839d2a4befaea8bc121873f85d662cc6e'),
        explicit_guard_observer_terminal='f18de5',actual_street_guest_terminal='2e08a4',
        street=dict(lowID=48312,level=3,instructions=street['instructions'],actual_CP950_text=streettext,frontier=street['frontier'],native_public_getter_return=False,invalid_memory=None,actual_original_entry_visits=street['actual_original_entry_visits']),
        house=dict(lowID=3781595,level=4,instructions=result['instructions'],actual_CP950_text=text,frontier=result['frontier'],actual_full_packed_reader_native_return0=True,actual_packed_fields_u32=result['actual_full_packed_reader_fields_u32'],native_public_getter_return=False,invalid_memory=None,actual_original_entry_visits=result['actual_original_entry_visits']),
        missing_registry_guard=dict(original_instructions=1664,actual_registry_enumeration_exhausted=True,actual_original_status1_branch_executed=True,complete_native_return=False,unmapped_original_cleanup_target='0x002CE94C',unknown_return_faked=False),
        actual_native_metadata_mapordinal_registry_cached_GMP_chain_executed=True,actual_LBL_full_decoder_FS_and_CP950_copy_executed=True,original_LBL_full_decoder_and_public_getter_return=False,
        original_high_level_provider_metadata_getter_return_faked=False,unknown_postprocess_or_cleanup_return_faked=False,
        frozen_JAI_materializer_query_chain_inherited_not_rerun=saved.old['true_JAI_chain'],query_result_vector_consumer_to_MDR_context_actual_connection_verified=False,
        full_cold_registry_GMP_parser_initialization=False,uninterrupted_native_query_to_MDR_and_LBL_getter=False,native_SQLite=False,native_UI=False,physical_acceptance=False,device_IO=False,installable=False,full_Taiwan_complete=False,
        explicit_fixtures=['selected slot0 preinitialized linkedblock with one80B descriptor, actual public mapID; original enum/lookup runs','already-open cached GMPcontext and actual public TRE/LBL metadata; no native Map load/admission claim','mutex OS boundary single guest; current-thread comparison executes original code','bounded temporary-memory allocation/handle-buffer/free and known two-argument byte-zero API','bottom FS read/map exact actual non-realigned IMG windows; genuine native wrapper position/bit decoding/rescaling executes','frozen query record48312 inherited from sealed original materializer; this scope starts public MDR label consumer044B153A with explicit DIR level/context'],
        next_minimal_original_entries=[dict(call='0x044BFF32',veneer='0x0448E868',target='0x0049A711',r0='actual decoded CP950 output pointer',r1=29,return_semantics='unknown; not called or faked',purpose='first original postprocess helper before complete LBL/public return'),dict(target='0x002CE94C',r0='cached GMP object',purpose='cleanup when mapregistry lookup fails on an open cached object; native call reached unmapped instruction fetch')],
        source_historical_alias_and_house368_held=True,source_official_street_name_new_parent_evidence_separate=True,OSM_source_raw24_district_gates_inherited_not_reexecuted=True,
        old_closed_cases_or_suites_reexecuted=False,all_candidate_MAIN_DB_handles_closed=True,no_sealed_sources_IMG_device_report_or_canonical_mutation=True,
        limitation='Scope succeeds in identifying/executing the new real provider/decoder frontier. It does not claim complete getter return, native query-vector provider connection, official house/alias verification, UI or installation.')
    save('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,new_IMG_bytes=imgbytes,new_MAIN_bytes=65536,remaining_house_case_instructions=result['instructions'],actual_texts=[streettext,text],full_getter_return=False,unknown_returns_faked=False,all_handles_closed=True),ensure_ascii=False))
if __name__=='__main__':main()
