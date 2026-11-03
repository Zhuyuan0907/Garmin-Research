#!/usr/bin/env python3
"""Sealable five-witness constructor interpretation, not a guest rerun."""
import hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;DEPS=[];SEALS={}
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,m):
 if not x:raise ValueError(m)
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,d):
 with(HERE/name).open('x')as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def bound(stage,pin,name):
 if stage not in SEALS:
  p=ROOT/'staging'/stage/'sealed-files.json';b=p.read_bytes();need(sha(b)==pin,'Closed scope seal pin');SEALS[stage]=json.loads(b);DEPS.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b)))
 p=ROOT/'staging'/stage/name;rel=str(p.relative_to(ROOT));entry=next(x for x in SEALS[stage]['files']if x['path']==rel);before=stat(p);b=p.read_bytes()
 need(sha(b)==entry['sha256']and len(b)==entry['bytes']and stat(p)==before,'Immutable source pin:'+rel)
 DEPS.append(dict(path=rel,bytes=len(b),sha256=sha(b),stat_before=before,stat_after=stat(p),old_cases_executed=False));return b
def main():
 previous='navigation-native-query-vector-provider-binding-v1';pp='b615cf69e041c68f8db92dda4f5251e7e5ad1f53bb9d49b526bfb024ae0a8235'
 getter='navigation-native-query-provider-full-getter-v1';pg='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'
 mat='navigation-native-jai-img-materializer-abi-v1';pm='333dc553b0e259a8b5493d77168ebffca726b22f99be1992f7f3481443e38b3b'
 previousproof=json.loads(bound(previous,pp,'proof.json'));need(previousproof['new_IMG_bytes_read']==0,'Previous static scope')
 pages={0x32d000:bound(previous,pp,'MAIN-page-0032d000.bin'),0x388000:bound(getter,pg,'MAIN-page-00388000.bin'),0x32b000:bound(getter,pg,'MAIN-page-0032b000.bin'),0x44b2000:bound(mat,pm,'MAIN-page-044b2000.bin')}
 captures=[]
 for p in sorted(HERE.glob('capture-*-receipt.json')):
  d=json.loads(p.read_bytes());need(d['source_stat_before']==d['source_stat_after']and d['all_source_handles_closed'],'Fresh bounded source stable')
  for r in d['new_source_reads']:
   b=(ROOT/r['path']).read_bytes();need(sha(b)==r['sha256'],'New captured byte pin');pages[r['runtime']]=b;captures.append(r)
 need(len(captures)==2 and sum(x['bytes']for x in captures)==8192,'Exact actual new source scope')
 def span(a,z,mode='thumb'):
  pg=a&~4095;need(z<=pg+4096 and pg in pages,'Bounded captured span');b=pages[pg][a-pg:z-pg]
  decoder=Cs(CS_ARCH_ARM,(CS_MODE_THUMB if mode=='thumb'else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN)
  return dict(start=a,end_exclusive=z,mode=mode,bytes=len(b),hex=b.hex(),sha256=sha(b),instructions=[dict(address=i.address,hex=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)for i in decoder.disasm(b,a)])
 case=json.loads((HERE/'actual-cold-constructor-frontier.json').read_bytes());need(case['all_assigned_checks_passed']and case['instructions_executed']==31,'Actual single logical frontier result')
 callback=span(0x173b50,0x173cfc)
 need(struct.unpack_from('<I',pages[0x173000],0xcf4)[0]==0x12435687,'Originalcachemagic')
 veneers=span(0x2e382c,0x2e3844,'arm');need(struct.unpack_from('<I',pages[0x2e3000],0x838)[0]==0x44b209f,'Trueparserpointer')
 need(pages[0x173000][0xc44:0xc46]==bytes.fromhex('2862'),'TrueDIR160setterencoding')
 need(pages[0x173000][0xbb8:0xbba]==bytes.fromhex('4161'),'TruecachedDIR154bindingstore')
 witness=[
 dict(id='W1',name='Address DIR callback; cold and cached paths; level selection',spans=[callback],interpretation={'domain':'ActualDIRpacked-addressclassbydirectoriginalparser/readerbindings;notmerelyagenericdescriptorlookalike','entry':'0x00173B50','guard':'*(reply[0]+0x10)==0x12435687','cold':'record+1C==0 →38853C(size17C,flags0,outrecord+1C)→388804→35B4F4(buffer,17C)→2E3834(inputoptions+C,DIR)','helper35B4F4':'Originalcalleeandargumentsonly;noexecution/purposeclaiminthisscope','cached':'173BB8store inputoptions+C atDIR+154','DIR160_selected':'173C3E..44 stores packed outputflagslow3 atDIR+160 afterreadingselecteddescriptor level(byte9&3F)-2/lowID(+4)','DIR160_fallback':'173CE2..E6 sets1when noselecteddescriptor/mapIDzero;DIRtable1countused','executed_part':'Onlyentry/coldbranchtooriginalhandleallocator;remainingstatic'}) ,
 dict(id='W2',name='Exact original veneers fix the address domain',spans=[veneers],interpretation={'2E382C':'Thumb044B10E4packedreader','2E3834':'Thumb044B209EDIRparser','2E383C':'Thumb044B1EEArelationship/iterationmethod;fullmeaningnotassumed','cold_parser_called_by_original_code':True,'cold_parser_executed_this_scope':False}),
 dict(id='W3',name='Actual parser initializes DIR154',spans=[span(0x44b20b4,0x44b20ce)],interpretation={'store':'044B20C0 DIR+140+14=inputMDRctx','parser_input':'r0=inputMDRctx/r1=DIR','not_a_manual_DIR_assignment':True,'CPU_executed_this_scope':False}),
 dict(id='W4',name='Where callback inputoptions+C originates',spans=[span(0x32dc5c,0x32dc9a),span(0x32bb3c,0x32bb8c)],interpretation={'cached_source':'32DC78..7E unwrapsrecord+18handle, adds4, storesSP2C=localoptions+C','cold_source':'32DC6C..72 calls32BB3C(outrecord+18,&options)','32BB3C':'allocates (optionsbyte16*0x408)+4, getsblock+4, writesoptions+C;hasnative handle/clearing/cleanup calls','claim_limit':'MDRctxstorageallocation/sourcepointerstatic;validMDRheader/provider/FSinitializationnotproven','input_to_callback':'PrevioussealoriginalenginecallsiteCB16 passesr2=options;173B54 readsoptions+C'}),
 dict(id='W5',name='Actual limited original cold-handle call frontier',spans=[span(0x38853c,0x38856e)],actual_case_path='staging/navigation-native-query-dir-constructor-v1/actual-cold-constructor-frontier.json',actual_case_sha256=sha((HERE/'actual-cold-constructor-frontier.json').read_bytes()),interpretation={'successful_trace_instructions':31,'native_cold_handle_abi':{'r0_size':380,'r1_flags':0,'r2_handle_output':'cache+1C'},'stop':'0038854AbeforeBL003009A0','native_handle_after':0,'unknown_returns_faked':False,'DIRparser_and_fieldstores_executed':False,'original_full_callback_return_observed':False})]
 need(len(witness)==5,'Finitefivewitnessscope')
 save('constructor-witnesses.json',dict(schema='garmin-native-query-dir-constructor-five-witnesses/v1',witness_count=5,witnesses=witness))
 source=ROOT/'evidence/firmware-analysis/main_02bd.bin';now=stat(source);need(all(json.loads(p.read_bytes())['source_stat_after']==now for p in HERE.glob('capture-*-receipt.json')),'Finaloriginalstatimmutable')
 save('proof.json',dict(schema='garmin-native-query-dir-constructor-proof/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,scope_work_completed=True,actual_frontier_terminal='b575b6',actual_exit_code=0,exact_byte_witness_count=5,new_MAIN_bytes_read=8192,new_MAIN_cap=32768,new_IMG_bytes_read=0,new_IMG_cap_if_needed=32768,logical_guest_cases=1,execution_attempts=2,successful_frontier_instruction_count=31,first_attempt='7da119 fixturebankedSPpreparationerror;source/failurepreserved;noinstructiontracesaved',first_attempt_instruction_count_unknown=True,fixture_only_banked_SP_observation='759eb2/EXIT0/zero guest instructions; SPsetting beforemodechange becomes0; CPSRbeforeSPcorrectedforsamelogicalcase',old_closed_cases_or_suites_replayed=False,all_source_handles_closed=True,source_MAIN_stat_after=now,source_whole_hash_repeated=False,capture_reads=captures,dependencies=DEPS,established=dict(callback_is_true_DIR_packed_address_domain=True,DIR154_cold_original_parser_called_static=True,DIR154_cached_rebind_store_static=True,DIR154_input_pointer_from_options_C_static=True,DIR160_setter_identified_static=True,DIR160_source_is_selected_record_flags_low3_or_fallback1=True,DIR160_equals_query_tuple_level=False,actual_cold_handle_allocator_entered=True,actual_cold_handle_call_ABI_confirmed=True),remaining=dict(original_handle_allocator_return_unproven=True,unknown_mutex_entry='0x003009A0',unknown_handle_allocator_core='0x003881BC',original_callback_full_return=False,query_DIR_handle_created=False,valid_MDR_context_header_provider_FS_initialization=False,DIR154_or_DIR160_store_executed_this_scope=False,cold_registry_initialized=False,uninterrupted_query_to_getter=False,native_SQLite=False,native_UI=False,device_acceptance=False,historical_alias_or_official368_reassessment=False,full_Taiwan_completion=False,App_completion=False,installable=False),static_corrections=['The conditional4006callbackreallycallsoriginaladdressDIRparser/reader;notgeneric-only.', 'DIR+160setterisnowidentifiedinstaticsandcomesfromselectedrecordnextlevel,notdirecttuplelevel3.', '32BB3Cprovesoptions+Cstoragepointerallocationmechanismonly;notcompleteMDRheaderparse.', 'Original35B4F4argumentsobservedstatically;helpernotexecutedhere.'],stop_reason='One logical realcallbackcase halted beforeunknown originalmutex; handle0. Nohighlevel/dispatch/allocator/handle return invented. NoadditionalMAIN/IMG/casesafterthisfinitefrontier.'))
 print(json.dumps(dict(all_assigned_checks_passed=True,witnesses=5,new_MAIN_bytes_read=8192,new_IMG_bytes_read=0,logical_guest_cases=1,successful_frontier_instructions=31,DIR160_setter_static=True,full_constructor_return=False)))
if __name__=='__main__':main()
