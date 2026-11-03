#!/usr/bin/env python3
"""Finite exact-byte static binding study. No old main/cases and no guest."""
import hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
DEPS=[];SEALS={};THUMB=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);ARM=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
def need(x,m):
 if not x:raise ValueError(m)
def sha(x):return hashlib.sha256(x).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,row):
 with (HERE/name).open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n')
def sealed(stage,pin,filename):
 if stage not in SEALS:
  p=ROOT/'staging'/stage/'sealed-files.json';raw=p.read_bytes();need(sha(raw)==pin,'Closed seal pin:'+stage)
  SEALS[stage]=json.loads(raw);DEPS.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=pin,stat=stat(p),old_cases_executed=False))
 rel='staging/'+stage+'/'+filename;entry=next(x for x in SEALS[stage]['files']if x['path']==rel)
 p=ROOT/rel;before=stat(p);raw=p.read_bytes();need(len(raw)==entry['bytes']and sha(raw)==entry['sha256'],'Sealed artifact identity:'+rel)
 need(stat(p)==before,'Immutable sealed artifact');DEPS.append(dict(path=rel,bytes=len(raw),sha256=sha(raw),stat_before=before,stat_after=stat(p),old_cases_executed=False));return raw
def main():
 frontend='navigation-native-jai-frontend-abi-v1';mat='navigation-native-jai-img-materializer-abi-v1';getter='navigation-native-query-provider-full-getter-v1'
 pf='0f07b17d802a3fb34abf9d1f4a9dba04cacc633c03569db556edb8e7284207d3';pm='333dc553b0e259a8b5493d77168ebffca726b22f99be1992f7f3481443e38b3b';pg='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'
 pages={};q=sealed(frontend,pf,'JAI-runtime-code-64KiB.bin')
 for a in (0x4421000,0x4422000):pages[a]=q[a-0x4420000:a-0x4420000+4096]
 for a in(0x448e000,0x448f000,0x44b1000,0x44b2000):pages[a]=sealed(mat,pm,'MAIN-page-%08x.bin'%a)
 for a in(0x388000,0x32c000):pages[a]=sealed(getter,pg,'MAIN-page-%08x.bin'%a)
 endpoint=json.loads(sealed(mat,pm,'actual-native-materializer-case.json'))
 need(endpoint['native_return_r0']==0 and endpoint['actual_query_result_vector_count']==1,'Frozen genuine query endpoint')
 need(endpoint['actual_native_chain_12byte_records']==[[3,48312,0],[2,74,4294967295],[1,8,4294967295]],'Frozen actual tuple chain')
 captures=[]
 for p in sorted(HERE.glob('capture-*-receipt.json')):
  receipt=json.loads(p.read_bytes());need(receipt['all_source_handles_closed']and receipt['source_stat_before']==receipt['source_stat_after'],'Original source stable')
  for x in receipt['new_source_reads']:
   raw=(ROOT/x['path']).read_bytes();need(len(raw)==4096 and sha(raw)==x['sha256'],'Captured original page identity')
   need(x['runtime']not in pages,'No source window collision');pages[x['runtime']]=raw;captures.append(x)
 need(len(captures)==8 and sum(x['bytes']for x in captures)==32768,'Exact32KiB new MAIN scope')
 def raw(a,z):
  b=bytearray()
  while a<z:
   pg=a&~4095;n=min(z-a,pg+4096-a);need(pg in pages,'Saved exact source page');b.extend(pages[pg][a-pg:a-pg+n]);a+=n
  return bytes(b)
 def fragment(name,a,z,mode='thumb',meaning=None):
  b=raw(a,z);decoder=THUMB if mode=='thumb'else ARM
  return dict(name=name,start=a,end_exclusive=z,mode=mode,bytes=len(b),hex=b.hex(),sha256=sha(b),static_meaning=meaning,instructions=[dict(address=i.address,hex=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)for i in decoder.disasm(b,a)],CPU_executed_this_scope=False)
 fragments=[
  fragment('outer_selector6_and_handle_guard',0x442250c,0x442259c,meaning='Original outer query chooses selector6 and requires handles+18/+1C nonzero. Original high-level dispatch was not executed.'),
  fragment('query_then_result_consumer',0x4422806,0x4422846,meaning='0442217E receives SP+28 output collection; 04421E5A receives the same collection after native collector return.'),
  fragment('consumer_DIR_handle',0x4421e6e,0x4421e7e,meaning='The other handle+18 is unwrapped to a context pointer+4.'),
  fragment('consumer_DIR_handle_exact',0x4421e8c,0x4421e96,meaning='Input object+1C handle → 448FD98 → 388804; resulting pointer storedSP50 and used asDIR argument.'),
  fragment('tuple_caller',0x4421f0a,0x4421f20,meaning='tuple[0]level→stackarg5; tuple[1]lowID→r3; inputDIR→r1; outputdescriptor→r2; outercontext→r0. Genuine BL04421DB4.'),
  fragment('descriptor_constructor',0x4421db4,0x4421e5a,meaning='Packed reader receives tuple level directly. After reader, DIR+140 is added before accessing+14, hence trueMDRctx atDIR+154. This is static and not an uninterrupted guest path.'),
  fragment('DIR_parser_initialization',0x44b209e,0x44b20ee,meaning='044B20C0 stores inputMDRctx atDIR+154. StoresDIR+174/+178=0, copiesctx+2C0 tablecount. No DIR+160 initialization shown.'),
  fragment('real_local_DIR_constructor_caller',0x44b295e,0x44b298e,meaning='Original descriptor getter clears0x17C-byte localDIR, calls044B209E withctx andSP+10, then decodes descriptorlevel−2 andlowID with044B10E4. This is another real caller, not the query handle allocation producer.'),
  fragment('public_getter_level_read',0x44b153a,0x44b1550,meaning='Public sequential consumer readsDIR+160. Its setter is still unknown; this must not be equated with directtupleargument path.'),
  fragment('handle_unwrap',0x388804,0x38882e,meaning='Native handle lookup through388E92, extractsblockpointer by maskinglow3bits; original mutex functions are called.'),
  fragment('outer_dispatch_veneer',0x448ee28,0x448ee30,'arm'),
  fragment('DIR_handle_unwrap_veneer',0x448fd98,0x448fda0,'arm'),
  fragment('dispatch_entry',0x32db4c,0x32db9a,meaning='General dispatch preservesselector/r1/r2/r3 plusstackargs; selector is translated bytrue3C21A4 resolver.'),
  fragment('dispatch_pass_to_engine',0x32dcc6,0x32dcd8,meaning='r0=selector;r1=inputdescriptor;r2=localoptions;r3=resolverindex;stackarg5=result/outputcontainer;stackarg6=originalr3. Calls351770→044DC366.'),
  fragment('engine_veneer',0x351770,0x351778,'arm'),
  fragment('resolver_veneer',0x3c21a4,0x3c21ac,'arm'),
  fragment('actual_resolver',0x44db2f8,0x44db318,meaning='Linear12byte rows atactual8723A0, returnsmatchingindex or sentinel index without automaticallyrejectingmissingtype.'),
  fragment('engine_flags_and_inputpredicate',0x44dc3a4,0x44dc3bc,meaning='Actual predicate32CCAA or inputdescriptor+18 nonzero yieldsflags0x4000; this is not a string check.'),
  fragment('predicate_veneer',0x448e4e8,0x448e4f0,'arm'),
  fragment('predicate_native',0x32ccaa,0x32ccc8,meaning='Only kindbyte+8=18/19 proceeds toencodedkey+C validity32C4FE. No semanticname assumed.'),
  fragment('predicate_key_validity',0x32c4fe,0x32c52e,meaning='Sums99slotcounts; requireskeyhighbyte80 andlow16 less than total. Registryinitialization/coldentry not executed.'),
  fragment('conditional_reresolve_and_callback_load',0x44dc404,0x44dc43c,meaning='When engineindex isFFFF orflagsnonzero, resolvesselector|flags, then loadsrow+4callback intoSP3C.'),
  fragment('actual_callback_callsite',0x44dcb0e,0x44dcb1c,meaning='TrueBLXr3; r3=SP3C callback,r0=R4 local,r1=SP8C callerarg6,r2=SP6C options/input. Meaning ofR4 atthisstage remainsheld.'),
 ]
 need(raw(0x44b20c0,0x44b20c2)==bytes.fromhex('4e61'),'ActualMDRctxstoreencoding')
 need(struct.unpack('<I',raw(0x448ee2c,0x448ee30))[0]==0x32db4d,'Original dispatch pointer')
 need(struct.unpack('<I',raw(0x351774,0x351778))[0]==0x44dc367,'True runtime engine pointer')
 need(struct.unpack('<I',raw(0x3c21a8,0x3c21ac))[0]==0x44db2f9,'True runtime resolver pointer')
 need(struct.unpack('<I',raw(0x44db6e4,0x44db6e8))[0]==0x8723a0,'Resolvertableliteral')
 need(struct.unpack('<I',raw(0x44dc824,0x44dc828))[0]==0x8723a0,'Callbacktableliteral')
 rows=[]
 for idx in range(100):
  a=0x8723a0+12*idx;t,callback,context=struct.unpack('<3I',raw(a,a+12));rows.append(dict(index=idx,address=a,selector=t,callback_pointer=callback,shared_context_pointer=context))
  if t==0x30:break
 need(len(rows)==52 and rows[-1]['selector']==0x30,'Boundedtrueendmarker')
 need(not any(x['selector']==6 for x in rows),'Exactbare6notinactualtable')
 typed=next(x for x in rows if x['selector']==0x4006);need(typed['index']==46 and typed['callback_pointer']==0x173b51,'Actual4006nextentry')
 size_rows=[]
 for idx in range(60):
  a=0xb9e2e8+8*idx;t,n=struct.unpack('<2I',raw(a,a+8));size_rows.append(dict(index=idx,address=a,selector=t,bytes=n))
  if t==0x30:break
 need(next(x for x in size_rows if x['selector']==6)['bytes']==0x868,'Selector6 bounded allocation size table')
 save('abi-witnesses.json',dict(schema='garmin-native-query-vector-provider-static-witnesses/v1',fragments=fragments,actual_callback_table=dict(address=0x8723a0,rows=rows,bare6_result=rows[-1],conditional4006_result=typed,logical_table_sha256=sha(raw(0x8723a0,0x8723a0+12*52))),selector_size_table=dict(address=0xb9e2e8,rows=size_rows),frozen_source_query=dict(path='staging/'+mat+'/actual-native-materializer-case.json',native_return_r0=endpoint['native_return_r0'],result_count=endpoint['actual_query_result_vector_count'],tuple_chain=endpoint['actual_native_chain_12byte_records'],SQL_and_preallocated_vector_fixtures_inherited=True,case_replayed=False)))
 original=ROOT/'evidence/firmware-analysis/main_02bd.bin';s=stat(original);need(all(json.loads(p.read_bytes())['source_stat_after']==s for p in HERE.glob('capture-*-receipt.json')),'Final original source stable')
 save('proof.json',dict(schema='garmin-native-query-vector-provider-binding-proof/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,scope_work_completed=True,work_kind='Exact-byte static caller/ABI and bounded original dispatch-data capture; no guest',new_MAIN_bytes_read=32768,new_MAIN_read_cap=32768,new_IMG_bytes_read=0,guest_cases_executed=0,device_IO=False,whole_source_hashes_repeated=False,all_actual_source_handles_closed=True,old_cases_or_suites_replayed=False,original_MAIN_stat_after=s,capture_reads=captures,dependencies=DEPS,established=dict(true_tuple_consumer_and_constructor_static=True,DIR154_original_parser_store_static=True,DIR154_parser_called_by_original_descriptor_getter_static=True,query_DIR_retrieved_from_real_handle_static=True,tuple_level_direct_argument_static=True,selector_engine_and_original_callback_table_static=True,conditional4006_callback_entry='0x00173B50 (Thumb pointer0x00173B51)'),held=dict(query_handle_constructed_by_original_callback=False,DIR160_level_setter_identified=False,original_callback173B50_executed=False,query_to_getter_uninterrupted=False,cold_MDR_context_registry_or_FS_initialization=False,native_SQLite=False,native_UI=False,physical_acceptance=False,source_historical_alias_or_368_official_proof=False,full_Taiwan_completion=False,App_completion=False,installable=False),next_minimum_entries=[dict(entry='0x00173B50',reason='Actualselector4006callback; captureitsoriginalABIandDIR/MDRhandleproducerbeforeguest. Exactbare6defaultisnotqueryfailure.'),dict(entry='0x04421F0A → 0x04421DB4',reason='Trueactualtuplecaller; mustobtainrealDIRhandlefirst; firststringassignmenthelper4515AB4isnotexecuted.'),dict(entry='0x044B209E',reason='RealDIRparseproducer; coldMDRctxisstillcaller-owned, manualDIR/ctxfillsmustremainfixtures.'),dict(entry='DIR+0x160 setter',reason='Differentpublicsequentialgetterpath; directresulttupleleveldoesnotestablishthisfield.')],stop_reason='New32KiBsourcecapmet; truecallback173B50notyetcaptured. Noartificialconstructor, nofakeunknownreturn, noCPUdeclaredsuccessful.'))
 print(json.dumps(dict(all_assigned_checks_passed=True,work_kind='static ABI',new_MAIN_bytes_read=32768,new_IMG_bytes_read=0,guest_cases=0,next_callback='0x00173B50',source_handles_closed=True)))
if __name__=='__main__':main()
