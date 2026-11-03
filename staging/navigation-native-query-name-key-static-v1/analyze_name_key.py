#!/usr/bin/env python3
"""Five static name/key witnesses using only sealed local artifacts; IMG0/CPU0."""
import hashlib,json,struct
from datetime import datetime,timezone
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(v,msg):
 if not v:raise ValueError(msg)
def write(n,v):
 with(HERE/n).open('x')as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 started=datetime.now(timezone.utc).isoformat();readlog=[];cache={};seals={};pages={}
 def read(rel,cap,expected=None):
  if rel in cache:return cache[rel]
  p=ROOT/rel;before=stat(p);need(before[2]<=cap,'Bounded saved artifact:'+rel)
  b=p.read_bytes();need(stat(p)==before,'Artifact unchanged:'+rel)
  if expected:need(sha(b)==expected,'Sealed hash:'+rel)
  readlog.append(dict(path=rel,bytes=len(b),sha256=sha(b),stat_before=before,stat_after=stat(p)))
  cache[rel]=b;return b
 def sealed(stage,leaf,cap):
  if stage not in seals:seals[stage]=json.loads(read('staging/'+stage+'/sealed-files.json',25000))
  rel='staging/'+stage+'/'+leaf;row=next(x for x in seals[stage]['files']if x['path']==rel)
  raw=read(rel,cap,row['sha256']);need(len(raw)==row['bytes'],'Sealed size:'+rel);return raw
 get='navigation-native-query-provider-full-getter-v1';ctx='navigation-native-query-context-producer-static-v1';mat='navigation-native-jai-img-materializer-abi-v1'
 for stage,leaf,base in [(get,'MAIN-page-001ee000.bin',0x1ee000),(get,'MAIN-page-0032c000.bin',0x32c000),
  (ctx,'MAIN-page-001f1000.bin',0x1f1000),(ctx,'MAIN-page-002cc000.bin',0x2cc000),
  (mat,'MAIN-page-002cd000.bin',0x2cd000),(mat,'MAIN-page-001c8000.bin',0x1c8000)]:
  pages[base]=(sealed(stage,leaf,4096),'staging/'+stage+'/'+leaf)
 cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 def span(a,b,data=False,expected=None):
  base=a&~4095;raw,path=pages[base];need(b<=base+4096,'Exact small page span')
  raw=raw[a-base:b-base]
  if expected:need(raw==expected,'Exact literal/opcode '+hex(a))
  return dict(start=a,end_exclusive=b,source_path=path,mode='data'if data else'thumb',bytes=len(raw),hex=raw.hex(),sha256=sha(raw),
   instructions=[]if data else[dict(address=i.address,hex=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)for i in cs.disasm(raw,a)])
 witnesses=[]
 def w(i,title,spans,facts,held):witnesses.append(dict(id=i,title=title,evidence_kind='original exact bytes/static; no guest',spans=spans,facts=facts,held=held))
 need(struct.unpack_from('<I',pages[0x32c000][0],0x5ac)[0]==0x1287a3c,'Lookup array literal')
 w('W1','Original encoded key resolves a registry record, not a JAI house/street ID',[
  span(0x32c4be,0x32c4fe),span(0x32c5ac,0x32c5b0,True)],{
  'input':'32C4BE r0=key; high8 must80; lookup uses low16; middle8 not consumed in this function',
  'table':'literal32C5AC=01287A3C,99 pointer slots; nonzero block firstu16=count',
  'lookup':'Subtract each preceding block count until relativeindex<count; return block+0C+28*relativeindex',
  'kind_of_output':'28-byte source record pointer consumed by1F18CC; no address hierarchy level/record_info lookup here',
  'no_live_key':'No concrete encoded source key or live table/block bytes supplied or claimed'
 },['Original table/record producer and ownership unverified; byte0/byte1 exact broader meanings remain unknown.',
    'Do not substitute0x3000BCB8(JAI),48312(street lowID),3781595(house lowID)or mapID for this key.'])
 w('W2','1F18CC supplies internal filename template and original encoded key',[
  span(0x1f18cc,0x1f1918),span(0x1f1932,0x1f195a),span(0x1f1962,0x1f1992),
  span(0x1f19e6,0x1f1a0a),span(0x1f1a4c,0x1f1a60,True)],{
  'template':'1F18CE ADR points1F1A4C exact ASCII :????????; three words copied to local template',
  'primary_number':'1F1908..14 uses source record byte0 &0x7F as1EE324 r0,template r1,destinationSP r2,size18 r3',
  'constructor':'1F194A..52 passes r0=context slot,r1=SP name,r2=SP orSP+1C optional buffer,r3=*originalkeycursor ->2CDAAC',
  'optional_selector':'record+6 u16 comparedFFFF; recordbyte0low7 comparedbyte1 influences optional buffer and second path',
  'second_number':'1F1966 loads recordbyte1; alternative1F1974 formats that value with same template',
  'key_cursor':'1F19F8..A04 reads *cursor; rejectsFFFFFFFF/non80highbyte;1F19E8..EA advances cursor4B'
 },['Prefix value is a descriptor byte; no evidence here naming it a physical disk, mapID, mount priority or address record ID.',
    'Real registry records/key cursor/options slots not captured; resulting actual filename not observed.'])
 w('W3','1EE324 is a numeric/template formatter; MDR and SRT suffixes reach native component open',[
  span(0x1ee324,0x1ee36e),span(0x1ee460,0x1ee465,True,b'%d%s\0'),
  span(0x2cc466,0x2cc490),span(0x2cc86c,0x2cc871,True,b'.MDR\0'),
  span(0x2cdb42,0x2cdb62),span(0x2cdbc0,0x2cdbc5,True,b'.SRT\0'),span(0x2cc3e0,0x2cc400)],{
  'format':'1EE35C exactADR->1EE460 %d%s;1EE35E BL3472D4 r0=dest,r1=format,r2=number,r3=template',
  'bound':'Destination initially goes through35AD4C; numeric-length loop254A4C and template-length35B570 contribute to capacity guard; original helper results not executed',
  'symbolic_primary':'Static format/argument relation is decimal(descriptorbyte0&7F) + :????????, then parser adds.MDR',
  'MDR_open':'2CC474..88 copies contextprimary intoSP,appends literal.MDR;1C8682 receives r0=ctx+1Ckey,r1=&ctx+20pair,r2=SP filename',
  'symbolic_secondary':'Constructor2CDB4A..56 copiesctx+0D and appends.SRT; alternative1F197E appends.SRT to separately formatted recordbyte1 prefix',
  'SRT_open':'2CC3E0 consumes already-suffixedfilename, r0=contextkey+1C,r1=&ctx+384pair,r2=filename ->1C8682',
  'domain':'Wildcard ASCII internal component/file names; user streettext 敦富六街 is not an input to these formatting instructions'
 },['Symbolic string from original format arguments, not a fabricated native output or a guest case.',
    '3472D4 formatter,254A4C,35B570,35AD4C and filename append helpers not executed this scope.',
    'Wildcard matching/actual chosen .MDR/.SRT name and FS acceptance remain unverified.'])
 w('W4','Native open wrapper selects MDR/SRT fields from key record before lower FS call',[
  span(0x1c8682,0x1c86c4),span(0x1c871c,0x1c875e)],{
  'ABI':'1C8682 r0=encodedkey,r1=outputpair,r2=filename; saves input r0/r2 on stack',
  'extension_selector':'Finds dot via49A710 and uppercases followingletter via332C88; M setsr4=20hex;S setsr4=6',
  'lookup':'M/S route1C8728 calls32C4BE with saved encodedkey',
  'MDR_value':'M type20hex reads record+4 u16 at1C8734',
  'SRT_value':'S type6 reads record+6 u16 at1C873C',
  'lower_FS_boundary':'1C8752..56 calls2FBA70(r0=outputpair,r1=providedinternalfilename,r2=selectedu16),rejects sentinel or nonzero status'
 },['record+4/+6 u16 exact semantic labels unknown; not declared physical offsets, FAT blocks or valid FS handles.',
    '2FBA70 body/FS/context ownership unexamined here; no lower-level return faked, pair generated or filesystem guest run.',
    'The resulting pair is distinct from the encoded source key stored at context+1C.'])
 cross=json.loads(sealed(ctx,'materializer-context-crossbinding.json',6000))
 binding=json.loads(sealed(mat,'query-to-container-binding.json',4000))
 need(cross['street_ID']==48312 and cross['house_ID']==3781595 and binding['exact_native_chain']==cross['exact_native_chain'],'Sealed image tuple identity')
 need(cross['native_street_ref']==475679 and cross['native_house_ref']==2967,'Sealed actual native refs')
 w('W5','Actual image materializer references remain separate from internal name/key ABI',[],{
  'candidate_inherited_SHA':cross['candidate_inherited_sha256'],'candidate_bytes':cross['candidate_bytes'],
  'actual_inherited_tuple':cross['exact_native_chain'],'street48312_house3781595':True,
  'actual_inherited_text_refs':{'475679':'敦富六街','2967':'368號'},
  'context_field_distinction':{'0':'primaryinternalname','0D':'optionalsecondaryinternalname','1C':'originalencodedsourcekey','20/24':'MDRopenpair','384/388':'SRTopenpair'},
  'mapping':'No nativequery tuple→encodedsourcekey or actual filename mapping established; preserve priorcrossbinding and fixture boundaries'
 },['No new IMG bytes, prefix decoding, label reading or CPU execution.',
    'True uninterrupted query/provider/getter/SQLite/UI/device acceptance and installed App/full Taiwan remain false.',
    'Historical alias,368 address and2026street-name continuity are not verified by these internals.'])
 need(len(witnesses)==5,'Five witness finite stop')
 write('name-key-witnesses.json',dict(schema='garmin-native-query-name-key-five-static-witnesses/v1',witness_count=5,witnesses=witnesses))
 relation=dict(schema='one-source-native-name-key-materializer-static-relation/v1',
  candidate_inherited_SHA256=cross['candidate_inherited_sha256'],candidate_bytes=cross['candidate_bytes'],
  materializer_tuple=cross['exact_native_chain'],street_lowID=48312,house_lowID=3781595,street_ref=475679,house_ref=2967,
  primary_symbolic_name='decimal(recordbyte0&0x7F) + :???????? + .MDR',
  secondary_symbolic_name='caller-selected prefix + :???????? + .SRT',
  name_semantics='Internal wildcard component/file name, separate from user street text',
  key_semantics='Original 0x80-high8/low16 flattened record index into99slots at01287A3C',
  record_u16_MDR_field_offset=4,record_u16_SRT_field_offset=6,
  actual_filename_or_sourcekey_observed=False,sourcekey_equals_JAI_record_or_tuple_ID=False,
  original_FS_pair_generated_this_scope=False,IMG_bytes_read=0,CPU_cases_executed=0,
  uninterrupted_native_query_UI_device_installable_full_Taiwan_verified=False)
 write('materializer-name-key-distinction.json',relation)
 write('source-artifact-read-ledger.json',dict(schema='native-name-key-static-source-artifacts/v1',reads=readlog,
  saved_code_bytes=6*4096,new_original_MAIN_bytes=0,new_original_IMG_bytes=0,
  original_whole_MAIN_IMG_hash_repeated=False,all_artifact_stats_unchanged=True,all_source_handles_closed=True))
 proof=dict(schema='garmin-native-query-name-key-static-proof/v1',started_utc=started,
  finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,scope_work_completed=True,
  script_sha256=sha(Path(__file__).read_bytes()),exact_byte_witness_count=5,new_MAIN_bytes_read=0,new_MAIN_bytes_cap=16384,
  new_IMG_bytes_read=0,CPU_cases_executed=0,heap_mutex_music_admission_guests_run=False,old_suites_replayed=False,
  original_unknown_returns_faked=False,MAIN_or_shared_seals_canonicals_devices_mutated=False,
  original_1EE324_format_and_32C4BE_lookup_identified_static=True,internal_names_are_user_street_text=False,
  actual_internal_name_key_and_FS_pair_established=False,uninterrupted_query_UI_device_App_full_Taiwan_verified=False,
  all_actual_source_handles_closed=True,next_minimum_gap=dict(
   entry='1F18F0/32C4BE registry source record before1F1914 formatter and1F1952 constructor',
   needed=['actual01287A3Cblock/28Brecordproducerandkeycursor','recordbyte0/byte1prefixmeaning',
    'record+4/+6u16actualcomponentbinding','2FBA70originalFSownership/openpaircontract'],
   limits='Do not fill these fields from JAI/tuple IDs or use a successful host string as native frontend proof. No allocator/admission continuation.'))
 write('proof.json',proof)
 print(json.dumps(dict(all_assigned_checks_passed=True,witnesses=5,new_MAIN_bytes_read=0,new_IMG_bytes_read=0,
  CPU_cases_executed=0,proof_sha256=sha((HERE/'proof.json').read_bytes()))))
if __name__=='__main__':main()
