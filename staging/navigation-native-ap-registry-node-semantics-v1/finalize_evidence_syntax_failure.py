#!/usr/bin/env python3
"""Seal-oriented bounded audit, interpreting only exact saved/new windows.

No guest rerun, MAIN data read, IMG read or device operation. One sealed peer
page is read to resolve a previously unbacked saved-window literal precisely.
"""
from pathlib import Path
import hashlib,json,struct

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent

def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(n,d):(HERE/n).write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')

def main():
 ledger=json.loads((HERE/'read-ledger.json').read_bytes());assert ledger['bytes']==4122 and ledger['operations']==53 and ledger['bytes']<=32768
 assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin')==ledger['MAIN_stat']
 ws=[];captures=[]
 for r in ledger['batches']:
  b=(ROOT/r['path']).read_bytes();assert sha(b)==r['sha256'];d=json.loads(b)
  assert d['MAIN_stat_before']==d['MAIN_stat_after']==ledger['MAIN_stat']
  assert d['source_sha256']==sha((HERE/'capture_windows.py').read_bytes())
  ws+=d['windows'];captures.append(dict(path=r['path'],sha256=sha(b),bytes=d['explicit_read_bytes'],operations=d['explicit_read_operations']))
 assert sum(x['bytes']for x in captures)==4122 and sum(x['operations']for x in captures)==53
 reuse_b=(HERE/'reused-windows.json').read_bytes();reuse=json.loads(reuse_b)
 assert reuse['source_sha256']==sha((HERE/'prepare_reused_windows.py').read_bytes())
 ws+=reuse['windows']
 old=ROOT/'staging/navigation-native-ap-map-registry-consumer-v1';seal=(old/'sealed-files.json').read_bytes()
 assert sha(seal)=='bedfbf5d3f6ec8ea1e988aa81b1cf0c7533d8e88ac872c50aae9f5e2b83fdce6'
 manifest={x['path']:x for x in json.loads(seal)['files']}
 inherited=[]
 for n in ['windows-seeds.json','windows-selectors.json','windows-registrations.json']:
  p=old/n;b=p.read_bytes();assert sha(b)==manifest[str(p.relative_to(ROOT))]['sha256']
  inherited.append(dict(path=str(p.relative_to(ROOT)),sha256=sha(b),sealed=True));ws+=json.loads(b)['windows']
 peer=ROOT/'staging/navigation-native-query-provider-full-getter-v1';pb=(peer/'sealed-files.json').read_bytes()
 assert sha(pb)=='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'
 pm={x['path']:x for x in json.loads(pb)['files']};p=peer/'MAIN-page-0032c000.bin';before=stat(p);b=p.read_bytes()
 assert len(b)==4096 and sha(b)==pm[str(p.relative_to(ROOT))]['sha256'] and stat(p)==before
 node_literal=b[0x184:0x188];assert struct.unpack('<I',node_literal)[0]==0x1286bcc
 supplement=dict(schema='sealed-peer-page-literal-resolution/v1',source_path=str(p.relative_to(ROOT)),source_page_sha256=sha(b),peer_seal_sha256=sha(pb),source_stat_before=before,source_stat_after=stat(p),runtime='0x32c184',raw_hex=node_literal.hex(),value='0x1286bcc',saved_page_local_read_bytes=4096,new_MAIN_reads=0,new_IMG_reads=0,handles_closed=True)
 save('shared-node-base-literal.json',supplement)
 def raw(a,n):
  hits=[bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'],16):a-int(w['runtime_start'],16)+n]for w in ws if int(w['runtime_start'],16)<=a and a+n<=int(w['runtime_start'],16)+w['bytes']]
  assert hits and all(x==hits[0]for x in hits),(hex(a),n)
  return hits[0]
 def rows(a,n):
  out={}
  for w in ws:
   for i in w['instructions']:
    x=int(i['address'],16)
    if a<=x<a+n:
     # Saved corrected-entry windows supersede untrusted linear decoding from
     # unrelated starts. Exact bytes remain independently checked below.
     if x not in out or w['name'] in ['threshold_caller','registry_kind5_linker','list_record_field6_writer']:
      out[x]=i
  for x,i in out.items():assert raw(x,len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
  return [out[x]for x in sorted(out)]
 def frag(a,n):return dict(start=hex(a),bytes=n,raw_hex=raw(a,n).hex(),instructions=rows(a,n))
 baseline=raw(0x871e2a,4);assert baseline.hex()=='0101d107'
 assert raw(0x2bf474,4).hex()=='509510ea'
 assert struct.unpack('<I',raw(0x6e49d8,4))[0]==0x49249249
 assert struct.unpack('<I',raw(0x110414,4))[0]==0xfffe
 assert raw(0x10ce3c,8).hex()=='00221100100024e7'
 witnesses=[
  dict(id='Date_week_threshold_source',entry='0x1100aa',
   fragments=[frag(0x1100aa,72),frag(0x1be16e,102),frag(0x2bf474,4),frag(0x6e49bc,32)],
   baseline_struct=dict(address='0x871e2a',raw_hex=baseline.hex(),month=1,day=1,year=2001),
   exact_arithmetic='SP+70 day ordinal minus 2001-01-01 day ordinal; original ARM target returns quotient /7 in r1; caller stores its low16 at SP+6C. For pre-base day input it keeps FFFE.',
   division_magic='0x49249249',
   CPU_scope='already converted day ordinal fixtures; real clock/string/date source is not executed',
   does_not_prove='that record+6 is written as an expiry date, or that the physical v3 regression takes this guard'),
  dict(id='Header_field6_registry_guard_condition',
   fragments=[frag(0x110f9e,30),frag(0x110fbe,34),frag(0x110fee,34),frag(0x111052,4)],
   exact_condition='Initialize minimum FFFF, minimize linked node.recordptr+6 u16. Matching typed119D key pair calls10E328; false status sets SP+60=0, true status restores the original minimum via111052. Guard clears when effective minimum <= date-derived SP+6C; BHI retains.',
   comparison_is_unsigned=True,
   header_field6_write_origin='unresolved',
   field6_semantic_name='unassigned; its use is compared to a calendar-week threshold',
   statement_is_static_controlflow_not_actual_v3_execution=True),
  dict(id='Typed_kind5_block_links_to_shared_query_registry',
   fragments=[frag(0x10f170,170),frag(0x32be40,224)],
   registry='0x1286bcc + 24*slot',resolved_registry_literal=supplement,
   observed_linker='Type101A iterator; payload byte+1 high3bits==5; pair payload+8/+C matched; linked node {payload,next} inserted; registry+0C sums payload+2 counts.',
   shared_query_consumer='Original32BE40 traverses the same head, reads block+2 signed descriptor count, and addresses block+100+80*index.',
   relation_to_peer_scope='Peer sealed real metadata getter independently binds MDR1 mapID to descriptor+2C; that guest uses preinitialized registry/slot fixtures, not cold Map load.',
   peer_seal_sha256=sha(pb),
   block_field6_producer_and_relation_to_MDR_fields_unproved=True),
  dict(id='Typed_record_keypair_cleanup_and_zero_key_wrapper',
   fragments=[frag(0x10cc8e,430),frag(0x10ce3c,8)],
   observed_types=['101A','101B','110A','11A0','119D','11CA','11C0','118C'],
   keypair_offsets_by_type={'101A':[8,12],'101B':[4,8],'110A':[4,8],'11A0':[4,8],'119D':[0,4],'11CA':[8,12],'11C0':[0,4],'118C':[4,8]},
   original_behavior='Iterate typed records through2CABBC. For matching input two-word pair, or zero pair wildcard, call2CAAEA on record. Another10CC28 call remains semantically unclosed.',
   wrapper_10CE3C='Zero r0/r1/r2 then B10CC8E; this is a wildcard typed-record cleanup entry, not proof of full Map reload or renderer selection.',
   record_removal_callee_not_executed_or_faked=True),
  dict(id='Runtime_status_predicate_10E328',
   fragments=[frag(0x10e328,70),frag(0x2caee2,16),frag(0x221644,20),frag(0x22457c,38)],
   global=dict(base='0xf06ef4',active_byte_offset=3,value_word_offset=32),
   two_slots=dict(base='0x12787c0',stride=64,active_byte_offset=1,value_word_offset=16),
   exact_behavior='At most99 repeated reads of the same global value; if none match, test two slots. Return1 for an active matching opaque value, otherwise0.',
   value_identity='opaque runtime value; not established as mapID, physical offset, draw priority or MDR directory value',
   completed_CPU_cases=['global_active_match','only_second_slot_match','all_active_values_different'])
 ]
 save('node-semantics-witnesses.json',dict(schema='bounded-ap-registry-node-semantics-witnesses/v1',witness_count=5,witnesses=witnesses,raw_byte_checks_passed=True))
 cb=(HERE/'new-state-cpu-proof.json').read_bytes();cpu=json.loads(cb)
 assert cpu['source_sha256']==sha((HERE/'run_new_state_corrected_cases.py').read_bytes())
 assert cpu['case_count']==7 and cpu['all_passed'] and cpu['semantic_hooks']==[] and cpu['IMG_reads']==0
 assert sum(c['instructions']for c in cpu['cases'])==3402
 for x in cpu['inputs']:assert sha((ROOT/x['path']).read_bytes())==x['sha256']
 partial=json.loads((HERE/'new-state-partial-results.json').read_bytes());assert partial['case_count']==7 and partial['source_sha256']==cpu['source_sha256']
 for n,source in [('guest-fixture-failure.json','run_new_state_cases.py'),('caller-expectation-failure.json','run_new_state_pending_cases.py')]:
  d=json.loads((HERE/n).read_bytes());assert d['source_sha256']==sha((HERE/source).read_bytes())
 prep=json.loads((HERE/'initial-preparation-failure.json').read_bytes())
 for r in prep['executed_sources']:assert sha((HERE/r['snapshot']).read_bytes())==r['sha256']
 receipts=dict(schema='actual-node-semantics-scope-tool-receipts/v1',
  MAIN_capture_tools=[dict(tag=t,tool_chunk=c,exit_code=0)for t,c in [('callees','54b537'),('sources',None),('constructors','0a7ef8'),('recordparse','8c21b9'),('threshold','018044'),('division','9997e7'),('typednodes','a91f1b')]],
  sources_batch_receipt='capture-sources-terminal.txt and windows-sources.json actual_read_receipts preserve the actual successful batch; chunk identifier omitted rather than reconstructed.',
  actual_MAIN_reads=dict(bytes=4122,operations=53,limit=32768,stat_before=ledger['MAIN_stat'],stat_after=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin'),whole_read_or_hash=False),
  cached_page_reads=dict(initial_failed_preparation=8192,corrected_preparation=8192,final_literal_resolution=4096,total_saved_page_local_bytes=20480,new_MAIN_bytes=0),
  failed_preparation=dict(receipt='initial-preparation-failure.json',tool_chunk='999348',exit_code=1),
  dependent_guest_not_started=dict(tool_chunk='81cb7a',exit_code=1,missing_prepared_input=True,guest_started=False),
  failed_new_guest_attempts=[dict(tool_chunk='a723eb',exit_code=1,receipt='guest-fixture-failure.json',durable_completed_cases=0),dict(tool_chunk='4657f9',exit_code=1,receipt='caller-expectation-failure.json',durable_completed_cases=0)],
  corrected_preparation=dict(tool_chunk='e085a0',exit_code=0,MAIN_reads=0,IMG_reads=0),
  completed_new_guest=dict(tool_chunk='8e44de',exit_code=0,cases=7,completed_original_instructions=3402,source_sha256=cpu['source_sha256'],proof_sha256=sha(cb),semantic_hooks=[]),
  old_guard3_mount3_reader15_cases_notrun=True,IMG_reads=0,device_operations=False,handles_closed=True)
 save('actual-tool-receipts.json',receipts)
 proof=dict(schema='bounded-ap-registry-node-semantics-review/v1',
  source_sha256=sha(Path(__file__).read_bytes()),captures=captures,inherited_captures=inherited,
  peer_seal_sha256=sha(pb),reuse_sha256=sha(reuse_b),CPU_proof_sha256=sha(cb),
  witnesses_sha256=sha((HERE/'node-semantics-witnesses.json').read_bytes()),
  receipts_sha256=sha((HERE/'actual-tool-receipts.json').read_bytes()),
  all_assigned_bounded_checks_passed=True,closed_with_producer_gap=True,
  completed_original_CPU_cases=7,completed_original_instructions=3402,
  fresh_MAIN_read_bytes=4122,fresh_MAIN_read_operations=53,MAIN_read_cap=32768,
  IMG_reads=0,IMG_read_cap=65536,source_stats_stable=True,
  precise_field_result='SP+6C is derived from calendar days since2001-01-01 divided by7, normalizedlow16. Headerpayload+6 is minimized asu16 and compared with it; its writing producer remains unlocated.',
  node_query_bridge='Type101A kind5 payloads link into same1286BCC+24slot traversed by actual32BE40; peer realMDR getter binds descriptor+2C mapID independently.',
  corrections=[
   'Initial hypothesis that2BF474 might divide byFFFE or produce a modulo was rejected by originalARMbytes: target6E49BC is specialized divide7; FFFE is only a pre-base sentinel.',
   'Previous closed consumer scope named10CE3C a Map reload frontier. This new scope proves its exact8bytes are zero-keypair B10CC8E, wildcard typed-record cleanup.',
   'Capture nameordinal_state_getter at2CAEE2 is provisional: original code ignores ordinal argument and reads one active global value.',
   'New guest attempts omitted actualSP+70 fixture then incorrectly expectedcallee remainder aftercaller overwrittenr0; all failures/exactsource preserved, no failed case counted asdurablepass.',
   'Saved32BE40 window initiallyleftPC literal32C184 unresolved; a separate sealedpeerpage resolution now provides actual1286BCC value without MAINreread.'
  ],
  fixtures=['already converted calendar day ordinals', 'synthetic originalruntime global and two-slot status RAM', 'originalreturn sentinel observer stop'],
  semantic_hooks=[],unknown_callee_returns_not_substituted=True,
  remaining_blockers=[
   'Producer writingtype101A/kind5 blockpayload+6 is unlocated; exactdate/expiry/validity semanticname remainsunassigned.',
   'Live31CD76 clock/data delivery andactualslotstatus values were notobserved.',
   'Two-word keypairidentity and2CAAEA/10CC28 completeeffects remainunexecuted.',
   'ActualcoldAPfilenameopener,registryconstruction/Mapadmission,other-layerdisplaypolicy,boardcache/window remainunproved.',
   'Thisdate/statusguard hasnotbeenboundtoa realv3failure;128MiBphysical-positionhypothesisremainsopen.'
  ],
  minimal_next_entry='Locateactualtype101A/kind5 payload producer before2CA82C registration; tracewritingpayload+6,withoutrepeatingdate/statuscases.',
  live_registry_or_clock_proved=False,physical_128MiB_guard_proved=False,
  v3_road_regression_rootcause_proved=False,renderer_or_device_acceptance=False,
  install_candidate_created=False,shared_or_sealed_input_modified=False,
  full_address_update_completed=False,all_scope_handles_closed=True)
 save('proof.json',proof)
 print(json.dumps(dict(bounded_audit_passed=True,MAIN_bytes=4122,IMG_bytes=0,durable_new_CPU_cases=7,completed_original_instructions=3402,field6_producer_unresolved=True,handles_closed=True)))

if __name__=='__main__':main()
