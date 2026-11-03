#!/usr/bin/env python3
"""Pure read-only source/runtime-file/opcode review; no Unicorn construction."""
import ast,hashlib,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_sdp_activation import trace
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 failure=BASE/'guest-v1/terminal-failure.json';receipt=BASE/'guest-v1-terminal-tool-receipt.json'
 r=json.loads(failure.read_text());t=json.loads(receipt.read_text())
 assert not r['all_passed']and r['error']=='unexpected opaque allocation shape'
 assert r['registers']=={'pc':'0x38853c','lr':'0x277833','sp':'0x880fe28'}
 assert t['tool_result']['exit_code']==1 and t['tool_result']['chunk_id']=='543390'
 assert r['phase']=='original_start_selector_factory_and_capture'and not r['cases_completed']
 assert not r['readers']and not r['full_returns']
 oldseal=BASE/'audio-session-build-only-handoff-seal.json'
 oldledger=BASE/'build-only-source-output-ledger.json'
 seal=json.loads(oldseal.read_text());ledger=json.loads(oldledger.read_text())
 assert sha(oldseal)=='0a925b5c24272b740d3f6b8f87034c3f34a032da104263507986bfdd0eb105d4'
 assert sha(oldledger)==seal['ledger_sha256']
 for registry in ('source_sha256','output_sha256'):
  for p,h in ledger[registry].items():assert sha(ROOT/p)==h,p
 image=NativeImage();assert sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')==EXPECTED
 assert image.word(0x277e94)==0x215
 expected={0x2777f0:'ffb5',0x2777f2:'83b0',0x277824:'208a',
  0x27782a:'3246',0x27782c:'0221',0x277832:'3068',0x27783a:'228a',0x27783c:'1231'}
 # Register-copy encodings depend on compiler/tool mnemonic spelling; compare
 # actual instructions/operands as decoded from the original bytes below.
 actual={i.address:i.mnemonic+' '+i.op_str for i in image.instructions(0x2777f0,0x277862)}
 required={0x2777f0:'push {r0, r1, r2, r3, r4, r5, r6, r7, lr}',
  0x2777f2:'sub sp, #0xc',0x277824:'ldrh r0, [r4, #0x10]',
  0x27782a:'movs r2, r6',0x27782c:'movs r1, #2',0x27782e:'bl #0x38853c',
  0x277832:'ldr r0, [r6]',0x277834:'bl #0x388804',0x27783a:'ldrh r2, [r4, #0x10]',
  0x27783c:'adds r1, #0x12',0x27783e:'blx #0x3732c8',
  0x277844:'bl #0x388b22',0x27784e:'ldr r0, [sp, #4]',0x277850:'bl #0x388b22'}
 for pc,description in required.items():assert actual[pc]==description,(hex(pc),actual[pc])
 journal=r['CPU_store_journal'];push=[e for e in journal if e['PC']=='0x2777f0']
 assert len(push)==9 and [int(e['address'],16)for e in push]==list(range(0x0880fe34,0x0880fe58,4))
 assert [e['value']for e in push[:4]]==[0x034e80f0,0,0x0880feac,0x0880fec4]
 length=[e for e in journal if e['PC']=='0x277cdc']
 assert len(length)==1 and length[0]['address']=='0x9700030'and length[0]['size']==2 and length[0]['value']==524
 assert 0x0880feac==int(r['registers']['sp'],16)+0x84
 v2=BASE/'emulate_audio_session_v2.py';ast.parse(v2.read_text(),filename=str(v2))
 source=dict(ledger['source_sha256'])
 for p in (v2,Path(__file__).resolve(),failure,receipt,oldseal,oldledger):source[rel(p)]=sha(p)
 facts=dict(original_entry={'PC':'0x38853c','LR':'0x277833','SP':'0x0880fe28'},
  instruction_trace=r['trace'],native_phase=r['phase'],actual_node_halfword_store=length[0],
  actual_2777F0_saved_R0_R3=[dict(address=e['address'],value=hex(e['value']),ordinal=e['ordinal'])for e in push[:4]],
  derived_next_request={'r0':'0x20c','r1':'0x2','r2':'0x0880feac',
   'derivation':'original277824 node length +27782A R2=R6/R6=entryR2 +27782C R1=2; linked CPU push/length journal',
   'r0_r1_r2_live_snapshot_present':False,'r3_not_asserted':True},
  original_queue_registration_complete='setup progressed through return guards before aas_select; frozen failure omits the lower_returns array',
  original_factory_index_busy_reader_full_pull_not_reached=True)
 erratum=dict(all_passed=True,scope='verified v1 failure facts and exact source/opcode derivation only',
  source_sha256=source,authoritative_terminal_tool_receipt_path=rel(receipt),terminal_tool_chunk_id='543390',
  terminal_exit_code=1,v1_guest_success=False,observed=facts,
  correction='v1 pure build/static checks did not validate selector kind2 temporary allocation ABI. Queue-only fixture kind3 rejected before native allocator body. This does not prove original selector allocator failure.',
  all_original_v1_build_seal_sources_outputs_unchanged=True,
  existing_build_only_all_passed_is_not_guest_success=True,no_partial_runtime_promoted_to_complete=True,
  missing_snapshot=['v1 failure did not preserve liveR0..R12/CPSR','v1 failure omitted full lower_return rows and whole initial/finalRW zones'],
  V2_new_failure_snapshot_includes_all_GP_CPSR_and_whole_RW=True,
  native_heap_allocator_or_pinning_or_full_pull_success_proven=False,device_io=False)
 dump(BASE/'audio-session-v1-failure-scope-erratum.json',erratum)
 source[rel(BASE/'audio-session-v1-failure-scope-erratum.json')]=sha(BASE/'audio-session-v1-failure-scope-erratum.json')
 fragments={hex(a):dict(bytes=image.read(a,b-a).hex(),instructions=
   [dict(PC=hex(i.address),instruction=i.mnemonic+' '+i.op_str,bytes=i.bytes.hex())for i in image.instructions(a,b)])
   for a,b in ((0x2777f0,0x277862),(0x277ac2,0x277afc),(0x277c9a,0x277cf8),(0x2f9fec,0x2fa01e))}
 preflight=dict(all_passed=True,scope='static v2 source/ABI contract; no guest run',source_sha256=source,
  v1_failure_facts=facts,original_bounded_fragments=fragments,
  bounded_CFG_2777F0=trace(image,0x2777f0,180),
  exact_new_fixture_table=[
   dict(entry='0x38853c',normalized_LR='0x277832',length524=True,kind=2,
    output_cell='actual2777F0 entryR2/48-byte frame/SP+0x84',length_source='actual live type3 queue node+0x10 uint16',
    fixture_mutations=['new private backing with32-byte canaries','outcell stores synthetic handle only'],
    native_allocator_body_executed=False),
   dict(entry='0x388804',normalized_LR='0x277838',handle='new selector kind2 handle',
    fixture_result='its declared backing pointer; original27783E copies524 bytes from node+0x12'),
   dict(entry='0x388b22',normalized_LR='0x277848',original_BX_LR=True,
    original_copy524_verified_before_completion=True),
   dict(entry='0x388804',normalized_LR='0x2f9ff6',handle='same live selector handle',
    original_copy524_verified_before_query=True),
   dict(entry='0x3887a2',normalized_LR='0x2fa018',fixture='unchanged inherited release clears handle cell; no original core heap release claim')],
  parent_guards_preserved=['frozen build-v3 ELF exact dde2664a10207a2aa4aec3c25b13355eb5e5bb99d864f7eb507a8ff62cabdca2',
    'no changes to C/assembly/session helper/oldv1 runner',
    'source-derived index/busy CPU stores; no host seed',
    'full native64-byte return and live1/1 leases then0/0',
    'whole joint CPU/fixture ordinal replay and unchanged RX',
    'neighbor17 records,opaque/caller/mixer/scratch/input boundaries,fixture mutex balances,witness-200',
    'same positive512byte/two256pull and Stop-denial cases'],
  extra_observer_constraints=['kind2 queries only exact native callers and livehandle',
    'node original length/type/flags are copied by CPU, not host',
    'temporary524-byte handle has exactly allocate/query/BXLRcompletion/query then inherited release',
    'type2 allocation failure not supplied; no forged factory/prepare/reader return'],
  limits=['lower allocator/query/release/mutex/wake/priority/messages remain explicit fixtures',
    'actual request0 or failed allocator branch not covered',
    'old v1 runtime failed before factory/index/fullreader; no positive complete pipeline yet',
    'actual2FA572 native mixer caller/source-owner handoff/lifecycle/exclusive/kernel/hardware/App remain unverified'],
  command='staging/unicorn-stream-venv/bin/python -B staging/native-player-native-allocation/audio-session-static/emulate_audio_session_v2.py',
  runtime_directory=rel(BASE/'guest-v2'),success_proof=rel(BASE/'audio-session-emulation-v2-proof.json'),
  failure_path=rel(BASE/'guest-v2/terminal-failure.json'),
  receipt_requested=rel(BASE/'guest-v2-terminal-tool-receipt.json'),
  guest_executed=False,device_io=False,no_canonical_writes=True)
 dump(BASE/'selector-opaque-v2-preflight.json',preflight)
 print(json.dumps(dict(all_passed=True,v2_runner_sha256=sha(v2),
   erratum_sha256=sha(BASE/'audio-session-v1-failure-scope-erratum.json'),
   preflight_sha256=sha(BASE/'selector-opaque-v2-preflight.json'),guest_executed=False)))
if __name__=='__main__':main()
