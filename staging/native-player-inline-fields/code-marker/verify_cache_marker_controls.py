#!/usr/bin/env python3
"""File-only independent verifier: no Uc construction, guest/device/sound calls."""
import sys
sys.dont_write_bytecode=True
import json,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent;IMAGE=0x2d4bb74
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
proof=json.loads((OUT/'cache-marker-emulation-proof.json').read_text())
require(proof['all_passed'] and proof['case_count']==5,'All five guest controls required')
checks={};cases={};sources={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__)),str((OUT/'cache-marker-emulation-proof.json').relative_to(ROOT)):sha(OUT/'cache-marker-emulation-proof.json')}
for p,h in proof['source_sha256'].items():require(sha(ROOT/p)==h,'Frozen source hash differs: '+p);sources[p]=h
builds=json.loads((OUT/'build-manifest.json').read_text())['builds'];md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
for r in proof['cases']:
 p=ROOT/r['artifact'];require(sha(p)==r['artifact_sha256'],'Runtime control hash differs');sources[str(p.relative_to(ROOT))]=sha(p);c=json.loads(p.read_text());name=c['name'];cases[name]=c
 zones=c['whole_zone_CPU_replay'];replay={k:bytearray.fromhex(z['before_hex']) for k,z in zones.items()}
 for event in c['CPU_write_journal']:
  z=zones[event['zone']];offset=event['address']-z['address'];n=event['size'];require(0<=offset and offset+n<=z['bytes'],'CPU store escaped whole-zone input');require(bytes(replay[event['zone']][offset:offset+n]).hex()==event['before_hex'],'CPU independent store-before mismatch');replay[event['zone']][offset:offset+n]=(event['value']&((1<<(8*n))-1)).to_bytes(n,'little')
 require(all(bytes(replay[k]).hex()==z['after_hex'] for k,z in zones.items()),'Independent whole-zone replay mismatch')
 before=bytes.fromhex(zones['record']['before_hex']);after=bytes.fromhex(zones['record']['after_hex']);require(len(before)==len(after)==1912,'Native record shape');require(before[:0x6b8]==after[:0x6b8] and before[0x6c2:]==after[0x6c2:],'Native record changed outside version10 bytes');require(before[0x6b8:0x6c2]=='2.10\0'.encode('utf-16le'),'Native metadata baseline is not stock2.10')
 require(after[0x760]==1 and struct.unpack_from('<I',after,0x764)[0]==0xca73f5a,'Native accepted record/type/checksum changed');require(c['native_registry'][0]['volume_id']=='mei-lingb','Native late identity differs')
 expected='M7Q9\0' if name=='preserving_marker' else '2.10\0';require(after[0x6b8:0x6c2].hex()==c['getter_version_utf16_hex']==c['consumer_input_utf16_hex']==expected.encode('utf-16le').hex(),'CPU marker/getter/page input mismatch')
 for k in ['list_mutex','heap_mutex']:
  b=bytes.fromhex(zones[k]['after_hex']);require(struct.unpack_from('<II',b,8)==(0,0) and struct.unpack_from('<H',b,20)[0]==0,'Native semaphore remains owned/waiting/recursive')
 require(struct.unpack_from('<I',bytes.fromhex(zones['fixture_tcb']['after_hex']),32)[0]==0,'Fixture TCB owned chain not released')
 require(c['native_mutex_calls'] and all(x['returned'] and x['epilog_seen'] for x in c['native_mutex_calls']),'Actual mixed body epilog/continuation missing')
 raw={'original_baseline':[11],'preserving_marker':[11],'wrong_identity':[11],'first_native_raw6':[6],'retry_native_raw6':[5,6]}[name]
 require([x['raw_return'] for x in c['entry_layers']]==raw==[x['raw_return'] for x in c['original_bootstrap_layers']],'Native bootstrap and entry layers conflated');require([x['pc'] for x in c['MAIN_mapper_layers']][-1]=='0x2404c6','Actual selector return layer missing')
 require(c['MAIN_mapper_layers'][-1]['r0']==(6 if name=='retry_native_raw6' else 11),'Actual MAIN first/retry mapping differs');require(c['selected_index']==(255 if name=='retry_native_raw6' else 0),'Late native publication differs');require(c['late_selection_CPU_stores'][-1]['pc']==(0x2404d0 if name=='retry_native_raw6' else 0x2404ca),'Publication occurred at wrong original opcode')
 require(all(x['count']==40 for x in c['native_registration']),'Original40 registration missing');require(c['native_registration'] and len(c['native_registration'][-1]['targets'])==40,'Actual40 targets absent')
 require(c['consumer_fragment']=={'entry':'0x6817d2','original_ARM_veneer':'0x52c5ec','original_getter':'0x2744f6','stop_before':'0x6817d6','rendered_UI':False},'Page consumer claim exceeds fragment')
 if name=='preserving_marker':
  m=next(m for m in builds if m['name']==name);b=(ROOT/m['combined_file']).read_bytes();events=c['marker_CPU_stores'];start=zones['record']['address']+0x6b8;require(len(events)==5 and [x['address'] for x in events]==list(range(start,start+10,2)),'Actual5 UTF16 store addresses/NUL range differs');require([x['value'] for x in events]==[77,55,81,57,0],'Actual4 characters +NUL differs')
  for e in events:
   op=bytes.fromhex(e['opcode_hex']);require(e['size']==2 and not(e['cpsr']&32),'Marker store is not real ARM16bit write');require(b[e['pc']-IMAGE:e['pc']-IMAGE+4]==op,'Actual CPU opcode differs from built image');ins=list(md.disasm(op,e['pc']));require(len(ins)==1 and ins[0].mnemonic=='strh','Marker is not appended STRH instruction')
  state=bytes.fromhex(c['prototype_state_hex']);require(struct.unpack_from('<7I',state)==(0x50000,11,1,0,c['native_registry'][0]['handle'],zones['record']['address'],0),'Private CPU state raw result/identity not exact')
 else:require(not c['marker_CPU_stores'],'Rejected/version control executed marker store')
 checks[name+'_independent_CPU_replay_and_layers']=True
baseline=cases['original_baseline']
for name in ['preserving_marker','wrong_identity']:
 for k in ['original_module_postheader_runtime_sha256','original40_stubs_sha256','original40_storage_sha256','original99_imports_sha256']:require(cases[name][k]==baseline[k],'Preserving entry changed native runtime/40/imports')
 checks[name+'_preserves_original_runtime_40_and_imports']=True
samples=proof['resource_samples'];hwm=max(int(s['proc']['VmHWM'].split()[0]) for s in samples);rss=max(int(s['proc']['VmRSS'].split()[0]) for s in samples);require(hwm<200*1024 and rss<200*1024,'Actual process /proc resource bound failed');checks['actual_process_stage_VmHWM_and_VmRSS_below_200MiB']=True
require(proof['protected_before_after']['count']==1363 and proof['protected_before_after']['all_unchanged'],'Protected baseline registry missing');checks['1363_protected_stream_hashes_unchanged']=True
require(not any(proof[k] for k in ['device_io','audible_output','modified_VPM_or_SIG_generated','device_install_candidate','physical_changed_code_acceptance_verified','complete_App_or_music_goal']),'Claim exceeds emulation-only scope')
out={'all_passed':all(checks.values()),'assertions':checks,'case_count':5,'source_sha256':sources,'proc_stage_VmHWM_peak_KiB':hwm,'proc_stage_VmRSS_peak_KiB':rss,'previous_rusage_failures_preserved':True,'rusage_504320KiB_not_equated_with_current_guest_RSS':True,'rusage_VmHWM_disagreement_cause':'unknown; no optimization/cause conclusion','normal_layers':{'original_bootstrap':11,'compiled_entry':11,'MAIN_first':11},'typed_version_fixture_layers':{'first':[6,6,11],'retry_original_bootstrap_and_entry':[5,6],'MAIN_retry':6},'CPU_UTF16_marker_and_original_getter_consumer_input_verified':True,'complete_native_kernel_or_UI_or_physical_acceptance_verified':False,'emulation_only':True,'guest_or_device_executed_by_this_verifier':False,'limits':proof['limits']}
(OUT/'cache-marker-independent-verification.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_passed':out['all_passed'],'assertion_count':len(checks),'actual_proc_VmHWM_peak_KiB':hwm,'verification':'staging/native-player-inline-fields/code-marker/cache-marker-independent-verification.json'}))
