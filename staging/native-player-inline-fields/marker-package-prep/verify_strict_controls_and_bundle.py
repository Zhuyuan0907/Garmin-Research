#!/usr/bin/env python3
"""Pure file verification. No emulator instance/device/installer/sound calls."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_tts_vpm import parse_image
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
proof=json.loads((OUT/'strict-marker-control-proof.json').read_text());bundle=json.loads((OUT/'local-marker-bundle-manifest-v2.json').read_text());m=json.loads((OUT/'strict_marker/manifest.json').read_text());checks={};cases={};sources={}
for registry in [proof['source_sha256'],bundle['source_sha256']]:
 for p,h in registry.items():require(sha(ROOT/p)==h,'Sealed source changed: '+p);sources[p]=h
binary=(ROOT/m['combined_file']).read_bytes();require(hashlib.sha256(binary).hexdigest()==m['binary_sha256'],'Actual tested BIN changed');md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
for row in proof['cases']:
 p=ROOT/row['path'];require(sha(p)==row['sha256'],'Control artifact hash mismatch');c=json.loads(p.read_text());cases[c['name']]=c;sources[row['path']]=row['sha256'];zones=c['whole_zone_CPU_replay'];replay={k:bytearray.fromhex(z['before_hex']) for k,z in zones.items()}
 for e in c['CPU_write_journal']:
  z=zones[e['zone']];off=e['address']-z['address'];n=e['size'];require(0<=off and off+n<=z['bytes'],'Store outside strict whole zone');require(bytes(replay[e['zone']][off:off+n]).hex()==e['before_hex'],'Strict store-before mismatch');replay[e['zone']][off:off+n]=(e['value']&((1<<(8*n))-1)).to_bytes(n,'little')
 require(all(bytes(replay[k]).hex()==z['after_hex'] for k,z in zones.items()),'Strict independent whole-zone replay failed')
 require(all(r['returned'] and r['epilog'] and r['raw_return'] in [0,1] for r in c['try_calls']),'Original nonblocking try body completion missing')
 require(all(r['raw_return']==11 for r in c['native_entry_and_bootstrap_rows']['entry']) and all(r['raw_return']==11 for r in c['native_entry_and_bootstrap_rows']['bootstrap']),'Original raw11 not forwarded')
 require(struct.unpack_from('<I',bytes.fromhex(zones['fixture_tcb']['after_hex']),32)[0]==0,'Current fixture retains native owner chain')
 for k in ['list_mutex','slot_record']:
  b=bytes.fromhex(zones[k]['after_hex']);off=8 if k=='list_mutex' else 12;require(struct.unpack_from('<I',b,off)[0]==0,'Native list/slot not released')
 fileafter=bytes.fromhex(zones['outer_file']['after_hex']);require(struct.unpack_from('<I',fileafter,40)[0]==(0x0803d000 if c['name']=='foreign_file_lock' else 0),'Native file owner release/foreign preservation failed')
 a=bytes.fromhex(zones['record']['before_hex']);b=bytes.fromhex(zones['record']['after_hex']);require(a[:0x6b8]==b[:0x6b8] and a[0x6c2:]==b[0x6c2:],'Strict record changed outside10 versionbytes')
 if c['name']=='valid_unique_repeat':
  stores=c['CPU_marker_stores'];require(len(stores)==5 and [e['value'] for e in stores]==[77,55,81,57,0],'Strict actual five UTF16 stores/NUL missing')
  for e in stores:
   op=bytes.fromhex(e['opcode_hex']);require(binary[e['pc']-0x2d4bb74:e['pc']-0x2d4bb74+4]==op,'Strict CPU opcode differs from actual bundleBIN');require(next(md.disasm(op,e['pc'])).mnemonic=='strh','Strict writer is not ARM STRH')
  require(c['actual_retained_before_utf16_hex']=='2.10\0'.encode('utf-16le').hex(),'Not actual original before value');f=bytes.fromhex(c['first_private_state_hex']);s=bytes.fromhex(c['second_private_state_hex']);require(f[40:50]==s[40:50] and struct.unpack_from('<I',s,16)[0]==2 and struct.unpack_from('<I',s,24)[0]==17,'Repeated native entry overwrote before bytes')
 else:require(not c['CPU_marker_stores'],'Negative input wrote marker')
 checks[c['name']+'_whole_replay_return_release_guard']=True
require(len(cases)==8 and proof['1363protected_unchanged'],'Strict suite/protected source scope')
candidate=ROOT/bundle['candidate_path'];rollback=ROOT/bundle['rollback_path'];original=ROOT/bundle['original_backup'];require(sha(candidate)==bundle['candidate_sha256'],'Local candidate differs');require(sha(rollback)==sha(original)==bundle['rollback_sha256'],'Rollback not byte-identical original')
old,og=parse_image(original.read_bytes());new,ng=parse_image(candidate.read_bytes());require(new.keys()==old.keys(),'Member set differs');require(new['DLLIMG.BIN']['content']==binary,'Candidate member is not actual tested BIN');require(all(new[k]['content']==r['content'] for k,r in old.items() if k!='DLLIMG.BIN'),'DLLINFO/SIG/another original member changed');require(len(new['DLLIMG.SIG']['content'])==72,'SIG size differs');checks['all_original_other_member_payloads_DLLINFO_SIG_byte_identical']=True;checks['exact_original_rollback_single_file']=True
diff=json.loads((ROOT/bundle['diff_path']).read_text());a=original.read_bytes();b=candidate.read_bytes();replay=bytearray(a);replay.extend(bytes(len(b)-len(a)))
for r in diff['diff_ranges']:
 off,n=r['offset'],r['bytes'];require(a[off:off+n].hex()==r['original_hex'],'Package diff original bytes mismatch');replay[off:off+n]=bytes.fromhex(r['candidate_hex'])
require(bytes(replay)==b,'Complete package byte diff does not replay');checks['complete_package_diff_replay']=True
require(proof['native_baseline_original40_imports_postheader_RAM_unchanged'] and not bundle['device_transfer_or_install_performed'] and not bundle['signature_forged_or_recomputed'],'Claim exceeds local scope');checks['no_device_transfer_signature_forgery_or_firmware_flash']=True
require(max(r['VmHWM'] for r in proof['resource_samples'])<200*1024,'Actual process resource guard');checks['strict_actual_proc_resource_guard']=True
for p in [Path(__file__),OUT/'strict-marker-control-proof.json',OUT/'local-marker-bundle-manifest-v2.json',ROOT/bundle['diff_path'],candidate,rollback,ROOT/m['combined_file'],OUT/'strict_marker/manifest.json']:sources[str(p.relative_to(ROOT))]=sha(p)
out={'all_passed':all(checks.values()),'assertions':checks,'bounded_control_count':8,'source_sha256':sources,'candidate_sha256':sha(candidate),'rollback_sha256':sha(rollback),'candidate_local_only':True,'actual_program_five_CPU_STRH_and_repeat_retention_verified':True,'native_currentloader_pointer_and_path_producer_inputs_are_fixtures':True,'currentloader_lifecycle_physically_verified':False,'signature_or_changed_package_acceptance_physically_verified':False,'AudioTest_UI_rendering_physically_verified':False,'fullApp_or_audio_goal_complete':False,'pure_file_verifier_no_guest':True,'limits':proof['limits']+bundle['limits']}
(OUT/'strict-controls-and-local-bundle-verification.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_passed':out['all_passed'],'assertion_count':len(checks),'candidate_sha256':sha(candidate),'verification':'staging/native-player-inline-fields/marker-package-prep/strict-controls-and-local-bundle-verification.json'}))
