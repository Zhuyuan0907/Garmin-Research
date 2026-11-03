#!/usr/bin/env python3
"""Prepare ONE local-only changed Voice VPM plus byte-exact original rollback.
Never sends anything to Garmin. Original DLLINFO and72-byteSIG stay unchanged.
No forged signature, firmware update, device mount or installer is produced.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,struct,shutil
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from build_native_voice_package_fixture import repack
from analyze_tts_vpm import parse_image
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
proof=json.loads((OUT/'strict-marker-control-proof.json').read_text());require(proof['all_passed'] and proof['control_count']==8,'New strict controls must finish first')
for p,h in proof['source_sha256'].items():require(sha(ROOT/p)==h,'Strict positive source changed')
m=json.loads((OUT/'strict_marker/manifest.json').read_text());source=ROOT/'backups/20261002T154458Z/files/Voice/Chinese_Big5_MeiLing.vpm';original=source.read_bytes();binary=(ROOT/m['combined_file']).read_bytes();require(hashlib.sha256(binary).hexdigest()==m['binary_sha256'],'Candidate compiled BIN changed')
files,geometry=parse_image(original);require(files['DLLIMG.BIN']['sha256']==m['original_sha256'],'Wrong original Big5 member')
candidate,recipe=repack(original,binary,checksum=False,zero_signature=False)
new,ng=parse_image(candidate);require(new['DLLIMG.BIN']['content']==binary,'Container extraction differs from actual tested program')
require(new.keys()==files.keys(),'VPM member inventory changed')
require(all(new[k]['content']==r['content'] for k,r in files.items() if k!='DLLIMG.BIN'),'Member other than BIN changed')
require(new['DLLINFO.TXT']['content']==files['DLLINFO.TXT']['content'] and new['DLLIMG.SIG']['content']==files['DLLIMG.SIG']['content'] and len(new['DLLIMG.SIG']['content'])==72,'Original metadata or SIG changed')
require(candidate[:geometry['directory_start']]==original[:geometry['directory_start']],'Outer IMG header changed')
require(binary[12:len(files['DLLIMG.BIN']['content'])]==files['DLLIMG.BIN']['content'][12:],'Original BIN postheader changed')
require(0<len(binary)<struct.unpack_from('<I',binary,4)[0]<=0x300000 and struct.unpack_from('<I',binary,8)[0]==len(binary),'Native loader file/RAM reservation invalid')
bundle=OUT/'local-test-bundle-v2';(bundle/'candidate').mkdir(parents=True,exist_ok=True);(bundle/'rollback').mkdir(exist_ok=True)
cp=bundle/'candidate/Chinese_Big5_MeiLing.vpm';rp=bundle/'rollback/Chinese_Big5_MeiLing.vpm';cp.write_bytes(candidate);shutil.copyfile(source,rp);require(sha(source)==sha(rp),'Rollback copy differs')
allowed=[(b*geometry['block_bytes'],(b+1)*geometry['block_bytes']) for b in new['DLLIMG.BIN']['blocks']]
allowed += [(a,a+512) for k in ['DLLIMG.BIN','DLLIMG.SIG','IMGEND.TST'] for a in files[k]['directory_offsets']]
allowed += [(len(original),len(candidate))]
merged=[]
for a,b in sorted(allowed):
 if merged and a<=merged[-1][1]:merged[-1]=(merged[-1][0],max(b,merged[-1][1]))
 else:merged.append((a,b))
allowed=merged
ranges=[];i=0;changed=0
while i<len(candidate):
 if i<len(original) and original[i]==candidate[i]:i+=1;continue
 start=i
 while i<len(candidate) and (i>=len(original) or original[i]!=candidate[i]):i+=1
 require(any(a<=start and i<=b for a,b in allowed),'Byte changed outside declared BIN/allocation/append range')
 changed+=i-start;ranges.append({'offset':start,'bytes':i-start,'original_hex':original[start:i].hex(),'candidate_hex':candidate[start:i].hex()})
diff=OUT/'bundle-byte-diff-v2.json';diff.write_text(json.dumps({'original_bytes':len(original),'candidate_bytes':len(candidate),'changed_byte_count':changed,'diff_ranges':ranges,'all_changes_in_declared_ranges':True,'only_changed_member_payload':'DLLIMG.BIN'},indent=2)+'\n')
members={k:{'original_sha256':r['sha256'],'candidate_sha256':new[k]['sha256'],'payload_unchanged':k!='DLLIMG.BIN','original_bytes':r['bytes'],'candidate_bytes':new[k]['bytes'],'original_blocks':r['blocks'],'candidate_blocks':new[k]['blocks'],'original_directory_offsets':r['directory_offsets'],'candidate_directory_offsets':new[k]['directory_offsets']} for k,r in files.items()}
manifest={'all_passed':True,'local_only_reviewable_test_input':True,'device_transfer_or_install_performed':False,'approved_for_device_install':False,'single_device_target':'Voice/Chinese_Big5_MeiLing.vpm','exact_target':{'HWID':1352,'SW':'8.00','MAIN_sha256':'10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'},'candidate_path':str(cp.relative_to(ROOT)),'candidate_sha256':sha(cp),'candidate_bytes':len(candidate),'rollback_path':str(rp.relative_to(ROOT)),'rollback_sha256':sha(rp),'rollback_bytes':len(original),'original_backup':str(source.relative_to(ROOT)),'original_sha256':sha(source),'actual_tested_BIN':m['combined_file'],'actual_tested_BIN_sha256':sha(ROOT/m['combined_file']),'original_member_payload_inventory':members,'member_count':len(members),'original_DLLINFO_and_SIG_retained_byte_exact':True,'signature_forged_or_recomputed':False,'DLLINFO_checksum_left_original':'0x0CA73F5A','actual_modified_BIN_byte_sum':hex(sum(binary)&0xffffffff),'stale_DLLINFO_checksum_intentional':True,'only_member_payload_modified':'DLLIMG.BIN','BIN_original_header_mutation_words':[0,4,8],'BIN_original_postheader_bytes_unchanged':True,'original3MiB_RAM_cap_respected':True,'repack_recipe':recipe,'geometry_before':geometry,'geometry_after':ng,'diff_path':str(diff.relative_to(ROOT)),'diff_sha256':sha(diff),'physical_code_acceptance_or_signature_enforcement_verified':False,'AudioTest_rendering_verified':False,'silent_payload':'Appended code adds cache/identity/lock/private-state work only; original bootstrap/APIs forwarded. No new audio calls. Device itself may still emit ordinary navigation/voice sounds.','rollback_contract':'Restore the exact original single Voice file from rollback, read back/hash, then cold restart or native cache rebuild. Original DLLINFO remains2.10 and repopulates the5 UTF16 cache field. No rollback program, MAIN/BOOT change or automatic device action.','result_interpretation':'Only a fresh B markerM7Q9 with unchanged DLLINFO and an A/rollback2.10 observation can establish physical modified instructions executed. Old2.10 is ambiguous: signature rejection, load not reached, strict guard skip or stale page may each cause it. Emulated currentloader file/map inputs are fixtures.','limits':['Unknown physical higherFAT/VPM/SIG acceptance; no claim originalSIG authenticates changedBIN.','Outer IMG header/volume byte fields unchanged; directory BIN length/block lists and SIG/END relocation are necessary declared container changes. Native embedded-reader followup separate.','8 strict bounded controls do not prove all concurrent FS/kernel/opaque lifecycle or every possible skip branch.','Source comment no wait/wake means no added blocking acquisition: original unlock may legitimately wake a waiter that arrives; no such hardware event tested.','No40 separate TTS/navigation API synthesis or fullApp/music UI validated.'],'MAIN_flash_BOOT_device_IO_sound_calls_installer':False,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),OUT/'strict_cache_marker_entry.c',OUT/'build_strict_marker.py',OUT/'emulate_strict_marker.py',OUT/'strict-marker-control-proof.json',OUT/'strict_marker/manifest.json',ROOT/'scripts/build_native_voice_package_fixture.py',ROOT/'scripts/analyze_tts_vpm.py',source]}}
(OUT/'local-marker-bundle-manifest-v2.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
(bundle/'REVIEW.txt').write_text('LOCAL ONLY — NOT TRANSFERRED OR APPROVED FOR INSTALL\n\nOne candidate: candidate/Chinese_Big5_MeiLing.vpm\nExact original rollback: rollback/Chinese_Big5_MeiLing.vpm\n\nOriginal DLLINFO.TXT and72-byte DLLIMG.SIG are retained. SIG acceptance is unknown; no forged signature. Modified BIN preserves original40 APIs and original postheader bytes, then runs guarded RAM version stores M7Q9 plus NUL after actual bootstrap11. Unique identity/current-loader name/locks/reentry are checked. Current-loader inputs in8 emulated controls are explicit fixtures.\n\nA/B/rollback observation: obtain fresh original AudioTest AudVer2.10, use the one reviewed file in a later explicitly scheduled USB action, restart/select this Big5 voice and reopen the page. M7Q9 would be positive code-execution evidence;2.10 is ambiguous and must not be called rejection. Rollback restores original file and cold cache2.10. No device actions have been performed.\n')
print(json.dumps({'all_passed':True,'candidate':str(cp.relative_to(ROOT)),'candidate_sha256':sha(cp),'candidate_bytes':len(candidate),'rollback_sha256':sha(rp),'original_DLLINFO_SIG_byte_identical':True,'changed_members':['DLLIMG.BIN'],'new_signature_generated':False,'device_io':False}))
