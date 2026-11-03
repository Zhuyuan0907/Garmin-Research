#!/usr/bin/env python3
"""Pure-file independent replay of actual candidate metadata->reader->ARM marker.
No Uc instance, guest rerun, device, installer or sound actions.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,struct
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from analyze_tts_vpm import parse_image
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
p=OUT/'candidate-embedded-reader-metadata-control-v2.json';x=json.loads(p.read_text());bundle=json.loads((OUT/'local-marker-bundle-manifest-v2.json').read_text());m=json.loads((OUT/'strict_marker/manifest.json').read_text());baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text());sources={};checks={}
for reg in [x['source_sha256'],bundle['source_sha256']]:
 for path,h in reg.items():require(sha(ROOT/path)==h,'Source/input hash differs: '+path);sources[path]=h
checks['exact_source_candidate_manifest_hashes']=True
candidate=ROOT/bundle['candidate_path'];original=ROOT/bundle['original_backup'];new,geometry=parse_image(candidate.read_bytes());old,og=parse_image(original.read_bytes());binary=(ROOT/m['combined_file']).read_bytes();require(new['DLLIMG.BIN']['content']==binary,'Candidate is not actual tested compiledBIN');require(all(new[k]['content']==r['content'] for k,r in old.items() if k!='DLLIMG.BIN'),'Original nonBIN member changed');require(len(new['DLLIMG.SIG']['content'])==72,'Original SIG size differs');checks['actual_candidate_BIN_and_original_DLLINFO_SIG_all_other_members']=True
rows=x['native_metadata_entry_return_rows'];require(len(rows)==1 and rows[0]['returned'] and rows[0]['raw_return']==1 and rows[0]['parsed_checksum']==0x0ca73f5a,'Actual metadata entry/return missing');require(rows[0]['version_hex']=='2.10\0'.encode('utf-16le').hex(),'Metadata was not original2.10');enum=x['native_enumeration_before_module_load'];require(enum['original_functions_executed']['0x275590']==1 and enum['original_functions_executed']['0x274acc']==1 and len(enum['registry'])==1 and enum['registry'][0]['volume_id']=='mei-lingb','Original metadata registry not produced');checks['actual_metadata_status1_registry_unique_native_record']=True
stock=NativeImage();points=x['native_END_checksum_parser_observations']
for e in points:
 raw=bytes.fromhex(e['opcode_hex']);pc=int(e['pc'],16);require(stock.read(stock.runtime_to_load(pc,len(raw)),len(raw))==raw,'Metadata observation not exact original opcode')
require(any(e['pc']=='0x275ac8' and e['r0']==0 and e['END_buffer_hex']=='454e44' for e in points),'Original END comparison not zero');require(any(e['pc']=='0x275ad0' for e in points),'END success branch not executed');checks['actual_original_END_three_bytes_compare_and_success_branch']=True
parsecall=next(e for e in points if e['pc']=='0x27544a');parsereturn=next(e for e in points if e['pc']=='0x27544e');require(parsecall['checksum_destination']==rows[0]['record']+0x764 and parsecall['text_utf16']=='0x0CA73F5A' and parsereturn['r0']==1 and parsereturn['record_checksum']==0x0ca73f5a,'Original checksum numeric parser/destination/readback mismatch');require(sum(binary)&0xffffffff==int(bundle['actual_modified_BIN_byte_sum'],16) and sum(binary)&0xffffffff!=rows[0]['parsed_checksum'],'ChangedBIN sum does not differ from retained metadata');checks['checksum_is_original_tag_numeric_parse_changed_BIN_sum_distinguished']=True
opens=x['metadata_and_loader_native_open_names'];require(opens==['dllinfo.txt','IMGEND.tst','dllinfo.txt','dllimg.bin'],'Unexpected same-instance native open sequence');require(all(v>0 for v in x['loader_file_callback_entries_during_selection'].values()) and len(x['loader_file_callback_entries_during_selection'])==5 and x['actual_original5_loader_callbacks_not_intercepted'] and not x['BIN_file_input_fixture_used'],'BIN callback bypass/fixture found');require(all(r['package_sha256']==sha(candidate) for r in enum['binding_events']),'Different package bound during metadata');require(rows[0]['epilog']['instruction']<x['native_selector_and_bootstrap_rows']['calls'][4]['instructions'],'Metadata ordering observation invalid');checks['same_actual_candidate_metadata_then_original5callbacks_BIN_no_direct_input']=True
native=x['native_selector_and_bootstrap_rows'];require(all(e['raw_return']==11 for e in native['entry']+native['bootstrap']),'Original raw11 layers not forwarded');require(native['registration'][0]['targets']==baseline['native_registration'][0]['targets'] and native['registration'][0]['count']==40,'40 exports differ from original baseline');require(x['original40_and_postheader_runtime_match_baseline'],'Native module baseline not checked');checks['genuine_bootstrap_entry11_original40_targets_and_original_runtime']=True
zones=x['whole_zone_CPU_replay'];require(len(zones)==11,'Whole-zone inventory differs');replay={k:bytearray.fromhex(z['before_hex']) for k,z in zones.items()}
for e in x['CPU_write_journal']:
 z=zones[e['zone']];off=e['address']-z['address'];n=e['size'];require(0<=off and off+n<=z['bytes'],'CPU store crosses declaredzone');require(bytes(replay[e['zone']][off:off+n]).hex()==e['before_hex'],'CPU store-before replay mismatch');replay[e['zone']][off:off+n]=(e['value']&((1<<(8*n))-1)).to_bytes(n,'little')
require(all(bytes(replay[k]).hex()==z['after_hex'] for k,z in zones.items()),'Independent eleven-zone replay failed');checks['independent_all11_whole_zone_CPU_store_replay']=True
stores=x['actual_CPU_marker_stores'];require(len(stores)==5 and [e['value'] for e in stores]==[77,55,81,57,0],'FiveUTF16+NUL actualstores differ');md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
for e in stores:
 raw=bytes.fromhex(e['opcode_hex']);off=e['pc']-0x2d4bb74;require(binary[off:off+len(raw)]==raw and next(md.disasm(raw,e['pc'])).mnemonic=='strh','Actual marker opcode not compiled candidate ARMSTRH')
record=zones['record'];a=bytes.fromhex(record['before_hex']);b=bytes.fromhex(record['after_hex']);require(a[:0x6b8]==b[:0x6b8] and a[0x6c2:]==b[0x6c2:] and a[0x6b8:0x6c2]=='2.10\0'.encode('utf-16le'),'Native record changed outside marker field or before is wrong');require(b[0x6b8:0x6c2]=='M7Q9\0'.encode('utf-16le') and x['getter_and_page_input_utf16_hex']==b[0x6b8:0x6c2].hex(),'Original getter/pageinput not actualCPUmarker');checks['actual5_ARM_STRH_preserving_NUL_then_original_getter_and_consumer_input']=True
require(struct.unpack_from('<I',bytes.fromhex(zones['fixture_tcb']['after_hex']),32)[0]==0,'Fixture owner head retained');require(max(r['VmHWM'] for r in x['resource_samples'])<200*1024,'Actualproc resourceguard failed');require(not x['actual_physical_higher_FAT_or_signature_acceptance_verified'] and not x['device_transfer_or_UIrendering'],'Physical claim exceeds guest evidence');checks['owner_endpoint_actual_proc_resources_and_partial_claims']=True
for path in [Path(__file__),p,OUT/'candidate-reader-metadata-v2-source-at-run.json',OUT/'source-at-candidate-reader-metadata-v2-run.py',OUT/'local-marker-bundle-manifest-v2.json',OUT/'strict_marker/manifest.json',ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_tts_vpm.py',ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json']:sources[str(path.relative_to(ROOT))]=sha(path)
out={'all_passed':all(checks.values()),'assertions':checks,'bounded_assertion_count':len(checks),'bounded_original_function_control_count':1,'source_sha256':sources,'candidate_sha256':sha(candidate),'actual_modified_BIN_byte_sum':hex(sum(binary)&0xffffffff),'parsed_original_DLLINFO_checksum':'0x0ca73f5a','metadata_END_tag_parser_accepted':True,'actual5_filecallbacks_read_candidate_BIN':True,'actual_ARM_marker_stores_and_original_getter_verified':True,'signature_read_or_enforcement_in_this_narrow_path_verified':False,'physical_changed_code_acceptance_verified':False,'physical_UI_rendering_verified':False,'complete_native_FS_kernel_lifetime_or_App_goal_verified':False,'pure_file_verifier_no_guest':True,'limits':x['explicit_fixtures']+[x['limits'],'The saved enumeration object contains an aliased open-attempt list; its list later includes DLLIMG open. Original-function visit counters are scalar before-load snapshots. Independently verified full ordered names separate metadata first3 from DLLIMG fourth. No retroactive before-load SIG assertion.','Stale checksum tag parsed successfully; this is not absence of global digest/signature validation.']}
(OUT/'candidate-embedded-reader-independent-verification-v2.json').open('x').write(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_passed':out['all_passed'],'assertions':len(checks),'candidate_sha256':sha(candidate),'verification':'staging/native-player-inline-fields/marker-package-prep/candidate-embedded-reader-independent-verification-v2.json'}))
