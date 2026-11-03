#!/usr/bin/env python3
"""Pure static file review. No guest, compiler, VM import or device access.
Writes only this new review JSON; all reviewed sources are read-only.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,struct,difflib
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
OLD=ROOT/'staging/native-os20-source-media-v1'
AD=ROOT/'staging/native-os20-mixer-admission-v1'
WARM=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def cstr(b,o):return b[o:b.index(0,o)].decode()
def elf(p):
 b=p.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b);assert h[0][:6]==b'\x7fELF\x01\x01'and h[2]==40
 ph=[]
 for i in range(h[10]):
  kind,off,a,phys,fs,ms,fl,align=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if kind==1:ph.append(dict(address=a,file_bytes=fs,memory_bytes=ms,flags=fl,alignment=align,data=b[off:off+fs]))
 sh=[struct.unpack_from('<10I',b,h[6]+i*h[11])for i in range(h[12])];table=sh[h[13]];names=b[table[4]:table[4]+table[5]];sections={};symbols={}
 for s in sh:
  name=cstr(names,s[0])if s[0]else '';data=b[s[4]:s[4]+s[5]]if s[1]!=8 else b''
  sections[name]=dict(type=s[1],flags=s[2],address=s[3],offset=s[4],size=s[5],alignment=s[8],data=data)
  if s[1]==2:
   st=sh[s[6]];strings=b[st[4]:st[4]+st[5]]
   for o in range(s[4],s[4]+s[5],s[9]):
    n,v,size,info,other,index=struct.unpack_from('<IIIBBH',b,o)
    if n:symbols[cstr(strings,n)]=dict(address=v,size=size,type=info&15,binding=info>>4,index=index)
 return dict(header=h,segments=ph,sections=sections,symbols=symbols)
def diff_ranges(a,b,base=0):
 spans=[];start=None;limit=max(len(a),len(b))
 for i in range(limit):
  differs=i>=len(a)or i>=len(b)or a[i]!=b[i]
  if differs and start is None:start=i
  if start is not None and (not differs or i==limit-1):
   end=i+1 if differs and i==limit-1 else i
   spans.append(dict(start_address=base+start,offset=start,length=end-start,before_hex=a[start:min(end,len(a))].hex(),after_hex=b[start:min(end,len(b))].hex()));start=None
 return spans
def main():
 out=BASE/'review.json';assert not out.exists()
 oldsrc=OLD/'media_case_v1.c';newsrc=AD/'media_case_v2.c';oldm=OLD/'build/manifest.json';newm=AD/'build-media-v2/manifest.json'
 old=json.loads(oldm.read_text());new=json.loads(newm.read_text());warm=json.loads(WARM.read_text())
 oldelf=ROOT/old['ELF'];newelf=ROOT/new['ELF'];a,b=elf(oldelf),elf(newelf)
 assert sha(oldelf)==old['ELF_SHA256']and sha(newelf)==new['ELF_SHA256']
 assert newsrc.read_text()==oldsrc.read_text().replace('output_bytes==256','output_bytes==1792')
 c_diff=list(difflib.unified_diff(oldsrc.read_text().splitlines(),newsrc.read_text().splitlines(),fromfile=rel(oldsrc),tofile=rel(newsrc),lineterm=''))
 loaded=[]
 for x,y in zip(a['segments'],b['segments']):
  loaded.append(dict(address=x['address'],new_address=y['address'],old_file_bytes=x['file_bytes'],new_file_bytes=y['file_bytes'],
   old_memory_bytes=x['memory_bytes'],new_memory_bytes=y['memory_bytes'],flags=x['flags'],new_flags=y['flags'],
   old_data_SHA256=hashlib.sha256(x['data']).hexdigest(),new_data_SHA256=hashlib.sha256(y['data']).hexdigest(),
   different_byte_positions=sum(1 for i in range(max(len(x['data']),len(y['data'])))if i>=len(x['data'])or i>=len(y['data'])or x['data'][i]!=y['data'][i]),
   exact_loaded_diff_ranges=diff_ranges(x['data'],y['data'],x['address'])))
 assert [(x['address'],x['memory_bytes'],x['flags'])for x in a['segments'][1:]]==[(x['address'],x['memory_bytes'],x['flags'])for x in b['segments'][1:]]
 sections=[]
 for n in sorted(set(a['sections'])|set(b['sections'])):
  x,y=a['sections'].get(n),b['sections'].get(n);assert x is not None and y is not None
  sections.append(dict(name=n,old={k:v for k,v in x.items()if k!='data'},new={k:v for k,v in y.items()if k!='data'},
   content_equal=x['data']==y['data'],old_content_SHA256=hashlib.sha256(x['data']).hexdigest(),new_content_SHA256=hashlib.sha256(y['data']).hexdigest()))
 symbol_diff=[dict(name=n,old=a['symbols'].get(n),new=b['symbols'].get(n))for n in sorted(set(a['symbols'])|set(b['symbols']))if a['symbols'].get(n)!=b['symbols'].get(n)]
 stable=['media_case_failure_v1','check','media_case_producer_v1','media_case_result_v1','packet','producer_stack','producer_descriptor']
 assert all(a['symbols'][n]==b['symbols'][n]for n in stable)
 assert a['symbols']['media_case_bootstrap_v1']['address']==b['symbols']['media_case_bootstrap_v1']['address']
 assert a['symbols']['FRAME_PACKET_V1']['address']+4==b['symbols']['FRAME_PACKET_V1']['address']
 def symbytes(e,n):
  s=e['symbols'][n];z=next(z for z in e['segments']if z['address']<=s['address']and s['address']+s['size']<=z['address']+z['file_bytes']);o=s['address']-z['address'];return z['data'][o:o+s['size']]
 assert symbytes(a,'FRAME_PACKET_V1')==symbytes(b,'FRAME_PACKET_V1')and len(symbytes(a,'FRAME_PACKET_V1'))==85
 deps=[]
 for label,m in [('old_media_build',old),('new_media_build',new),('warm_build',warm),('grant_build',json.loads((AD/'build/manifest.json').read_text()))]:
  for field in('source_sha256','generated_sha256'):
   for p,h in m.get(field,{}).items():deps.append(dict(manifest=label,path=p,expected_SHA256=h,current_SHA256=sha(ROOT/p),matches=sha(ROOT/p)==h))
 assert all(x['matches']for x in deps)
 objects=warm['reused_relocatable_objects'];assert len(objects)==37
 assert all(sha(ROOT/p)==warm['source_sha256'][p]for p in objects)
 warmelf=ROOT/warm['ELF'];assert sha(warmelf)==warm['ELF_sha256']=='13d2068c54857a8edaad8172c74b454f726bf3c6a73bf4a207b54d8afa8111f1'
 assert old['source_sha256'][rel(WARM)]==new['source_sha256'][rel(WARM)]==sha(WARM)
 assert old['source_sha256'][rel(warmelf)]==new['source_sha256'][rel(warmelf)]==sha(warmelf)
 voices=[]
 for v in warm['installed_original_voice_ranges']:
  p=ROOT/v['path'];voices.append(dict(path=v['path'],current_SHA256=sha(p),expected_SHA256=v['sha256'],matches=sha(p)==v['sha256']))
 assert len(voices)==3 and all(v['matches']for v in voices)
 headers=[]
 for name in('frame_v1.h','media_addresses_v1.h'):
  x=OLD/'build'/name;y=AD/'build-media-v2'/name;headers.append(dict(name=name,old_SHA256=sha(x),new_SHA256=sha(y),exact_equal=x.read_bytes()==y.read_bytes()))
 assert all(h['exact_equal']for h in headers)
 receipt=json.loads((AD/'guest-v1/terminal-tool-receipt.json').read_text());assert receipt['actual_terminal_result']['exit_code']==1
 absent=[rel(AD/p)for p in('guest-v1/terminal-failure.json.gz','guest-v1/media-proof.json.gz','guest-v1/guest-proof.json','file-v1/FILE-proof.json','SEAL-v1.json','probe_v2.py')if not(AD/p).exists()]
 runner=(AD/'probe_v1.py').read_text();assert "r['output_bytes']==256"in runner and "allocator_supply_result_v1"in runner
 p=dict(review_completed=True,review_is_static_file_only=True,review_is_not_guest_success=True,
  no_guest_or_compiler_or_VM_or_device_execution=True,no_reviewed_source_or_original_instruction_patch_modified=True,
  C_source_diff=c_diff,C_source_only_change='NEW test fixture output byte assertion 256 -> 1792; native/decoder/lease/Stop code unchanged',
  original_executed_media_build=dict(manifest=rel(oldm),ELF=rel(oldelf),ELF_SHA256=sha(oldelf)),
  unexecuted_media_v2_build=dict(manifest=rel(newm),ELF=rel(newelf),ELF_SHA256=sha(newelf),guest_executed=False),
  loaded_segment_comparison=loaded,section_comparison=sections,symbol_differences=symbol_diff,
  important_layout=dict(text_bytes=[789,793],text_growth_bytes=4,bootstrap_start_unchanged=True,bootstrap_symbol_size=[a['symbols']['media_case_bootstrap_v1']['size'],b['symbols']['media_case_bootstrap_v1']['size']],
   FRAME_PACKET_addresses=[a['symbols']['FRAME_PACKET_V1']['address'],b['symbols']['FRAME_PACKET_V1']['address']],FRAME_PACKET_content_identical=True,
   producer_function_start_and_size_unchanged_but_FRAME_pointer_literal_changed=True,
   mutable_result_packet_descriptor_stack_symbols_exactly_equal=stable,no_LOAD_BSS_or_stack_placement_change=True,
   live_state_equivalence_or_safe_frozen_prefix_RX_replacement_not_proven_by_static_layout=True,
   ELF_difference_is_not_one_CMP_constant=True),
  frozen_decoder_Source_FIFO_TTS=dict(warm_ELF=rel(warmelf),warm_ELF_SHA256=sha(warmelf),same_in_old_and_new_manifests=True,
   reused_objects_current_hash_verified=37,old_and_new_generated_headers=headers,original_voice_inputs=voices,
   stock_TTS_export_count_from_same_frozen_manifest=40,same_frozen_binary_preserves_existing_static_export_evidence_scope=True,
   no_new_TTS_runtime_execution_or_full_40_API_functionality_proven=True,no_new_decoder_or_Stream_Stop_lifetime_validation=True),
  current_execution_evidence=dict(terminal='9eb25d',EXIT=1,source_started_error_and_1792_count_only_terminal_observation=True,
   PCM_256_plus_silence_1536_not_byte_verified=True,full_pull_lease_evidence_not_persisted=True,
   failure_serializer_KeyError='allocator_supply_result_v1',missing_artifacts=absent),
  source_documentation_review=[
   dict(topic='CONFIG ordering',assessment='Bridge C checks current Source/mixer pointer/ready/LR and checks compiled grant result before calling original37BCE4. Source-level order is explicit; final runtime journal/FILE proof absent. No native exclusive/hardware certificate.'),
   dict(topic='Stop',assessment='One packet test does not invoke Stop. native_STOP_DONE false remains correct; it cannot prove Stop completion, drain, or safe unload.'),
   dict(topic='held leases',assessment='Runner contains 64-byte original frame and nonzero borrowed/media/callback checks at entry/full thunk return and final zeros; these are intended checks, not saved passing evidence. Expected single-pull count and256B byte audit are stale for1792B output.'),
   dict(topic='pinning',assessment='Resident/pinned storage describes intended no-reclaim scope; no native shutdown/quiescence/free/unload proof. The new bridge grants scoped CONFIG capability only.'),
   dict(topic='copied success dictionary',assessment='all_passed/TTS_runtime_unchanged/complete pull fields are only hypothetical code reached after assertions. No guest-proof.json exists; they must not be published as achieved.'),
   dict(topic='caller and backing labels',assessment='declared_NEW_idle_caller is misnamed: this continuation enters actual Source callsite3B9C4A. explicit_NEW_VM_software_backing_extent is inherited from the allocator prefix; its append and creation are not new guest events here.'),
   dict(topic='original factory/reader',assessment='Bridge comment states intended original selector/factory/pulls forward behavior; terminal has partial Source started1/error0. Original full-body/return/lease provenance still requires persisted successful bounded evidence.'),
  ],
  required_future_validation_without_executing_it_now=[
   'Record exact new fixture RX replacement, shifted FRAME/literal layout and compatibility with inherited pending caller frames before any future guest.',
   'Fix NEW failure serialization field and retain actual failure state even on assertion exceptions.',
   'Align future observer byte/count assertions with native complete1792B ring layout; verify every output byte, PCM reference and actual silence, wrapped pointers and unused guards.',
   'Persist every original caller/full-return frame and held/released typed lease; preserve actual Source89/Mixer23 preemption and original selector/factory/send/pull bodies.',
   'Keep old exhausted backing pool and before-grant-priority countercases immutable; require new actual terminal EXIT0 plus FILE proof before any passed seal.',
  ],
  manifest_success_scope='all_passed means static build/check status; guest_executed false and install_candidate false remain authoritative',
  dependency_hash_checks=deps,exclusive_native_witness=-200,native_STOP_DONE=False,install_candidate=False,
  App_direct_phone_speaker_achieved=False,device_IO=False,
  source_SHA256={rel(p):sha(p)for p in(Path(__file__),oldsrc,newsrc,oldm,newm,WARM,AD/'probe_v1.py',AD/'config_before_send_v1.c',AD/'guest-v1/terminal-tool-receipt.json')})
 out.write_text(json.dumps(p,indent=2,ensure_ascii=False)+'\n')
 print(json.dumps(dict(review_completed=True,review=rel(out),review_SHA256=sha(out),guest_success=False,
  C_changes=1,text_growth_bytes=4,loaded_changed_bytes=loaded[0]['different_byte_positions'],frozen_37_object_hashes_match=True,
  three_voice_input_hashes_match=True,old_and_new_headers_equal=True,new_guest_or_compiler_executed=False,device_IO=False)),flush=True)
if __name__=='__main__':main()
