#!/usr/bin/env python3
"""FILE micro replay and reversible local-only voice bundle; no VM/device."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,struct,gzip
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent;IMAGE=0x02d4bb74
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_tts_vpm import parse_image
from build_native_voice_package_fixture import repack
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def require(v,m):
 if not v:raise ValueError(m)
def read(p):return json.loads(p.read_text())
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def pack(mode,midr,sctlr):return((int(mode==31)|((sctlr&1)<<1)|(sctlr&4)|((sctlr>>9)&8))<<12)|((midr>>4)&4095)
def main():
 out=BASE/'file-v1';out.mkdir(exist_ok=False);proof=read(BASE/'platform-micro-v1-proof.json');m=read(BASE/'strict_marker/manifest.json');receipt=read(BASE/'micro-v1-terminal-tool-receipt.json')['actual_terminal'];require(receipt['exit_code']==0 and 'session_id'not in receipt,'micro not terminal')
 artifact=ROOT/proof['artifact'];require(sha(artifact)==proof['artifact_sha256'],'micro artifact changed');raw=gzip.decompress(artifact.read_bytes());d=json.loads(raw);rows=d['cases'];require(len(rows)==44,'micro case count')
 binary=(ROOT/m['combined_file']).read_bytes();require(sha(ROOT/m['combined_file'])==m['binary_sha256'],'binary changed');md=Cs(CS_ARCH_ARM,CS_MODE_ARM);totals=dict(CPU_stores=0,instructions=0,MRS=0,MRC=0,whole_regions=0,full_ABI_returns=0,pure_formatters=0,skipped_samplers=0,privileged_samplers=0);summaries=[];nibbles={};deps=dict(proof['source_sha256'])
 for p in[Path(__file__),BASE/'platform-micro-v1-proof.json',BASE/'micro-v1-terminal-tool-receipt.json',BASE/'strict_marker/manifest.json',artifact,ROOT/'scripts/analyze_tts_vpm.py',ROOT/'scripts/build_native_voice_package_fixture.py']:deps[rel(p)]=sha(p)
 for r in rows:
  before=r['before'];after=r['after'];require(r['passed']and after['GP16'][15]==0x09003000 and after['GP16'][13]==before['GP16'][13]and after['GP16'][4:12]==before['GP16'][4:12]and (after['CPSR']&255)==(before['CPSR']&255),'actual complete micro ABI')
  require(r['CP15_before']==r['CP15_after'],'CPU model registers changed');totals['full_ABI_returns']+=1
  zones={k:bytearray.fromhex(v)for k,v in r['initial'].items()};origins={'state':m['symbols']['marker_state'],'stack':0x09000000}
  for e in r['CPU_store_journal']:
   z=zones[e['zone']];off=e['address']-origins[e['zone']];require(z[off:off+e['size']].hex()==e['before_hex'],'micro store preimage');pc=e['PC'];op=bytes.fromhex(e['opcode_hex']);require(binary[pc-IMAGE:pc-IMAGE+4]==op,'actual CPU store opcode')
   ins=next(md.disasm(op,pc,count=1),None);require(ins and ins.mnemonic.startswith(('str','stm','push')),'not ARM store');z[off:off+e['size']]=(e['value']&((1<<(e['size']*8))-1)).to_bytes(e['size'],'little');totals['CPU_stores']+=1
  for k,z in zones.items():require(z.hex()==r['final'][k],'micro whole region differs');totals['whole_regions']+=1
  require(r['initial']['state'][:208]==r['final']['state'][:208],'legacy104 bytes modified')
  for t in r['actual_instruction_trace']:
   pc=t['PC'];op=bytes.fromhex(t['opcode_hex']);require(binary[pc-IMAGE:pc-IMAGE+len(op)]==op,'actual trace opcode differs');ins=next(md.disasm(op,pc,count=1),None);require(ins and ins.mnemonic not in('mcr','mcrr','msr'),'new trace register write');totals['instructions']+=1
   if ins.mnemonic=='mrs':require('apsr'in ins.op_str or 'cpsr'in ins.op_str,'unexpected MRS');totals['MRS']+=1
   if ins.mnemonic=='mrc':totals['MRC']+=1
  reads=r['actual_CP15_read_observations'];mode=before['CPSR']&31
  for e in reads:
   op=struct.unpack('<I',bytes.fromhex(e['opcode_hex']))[0];require(((op>>8)&15)==15 and ((op>>21)&7)==0 and (op&15)==0 and ((op>>5)&7)==0 and ((op>>16)&15)==e['crn']in(0,1),'CP15 read encoding')
   require(e['before']['CPSR']&31 in(19,31)and e['before']['GP16'][15]==e['PC']and e['after']['GP16'][e['dest']]==e['reference'],'actual MRC result/mode')
   require(e['reference']==r['CP15_before']['MIDR'if e['crn']==0 else'SCTLR'],'actual CPU model read reference')
  if r['entry']==m['symbols']['sample_platform']:
   accepted=mode in(19,31);fields=struct.unpack_from('<5I',bytes.fromhex(r['final']['state']),104);require(fields[0]==before['CPSR']and fields[3]==int(accepted),'actual platform mode fields');want=pack(mode,r['CP15_before']['MIDR'],r['CP15_before']['SCTLR'])if accepted else mode
   require(fields[4]==r['returned']==after['GP16'][0]==want and len(reads)==(2 if accepted else 0),'actual platform tag/guard');require(list(fields[1:3])==([r['CP15_before']['MIDR'],r['CP15_before']['SCTLR']]if accepted else[0,0]),'platform saved fields')
   if accepted:totals['privileged_samplers']+=1;tag=f'{want:04X}'
   else:totals['skipped_samplers']+=1;tag=('U'if mode==16 else'X')+f'{mode:03X}'
  else:
   want=pack(*r['args']);require(want==r['returned']==after['GP16'][0]and not reads and r['initial']['state']==r['final']['state'],'pure formatter');totals['pure_formatters']+=1;tag=f'{want:04X}';part=want&4095;nibbles.setdefault(part,set()).add(want>>12)
  require(tag==r['tag'],'rendered tag');summaries.append(dict(name=r['name'],tag=tag,stores=len(r['CPU_store_journal']),MRC=len(reads),mode=mode))
 require(totals['MRC']==8 and totals['full_ABI_returns']==44 and totals['privileged_samplers']==4 and totals['skipped_samplers']==8 and totals['pure_formatters']==32 and all(v==set(range(16))for v in nibbles.values()),'micro coverage totals')
 original_path=ROOT/'backups/20261002T154458Z/files/Voice/Chinese_Big5_MeiLing.vpm';original=original_path.read_bytes();files,meta=parse_image(original);require(files['DLLIMG.BIN']['sha256']==m['original_sha256'],'original BIN differs');candidate,recipe=repack(original,binary,checksum=False,zero_signature=False);new,newmeta=parse_image(candidate)
 require(new.keys()==files.keys()and new['DLLIMG.BIN']['content']==binary and all(new[k]['content']==v['content']for k,v in files.items()if k!='DLLIMG.BIN'),'candidate members changed');require(candidate[:meta['directory_start']]==original[:meta['directory_start']],'outer header changed');require(binary[12:len(files['DLLIMG.BIN']['content'])]==files['DLLIMG.BIN']['content'][12:],'original module postheader changed')
 bundle=BASE/'local-test-bundle-v1';(bundle/'candidate').mkdir(parents=True);(bundle/'rollback').mkdir();cp=bundle/'candidate/Chinese_Big5_MeiLing.vpm';rp=bundle/'rollback/Chinese_Big5_MeiLing.vpm'
 for p,data in[(cp,candidate),(rp,original)]:
  with p.open('xb')as f:f.write(data)
  deps[rel(p)]=sha(p)
 deps[rel(original_path)]=sha(original_path);require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed frozen dependencies')
 manifest=dict(all_passed=True,candidate_path=rel(cp),candidate_sha256=sha(cp),candidate_bytes=len(candidate),rollback_path=rel(rp),rollback_sha256=sha(rp),rollback_bytes=len(original),single_device_target='Voice/Chinese_Big5_MeiLing.vpm',HWID=1352,SW='8.00',Arm_compile_arch='ARMv4T soft-float',original40_API_and_BIN_postheader_retained=True,only_changed_member_payload='DLLIMG.BIN',original_DLLINFO_SIG_other_members_retained=True,repack_recipe=recipe,tag='four hex: System-vs-SVC plus controlM/C/I in high nibble andMIDRpart12 low; Uxxx/Xxxx skips unsupported mode',controlM_interpretation_depends_on_actual_CPU=True,diagnostic_is_cached_entry_snapshot=True,no_new_audio_tasks_or_heap_or_native_code_patch_or_CP15_write=True,physical_new_candidate_acceptance_CPU_state_or_MAIN_RAM_permissions_unverified=True,device_transfer_or_install_performed=False,device_IO=False,source_sha256=deps);dump(BASE/'local-platform-probe-bundle-v1.json',manifest);deps[rel(BASE/'local-platform-probe-bundle-v1.json')]=sha(BASE/'local-platform-probe-bundle-v1.json')
 result=dict(all_passed=True,ROOT_FILE_only=True,case_count=44,cases=summaries,totals=totals,micro_decoded_sha256=hashlib.sha256(raw).hexdigest(),source_sha256=deps,candidate_sha256=sha(cp),rollback_sha256=sha(rp),actual_CPU_model_MRCs_not_physical_device_values=True,all_sixteen_formatter_flag_nibbles_per_part=True,CP15_writes_or_in_run_context_patches=0,VM_import_or_device_IO=False,physical_CPU_MMU_mapping_Main_permission_heap_App_phone_not_proven=True,updated_utc=datetime.now(timezone.utc).isoformat());require(not any(n=='unicorn'or n.startswith('unicorn.')for n in sys.modules),'VM imported');dump(BASE/'ROOT-platform-micro-file-bundle-v1.json',result);print(json.dumps(dict(all_passed=True,cases=44,totals=totals,candidate_bytes=len(candidate),candidate_sha256=sha(cp),device_IO=False)),flush=True)
if __name__=='__main__':main()
