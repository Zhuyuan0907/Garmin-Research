#!/usr/bin/env python3
"""Relink reserved-tail image with selective warm Source; no device package."""
import sys
sys.dont_write_bytecode=True
import json,hashlib,subprocess,importlib.util,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
PREV=ROOT/'staging/native-player-reserved-tail'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 old=json.loads((PREV/'build-v2.json').read_text())
 for p,h in old['source_sha256'].items():assert sha(ROOT/p)==h,p
 objects=[ROOT/p for p in old['reused_relocatable_objects'] if 'mixer_source_pause'not in p]
 objects+=sorted((ROOT/'staging/native-player-loaded-single-image/build-v3').glob('loaded-*.o'))
 objects+=[PREV/'build-v2/loader_tail_gate_v2.o',PREV/'build-v2/stock_reader_tail_v1.o']
 assert len(objects)==28,len(objects)
 out=BASE/'build-v1';out.mkdir(exist_ok=False)
 ld=out/'warm-resident.ld';ld.write_bytes((PREV/'build-v2/reserved-tail.ld').read_bytes())
 deps=dict(old['source_sha256'])
 for p in [Path(__file__),PREV/'build-v2.json',BASE/'prepare_warm_source_v1.py',BASE/'warm-source-derivation-v1.json',BASE/'mixer_source_warm_v1.c',ld,*objects]:deps[rel(p)]=sha(p)
 cmds=[]
 def run(args):
  r=subprocess.run(args,capture_output=True,text=True)
  dump(out/f'command-{len(cmds):02d}.json',dict(command=args,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));cmds.append(args)
  assert r.returncode==0,r.stderr[-3500:]
  return r.stdout
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-I'+str(ROOT/'staging/native-player-mixer-handoff'),'-I'+str(ROOT/'native/sbc-prototype')]
 obj=out/'mixer_source_warm_v1.o';run(['arm-linux-gnueabi-gcc',*flags,'-c',str(BASE/'mixer_source_warm_v1.c'),'-o',str(obj)]);objects.append(obj)
 elf=out/'warm-player-EMULATION-ONLY.elf';flat=out/'warm-player-EMULATION-ONLY.bin'
 run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie','-Wl,--no-undefined,--gc-sections,--build-id=none,-Map='+str(out/'warm.map'),'-Wl,-T,'+str(ld),*map(str,objects),'-lgcc','-o',str(elf)])
 assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
 spec=importlib.util.spec_from_file_location('warm_ELF32',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
 blob=bytearray(flat.read_bytes());image=0x02d4bb74;ram=symbols['__resident_end']['value']-image
 struct.pack_into('<3I',blob,0,0xea000000|(((e.entry-(image+8))//4)&0xffffff),ram,len(blob));flat.write_bytes(blob)
 original=(ROOT/old['original_binary']).read_bytes()
 assert blob[12:len(original)]==original[12:]and len(blob)<ram<=0x300000
 assert old['protected_tail_start']==symbols['__resident_tail_start']['value']
 code=run(['arm-linux-gnueabi-objdump','-d','--disassemble=mw_attach_stage1',str(elf)])
 (out/'warm-attach-opcodes.txt').write_text(code)
 for name in ['mw_attach_stage1','mw_attaches','mw_denials','mw_last_reason']:assert name in symbols,name
 manifest=dict(old,all_passed=True,ELF=rel(elf),ELF_sha256=sha(elf),symbols=symbols,source_sha256=deps,
  reused_relocatable_objects=[rel(p)for p in objects if p!=obj],combined_binary=rel(flat),combined_sha256=sha(flat),combined_file_bytes=len(blob),combined_ram_bytes=ram,
  extension_added_file_bytes=len(blob)-len(original),extension_added_RAM_bytes=ram-old['original_ram_bytes'],remaining_loader_capacity=0x300000-ram,
  pcm_pages=[symbols['pcm'+str(i)]['value']for i in range(4)],
  reader_patch=dict(old['reader_patch'],after_hex=(bytes.fromhex('004b1847')+struct.pack('<I',symbols['resident_loader_read_gate']['value'])).hex()),
  native_descriptor_patch=dict(old['native_descriptor_patch'],after_hex=(bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',symbols['nr_reply_dispatch']['value'])).hex()),
  selective_warm_Source_structural_admission=True,durable_native_ownership=False,guest_executed=False,device_IO=False)
 assert all(sha(ROOT/p)==h for p,h in deps.items())
 dump(BASE/'build-v1.json',manifest)
 print(json.dumps(dict(all_passed=True,file_bytes=len(blob),RAM_bytes=ram,tail=old['protected_tail_start'],device_IO=False)))
if __name__=='__main__':main()
