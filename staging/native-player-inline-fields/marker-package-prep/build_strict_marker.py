#!/usr/bin/env python3
"""Build only local EMULATION-ONLY raw images; never VPM/SIG/installers."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,struct,subprocess
ROOT=Path('/root/garmin'); OUT=Path(__file__).resolve().parent; IMAGE=0x2d4bb74
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def run(cmd): return subprocess.check_output(cmd,stderr=subprocess.STDOUT,text=True)
rows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
row=next(r for r in rows if 'Chinese_Big5_MeiLing' in r['file']); p=ROOT/row['module']['extracted_binary']; raw=p.read_bytes()
assert sha(p)==row['files']['DLLIMG.BIN']['sha256']
ram=row['module']['image_header_ram_bytes']; offset=(ram+31)&~31
builds=[]
for mode,name in [(0,'strict_marker')]:
 d=OUT/name;d.mkdir(exist_ok=True); ld=d/'entry.ld'
 ld.write_text(f'''ENTRY(cache_marker_entry)
original_tts_entry = {IMAGE+row['module']['first_branch_offset']:#x};
SECTIONS {{ . = {IMAGE+offset:#x}; .entry : {{ KEEP(*(.text.cache_marker_entry)) }}
 .text : {{ *(.text*) }} .rodata : {{ *(.rodata*) }} . = ALIGN(32);
 .data : {{ *(.data*) }} . = ALIGN(32); .bss (NOLOAD) : {{
 __marker_bss_start = .; *(.bss*) *(COMMON) __marker_bss_end = .; }}
 __combined_ram_bytes = . - {IMAGE:#x};
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }} }}
''')
 elf=d/'marker-emulation.elf'; flat=d/'marker-emulation.bin'; combined=d/'combined-emulation-only.bin'
 commands=[['arm-linux-gnueabi-gcc','-Os','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-static','-no-pie',f'-DCONTROL={mode}',f'-Wl,-T,{ld}',f'-Wl,--build-id=none,-Map={d}/entry.map',str(OUT/'strict_cache_marker_entry.c'),'-o',str(elf)],['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
 for command in commands: run(command)
 assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
 symbols={}
 for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
  parts=line.split()
  if len(parts)==3:symbols[parts[2]]=int(parts[0],16)
 assert symbols['cache_marker_entry']==IMAGE+offset
 b=bytearray(raw); b.extend(bytes(offset-len(b))); b.extend(flat.read_bytes()); struct.pack_into('<3I',b,0,0xea000000|(((offset-8)//4)&0xffffff),symbols['__combined_ram_bytes'],len(b));assert b[12:len(raw)]==raw[12:];assert len(b)<symbols['__combined_ram_bytes']<0x300000
 combined.write_bytes(b)
 manifest={'control':mode,'name':name,'symbols':symbols,'combined_file':str(combined.relative_to(ROOT)),'combined_ram':symbols['__combined_ram_bytes'],'original_ram':ram,'original_entry':IMAGE+row['module']['first_branch_offset'],'original_binary':str(p.relative_to(ROOT)),'original_sha256':sha(p),'commands':commands,'header_only_original_mutations':[0,4,8],'original_postheader_file_unchanged':True,'source_sha256':{str(q.relative_to(ROOT)):sha(q) for q in [OUT/'strict_cache_marker_entry.c',Path(__file__),ld]},'binary_sha256':sha(combined),'elf_sha256':sha(elf),'emulation_only':True,'device_install_candidate':False,'VPM_or_SIG_generated':False}
 (d/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');builds.append(manifest)
(OUT/'build-manifest.json').write_text(json.dumps({'builds':builds,'all_passed':True,'emulation_only':True},indent=2)+'\n')
print(json.dumps({'built':len(builds),'all_passed':True,'namespace':str(OUT.relative_to(ROOT))}))
