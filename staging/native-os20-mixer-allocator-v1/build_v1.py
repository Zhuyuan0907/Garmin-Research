#!/usr/bin/env python3
import json,hashlib,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def main():
 assert not OUT.exists();OUT.mkdir();elf=OUT/'allocator-supply-EMULATION-ONLY.elf'
 cmd=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mthumb','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie',
  '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-std=c11','-Wall','-Wextra','-Werror',
  '-nostdlib','-static','-no-pie','-Wl,--build-id=none,-T,'+str(BASE/'allocator_supply_v1.ld'),str(BASE/'allocator_supply_v1.c'),'-o',str(elf)]
 r=subprocess.run(cmd,text=True,capture_output=True);(OUT/'command.json').write_text(json.dumps(dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2)+'\n');assert r.returncode==0,r.stderr
 assert not subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip();sy={}
 for row in subprocess.check_output(['arm-linux-gnueabi-nm','-n','-S',str(elf)],text=True).splitlines():
  f=row.split()
  if len(f)==4:sy[f[3]]=dict(address=int(f[0],16),size=int(f[1],16),type=f[2])
 assert sy['allocator_supply_result_v1']['size']==56
 p=dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf),symbols=sy,source_sha256={rel(p):sha(p)for p in(Path(__file__),BASE/'allocator_supply_v1.c',BASE/'allocator_supply_v1.ld',BASE/'prefix/FILE-prefix-proof.json')},
  software_backing_extent=dict(address=0x18400000,size=65536,physical_availability='unknown'),guest_executed=False,device_IO=False,install_candidate=False)
 (OUT/'manifest.json').write_text(json.dumps(p,indent=2)+'\n');print(json.dumps({k:v for k,v in p.items()if k not in('symbols','source_sha256')}),flush=True)
if __name__=='__main__':main()
