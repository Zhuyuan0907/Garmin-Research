#!/usr/bin/env python3
import json,hashlib,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def main():
 assert not OUT.exists();OUT.mkdir();warmfile=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json';warm=json.loads(warmfile.read_text())
 header=OUT/'warm_addresses_v1.h';symbols={'MH_SOURCE_TCB':'mh_source_tcb','MH_INITIALIZED':'mh_initialized','MCS_HANDOFF':'mcs_handoff_source_to_mixer','AAS_GUARD':'aas_guard'}
 header.write_text(''.join('#define '+n+' 0x%08xu\n'%warm['symbols'][s]['value']for n,s in symbols.items()))
 elf=OUT/'config-before-send-EMULATION-ONLY.elf';cmd=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mthumb','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie',
  '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-std=c11','-Wall','-Wextra','-Werror','-I'+str(OUT),
  '-nostdlib','-static','-no-pie','-Wl,--build-id=none,-T,'+str(BASE/'config_before_send_v1.ld'),str(BASE/'config_before_send_v1.c'),'-o',str(elf)]
 r=subprocess.run(cmd,text=True,capture_output=True);(OUT/'command.json').write_text(json.dumps(dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2)+'\n');assert r.returncode==0,r.stderr
 assert not subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip();sy={}
 for row in subprocess.check_output(['arm-linux-gnueabi-nm','-n','-S',str(elf)],text=True).splitlines():
  f=row.split()
  if len(f)==4:sy[f[3]]=dict(address=int(f[0],16),size=int(f[1],16),type=f[2])
 assert sy['config_before_send_result_v1']['size']==32
 p=dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf),symbols=sy,
  source_sha256={rel(p):sha(p)for p in(Path(__file__),BASE/'config_before_send_v1.c',BASE/'config_before_send_v1.ld',BASE/'prefix/FILE-prefix-proof.json',warmfile)},
  generated_sha256={rel(header):sha(header)},guest_executed=False,device_IO=False,install_candidate=False)
 (OUT/'manifest.json').write_text(json.dumps(p,indent=2)+'\n');print(json.dumps(dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf))),flush=True)
if __name__=='__main__':main()
