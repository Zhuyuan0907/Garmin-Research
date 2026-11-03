#!/usr/bin/env python3
"""Compile NEW continuation controller; do not relink/change frozen player."""
import json,hashlib,subprocess,struct
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
 with p.open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def main():
 assert not OUT.exists();OUT.mkdir()
 frozen_path=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json'
 frozen=json.loads(frozen_path.read_text());assert frozen['all_passed']
 assert sha(ROOT/frozen['ELF'])==frozen['ELF_sha256']
 for p,h in frozen['source_sha256'].items():assert sha(ROOT/p)==h,p
 names={'MH_READY_CONTROLLER':'mh_os20_ready_controller','MH_CREATE_RETURNS':'mh_os20_create_returns',
  'MH_ADAPTER':'mh_os20_adapter','MH_INITIALIZED':'mh_initialized','MH_READY_POST_RETURNS':'mh_os20_ready_post_returns',
  'MH_BIND_READY':'mh_bind_ready_controller','MH_INITIALIZE_RESULT':'mh_initialize_result',
  'MH_READY_POSTS':'mh_os20_ready_posts','MH_SELF_TCB':'mh_os20_self_tcb','MH_CALLBACK_ARGUMENT':'mh_os20_callback_argument',
  'MH_WORKER_ENTRIES':'mh_os20_worker_entries','MH_PUBLICATION_CHECKS':'mh_os20_publication_checks',
  'MH_PUBLICATION_ERRORS':'mh_os20_publication_errors','MEMORY_OUTPUT_CONTROL':'memory_output_control',
  'MEDIA_QUEUE_CONTROL':'media_queue_control','MH_CONTEXT':'mh_os20_context'}
 header=OUT/'source_addresses_v1.h'
 header.write_text('/* Exact sealed warm ELF symbol bindings. */\n'+''.join('#define '+k+' 0x%08xu\n'%frozen['symbols'][v]['value']for k,v in names.items()))
 inputs=[Path(__file__),BASE/'controller_v1.c',BASE/'controller_v1.ld',frozen_path,ROOT/frozen['ELF'],
  ROOT/'native/os20-audio-source-v1/contract-v1.json',ROOT/'staging/native-os20-audio-prefix-v1/FILE-prefix-proof.json',
  ROOT/'staging/native-os20-audio-prefix-v1/journal-reconstructed-prefix.json.gz']
 hashes={rel(p):sha(p)for p in inputs};save(OUT/'inputs-at-build.json',hashes)
 cmd=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
  '-fno-builtin','-fno-pie','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
  '-ffunction-sections','-fdata-sections','-std=c11','-Wall','-Wextra','-Werror','-I'+str(OUT),
  '-nostdlib','-static','-no-pie','-Wl,--build-id=none,-T,'+str(BASE/'controller_v1.ld'),
  str(BASE/'controller_v1.c'),'-o',str(OUT/'controller-EMULATION-ONLY.elf')]
 r=subprocess.run(cmd,text=True,capture_output=True);save(OUT/'command-00.json',dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));assert r.returncode==0,r.stderr
 elf=OUT/'controller-EMULATION-ONLY.elf';assert not subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip()
 symbols={}
 for row in subprocess.check_output(['arm-linux-gnueabi-nm','-n','-S',str(elf)],text=True).splitlines():
  f=row.split()
  if len(f)==4:symbols[f[3]]=dict(address=int(f[0],16),size=int(f[1],16),type=f[2])
 assert symbols['source_ready_result_v1']['size']==104
 save(OUT/'manifest.json',dict(all_passed=True,source_sha256=hashes,generated_sha256={rel(header):sha(header)},ELF=rel(elf),ELF_SHA256=sha(elf),symbols=symbols,
  original_37_other_object_inputs_relinked=False,frozen_warm_ELF_unchanged=True,guest_executed=False,device_IO=False,install_candidate=False))
 print(json.dumps(dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf),observation_bytes=104)),flush=True)
if __name__=='__main__':main()
