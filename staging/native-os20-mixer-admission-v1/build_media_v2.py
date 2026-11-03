#!/usr/bin/env python3
"""New guest producer/idle fixture caller; sealed warm player remains intact."""
import hashlib,json,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'build-media-v2'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
 with p.open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def main():
 assert not OUT.exists();OUT.mkdir()
 warm_path=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json';warm=json.loads(warm_path.read_text())
 assert warm['all_passed'];assert sha(ROOT/warm['ELF'])==warm['ELF_sha256']
 symbols={'SBI_RECEIVE':'sbi_receive_packet','MH_INITIALIZED':'mh_initialized','MH_INITIALIZE_RESULT':'mh_initialize_result',
  'MH_READY_POST_RETURNS':'mh_os20_ready_post_returns','MH_SOURCE_TCB':'mh_source_tcb','MH_STARTED':'mh_started',
  'MH_STREAM_ERROR':'mh_stream_error','MS_SYNC_COMPLETED':'ms_original_sync_completed'}
 addresses=OUT/'media_addresses_v1.h';addresses.write_text('/* Exact sealed warm ELF. */\n'+''.join('#define '+a+' 0x%08xu\n'%warm['symbols'][b]['value']for a,b in symbols.items()))
 frames=ROOT/'staging/native-os20-resident-music-v2/frames.sbc';assert sha(frames)=='8139201e1a8e7a88a1429c94a6c2625c26ce2b7b64f1ad931ef8656e95aa109d'
 packet=bytes.fromhex('80600000000000000000000001')+frames.read_bytes()[:72];assert len(packet)==85
 frame=OUT/'frame_v1.h';frame.write_text('#include <stdint.h>\nstatic const uint8_t FRAME_PACKET_V1[85]={'+','.join('0x%02x'%v for v in packet)+'};\n')
 inputs=[Path(__file__),BASE/'media_case_v2.c',ROOT/'staging/native-os20-source-media-v1/media_case_v1.ld',warm_path,ROOT/warm['ELF'],frames,
  BASE/'prefix/FILE-prefix-proof.json',BASE/'prefix/FILE-prefix-proof.json']
 hashes={rel(p):sha(p)for p in inputs};save(OUT/'inputs-at-build.json',hashes)
 elf=OUT/'source-media-EMULATION-ONLY.elf'
 cmd=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mthumb','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin',
  '-fno-pie','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
  '-std=c11','-Wall','-Wextra','-Werror','-I'+str(OUT),'-nostdlib','-static','-no-pie',
  '-Wl,--build-id=none,-T,'+str(ROOT/'staging/native-os20-source-media-v1/media_case_v1.ld'),str(BASE/'media_case_v2.c'),'-o',str(elf)]
 r=subprocess.run(cmd,text=True,capture_output=True);save(OUT/'command-00.json',dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));assert r.returncode==0,r.stderr
 assert not subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip();sy={}
 for row in subprocess.check_output(['arm-linux-gnueabi-nm','-n','-S',str(elf)],text=True).splitlines():
  f=row.split()
  if len(f)==4:sy[f[3]]=dict(address=int(f[0],16),size=int(f[1],16),type=f[2])
 assert sy['media_case_result_v1']['size']==84 and sy['producer_stack']['size']==16384
 save(OUT/'manifest.json',dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf),source_sha256=hashes,
  generated_sha256={rel(p):sha(p)for p in(addresses,frame)},symbols=sy,frozen_warm_ELF_unchanged=True,
  one_packet_bytes=85,one_SBC_frame=True,explicit_output_driver_memory_fixture=True,guest_executed=False,device_IO=False,install_candidate=False))
 print(json.dumps(dict(all_passed=True,ELF=rel(elf),ELF_SHA256=sha(elf),result_bytes=84,packet_bytes=85)),flush=True)
if __name__=='__main__':main()
