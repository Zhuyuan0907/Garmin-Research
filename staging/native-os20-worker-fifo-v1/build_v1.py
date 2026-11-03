#!/usr/bin/env python3
"""New tiny OS20 copied-media/FIFO ELF; frozen source TUs are read only."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,struct,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
OUT=BASE/'build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
    with p.open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def main():
    assert not OUT.exists();OUT.mkdir()
    imports=OUT/'playback_imports.h'
    imports.write_text('#ifndef OS20_FIFO_IMPORTS_V1_H\n#define OS20_FIFO_IMPORTS_V1_H\n#include <stdint.h>\nstatic const uint32_t playback_pcm_pages[4]={0x09140000u,0x09141000u,0x09142000u,0x09143000u};\n#endif\n')
    files=[BASE/'entry_v1.S',BASE/'worker_fifo_v1.c',BASE/'decoder_bind_v1.c',
        BASE/'runtime_v1.c',ROOT/'native/music-continuous/memory_output.c',
        ROOT/'native/music-continuous/owned_media.c',ROOT/'staging/native-owned-media/owned_queue.c',
        ROOT/'native/sbc-prototype/pcm_converter.c',ROOT/'native/sbc-prototype/voice_media.c',
        ROOT/'native/sbc-prototype/media_worker.c']
    headers=[BASE/'worker_fifo_v1.h',ROOT/'native/os20-task-bridge/resident_music_v1.h',
        *[ROOT/'native/sbc-prototype'/p for p in ('decoder.h','memory_output.h','media_queue.h','media_worker.h','pcm_converter.h')]]
    closed=[ROOT/'native/os20-task-bridge/resident-contract-v1.json',
        ROOT/'native/os20-audio-source-v1/contract-v1.json',
        ROOT/'staging/native-os20-resident-prefix-v1/FILE-prefix-proof.json',
        ROOT/'staging/native-os20-resident-prefix-v1/creation-bootstrap-prefix.json.gz',
        ROOT/'staging/native-sbc/manifest.json',ROOT/'staging/native-sbc/decoder-armv6.elf']
    frozen=json.loads(closed[-2].read_text())
    assert frozen['elf']=='staging/native-sbc/decoder-armv6.elf'
    assert sha(closed[-1])==frozen['elf_sha256']
    dependencies=[Path(__file__),BASE/'worker_fifo_v1.ld',*files,*headers,*closed]
    hashes={rel(p):sha(p)for p in dependencies}
    save(OUT/'inputs-at-build.json',hashes)
    flags=['-mcpu=arm1176jzf-s','-mthumb','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-pie','-fno-stack-protector','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-std=c11','-Wall','-Wextra','-Werror','-I'+str(OUT),'-I'+str(ROOT/'native/sbc-prototype')]
    commands=[]
    def run(args):
        r=subprocess.run(args,text=True,capture_output=True)
        save(OUT/f'command-{len(commands):02d}.json',dict(command=args,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
        commands.append(args)
        assert r.returncode==0,r.stderr[-4000:]
        return r.stdout
    objects=[]
    for i,p in enumerate(files):
        o=OUT/f'{i:02d}-{p.stem}.o';objects.append(o)
        defines=[]
        if p.name=='voice_media.c':defines=['-Dvoice_extension_submit_frame=owned_media_submit_frame',
            '-Dvoice_extension_media_callback=owned_packet_parse','-Dvoice_extension_media_api=owned_packet_api',
            '-Dvoice_media_stats=owned_packet_stats']
        run(['arm-linux-gnueabi-gcc',*flags,*defines,'-c',str(p),'-o',str(o)])
    elf=OUT/'worker-fifo-EMULATION-ONLY.elf'
    libgcc=Path(run(['arm-linux-gnueabi-gcc','-print-libgcc-file-name']).strip())
    run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
        '-Wl,--no-undefined,--gc-sections,--build-id=none,-Map='+str(OUT/'worker-fifo.map'),
        '-Wl,-T,'+str(BASE/'worker_fifo_v1.ld'),*map(str,objects),'-lgcc','-o',str(elf)])
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols={}
    for row in run(['arm-linux-gnueabi-nm','-n','-S',str(elf)]).splitlines():
        f=row.split()
        if len(f)==4:symbols[f[3]]=dict(address=int(f[0],16),size=int(f[1],16),type=f[2])
        elif len(f)==3:symbols[f[2]]=dict(address=int(f[0],16),size=0,type=f[1])
    anchors={'resident_music_worker_v1':0x09050000,'resident_controller_v1':0x090501e4,'resident_idle_v1':0x090502f8}
    for n,a in anchors.items():assert symbols[n]['address']==a
    for n in ('media_queue_callback','media_queue_step','owned_media_consume','memory_output_submit',
              'continuous_media_read','memory_output_discard','fifo_observations_v1'):
        assert n in symbols,n
    for n in ('memory_output_register','memory_output_after_selection','media_worker_boot','media_worker_entry'):
        assert n not in symbols,n
    for i in range(4):assert symbols['pcm'+str(i)]['address']==0x09140000+i*4096
    payload=elf.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',payload)
    segments=[]
    for i in range(h[10]):
        p=struct.unpack_from('<8I',payload,h[5]+i*h[9])
        if p[0]==1:
            assert not(p[6]&1 and p[6]&2)
            segments.append(dict(address=p[2],filesz=p[4],memsz=p[5],flags=p[6]))
    assert all(sha(ROOT/p)==h for p,h in hashes.items())
    result=dict(all_passed=True,source_sha256=hashes,generated_sha256={rel(imports):sha(imports)},
        ELF=rel(elf),ELF_sha256=sha(elf),symbols=symbols,segments=segments,
        decoder_ELF=frozen['elf'],decoder_ELF_sha256=frozen['elf_sha256'],
        static_libgcc_path=str(libgcc),static_libgcc_SHA256=sha(libgcc),
        new_entry_veneers=anchors,frozen_original_sources_modified=False,
        guest_executed=False,device_IO=False,install_candidate=False,undefined_symbols=[])
    save(OUT/'manifest.json',result)
    print(json.dumps(dict(all_passed=True,ELF=result['ELF'],ELF_sha256=result['ELF_sha256'],ELF_bytes=len(payload),
        observation_bytes=symbols['fifo_observations_v1']['size'],original_sources_modified=False)),flush=True)
if __name__=='__main__':main()
