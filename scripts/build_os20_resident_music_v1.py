#!/usr/bin/env python3
"""Compile persistent worker and native controller against frozen decoder."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/native-os20-resident-music-build-v1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    assert not OUT.exists();OUT.mkdir()
    decoder_manifest=ROOT/'staging/native-sbc/manifest.json'
    decoder=json.loads(decoder_manifest.read_text())
    assert sha(ROOT/decoder['elf'])==decoder['elf_sha256']
    assert decoder['symbols']['garmin_sbc_reset']['address']==0x0800223c
    assert decoder['symbols']['garmin_sbc_decode_frame']['address']==0x08002284
    source=ROOT/'native/os20-task-bridge/resident_music_v1.c'
    linker=ROOT/'native/os20-task-bridge/resident_music_v1.ld'
    elf=OUT/'resident-music-v1.elf'
    command=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mthumb','-mfloat-abi=soft',
        '-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections',
        '-std=c11','-Wall','-Wextra','-Werror','-nostdlib','-static','-no-pie',
        '-Wl,--build-id=none,-T,'+str(linker),str(source),'-o',str(elf)]
    subprocess.run(command,check=True,capture_output=True,text=True)
    undefined=subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip()
    assert not undefined
    symbols={}
    for line in subprocess.check_output(['arm-linux-gnueabi-nm','-n',str(elf)],text=True).splitlines():
        fields=line.split()
        if len(fields)==3:symbols[fields[2]]=dict(address=int(fields[0],16),type=fields[1])
    assert symbols['resident_music_worker_v1']['address']==0x09050000
    sources=[Path(__file__),source,linker,ROOT/'native/os20-task-bridge/resident_music_v1.h',
        ROOT/'native/sbc-prototype/decoder.h',decoder_manifest,ROOT/decoder['elf']]
    result=dict(all_passed=True,command=command,source_sha256={str(p.relative_to(ROOT)):sha(p)for p in sources},
        ELF=str(elf.relative_to(ROOT)),ELF_sha256=sha(elf),symbols=symbols,
        decoder_ELF=decoder['elf'],decoder_ELF_sha256=decoder['elf_sha256'],
        undefined_symbols=[],device_IO=False,install_candidate=False)
    with (OUT/'manifest.json').open('x')as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,ELF=result['ELF'],ELF_bytes=elf.stat().st_size,
        worker_entry=hex(symbols['resident_music_worker_v1']['address']|1),
        controller_entry=hex(symbols['resident_controller_v1']['address']|1),
        idle_entry=hex(symbols['resident_idle_v1']['address']|1))),flush=True)
if __name__=='__main__':main()
