#!/usr/bin/env python3
"""Build freestanding SBC configuration/session/media gate; no OS hook."""
from datetime import datetime,timezone
import hashlib,json,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
LOCAL=ROOT/'native/avdtp-policy';OUT=ROOT/'staging/native-music-policy'
BASE=0x08b00000  # Synthetic emulator placement; not a Garmin RAM allocation.
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(c):return subprocess.run(c,check=True,capture_output=True,text=True).stdout


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'policy.ld'
    linker.write_text(f'''ENTRY(music_validate_configuration)
SECTIONS {{
 . = {BASE:#x};
 .text : {{ *(.text .text.*) *(.rodata .rodata.*) }}
 __code_end = .;
 .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }}
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin',
        '-fno-stack-protector','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
    obj=OUT/'policy.o';elf=OUT/'policy.elf';flat=OUT/'policy.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(LOCAL/'policy.c'),'-o',str(obj)],
        ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib',
         '-static','-no-pie','-Wl,--build-id=none,-Map='+str(OUT/'policy.map'),
         '-Wl,-T,'+str(linker),str(obj),'-lgcc','-o',str(elf)],
        ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for c in commands:run(c)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines()
        if len(p:=line.split())==3}
    assert len(flat.read_bytes())==symbols['__code_end']-BASE
    deps=[Path(__file__),LOCAL/'policy.c',LOCAL/'policy.h',linker,
        ROOT/'native/sbc-prototype/decoder.c',
        ROOT/'sources/deep-research/bluez-alsa-4.3.1/src/a2dp-sbc.c',
        ROOT/'sources/deep-research/bluez-alsa-4.3.1/src/shared/a2dp-codecs.h']
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,
        'synthetic_link_address_not_device_allocation':True,
        'flat':str(flat.relative_to(ROOT)),'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
        'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),'symbols':symbols,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'commands':commands,'attributes':attrs,'segments':segments,'unresolved_symbols':[],
        'Linux_runtime_dependencies':False,
        'supported_subset':'MediaTransport + audio/SBC only;44.1/48kHz,one selected format,bitpool2..53,localSEID1..3/peer1..62,raw unmultiplexed media.',
        'profile_limits_are_application_policy_not_whole_SBC_spec':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'scope':'Pre-accept validator and one-owner monotonic-session gate. Caller provides exact pre-accept hook, real registered endpoint ownership, coherent native snapshot/lock, captured callback epoch and local receive MTU. No native hook installed, protocol reject sender, SDP/SEP activation, jitter/packet decoding, UI/loader/hardware or phone proof. Not a full Bluetooth stack or driver.'}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':manifest['flat_bytes'],'ARM':'v6','device_install_candidate':False}))


if __name__=='__main__':main()
