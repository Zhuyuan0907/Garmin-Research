#!/usr/bin/env python3
"""Build a GeneralReject compatibility experiment, never an install image."""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
from build_native_music_gate import run,sha,ROOT
from analyze_native_sections import NativeImage
BASE=0x08a00000
OUT=ROOT/'staging/native-music-reply'


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'reply.ld'
    linker.write_text(f'''ENTRY(music_reply_dispatch)
PHDRS {{ code PT_LOAD FLAGS(5); }}
SECTIONS {{
 . = {BASE:#x};
 .text : {{ *(.text.music_reply_dispatch) *(.text .text.*) *(.rodata .rodata.*) }} :code
 __code_end = .;
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror']
    sources=[ROOT/'native/avdtp-reply/reply.c',ROOT/'native/avdtp-reply/stock-relocated.S']
    objects=[OUT/(p.stem+'.o') for p in sources]
    elf,flat=OUT/'reply.elf',OUT/'reply.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(src),'-o',str(obj)] for src,obj in zip(sources,objects)]
    commands += [['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
        '-Wl,--build-id=none,-Map='+str(OUT/'reply.map'),'-Wl,-T,'+str(linker),*map(str,objects),'-lgcc','-o',str(elf)],
        ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for c in commands:run(c)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines()
        if len(p:=line.split())==3}
    attributes=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attributes and all(t not in segments for t in ['RWE','INTERP','DYNAMIC'])
    assert symbols['music_reply_dispatch']==BASE and flat.stat().st_size==symbols['__code_end']-BASE
    code=flat.read_bytes();stock=NativeImage();offset=symbols['stock_reply_relocated']-BASE
    assert code[offset:offset+16]==stock.read(0x5756ac,16)
    patches=[{'address':'0x524914','original':stock.read(0x524914,2).hex(),'replacement':'a07c',
        'purpose':'preserve_original_unknown_signal_with_ldrb_r0_from_context_before_existing_strb'},
        {'address':'0x5756ac','original':stock.read(0x5756ac,16).hex(),
         'replacement':(bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',BASE)).hex(),
         'purpose':'Thumb_push_r3_ldr_mov_IP_pop_r3_BX_IP_literal_preserves_four_args_and_SP_with_exact16byte_prologue_relocated'}]
    for site in patches:
        ins=stock.md.disasm(bytes.fromhex(site['replacement']),int(site['address'],16))
        site['first_instructions']=[i.mnemonic+' '+i.op_str for i in list(ins)[:(1 if site['address']=='0x524914' else 5)]]
    assert patches[0]['first_instructions']==['ldrb r0, [r4, #0x12]']
    assert patches[1]['first_instructions']==['push {r3}','ldr r3, [pc, #8]','mov ip, r3','pop {r3}','bx ip']
    deps=[Path(__file__),ROOT/'scripts/build_native_music_gate.py',ROOT/'scripts/analyze_native_sections.py',linker,*sources]
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,
        'synthetic_link_address_not_device_allocation':True,'flat':str(flat.relative_to(ROOT)),
        'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,'elf':str(elf.relative_to(ROOT)),
        'elf_sha256':sha(elf),'symbols':symbols,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'commands':commands,'attributes':attributes,'segments':segments,'BSS_bytes':0,
        'unresolved_symbols':[],'Linux_runtime_dependencies':False,'additional_patches':patches,
        'additional_patch_fields_bytes':18,'device_io':False,'firmware_modified':False,
        'device_install_candidate':False,
        'scope':'VM-only GeneralReject experiment preserves unknown signal, wraps reply helper with all four register arguments/SP intact, delegates known signals through exact relocated16-byte prologue. Unknown error1 returns type1 with original signal/no error body through native L2CAP send. Full deployment/actual RAM allocation/pinned code/loader/phone acceptance remain unverified.'}
    (OUT/'manifest.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':out['flat_bytes'],'additional_patch_fields_bytes':18,'device_install_candidate':False}))


if __name__=='__main__':main()
