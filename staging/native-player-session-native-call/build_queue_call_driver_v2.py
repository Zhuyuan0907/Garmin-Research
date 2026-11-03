#!/usr/bin/env python3
"""NEW bounded native-queue image; no old image addresses or files modified."""
import hashlib,json,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-inline-fields/music-session'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def name(p):return str(p.relative_to(ROOT))
def main():
 out=BASE/'build-v2';out.mkdir(exist_ok=False)
 snapshot=out/'source-snapshot';snapshot.mkdir()
 source=[BASE/'queue_call_driver_v2.c',Path(__file__).resolve(),OLD/'music_session_guard_v2.c',
 OLD/'music_session_guard_v2.h',OLD/'native_context_v2.c',
 ROOT/'native/ui-music-control-prototype/ui_music_control.c',
 ROOT/'native/ui-music-control-prototype/ui_music_control.h',
 ROOT/'native/ui-music-native-adapter/native_adapter.h']
 hashes={name(p):sha(p) for p in source}
 for i,p in enumerate(source):(snapshot/f'{i}-{p.name}').write_bytes(p.read_bytes())
 (out/'inputs.json').write_text(json.dumps(hashes,indent=2)+'\n')
 script=out/'queue-call.ld'
 script.write_text('''ENTRY(qcs_initialize)
SECTIONS {
 . = 0x07000000;
 .text : { *(.text.qcs_*) KEEP(*(.text.mcs_native_ownership_snapshot)) *(.text*) *(.rodata*) }
 . = ALIGN(4096);
 .data : { *(.data*) }
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss*) *(COMMON) }
 .ARM.attributes 0 : { *(.ARM.attributes) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
 '-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
 '-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-I',str(OLD)]
 files=[BASE/'queue_call_driver_v2.c',OLD/'music_session_guard_v2.c',
 OLD/'native_context_v2.c',ROOT/'native/ui-music-control-prototype/ui_music_control.c']
 objects=[];index=0
 def command(args):
  nonlocal index
  r=subprocess.run(args,text=True,capture_output=True)
  (out/f'command-{index}.json').write_text(json.dumps(dict(command=args,exit_code=r.returncode,
    stdout=r.stdout,stderr=r.stderr),indent=2)+'\n');index+=1
  if r.returncode:raise RuntimeError(r.stderr[-2000:])
  return r.stdout
 for p in files:
  o=out/(p.stem+'.o');objects.append(o)
  command(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(o)])
 elf=out/'queue-call-EMULATION-ONLY.elf'
 command(['arm-linux-gnueabi-gcc','-nostdlib','-no-pie','-Wl,--gc-sections',
   '-Wl,--no-undefined','-Wl,-T,'+str(script),'-Wl,-Map,'+str(out/'queue-call.map'),
   *[str(p)for p in objects],'-o',str(elf)])
 rd=command(['arm-linux-gnueabi-readelf','-h','-s','-l',str(elf)])
 (out/'readelf.txt').write_text(rd)
 spec=__import__('importlib.util',fromlist=['util'])
 loader=spec.spec_from_file_location('qcs_elf',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 mod=spec.module_from_spec(loader);loader.loader.exec_module(mod)
 e=mod.ELF32(elf)
 unresolved=[s['name']for s in e.symbols if s['name']and s['section_index']==0]
 assert not unresolved
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 for symbol in ('qcs_initialize','qcs_begin','qcs_end','qcs_stop','qcs_status','mcs_queue_bridge','mcs_native_ownership_snapshot'):
  assert symbol in symbols,symbol
 assert all(sha(ROOT/p)==h for p,h in hashes.items())
 manifest=dict(all_passed=True,source_sha256=hashes,ELF=name(elf),ELF_sha256=sha(elf),
   symbols=symbols,undefined_symbols=[],complete_player_image=False,
   native_instructions_executed=False,device_io=False)
 (BASE/'build-v2.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps(dict(all_passed=True,ELF=name(elf),sha256=sha(elf),undefined_symbols=[])))
if __name__=='__main__':main()
