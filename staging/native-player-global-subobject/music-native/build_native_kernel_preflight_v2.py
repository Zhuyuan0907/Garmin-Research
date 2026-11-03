#!/usr/bin/env python3
"""New exclusive compile/static preflight; no VM or guest operation."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,subprocess,struct
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
REGISTRY=ROOT/'staging/native-player-global-subobject/previous-audit.json'
MANIFEST=ROOT/'staging/native-player-settings-scope/music-owner/manifest.json'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(rows):
    for p,h in rows.items():assert sha(ROOT/p)==h,p
def newjson(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
def main():
    assert not (OUT/'preflight-v2.json').exists()
    assert sha(REGISTRY)=='0804ee3b65a6a5f2c64bb630582711ce4d0c15ae1170aaa9489688f90a5a2f98'
    protected=json.loads(REGISTRY.read_text())['protected_sources'];assert len(protected)==1274
    check(protected)
    m=json.loads(MANIFEST.read_text());check(m['source_sha256']);check(m['artifacts_sha256'])
    spec=importlib.util.spec_from_file_location('frozen_elf_reader',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    elf=mod.ELF32(ROOT/m['extension_elf']);assert elf.kind==2
    names=['source_worker_state','music_owner_irq_save','music_owner_irq_restore','music_owner_post']
    imports={n:elf.symbol(n)['value'] for n in names}
    directory=OUT/'compile-v2';directory.mkdir(exist_ok=False)
    script=directory/'publisher.ld'
    script.write_text('ENTRY(music_native_publish)\n'+''.join(n+' = '+hex(a)+';\n' for n,a in imports.items())+
        'SECTIONS { . = 0x09600000; .text : { KEEP(*(.text.music_native_publish)) *(.text*) *(.rodata*) } /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) } }\n')
    commands=[['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-Wall','-Wextra','-Werror','-c',str(OUT/'music_native_publish_v2.c'),'-o',str(directory/'publisher.o')],
      ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie','-Wl,--gc-sections,--build-id=none','-Wl,-T,'+str(script),str(directory/'publisher.o'),'-o',str(directory/'publisher.elf')]]
    for i,c in enumerate(commands):
        p=subprocess.run(c,text=True,capture_output=True);newjson(directory/('command-'+str(i)+'.json'),dict(command=c,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr));assert p.returncode==0
    publisher=mod.ELF32(directory/'publisher.elf');assert publisher.kind==2
    undefined=[s['name'] for s in publisher.symbols if s['name'] and s['section_index']==0];assert not undefined
    im=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_ARM);instructions={}
    for n in ['source_worker_entry','source_worker_boot','music_owner_control_boundary','music_owner_after_boundary','__wrap_media_coordinator_init','media_coordinator_cancel']:
        s=elf.symbol(n);raw,off,section=elf.at(s['value'],s['size'])
        instructions[n]=dict(symbol=s,section=section,ELF_offset=off,bytes_sha256=hashlib.sha256(raw).hexdigest(),instructions=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in md.disasm(raw,s['value'])])
    kernels={}
    for a,n,mode in [(0x358bf8,0x30,CS_MODE_THUMB),(0xf5030,12,CS_MODE_THUMB),(0xf6f26,40,CS_MODE_THUMB),(0x2fcf44,0xf0,CS_MODE_ARM),(0x2fd034,0x88,CS_MODE_THUMB),(0x21b6cc,32,CS_MODE_ARM),(0x358d24,16,CS_MODE_THUMB),(0x358ec4,0x58,CS_MODE_ARM)]:
        kernels[hex(a)]=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in Cs(CS_ARCH_ARM,mode).disasm(im.read(a,n),a)]
    deps=dict(m['source_sha256']);deps.update({rel(p):sha(p)for p in [Path(__file__).resolve(),OUT/'music_native_publish_v2.c',MANIFEST,REGISTRY,ROOT/m['extension_elf'],ROOT/m['extension_flat'],ROOT/'staging/native-player-settings-scope/music-owner/native-owner-contract.json',ROOT/'scripts/analyze_native_sections.py',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',script]})
    check(deps);check(protected)
    artifacts={rel(p):sha(p)for p in directory.rglob('*')if p.is_file()}
    d=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,exact_target=m['exact_target'],source_sha256=deps,artifacts_sha256=artifacts,
      protected_registry=rel(REGISTRY),protected_registry_sha256=sha(REGISTRY),protected_files_verified=1274,
      frozen_image_manifest=rel(MANIFEST),frozen_image_manifest_sha256=sha(MANIFEST),frozen_image_elf=rel(ROOT/m['extension_elf']),frozen_image_elf_sha256=sha(ROOT/m['extension_elf']),
      new_ARM_ET_EXEC=rel(directory/'publisher.elf'),new_ARM_ELF_sha256=sha(directory/'publisher.elf'),new_ARM_machine=40,new_ARM_undefined_symbols=undefined,
      exact_frozen_image_imports=imports,new_publisher_symbol=publisher.symbol('music_native_publish'),
      compiled_source_worker_and_owner=instructions,original_kernel_opcode_windows=kernels,
      planned_fixture=dict(loaded_single_image_sections_not_new_TTS_loader_proof=True,zeroed_image_BSS_is_declared_input=True,
          copied_initialized_bank_from_exact_MAIN=True,controller_idle_descriptors_and_initial_ready_membership=True,
          channel8_native_idle_state_is_declared_input_not_reservation=True,adapter_attached=False,
          producer_busy_pause_control_is_explicit_private_RAM_fixture=True),
      planned_controls=['original_builder_registry_post_boot_then_wait_schedules_compiled_persistent_loop_once',
        'normal0x80000 durable command drains with missing-adapter rejection,not fabricated service success',
        'mixed original10000/20000 events preserve compiled empty pump and resident originalwait',
        'actual compiled cancel result1 retainscancel_requested until compiled cancel return0 then sourceafter_boundary',
        'originalpost higher-priority preemption preserves publisher caller and persistent sourceentry',
        'whole mapped RW spans replay against CPU writes and code bytes remain exact'],
      limits=dict(VM_or_guest_execution=False,no_host_ABI_spies_or_ret_replacement_planned=True,
          no_native_audio_source_or_register_head_plan=True,exclusive_witness_and_session_missing=True,
          STOP_DONE_UI_generation_cleanup_not_proven=True,physical_App_VPM_SIG_BT_USB_audio=False))
    newjson(OUT/'preflight-v2.json',d)
    print(json.dumps(dict(preflight=rel(OUT/'preflight-v2.json'),sha256=sha(OUT/'preflight-v2.json'),publisher_ELF_sha256=sha(directory/'publisher.elf'),protected=1274)))
if __name__=='__main__':main()
