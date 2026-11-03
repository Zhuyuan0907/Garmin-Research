#!/usr/bin/env python3
"""Relink frozen preserving+music code inside original3MiB, local VM only.

Frozen outputs/sources are untouched. Reuses verified two-pass import resolution
and original contiguous VPM extent geometry; no transferable update is made.
"""
from datetime import datetime, timezone
import json, struct
from pathlib import Path
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR
from build_native_sbc import run, sha
from build_native_app_component import symbols, API_NAMES
from build_native_voice_package_fixture import repack
from analyze_tts_vpm import parse_image

OUT=ROOT/'staging/native-music-stream'
FROZEN=ROOT/'staging/native-app-component-emulation/Chinese_Big5_MeiLing/manifest.json'
MUSIC_API=('native_music_start','native_music_callback','music_endpoint_prepare','music_endpoint_publish',
 'music_endpoint_capabilities','music_configuration_gate','music_reply_dispatch','music_validate_configuration',
 'music_guard_bind','music_guard_unbind','music_guard_packet','music_guard_frame')


def patches(stock,s=None):
    replacements=[]
    for signal,name in [(2,'music_endpoint_capabilities'),(3,'music_stream_configuration_gate'),
                        (4,'music_endpoint_capabilities'),(5,'music_configuration_gate')]:
        target=0x12345678 if s is None else s[name]['address']
        replacements.append((0xba6f6c+(signal-1)*4,struct.pack('<I',target)))
    replacements.extend([(0x5249f8,bytes.fromhex('0200c046')),
                         (0x5248fc,bytes.fromhex('0a28')),(0x524914,bytes.fromhex('a07c')),
                         (0x5756ac,bytes.fromhex('08b4024b9c4608bc6047c046')+
                          struct.pack('<I',0x12345678 if s is None else s['music_reply_dispatch']['address']))])
    return [{'address':a,'length':len(raw),'before':stock.read(a,len(raw)).hex(),'after':raw.hex()}
            for a,raw in replacements]


def imports(path,plan):
    def array(raw):return '{'+','.join('0x'+raw[i:i+2] for i in range(0,len(raw),2))+'}'
    path.write_text('struct music_patch { uint32_t address,length; uint8_t before[16],after[16]; };\n'
      '#define MUSIC_PATCH_COUNT 8u\nstatic const struct music_patch music_patches[8]={\n'+
      ',\n'.join('{'+hex(p['address'])+'u,'+str(p['length'])+'u,'+
                  array(p['before'])+','+array(p['after'])+'}' for p in plan)+'\n};\n')


def main():
    stock=NativeImage();f=json.loads(FROZEN.read_text());OUT.mkdir(parents=True,exist_ok=True)
    for p,h in f['source_sha256'].items():assert sha(ROOT/p)==h,p
    assert sha(ROOT/f['combined_binary'])==f['combined_sha256']
    for name in ['native-music-endpoint','native-music-reply']:
        m=json.loads((ROOT/'staging'/name/'manifest.json').read_text())
        for p,h in m['source_sha256'].items():assert sha(ROOT/p)==h,p
    base=f['extension_base']; original=(ROOT/f['original_binary']).read_bytes()
    frozen_dir=(ROOT/f['extension_elf']).parent
    for name in ['playback_imports.h','source_worker_imports.h']:
        (OUT/name).write_bytes((frozen_dir/name).read_bytes())
    # Identical PHDR separation is enforced for the newly linked image only.
    linker=OUT/'music_component.ld'
    script=(frozen_dir/'app_component.ld').read_text()
    script=script.replace('ENTRY(native_app_component_entry)',
        'ENTRY(native_music_component_entry)\nPHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }')
    script=script.replace('KEEP(*(.text.native_app_component_entry))',
        'KEEP(*(.text.native_music_component_entry)) KEEP(*(.text.native_app_component_entry)) KEEP(*(.music_component_api)) KEEP(*(.music_stream_api))')
    script=script.replace('*(.text .text.*) *(.rodata .rodata.*) }',
        '*(.text .text.*) *(.rodata .rodata.*) } :code')
    # Each NOLOAD section belongs to the writable segment, never executable.
    script=script.replace('__app_bss_end = .; }','__app_bss_end = .; } :data')
    for section in ['pcm0','pcm1','pcm2','pcm3','gather']:
        script=script.replace('*(.'+section+') }','*(.'+section+') } :data')
    for section in ['queue_payload','worker_stack','source_stack']:
        script=script.replace('__'+section+'_end = .; }','__'+section+'_end = .; } :data')
    linker.write_text(script)
    header=OUT/'music_patch_imports.h';imports(header,patches(stock))
    commands=[];objects=[];deps=set(ROOT/p for p in f['source_sha256'])|{FROZEN,Path(__file__),linker,header}
    # Replay only each source's first compilation, in a new output namespace.
    seen=set();flags=None
    for command in f['commands']:
        if '-c' not in command:continue
        src=Path(command[command.index('-c')+1])
        if src in seen:continue
        seen.add(src);c=[x.replace(str(frozen_dir),str(OUT)) for x in command]
        run(c);commands.append(c);objects.append(c[c.index('-o')+1])
        if src.name=='app_component_entry.c':flags=c[1:c.index('-c')]
    assert flags
    extra=[ROOT/'native/music-stream/entry.c',ROOT/'native/music-stream/stream.c',ROOT/'native/music-endpoint/endpoint.c',
      ROOT/'native/avdtp-gate/gate.c',ROOT/'native/avdtp-policy/policy.c',
      ROOT/'native/avdtp-reply/reply.c',ROOT/'native/avdtp-reply/stock-relocated.S']
    for src in extra:
        obj=OUT/('music_'+src.stem+'.o');c=['arm-linux-gnueabi-gcc',*flags,'-c',str(src),'-o',str(obj)]
        run(c);commands.append(c);objects.append(str(obj));deps.add(src)
    elf=OUT/'music-component-EMULATION-ONLY.elf';flat=OUT/'music-component-EMULATION-ONLY.bin'
    link=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
      '-Wl,--gc-sections,--build-id=none,-Map='+str(OUT/'music_component.map'),'-Wl,-T,'+str(linker),
      *objects,'-lgcc','-o',str(elf)]
    run(link);commands.append(link);s=symbols(elf)
    (OUT/'source_worker_imports.h').write_text('#define OWNED_CONSUME_RESUME '+hex(s['owned_media_consume']['address']+8)+'\n')
    plan=patches(stock,s);imports(header,plan)
    for src,obj in [(ROOT/'native/sbc-prototype/source_event_hooks.S',OUT/'source_event_hooks.o'),
                    (extra[0],OUT/'music_entry.o')]:
        c=['arm-linux-gnueabi-gcc',*flags,'-c',str(src),'-o',str(obj)]
        run(c);commands.append(c)
    run(link);commands.append(link);assert symbols(elf)==s,'Import resolution changed addresses'
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)]);segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and all(x not in segments for x in ['RWE','INTERP','DYNAMIC'])
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    code=flat.read_bytes();assert len(code)==s['__app_code_end']['address']-base<=65536
    combined=bytearray(original)+bytearray(base-IMAGE-len(original))+bytearray(code)
    entry=s['native_music_component_entry']['address'];disp=entry-(IMAGE+8);ram=s['__combined_ram_bytes']['address']
    struct.pack_into('<3I',combined,0,0xea000000|((disp//4)&0xffffff),ram,len(combined))
    assert combined[12:len(original)]==original[12:] and len(combined)<ram<=0x300000
    binary=OUT/'combined-voice-music-EMULATION-ONLY.bin';binary.write_bytes(combined)
    original_vpm=(ROOT/f['voice_package']).read_bytes();vpm,checks=repack(original_vpm,bytes(combined))
    package=OUT/'music-app-EMULATION-ONLY.vpm';package.write_bytes(vpm)
    files,_=parse_image(vpm);assert files['DLLIMG.BIN']['content']==combined
    for n in ['native/music-endpoint/endpoint.h','native/avdtp-gate/gate.h','native/avdtp-policy/policy.h',
              'scripts/build_native_voice_package_fixture.py','scripts/build_native_app_component.py']:
        deps.add(ROOT/n)
    deps.update([OUT/'playback_imports.h',OUT/'source_worker_imports.h',ROOT/'native/music-stream/stream.h',ROOT/'native/sbc-prototype/media_queue.h',ROOT/'native/sbc-prototype/memory_output.h',ROOT/'scripts/build_native_music_loaded.py',ROOT/'native/music-app/entry.c'])
    m={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
      'extension_base':base,'extension_bytes':len(code),'extension_elf':str(elf.relative_to(ROOT)),
      'extension_elf_sha256':sha(elf),'extension_flat':str(flat.relative_to(ROOT)),'extension_flat_sha256':sha(flat),
      'combined_binary':str(binary.relative_to(ROOT)),'combined_sha256':sha(binary),
      'combined_file_bytes':len(combined),'combined_ram_bytes':ram,'reservation_start':IMAGE,
      'reservation_end':DESCRIPTOR,'remaining_reservation_bytes':0x300000-ram,
      'original_binary':f['original_binary'],'original_bytes_after_header_unchanged':True,
      'voice_package':f['voice_package'],'package':str(package.relative_to(ROOT)),
      'package_sha256':sha(package),'package_bytes':len(vpm),'package_checks':checks,
      'symbols':s,'private_api':list(API_NAMES),'music_api':list(MUSIC_API),'pcm_pages':f['pcm_pages'],
      'stream_api':['music_stream_output_prepare','music_stream_configuration_gate','music_stream_callback','music_stream_consume','music_stream_retire_private'],
      'BSS_bytes':s['__app_bss_end']['address']-s['__app_bss_start']['address'],
      'patch_plan':plan,'VM_MAIN_patch_bytes':sum(p['length'] for p in plan),'code_RX_data_RW_segments':True,
      'frozen_preserving_manifest_sha256':sha(FROZEN),'frozen_artifacts_modified':False,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(deps)},'commands':commands,
      'attributes':attrs,'segments':segments,'unresolved_symbols':[],
      'device_io':False,'device_install_candidate':False,'real_package_acceptance_verified':False,
      'limits':'Local emulation-only relink at original reserved addresses. Compiled bootstrap checks eight original sites before guest writes, binds owned callback then publishes stock SDP, only with explicit writable MAIN/kernel/radio/storage fixtures. Original40 exports and12 private APIs retained but private addresses relinked. Native callback binds session/queue epoch under AVDTP lock, checks state/local receiveMTU/RTP/all SBC frames, copies packets, and guarded queue consumer decodes/converts into finite private PCM. OS worker/output-task/DAC/navigation integration is still unverified; READY PCM is not playback. Cache/MMU/task/pinning/reload/unload/actual package acceptance/App/menu/phone/speaker/concurrency are unverified. Never transfer this experimental VPM to navigator.'}
    (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':len(code),'file_bytes':len(combined),'ram_bytes':ram,'device_install_candidate':False}))


if __name__=='__main__':main()
