#!/usr/bin/env python3
"""New-only full ARM image; frozen source/REL inputs read and checked.

All attempt artifacts are retained. No VPM, signature or device candidate is
created. This builder never imports/runs an older build or emulation main.
"""
import sys
sys.dont_write_bytecode = True
import hashlib, importlib.util, json, struct, subprocess
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
OLD = ROOT / 'staging/native-music-continuous'
GLUE = ROOT / 'staging/native-player-dispatcher-native-body/music-static'
AUDIT = OUT.parent / 'previous-audit.json'
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p): return str(p.relative_to(ROOT))
def check(reg):
    for p,h in reg.items(): assert sha(ROOT/p) == h, p
def newjson(p,d):
    with p.open('x') as f: json.dump(d,f,indent=2,ensure_ascii=False); f.write('\n')
def newtext(p,s):
    with p.open('x') as f: f.write(s)
def run(cmd, destination, timeout=60):
    p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
    r={'command':cmd,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    newjson(destination,r)
    assert not p.returncode,(rel(destination),p.stderr[-2000:])
    return r

def elf_reader():
    p=GLUE/'analyze_single_image_link_bindings.py'
    spec=importlib.util.spec_from_file_location('frozen_ELF32_reader',p)
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.ELF32

def patch_plan(stock,s=None):
    def target(name): return 0x12345678 if s is None else s[name]['address']
    changes=[]
    for signal,name in [(2,'music_endpoint_capabilities'),(3,'music_stream_configuration_gate'),
                        (4,'music_endpoint_capabilities'),(5,'music_configuration_gate'),(7,'music_runtime_start_gate')]:
        changes.append((0xba6f6c+(signal-1)*4,struct.pack('<I',target(name))))
    changes += [(0x5249f8,bytes.fromhex('0200c046')),(0x5248fc,bytes.fromhex('0a28')),
                (0x524914,bytes.fromhex('a07c')),
                (0x5756ac,bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',target('music_reply_dispatch'))),
                (0x3b9dfc,bytes.fromhex('004b1847')+struct.pack('<I',target('umcn_cleanup_bridge'))+bytes.fromhex('c046')),
                (0x2f998e,bytes.fromhex('014b1847c046')+struct.pack('<I',target('playback_callback_hook')))]
    assert len(changes)==11
    return [{'address':a,'length':len(b),'before':stock.read(a,len(b)).hex(),'after':b.hex()} for a,b in changes]

def headers(directory,stock,pcm,s=None):
    def array(x): return '{'+','.join('0x'+x[i:i+2] for i in range(0,len(x),2))+'}'
    plan=patch_plan(stock,s)
    text='struct music_patch { uint32_t address,length; uint8_t before[16],after[16]; };\n'
    text+='#define MUSIC_PATCH_COUNT 11u\nstatic const struct music_patch music_patches[11]={\n'
    text+=',\n'.join('{'+hex(p['address'])+'u,'+str(p['length'])+'u,'+array(p['before'])+','+array(p['after'])+'}' for p in plan)
    text+='\n};\n#define STOCK_START_HANDLER '+hex(struct.unpack('<I',stock.read(0xba6f84,4))[0])+'u\n'
    newtext(directory/'music_patch_imports.h',text)
    newtext(directory/'playback_imports.h','static const uint32_t playback_pcm_pages[4] = {'+','.join(hex(p)+'u' for p in pcm)+'};\n')
    resume=0x12345678 if s is None else s['owned_media_consume']['address']+8
    newtext(directory/'source_worker_imports.h','#define OWNED_CONSUME_RESUME '+hex(resume)+'\n')
    return plan

def symbols(reader):
    return {s['name']:{'address':s['value'],'size':s['size'],'type':s['type'],'binding':s['binding']}
            for s in reader.symbols if s['name'] and s['section_index']!=0 and s['type']!=4}

def main():
    assert not (OUT/'attempt-v1').exists() and not (OUT/'manifest.json').exists()
    protected=json.loads(AUDIT.read_text())['protected_sources']; assert len(protected)==892;check(protected)
    continuous=json.loads((OLD/'manifest.json').read_text())
    prior=json.loads((GLUE/'verification.json').read_text())
    static=json.loads((GLUE/'single-image-link-binding-review.json').read_text())
    for record in (continuous,prior,static):check(record['source_sha256'])
    check(prior['artifacts_sha256']);check(prior['failed_candidate_history']['artifacts_sha256'])
    frozen_rel=ROOT/prior['ARM_artifact']['path'];assert sha(frozen_rel)==prior['ARM_artifact']['sha256']
    assert prior['ARM_artifact']['undefined_symbols'] and len(prior['ARM_artifact']['undefined_symbols'])==12
    attempt=OUT/'attempt-v1';attempt.mkdir()
    source=ROOT/'native/music-continuous/entry.c';text=source.read_text()
    begin=text.index('int native_music_component_entry(void *loader)');end=text.index('const void *const music_component_api[]',begin)
    text=text[:begin]+text[end:]
    for a,b in {'"../music-endpoint/endpoint.h"':'"../../../native/music-endpoint/endpoint.h"',
                '"../avdtp-gate/gate.h"':'"../../../native/avdtp-gate/gate.h"',
                '"../avdtp-policy/policy.h"':'"../../../native/avdtp-policy/policy.h"',
                '"stream.h"':'"../../../native/music-continuous/stream.h"'}.items():text=text.replace(a,b)
    text=text.replace('#include "stream.h"','#include "../../../native/music-continuous/stream.h"')
    text='#include "'+str(GLUE/'ui_music_single.h')+'"\n'+text
    needle='int native_music_start(void)\n{\n';assert needle in text
    text=text.replace(needle,needle+'    /* Full-linked but deferred: no cleanup patch before real adapter context. */\n'
        '    if (!native_ui_music_resident.attached ||\n'
        '        umcn_cleanup_bridge_context != &native_ui_music_resident.adapter) return UMC_NOT_READY;\n',1)
    newtext(OUT/'music_support.c',text)
    ELF=elf_reader();stock=NativeImage();base=continuous['extension_base']
    pcm=[base+x for x in (0x27000,0x28000,0x29000,0x2a000)]
    commands=[];source_inputs=set();compiles=[];seen=set()
    for command in continuous['commands']:
        if '-c' not in command:continue
        original=Path(command[command.index('-c')+1])
        if original in seen:continue
        seen.add(original);compiles.append((original,command));source_inputs.add(original)
    assert len(compiles)==23
    first=None
    try:
        for phase in (1,2):
            directory=attempt/('pass-'+str(phase));directory.mkdir()
            plan=headers(directory,stock,pcm,first)
            objects=[]
            for n,(original,command) in enumerate(compiles):
                src=original
                if original==ROOT/'native/music-continuous/memory_output.c':src=OUT/'memory_output_owner.c'
                if original==ROOT/'native/music-continuous/entry.c':src=OUT/'music_support.c'
                flags=command[1:command.index('-c')]
                flags=[x.replace(str(OLD),str(directory)) for x in flags]
                flags.insert(0,'-I'+str(directory))
                obj=directory/(str(n)+'-'+Path(command[command.index('-o')+1]).name)
                cmd=['arm-linux-gnueabi-gcc',*flags,'-c',str(src),'-o',str(obj)]
                run(cmd,directory/('compile-'+str(n)+'.json'));commands.append(cmd);objects.append(str(obj))
            elf=directory/'single-bootstrap-ui-music-EMULATION-ONLY.elf'
            cmd=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
                 '-Wl,--gc-sections,--build-id=none,-Map='+str(directory/'single_image.map'),'-Wl,-T,'+str(OUT/'single_image.ld'),
                 str(frozen_rel),*objects,'-Wl,--wrap=media_coordinator_init','-lgcc','-o',str(elf)]
            run(cmd,directory/'link.json');commands.append(cmd)
            e=ELF(elf);current=symbols(e)
            assert e.kind==2 and e.entry==current['native_ui_music_single_entry']['address']
            assert not [s for s in e.symbols if s['name'] and s['section_index']==0]
            if phase==1:first=current
            else:assert current==first,'two-pass imported literal values changed symbol map'
        final=attempt/'pass-2';elf=final/'single-bootstrap-ui-music-EMULATION-ONLY.elf';e=ELF(elf);s=current
        flat=final/'single-bootstrap-ui-music-EMULATION-ONLY.bin'
        run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)],final/'objcopy.json')
        raw=flat.read_bytes();assert len(raw)==s['__app_file_end']['address']-base==0x20004
        assert s['__app_file_end']['address']>s['__app_code_end']['address']
        guard=e.symbol('native_ui_music_entry_phase');anchor=e.symbol('anchor_zero')
        assert anchor['binding']==0 and anchor['type']==1 and anchor['size']==2
        assert guard['size']==4 and guard['value']==s['__app_data_start']['address']
        assert e.sections[guard['section_index']]['name']=='.data'
        assert e.at(guard['value'],4)[0]==bytes.fromhex('31534955')
        assert s['__app_data_end']['address']<=s['__app_zero_start']['address']
        assert s['__app_zero_start']['address']<=s['native_ui_music_resident']['address']<s['__app_zero_end']['address']
        assert s['__app_zero_start']['address']<=anchor['value']<s['__app_zero_end']['address']
        assert all(n not in s for n in ('native_music_component_entry','native_player_component_entry'))
        for n in ('native_ui_music_menu_install','native_ui_music_linked_bindings','umcn_cleanup_bridge',
                  'native_ui_music_service_owner','native_ui_music_owned_anchor_address'):assert n in s
        object_sizes={'coordinator_state':60,'media_queue_control':36,'media_worker_state':32,'memory_output_control':48,
                      'memory_output_slots':96,'music_runtime_state':40,'owned_media_control':52,'source_worker_state':52}
        for n,size in object_sizes.items():assert s[n]['size']==size,(n,s[n])
        attrs=run(['arm-linux-gnueabi-readelf','-h','-A',str(elf)],final/'ELF-header.json')['stdout']
        segments=run(['arm-linux-gnueabi-readelf','-lW',str(elf)],final/'ELF-segments.json')['stdout']
        assert 'Tag_CPU_arch: v6' in attrs and 'Tag_ABI_VFP_args' not in attrs
        assert all(x not in segments for x in ('INTERP','DYNAMIC','RWE'))
        assert ' R E ' in segments and ' RW ' in segments
        for label,args in [('sections',['-SW']),('symbols',['-sW']),('relocations',['-rW'])]:
            run(['arm-linux-gnueabi-readelf',*args,str(elf)],final/('ELF-'+label+'.json'))
        run(['arm-linux-gnueabi-objdump','-d','--disassemble=native_ui_music_owned_anchor_address',str(elf)],final/'anchor-getter-opcodes.json')
        original_path=ROOT/continuous['original_binary'];original=original_path.read_bytes()
        combined=bytearray(original)+bytearray(base-0x2d4bb74-len(original))+bytearray(raw)
        disp=e.entry-(0x2d4bb74+8);ram=s['__combined_ram_bytes']['address']
        struct.pack_into('<3I',combined,0,0xea000000|((disp//4)&0xffffff),ram,len(combined))
        assert combined[12:len(original)]==original[12:] and len(combined)<ram<=0x300000
        image=final/'combined-TTS-ui-music-EMULATION-ONLY.bin'
        with image.open('xb') as f:f.write(combined)
        bindings=[{'symbol':n,'fresh':s[n]} for n in prior['ARM_artifact']['undefined_symbols']]
        host=attempt/'host-single-controls-sanitized'
        hostcmd=['gcc','-std=c11','-Wall','-Wextra','-Werror','-Wshadow','-Wstrict-prototypes','-O2',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                 str(ROOT/'native/ui-music-control-prototype/ui_music_control.c'),
                 str(ROOT/'native/ui-music-native-adapter/native_adapter.c'),str(GLUE/'ui_music_single.c'),
                 str(GLUE/'host_single_controls.c'),'-o',str(host)]
        run(hostcmd,attempt/'host-compile.json');host_result=run([str(host)],attempt/'host-controls.json')
        h=json.loads(host_result['stdout']);assert h['all_passed'] and h['group_count']==8
        dependencies=dict(static['source_sha256']);dependencies.update(continuous['source_sha256'])
        for p in source_inputs|{AUDIT,OLD/'manifest.json',GLUE/'verification.json',GLUE/'single-image-link-binding-review.json',
                                 frozen_rel,original_path,ROOT/'evidence/firmware-analysis/main_02bd.bin'}:
            dependencies[rel(p)]=sha(p)
        for p in OUT.iterdir():
            if p.is_file():dependencies[rel(p)]=sha(p)
        for directory in (attempt/'pass-1',final):
            for p in directory.glob('*.h'):dependencies[rel(p)]=sha(p)
        check(protected);check(dependencies)
        manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','MAIN_sha256':EXPECTED},
          'all_passed':True,'extension_base':base,'extension_bytes':len(raw),'extension_code_bytes':s['__app_code_end']['address']-base,
          'extension_elf':rel(elf),'extension_elf_sha256':sha(elf),'extension_flat':rel(flat),'extension_flat_sha256':sha(flat),
          'combined_binary':rel(image),'combined_sha256':sha(image),'combined_file_bytes':len(combined),'combined_ram_bytes':ram,
          'remaining_reservation_bytes':0x300000-ram,'original_binary':rel(original_path),'original_binary_sha256':sha(original_path),
          'original_file_bytes':len(original),'original_ram_bytes':struct.unpack_from('<I',original,4)[0],
          'original_bytes_after_header_unchanged':True,'entry':e.entry,'sole_wrapper':'native_ui_music_single_entry','symbols':s,
          'pcm_pages':pcm,'patch_plan':plan,'patch_plan_installed_or_executed':False,'patch_bytes':sum(p['length'] for p in plan),
          'patch_3B9DFC_target':'umcn_cleanup_bridge','music_start_requires_attached_adapter':True,
          'initialized_guard':{'address':guard['value'],'bytes_hex':'31534955','section':'.data','outside_zero_span':True},
          'owned_anchor':{'symbol':anchor,'getter':s['native_ui_music_owned_anchor_address'],'same_owner_TU':True,
                          'no_frozen_source_edited':True,'runtime_same_object_verification_pending':True},
          'ELF_type':'ET_EXEC','machine':'EM_ARM','ARMv6_soft_float':True,'undefined_symbols':[],
          'freshly_resolved_12_boundaries':bindings,'two_pass_symbol_maps_identical':True,'old_import_maps_compiled':False,
          'frozen_glue_REL_linked':rel(frozen_rel),'lower_objects_recompiled_in_exclusive_namespace':len(compiles),
          'file_end_includes_RW_initialized_data':True,'code_RX_data_RW_segments':True,'attributes':attrs,'segments':segments,
          'source_sha256':dict(sorted(dependencies.items())),
          'artifacts_sha256':{rel(p):sha(p) for p in attempt.rglob('*') if p.is_file()},
          'protected_registry':{'snapshot':rel(AUDIT),'sha256':sha(AUDIT),'count':892,'checked_before_after':True,'unchanged':True},
          'host_controls':h,'host_ASan_UBSan':True,'commands':commands,
          'limitations':{'original_TTS40_runtime_preservation':'requires new bounded original-loader control',
                         'host_controls_use_explicit_mock_ownership_not_native_proof':True,
                         'source_loop_publication_iteration_admission_and_media_lease_calls_not_integrated':True,
                         'native_channel8_exclusivity_AV_session_GUI_render_touch_not_proven':True,
                         'source9_binding_missing_fail_closed':True,'original_SIG_policy_physical_modified_code_acceptance':'unknown',
                         'VPM_or_SIG_generated':False,'device_service_IO':False,'physical_App_direct_A2DP_verified':False,
                         'device_install_candidate':False,'goal_active':True}}
        newjson(OUT/'manifest.json',manifest)
        print(json.dumps({'manifest':rel(OUT/'manifest.json'),'sha256':sha(OUT/'manifest.json'),
                          'ELF_sha256':sha(elf),'text_bytes':manifest['extension_code_bytes'],'flat_bytes':len(raw),
                          'unresolved':0,'host_groups':h['group_count'],'protected_unchanged':892}))
    except BaseException as exc:
        check(protected)
        newjson(attempt/'failed-attempt.json',{'error_type':type(exc).__name__,'error':str(exc),
                    'source_sha256':{rel(p):sha(p) for p in OUT.iterdir() if p.is_file()},
                    'artifacts_sha256':{rel(p):sha(p) for p in attempt.rglob('*') if p.is_file()},
                    'protected_892_unchanged':True,'no_device':True})
        raise

if __name__=='__main__':main()
