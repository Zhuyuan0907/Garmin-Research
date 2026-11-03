#!/usr/bin/env python3
"""Bounded stock DLL loader/sole entry controls, never native workers/audio/UI.

The old simulator is imported only as a function. Its main/proof path is never
run. File reads, strcmp/cache effects and RAM/MMU remain explicit fixtures.
"""
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,struct
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import emulate_native_loader as loader
from analyze_native_sections import NativeImage,EXPECTED
from analyze_native_loader import IMAGE,DESCRIPTOR,INIT
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(b):return hashlib.sha256(b).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(r):
    for p,h in r.items():assert sha(ROOT/p)==h,p
def newjson(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')
def signed(n):return n-(1<<32) if n&(1<<31) else n

def main():
    manifest=OUT/'manifest.json';m=json.loads(manifest.read_text());check(m['source_sha256']);check(m['artifacts_sha256'])
    protected=json.loads((OUT.parent/'previous-audit.json').read_text())['protected_sources'];assert len(protected)==892;check(protected)
    directory=OUT/'cold-loader-v1';assert not directory.exists();directory.mkdir()
    dependencies=dict(m['source_sha256'])
    for p in [Path(__file__).resolve(),manifest,ROOT/'scripts/emulate_native_loader.py',ROOT/'scripts/analyze_native_loader.py',
              ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_sdp_activation.py']:
        dependencies[rel(p)]=sha(p)
    original=(ROOT/m['original_binary']).read_bytes();combined=(ROOT/m['combined_binary']).read_bytes()
    assert digest(original)==m['original_binary_sha256'] and digest(combined)==m['combined_sha256']
    s={k:v['address'] for k,v in m['symbols'].items()};factory=loader.Uc
    limits={'loader_instruction_limit_per_control':1000000,'loader_timeout_us_per_control':30000000,
            'direct_control_instruction_limit':10000,'direct_control_timeout_us':1000000}
    results=[];new_vm=None;observer=None
    try:
        for kind,payload,ram in [('original_voice',original,m['original_ram_bytes']),('extended_voice',combined,m['combined_ram_bytes'])]:
            state={'entries':Counter(),'phase_writes':[],'zero_store_count':0,'other_new_BSS_stores':[],'permissions_set':False}
            def factory_new(*args,**kwargs):
                uc=factory(*args,**kwargs);start=uc.emu_start
                def observe(uc,address,size,data):
                    if kind!='extended_voice':return
                    for name in ('native_ui_music_single_entry','native_app_component_entry','original_tts_entry',
                                 'native_music_start','music_runtime_boot','native_ui_music_menu_install'):
                        if address==s[name]:state['entries'][name]+=1
                    if address==IMAGE and not state['permissions_set']:
                        uc.mem_protect(m['extension_base'],0x20000,UC_PROT_READ|UC_PROT_EXEC)
                        uc.mem_protect(s['__app_data_start'],s['__app_end']-s['__app_data_start'],UC_PROT_READ|UC_PROT_WRITE)
                        state['permissions_set']=True
                        phase=struct.unpack('<I',uc.mem_read(s['native_ui_music_entry_phase'],4))[0]
                        assert phase==0x55495331
                        before=bytes(uc.mem_read(s['__app_zero_start'],s['__app_zero_end']-s['__app_zero_start']))
                        assert before==b'\xa5'*len(before)
                        state['before_common_zero_sha256']=digest(before)
                    if address==s['native_app_component_entry']:
                        assert struct.unpack('<I',uc.mem_read(s['native_ui_music_entry_phase'],4))[0]==0x55495332
                def write(uc,access,address,size,value,data):
                    if kind!='extended_voice':return
                    pc=uc.reg_read(UC_ARM_REG_PC)
                    if address==s['native_ui_music_entry_phase']:
                        state['phase_writes'].append({'PC':hex(pc),'address':hex(address),'bytes':size,'value':hex(value)})
                    if s['__app_zero_start']<=address< s['__app_zero_end']:
                        if s['native_app_component_entry']<=pc<s['native_app_component_entry']+m['symbols']['native_app_component_entry']['size'] and size==4 and value==0:
                            state['zero_store_count']+=1
                        elif len(state['other_new_BSS_stores'])<64:
                            state['other_new_BSS_stores'].append({'PC':hex(pc),'address':hex(address),'bytes':size,'value':hex(value)})
                code_hook=uc.hook_add(UC_HOOK_CODE,observe);write_hook=uc.hook_add(UC_HOOK_MEM_WRITE,write)
                state['hook_ids']=(code_hook,write_hook)
                def bounded(begin,until,timeout=0,count=0):
                    if begin==INIT|1:timeout=limits['loader_timeout_us_per_control'];count=limits['loader_instruction_limit_per_control']
                    return start(begin,until,timeout=timeout,count=count)
                uc.emu_start=bounded
                return uc
            loader.Uc=factory_new
            uc,r=loader.simulate(NativeImage(),kind,module_bytes=payload,module_ram_bytes=ram,poison_module_ram=True,return_session=True)
            loader.Uc=factory
            for hook in state.pop('hook_ids'):uc.hook_del(hook)
            r['new_image_observation']=state
            newjson(directory/(kind+'-loader.json'),r);results.append((uc,r))
            if kind=='extended_voice':new_vm=uc;observer=state
        baseline_uc,baseline=results[0];uc,loaded=results[1]
        a=baseline['module_export_registration'][-1];b=loaded['module_export_registration'][-1]
        assert a['count']==b['count']==40
        assert all(a[k]==b[k] for k in ('version','export_table','count','targets'))
        assert baseline['trampolines_verified']==loaded['trampolines_verified']
        oldruntime=bytes(baseline_uc.mem_read(IMAGE+12,m['original_ram_bytes']-12))
        newruntime=bytes(uc.mem_read(IMAGE+12,m['original_ram_bytes']-12));assert newruntime==oldruntime
        assert observer['entries']['native_ui_music_single_entry']==observer['entries']['native_app_component_entry']==observer['entries']['original_tts_entry']==1
        assert not any(observer['entries'][n] for n in ('native_music_start','music_runtime_boot','native_ui_music_menu_install'))
        assert observer['zero_store_count']==(s['__app_zero_end']-s['__app_zero_start'])//4
        assert [p['value'] for p in observer['phase_writes']]==['0x55495332','0x55495333']
        assert struct.unpack('<Iii',uc.mem_read(s['app_component_state'],12))==(1,11,0)
        assert struct.unpack('<I',uc.mem_read(s['native_ui_music_entry_phase'],4))[0]==0x55495333
        tail=struct.unpack('<11I',uc.mem_read(s['native_ui_music_resident']+m['symbols']['native_ui_music_resident']['size']-44,44))
        assert tail[0]==1 and tail[1:4]==(0,0,0) and tail[4]==11
        dormant={}
        for n,length in [('music_runtime_state',40),('source_worker_state',52),('media_worker_state',32),
                         ('coordinator_state',60),('memory_output_control',48),('media_queue_control',36),('owned_media_control',52)]:
            raw=bytes(uc.mem_read(s[n],length));assert not any(raw);dormant[n]={'bytes':length,'sha256':digest(raw)}
        cpu_calls=[]
        def call(name,args=()):
            visited=[];main_writes=[]
            def observe(uc,address,size,data):visited.append(address)
            def write(uc,access,address,size,value,data):
                if 0x50000<=address<0xcb179c:main_writes.append({'PC':hex(uc.reg_read(UC_ARM_REG_PC)),'address':hex(address),'bytes':size})
            hook=uc.hook_add(UC_HOOK_CODE,observe)
            write_hook=uc.hook_add(UC_HOOK_MEM_WRITE,write)
            uc.reg_write(UC_ARM_REG_SP,0x0200f000);uc.reg_write(UC_ARM_REG_LR,loader.RETURN)
            for reg,val in zip((UC_ARM_REG_R0,),args):uc.reg_write(reg,val)
            uc.emu_start(s[name],loader.RETURN,timeout=1000000,count=10000)
            uc.hook_del(hook);uc.hook_del(write_hook)
            assert uc.reg_read(UC_ARM_REG_PC)==loader.RETURN,(name,hex(uc.reg_read(UC_ARM_REG_PC)))
            cpu_calls.append({'function':name,'actual_instructions':len(visited),'returned_signed':signed(uc.reg_read(UC_ARM_REG_R0)),
                              'MAIN_writes':main_writes,
                              'original_common_or_TTS_entered':any(x in (s['native_app_component_entry'],s['original_tts_entry']) for x in visited)})
            return uc.reg_read(UC_ARM_REG_R0)
        before=bytes(uc.mem_read(IMAGE,m['combined_ram_bytes']))
        assert signed(call('native_ui_music_single_entry',(DESCRIPTOR,)))==-104
        assert bytes(uc.mem_read(IMAGE,m['combined_ram_bytes']))==before and not cpu_calls[-1]['original_common_or_TTS_entered']
        anchor=call('native_ui_music_owned_anchor_address');assert anchor==s['anchor_zero']
        assert bytes(uc.mem_read(IMAGE,m['combined_ram_bytes']))==before
        # Explicit host-owned test output buffer only; no native ownership, TCB,
        # IRQ state, session or runtime storage is seeded.
        test=0x02008000;uc.mem_write(test,bytes(100))
        assert signed(call('native_ui_music_linked_bindings',(test,)))==-100
        binding=struct.unpack('<25I',uc.mem_read(test,100))
        names=['music_runtime_state','source_worker_state','coordinator_state','memory_output_control',
               'owned_media_control','media_queue_control','media_worker_state','memory_output_slots']
        assert list(binding[9:17])==[s[n] for n in names]
        assert binding[22]==anchor and binding[23]==8 and binding[0]==binding[7]==binding[8]==binding[24]==0
        assert signed(call('native_music_start'))==-2
        assert not cpu_calls[-1]['MAIN_writes']
        assert bytes(uc.mem_read(IMAGE,m['combined_ram_bytes']))==before
        # Saved fresh opcodes must point registration params[3] to the very
        # same local BSS object as the executed getter; registration itself
        # is not invoked (native channel/allocator ownership still missing).
        spec=importlib.util.spec_from_file_location('fresh_ELF',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);elf=mod.ELF32(ROOT/m['extension_elf'])
        register=elf.symbol('memory_output_register');raw,_,_=elf.at(register['value'],register['size']);md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
        literal_refs=[]
        for ins in md.disasm(raw,register['value']):
            if ins.mnemonic=='ldr' and ins.op_str.startswith('r2, [pc, #'):
                disp=int(ins.op_str.split('#')[1].split(']')[0],0);literal=ins.address+8+disp
                value=struct.unpack('<I',elf.at(literal,4)[0])[0]
                if value==anchor:
                    following=list(md.disasm(elf.at(ins.address+4,8)[0],ins.address+4))
                    assert any(i.mnemonic=='str' and i.op_str=='r2, [sp, #0x20]' for i in following)
                    literal_refs.append({'PC':hex(ins.address),'bytes':ins.bytes.hex(),'instruction':ins.mnemonic+' '+ins.op_str,
                                         'literal_PC':hex(literal),'literal_bytes':elf.at(literal,4)[0].hex(),
                                         'actual_same_anchor_address':hex(value),'following_opcodes':[{'PC':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in following]})
        assert len(literal_refs)==1
        check(m['source_sha256']);check(m['artifacts_sha256']);check(protected);check(dependencies)
        proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':m['exact_target'],'all_passed':True,
          'manifest':rel(manifest),'manifest_sha256':sha(manifest),'ELF_sha256':m['extension_elf_sha256'],'limits':limits,
          'controls':{'original_loader_baseline':True,'new_full_image_loaded_by_original_DLL_initializer':True,
              'RX_code_RW_data_before_actual_entry':True,'original40_exports_imports_trampolines_identical':True,
              'whole_original_RAM_after_header_identical':True,'all_new_zero_span_original_common_stores':observer['zero_store_count'],
              'single_common_and_TTS_bootstrap':True,'repeat_entry_pinned_without_module_write':True,
              'executed_getter_same_local_anchor':True,'actual_fresh_binding_pointers_fail_closed':True,
              'music_start_missing_adapter_rejected_without_MAIN_write':True},
          'observer':observer,'original_runtime_after_header_sha256':digest(newruntime),'dormant_runtime_controls':dormant,
          'direct_ARM_controls':cpu_calls,'actual_linked_binding_words':list(binding),'fresh_register_static_anchor_opcodes':literal_refs,
          'source_sha256':dict(sorted(dependencies.items())),
          'artifacts_sha256':{rel(p):sha(p) for p in directory.rglob('*') if p.is_file()},
          'protected_registry':{'count':892,'unchanged':True,'checked_before_after':True},
          'limitations':{'synthetic_file_callbacks_and_cache_sync_strcmp':True,'declared_RAM_MMU_permissions_fixture':True,
              'not_native_kernel_task_IRQ_GUI_audio_ownership_or_physical_acceptance_proof':True,
              'actual_memory_output_register_not_called':True,'native_ownership_session_lifecycle_callsite_glue_missing':True,
              'VPM_SIG_or_device_candidate_generated':False,'device_service_IO':False,'audible_output':False,
              'physical_App_direct_A2DP_verified':False,'goal_active':True}}
        newjson(OUT/'cold-loader-verification.json',proof)
        print(json.dumps({'proof':rel(OUT/'cold-loader-verification.json'),'sha256':sha(OUT/'cold-loader-verification.json'),
                          'controls_passed':len(proof['controls']),'original40_preserved':True,'zero_stores':observer['zero_store_count'],
                          'same_anchor':hex(anchor),'protected_unchanged':892,'native_runtime_UI_audio':False}))
    except BaseException as exc:
        loader.Uc=factory;check(protected)
        newjson(directory/'failed-attempt.json',{'error_type':type(exc).__name__,'error':str(exc),
            'source_sha256':dependencies,'completed_control_count':len(results),
            'artifacts_sha256':{rel(p):sha(p) for p in directory.rglob('*') if p.is_file()},'protected_892_unchanged':True,'device_IO':False})
        raise
    finally:loader.Uc=factory

if __name__=='__main__':main()
