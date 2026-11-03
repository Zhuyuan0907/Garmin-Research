#!/usr/bin/env python3
"""Read existing ELF32/source bytes only; write one exclusive static review.

No compiler, compiled controls, emulators, device/services or package mutation.
Uses a small ELF32 reader and Capstone only for saved instruction decoding.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
REPORT=OUT/'single-image-link-binding-review.json'
VERIFICATION=OUT/'verification.json'
REL=OUT/'arm1176-rel-v2/ui-music-single-bootstrap-relocatable.elf'
CONT=ROOT/'staging/native-music-continuous/manifest.json'
PLAYER=ROOT/'staging/native-player-resources/manifest.json'
AUDIT=ROOT/'staging/native-player-dispatcher-native-body/previous-audit.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(reg):
    for p,digest in reg.items():
        assert sha(ROOT/p)==digest,p
def source_lines(path,needles):
    lines=path.read_text().splitlines()
    return [{'line':n,'text':line} for n,line in enumerate(lines,1) if any(s in line for s in needles)]

class ELF32:
    def __init__(self,path):
        self.path=path;self.raw=path.read_bytes()
        h=struct.unpack_from('<16sHHIIIIIHHHHHH',self.raw)
        assert h[0][:7]==b'\x7fELF\x01\x01\x01' and h[2]==40
        self.kind=h[1];self.entry=h[4]
        self.sections=[]
        assert h[11]==40
        keys=['name_index','type','flags','address','file_offset','size','link','info','alignment','entry_size']
        for n in range(h[12]):
            self.sections.append(dict(zip(keys,struct.unpack_from('<10I',self.raw,h[6]+n*h[11])),index=n))
        strings=self.data(self.sections[h[13]])
        for s in self.sections:s['name']=self.string(strings,s['name_index'])
        table=next(s for s in self.sections if s['type']==2);assert table['entry_size']==16
        strings=self.data(self.sections[table['link']]);self.symbols=[]
        for offset in range(table['file_offset'],table['file_offset']+table['size'],16):
            n,value,size,info,other,index=struct.unpack_from('<IIIBBH',self.raw,offset)
            self.symbols.append({'name':self.string(strings,n),'value':value,'size':size,
                'binding':info>>4,'type':info&15,'visibility':other&3,'section_index':index})
    @staticmethod
    def string(raw,n):return raw[n:].split(b'\0',1)[0].decode('ascii')
    def data(self,section):
        assert section['type']!=8,'NOBITS has no input bytes'
        return self.raw[section['file_offset']:section['file_offset']+section['size']]
    def symbol(self,name):
        found=[s for s in self.symbols if s['name']==name];assert len(found)==1,(name,len(found));return found[0]
    def at(self,address,count):
        found=[s for s in self.sections if s['type']!=8 and s['address']<=address and address+count<=s['address']+s['size'] and s['flags']&2]
        assert len(found)==1,(hex(address),count)
        s=found[0];offset=s['file_offset']+address-s['address']
        return self.raw[offset:offset+count],offset,s['name']
    def relocations(self,names):
        result=[]
        for section in self.sections:
            if section['type']!=9:continue
            assert section['entry_size']==8
            target=self.sections[section['info']]
            for offset in range(section['file_offset'],section['file_offset']+section['size'],8):
                location,info=struct.unpack_from('<II',self.raw,offset);symbol=self.symbols[info>>8]
                if symbol['name'] not in names:continue
                typ=info&255;raw=self.data(target)[location:location+4];assert len(raw)==4
                row={'symbol':symbol['name'],'target_section':target['name'],'section_offset':hex(location),
                     'ELF_file_offset':hex(target['file_offset']+location),'type_number':typ,
                     'type':{2:'R_ARM_ABS32',28:'R_ARM_CALL',29:'R_ARM_JUMP24'}[typ],'bytes':raw.hex()}
                if typ in (28,29):
                    ins=next(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(raw,location,count=1));row['unrelocated_instruction']=ins.mnemonic+' '+ins.op_str
                    row['unrelocated_branch_is_not_final_target']=True
                else:row['literal_addend']=struct.unpack('<I',raw)[0]
                result.append(row)
        return result
    def instructions(self,addresses):
        rows=[];md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
        for address in addresses:
            raw,offset,section=self.at(address,4);i=next(md.disasm(raw,address,count=1))
            rows.append({'runtime_in_THIS_old_ELF':hex(address),'ELF_file_offset':hex(offset),'section':section,
                         'bytes':raw.hex(),'instruction':i.mnemonic+' '+i.op_str,'executed_by_this_review':False})
        return rows

def main():
    assert not REPORT.exists()
    v=json.loads(VERIFICATION.read_text());assert sha(VERIFICATION)=='1eba45812c7933ac04b9185f3761116e825187fe5256b7d4fbc7f436cb94ceaa'
    check(v['source_sha256']);check(v['artifacts_sha256']);check(v['failed_candidate_history']['artifacts_sha256'])
    protected=json.loads(AUDIT.read_text())['protected_sources'];assert len(protected)==781;check(protected)
    c=json.loads(CONT.read_text());p=json.loads(PLAYER.read_text());check(c['source_sha256']);check(p['source_sha256'])
    old_path=ROOT/c['extension_elf'];player_path=ROOT/p['extension_elf']
    assert sha(old_path)==c['extension_elf_sha256'] and sha(player_path)==p['extension_elf_sha256']
    new=ELF32(REL);old=ELF32(old_path);player=ELF32(player_path);assert new.kind==1 and old.kind==player.kind==2
    undefined={s['name'] for s in new.symbols if s['name'] and s['section_index']==0}
    assert undefined==set(v['ARM_artifact']['undefined_symbols']) and len(undefined)==12
    requirements={
        'coordinator_state':('native/music-continuous/media_coordinator.c',60,'struct umcn_coordinator_view'),
        'media_queue_control':('native/sbc-prototype/media_queue.c',36,'struct umcn_queue_view'),
        'media_worker_state':('native/sbc-prototype/media_worker.c',32,'struct umcn_worker_view'),
        'memory_output_control':('native/music-continuous/memory_output.c',48,'struct umcn_output_view'),
        'memory_output_slots':('native/music-continuous/memory_output.c',96,'four struct umcn_slot_view[24]'),
        'music_runtime_cancel':('native/music-continuous/runtime.c',16,'int(void); cancellation request only'),
        'music_runtime_state':('native/music-continuous/runtime.c',40,'struct umcn_runtime_view'),
        'native_app_component_entry':('native/sbc-prototype/app_component_entry.c',104,'int(void *loader); common original-TTS bootstrap and BSS clear'),
        'owned_media_control':('native/music-continuous/owned_media.c',52,'struct umcn_owned_view'),
        'source_worker_completed':('native/sbc-prototype/source_worker.c',88,'void(const volatile void *record); unchanged notification after original cleanup'),
        'source_worker_state':('native/sbc-prototype/source_worker.c',52,'struct umcn_source_view'),
    }
    refs=new.relocations(undefined);assert len(refs)==12
    rows=[]
    for name in sorted(undefined):
        refs_for=[r for r in refs if r['symbol']==name];assert len(refs_for)==1
        row={'required_symbol':name,'new_REL_relocations':refs_for,'final_binding_still_required':True}
        if name in requirements:
            source,size,abi=requirements[name];s=old.symbol(name)
            assert s['binding']==1 and s['size']==size
            assert s['type']==(2 if name in ('music_runtime_cancel','native_app_component_entry','source_worker_completed') else 1)
            row.update(source=source,source_sha256=sha(ROOT/source),declaration_lines=source_lines(ROOT/source,[name]),
                old_exact_ELF_symbol={**s,'address_hex':hex(s['value']),'section_name':old.sections[s['section_index']]['name']},
                adapter_ABI=abi,actual_old_symbol_size_verified=size,old_absolute_address_must_not_be_reused=True,
                binding='Exactly one same-image definition from the selected continuous variant/common bootstrap source; resolve by fresh ELF link, not --defsym to an old RAM address.')
        else:
            row.update(source_definition_exists=False,adapter_ABI='uint32_t(void), ARM1176 soft-float, actual same-owner static anchor address',
                binding='NEW wrapper compilation TU includes frozen memory_output.c and appends address-only accessor; compile wrapper INSTEAD of frozen memory_output.c, once.')
        rows.append(row)
    anchor=old.symbol('anchor_zero');assert anchor['binding']==0 and anchor['type']==1 and anchor['size']==2
    register=old.instructions([0x2f80108,0x2f801cc,0x2f801d4,0x2f801ec,0x2f801f4,0x2f801f8])
    literal,literal_offset,literal_section=old.at(0x2f80280,4);assert struct.unpack('<I',literal)[0]==anchor['value']
    bootstrap=old.instructions([0x2f7d044,0x2f7d048,0x2f7d060,0x2f7d080,0x2f7d090,0x2f7d094])
    common=old.symbol('native_app_component_entry')
    assert bootstrap[2]['instruction']=='bl #0x2d5a938'
    assert bootstrap[4]['instruction']=='str r1, [r3], #4'
    music_call=old.instructions([old.symbol('native_music_component_entry')['value']+4])
    player_entry=player.symbol('native_player_component_entry');player_common=player.symbol('native_app_component_entry')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);body,_,_=player.at(player_entry['value'],player_entry['size'])
    calls=[i.address for i in md.disasm(body,player_entry['value']) if i.mnemonic=='bl' and i.op_str=='#'+hex(player_common['value'])]
    assert len(calls)==1;player_call=player.instructions(calls)
    guard=new.symbol('native_ui_music_entry_phase');gs=new.sections[guard['section_index']]
    assert gs['name']=='.data.native_ui_music_entry_phase' and gs['type']==1 and guard['size']==4
    assert new.data(gs)[guard['value']:guard['value']+4]==bytes.fromhex('31534955')
    new_sections={s['name']:s for s in new.sections}
    assert all(name in new_sections for name in ['.ui_music_single_api','.ui_music_control_api',
        '.text.native_ui_music_menu_install','.text.native_ui_music_linked_bindings','.text.umcn_cleanup_bridge'])
    linker_path=ROOT/'staging/native-music-continuous/music_component.ld';linker=linker_path.read_text()
    assert '.data :' not in linker and '.ui_music_single_api' not in linker
    dependencies=dict(v['source_sha256'])
    for q in [Path(__file__).resolve(),VERIFICATION,REL,CONT,PLAYER,AUDIT,old_path,player_path,linker_path,
              ROOT/'native/sbc-prototype/memory_output.h',ROOT/'native/sbc-prototype/media_queue.h',ROOT/'native/sbc-prototype/media_worker.h',
              ROOT/'scripts/build_native_app_component.py',ROOT/'scripts/build_native_music_continuous.py',
              ROOT/'scripts/emulate_native_music_ready.py',ROOT/'native/sbc-prototype/source_event_hooks.S',
              ROOT/'staging/native-music-continuous/source_worker_imports.h',ROOT/'staging/native-music-continuous/playback_imports.h']:
        dependencies[rel(q)]=sha(q)
    recipe='''/* PROPOSED NEW TU ONLY; not created/compiled/executed by this review. */
#include "../../../native/music-continuous/memory_output.c"
_Static_assert(sizeof(anchor_zero) == 2, "actual original anchor size");
_Static_assert(sizeof(uintptr_t) == 4, "32-bit native address ABI");
uint32_t native_ui_music_owned_anchor_address(void)
{
    return (uint32_t)(uintptr_t)&anchor_zero;
}
'''
    report={
        'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','MAIN_sha256':v['exact_target']['MAIN_sha256']},
        'scope':'Read-only followup to frozen v2 REL; no new compilation or runtime. 12 relocations are linkage boundaries, not 12 independent native tests.',
        'source_sha256':dict(sorted(dependencies.items())),
        'frozen_v2_verification':{'path':rel(VERIFICATION),'sha256':sha(VERIFICATION),'source_dependencies_checked':len(v['source_sha256']),
            'artifacts_checked':len(v['artifacts_sha256']),'failed_history_artifacts_checked':len(v['failed_candidate_history']['artifacts_sha256'])},
        'protected_snapshot':{'path':rel(AUDIT),'sha256':sha(AUDIT),'count':781,'all_hashes_checked_before_and_after':True,'unchanged':True},
        'ELF_reader':'Pure little-endian ELF32 header/sections/symbols/SHT_REL decoding; no readelf/nm process, compiler or guest used by this analyzer.',
        'relocatable_artifact':{'path':rel(REL),'sha256':sha(REL),'type':'ET_REL','machine':'EM_ARM','entry_header':new.entry,
            'actual_undefined_count':12,'actual_undefined_relocation_count':len(refs),'final_loaded_addresses_or_loader_image':False},
        'symbol_boundaries':rows,
        'owned_anchor':{'original_source':'native/music-continuous/memory_output.c','source_sha256':sha(ROOT/'native/music-continuous/memory_output.c'),
            'declaration_and_usage':source_lines(ROOT/'native/music-continuous/memory_output.c',['static uint16_t anchor_zero','params[3]=','&anchor_zero']),
            'actual_old_ELF_symbol':{**anchor,'address_hex':hex(anchor['value']),'section':old.sections[anchor['section_index']]['name']},
            'static_local_not_externally_resolvable':True,'original_registration_opcodes':register,
            'original_literal':{'PC':'0x2f80280','ELF_file_offset':hex(literal_offset),'section':literal_section,'bytes':literal.hex(),'points_to_same_local_anchor':True},
            'parameter_provenance':'params begins SP+20 at2F801EC;2F801CC loads exact local anchor literal;2F801D4 stores SP+32=params[3];2F80108 guards READY value2 in callee-savedr9 and2F801F4 storesSP+36=params[4] byte count2;2F801F8 invokes270459. These are old compiled instruction bytes, not native execution here.',
            'proposed_NEW_same_TU_accessor_source':recipe,'proposal_created_as_C_file_or_compiled':False,
            'safe_scope':'Address-only accessor refers to original static object in its owning translation unit, has no store/read of payload, IRQ/allocator/stop/release call or new anchor. Internal linkage remains unchanged; full module lifetime and native channel ownership remain separate required contracts.',
            'exact_next_builder_change':'For the one memory-output source slot, compile NEW wrapper TU instead of native/music-continuous/memory_output.c; retain original -I native/sbc-prototype and generated-header includes. Never compile both original and wrapper or amalgamate other owner TUs.',
            'forbidden_substitutions':['extern anchor_zero','globalize old static symbol','-Dstatic=','reuse old absolute02F91124','create a different zero anchor','infer ownership from address or zero value'],
            'next_compile_validation':['Exactly one global definition of output control/slots/register/read/release; anchor stays STB_LOCAL/STT_OBJECT size2; one new STB_GLOBAL/STT_FUNC accessor.',
                'Fresh accessor relocation and original params[3] target the SAME local BSS object; original params[4] stays2; no extra native lifecycle call in accessor.',
                'New getter address, source/hash, codeRX/dataRW and full original TTS40/import/trampoline/after-header RAM guards belong to new artifacts; no old compiled-binary equality claimed.']},
        'bootstrap_opcodes':{'old_common_source':'native/sbc-prototype/app_component_entry.c','old_common_symbol':common,
            'zero_and_TTS_reset_instructions':bootstrap,'old_zero_start':hex(c['symbols']['__app_zero_start']['address']),
            'old_zero_end':hex(c['symbols']['__app_zero_end']['address']),
            'old_music_wrapper_common_call':music_call,'old_player_wrapper_common_call':player_call,
            'double_entry_effect':'Both old wrappers call common BSS/PCM/queue/stack clearing and original TTS bootstrap. Do not chain them or use their overlapping images.',
            'new_common_call_relocation':[r for r in refs if r['symbol']=='native_app_component_entry'],
            'new_guard':{'symbol':guard,'section':gs['name'],'bytes':'31534955','meaning':'UI_MUSIC_ENTRY_COLD initialized data; common zero span must exclude it; serialize loader and prohibit reload.'}},
        'actionable_NEW_image_recipe':[
            {'order':1,'action':'Select one original preserved TTS image and continuous sources. ENTRY(native_ui_music_single_entry); exactly one common source and one each runtime/source/decoder/output/coordinator/queue; skip both old component wrappers. No old module objects or complete images are stacked.'},
            {'order':2,'action':'Compile NEW owner wrapper including frozen memory_output.c plus pure getter, INSTEAD of its normal source slot. Keep source-worker/coordinator/runtime in separate TUs and retain --wrap=media_coordinator_init so full-return owner/result readiness remains observed.'},
            {'order':3,'action':'Use a fresh linker script with explicit kept new APIs and call-site roots. Old --gc-sections script omits new sections; ENTRY alone reaches only common bootstrap and may drop the controller/adapter.',
             'mandatory_KEEP_sections':['.ui_music_single_api','.ui_music_control_api','.text.native_ui_music_menu_install','.text.native_ui_music_linked_bindings','.text.umcn_cleanup_bridge'],
             'why_explicit_roots':'The frozen v2 single_api omits menu_install, linked_bindings and ASMbridge; retain via explicit KEEP or real new deferred callers, then verify all expected symbols survived.'},
            {'order':4,'action':'Give initialized once-guard its own file-backed RW.data before the common zero span. Preserve RX code separately. A directly reused old linker has no .data output and old loader fixture protects entire flat RX, so orphan placement or entry stores can fail.',
             'proposed_relative_budget_only':{'code_capacity':'0x20000','data_page':'base+0x20000','zero_BSS_start':'base+0x21000','BSS_limit':'base+0x26000',
                 'PCM0':'base+0x27000','PCM1':'base+0x28000','PCM2':'base+0x29000','PCM3':'base+0x2a000','gather':'base+0x2b000',
                 'queue_payload':'base+0x2c000..base+0x30000','decoder_stack':'base+0x31000..base+0x35000',
                 'source_stack':'base+0x35000..base+0x39000','end':'base+0x39000'},
             'fresh_link_and_native_memory_permission_validation_required':True,'remaining3MiB_budget_after_this_shift_only':c['remaining_reservation_bytes']-0x11000,
             'builder_changes':'Use __app_file_end including initialized.data for flat length/file header, not old __app_code_end. Track code/data RX/RW pages and data initial31534955; __app_zero_start/end word aligned and covers BSS/PCM/gather/queue/stacks only; original TTS header words0/4/8 and after-header preservation checked separately.'},
            {'order':5,'action':'Two-pass recalculate OWNED_CONSUME_RESUME, playback_pcm_pages, all named data/helper addresses and11-site music patches. Retain literal-pool shape and verify second-pass symbol equality; no old50a2/GUI addresses carried forward.'},
            {'order':6,'action':'Close all12 undefined symbols in fresh full link; assert every data size matches verified views and no Linux/dynamic or stray undefined symbol. Keep original TTS40 via original bootstrap, private exports/hooks independently declared and verified; ordinary link success does not wire runtime calls.'},
            {'order':7,'action':'Only after new image is reviewable run separately authorized native controls. Current followup performs no such compile/run/loader/UI/audio operation.'}],
        'concrete_native_runtime_blockers':[
            {'boundary':'single bootstrap','missing':'Fresh linked data outside zero-span and actual code/data permissions plus original-TTS40/no-repeat execution; old compile-only once-guard is not this native proof.'},
            {'boundary':'source8 ownership/session','missing':'Actual native reservation/epoch excluding independent writers and future borrowers; AV-locked coherent session preparation/resume. Missing callbacks remain mandatory, no success stub.'},
            {'boundary':'loop service','missing':'NEW source-worker copy must service0x80000 controller pending on same persistent TCB, observe full coordinator init and real cancel/pump returned marker. Frozen loop alone drops new control work into ordinary pump.'},
            {'boundary':'publication/cleanup','missing':'Publication token hook after actual registration before START; exactly one3B9DFC replacement umcn wrapper, full originalreturn references and iteration marker aftercancel_requested clear. Existing private source_completion_hook references and patch target require explicit new binding review so no legacy/doublecleanup entry bypass.'},
            {'boundary':'five admissions/media lease','missing':'Config/remoteSTART/event17/F1/consumer hooks and whole media leases currently not called by immutable stream; local STOP must remain disarmed while remote events continue.'},
            {'boundary':'GUI','missing':'Actual GUI/Dispatcher TCB and original queued launch/render/input ownership; known ID cannot be appended over old legacy player ID. New menu must be registered at a deferred GUI-owner boundary before that old entry is called.'},
            {'boundary':'radio/HFP','missing':'Three radio fixture helper calls are not a full physical stack boot; preserve existing stock Handsfree90005 and do not reset live SDP to only server-active. Channel8 boot/readiness andnew90007 publication require separate native fixture/physical validation.'},
            {'boundary':'source9','missing':'Route9 remains unsupported; owned nativeWAV node/provider and async36AF75 stop→quiescence→270537clear→388746callback→388676core-release returned witnesses absent. Getter solves channel8anchor linkage only.'},
            {'boundary':'package/App/directphone','missing':'NativeSIG requester/publickey/enforcement, physicalmodified-code acceptance andactualphone→nativeSEP/audio/output/menu still unknown. No signature/package candidate is generated by this review.'}],
        'limits':{'static_ELF_symbols_relocations_and_opcode_bytes_captured':True,'source_ORIGINAL_native_registers_or_branch_outcomes_captured':False,
            'compiled_build_or_host_tests_performed':False,'guest_emulator_or_device_service_IO':False,'sounds_emitted':False,
            'existing_sources_outputs_manifest_proof_report_canonical_modified':False,'full_ELF_or_App_installed':False,
            'accepted_modified_package_or_physical_App_or_direct_A2DP_verified':False,'goal_active':True,'AA_Maps':'deferred'}
    }
    check(protected);check(dependencies)
    with REPORT.open('x') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({'review':rel(REPORT),'sha256':sha(REPORT),'source_dependencies':len(dependencies),
        'actual_unresolved_symbols':12,'actual_relocations':len(refs),'protected_unchanged':781,'compiled_or_guest_run':False}))

if __name__=='__main__':main()
