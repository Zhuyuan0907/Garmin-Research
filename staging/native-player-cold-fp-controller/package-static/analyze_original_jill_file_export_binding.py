#!/usr/bin/env python3
"""Exclusive static append: original Jill exports -> MAIN callsites -> fopen.

No emulator, native execution, device/service I/O, modified package or keys.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import json
import struct
from datetime import datetime, timezone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
sys.path.insert(0,str(OUT))
from analyze_native_sig_request_contract_v2 import (NativeImage,RuntimeImage,ModuleImage,
    instruction,function,frozen_check,need,rel,write_new,sha,IMAGE_BASE,EXPECTED)


def main():
    report=OUT/'original-jill-file-export-binding.json'
    need(not report.exists(),'Keep exclusive static append immutable')
    audit=ROOT/'staging/native-player-cold-fp-controller/previous-audit.json'
    registry=json.loads(audit.read_text())['protected_sources'];need(len(registry)==707,'Expected707')
    frozen_check(registry)
    previous=OUT/'native-sig-request-contract-v2.json'
    record=json.loads(previous.read_text())
    jill=next(row for row in record['original_module_file_API']if 'Jill' in row['original_module'])
    path=ROOT/jill['original_module'];raw=path.read_bytes();need(sha(raw)==jill['sha256'],'Original Jill changed')
    module=ModuleImage(raw);stock=NativeImage();image=RuntimeImage(stock)
    exports_file=int(jill['import_ARM_stub_array_file_offset'],16)+99*12
    bias=int(jill['link_origin_file_bias'],16)
    original_exports=struct.unpack_from('<40I',raw,exports_file)
    host_storage=struct.unpack('<40I',image.read(0xf092c4,160))
    slots=[]
    for slot,expected_link,expected_entry,expected_storage in [
            (15,0x191,0x1bdd0,0xf09560),(23,0x391,0x1bfd0,0xf09548)]:
        need(original_exports[slot]==expected_link and bias+(expected_link&~1)==expected_entry,
             'Original Jill export binding differs')
        need(host_storage[slot]==expected_storage and image.word(expected_storage)==0,
             'Original MAIN export storage differs')
        stub=0x2d4b994+slot*12
        slots.append(dict(slot=slot,original_export_word_offset=hex(exports_file+slot*4),
            original_export_word_hex=hex(expected_link),original_export_word_bytes=raw[exports_file+slot*4:exports_file+slot*4+4].hex(),
            file_link_bias=hex(bias),Thumb_callee_file_offset=hex(expected_entry),
            candidate_loaded_Thumb_target=hex(IMAGE_BASE+expected_entry+1),
            MAIN_import_storage_table_word_runtime=hex(0xf092c4+slot*4),
            MAIN_import_storage_table_word_load=hex(stock.runtime_to_load(0xf092c4+slot*4,4)),
            MAIN_pointer_storage=hex(expected_storage),original_initialized_storage_value=0,
            constructed_MAIN_ARM_trampoline=hex(stub),trampoline_target_word=hex(stub+8),
            actual_current_storage_or_registration_not_observed=True))
    expected={
        0x3b3284:'ldr r7, [r1, r7]',0x3b328a:'str r3, [r7]',
        0x2356f0:'ldr r3, [r1, #0xc]',0x2356f4:'ldr r5, [r3, r5]',
        0x2356fa:'ldr r6, [r4, #0x20]',0x2356fe:'adds r3, #8',0x235700:'str r5, [r6, r3]',
        0x21c50a:'ldr r2, [pc, #0x18c]',0x21c50e:'ldr r2, [r2]',
        0x21c510:'add r0, sp, #0xc',0x21c512:'blx r2',
        0x21c290:'ldr r3, [pc, #0x3d8]',0x21c294:'ldr r5, [r3]',0x21c29a:'blx r5',
        0x21c2fc:'ldr r3, [pc, #0x36c]',0x21c300:'ldr r5, [r3]',0x21c306:'blx r5',
        0x21c56a:'ldr r3, [pc, #0x100]',0x21c56e:'ldr r6, [r3]',0x21c576:'blx r6',
        0x21c5a0:'ldr r3, [pc, #0xc8]',0x21c5a6:'ldr r5, [r3]',0x21c5ac:'blx r5'}
    exact=[]
    for pc,wanted in expected.items():
        ins,row=instruction(image,pc);need(row['instruction']==wanted,'Exact MAIN opcode differs '+hex(pc))
        row['load_address']=hex(stock.runtime_to_load(pc,ins.size));exact.append(row)
    callsites=[]
    for slot,load,pc,reg in [(15,0x21c50a,0x21c512,'r2'),(23,0x21c290,0x21c29a,'r5'),
                            (23,0x21c2fc,0x21c306,'r5'),(23,0x21c56a,0x21c576,'r6'),
                            (23,0x21c5a0,0x21c5ac,'r5')]:
        ins,_=instruction(image,load);literal=((load+4)&~3)+ins.operands[1].mem.disp
        storage=host_storage[slot];need(image.word(literal)==storage,'Native callsite storage literal differs')
        rows=[]
        for op in image.md.disasm(image.read(load-8,pc-load+18),load-8):
            rows.append(dict(address=hex(op.address),bytes=op.bytes.hex(),instruction=op.mnemonic+' '+op.op_str))
        callsites.append(dict(slot=slot,MAIN_function_pointer_load=hex(load),pointer_storage_literal=hex(literal),
            pointer_storage_value=hex(storage),call_PC=hex(pc),call_instruction='blx '+reg,
            expected_module_entry_LR_if_this_original_binding_is_live=hex(pc+3),
            exact_bounded_window=rows,actual_native_call_or_branch_outcome_observed=False))
    literal_reads=[]
    for call,adr,countpc,copypc,openpc,modepc,expected_name in [
            (0x1be0e,0x1be04,0x1bdfe,0x1be06,0x1be0e,0x1be0a,b'brkinf16.hdr\0'),
            (0x1be24,0x1be1a,0x1be16,0x1be1c,0x1be24,0x1be20,b'brkinf22.hdr\0')]:
        name_ins,name_row=instruction(module,adr)
        name_address=((adr+4)&~3)+name_ins.operands[1].imm
        need(module.read(name_address,13)==expected_name,'Original fixed filename bytes differ')
        need(instruction(module,countpc)[1]['instruction']=='movs r2, #0xd','Original filename copy count differs')
        need(instruction(module,copypc)[1]['instruction']=='bl #0x12875c','Original byte-copy target differs')
        mode_ins,mode_row=instruction(module,modepc);mode_address=((modepc+4)&~3)+mode_ins.operands[1].imm
        need(module.read(mode_address,3)==b'rb\0','Original fixed file mode differs')
        literal_reads.append(dict(caller_file_offset=hex(call),filename_ADR=name_row,
            filename_file_offset=hex(name_address),original_filename_bytes_hex=expected_name.hex(),
            filename=expected_name[:-1].decode(),copy_count_instruction=instruction(module,countpc)[1],
            copy_call_instruction=instruction(module,copypc)[1],mode_ADR=mode_row,mode_file_offset=hex(mode_address),
            module_fopen_forwarder_call=instruction(module,openpc)[1],
            expected_saved_fopen_caller_LR=hex(IMAGE_BASE+call+5),
            actual_buffer_bytes_or_resource_open_not_observed=True))
    arm=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    copy_rows=[dict(address=hex(op.address),bytes=op.bytes.hex(),instruction=op.mnemonic+' '+op.op_str)
               for op in arm.disasm(module.read(0x128760,0x70),0x128760)]
    need(any(row['instruction']=='ldmhs r1!, {r3, r4, ip, lr}'for row in copy_rows)and
         any(row['instruction']=='stmhs r0!, {r3, r4, ip, lr}'for row in copy_rows),
         'Original memcpy-shaped source/destination word transfers differ')
    sources=[Path(__file__),OUT/'analyze_native_sig_request_contract_v2.py',previous,path,audit,
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT/'scripts/analyze_sdp_activation.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        source_sha256={rel(p):sha(p.read_bytes())for p in sorted(set(sources))},
        protected_registry=dict(path=rel(audit),sha256=sha(audit.read_bytes()),count=len(registry),changed_or_missing=[]),
        append_to=dict(path=rel(previous),sha256=sha(previous.read_bytes()),prior_record_unmodified=True),
        original_Jill_export_array_file_offset=hex(exports_file),exact_export_slot_bindings=slots,
        registration_functions={hex(e):function(image,e)for e in [0x3b3268,0x2356bc]},
        exact_MAIN_instruction_assertions=exact,native_function_pointer_callsites=callsites,
        original_Jill_fixed_resource_filename_reads=literal_reads,
        original_13_byte_copy_Thumb_interwork=instruction(module,0x12875c)[1],
        original_copy_ARM_source_opcodes=copy_rows,
        static_join='3B3268 writes generated12byte trampoline to F09560(slot15)/F09548(slot23);2356BC writes originalrelocatedexport pointer to eachtrampoline+8. MAIN21C512 loads F09560 and BLXr2;four listedslot23callssimilarlyloadF09548. WithoriginalJillbindinglive these reach1BDD0/1BFD0 andtheidentifiedresourcefopen chain.',
        original_SIG_requester_proven=False,native_DSAVerifier_or_public_key_join=False,
        possible_next_observation='Observe originalMAIN21C512 andmatchingJillmodule0x1BDD0 entry usingactualF09560/trampoline+8/exportbinding; preserveMAINentryLR21C515,thenstock13byte filenamecopy andfopenframe. This supplies originalresource I/O provenance, not DLLIMG.SIG acceptance. Do not callslot15 or23 with guessedarguments orassume noaudio sideeffects.',
        limits=dict(static_only=True,native_current_binding_observed=False,device_or_emulator_IO=False,
            audio_or_UI_logic_changed=False,modifiedpackage_or_signature_or_key_created=False,
            no_direct_Thumb_parent_is_not_unreachable=True,global_callgraph_or_SIG_policy_not_closed=True))
    frozen_check(registry);write_new(report,result)
    print(json.dumps(dict(report=rel(report),sha256=sha(report.read_bytes()),protected=len(registry),
        source_dependencies=len(result['source_sha256']),MAIN_assertions=len(exact),native_callsite_provenance_count=len(callsites),
        native_SIG_requester=False)))


if __name__=='__main__':main()
