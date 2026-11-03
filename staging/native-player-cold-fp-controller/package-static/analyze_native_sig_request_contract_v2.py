#!/usr/bin/env python3
"""Read-only exact original DLL file-API provenance, not native execution.

Writes only exclusive sibling JSON records. No emulator imports, package
mutation, signatures/keys, device or service I/O, or canonical updates.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage
from analyze_sdp_activation import trace

REPORT = OUT/'native-sig-request-contract-v2.json'
CFG = OUT/'original-module-file-api-functions-v2.json'
AUDIT = ROOT/'staging/native-player-cold-fp-controller/previous-audit.json'
PREVIOUS = ROOT/'staging/native-player-cache-declared-followup/package-static/vpm-sig-format-and-gate-preflight.json'
INVENTORY = ROOT/'evidence/firmware-analysis/tts-vpm-containers.json'
IMAGE_BASE = 0x2d4bb74


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def need(condition, message):
    if not condition:
        raise ValueError(message)


def write_new(path, value):
    with path.open('x') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def frozen_check(registry):
    for name, digest in registry.items():
        need(sha((ROOT/name).read_bytes()) == digest, 'Changed frozen source '+name)


class ModuleImage:
    def __init__(self, raw):
        self.raw = raw
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.md.detail = True

    def read(self, address, count):
        need(0 <= address and address+count <= len(self.raw), 'Module read outside original file')
        return self.raw[address:address+count]

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]


def instruction(image, address, mode=None):
    md = image.md if mode is None else Cs(CS_ARCH_ARM, mode)
    md.detail = True
    value = next(md.disasm(image.read(address, 4), address, count=1), None)
    need(value is not None, 'Undecodable exact instruction '+hex(address))
    row = dict(address=hex(address), bytes=value.bytes.hex(),
               instruction=value.mnemonic+' '+value.op_str)
    return value, row


def function(image, entry, module=False):
    result = trace(image, entry, 2000)
    need(not result['instruction_limit_reached'], 'Bounded function instruction limit '+hex(entry))
    for row in result['instructions']:
        a = int(row['address'], 16)
        ins, exact = instruction(image, a)
        row['bytes'] = exact['bytes']
        if module:
            row['original_module_file_offset'] = hex(a)
            row['candidate_loaded_runtime_PC'] = hex(IMAGE_BASE+a)
    result['bounded_not_transitive_or_indirect_call_closure'] = True
    return result


def thumb_direct_calls(image, targets):
    result = []
    raw = image.raw
    for address in range(0, len(raw)-3, 2):
        a, b = struct.unpack_from('<2H', raw, address)
        if a & 0xf800 != 0xf000 or b & 0xf800 != 0xf800:
            continue
        offset = ((a & 0x7ff) << 12) | ((b & 0x7ff) << 1)
        if offset & 0x400000:
            offset -= 0x800000
        target = address+4+offset
        if target not in targets:
            continue
        ins, row = instruction(image, address)
        need(ins.mnemonic == 'bl' and ins.operands[0].imm == target,
             'Exact Thumb BL decoder disagreement')
        result.append(dict(**row, target=hex(target)))
    return result


def recognized_file_veneers(image, stub_base):
    targets = {stub_base+i*12:i for i in range(54, 60)}
    rows = []
    for match in re.finditer(re.escape(bytes.fromhex('7847c046')), image.raw):
        entry = match.start()
        if entry % 4 or entry+8 > len(image.raw):
            continue
        word = image.word(entry+4)
        if word & 0xff000000 != 0xea000000:
            continue
        delta = (word & 0xffffff) << 2
        if delta & 0x2000000:
            delta -= 0x4000000
        target = entry+12+delta
        if target not in targets:
            continue
        need(instruction(image, entry)[0].mnemonic == 'bx' and
             instruction(image, entry)[0].op_str == 'pc', 'Interwork BX PC differs')
        branch, exact = instruction(image, entry+4, CS_MODE_ARM)
        need(branch.mnemonic == 'b' and branch.operands[0].imm == target,
             'Interwork ARM branch differs')
        rows.append(dict(host_slot=targets[target], Thumb_entry_file_offset=hex(entry),
                         bytes=image.read(entry, 8).hex(), ARM_branch=exact,
                         target_ARM_stub_file_offset=hex(target),
                         recognized_exact_interwork_shape_only=True))
    need(len(rows) == 6 and {r['host_slot'] for r in rows} == set(range(54, 60)),
         'Expected one exact file interwork veneer per original host54..59')
    return sorted(rows, key=lambda row:row['host_slot'])


def prologue_candidate(image, call):
    candidates = []
    for address in range(max(0, call-0x1000), call, 2):
        ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
        if ins and ins.mnemonic == 'push' and 'lr' in ins.op_str:
            candidates.append(address)
    need(candidates, 'No bounded PUSH/LR prologue candidate')
    return candidates[-1]


def extend_exact_byte_switch(image, fn):
    # Preserve opaque computed exits. Only the identified six-byte file-state
    # table is decoded after verifying ADR/load/shift/ADD and CMP/BHS guard.
    switches = []
    for exit in fn['unresolved_exits']:
        if exit['reason'] != 'Computed PC; needs switch analysis':
            continue
        pc = int(exit['address'], 16)
        shape = [instruction(image, pc-6)[0], instruction(image, pc-4)[0],
                 instruction(image, pc-2)[0], instruction(image, pc)[0]]
        if [(i.mnemonic, i.op_str) for i in shape] != [
                ('adr', 'r3, #4'), ('ldrb', 'r3, [r3, r0]'),
                ('lsls', 'r3, r3, #1'), ('add', 'pc, r3')]:
            continue
        guard = [instruction(image, pc-10)[0], instruction(image, pc-8)[0]]
        need(guard[0].mnemonic == 'cmp' and guard[0].op_str == 'r0, #6' and
             guard[1].mnemonic == 'bhs', 'File-state computed table guard differs')
        table = ((pc-6+4) & ~3)+4
        need(table == pc+2, 'File-state literal table offset differs')
        values = image.read(table, 6)
        rows = []
        for state, value in enumerate(values):
            target = pc+4+2*value
            rows.append(dict(state=state, byte=value, target_file_offset=hex(target)))
        cases = {hex(int(r['target_file_offset'], 16)):function(image, int(r['target_file_offset'], 16), True)
                 for r in rows}
        switches.append(dict(computed_PC_file_offset=hex(pc), instruction_bytes=image.read(pc-10, 12).hex(),
                             table_file_offset=hex(table), original_six_bytes_hex=values.hex(),
                             PC_operand_base=hex(pc+4), cases=rows, case_functions=cases,
                             native_state_values_or_branch_outcomes_observed=False))
    return switches


def module_record(container, host):
    metadata = container['module']
    path = ROOT/metadata['extracted_binary']
    raw = path.read_bytes()
    need(sha(raw) == container['files']['DLLIMG.BIN']['sha256'], 'Original module extract differs')
    image = ModuleImage(raw)
    bias = metadata['first_branch_offset']
    entry = metadata['thumb_entry_offset'] & ~1
    need(entry == bias+8, 'Original entry/file link-origin relationship differs')
    entry_fn = function(image, entry, True)
    direct = [int(row['direct_call'], 16) for row in entry_fn['instructions'] if 'direct_call' in row]
    need(len(direct) == 4, 'Expected four direct entry calls, not a transitive closure')
    relocator, runtime_initializer, builder, callback_veneer = direct
    first_adr = instruction(image, relocator)[0]
    second_ldr = instruction(image, relocator+2)[0]
    need(first_adr.mnemonic == 'adr' and first_adr.op_str.startswith('r0, ') and
         second_ldr.mnemonic == 'ldr' and second_ldr.op_str.startswith('r1, [pc, '),
         'Original relocator link-origin operands differ')
    adr_file = ((relocator+4)&~3)+first_adr.operands[1].imm
    literal_file = ((relocator+6)&~3)+second_ldr.operands[1].mem.disp
    link_adr = image.word(literal_file)
    need(adr_file-link_adr == bias, 'Original module file/link bias differs')
    builder_fn = function(image, builder, True)
    registers, descriptor_fields = {}, {}
    for row in builder_fn['instructions']:
        ins, exact = instruction(image, int(row['address'],16))
        if ins.mnemonic == 'ldr' and len(ins.operands)==2 and ins.operands[1].type==ARM_OP_MEM and ins.operands[1].mem.base==ARM_REG_PC:
            literal = ((ins.address+4)&~3)+ins.operands[1].mem.disp
            registers[ins.reg_name(ins.operands[0].reg)] = dict(literal_file_offset=hex(literal),
                literal_link_address=hex(image.word(literal)), literal_instruction=exact)
        if ins.mnemonic=='str' and ins.operands[1].type==ARM_OP_MEM and ins.reg_name(ins.operands[1].mem.base)=='r1':
            source=ins.reg_name(ins.operands[0].reg)
            if source in registers and ins.operands[1].mem.disp in (12,16):
                descriptor_fields[ins.operands[1].mem.disp] = dict(**registers[source], store_instruction=exact)
    need(set(descriptor_fields)=={12,16}, 'Export/import local descriptor fields unresolved')
    stub_base = int(descriptor_fields[16]['literal_link_address'],16)+bias
    export_base = int(descriptor_fields[12]['literal_link_address'],16)+bias
    need(export_base == stub_base+99*12, 'Original 99 imports/export-array adjacency differs')
    stub_rows = []
    for slot in range(99):
        file = stub_base+slot*12
        need(image.read(file,8)==bytes.fromhex('00c09fe51cff2fe1') and image.word(file+8)==0,
             'Original empty ARM import stub differs')
        if slot in range(54,60):
            stub_rows.append(dict(slot=slot,file_offset=hex(file),candidate_loaded_runtime=hex(IMAGE_BASE+file),
                                 original_bytes=image.read(file,12).hex(),target_word_file_offset=hex(file+8),
                                 initialized_MAIN_host_target=hex(host[slot])))
    veneers = recognized_file_veneers(image, stub_base)
    veneer_calls = thumb_direct_calls(image,{int(row['Thumb_entry_file_offset'],16) for row in veneers})
    fopen_veneer = next(int(row['Thumb_entry_file_offset'],16) for row in veneers if row['host_slot']==55)
    fopen_calls = [row for row in veneer_calls if int(row['target'],16)==fopen_veneer]
    need(len(fopen_calls)==1, 'Original file-open veneer has unexpected direct Thumb BL candidates')
    fopen_call = int(fopen_calls[0]['address'],16)
    fopen_forwarder = fopen_call-2
    forwarder_fn = function(image,fopen_forwarder,True)
    need([row['instruction'] for row in forwarder_fn['instructions']]==[
        'push {r3, lr}', 'bl #'+hex(fopen_veneer), 'add sp, #4', 'pop {r3}', 'bx r3'],
        'Original fopen forwarder frame/parameter preservation differs')
    native_lr = IMAGE_BASE+fopen_call+5
    upper = thumb_direct_calls(image,{fopen_forwarder})
    expected_open_callers = 4 if 'Jill' in container['file'] else 2
    need(len(upper)==expected_open_callers, 'Exact original fopen-forwarder caller profile differs')
    functions = {hex(entry):entry_fn,hex(builder):builder_fn,
                 hex(relocator):function(image,relocator,True),
                 hex(runtime_initializer):function(image,runtime_initializer,True),
                 hex(fopen_forwarder):forwarder_fn}
    callers=[]
    for row in upper:
        pc=int(row['address'],16);head=prologue_candidate(image,pc)
        fn=function(image,head,True);switches=extend_exact_byte_switch(image,fn)
        reached=any(int(i['address'],16)==pc for i in fn['instructions']) or any(
            any(int(i['address'],16)==pc for i in case['instructions'])
            for switch in switches for case in switch['case_functions'].values())
        need(reached,'Candidate open caller not in bounded original CFG/six-byte cases')
        functions[hex(head)]=fn
        parent_calls=thumb_direct_calls(image,{head})
        parent_rows=[]
        for parent in parent_calls:
            parent_pc=int(parent['address'],16);parent_head=prologue_candidate(image,parent_pc)
            pfn=function(image,parent_head,True)
            parent_reached=any(int(i['address'],16)==parent_pc for i in pfn['instructions'])
            functions[hex(parent_head)]=pfn
            parent_rows.append(dict(**parent, prologue_file_offset=hex(parent_head),
                                    bounded_CFG_contains_call=parent_reached,
                                    unresolved_or_data_false_positive_not_excluded=not parent_reached,
                                    actual_runtime_execution_or_filename_not_observed=True))
        callers.append(dict(**row,prologue_file_offset=hex(head), original_CFG_contains_call=True,
                            exact_computed_switches=switches, parent_direct_Thumb_BL_candidates=parent_rows,
                            caller_saved_LR_at_native_fopen_entry_SP_plus=4,
                            expected_saved_caller_LR=hex(IMAGE_BASE+pc+5),
                            concrete_SIG_filename_or_key_proven=False))
    return dict(original_module=rel(path), sha256=sha(raw), bytes=len(raw),
        bootstrap_file_offset=hex(entry),link_origin_file_bias=hex(bias),
        link_origin_evidence=dict(relocator_file_offset=hex(relocator), ADR_PC_file_address=hex(adr_file),
            literal_file_offset=hex(literal_file),literal_link_address=hex(link_adr),
            exact_delta_file_bias=hex(adr_file-link_adr),relocation_runtime_address_not_native_observed=True),
        local_descriptor_fields=descriptor_fields, import_ARM_stub_array_file_offset=hex(stub_base),
        original_import_stubs=99,file_slots=stub_rows,file_interwork_veneers=veneers,
        direct_file_veneer_Thumb_BL_candidates=veneer_calls,
        fopen_forwarder_file_offset=hex(fopen_forwarder),fopen_forwarder_native_entry_LR=hex(native_lr),
        fopen_forwarder_actual_host_target_requires_live_slot55_check=True,
        fopen_forwarder_callers=callers,bootstrap_direct_calls=[hex(v) for v in direct],
        bootstrap_before_import_initializers_transitive_closure=False,
        bootstrap_body_file_open_forwarder_called=False,
        body_no_direct_open_is_not_global_SIG_absence=True,
        indirect_ARM_or_computed_callers_not_excluded=True),functions


def main():
    need(not REPORT.exists() and not CFG.exists(),'Keep exclusive artifacts immutable')
    registry=json.loads(AUDIT.read_text())['protected_sources']
    need(len(registry)==707,'Expected current 707-file protected registry')
    frozen_check(registry)
    stock=NativeImage();main_image=RuntimeImage(stock)
    host=list(struct.unpack('<99I',main_image.read(0xf09364,396)))
    need(host[55]==0x1fb305 and host[56]==0x1fb3a3,'Original initialized fopen/fread host slots differ')
    main_entries=[0x23c3c4,0x3b3294,0x3b331a,0x2356bc,0x1fb304,0x1fb3a2,0x2fba70,0x2fb988]
    main_functions={hex(entry):function(main_image,entry) for entry in main_entries}
    exact={0x23c3f8:'ldr r1, [pc, #0xe4]',0x23c3fa:'str r1, [r7, #0x24]',
        0x23c3fc:'movs r1, #0x63',0x23c3fe:'str r1, [r7, #0x28]',
        0x23c422:'bl #0x3b3294',0x23c42e:'bl #0x3b331a',
        0x1fb32a:'ldrb r0, [r0, #8]',0x1fb32c:'bl #0xfe648',
        0x1fb336:'adr r2, #0xbc',0x1fb378:'ldr r2, [pc, #0xac]',
        0x1fb37e:'bl #0x2fba70',0x1fb388:'ldrb r0, [r0, #0xb]',
        0x1fb38a:'lsls r0, r0, #0x19',0x1fb38c:'bmi #0x1fb390',
        0x1fb39c:'ldr r0, [sp, #8]'}
    assertions=[]
    for pc,wanted in exact.items():
        ins,row=instruction(main_image,pc)
        need(row['instruction']==wanted,'Exact MAIN assertion changed '+hex(pc))
        row['load_address']=hex(stock.runtime_to_load(pc,ins.size));assertions.append(row)
    inventory=json.loads(INVENTORY.read_text())
    modules,all_functions=[],{}
    for container in inventory['containers']:
        if not container.get('native_module_container'):
            continue
        record,functions=module_record(container,host)
        modules.append(record);all_functions[record['original_module']]=functions
    need(len(modules)==3,'Expected three original TTS DLLs')
    write_new(CFG,dict(exact_MAIN_sha256=EXPECTED, MAIN_functions=main_functions,
                       original_module_functions=all_functions,
                       limits='Static bounded bodies; unknown/indirect/transitive paths remain unknown. No native execution.'))
    deps=[Path(__file__),OUT/'failed-uniform-analyzer.json',OUT/'failed-uniform-analyzer.stderr.txt',
          OUT/'analyze_native_sig_request_contract_failed_uniform.py',
          OUT/'analyze_native_sig_request_contract.py',OUT/'native-sig-request-contract.json',
          AUDIT,PREVIOUS,INVENTORY,CFG,
          ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_vpm_acceptance_path.py',
          ROOT/'scripts/analyze_sdp_activation.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    deps.extend(ROOT/row['original_module'] for row in modules)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        exact_target=dict(HWID=1352,software='8.00',model='Taiwan nuvi2565RT',MAIN_sha256=EXPECTED),
        source_sha256={rel(p):sha(p.read_bytes())for p in sorted(set(deps))},
        protected_registry=dict(path=rel(AUDIT),sha256=sha(AUDIT.read_bytes()),count=len(registry),changed_or_missing=[]),
        reused_SIG_format_artifact=dict(path=rel(PREVIOUS),sha256=sha(PREVIOUS.read_bytes()),
            format_parser_not_rerun=True,DSA_SHA1_format_declared_known=True,full_DSA_or_native_enforcement_unknown=True),
        earlier_failed_profile=json.loads((OUT/'failed-uniform-analyzer.json').read_text()),
        corrected_per_original_module_direct_fopen_caller_profile={'Chinese_Big5_MeiLing':2,'Chinese_GB_MeiLing':2,'English_American_Jill':4},
        exact_MAIN_assertions=assertions,original_module_file_API=modules,
        captured_facts_in_this_run=dict(original_file_bytes_and_SHA256=True,static_original_opcode_decode=True,
            native_request_filename_or_handle_or_branch_outcome=False,native_execution=False),
        static_MAIN_to_original_module_file_binding=dict(
            caller='23C3C4 sets descriptor+36=F09364 and+40=99 at23C3F8..23C3FE; descriptor+44=2356BD.',
            bootstrap='Original DLL body copies table[i] into its ARM import stub[i]+8 with12-byte stride. File55 is initially1FB305; table is runtime mutable and must be checked before attributing live I/O.',
            reader_callbacks='23C3C6..23C3E2 constructs stack close/open/read/seek/tell pointers1FB2F9/1FB305/1FB3A3/1FB3CF/1FB3E5, then23C422 calls3B3294; this callback block reads the descriptor name dllimg.bin.',
            generic_open='Original module host55 tail-calls1FB304 through preserved LR and one8-byte Thumb frame. Native1FB304 derives active voice drive fromF09658+8→FE648, prefixes%i:, then2FBA70/2FB988 resolve named ordinary member.',
            mode_argument='The identified module forwarders pass filename/mode according to fopen-shapedABI, but1FB304 does not preserve/use incomingr1 beforeclobberingit; actual access admission is the nativefileobject+11 bit0x40 gate. Do not infer mode r/rb selects separate signature policy.',
            return_gate='1FB382 checks handle nonzero;1FB388..38C requires fileobject+11 bit0x40 or clears handle at1FB38E;1FB39C returns surviving handle. Actual filename/mode/drive/handle/state not observed here.',
            no_SIG_requester_or_cryptographic_verifier_join=True),
        Big5_bounded_filename_parameter_contract=[
            dict(call='module file0x1DD0C→0xF318',caller_entry='0x1DC3C',
                 filename='Entryr2 saved atSP+12 after36-byte PUSH+4-byte SUB, copied via1DC7C/1DC88/1DC94 into r6;rb at1DD08;fopen handle stored owner+12 at1DD10.',
                 upstream='1C464→1C5B0 calls19FCC withr2=SP+16 output;1C5DA loads thatfilename into r2 before1C5DE→1DC3C. Actual string/source identity remains unknown.'),
            dict(call='module file0x23E46→0xF318',caller_entry='0x23E3C',
                 filename='Entryr1→r0 at23E3E; entryr2→mode r1 at23E40; entryr3→out pointerr5 at23E42. Handle stored[r5] at23E4A; successstatus0, NULLstatus80606003.',
                 upstream='2240E uses entryr1 savedSP+8 at2246C andrb at2246A before2246E;3420C uses entryr2 record+0 at34238 andrb at3423E before34242. No SIG name established.')],
        Jill_distinct_bounded_filename_parameter_contract=[
            dict(calls=['0x1BE0E','0x1BE24'],caller_entry='0x1BDD0',
                 filename='1BE04 ADR→1C1C4 brkinf16.hdr;1BE06 copies13bytes through12875C intor5 then1BE0E fopen. NULL leads1BE1A ADR→1C1D8 brkinf22.hdr andsecond13bytecopy1BE1C then1BE24 fopen. Bothmode rb at1C1D4.',
                 known_SIG_request=False,native_branch_outcome_observed=False),
            dict(call='0x1C278',caller_entry='0x1BFD0',
                 filename='1C276 loads externalfilename fromSP+24;mode r at1C3D0 from1C274;actual sourcefilename unknown.',known_SIG_request=False),
            dict(call='0x55E74',caller_entry='0x55E6C',
                 filename='Entryr2→r0 andentryr3→r1 at55E6E/70;fifthargumentout-handlepointer fromSP+8 afterpushr4/LR at55E72;55E7A storesresult.',known_SIG_request=False)
        ],
        minimal_pure_observation_contract=dict(
            readiness='Only a future original execution observation contract; no native/device test performed or authorized here.',
            before_actual_fopen=[
                'Check original loaded DLL hash/base, descriptor+36 currenttable andcount; capture module slot55 targetword matching1FB305 rather than assuming initialized MAIN data remains live.',
                'At actual1FB304 entry capturer0 boundedNUL filename,r1 mode argument,entryLR,SP andsavedcallerLR atSP+4 only when the exact5-opcode fopen-forwarder frame andveneer provenance match the original module.',
                'CaptureF09658+8,FE648 return andthe resulting native%i:filename; at2FB988/123F6C capture the actual8+3 key,memberdirectoryentry/ordinarytype,length andactivevolume provenance. A synthetic explicitSIGopen cannot identify thiscaller.'
            ],
            request_must_be_original_program_generated=True,
            read_completion=[
                'Join a real original request resolvingDLLIMG  SIG to the returned memberhandle; only then attribute actual1FB3A2 reads, requested count,returned count andoriginal72byteSHA256 to it.',
                'Keep failed/shortreads andNULL open outcomes; count/left16 formatmatch cannot substitute for nativeverification.',
                'Follow that proven caller/read consumer to OpenPGP parsing,key source,DSAverification return andits accepting/rejecting branch. Preserve indirect target,entryLR/callsite andstatus provenance.'
            ],
            excluded='No injectedSIGrequest, callback replacement,seededfilename/handle,key/signature manufacture, arbitraryDLLbyte modification, or changedpackage installation.'),
        unresolved=[
            'No actual original DLLIMG.SIG request was captured; all discovered module fopen callers are generic filename parameter chains.',
            'Initializer callees beforeimportbinding andall later40exports are not a transitive/indirect closed callgraph. Finding no directfopen in the bootstrap body does not prove no nativeSIG policy.',
            'No publickey acquisition or nativeDSA verifier is joined to a voice memberread. External/transformed key storage andboot/update/earliermount policy remain possible.',
            'Original fileAPI stubs are static source addresses andruntime candidate PCs, not currently executed physical calls. Real modifiedVPM/DLL/App acceptance remains unverified.'
        ],
        limits=dict(static_only=True,emulator_imported=False,native_code_executed=False,device_or_service_IO=False,
                    modified_package_or_signature_or_key_written=False,frozen_sources_modified=False,canonical_updated=False))
    frozen_check(registry)
    write_new(REPORT,result)
    print(json.dumps(dict(report=rel(REPORT),sha256=sha(REPORT.read_bytes()),protected=len(registry),
        modules=len(modules),MAIN_assertions=len(assertions),dependencies=len(result['source_sha256']),
        native_SIG_requester_identified=False,native_enforcement=False),ensure_ascii=False))


if __name__=='__main__':
    main()
