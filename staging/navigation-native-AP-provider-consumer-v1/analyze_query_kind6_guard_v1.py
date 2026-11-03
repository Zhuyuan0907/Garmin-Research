#!/usr/bin/env python3
"""New bounded static caller chain + original kind6 gate fragment.

No full UI query, filesystem, map discovery or old comparator replay. The
argument registers/object/context for the fragment are synthetic; original
conditions are executed without result/policy hooks.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *


def main():
    image=NativeImage();cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    def rd(address,length):
        try:address=image.runtime_to_load(address,length)
        except ValueError:pass
        return image.read(address,length)
    def window(start,end):
        raw=rd(start,end-start)
        return dict(start=hex(start),end_exclusive=hex(end),bytes_sha256=hashlib.sha256(raw).hexdigest(),
            instructions=[dict(pc=hex(x.address),bytes=x.bytes.hex(),op=x.mnemonic+' '+x.op_str)
                          for x in cs.disasm(raw,start)])
    veneers=[]
    for address,target in [(0x448ED78,0x1F18CD),(0x448DDD0,0x17DB9F),(0x448F2E0,0x32C6B1)]:
        raw=rd(address,8)
        if raw[:4]!=bytes.fromhex('04f01fe5') or struct.unpack_from('<I',raw,4)[0]!=target:
            raise ValueError('Exact ARMveneer mismatch')
        veneers.append(dict(address=hex(address),stock_bytes=raw.hex(),target=hex(target)))
    entry=0x44DBDF6;endpoints={0x44DBE60:'continue_after_nonzero_kind6_count',
                             0x44DC100:'skip_current_map_nextmap_enumeration',
                             0x44DBE0A:'non_kind6_alternate_branch'}
    original=rd(entry,0x14)
    if original!=bytes.fromhex('062e07d1e8680b21890140180068002866d02ae0'):
        raise ValueError('Kind6 originalbranch signature mismatch')
    source=ROOT/'staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-fields-proof-v1.json'
    records=json.loads(source.read_text())['cases']
    ap=next(c for c in records if c['name'].endswith('gmapprom1.img'))
    cn=next(c for c in records if c['name'].endswith('gmapprom.img'))
    cases=[]
    for name,kind,count,expected in [
        ('AP_originalparser_count6',6,ap['native_context_offset2c0'],0x44DBE60),
        ('CN_originalparser_count0',6,cn['native_context_offset2c0'],0x44DC100),
        ('candidate_missingfield_count0',6,0,0x44DC100),
        ('non_kind6_with_count0',5,0,0x44DBE0A),
    ]:
        u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages=[]
        for page in [0x44DB000,0x44DC000]:
            raw=rd(page,4096);u.mem_map(page,4096);u.mem_write(page,raw)
            u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            pages.append(dict(runtime=hex(page),load=hex(image.runtime_to_load(page,4096)),
                              sha256=hashlib.sha256(raw).hexdigest()))
        u.mem_map(0x9000000,0x3000)
        obj,context=0x9000000,0x9001000
        u.mem_write(obj+0xc,struct.pack('<I',context))
        u.mem_write(context+0x2c0,struct.pack('<I',count))
        u.reg_write(UC_ARM_REG_CPSR,0x3f)
        u.reg_write(UC_ARM_REG_R5,obj);u.reg_write(UC_ARM_REG_R6,kind)
        trace=[];observed=[]
        def code(uc,pc,size,_):
            trace.append(dict(pc=hex(pc),bytes=bytes(uc.mem_read(pc,size)).hex()))
            if pc in endpoints:
                observed.append(pc);uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,code)
        u.emu_start(entry|1,0,count=50,timeout=100000)
        if observed!=[expected]:raise ValueError('Original gate fragment endpoint mismatch')
        cases.append(dict(name=name,request_kind=kind,synthetic_context_count=count,
            endpoint=hex(observed[0]),endpointmeaning=endpoints[observed[0]],
            original_instructions_executed=len(trace)-1,trace=trace,
            synthetic_object_context_registers=True,policy_hooks=[],codepages=pages))
    evidence=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        stock_MAIN_sha256=EXPECTED,actual_fragment_cases_passed=True,cases=cases,
        verified_ARM_veneers=veneers,
        original_windows=[
            window(0x44DBAA4,0x44DBAF4),
            window(0x44DBDD6,0x44DBE60),
            window(0x44DC0FC,0x44DC112),
            window(0x1F18CC,0x1F195A),
            window(0x2CD47A,0x2CD49E),
        ],
        source_header_parser_proof=dict(path=str(source.relative_to(ROOT)),
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),rerun=False),
        caller_chain=dict(query_entry='0x044dbaa4',argument0_is_numeric_query_kind=True,
            negative_highbit_stripped_at=['0x044dbad4','0x044dbada','0x044dbadc'],
            query_object_saved_r5_from_argument2_at='0x044dbab6',
            map_context_pointer_at_query_object_offset='0x0c',
            map_loader_callsite='0x044dbde2',map_loader='0x001f18cc',
            map_loader_calls_original_MDR_context_loader='0x001f1952 -> 0x002cdaac',
            kind6_count_guard='0x044dbdf6 .. 0x044dbe08',
            missingfield_skip='0x044dc100 -> veneer0x0448f2e0 -> mapenumerator0x0032c6b0(flags0x43)',
            request_kind6_plaintext_semantics_not_yet_identified=True),
        exact_descriptor_store=dict(file_header_offset='0x258', bytes=16,
            descriptor_firstDWORD_to_context_offset2b4='0x002cd480/0x002cd482',
            descriptor_thirdDWORD_to_context_offset2b8='0x002cd484/0x002cd486',
            descriptor_fourthDWORD_to_context_offset2bc='0x002cd488/0x002cd48a',
            descriptor_secondDWORD_divided_by_third_to_context_offset2c0='0x002cd494/0x002cd496/0x002cd49c',
            context_offset2b0_not_initialized_by_this_descriptor=True),
        six_record_payload_reader_yet_identified=False,
        device_IO=False, physical_navigation_or_query_verified=False,
        full_UIquery_executed=False, live_selected_map_or_manager_observed=False,
        policy_hooks=[], synthetic_filesystem_IO_hooks_in_this_probe=[],
        limits=['Fragment begins at established inside-function guard, not public callableUI ABI.',
            'Counts from completedoriginalheaderparser are copied into syntheticcallercontext; originalparser not rerun.',
            'Actualquerykind6 zero-countbranch skipsmap; it is not proofquerykind6 is thephysicalstreetrequest.',
            'Six20-byterecordsemantics/consumer, fullqueryfilters andDB→GMP/NET destinationlink remainunknown.',
            'Conditionalruntimecopyflag notread fromlivehardware; no map/code/header/USB changes.'])
    output=HERE/'kind6-MDR-provider-query-guard-proof-v1.json'
    if output.exists():raise ValueError('Refuse overwrite terminalproof')
    output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output),original_fragment_cases=4,all_passed=True,
                          physical_query_verified=False,six_record_consumer_identified=False)))


if __name__=='__main__':main()
