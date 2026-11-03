#!/usr/bin/env python3
"""Original packed reader entry/guards/address planning, no body reads.

The directory object is the frozen original consumer's observed output. An
observer stops at the actual bit-reader ARM veneer before any file I/O.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *

DIR,CTX,FILE,OUT,RET,STACK=0x09002000,0x09000000,0x09001000,0x09003000,0x09004000,0x09010000
ENTRY,STOP=0x044B10E4,0x0448EB90


def main():
    dep=ROOT/'staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json'
    sha=hashlib.sha256(dep.read_bytes()).hexdigest()
    if sha!='2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60':
        raise ValueError('Frozen originalconsumer receipt mismatch')
    observed=json.loads(dep.read_text())['cases'][0]
    directory=bytes.fromhex(observed['output_hex'])
    image=NativeImage()
    def rd(a,n):
        try:a=image.runtime_to_load(a,n)
        except ValueError:pass
        return image.read(a,n)
    if rd(ENTRY,8).hex()!='ffb500208fb00590':
        raise ValueError('Original packedreader entry signature mismatch')
    if rd(STOP,8).hex()!='04f01fe54b783000':
        raise ValueError('Original bitreader veneer mismatch')
    cases=[]
    controls=[('JAI_city_lowID8',8,1,True),('JAI_district_lowID88',88,2,True),
              ('JAI_central_Minquan_street_lowID16707',16707,3,True),
              ('zero_recordID',0,3,False),('zero_tablelevel',16707,0,False),
              ('tablelevel7_exceeds_directorycount',16707,7,False),
              ('street_ID47871_exceeds_bitspan',47871,3,False),
              ('full_logicalkey_not_lowID',0x30004143,3,False)]
    for name,record,level,expected in controls:
        u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages=[]
        for page in [0x044B1000,0x0448E000]:
            raw=rd(page,4096);u.mem_map(page,4096);u.mem_write(page,raw)
            u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            pages.append(dict(runtime=hex(page),load=hex(image.runtime_to_load(page,4096)),sha256=hashlib.sha256(raw).hexdigest()))
        u.mem_map(CTX,0x4000);u.mem_map(STACK,0x4000);u.mem_map(RET,4096)
        u.mem_write(RET,b'\x70\x47');u.mem_protect(RET,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_write(DIR,directory);u.mem_write(DIR+0x154,struct.pack('<I',CTX))
        u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        u.reg_write(UC_ARM_REG_CPSR,0x3f);u.reg_write(UC_ARM_REG_SP,STACK+0x3000)
        u.reg_write(UC_ARM_REG_LR,RET|1);u.reg_write(UC_ARM_REG_R0,DIR)
        u.reg_write(UC_ARM_REG_R1,record);u.reg_write(UC_ARM_REG_R2,level);u.reg_write(UC_ARM_REG_R3,OUT)
        trace=[];plan=[];returned=[]
        def code(uc,pc,size,_):
            trace.append(dict(pc=hex(pc),bytes=bytes(uc.mem_read(pc,size)).hex()))
            if pc==STOP:
                plan.append(dict(original_callee_veneer=hex(STOP),original_callee='0x0030784a',
                    r0_file_pointer=hex(uc.reg_read(UC_ARM_REG_R0)),r1_file_kind=uc.reg_read(UC_ARM_REG_R1),
                    r2_MDR_relative_byte_offset=uc.reg_read(UC_ARM_REG_R2),r3_initial_bit_offset=uc.reg_read(UC_ARM_REG_R3),
                    stack_fifth_bitreader_object_pointer=hex(struct.unpack('<I',uc.mem_read(uc.reg_read(UC_ARM_REG_SP),4))[0]),
                    CPSR_thumb_at_ARMveneer=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),observer_stop_before_callee_execution=True))
                uc.emu_stop()
            elif pc==RET:
                returned.append(uc.reg_read(UC_ARM_REG_R0));uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,code)
        u.emu_start(ENTRY|1,RET+2,count=3000,timeout=100000)
        if bool(plan)!=expected or (not expected and returned!=[3]):
            raise ValueError('Original planning/guard outcome mismatch')
        if plan:
            entry=observed['decoded_records'][level-1]
            bits=(record-1)*entry['third_scalar']
            expected_byte=entry['span_start']+bits//8
            if plan[0]['r2_MDR_relative_byte_offset']!=expected_byte or plan[0]['r3_initial_bit_offset']!=bits%8:
                raise ValueError('Original planned byte/bit mismatch')
            plan[0].update(actual_selected_directory_ordinal_zero_based=level-1,
                third_scalar_record_bits=entry['third_scalar'],body_bytes_covering_this_one_record=(bits%8+entry['third_scalar']+7)//8,
                original_directory_span_start=entry['span_start'],original_directory_span_bytes=entry['span_bytes'])
        cases.append(dict(name=name,synthetic_explicit_recordID=record,synthetic_explicit_tablelevel=level,
            original_planned_read=plan,returned_error_code=returned,original_instructions_executed=len(trace)-1,
            trace=trace,original_RX_pages=pages,filesystem_or_result_or_policy_hooks=[],device_IO=False))
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),stock_MAIN_sha256=EXPECTED,
        original_entry=hex(ENTRY),original_stop_veneer=hex(STOP),all_cases_passed=True,cases=cases,
        frozen_directory_dependency=dict(path=str(dep.relative_to(ROOT)),sha256=sha,original_consumer_not_replayed=True),
        original_address_planning_instructions=[dict(pc=hex(x.address),bytes=x.bytes.hex(),instruction=x.mnemonic+' '+x.op_str)
            for x in cs.disasm(rd(ENTRY,0x72),ENTRY)],
        original_nearby_descriptor_to_reader_caller_instructions=[dict(pc=hex(x.address),bytes=x.bytes.hex(),instruction=x.mnemonic+' '+x.op_str)
            for x in cs.disasm(rd(0x044B2976,0x18),0x044B2976)],
        proven_explicit_reader_contract='tablelevel1 selects directoryordinal0; level2->ordinal1; level3->ordinal2. RecordID1 begins at spanstart, byteoffset=start+floor((ID-1)*recordbits/8), bitoffset=((ID-1)*recordbits)%8.',
        partial_caller='0x044b297a reads descriptorbyte9; mask0x3f; subtract2 supplies readerlevel; descriptor+4 supplies readerrecordID. JAI logicalkey-to-descriptor constructor is not yet proven.',
        full_logicalkey_guard_note='0x30004143 fails this bounded originalguard; the exactquerycaller masking/conversion into lowID16707 remainsunproven.',
        body_bytes_read=0,physical_query_verified=False,fullquery_executed=False,
        limits=['This executes entry/guards/addresscalculation only; stops at realbitreader ARM veneer before any body/file read.',
            'Directorybytes are observedoriginalconsumer output; object/context/registers/recordlevel are synthetic inputs.',
            'The chosen JAI names/levelscome fromseparatefrozenpeerDB proofs; noJAI-to-descriptorcallerexecutedhere.',
            'Coordinates, housereferences and packed recordcontents have not been decoded here.'])
    p=HERE/'original-packed-reader-plan-proof-v1.json'
    if p.exists():raise ValueError('Refuse overwrite proof')
    p.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(p),all_passed=True,cases=len(cases),body_bytes_read=0,
        plans=[dict(case=c['name'],byte=c['original_planned_read'][0]['r2_MDR_relative_byte_offset'],
                    bit=c['original_planned_read'][0]['r3_initial_bit_offset'],bytes=c['original_planned_read'][0]['body_bytes_covering_this_one_record'])
               for c in cases if c['original_planned_read']])))


if __name__=='__main__':main()
