#!/usr/bin/env python3
"""Decode three sealed stock records using original packed-reader instructions.

One underlying filesystem mapping hook supplies peer-read sixteen-byte ranges.
No sort/query/result hook. Stop before the original map metadata lookup, so
the two 24-bit values are reported before any native reference/rescaling.
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
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *

DIR,CTX,FILE,OUT,RET,BUF,STACK=0x09002000,0x09000000,0x09001000,0x09003000,0x09004000,0x09006000,0x09010000
ENTRY,STOP=0x044B10E4,0x0448F740


def dependency(path,expected):
    raw=path.read_bytes();sha=hashlib.sha256(raw).hexdigest()
    if sha!=expected:raise ValueError('Frozen dependency mismatch')
    return json.loads(raw),dict(path=str(path.relative_to(ROOT)),sha256=sha,old_probe_not_replayed=True)


def main():
    consumer,consumer_dep=dependency(ROOT/'staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
        '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60')
    body,body_dep=dependency(ROOT/'staging/navigation-AP-target-packed-bytes-v1/target-packed-bytes-evidence.json',
        'd004fe9571d5748c21aa6181b99ea5d1a5012d314dca297812364d95f02cb448')
    directory=bytes.fromhex(consumer['cases'][0]['output_hex'])
    image=NativeImage()
    def rd(a,n):
        try:a=image.runtime_to_load(a,n)
        except ValueError:pass
        return image.read(a,n)
    # These original bytecode contracts are checked, not replaced.
    if rd(0x00307930,4).hex()!='b3773000' or rd(0x0448EB90,8).hex()!='04f01fe54b783000':
        raise ValueError('Original bitreader/mapping callback mismatch')
    cases=[]
    for source in body['records']:
        level=source['explicit_level'];record=source['explicit_low28_ID'];offset=source['MDR_relative_offset']
        raw=bytes.fromhex(source['hex']);initial=source['initial_bit_offset']
        if len(raw)!=16 or source['actual_source_read_bytes']!=16:raise ValueError('Exact body range mismatch')
        item=consumer['cases'][0]['decoded_records'][level-1]
        widths=item['six_bit_values_at_record_offsets_10_to_17'];flags=item['flags_at_record_offsets_18_19']
        # Independent little-endian least-significant-bit extraction of only
        # these frozen bytes. Outputs are still deliberately unnamed fields.
        seq=[('+08',8,widths[4],True),('+1c',28,widths[3],bool(flags[1])),
             ('+10',16,widths[3],bool(flags[0])),('+00',0,widths[0],bool(widths[0])),
             ('+0c',12,widths[5],bool(widths[5])),('+04',4,widths[1],bool(widths[1])),
             ('+14',20,widths[2],bool(widths[2])),('+18',24,widths[2],bool(widths[2]))]
        bits=int.from_bytes(raw,'little');cursor=initial;expected={};host=[]
        for label,outoffset,width,enabled in seq:
            value=(bits>>cursor)&((1<<width)-1) if enabled else (0xffffffff if outoffset in [16,28] else 0)
            if enabled:cursor+=width
            expected[outoffset]=value
            host.append(dict(output_offset=label,width=width,conditional_enabled=enabled,value=value,
                             cumulative_record_bits_consumed=cursor-initial))
        if cursor-initial!=item['third_scalar']:raise ValueError('Actual conditional-width stride mismatch')
        u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages=[]
        for page in [0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000]:
            codebytes=rd(page,4096);u.mem_map(page,4096);u.mem_write(page,codebytes)
            u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            try:load=image.runtime_to_load(page,4096)
            except ValueError:load=page
            pages.append(dict(runtime=hex(page),load=hex(load),sha256=hashlib.sha256(codebytes).hexdigest()))
        u.mem_map(CTX,0x4000);u.mem_map(STACK,0x4000);u.mem_map(RET,4096);u.mem_map(BUF,4096)
        u.mem_write(RET,b'\x70\x47');u.mem_protect(RET,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_write(BUF,raw);u.mem_protect(BUF,4096,UC_PROT_READ)
        u.mem_write(DIR,directory);u.mem_write(DIR+0x154,struct.pack('<I',CTX))
        u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        u.mem_write(FILE+0xc,struct.pack('<2I',body['MDR_component_bytes'],0))
        u.reg_write(UC_ARM_REG_CPSR,0x3f);u.reg_write(UC_ARM_REG_SP,STACK+0x3000)
        u.reg_write(UC_ARM_REG_LR,RET|1);u.reg_write(UC_ARM_REG_R0,DIR)
        u.reg_write(UC_ARM_REG_R1,record);u.reg_write(UC_ARM_REG_R2,level);u.reg_write(UC_ARM_REG_R3,OUT)
        trace,mappings,progress,callee_calls=[],[],[],[];stopped=False
        boundaries={0x044B1190:'+08',0x044B11DE:'+1c',0x044B122E:'+10',0x044B1268:'+00',
                    0x044B12A4:'+0c',0x044B12DE:'+04',0x044B1314:'+14',0x044B1344:'+18'}
        def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
        def code(uc,pc,size,_):
            nonlocal stopped
            trace.append(dict(pc=hex(pc),bytes=bytes(uc.mem_read(pc,size)).hex(),
                              thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
            if pc==0x00112194:
                fp=uc.reg_read(UC_ARM_REG_R0);lengthpointer=uc.reg_read(UC_ARM_REG_R1);mode=uc.reg_read(UC_ARM_REG_R2)
                actualcursor=word(FILE+0x10)
                if fp!=FILE or actualcursor!=offset or mode!=0 or mappings:
                    raise ValueError('Mapping exceeds exact peer16-byte range')
                uc.mem_write(lengthpointer,struct.pack('<I',16));uc.reg_write(UC_ARM_REG_R0,BUF)
                mappings.append(dict(original_underlying_FS_mapping_callee='0x00112194',file=hex(fp),
                    original_FILE_cursor_MDRrelative=actualcursor,output_length_pointer=hex(lengthpointer),mode=mode,
                    supplied_bytes=16,source_payload_sha256=hashlib.sha256(raw).hexdigest(),synthetic_buffer=hex(BUF)))
                uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            elif pc in boundaries:
                sp=uc.reg_read(UC_ARM_REG_SP);reader=sp+0x10
                consumed=(word(reader+8)-offset)*8-word(reader)
                progress.append(dict(original_pc=hex(pc),completed_output_offset=boundaries[pc],
                    native_bits_consumed_including_initial_offset=consumed,native_record_bits_consumed=consumed-initial,
                    original_bitreader_buffered_bits=word(reader),original_bitreader_next_byte_cursor=word(reader+8)))
            elif pc in [0x0030784A,0x00307770,0x003077B2,0x001C8802,0x001C8850,0x001C8882,0x00307348,0x003732C8]:
                callee_calls.append(dict(pc=hex(pc),r0=hex(uc.reg_read(UC_ARM_REG_R0)),r1=hex(uc.reg_read(UC_ARM_REG_R1)),
                                         r2=uc.reg_read(UC_ARM_REG_R2),r3=uc.reg_read(UC_ARM_REG_R3)))
            elif pc==STOP:
                stopped=True;uc.emu_stop()
            elif pc==RET:
                raise ValueError('Unexpected early originalreader return')
        u.hook_add(UC_HOOK_CODE,code)
        try:u.emu_start(ENTRY|1,RET+2,count=30000,timeout=1000000)
        except Exception as exc:
            p=HERE/'packed-records-failure-v1.json'
            failure=dict(case=source['original_plan_case'],exception=repr(exc),last_pc=hex(u.reg_read(UC_ARM_REG_PC)),
                         trace_tail=trace[-48:],mappings=mappings,progress=progress,callee_calls=callee_calls)
            if not p.exists():p.write_text(json.dumps(failure,indent=2)+'\n')
            raise
        if not stopped or len(mappings)!=1:raise ValueError('Original prefixdecode/mapping outcome mismatch')
        output=bytes(u.mem_read(OUT,32));values={i:struct.unpack_from('<I',output,i)[0]for i in range(0,32,4)}
        if values!=expected:raise ValueError('Native original fields disagree with independent frozen-byte extraction')
        for actual,model in zip(progress,host):
            if actual['completed_output_offset']!=model['output_offset'] or actual['native_record_bits_consumed']!=model['cumulative_record_bits_consumed']:
                raise ValueError('Native conditional field consumption mismatch')
        if len(progress)!=8 or progress[-1]['native_record_bits_consumed']!=item['third_scalar']:
            raise ValueError('Native stride/conditional progress mismatch')
        if bytes(u.mem_read(BUF,16))!=raw:raise ValueError('Readonly payload changed')
        cases.append(dict(source_plan_case=source['original_plan_case'],explicit_level=level,explicit_low28_ID=record,
            MDRrelative_byte_offset=offset,initial_bit_offset=initial,original_readonly_payload_hex=raw.hex(),
            source_logical_key_witness=source['logical_key_from_separate_JAI_witness'],native_32byte_output_hex=output.hex(),
            native_unnamed_fields={f'+{k:02x}':v for k,v in values.items()},conditional_read_sequence=host,
            actual_native_consumption_progress=progress,original_callee_observations=callee_calls,
            synthetic_underlying_FS_mappings=mappings,original_RX_pages=pages,original_instructions_executed=len(trace)-1,
            original_instruction_trace_sha256=hashlib.sha256(json.dumps(trace,sort_keys=True).encode()).hexdigest(),
            original_map_metadata_lookup_not_executed=True,synthetic_context_directory_registers=True,
            actual_record_bits_consumed=progress[-1]['native_record_bits_consumed']))
    result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),stock_MAIN_sha256=EXPECTED,
        dependencies=[consumer_dep,body_dep],all_cases_passed=True,cases=cases,
        original_reader_entry=hex(ENTRY),stop_before_original_mapmetadata_lookup=hex(STOP),
        original_bitreader='0x0030784a',original_mapping_callback='0x003077b2',
        underlying_filesystem_hook_only='0x00112194',result_or_policy_or_sort_or_converter_hooks=[],
        no_new_IMG_reads_here=True,device_IO=False,physical_query_verified=False,fullquery_executed=False,
        complete_reader_return_or_reference_rescaling_verified=False,
        field_semantics_confirmed=False,
        limits=['Exactpeer16-byte slicesprovidedbyoneunderlyingFS mappinghook; originalGETPOS/SEEK/readbit/memcopyexecuted.',
            'Theseare originalstoredrecordvalues, notcurrentmapUIresults ornew2026data.',
            'Two24-bitfieldsarecaptured beforemapreference/rescaling; nofinalcoordinateclaim.',
            'JAIlogicalkey-to-descriptor/querycaller remainsunproven; explicitreaderlevel/lowID suppliedsynthetically.',
            'No indexwriter, newrecordinjection, firmware/candidate/USB modification orwholepayloadreading.'])
    p=HERE/'original-packed-records-proof-v1.json'
    if p.exists():raise ValueError('Refuse overwrite proof')
    p.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(p),all_passed=True,cases=len(cases),fields=[c['native_unnamed_fields']for c in cases],
                         recordbits=[c['actual_record_bits_consumed']for c in cases],physical_query_verified=False)))


if __name__=='__main__':main()
