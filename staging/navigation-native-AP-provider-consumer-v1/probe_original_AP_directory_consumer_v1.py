#!/usr/bin/env python3
"""Finite stock MDR directory consumer with peer's sealed 120-byte payload.

Executes the real consumer, ARM veneers, filesystem read wrapper and division.
Only the underlying file read is synthetic. No span body, query or UI runs.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

CTX, FILE, OUT, RET, STACK = 0x09000000, 0x09001000, 0x09002000, 0x09004000, 0x09010000
ENTRY = 0x044B209E


def main():
    dependency = ROOT/'staging/navigation-AP-provider-records-v1/AP-provider-records-evidence.json'
    if hashlib.sha256(dependency.read_bytes()).hexdigest() != '32aae3c125bc21ae71d81997d4b7d481cd08686e4b42683b51501adc8b7121dd':
        raise ValueError('Peer sealed directory receipt mismatch')
    data = json.loads(dependency.read_text())
    directory = data['provider_directory']
    payload = bytes.fromhex(directory['hex'])
    start = directory['MDR_relative_offset']
    if len(payload) != 120 or hashlib.sha256(payload).hexdigest() != directory['sha256']:
        raise ValueError('Peer payload mismatch')
    image = NativeImage()
    def rd(a,n):
        try: a = image.runtime_to_load(a,n)
        except ValueError: pass
        return image.read(a,n)
    veneers = []
    for address,target in [(0x0448FB90,0x001C8783),(0x0448FF28,0x0038C168)]:
        b = rd(address,8)
        if b[:4] != bytes.fromhex('04f01fe5') or struct.unpack_from('<I',b,4)[0] != target:
            raise ValueError('Original ARM veneer mismatch')
        veneers.append(dict(address=hex(address),bytes=b.hex(),target=hex(target)))
    if rd(ENTRY,8).hex() != 'f0b506000d000027':
        raise ValueError('Original consumer signature mismatch')
    cases = []
    for name,count in [('original_AP_six_records',6),('no_provider_count_control',0)]:
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages = []
        for page in [0x044B2000,0x0448F000,0x001C8000,0x00332000,0x0038C000]:
            raw = rd(page,4096)
            u.mem_map(page,4096)
            u.mem_write(page,raw)
            u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            try: load = image.runtime_to_load(page,4096)
            except ValueError: load = page
            pages.append(dict(runtime=hex(page),load=hex(load),sha256=hashlib.sha256(raw).hexdigest()))
        u.mem_map(CTX,0x3000)
        u.mem_map(STACK,0x4000)
        u.mem_map(RET,4096)
        u.mem_write(RET,b'\x70\x47')
        u.mem_protect(RET,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        u.mem_write(CTX+0x2b4,struct.pack('<4I',start,20,1,count))
        u.mem_write(FILE+11,b'\x40')
        trace,reads,divisions = [],[],[]
        returned = False
        def word(a): return struct.unpack('<I',u.mem_read(a,4))[0]
        def code(uc,pc,size,_):
            nonlocal returned
            trace.append(dict(pc=hex(pc),bytes=bytes(uc.mem_read(pc,size)).hex(),
                              thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
            if pc == RET:
                returned = True
                uc.emu_stop()
            elif pc == 0x003324B8:
                fp,destination,n = [uc.reg_read(reg) for reg in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
                offset = word(FILE+0x10)
                relative = offset-start
                if fp != FILE or n != 20 or relative not in range(0,120,20):
                    raise ValueError('Read exceeds exact peer directory scope')
                raw = payload[relative:relative+n]
                uc.mem_write(destination,raw)
                uc.mem_write(FILE+0x10,struct.pack('<I',offset+n))
                reads.append(dict(MDR_relative_offset=offset,bytes=n,payload_hex=raw.hex(),
                                  synthetic_underlying_filesystem=True))
                uc.reg_write(UC_ARM_REG_R0,0)
                uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            elif pc == 0x0038C168:
                divisions.append(dict(numerator=uc.reg_read(UC_ARM_REG_R0),
                                      denominator=uc.reg_read(UC_ARM_REG_R1),
                                      caller_LR=hex(uc.reg_read(UC_ARM_REG_LR)),
                                      original_ARM_instructions_executed=True))
        u.hook_add(UC_HOOK_CODE,code)
        u.reg_write(UC_ARM_REG_CPSR,0x3f)
        u.reg_write(UC_ARM_REG_SP,STACK+0x3000)
        u.reg_write(UC_ARM_REG_LR,RET|1)
        u.reg_write(UC_ARM_REG_R0,CTX)
        u.reg_write(UC_ARM_REG_R1,OUT)
        try:
            u.emu_start(ENTRY|1,RET+2,count=30000,timeout=1000000)
        except Exception as exc:
            failure = dict(case=name,exception=repr(exc),last_pc=hex(u.reg_read(UC_ARM_REG_PC)),
                           trace_tail=trace[-40:],reads=reads,divisions=divisions)
            p = HERE/'AP-directory-consumer-failure-v1.json'
            if not p.exists(): p.write_text(json.dumps(failure,indent=2)+'\n')
            raise
        if not returned or u.reg_read(UC_ARM_REG_R0) != (0 if count else 3):
            raise ValueError('Original consumer return mismatch')
        output = bytes(u.mem_read(OUT,4+28*count))
        observed = []
        for i in range(count):
            record = output[4+28*i:4+28*(i+1)]
            q,pbits,pstart,plen = struct.unpack_from('<4I',record)
            fields = list(record[16:24]);flags = list(record[24:26])
            s,n,b,w,x = struct.unpack_from('<5I',payload,i*20)
            expected_fields = [(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,
                               x&63,(x>>11)&63,(x>>17)&63]
            expected_flags = [(w>>30)&1,(w>>31)&1]
            if (q,pbits,pstart,plen,fields,flags) != (n*8//b,b,s,n,expected_fields,expected_flags):
                raise ValueError('Original consumer decoded field mismatch')
            observed.append(dict(ordinal_zero_based=i,original_raw_words=[s,n,b,hex(w),x],
                native_decoded_record_hex=record.hex(),native_floor_spanbits_div_scalar=q,
                span_bits_division_remainder=n*8%b,third_scalar=pbits,span_start=pstart,span_bytes=plen,
                six_bit_values_at_record_offsets_10_to_17=fields,
                flags_at_record_offsets_18_19=flags,
                original_native_division=divisions[i]))
        if len(reads) != count or len(divisions) != count or word(OUT) != count:
            raise ValueError('Read/division/output count mismatch')
        cases.append(dict(name=name,provider_count=count,returned=returned,return_code=u.reg_read(UC_ARM_REG_R0),
            instructions=len(trace)-1,synthetic_context_and_output=True,underlying_FS_read_hooks=['0x003324b8'],
            policy_or_result_hooks=[],map_bytes_read_by_this_probe=0,payload_bytes_from_peer_receipt=20*len(reads),
            actual_native_filesystem_wrapper_reads=reads,decoded_records=observed,
            output_hex=output.hex(),original_context_pointer_stored_at_output_offset154=hex(word(OUT+0x154)),
            original_instruction_trace_sha256=hashlib.sha256(json.dumps(trace,sort_keys=True).encode()).hexdigest(),
            original_RX_pages=pages))
    cs = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    instructions = [dict(pc=hex(x.address),bytes=x.bytes.hex(),instruction=x.mnemonic+' '+x.op_str)
                    for x in cs.disasm(rd(ENTRY,0x100),ENTRY)]
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),stock_MAIN_sha256=EXPECTED,
        dependency=dict(path=str(dependency.relative_to(ROOT)),sha256=hashlib.sha256(dependency.read_bytes()).hexdigest(),
                        original_file_read_not_replayed=True),
        original_consumer_entry=hex(ENTRY),original_veneers=veneers,
        original_consumer_instructions=instructions,all_cases_passed=True,cases=cases,
        actual_decoded_count=[r['native_floor_spanbits_div_scalar'] for r in cases[0]['decoded_records']],
        context_offsets=dict(directory_start='0x2b4',directory_item_bytes='0x2b8',directory_flags='0x2bc',directory_count='0x2c0'),
        output_layout=dict(count_word_offset=0,entry_base_offset=4,entry_stride=28,
            floor_spanbits_div_scalar_offset=0,third_scalar_offset=4,span_start_offset=8,span_bytes_offset=12,
            six_bit_values_offset=16,two_flags_offset=24,context_pointer_offset='0x154'),
        inference='The six directory entries describe packed data spans and layout scalars; the first three computed sizes match existing JAI logical-ID maxima22/343/47870. Their level selector/recordID encoding remains unproven.',
        physical_UI_query_verified=False,device_IO=False,full_query_or_UI_executed=False,
        six_span_bodies_read=False,record_payload_or_name_decoded=False,
        limits=['UnderlyingFS copies only a prior sealed120-byte peer receipt into syntheticstackbuffers.',
            'Context/count/file/object/output are synthetic; exact original parser is not rerun.',
            'Nativeconsumer computes bitlengthquotients and field widths; writer/bitstream/name/reference interpretation is not proven.',
            'No live selectedprovider or destination/road/house association observed; no sealedmap/source/proof/USB changed.'])
    p = HERE/'original-AP-directory-consumer-proof-v1.json'
    if p.exists(): raise ValueError('Refuse overwrite terminal proof')
    p.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(p),all_passed=True,actual_counts=result['actual_decoded_count'],physical_query_verified=False)))


if __name__ == '__main__': main()
