#!/usr/bin/env python3
"""One new bounded synthetic L3 width23 profile, original-CPU execution.

The original MDR header/parser and directory consumer feed the actual packed
reader prefix. Stop before metadata; no metadata/getter/query success hooks.
No IMG/candidate/device reads or writes and no historical cases are rerun.
"""
import datetime
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import resource

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from unicorn import UC_HOOK_CODE,UC_PROT_READ
from unicorn.arm_const import *

CTX,FILE,DIR,OUT,RET,BUF,STACK = 0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09006000,0x09010000
DIRECTORY_OFFSET,BODY_OFFSET = 1024,4096


def sha(raw): return hashlib.sha256(raw).hexdigest()


def need(ok,message):
    if not ok: raise ValueError(message)


def imported(relative,expected,name,dependencies):
    path = ROOT/relative
    raw = path.read_bytes()
    need(sha(raw) == expected,'Frozen method changed: '+relative)
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dependencies.append(dict(path=relative,sha256=expected,historical_cases_not_run=True))
    return module


def encode(first,count,ref,lat,lon,width=23):
    values = [(1,1),(ref,19),(first,width),(count,12),(4,9),(lat,24),(lon,24)]
    cursor,bits = 0,0
    for value,n in values:
        need(type(value) is int and 0 <= value < 1<<n,'Producer finite field exceeds specified width')
        if n == 19: need(value != (1<<19)-1,'Primary reference would collide with sentinel')
        bits |= value<<cursor
        cursor += n
    need(cursor == 89+width,'Producer field-width sum differs')
    expected = {'+00':first,'+04':4,'+08':1,'+0c':count,'+10':ref,'+14':lat,'+18':lon,'+1c':0xffffffff}
    return bits.to_bytes((cursor+7)//8,'little'),expected


def main():
    target = HERE/'synthetic-width23-original-CPU-proof-v1.json'
    need(not target.exists(),'Refuse overwrite terminal proof')
    dependencies = []
    old = imported('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py',
        '2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa',
        'sealed_native_machine_only',dependencies)
    parser_methods = imported('staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py',
        '0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349',
        'sealed_parser_method_only',dependencies)
    proof_path = ROOT/'staging/navigation-native-address-supplement-native-v1/candidate-original-CPU-proof-v1.json'
    seed_raw = proof_path.read_bytes()
    need(sha(seed_raw) == 'cd91c716cf360d0d47cbfa9d62908ac926864fe592d0d9e54df038fa31f6a8c6','Frozen header seed changed')
    seed = json.loads(seed_raw)
    dependencies.append(dict(path=str(proof_path.relative_to(ROOT)),sha256=sha(seed_raw),old_cases_not_replayed=True))
    cpu = old.CPU(NativeImage())
    # Original word3 bits18..23 are w0, so only one scalar/one width bitfield
    # changes. No firmware patch, no existing writer whitelist alteration.
    directory = bytearray.fromhex(seed['new_candidate_directory']['hex'])
    original_words = list(struct.unpack_from('<5I',directory,40))
    modified_words = original_words.copy()
    modified_words[0:3] = [BODY_OFFSET,56,112]
    modified_words[3] = (modified_words[3]&~(63<<18))|(23<<18)
    struct.pack_into('<5I',directory,40,*modified_words)
    header = bytearray.fromhex(seed['new_candidate_MDR_header']['hex'])
    struct.pack_into('<3I',header,600,DIRECTORY_OFFSET,120,20)
    body_parts = [
        ('expanded_clone_target',*encode(4267896,93,206,1124821,5624199)),
        ('first_above_width22',*encode(4194304,4095,524286,1124806,5624212)),
        ('width23_first_maximum',*encode(8388607,1,206,0xffffff,0xffffff)),
        ('last_inclusive_width23_maximum',*encode(8384513,4095,206,1,2)),
    ]
    body = b''.join(row[1] for row in body_parts)
    need(len(body) == 56,'Synthetic width23 records must be14byte aligned')
    # Original bitreader prefetch may touch the bytes following its final
    # extracted field. Keep four explicit zero lookahead bytes in the small
    # synthetic FILE, outside the directory's declared56-byte record span.
    mapped_source = body+bytes(4)
    fixtures = [{'offset':0,'bytes':len(header),'hex':header.hex(),'purpose':'new_synthetic_MDR_header'},
                {'offset':DIRECTORY_OFFSET,'bytes':len(directory),'hex':directory.hex(),'purpose':'new_synthetic_directory'},
                {'offset':BODY_OFFSET,'bytes':len(mapped_source),'hex':mapped_source.hex(),
                 'record_span_bytes':56,'explicit_nonrecord_lookahead_bytes':4,'purpose':'four_new_width23_records_and_lookahead'}]
    fixture_path = HERE/'synthetic-width23-fixtures-v2.json'
    fixture_text = json.dumps(dict(synthetic_profile=True,sections=fixtures),indent=2)+'\n'
    if fixture_path.exists():
        need(fixture_path.read_text() == fixture_text,'Existing unfinalized fixture differs')
    else:
        fixture_path.write_text(fixture_text)
    static = []
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for address,count,purpose in [(0x044B211A,0x44,'Directory field widths dynamically extracted in6bits'),
        (0x044B1120,0x30,'Stride scalar drives(ID−1)*bits,byteoffset and bitoffset, with finite source-span guard'),
        (0x044B1232,0x32,'Dynamic firstchild width and true bitreader call'),
        (0x044B126C,0x38,'Independent count width remains12'),
        (0x044B11E0,0x4E,'Independent primary reference width remains19')]:
        raw = cpu.read(address,count)
        static.append(dict(address=hex(address),bytes=count,sha256=sha(raw),raw_hex=raw.hex(),purpose=purpose,
            instructions=[dict(pc=hex(i.address),hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in md.disasm(raw,address)]))
    parser = parser_methods.invoke(cpu.image,bytes(header),'new_synthetic_width23')
    gc.collect()
    need(parser['success'] and parser['native_context_offset2b8'] == 20 and parser['native_context_offset2c0'] == 6,'New profile header rejected')
    u,pages = cpu.machine([0x044B2000,0x0448F000,0x001C8000,0x00332000,0x0038C000])
    u.mem_write(CTX+0x280,bytes.fromhex(parser['native_context_slice280_2c4']))
    u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
    u.mem_write(FILE+11,b'\x40')
    reads,trace,stop = [],[],[]
    def word(a): return struct.unpack('<I',u.mem_read(a,4))[0]
    def directory_hook(uc,pc,size,_):
        trace.append((pc,bytes(uc.mem_read(pc,size)).hex()))
        if pc == RET:
            stop.append(True);uc.emu_stop()
        elif pc == 0x003324B8:
            fp,destination,n = [uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
            offset = word(FILE+0x10)
            relative = offset-DIRECTORY_OFFSET
            need(fp == FILE and n == 20 and relative in range(0,120,20),'Directory read beyond new fixture')
            raw = bytes(directory[relative:relative+20])
            uc.mem_write(destination,raw)
            uc.mem_write(FILE+0x10,struct.pack('<I',offset+n))
            reads.append(dict(offset=offset,bytes=n,sha256=sha(raw)))
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    directory_hook_handle = u.hook_add(UC_HOOK_CODE,directory_hook)
    u.reg_write(UC_ARM_REG_R0,CTX);u.reg_write(UC_ARM_REG_R1,DIR)
    u.emu_start(0x044B209F,RET+2,count=30000,timeout=1000000)
    need(stop == [True] and u.reg_read(UC_ARM_REG_R0) == 0 and len(reads) == 6 and word(DIR) == 6,'Original new directory did not return')
    native_directory = bytes(u.mem_read(DIR,172))
    native_l3 = native_directory[60:88]
    q,bits,start,length = struct.unpack_from('<4I',native_l3)
    widths,flags = list(native_l3[16:24]),list(native_l3[24:26])
    need((q,bits,start,length,widths,flags) == (4,112,BODY_OFFSET,56,[23,9,24,19,1,12,0,0],[1,0]),'Original new L3 directory decode differs')
    directory_result = dict(native_output_hex=native_directory.hex(),native_L3=dict(count=q,record_bits=bits,start=start,bytes=length,widths=widths,flags=flags),
        FS_reads=reads,original_instructions=len(trace)-1,trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages)
    u.hook_del(directory_hook_handle)
    del u
    gc.collect()
    results = []
    boundaries = {0x044B1190:'+08',0x044B11DE:'+1c',0x044B122E:'+10',0x044B1268:'+00',
                  0x044B12A4:'+0c',0x044B12DE:'+04',0x044B1314:'+14',0x044B1344:'+18'}
    planned = [(name,i+1,3,expected,True) for i,(name,raw,expected) in enumerate(body_parts)]
    planned.extend([('ID_zero_guard',0,3,None,False),('ID_beyond_span_guard',5,3,None,False),
                    ('level_zero_guard',1,0,None,False),('level_beyond_directory_guard',1,7,None,False)])
    for name,ID,level,expected,success in planned:
        v,record_pages = cpu.machine([0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000])
        v.mem_write(DIR,native_directory)
        v.mem_write(DIR+0x154,struct.pack('<I',CTX))
        v.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        v.mem_write(FILE+0xc,struct.pack('<2I',BODY_OFFSET+len(mapped_source),0))
        v.mem_write(BUF,mapped_source)
        v.mem_protect(BUF,4096,UC_PROT_READ)
        calls,progress,record_trace,stops = [],[],[],[]
        def rw(address): return struct.unpack('<I',v.mem_read(address,4))[0]
        def record_hook(uc,pc,size,_):
            record_trace.append((pc,bytes(uc.mem_read(pc,size)).hex()))
            if pc == 0x00112194:
                fp,destination,mode = [uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
                offset = rw(FILE+0x10)
                relative = offset-BODY_OFFSET
                need(success and fp == FILE and relative == (ID-1)*14 and mode == 0 and not calls,
                     'Packed mapping beyond new fixture: '+json.dumps(dict(case=name,ID=ID,success=success,fp=hex(fp),offset=offset,relative=relative,mode=mode,calls=calls)))
                uc.mem_write(destination,struct.pack('<I',BUF+relative))
                uc.reg_write(UC_ARM_REG_R0,len(mapped_source)-relative)
                calls.append(dict(offset=offset,bytes=len(mapped_source)-relative,source_sha256=sha(mapped_source[relative:]),explicit_FS_only=True,
                    directory_record_span_bytes=56,synthetic_source_lookahead_bytes=4))
                uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            elif pc in boundaries:
                reader = uc.reg_read(UC_ARM_REG_SP)+0x10
                offset = BODY_OFFSET+(ID-1)*14
                consumed = (rw(reader+8)-offset)*8-rw(reader)
                progress.append(dict(native_pc=hex(pc),field=boundaries[pc],consumed_bits=consumed))
            elif pc in [0x0448F740,RET]:
                stops.append(pc);uc.emu_stop()
        record_hook_handle = v.hook_add(UC_HOOK_CODE,record_hook)
        for reg,value in [(UC_ARM_REG_R0,DIR),(UC_ARM_REG_R1,ID),(UC_ARM_REG_R2,level),(UC_ARM_REG_R3,OUT)]:v.reg_write(reg,value)
        v.emu_start(0x044B10E5,RET+2,count=30000,timeout=1000000)
        output = bytes(v.mem_read(OUT,32))
        actual = {f'+{k:02x}':struct.unpack_from('<I',output,k)[0] for k in range(0,32,4)}
        if success:
            need(stops == [0x0448F740] and len(calls) == 1 and actual == expected and len(progress) == 8,'New width23 original reader prefix differs')
            need([p['consumed_bits']for p in progress] == [1,1,20,43,55,64,88,112],'New dynamic width23 native bit progress differs')
        else:
            need(stops == [RET] and v.reg_read(UC_ARM_REG_R0) == 3 and not calls,'Native guard did not reject before I/O/metadata')
        results.append(dict(name=name,explicit_ID=ID,explicit_level=level,new_profile_synthetic=True,
            original_prefix_reached_metadata_boundary=success,full_original_reader_return=not success,
            actual_return_code=None if success else v.reg_read(UC_ARM_REG_R0),
            actual_native_fields=actual if success else None,actual_output_hex=output.hex(),native_bit_progress=progress,
            FS_mapping_calls=calls,original_instructions=len(record_trace)-1,
            trace_sha256=sha(json.dumps(record_trace).encode()),original_RX_pages=record_pages))
        v.hook_del(record_hook_handle)
        del v
        gc.collect()
    producer_guards = []
    for name,values in [
        ('width22_rejects_clone_target',(4267896,93,206,1,2,22)),
        ('width23_overflow_rejected',(8388608,1,206,1,2,23)),
        ('count12_overflow_rejected',(4267896,4096,206,1,2,23)),
        ('ref19_sentinel_collision_rejected',(4267896,1,524287,1,2,23))]:
        try: encode(*values)
        except ValueError as exc: producer_guards.append(dict(name=name,rejected=True,exception=str(exc),host_producer_control_only=True))
        else: raise ValueError('Required producer guard did not reject')
    result = dict(schema='synthetic-L3-width23-native/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=sha(Path(__file__).read_bytes()),stock_MAIN_sha256=EXPECTED,dependencies=dependencies,
        exact_new_original_prefix_cases=4,exact_new_native_guard_cases=4,all_bounded_checks_passed=True,
        fixture_file=dict(path=str(fixture_path.relative_to(ROOT)),sha256=sha(fixture_path.read_bytes()),source_bytes=952,
            record_span_bytes=56,synthetic_source_lookahead_bytes=4),
        changed_directory_words=dict(old=original_words,new=modified_words),changed_header_words_at600=[DIRECTORY_OFFSET,120,20],
        static_original_instructions=static,actual_original_parser=parser,actual_original_directory=directory_result,
        cases=results,host_producer_guards=producer_guards,
        alignment_relation=dict(width22_stride111='offset bit=((ID−1)*111)%8:0,7,6,5,4,3,2,1; variable byte boundary',
            width23_stride112='offset bit0 for every ID; byteoffset=spanStart+(ID−1)*14',
            directory_entry_wire_bytes_unchanged=20,native_decoded_entry_bytes_unchanged=28,
            reference_width_unchanged=19,count_width_unchanged=12,
            minimum_source_span_bytes_for47870_streets_width23=670180),
        only_function_hooks=['underlying FS open0x1C8682','underlying FS read0x3324B8','underlying FS mapping0x112194'],
        metadata_registry_getter_query_sort_or_result_hooks=[],full_original_L3_reader_or_getter_executed=False,
        original_complete_query_or_house_search=False,device_IO=False,IMG_or_DB_or_candidate_read_or_write=False,
        old_closed_suites_replayed=False,complete_nationwide_candidate=False,installable=False,
        actual_process_peak_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        inference='This exact dynamic packed-reader prefix accepts a synthetic23-bit firstchild above4194303 when directory stride becomes112. It does not establish full platform/update/UI compatibility.',
        remaining_limits=['Every successful packed record stops before real mapmetadata lookup0x0448F740; no successful metadata/getter result fabricated.',
            'Profile bytes are synthetic and not an IMG or a proposed full Taiwan map; original labels/other body tables and complete provider lifecycle do not run.',
            'Width and stride are independent wire fields. Native prefix uses each dynamically; producers must keep total field widths and stride consistent. Mis-sized stride not experimentally replayed here.',
            'Field width23 allows8388607 as a firstchild encoding; child-end bounds, level4 capacity, 28-bit logicalIDs, consumer/JAI/SQL/query/routing and actual device acceptance remain separate requirements.',
            'Native guard controls reject invalid recordID/level against synthetic span. Host producer overflow/sentinel checks are not native parser guards.',
            'This bounded result cannot justify calling22bits a hard platform limit or declaring wholeTaiwan update complete.'])
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(target.relative_to(ROOT)),proof_sha256=sha(target.read_bytes()),all_passed=True,
        new_records=4,native_guards=4,host_producer_guards=4,firstchildren=[r['actual_native_fields']['+00']for r in results if r['actual_native_fields']],
        native_widths=widths,stride=bits,full_L3_getter_executed=False),ensure_ascii=False))


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        path = HERE/'unfinalized-failure-v2.json'
        if not path.exists(): path.write_text(json.dumps(dict(exception=repr(exc)),indent=2)+'\n')
        raise
