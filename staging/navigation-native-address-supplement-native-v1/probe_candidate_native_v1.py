#!/usr/bin/env python3
"""Bounded original-CPU checks of a newly built one-street AP supplement.

Reads candidate bytes through its actual DSKIMG/FAT. Runs native MDR parser,
directory decoder and the packed-record prefix. Metadata/registry/query success
is never supplied. LBL parser/address/encoding-10 and coordinate suffix are
explicit separate fragments, not fabricated full-reader continuations.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

CTX, FILE, DIR, OUT, RET, BUF, OBJECT, STACK = (
    0x09000000, 0x09001000, 0x09002000, 0x09003000,
    0x09004000, 0x09006000, 0x09008000, 0x09010000)
RECORD_ENTRY, PREFIX_STOP = 0x044B10E4, 0x0448F740
FIRST, COUNT, STREET = 2133949, 93, 16707
REF_LABELS = [(23,'6號'),(25,'8號'),(150,'138號'),(152,'140號'),(154,'142號'),
              (783,'144號'),(784,'146號'),(157,'148號'),(787,'150號')]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def stat(path):
    s = path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def frozen_module(relative, expected, name, dependencies):
    path = ROOT/relative
    raw = path.read_bytes()
    need(sha(raw) == expected, 'Frozen method source changed: '+relative)
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dependencies.append(dict(path=relative,sha256=expected,old_main_or_cases_not_run=True))
    return module


class CandidateIMG:
    """Independent logical reader of exactly two relevant real FAT entries."""
    def __init__(self,path):
        self.path = path
        self.before = stat(path)
        self.stream = path.open('rb')
        self.log = []
        header = self.physical(0,512,'candidate_DSKIMG_header')
        need(header[0] == 0 and header[16:23] == b'DSKIMG\0' and header[65:72] == b'GARMIN\0',
             'Unexpected candidate DSKIMG format')
        self.block_size = 1 << (header[97]+header[98])
        start = header[64]*512
        first = self.physical(start,512,'candidate_FAT_extent')
        end = struct.unpack_from('<I',first,12)[0]
        need(start < end <= 131072 and end%512 == 0,'Candidate FAT extent invalid')
        directory = first+self.physical(start+512,end-start-512,'candidate_FAT_rows')
        self.extent = [start,end]
        self.components = {}
        targets = {'00004171.MDR','I053061A.GMP'}
        for pos in range(0,len(directory),512):
            row = directory[pos:pos+512]
            if row[0] != 1 or row[16] == 3:
                continue
            name = row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
            if name not in targets:
                continue
            c = self.components.setdefault(name,dict(blocks=[],parts=[]))
            part = struct.unpack_from('<H',row,17)[0]
            need(part == len(c['parts']),'Candidate FAT parts out of order')
            if part == 0:
                c['bytes'] = struct.unpack_from('<I',row,12)[0]
            blocks = [b for b in struct.unpack_from('<240H',row,32) if b != 65535]
            need(all((b+1)*self.block_size <= self.before[2] for b in blocks),'FAT block outside candidate')
            c['parts'].append(dict(part=part,physical_directory_row=start+pos))
            c['blocks'].extend(blocks)
        need(set(self.components) == targets,'Candidate required components absent')
        allblocks = []
        for c in self.components.values():
            need(len(c['blocks']) == (c['bytes']+self.block_size-1)//self.block_size,
                 'Candidate FAT blocks versus component size mismatch')
            allblocks.extend(c['blocks'])
        need(len(set(allblocks)) == len(allblocks),'Candidate target components overlap')

    def physical(self,offset,count,purpose):
        need(0 <= offset <= offset+count <= self.before[2],'Candidate physical read out of range')
        self.stream.seek(offset)
        raw = self.stream.read(count)
        need(len(raw) == count,'Short candidate read')
        self.log.append(dict(purpose=purpose,physical_offset=offset,bytes=count))
        return raw

    def read(self,name,offset,count,purpose):
        c = self.components[name]
        need(0 <= offset <= offset+count <= c['bytes'],'Candidate logical read out of range')
        output = bytearray()
        mappings = []
        cursor = offset
        while cursor < offset+count:
            index,within = divmod(cursor,self.block_size)
            length = min(offset+count-cursor,self.block_size-within)
            physical = c['blocks'][index]*self.block_size+within
            output.extend(self.physical(physical,length,purpose))
            mappings.append(dict(logical_offset=cursor,logical_block=index,allocated_block=c['blocks'][index],
                                 physical_offset=physical,bytes=length))
            cursor += length
        raw = bytes(output)
        return dict(component=name,offset=offset,bytes=count,sha256=sha(raw),hex=raw.hex(),FAT_mapping=mappings),raw

    def close(self):
        self.stream.close()
        need(stat(self.path) == self.before,'Candidate changed during bounded read/probe')


class CPU:
    def __init__(self,image):
        self.image = image

    def read(self,address,count):
        try:
            address = self.image.runtime_to_load(address,count)
        except ValueError:
            pass
        return self.image.read(address,count)

    def machine(self,pages):
        u = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        receipts = []
        for page in pages:
            raw = self.read(page,4096)
            u.mem_map(page,4096)
            u.mem_write(page,raw)
            u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            receipts.append(dict(runtime=hex(page),sha256=sha(raw)))
        u.mem_map(CTX,0x4000)
        for base,length in [(RET,4096),(BUF,4096),(OBJECT,4096),(STACK,0x4000)]:
            u.mem_map(base,length)
        u.mem_write(RET,b'\x70\x47')
        u.mem_protect(RET,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.reg_write(UC_ARM_REG_CPSR,0x3f)
        u.reg_write(UC_ARM_REG_SP,STACK+0x3000)
        u.reg_write(UC_ARM_REG_LR,RET|1)
        return u,receipts

    def directory(self,parser,directory_bytes,start):
        u,pages = self.machine([0x044B2000,0x0448F000,0x001C8000,0x00332000,0x0038C000])
        # Both values are literal original parser output from this candidate.
        parser_slice = bytes.fromhex(parser['native_context_slice280_2c4'])
        u.mem_write(CTX+0x280,parser_slice)
        u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        u.mem_write(FILE+11,b'\x40')
        trace,reads,divisions,stopped = [],[],[],[]
        def word(a): return struct.unpack('<I',u.mem_read(a,4))[0]
        def code(uc,pc,size,_):
            trace.append(dict(pc=hex(pc),hex=bytes(uc.mem_read(pc,size)).hex()))
            if pc == RET:
                stopped.append(True)
                uc.emu_stop()
            elif pc == 0x003324B8:
                fp,destination,count = [uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
                cursor = word(FILE+0x10)
                relative = cursor-start
                need(fp == FILE and count == 20 and relative in range(0,120,20),'Directory FS fixture exceeds candidate directory')
                raw = directory_bytes[relative:relative+20]
                uc.mem_write(destination,raw)
                uc.mem_write(FILE+0x10,struct.pack('<I',cursor+count))
                reads.append(dict(offset=cursor,bytes=count,sha256=sha(raw),hex=raw.hex()))
                uc.reg_write(UC_ARM_REG_R0,0)
                uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            elif pc == 0x0038C168:
                divisions.append(dict(numerator=uc.reg_read(UC_ARM_REG_R0),denominator=uc.reg_read(UC_ARM_REG_R1)))
        u.hook_add(UC_HOOK_CODE,code)
        u.reg_write(UC_ARM_REG_R0,CTX)
        u.reg_write(UC_ARM_REG_R1,DIR)
        u.emu_start(0x044B209F,RET+2,count=30000,timeout=1000000)
        need(stopped == [True] and u.reg_read(UC_ARM_REG_R0) == 0 and word(DIR) == 6,'Candidate native directory did not return six')
        result = bytes(u.mem_read(DIR,172))
        decoded = []
        for index in range(6):
            record = result[4+index*28:4+(index+1)*28]
            q,b,s,n = struct.unpack_from('<4I',record)
            widths,flags = list(record[16:24]),list(record[24:26])
            raw_s,raw_n,raw_b,w,x = struct.unpack_from('<5I',directory_bytes,index*20)
            expected_widths = [(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
            need((q,b,s,n,widths,flags) == (raw_n*8//raw_b,raw_b,raw_s,raw_n,expected_widths,[(w>>30)&1,(w>>31)&1]),
                 'Original candidate directory disagrees with direct wire decoding')
            decoded.append(dict(level=index+1,count=q,record_bits=b,start=s,bytes=n,widths=widths,flags=flags))
        need(len(reads) == 6 and len(divisions) == 6 and decoded[3]['count'] == 2134041,
             'Candidate new level4 count unexpected')
        return result,decoded,dict(original_entry='0x044B209E',returned=True,return_code=0,
            parser_output_chained=True,actual_directory_output_hex=result.hex(),decoded=decoded,
            filesystem_reads=reads,original_divisions=divisions,instructions=len(trace)-1,
            trace_sha256=sha(json.dumps(trace,sort_keys=True).encode()),original_RX_pages=pages)

    def record(self,directory,layout,lowid,raw,offset,initial,expected):
        u,pages = self.machine([0x044B1000,0x0448E000,0x0448F000,0x00307000,
                               0x001C8000,0x00112000,0x00427000,0x00373000])
        u.mem_write(DIR,directory)
        u.mem_write(DIR+0x154,struct.pack('<I',CTX))
        u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0))
        u.mem_write(FILE+0xc,struct.pack('<2I',92655088,0))
        u.mem_write(BUF,raw)
        u.mem_protect(BUF,4096,UC_PROT_READ)
        w,f = layout['widths'],layout['flags']
        seq = [(8,w[4],True),(28,w[3],bool(f[1])),(16,w[3],bool(f[0])),
               (0,w[0],bool(w[0])),(12,w[5],bool(w[5])),(4,w[1],bool(w[1])),
               (20,w[2],bool(w[2])),(24,w[2],bool(w[2]))]
        bits,cursor,model,projection = int.from_bytes(raw,'little'),initial,{},[]
        for outoffset,width,enabled in seq:
            wire = (bits>>cursor)&((1<<width)-1) if enabled else None
            value = wire if enabled else (0xffffffff if outoffset in [16,28] else 0)
            if enabled and outoffset in [16,28] and value == (1<<width)-1:
                value = 0xffffffff
            if enabled: cursor += width
            model[f'+{outoffset:02x}'] = value
            projection.append(dict(offset=outoffset,width=width,enabled=enabled,bits_consumed=cursor-initial,wire=wire))
        need(cursor-initial == layout['record_bits'] and model == expected,'Candidate bytes differ from source expectation')
        trace,mappings,progress,stopped = [],[],[],[]
        boundaries = {0x044B1190:8,0x044B11DE:28,0x044B122E:16,0x044B1268:0,
                      0x044B12A4:12,0x044B12DE:4,0x044B1314:20,0x044B1344:24}
        def word(a): return struct.unpack('<I',u.mem_read(a,4))[0]
        def observe(uc,pc,size,_):
            trace.append(dict(pc=hex(pc),hex=bytes(uc.mem_read(pc,size)).hex()))
            if pc == 0x00112194:
                fp,destination,mode = [uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
                need(fp == FILE and word(FILE+0x10) == offset and mode == 0 and not mappings,'Record FS fixture outside assigned candidate slice')
                uc.mem_write(destination,struct.pack('<I',BUF))
                uc.reg_write(UC_ARM_REG_R0,len(raw))
                mappings.append(dict(offset=offset,bytes=len(raw),sha256=sha(raw)))
                uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            elif pc in boundaries:
                reader = uc.reg_read(UC_ARM_REG_SP)+0x10
                consumed = (word(reader+8)-offset)*8-word(reader)-initial
                progress.append(dict(offset=boundaries[pc],bits_consumed=consumed))
            elif pc == PREFIX_STOP:
                stopped.append(True)
                uc.emu_stop()
            elif pc == RET:
                raise ValueError('Unexpected full reader return')
        u.hook_add(UC_HOOK_CODE,observe)
        for reg,value in [(UC_ARM_REG_R0,DIR),(UC_ARM_REG_R1,lowid),(UC_ARM_REG_R2,layout['level']),(UC_ARM_REG_R3,OUT)]:
            u.reg_write(reg,value)
        u.emu_start(RECORD_ENTRY|1,RET+2,count=30000,timeout=1000000)
        output = bytes(u.mem_read(OUT,32))
        expected_bytes = b''.join(struct.pack('<I',expected[f'+{k:02x}']) for k in range(0,32,4))
        need(stopped == [True] and output == expected_bytes and len(mappings) == 1 and len(progress) == 8,
             'Native candidate record prefix mismatch')
        need(all((p['offset'],p['bits_consumed']) == (q['offset'],q['bits_consumed']) for p,q in zip(progress,projection)),
             'Native original bit progress disagrees with wire plan')
        # Separate genuine original rescale fragment, with source-backed TRE
        # input; no attempt to manufacture the intervening metadata success.
        v,suffix_pages = self.machine([0x044B1000])
        v.mem_write(DIR+0x154,struct.pack('<I',CTX))
        v.mem_write(CTX+0x3f4,struct.pack('<I',OBJECT))
        v.mem_write(OBJECT+0x68,b'\0')
        v.mem_write(OBJECT+0x56,b'\x18')
        v.reg_write(UC_ARM_REG_R7,DIR+0x140)
        field_trace,field_stop = [],[]
        def field_hook(uc,pc,size,_):
            if pc == 0x044B136A:
                field_stop.append(True); uc.emu_stop(); return
            field_trace.append(dict(pc=hex(pc),hex=bytes(uc.mem_read(pc,size)).hex()))
        hook = v.hook_add(UC_HOOK_CODE,field_hook)
        v.emu_start(0x044B1355,0x044B136E,count=100,timeout=100000)
        v.hook_del(hook)
        parameter = struct.unpack('<I',v.mem_read(STACK+0x300c,4))[0]
        need(field_stop == [True] and parameter == 24,'Native source-field parameter mismatch')
        v.mem_write(OUT,output)
        v.reg_write(UC_ARM_REG_R4,OUT)
        suffix_trace,suffix_stop = [],[]
        def suffix_hook(uc,pc,size,_):
            if pc == 0x044B1384:
                suffix_stop.append(True); uc.emu_stop(); return
            suffix_trace.append(dict(pc=hex(pc),hex=bytes(uc.mem_read(pc,size)).hex()))
        v.hook_add(UC_HOOK_CODE,suffix_hook)
        v.emu_start(0x044B1373,0x044B1388,count=100,timeout=100000)
        scaled = struct.unpack('<8I',v.mem_read(OUT,32))
        need(suffix_stop == [True] and scaled[5:7] == tuple(expected[k]<<8 for k in ['+14','+18']),
             'Original raw24 suffix differs')
        return dict(level=layout['level'],lowID=lowid,MDR_offset=offset,initial_bit_offset=initial,
            candidate_payload_hex=raw.hex(),candidate_payload_sha256=sha(raw),actual_native_fields=model,
            actual_native_output_hex=output.hex(),actual_bit_progress=progress,original_instructions=len(trace)-1,
            trace_sha256=sha(json.dumps(trace,sort_keys=True).encode()),underlying_FS_fixture=mappings[0],
            original_RX_pages=pages,stop_before_metadata=hex(PREFIX_STOP),
            coordinate_suffix=dict(explicit_source_backed_TRE_instance_input=True,parameter=parameter,
                actual_rescaled_fields=list(scaled[5:7]),field_trace=field_trace,shift_trace=suffix_trace,
                original_RX_pages=suffix_pages,independent_fragment_not_full_reader_continuation=True))


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--candidate',type=Path,default=ROOT/'staging/navigation-native-address-supplement-v1/candidate/gmapprom1.img')
    args.add_argument('--manifest',type=Path,required=True)
    opt = args.parse_args()
    opt.candidate = opt.candidate.resolve()
    opt.manifest = opt.manifest.resolve()
    proof_path = HERE/'candidate-original-CPU-proof-v1.json'
    need(not proof_path.exists(),'Refuse overwrite terminal proof')
    manifest_raw = opt.manifest.read_bytes()
    manifest = json.loads(manifest_raw)
    dependencies = []
    parser_source = ROOT/'staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py'
    lbl_source = ROOT/'staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py'
    # Frozen methods are imported; their historical main()/cases never run.
    parser_module = frozen_module(str(parser_source.relative_to(ROOT)),'0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349','old_parser_methods',dependencies)
    lbl_module = frozen_module(str(lbl_source.relative_to(ROOT)),'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','old_LBL_methods',dependencies)
    cpu = CPU(NativeImage())
    candidate = CandidateIMG(opt.candidate)
    try:
        header_witness,header = candidate.read('00004171.MDR',0,772,'new_candidate_MDR_header')
        need(struct.unpack_from('<H',header)[0] == 772 and header[2:12] == b'GARMIN MDR','Expected candidate MDR header absent')
        parser = parser_module.invoke(cpu.image,header,'new_one_street_candidate')
        need(parser['success'] and parser['native_context_offset2b8'] == 20 and parser['native_context_offset2c0'] == 6,
             'New candidate native header parser did not find six directory records')
        start = struct.unpack_from('<I',bytes.fromhex(parser['native_context_slice280_2c4']),0x34)[0]
        need(start == 92654968,'Unexpected candidate native directory start')
        directory_witness,directory_bytes = candidate.read('00004171.MDR',start,120,'new_candidate_directory')
        directory,layouts,directory_proof = cpu.directory(parser,directory_bytes,start)
        need(candidate.components['00004171.MDR']['bytes'] == 92655088,'Unexpected candidate MDR length')
        stock_raw = (ROOT/'staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json').read_bytes()
        need(sha(stock_raw) == 'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53','Stock street expectation changed')
        stock = json.loads(stock_raw)
        street_expected = next(c for c in stock['cases'] if c['explicit_low28_ID'] == STREET)['native_unnamed_fields'].copy()
        street_expected.update({'+00':FIRST,'+0c':COUNT})
        witness_raw = (ROOT/'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json').read_bytes()
        need(sha(witness_raw) == '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774','Stock184 expectation changed')
        old184 = json.loads(witness_raw)['strict_184_matches'][0]
        dependencies.extend([dict(path='staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json',sha256=sha(stock_raw),old_cases_not_replayed=True),
                             dict(path='staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json',sha256=sha(witness_raw),old_cases_not_replayed=True)])
        # Root producer supplies an OSM source expectation for each new leaf.
        # Schema is deliberately narrow; no expected output is inferred from
        # the candidate itself or made successful by a helper hook.
        rows = [r for r in manifest['records'] if r.get('oldID') is None]
        need(len(rows) == 9,'Exactly nine newly supplied leaf records required')
        mapped184 = [r for r in manifest['records'] if r.get('oldID') == 904780]
        need(len(mapped184) == 1 and mapped184[0]['expected_native_fields'] == old184['host_fields'],
             'Expected preserved184 mapping absent or changed')
        planned = [('relocated_parent_street',3,STREET,street_expected),
                   ('relocated_preserved_house184',4,mapped184[0]['new_lowID'],old184['host_fields'])]
        for row,(ref,label) in zip(rows,REF_LABELS):
            lowid = row['new_lowID']
            need(FIRST <= lowid < FIRST+COUNT and row['primary_ref'] == ref and row['label'] == label,
                 'Root manifest new leaf identity changed')
            fields = {'+00':0,'+04':0,'+08':1,'+0c':0,'+10':ref,'+14':row['raw24'][0],'+18':row['raw24'][1],'+1c':0xffffffff}
            need(fields == row['expected_native_fields'],'Root source field projection changed')
            planned.append(('new_'+label,4,lowid,fields))
        records = []
        for name,level,lowid,expected in planned:
            layout = layouts[level-1]
            bits = (lowid-1)*layout['record_bits']
            offset,initial = layout['start']+bits//8,bits%8
            need((level == 3 and initial == 6 and layout['record_bits'] == 111) or
                 (level == 4 and initial == 0 and layout['record_bits'] == 128),
                 'Assigned packed record layout changed')
            source,raw = candidate.read('00004171.MDR',offset,16,name)
            if name == 'relocated_preserved_house184':
                need(raw.hex() == old184['record_hex'],'Relocated old184 raw bytes changed')
            result = cpu.record(directory,layout,lowid,raw,offset,initial,expected)
            result.update(name=name,candidate_source=source)
            records.append(result)
        lbl_witness,lbl_header = candidate.read('I053061A.GMP',874,661,'new_candidate_LBL_header')
        lbl_parser = lbl_module.parser_case(cpu.read,lbl_header)
        fields = lbl_parser['actual_metadata_fields']
        labels = []
        for result in records:
            reference = result['actual_native_fields']['+10']
            expected_text = '民權路' if result['level'] == 3 else ('184號' if result['name'] == 'relocated_preserved_house184' else result['name'][4:])
            offset = fields['label_start']+(reference<<fields['shift'])
            source,window = candidate.read('I053061A.GMP',offset,64,'native_label_'+str(reference))
            label = lbl_module.fragment_case(cpu.read,reference,fields,window)
            need(label['actual_byte_copy_and_termination_passed'] and label['host_CP950_display_of_actual_native_output'] == expected_text,
                 'Actual original LBL byte loop label mismatch')
            labels.append(dict(record_name=result['name'],expected_text=expected_text,candidate_source=source,actual_partial_CPU=label))
        candidate.close()
        proof = dict(schema='one-street-AP-supplement-native/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            script_sha256=sha(Path(__file__).read_bytes()),stock_MAIN_sha256=EXPECTED,
            candidate=dict(path=str(opt.candidate.relative_to(ROOT)),stat=candidate.before,stat_unchanged=True,
                actual_bounded_file_reads=True,whole_candidate_digest_repeated=False),
            producer_manifest=dict(path=str(opt.manifest.relative_to(ROOT)),sha256=sha(manifest_raw)),dependencies=dependencies,
            new_candidate_MDR_header=header_witness,actual_original_header_parser=parser,
            new_candidate_directory=directory_witness,actual_original_directory=directory_proof,
            exact_new_leaf_count=9,exact_record_case_count=11,records=records,new_candidate_LBL_header=lbl_witness,
            actual_partial_LBL_parser=lbl_parser,actual_partial_LBL_labels=labels,
            actual_candidate_read_log=candidate.log,total_candidate_bytes_read=sum(x['bytes'] for x in candidate.log),
            all_assigned_checks_passed=True,only_function_hooks=['underlying filesystem open 0x1C8682','underlying filesystem read 0x3324B8','underlying filesystem mapping 0x112194'],
            result_metadata_registry_sort_or_policy_hooks=[],device_IO=False,stock_map_or_DB_modified=False,
            full_reader_registry_getter_query_SQL_UI_or_route_executed=False,hardware_search_or_route_verified=False,
            full_Taiwan2026_address_update=False,installable=False,
            remaining_limits=['A bounded nine-address one-street prototype, not a full Taiwan update.',
                'Complete packed reader stops before original metadata lookup; coordinate and LBL code execute separate explicitly staged original fragments.',
                'Original CP950 byte loop retains label bytes; host cp950 decoding supplies text display. Full registry/getter or Unicode UI not run.',
                'Provider flags8/level5/6 records retain producer-preserved bytes but their query/comparator semantics are not established by this bounded probe.',
                'New addresses reuse original labels and mapordinal1; complete house query/sort, DB/JAI lifecycle, routing association and live IMG acceptance remain untested.',
                'No USB, services, installation or hardware navigation actions.'])
        proof_path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(output=str(proof_path.relative_to(ROOT)),proof_sha256=sha(proof_path.read_bytes()),
            all_passed=True,record_cases=len(records),new_leaf_count=9,labels=[x['actual_partial_CPU']['host_CP950_display_of_actual_native_output'] for x in labels],
            native_directory_counts=[x['count'] for x in layouts],candidate_bytes_read=proof['total_candidate_bytes_read'],installable=False),ensure_ascii=False))
    finally:
        if not candidate.stream.closed:
            candidate.stream.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        failure = HERE/'candidate-original-CPU-failure-v1.json'
        if not failure.exists():
            failure.write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),exception=repr(exc)),indent=2)+'\n')
        raise
