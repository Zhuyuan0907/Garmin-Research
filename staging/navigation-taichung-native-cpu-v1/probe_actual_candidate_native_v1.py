#!/usr/bin/env python3
"""Bounded new-candidate native parser/directory/packed-reader/LBL fragments.

No old main/cases, full registry/metadata/query, device I/O, or map copy.
"""
import datetime
import gc
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from unicorn import UC_HOOK_CODE, UC_PROT_READ
from unicorn.arm_const import *

CTX,FILE,DIR,OUT,RET,BUF,STACK = 0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09006000,0x09010000
STREET_IDS = [12924,15867,16707,18164]
CANDIDATE = ROOT/'staging/navigation-taichung-native-candidate-v1/gmapprom1.img'
CANDIDATE_SHA = '3c03d0a09e24165f27b7ed275535552bfb3ea10defe0f492de6f51dfdaf9b00b'
BINDINGS = [
    ('staging/navigation-taichung-native-candidate-v1/proof.json','add307930f04a6f4a7a719ff3b730867f2d4a27037c6ecb2b35767dec32c0621'),
    ('staging/navigation-taichung-address-merge-v1/proof.json','0c9b254f5f508fc525b87517084a858e30e93ccf6052597347e3cfca64ee2e5f'),
    ('staging/navigation-taichung-address-merge-v1/selected-street-ranges.json','d523981764ca8c08c2b088bb39589be760818e28eeee33db21acc1c6d2b76592'),
    ('staging/navigation-taichung-address-merge-v1/new-house-records.jsonl.gz','12da55702df768402d56cf134b29089d878668cf094a370fb724ad669830bb2a'),
    ('staging/navigation-native-address-supplement-v1/manifest.json','042c8a94b9b50b2ea58881016e5196455269934bf4da5f6bd7ade0692e7d80c5'),
]


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def method(relative,expected,name,dependencies):
    path=ROOT/relative
    need(sha(path.read_bytes())==expected,'Sealed method changed:'+relative)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    dependencies.append(dict(path=relative,sha256=expected,historical_main_or_cases_executed=False))
    return module


def projection(raw,layout):
    widths,flags=layout['widths'],layout['flags']
    sequence=[(8,widths[4],True),(28,widths[3],bool(flags[1])),(16,widths[3],bool(flags[0])),
              (0,widths[0],bool(widths[0])),(12,widths[5],bool(widths[5])),(4,widths[1],bool(widths[1])),
              (20,widths[2],bool(widths[2])),(24,widths[2],bool(widths[2]))]
    bits,cursor,model,progress=int.from_bytes(raw,'little'),0,{},[]
    for offset,width,enabled in sequence:
        wire=(bits>>cursor)&((1<<width)-1)if enabled else None
        value=wire if enabled else (0xffffffff if offset in [16,28]else 0)
        if enabled and offset in [16,28]and value==(1<<width)-1:value=0xffffffff
        if enabled:cursor+=width
        model[f'+{offset:02x}']=value
        progress.append(dict(output_offset=offset,width=width,enabled=enabled,wire=wire,bits_consumed=cursor))
    need(cursor==layout['record_bits'],'Candidate directory widths do not sum to declared record stride')
    return model,progress


def directory(cpu,parser,raw,start):
    u,pages=cpu.machine([0x044B2000,0x0448F000,0x001C8000,0x00332000,0x0038C000])
    u.mem_write(CTX+0x280,bytes.fromhex(parser['native_context_slice280_2c4']))
    u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0));u.mem_write(FILE+11,b'\x40')
    trace,reads,divisions,stop=[],[],[],[]
    def word(address):return struct.unpack('<I',u.mem_read(address,4))[0]
    def observe(uc,pc,size,_):
        trace.append((pc,bytes(uc.mem_read(pc,size)).hex()))
        if pc==RET:stop.append(True);uc.emu_stop()
        elif pc==0x003324B8:
            fp,destination,count=[uc.reg_read(r)for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
            cursor=word(FILE+0x10);relative=cursor-start
            need(fp==FILE and count==20 and relative in range(0,120,20),'Directory FS request outside real candidate slice')
            data=raw[relative:relative+20]
            uc.mem_write(destination,data);uc.mem_write(FILE+0x10,struct.pack('<I',cursor+count))
            reads.append(dict(offset=cursor,bytes=count,hex=data.hex(),sha256=sha(data)))
            uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc==0x0038C168:divisions.append(dict(numerator=uc.reg_read(UC_ARM_REG_R0),denominator=uc.reg_read(UC_ARM_REG_R1)))
    hook=u.hook_add(UC_HOOK_CODE,observe)
    u.reg_write(UC_ARM_REG_R0,CTX);u.reg_write(UC_ARM_REG_R1,DIR)
    u.emu_start(0x044B209F,RET+2,count=30000,timeout=1000000)
    need(stop==[True]and u.reg_read(UC_ARM_REG_R0)==0 and word(DIR)==6 and len(reads)==len(divisions)==6,
         'Original candidate directory did not return six decoded entries')
    output=bytes(u.mem_read(DIR,172));layouts=[]
    for index in range(6):
        entry=output[4+index*28:4+(index+1)*28]
        count,bits,span,size=struct.unpack_from('<4I',entry)
        widths,flags=list(entry[16:24]),list(entry[24:26])
        s,n,b,w,x=struct.unpack_from('<5I',raw,index*20)
        directwidths=[(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
        need((count,bits,span,size,widths,flags)==(n*8//b,b,s,n,directwidths,[(w>>30)&1,(w>>31)&1]),
             'Original directory differs from candidate wire fields')
        layouts.append(dict(level=index+1,count=count,record_bits=bits,start=span,bytes=size,widths=widths,flags=flags))
    proof=dict(entry='0x044B209E',returned=True,return_code=0,parser_output_chained=True,actual_output_hex=output.hex(),
        decoded_layouts=layouts,underlying_FS_reads=reads,original_divisions=divisions,instructions=len(trace)-1,
        trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages)
    u.hook_del(hook);del u;gc.collect()
    return output,layouts,proof


def record(cpu,native_directory,layout,ID,raw,offset,component_size,expected_subset):
    model,directprogress=projection(raw,layout)
    need(all(model.get(k)==v for k,v in expected_subset.items()),'Candidate differs from independent producer/source expectation')
    u,pages=cpu.machine([0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000])
    u.mem_write(DIR,native_directory);u.mem_write(DIR+0x154,struct.pack('<I',CTX))
    u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0));u.mem_write(FILE+0xc,struct.pack('<2I',component_size,0))
    # End the exact real slice at an unmapped following page. Actual four
    # following bytes are present; an extra tail prefetch cannot read zeros.
    buffer_pointer=BUF+4096-len(raw)
    u.mem_write(buffer_pointer,raw);u.mem_protect(BUF,4096,UC_PROT_READ)
    trace,mappings,progress,stop=[],[],[],[]
    boundaries={0x044B1190:8,0x044B11DE:28,0x044B122E:16,0x044B1268:0,
                0x044B12A4:12,0x044B12DE:4,0x044B1314:20,0x044B1344:24}
    def word(address):return struct.unpack('<I',u.mem_read(address,4))[0]
    def observe(uc,pc,size,_):
        trace.append((pc,bytes(uc.mem_read(pc,size)).hex()))
        if pc==0x00112194:
            fp,destination,mode=[uc.reg_read(r)for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
            need(fp==FILE and word(FILE+0x10)==offset and mode==0 and not mappings,'Record FS fixture outside actual assigned slice')
            uc.mem_write(destination,struct.pack('<I',buffer_pointer));uc.reg_write(UC_ARM_REG_R0,len(raw))
            mappings.append(dict(offset=offset,bytes=len(raw),sha256=sha(raw),component_bytes=component_size,
                actual_following_candidate_lookahead_bytes=4,mapped_source_tail_at_unmapped_page=True,filesystem_fixture_only=True))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc in boundaries:
            reader=uc.reg_read(UC_ARM_REG_SP)+0x10
            consumed=(word(reader+8)-offset)*8-word(reader)
            progress.append(dict(native_pc=hex(pc),output_offset=boundaries[pc],bits_consumed=consumed))
        elif pc==0x0448F740:stop.append(pc);uc.emu_stop()
        elif pc==RET:raise ValueError('Unexpected complete packed reader return')
    hook=u.hook_add(UC_HOOK_CODE,observe)
    for reg,value in [(UC_ARM_REG_R0,DIR),(UC_ARM_REG_R1,ID),(UC_ARM_REG_R2,layout['level']),(UC_ARM_REG_R3,OUT)]:u.reg_write(reg,value)
    u.emu_start(0x044B10E5,RET+2,count=30000,timeout=1000000)
    output=bytes(u.mem_read(OUT,32))
    actual={f'+{k:02x}':struct.unpack_from('<I',output,k)[0]for k in range(0,32,4)}
    need(stop==[0x0448F740]and len(mappings)==1 and actual==model and len(progress)==8,'Original actual-candidate prefix disagrees')
    need([(p['output_offset'],p['bits_consumed'])for p in progress]==
         [(p['output_offset'],p['bits_consumed'])for p in directprogress],'Native actual-candidate dynamic bit progression differs')
    need(bytes(u.mem_read(buffer_pointer,len(raw)))==raw,'Readonly candidate record fixture mutated')
    result=dict(level=layout['level'],lowID=ID,MDR_offset=offset,initial_bit_offset=0,
        record_bits=layout['record_bits'],real_candidate_record_hex=raw[:layout['record_bits']//8].hex(),
        real_following_4byte_lookahead_hex=raw[-4:].hex(),original_FILE_component_bytes=component_size,
        actual_native_fields=actual,actual_native_output_hex=output.hex(),direct_wire_projection=directprogress,
        independent_producer_expected_fields=expected_subset,actual_native_bit_progress=progress,
        instructions=len(trace)-1,trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages,
        filesystem_mapping=mappings[0],stop_before_metadata='0x0448F740',full_original_reader_return=False)
    u.hook_del(hook);del u;gc.collect()
    return result


def inputs(dependencies):
    bound={};identities={}
    for relative,expected in BINDINGS:
        path=ROOT/relative;identities[relative]=identity(path)
        raw=path.read_bytes();need(sha(raw)==expected,'Producer binding changed:'+relative)
        dependencies.append(dict(path=relative,sha256=expected,old_cases_executed=False))
        if not relative.endswith('.gz'):bound[relative]=json.loads(raw)
    host=bound[BINDINGS[0][0]];merge=bound[BINDINGS[1][0]];ranges=bound[BINDINGS[2][0]];gold=bound[BINDINGS[4][0]]
    need(host['candidate_sha256']==CANDIDATE_SHA and host['candidate_bytes']==100945920 and host['all_assigned_checks_passed'],
         'Root actual readback binding differs')
    selected={r['nativeStreetID']:r for r in ranges if r['nativeStreetID']in STREET_IDS}
    need(set(selected)==set(STREET_IDS),'Missing representative source street')
    houses={ID:[]for ID in STREET_IDS}
    with gzip.open(ROOT/BINDINGS[3][0],'rt')as f:
        for line in f:
            r=json.loads(line)
            if r['nativeStreetID']in houses:houses[r['nativeStreetID']].append(r)
    samples=[]
    for ID in STREET_IDS:
        row=selected[ID]
        need(row['new_first']>merge['original_level4_count']and row['original_flags']&7==4 and
             1<=row['new_count']<=4095,'Selected source range/next4 differs')
        if ID==16707:
            golden=[r for r in gold['records']if r['oldID']is None]
            bylabel={r['house_label']:r for r in houses[ID]}
            need(len(golden)==len(bylabel)==9,'Minquan nine-golden group differs')
            for g in golden:
                r=bylabel[g['label']]
                need((r['payload'],r['primary_ref'],r['raw24'])==(g['payload'],g['primary_ref'],g['raw24']),
                     'Actual broader producer differs from installed golden payload')
                samples.append(dict(**r,golden_installed_trial_control=True))
        else:
            need(houses[ID],'Representative other street has no new address')
            samples.append(dict(**houses[ID][0],golden_installed_trial_control=False))
            if houses[ID][-1]['new_lowID']!=houses[ID][0]['new_lowID']:
                samples.append(dict(**houses[ID][-1],golden_installed_trial_control=False))
    need(len(samples)==14,'Finite new-leaf sample count differs')
    for r in samples:
        parent=selected[r['nativeStreetID']]
        need(parent['new_first']<=r['new_lowID']<parent['new_first']+parent['new_count'],
             'Assigned leaf is outside actual producer street range')
    return host,merge,selected,samples,identities


def main():
    output=HERE/'actual-Taichung-candidate-original-CPU-proof-v1.json'
    need(not output.exists(),'Refuse overwrite terminal CPU scope')
    dependencies=[]
    old=method('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py',
        '2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','sealed_actual_candidate_machine_methods',dependencies)
    parser_method=method('staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py',
        '0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349','sealed_actual_MDR_parser_only',dependencies)
    lbl_method=method('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
        'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','sealed_actual_LBL_fragments_only',dependencies)
    host,merge,selected,samples,input_stats=inputs(dependencies)
    cpu=old.CPU(NativeImage());candidate=old.CandidateIMG(CANDIDATE)
    try:
        need(candidate.before[2]==host['candidate_bytes'],'Actual candidate size differs from root readback receipt')
        header_source,header=candidate.read('00004171.MDR',0,772,'actual_candidate_MDR_header')
        parser=parser_method.invoke(cpu.image,header,'actual_Taichung_width23_candidate')
        gc.collect()
        need(parser['success']and parser['native_context_offset2b8']==20 and parser['native_context_offset2c0']==6,
             'Original header parser rejected new real candidate')
        native_start=struct.unpack_from('<I',bytes.fromhex(parser['native_context_slice280_2c4']),0x34)[0]
        header_start,dbytes,itembytes,dflags=struct.unpack_from('<4I',header,600)
        component_size=candidate.components['00004171.MDR']['bytes']
        need((dbytes,itembytes,dflags)==(120,20,1)and native_start==header_start and native_start+120==component_size,
             'Actual native parser directory start/EOF differs')
        directory_source,raw_directory=candidate.read('00004171.MDR',native_start,120,'actual_candidate_directory')
        native_directory,layouts,directory_proof=directory(cpu,parser,raw_directory,native_start)
        need((layouts[2]['count'],layouts[2]['record_bits'],layouts[2]['widths'],layouts[2]['flags'])==
             (47870,112,[23,9,24,19,1,12,0,0],[1,0]),'Actual original CPU width23 L3 directory differs')
        need(layouts[3]['count']==merge['proposed_level4_count']and layouts[3]['record_bits']==128,
             'Actual original CPU appended L4 count differs')
        need(layouts[2]['start']+layouts[2]['bytes']==layouts[1]['start'],'Actual L3 does not directly precede actual L2')
        records=[]
        for ID in STREET_IDS:
            group=selected[ID];layout=layouts[2]
            offset=layout['start']+(ID-1)*layout['record_bits']//8
            need((ID-1)*layout['record_bits']%8==0,'Width23 L3 is not byte aligned')
            witness,raw=candidate.read('00004171.MDR',offset,18,'native_parent_'+str(ID))
            expected={'+00':group['new_first'],'+0c':group['new_count'],'+04':group['original_flags'],'+08':1}
            result=record(cpu,native_directory,layout,ID,raw,offset,component_size,expected)
            result.update(name='parent_'+str(ID),street_ID=ID,street=group['street'],district=group['district'],
                expected_label=group['street'],candidate_source=witness,source_selected_range=group,
                child_first_above_original_L4_end=True)
            records.append(result)
        for sample in samples:
            layout=layouts[3];ID=sample['new_lowID']
            offset=layout['start']+(ID-1)*layout['record_bits']//8
            witness,raw=candidate.read('00004171.MDR',offset,20,'native_new_leaf_'+str(ID))
            need(raw[:16].hex()==sample['payload'],'Actual candidate leaf bytes differ from producer payload')
            expected={'+00':0,'+04':0,'+08':1,'+0c':0,'+10':sample['primary_ref'],
                '+14':sample['raw24'][0],'+18':sample['raw24'][1],'+1c':0xffffffff}
            result=record(cpu,native_directory,layout,ID,raw,offset,component_size,expected)
            result.update(name='new_leaf_'+str(ID),street_ID=sample['nativeStreetID'],
                expected_label=sample['house_label'],candidate_source=witness,independent_new_house_source=sample,
                record_ID_above_original_L4_end=True,record_offset_above_original_MDR_EOF=offset>92653600)
            records.append(result)
        # Resolve the LBL location from the actual GMP header pointers.
        gmp_source,gmp=candidate.read('I053061A.GMP',0,57,'actual_candidate_GMP_header')
        need(struct.unpack_from('<H',gmp)[0]==57 and gmp[2:12]==b'GARMIN GMP','Actual GMP header differs')
        lbl_start=struct.unpack_from('<7I',gmp,25)[2]
        prefix_source,prefix=candidate.read('I053061A.GMP',lbl_start,2,'actual_candidate_LBL_header_length')
        lbl_size=struct.unpack('<H',prefix)[0]
        need(lbl_size==661,'Actual original LBL public header shape differs')
        tail_source,tail=candidate.read('I053061A.GMP',lbl_start+2,lbl_size-2,'actual_candidate_LBL_header_body')
        lbl_header=prefix+tail
        need(lbl_header[2:12]==b'GARMIN LBL','Actual GMP-derived LBL signature absent')
        lbl_parser=lbl_method.parser_case(cpu.read,lbl_header);gc.collect()
        lbl_fields=lbl_parser['actual_metadata_fields'];labels=[]
        for result in records:
            reference=result['actual_native_fields']['+10']
            offset=lbl_fields['label_start']+(reference<<lbl_fields['shift'])
            witness,window=candidate.read('I053061A.GMP',offset,64,'native_label_'+str(reference))
            native_label=lbl_method.fragment_case(cpu.read,reference,lbl_fields,window);gc.collect()
            need(native_label['actual_byte_copy_and_termination_passed']and
                 native_label['host_CP950_display_of_actual_native_output']==result['expected_label'],
                 'Original actual-candidate GMP/LBL label fragment differs')
            labels.append(dict(record_name=result['name'],expected_text=result['expected_label'],
                source_native_field='+10',native_reference=reference,candidate_source=witness,
                actual_partial_original_CPU=native_label))
        candidate.close()
        for relative,oldstat in input_stats.items():need(identity(ROOT/relative)==oldstat,'Producer source changed:'+relative)
        proof=dict(schema='actual-Taichung-native-candidate-CPU/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            script_sha256=sha(Path(__file__).read_bytes()),stock_MAIN_sha256=EXPECTED,dependencies=dependencies,
            candidate=dict(path=str(CANDIDATE.relative_to(ROOT)),bytes=candidate.before[2],stat=candidate.before,
                stat_unchanged=True,root_actual_readback_sha256_reference=CANDIDATE_SHA,whole_candidate_hash_repeated=False,
                actual_FAT_extent=candidate.extent,only_bounded_actual_candidate_reads=True),
            original_CPU_method_reuse=dict(machine_and_FAT_methods_reused=True,
                historical_directory_and_record_methods_with_single_street_count_size_hardcodes_executed=False,
                new_directory_and_record_source_supplies_actual_candidate_count_size=True,historical_main_or_cases_executed=False),
            actual_candidate_MDR_header=header_source,actual_original_header_parser=parser,
            actual_candidate_directory=directory_source,actual_original_directory=directory_proof,
            directory_positions_derived_from_actual_native_parser=True,record_offsets_derived_from_actual_native_directory=True,
            exact_new_parent_count=4,exact_new_leaf_count=14,Minquan_golden_leaf_count=9,
            exact_native_record_prefix_count=len(records),records=records,
            actual_GMP_header=gmp_source,actual_GMP_derived_LBL_start=lbl_start,
            actual_LBL_header_length_source=prefix_source,actual_LBL_header_body_source=tail_source,
            actual_partial_LBL_parser=lbl_parser,actual_partial_LBL_labels=labels,
            actual_candidate_read_log=candidate.log,total_actual_candidate_bytes_read=sum(x['bytes']for x in candidate.log),
            all_assigned_checks_passed=True,only_function_hooks=['underlying FS open0x1C8682','underlying FS read0x3324B8',
                'underlying FS mapping0x112194'],metadata_registry_query_sort_result_or_policy_hooks=[],
            successful_records_stop_before_metadata='0x0448F740',full_reader_getter_query_UI_or_route_executed=False,
            device_IO=False,installation_performed=False,canonical_or_ZIP_or_services_mutated=False,
            complete_Taiwan_native_update=False,complete_candidate_acceptance_asserted=False,old_closed_suites_replayed=False,
            limits=['The true width23/stride112 candidate profile executed for four selected parents and14newleaves only. All sampled child IDs exceed original2133948; numeric firstchildren remain below4194304, so this is not a new high23rd-bit boundary test.',
                'Native header context feeds the original directory decoder; decoded original directory feeds the original packed reader. Only filesystem functions supply actual candidate bytes.',
                'Every successful packed reader stops before mapmetadata/registry0x0448F740; no successful full metadata/getter/query or UI result is fabricated.',
                'GMP pointer and LBL header come from actual candidate bytes. LBL parser/address/copy code are separately staged original fragments, not a continued complete registry getter; host CP950 decoding displays the actual copied bytes.',
                'Leaf raw24 coordinates and existing references match independent producer input. Parent first/count/flags and original names match the producer ranges; other parent raw fields are CPU/direct-wire checks plus root existing preservation evidence.',
                'Root already performed whole candidate hash/readback; this probe uses that sealed reference and verifies finite bytes/stat only, without rereading all47870fields/all1693groups or copying the map.',
                'Search order, JAI/SQL/provider lifecycle, unchanged next5/next6 query behavior, physical file acceptance/search/routing and complete Taiwan coverage are outside this bounded scope.'])
        output.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),all_passed=True,
            native_records=len(records),new_leaves=14,golden_leaves=9,parent_firstchildren=[r['actual_native_fields']['+00']for r in records if r['level']==3],
            actual_native_L3_width=layouts[2]['widths'][0],actual_native_L3_stride=layouts[2]['record_bits'],
            native_L4_count=layouts[3]['count'],candidate_bytes_read=proof['total_actual_candidate_bytes_read'],
            full_native_query_executed=False,device_IO=False),ensure_ascii=False))
    finally:
        if not candidate.stream.closed:candidate.stream.close()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        failed=HERE/'unfinalized-failure-v1.json'
        if not failed.exists():failed.write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_sha256=sha(Path(__file__).read_bytes()),exception=repr(exc),terminal_proof_written=False),indent=2)+'\n')
        raise
