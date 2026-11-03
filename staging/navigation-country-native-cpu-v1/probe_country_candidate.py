#!/usr/bin/env python3
"""New finite actual-country candidate native CPU scope, including bit offsets.

Original MDR header → six-entry directory → packed prefixes. Genuine candidate
bytes alone supply FS fixtures. Stop before metadata; stage actual GMP/LBL
fragments separately. No query result, device I/O, old suite or whole IMG copy.
"""
import datetime
import gc
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from unicorn import UC_HOOK_CODE, UC_PROT_READ
from unicorn.arm_const import *

CTX,FILE,DIR,OUT,RET,BUF,STACK=0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09006000,0x09010000
CANDIDATE=ROOT/'staging/navigation-country-native-candidate-v1/gmapprom1.img'
CANDIDATE_SHA='a2e3d43ae33307e6e81bd6f724314a5e03af82082cf453d0aa20cdc4c81b12fa'
CANDIDATE_BYTES=121823232
BINDINGS=[
 ('staging/navigation-country-native-candidate-v1/proof.json','35e7ad97a163fa22d256026ad50fff6ee15c1e9685698597b5336950a2ba8b47'),
 ('staging/navigation-country-native-candidate-v1/mdr-plan.json','c4bfd65f68b1318569f0f2d1bb16612fca9db4e189de4cd4255c94a1e5651ac6'),
 ('staging/navigation-country-native-house-merge-v1/proof.json','bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41'),
 ('staging/navigation-country-native-house-merge-v1/selected-street-ranges.json','dd42c0e57c96f61ed6d93f0309b4fdd5ae6c98652a937163fd61f494b8e7bbaa'),
 ('staging/navigation-country-native-house-merge-v1/new-house-records.jsonl.gz','34b4f509a89bd8f413e101d1b60c261d678a9c29723c99e96bdc124bdf34fd33'),
 ('staging/navigation-native-address-supplement-v1/manifest.json','042c8a94b9b50b2ea58881016e5196455269934bf4da5f6bd7ade0692e7d80c5')]

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def identity(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def method(relative,expected,name,dependencies):
    path=ROOT/relative;before=identity(path);raw=path.read_bytes()
    need(sha(raw)==expected and identity(path)==before,'Sealed reused source changed')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module)
    dependencies.append(dict(path=relative,sha256=expected,historical_main_or_cases_executed=False))
    return module

def producer_inputs():
    data={}; receipts=[]; stats={}
    for relative,expected in BINDINGS:
        path=ROOT/relative;before=identity(path);raw=path.read_bytes()
        need(sha(raw)==expected and identity(path)==before,'Actual producer binding changed:'+relative)
        need(len(raw)<16_000_000,'Small prepared input ceiling')
        stats[relative]=before
        receipts.append(dict(path=relative,bytes=len(raw),sha256=expected,stat_before=before,
            stat_unchanged=True,prepared_producer_artifact_only=True))
        data[relative]=raw if relative.endswith('.gz') else json.loads(raw)
    host,plan,merge,ranges,ledger,golden=(data[x[0]] for x in BINDINGS)
    need(host['all_assigned_checks_passed'] and host['candidate_sha256']==CANDIDATE_SHA
         and host['candidate_bytes']==CANDIDATE_BYTES,'Root actual candidate receipt binding')
    need(merge['all_assigned_checks_passed'] and merge['counts']['new_integer_house_records']==111608,
         'Actual merge proof binding')
    selected={r['nativeStreetID']:r for r in ranges}
    need(len(selected)==15679,'Exact selected street range count')
    # Deterministic finite selection: first new next4 house from street1142,
    # country Minquan6/150, first L5 new house at each actual bit offset0/2/4/6,
    # first L6 new house at offset0/4, and final source new L5/L6 records.
    samples={}; last={}; rows=0
    with gzip.GzipFile(fileobj=io.BytesIO(ledger),mode='rb') as f:
        for line in f:
            r=json.loads(line);rows+=1;level=r['next_level']
            need(level in (4,5,6),'Prepared leaf level')
            shift=((r['new_lowID']-1)*merge['strides'][str(level)])%8
            if level==4 and r['nativeStreetID']==1142:samples.setdefault('next4_first',r)
            if level==4 and r['nativeStreetID']==16707 and r['house_label'] in ('6號','150號'):
                samples['country_Minquan_'+r['house_label']]=r
            if level==5:samples.setdefault('next5_shift'+str(shift),r);last[5]=r
            if level==6:samples.setdefault('next6_shift'+str(shift),r);last[6]=r
    need(rows==111608 and set(samples)=={'next4_first','country_Minquan_6號','country_Minquan_150號',
         'next5_shift0','next5_shift2','next5_shift4','next5_shift6','next6_shift0','next6_shift4'},
         'Finite actual prepared selection lacks required packed offsets')
    for level,r in last.items():samples['next%d_final_source_new_house'%level]=r
    unique={}
    for name,r in samples.items():
        key=(r['next_level'],r['new_lowID'])
        unique.setdefault(key,dict(sample=r,selection_names=[]))['selection_names'].append(name)
    samples=list(unique.values()); parents={}
    need(9<=len(samples)<=11,'Finite leaf cap')
    golden_by_label={r['label']:r for r in golden['records'] if r['oldID'] is None}
    for s in samples:
        r=s['sample'];p=selected[r['nativeStreetID']];parents[r['nativeStreetID']]=p
        need(p['next_level']==r['next_level'] and p['original_flags']==p['next_level']
             and p['new_first']<=r['new_lowID']<p['new_first']+p['new_count']
             and p['new_first']>merge['original_counts'][str(p['next_level'])],
             'Actual new house is within unchanged branch-type selected parent')
        if r['nativeStreetID']==16707:
            g=golden_by_label[r['house_label']]
            need((r['payload'],r['primary_ref'],r['raw24'])==(g['payload'],g['primary_ref'],g['raw24']),
                 'Country Minquan actual producer differs from installed golden source')
    need({p['next_level'] for p in parents.values()}=={4,5,6} and len(parents)<=11,'Finite multilevel parents')
    return host,plan,merge,parents,samples,stats,receipts


def native_record(cpu,reused,native_directory,layout,ID,raw,offset,component_size,expected_subset):
    stride=layout['record_bits'];initial=((ID-1)*stride)%8
    span=(initial+stride+7)//8
    need(len(raw)==span+4 and 0<=initial<8,'Exact real packed span and four following candidate bytes')
    wire_value=(int.from_bytes(raw[:span],'little')>>initial)&((1<<stride)-1)
    normalized=wire_value.to_bytes((stride+7)//8,'little')
    # Direct projection is for comparison only. Native FS receives the original
    # non-realigned raw bytes; its own ID arithmetic performs the bit skip.
    model,directprogress=reused.projection(normalized,layout)
    need(all(model.get(k)==v for k,v in expected_subset.items()),'Actual wire differs from independent producer')
    u,pages=cpu.machine([0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000])
    u.mem_write(DIR,native_directory);u.mem_write(DIR+0x154,struct.pack('<I',CTX))
    u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0));u.mem_write(FILE+0xc,struct.pack('<2I',component_size,0))
    buffer_pointer=BUF+4096-len(raw)
    u.mem_write(buffer_pointer,raw);u.mem_protect(BUF,4096,UC_PROT_READ)
    trace,mappings,progress,stop=[],[],[],[]
    boundaries={0x044B1190:8,0x044B11DE:28,0x044B122E:16,0x044B1268:0,
                0x044B12A4:12,0x044B12DE:4,0x044B1314:20,0x044B1344:24}
    def word(address):return struct.unpack('<I',u.mem_read(address,4))[0]
    def observe(uc,pc,size,_):
        trace.append((pc,bytes(uc.mem_read(pc,size)).hex()))
        if pc==0x00112194:
            fp,destination,mode=[uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
            need(fp==FILE and word(FILE+0x10)==offset and mode==0 and not mappings,'FS mapping outside real assigned candidate slice')
            uc.mem_write(destination,struct.pack('<I',buffer_pointer));uc.reg_write(UC_ARM_REG_R0,len(raw))
            mappings.append(dict(offset=offset,bytes=len(raw),sha256=sha(raw),component_bytes=component_size,
                real_initial_bit_offset=initial,record_fixture_realigned=False,
                actual_following_candidate_bytes=4,tail_at_unmapped_page=True,filesystem_fixture_only=True))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc in boundaries:
            reader=uc.reg_read(UC_ARM_REG_SP)+0x10
            wire_consumed=(word(reader+8)-offset)*8-word(reader)
            progress.append(dict(native_pc=hex(pc),output_offset=boundaries[pc],
                wire_bits_consumed=wire_consumed,record_bits_consumed=wire_consumed-initial))
        elif pc==0x0448F740:stop.append(pc);uc.emu_stop()
        elif pc==RET:raise ValueError('Unexpected completed full record/metadata return')
    hook=u.hook_add(UC_HOOK_CODE,observe)
    for reg,value in [(UC_ARM_REG_R0,DIR),(UC_ARM_REG_R1,ID),(UC_ARM_REG_R2,layout['level']),(UC_ARM_REG_R3,OUT)]:u.reg_write(reg,value)
    u.emu_start(0x044B10E5,RET+2,count=30000,timeout=1000000)
    output=bytes(u.mem_read(OUT,32));actual={f'+{k:02x}':struct.unpack_from('<I',output,k)[0] for k in range(0,32,4)}
    need(stop==[0x0448F740] and len(mappings)==1 and actual==model and len(progress)==8,'Original actual-country prefix disagrees')
    need([(p['output_offset'],p['record_bits_consumed']) for p in progress]==
         [(p['output_offset'],p['bits_consumed']) for p in directprogress],
         'Original actual-country dynamic bit progression differs')
    need(bytes(u.mem_read(buffer_pointer,len(raw)))==raw,'Candidate readonly fixture mutated')
    result=dict(level=layout['level'],lowID=ID,MDR_offset=offset,initial_bit_offset=initial,record_bits=stride,
        real_candidate_span_hex=raw[:span].hex(),significant_wire_record_normalized_for_comparison_hex=normalized.hex(),
        real_following_4byte_lookahead_hex=raw[span:].hex(),actual_native_fields=actual,
        actual_native_output_hex=output.hex(),direct_wire_projection=directprogress,
        independent_producer_expected_fields=expected_subset,actual_native_bit_progress=progress,
        instructions=len(trace)-1,trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages,
        filesystem_mapping=mappings[0],stop_before_metadata='0x0448F740',full_original_reader_return=False)
    u.hook_del(hook);del u;gc.collect()
    return result


def main():
    output=HERE/'proof.json';need(not output.exists(),'New terminal proof only')
    started=datetime.datetime.now(datetime.timezone.utc).isoformat(); t0=time.monotonic();dependencies=[]
    reused=method('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py',
        'bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','sealed_country_directory_projection_methods',dependencies)
    old=method('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py',
        '2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','sealed_country_machine_FS_methods',dependencies)
    parser_method=method('staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py',
        '0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349','sealed_country_MDR_parser_fragment',dependencies)
    lbl_method=method('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
        'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','sealed_country_LBL_fragments',dependencies)
    host,plan,merge,parents,samples,input_stats,input_receipts=producer_inputs()
    cpu=old.CPU(NativeImage());candidate=old.CandidateIMG(CANDIDATE)
    try:
        need(candidate.before[2]==CANDIDATE_BYTES and candidate.block_size==4096,'Actual candidate geometry/size')
        header_source,header=candidate.read('00004171.MDR',0,772,'actual_country_MDR_header')
        parser=parser_method.invoke(cpu.image,header,'actual_country_width23_candidate');gc.collect()
        need(parser['success'] and parser['native_context_offset2b8']==20 and parser['native_context_offset2c0']==6,'Original actual-country header parser failed')
        native_start=struct.unpack_from('<I',bytes.fromhex(parser['native_context_slice280_2c4']),0x34)[0]
        header_start,dbytes,itembytes,dflags=struct.unpack_from('<4I',header,600)
        component_size=candidate.components['00004171.MDR']['bytes']
        need((dbytes,itembytes,dflags)==(120,20,1) and native_start==header_start and native_start+120==component_size,
             'Actual parser/directory/EOF relationship')
        directory_source,raw_directory=candidate.read('00004171.MDR',native_start,120,'actual_country_MDR_directory')
        native_directory,layouts,directory_proof=reused.directory(cpu,parser,raw_directory,native_start)
        for layout,expected in zip(layouts,plan['new_tables']):
            need((layout['start'],layout['bytes'],layout['record_bits'],layout['count'],layout['widths'],layout['flags'])==
                 (expected['start'],expected['bytes'],expected['stride'],expected['count'],expected['widths'],expected['flags']),
                 'Original decoded actual directory differs from independent writer plan')
        need(layouts[2]['record_bits']==112 and layouts[2]['widths'][0]==23,'Actual native dynamic width23')
        records=[]
        for ID,group in sorted(parents.items()):
            layout=layouts[2];offset=layout['start']+(ID-1)*layout['record_bits']//8
            witness,raw=candidate.read('00004171.MDR',offset,18,'actual_country_parent_'+str(ID))
            expected={'+00':group['new_first'],'+0c':group['new_count'],'+04':group['original_flags'],'+08':1}
            result=native_record(cpu,reused,native_directory,layout,ID,raw,offset,component_size,expected)
            result.update(name='parent_'+str(ID),street_ID=ID,expected_label=group['street'],candidate_source=witness,
                source_selected_range=group,next_child_level=group['next_level'],
                child_first_above_corresponding_original_table_end=True)
            records.append(result)
        for selected in samples:
            sample=selected['sample'];level=sample['next_level'];layout=layouts[level-1];ID=sample['new_lowID']
            bit=(ID-1)*layout['record_bits'];offset=layout['start']+bit//8
            length=((bit%8)+layout['record_bits']+7)//8+4
            witness,raw=candidate.read('00004171.MDR',offset,length,'actual_country_new_L%d_leaf_%d'%(level,ID))
            significant=((int.from_bytes(raw,'little')>>(bit%8))&((1<<layout['record_bits'])-1)).to_bytes((layout['record_bits']+7)//8,'little')
            need(significant.hex()==sample['payload'],'Actual tightly-packed new house differs from independently padded producer payload')
            expected={'+00':0,'+04':0,'+08':1,'+0c':0,'+10':sample['primary_ref'],
                '+14':sample['raw24'][0],'+18':sample['raw24'][1],'+1c':0xffffffff}
            result=native_record(cpu,reused,native_directory,layout,ID,raw,offset,component_size,expected)
            result.update(name='new_L%d_leaf_%d'%(level,ID),street_ID=sample['nativeStreetID'],expected_label=sample['house_label'],
                candidate_source=witness,independent_prepared_new_house_source=sample,
                selection_names=selected['selection_names'],record_ID_above_corresponding_original_table_end=True)
            records.append(result)
        gmp_source,gmp=candidate.read('I053061A.GMP',0,57,'actual_country_GMP_header')
        need(struct.unpack_from('<H',gmp)[0]==57 and gmp[2:12]==b'GARMIN GMP','Actual GMP header')
        lbl_start=struct.unpack_from('<7I',gmp,25)[2]
        prefix_source,prefix=candidate.read('I053061A.GMP',lbl_start,2,'actual_country_LBL_length')
        lbl_size=struct.unpack('<H',prefix)[0];need(lbl_size==661,'Actual LBL public shape')
        tail_source,tail=candidate.read('I053061A.GMP',lbl_start+2,lbl_size-2,'actual_country_LBL_header_body')
        need((prefix+tail)[2:12]==b'GARMIN LBL','Actual GMP-derived LBL signature')
        lbl_parser=lbl_method.parser_case(cpu.read,prefix+tail);gc.collect();fields=lbl_parser['actual_metadata_fields'];labels=[]
        for result in records:
            ref=result['actual_native_fields']['+10'];offset=fields['label_start']+(ref<<fields['shift'])
            witness,window=candidate.read('I053061A.GMP',offset,64,'actual_country_native_label_'+str(ref))
            label=lbl_method.fragment_case(cpu.read,ref,fields,window);gc.collect()
            need(label['actual_byte_copy_and_termination_passed'] and
                 label['host_CP950_display_of_actual_native_output']==result['expected_label'],
                 'Original actual country GMP/LBL label fragment differs')
            labels.append(dict(record_name=result['name'],native_reference=ref,candidate_source=witness,
                source_native_field='+10',expected_text=result['expected_label'],actual_partial_original_CPU=label))
        candidate.close()
        for relative,before in input_stats.items():need(identity(ROOT/relative)==before,'Producer artifacts immutable')
        reads=sum(x['bytes'] for x in candidate.log);need(reads<160000,'Bounded actual-candidate byte ceiling')
        proof=dict(schema='actual-country-native-candidate-CPU/v1',started_utc=started,
            finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-t0,
            all_assigned_checks_passed=True,script_sha256=sha(Path(__file__).read_bytes()),stock_MAIN_sha256=EXPECTED,
            dependencies=dependencies,prepared_producer_inputs=input_receipts,
            producer_input_scope='Prepared selected ranges/new-house records only; no PBF, source node/group or country-ready ledgers reopened.',
            candidate=dict(path=str(CANDIDATE.relative_to(ROOT)),bytes=candidate.before[2],stat_before=candidate.before,
                stat_after=identity(CANDIDATE),stat_unchanged=True,inherited_root_readback_sha256=CANDIDATE_SHA,
                whole_candidate_hash_repeated=False,FAT_extent=candidate.extent,block_size=candidate.block_size),
            actual_MDR_header_source=header_source,actual_original_header_parser=parser,
            actual_directory_source=directory_source,actual_original_directory=directory_proof,
            directory_position_from_actual_native_parser=True,record_positions_from_actual_native_directory=True,
            original_CPU_reuse='Sealed machine, logical-FAT reader, directory and direct projection functions only; old main/record/cases not executed.',
            exact_parent_count=len(parents),exact_new_leaf_count=len(samples),exact_record_prefix_count=len(records),
            selected_parent_nextlevels={str(level):sum(p['next_level']==level for p in parents.values()) for level in (4,5,6)},
            leaf_initial_bit_offsets_by_level={str(level):sorted({r['initial_bit_offset'] for r in records if r['level']==level}) for level in (4,5,6)},
            actual_native_records=records,actual_GMP_source=gmp_source,actual_GMP_derived_LBL_header_offset=lbl_start,
            actual_LBL_length_source=prefix_source,actual_LBL_body_source=tail_source,
            actual_partial_LBL_parser=lbl_parser,actual_partial_LBL_labels=labels,
            actual_candidate_read_log=candidate.log,total_actual_candidate_bytes_read=reads,
            only_function_hooks=['underlying FS open0x1C8682','underlying FS read0x3324B8','underlying FS mapping0x112194'],
            metadata_registry_query_sort_result_or_policy_hooks=[],stop_before_metadata='0x0448F740',
            full_reader_getter_query_UI_or_route_executed=False,device_IO=False,installation_performed=False,
            whole_image_copied=False,canonical_ZIP_or_services_mutated=False,old_closed_suites_replayed=False,
            complete_Taiwan_native_update=False,complete_candidate_acceptance_asserted=False,
            limits=['Finite original parser/directory/packed-prefix execution. Full metadata/registry/query/UI/search order/JAI/provider lifecycle untested.',
                'Actual nonbyte L5/L6 bytes feed original ID/stride bit arithmetic unchanged; significant normalized bytes are direct comparison only.',
                'GMP/LBL fragments separately stage original header/address/copy instructions after actual packed-prefix refs. No complete registry getter continuation is supplied.',
                'Real parent first/count/rawflags and new leaves refs/raw24 agree with sealed producer values. Host display CP950 interprets native copied bytes.',
                'All selected parent firstchildren exceed their old table count and remain below4194304; prior synthetic width boundary evidence is not replayed or relabeled as this actual map.',
                'Root already completed full SHA/readback. This scope bounds actual bytes and immutable stat; it does not replay root whole-field/group readback.',
                'Original flags13 unchanged and not among selected rewrites. Unknown high flag semantics, source point entrance correctness, physical file acceptance/search/route and pending cities/streets/lanes/subnumbers remain unproved.'])
        output.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        receipt=dict(exit_status=0,started_utc=started,finished_utc=proof['finished_utc'],elapsed_seconds=proof['elapsed_seconds'],
            source_sha256=proof['script_sha256'],proof_sha256=sha(output.read_bytes()),native_parent_count=len(parents),
            native_new_leaf_count=len(samples),total_actual_candidate_bytes_read=reads,source_stat_unchanged=True)
        (HERE/'execution-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,proof_sha256=sha(output.read_bytes()),native_parents=len(parents),
            native_new_leaves=len(samples),parent_nextlevels=proof['selected_parent_nextlevels'],
            leaf_bit_offsets=proof['leaf_initial_bit_offsets_by_level'],candidate_bytes_read=reads,
            elapsed_seconds=proof['elapsed_seconds'],full_native_query_executed=False,device_IO=False)))
    finally:
        if not candidate.stream.closed:candidate.stream.close()

if __name__=='__main__':
    try:main()
    except Exception as exc:
        failed=HERE/'unfinalized-failure-v1.json'
        if not failed.exists():failed.write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_sha256=sha(Path(__file__).read_bytes()),exception=repr(exc),terminal_proof_written=False),indent=2)+'\n')
        raise
