#!/usr/bin/env python3
"""New multilevel packing/boundary/capacity cases; one bounded stock plan."""
import datetime
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.dont_write_bytecode=True
import multilevel_mdr_writer as w
HERE=Path(__file__).resolve().parent
ROOT=w.ROOT


def need(ok,message):
    if not ok:raise AssertionError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def value(parts,widths):
    result,position=0,0
    for v,width in zip(parts,widths):
        need(0<=v<1<<width,'Independent fixture field overflows')
        result|=v<<position;position+=width
    return result


def dense(rows,width):
    return sum(int.from_bytes(row,'little')<<(i*width)for i,row in enumerate(rows)).to_bytes((len(rows)*width+7)//8,'little')


def row(level,i):
    if level==6:bits=value([1,31+i,1000+i,2000+i],[1,19,24,24])
    else:
        first,count=(1,1)if i==0 else(0,0)
        flags=(6,8,13,0)[i%4]
        bits=value([1,0x7ffff,31+i,first,count,flags,1000+i,2000+i],
                   [1,19,19,22 if level==4 else 21,10 if level==4 else 9,9,24,24])
    return bits.to_bytes((w.STRIDES[level]+7)//8,'little')


def fragment(raw,pattern=(1,2,3,7,11)):
    at,index=0,0
    while at<len(raw):
        n=pattern[index%len(pattern)];yield raw[at:at+n];at+=n;index+=1


def fixture(old5count=4):
    counts=[2,3,9,4,old5count,2]
    rows={level:[row(level,i)for i in range(counts[level-1])]for level in [4,5,6]}
    bodies={level:dense(records,w.STRIDES[level])for level,records in rows.items()}
    parents=[
        [1,101,1,1,6,100001,200001],
        [1,102,1,2,5,100002,200002],
        [1,103,1,2,4,100003,200003],
        [1,104,1,1,13,100004,200004],
        [1,105,0,0,8,100005,200005],
    ]+[[1,106+i,3,2,4|(i<<3),100006+i,200006+i]for i in range(4)]
    p=[value(v,[1,19,22,12,9,24,24]).to_bytes(14,'little')for v in parents]
    bodies[3]=dense(p,111);bodies[2]=bytes.fromhex('deadbeef')+bytes(range(42));bodies[1]=bytes(range(31))
    raw=bytearray((71+i*29)&255 for i in range(900));struct.pack_into('<H',raw,0,772);raw[2:12]=b'GARMIN MDR'
    starts={}
    for level in [6,5,4,3,2,1]:starts[level]=len(raw);raw.extend(bodies[level])
    directory_start=len(raw);struct.pack_into('<4I',raw,600,directory_start,120,20,1)
    for level,(stride,widths,flags)in enumerate(w.single.PROFILE,1):
        a,b,c,d,e,f,g,h=widths
        word=e|(d<<6)|(c<<12)|(a<<18)|(b<<24)|(flags[0]<<30)|(flags[1]<<31)
        x=f|(g<<11)|(h<<17)|(0x15<<6)|(0xa5<<23)
        raw.extend(struct.pack('<5I',starts[level],len(bodies[level]),stride,word,x))
    return dict(raw=bytes(raw),bodies=bodies,starts=starts,counts=counts,parents=parents,rows=rows,directory_start=directory_start)


def source(raw,**kwargs):
    return w.MDRSource(len(raw),kwargs.get('read',lambda at,n:bytes(raw[at:at+n])),
        kwargs.get('chunks',lambda at,n:fragment(bytes(raw[at:at+n]))),kwargs.get('unchanged',lambda:True))


def declarations(counts=None,callbacks=None):
    counts=counts or{4:3,5:3,6:3};callbacks=callbacks or{}
    return {level:w.PackedAppend.from_records(level,counts[level],callbacks.get(level,
        lambda level=level:iter([row(level,10+i)for i in range(counts[level])])))for level in [4,5,6]}


DEFAULT_RANGES=(w.SelectedRange(1,3,3,6,6),w.SelectedRange(2,5,3,5,5),w.SelectedRange(3,5,3,4,4))


def plan(f,appends=None,selected=DEFAULT_RANGES,src=None):
    return w.plan_multilevel_mdr(src or source(f['raw']),appends=appends or declarations(),selected_ranges=selected,synthetic_fixture=True)


def scalar(raw,bit,width):
    result=0
    for i in range(width):result|=((raw[(bit+i)//8]>>((bit+i)%8))&1)<<i
    return result


def parent_fields(raw,ID,firstwidth):
    position=(ID-1)*(89+firstwidth);result=[]
    for width in [1,19,firstwidth,12,9,24,24]:result.append(scalar(raw,position,width));position+=width
    return result


def check_suffix(f,p,result,counts):
    need(len(result)==p.size,'Multilevel stream EOF differs')
    expected_header=bytearray(f['raw'][:772]);struct.pack_into('<I',expected_header,600,p.new_directory_start)
    need(result[:772]==expected_header and result[772:f['starts'][6]]==f['raw'][772:f['starts'][6]],'Unknown header/prefix changed')
    cursor=f['starts'][6]
    for level in [6,5,4]:
        added=dense([row(level,10+i)for i in range(counts[level])],w.STRIDES[level])
        expected=f['bodies'][level]+added;t=p.new_tables[level-1]
        need((t['start'],t['bytes'],t['count'])==(cursor,len(expected),f['counts'][level-1]+counts[level]),'Affected level start/span/count differs')
        need(result[cursor:cursor+len(expected)]==expected,'Old/new multilevel packed bytes or boundary differ')
        cursor+=len(expected)
    need(p.new_tables[2]['start']==cursor and result[cursor:cursor+126]==p.L3,'L3 physical continuation differs');cursor+=126
    for level in [2,1]:
        need(p.new_tables[level-1]['start']==cursor and result[cursor:cursor+len(f['bodies'][level])]==f['bodies'][level],'L2/L1 body/position differs')
        cursor+=len(f['bodies'][level])
    need(cursor==p.new_directory_start and result[cursor:]==p.directory,'Directory physical continuation/EOF differs')
    for index in range(6):
        old=f['raw'][f['directory_start']+index*20:f['directory_start']+index*20+20]
        new=p.directory[index*20:index*20+20]
        need(old[16:20]==new[16:20],'Unknown directory word4 changed')
        if index!=2:need(old[12:16]==new[12:16],'Unrelated width/flag directory word changed')
        else:
            word=struct.unpack_from('<I',old,12)[0]
            need(struct.unpack_from('<I',new,12)[0]==((word&~(63<<18))|(23<<18)),'L3 directory unrelated bit changed')
    for ID,old in enumerate(f['parents'],1):
        expected=list(old)
        for change in p.report['selected_ranges']:
            if ID==change['ID']:expected[2:4]=[change['first'],change['count']]
        need(parent_fields(p.L3,ID,23)==expected,'Synthetic multilevel parent fields/flags differ')
    need(result[p.new_tables[1]['start']:p.new_tables[1]['start']+4]==bytes.fromhex('deadbeef'),'L3 lookahead is not actual L2 body')


def tiny_IMG(mdr):
    names=w.core.AP_NAMES
    contents={name:bytes((i*13+j)&255 for i in range(27+j*3))for j,name in enumerate(names)};contents[names[1]]=mdr
    header=bytearray(4096);header[16:23]=b'DSKIMG\0';header[65:72]=b'GARMIN\0';header[64]=8
    header[97]=9;header[98]=3;header[15]=0x37
    struct.pack_into('<H',header,24,16);struct.pack_into('<H',header,95,16);struct.pack_into('<H',header,99,32768)
    struct.pack_into('<I',header,458,262144);header[510:512]=b'\x55\xaa';header[700:709]=b'untouched'
    def dirrow(name,size,blocks,root=False):
        data=bytearray(512);data[0]=1;data[1:12]=b' '*11 if root else name.split('.')[0].encode().ljust(8,b' ')+name.split('.')[1].encode()
        struct.pack_into('<I',data,12,size);data[16]=3 if root else 0;data[19:32]=b'metadata keep'
        struct.pack_into('<240H',data,32,*(blocks+[65535]*(240-len(blocks))));return bytes(data)
    directory=dirrow('',8192,[0,1],True)
    for index,name in enumerate(names,2):directory+=dirrow(name,len(contents[name]),[index])
    directory+=bytes(4096-len(directory))
    data=bytes(header)+directory+b''.join(contents[name]+bytes((-len(contents[name]))%4096)for name in names)
    return data,contents


def read_components(data):
    block=1<<(data[97]+data[98]);start=data[64]*512;end=struct.unpack_from('<I',data,start+12)[0];components={}
    for at in range(start+512,end,512):
        r=data[at:at+512]
        if not r[0]:continue
        name=r[1:9].decode().rstrip()+'.'+r[9:12].decode().rstrip();part=struct.unpack_from('<H',r,17)[0]
        c=components.setdefault(name,dict(blocks=[]))
        if not part:c['size']=struct.unpack_from('<I',r,12)[0]
        c['blocks'] += [b for b in struct.unpack_from('<240H',r,32)if b!=65535]
    return {name:b''.join(data[b*block:(b+1)*block]for b in c['blocks'])[:c['size']]for name,c in components.items()}


def positives():
    cases=[]
    for level in [6,5,4]:
        for count in range(6):
            rows=[row(level,10+i)for i in range(count)];expected=dense(rows,w.STRIDES[level])
            actual=b''.join(w.pack_records(level,iter(rows),count));need(actual==expected,'Independent tight packing differs')
            declared=w.PackedAppend(level,count,count*w.STRIDES[level],lambda actual=actual:fragment(actual))
            need(b''.join(declared.chunks())==expected,'Fragmented packed validation differs')
            cases.append(dict(level=level,count=count,bits=count*w.STRIDES[level],bytes=len(actual),unused_bits=len(actual)*8-count*w.STRIDES[level],sha256=sha(actual)))
    f=fixture();p=plan(f);output=b''.join(p.chunks());check_suffix(f,p,output,{4:3,5:3,6:3})
    raw13=plan(f,selected=DEFAULT_RANGES+(w.SelectedRange(4,5,3,5,13),))
    need(parent_fields(raw13.L3,4,23)[4]==13,'Explicit raw13 selected parent flags were cleared/converted')
    zero={level:w.PackedAppend.empty(level)for level in [4,5,6]};z=plan(f,appends=zero,selected=())
    check_suffix(f,z,b''.join(z.chunks()),{4:0,5:0,6:0})
    integrations=[];original,contents=tiny_IMG(f['raw'])
    for kind in ['original4K','explicit8K']:
        with tempfile.TemporaryFile(dir=HERE)as srcfile:
            srcfile.write(original);srcfile.flush();srcfile.seek(0)
            if kind=='original4K':adapter=w.ContainerAdapter.original_4k(w.core.StreamIMG(srcfile))
            else:adapter=w.ContainerAdapter.explicit_8k(w.eight().Source4K(srcfile))
            prepared=plan(f,src=adapter.mdr_source).bind_container(adapter);destination=io.BytesIO();receipt=prepared.repack_stream(destination)
            rebuilt=read_components(destination.getvalue())
            need(rebuilt=={name:(output if name=='00004171.MDR'else raw)for name,raw in contents.items()},'Multilevel suffix/container integration differs')
            integrations.append(dict(kind=kind,output_bytes=len(destination.getvalue()),receipt=receipt))
    # Large sizes are arithmetic only; no large supplier/stream/output allocated.
    capacity_controls=[];calls=[]
    big={level:w.PackedAppend.empty(level)for level in [4,5,6]}
    big[4]=w.PackedAppend(4,8388603,8388603*128,lambda:(calls.append('called')or iter(())))
    for kind in ['original4K','explicit8K']:
        with tempfile.TemporaryFile(dir=HERE)as srcfile:
            srcfile.write(original);srcfile.flush();srcfile.seek(0)
            adapter=w.ContainerAdapter.original_4k(w.core.StreamIMG(srcfile))if kind=='original4K'else w.ContainerAdapter.explicit_8k(w.eight().Source4K(srcfile))
            semantic=plan(f,appends=big,selected=(),src=adapter.mdr_source)
            if kind=='original4K':
                try:semantic.bind_container(adapter)
                except ValueError as exc:need('declared container capacity'in str(exc),'Wrong separate capacity rejection');capacity_controls.append(dict(kind=kind,rejected=True,message=str(exc),semantic_MDR_bytes=semantic.size))
                else:raise AssertionError('Original4K overflow allowed')
            else:
                bound=semantic.bind_container(adapter);capacity_controls.append(dict(kind=kind,accepted_arithmetic_plan=True,semantic_MDR_bytes=semantic.size,
                    image_bytes=bound.capacity_plan['image_bytes'],explicit_capacity=bound.capacity_plan['output_declared_capacity'],large_stream_executed=False))
    need(not calls,'Capacity planning consumed large suppliers')
    return dict(all_passed=True,packing_controls=cases,multilevel_plan=p.report,synthetic_MDR_bytes=len(output),synthetic_MDR_sha256=sha(output),
        raw13_explicit_flags_preserved=True,unselected_raw8_preserved=True,zero_append_checked=True,
        three_packed_level_boundaries_checked=True,unknown_header_prefix_directory_and_L2_L1_bytes_checked=True,
        new_small_4K_8K_integrations=integrations,separate_capacity_controls=capacity_controls,large_supplier_calls=0)


def negatives():
    f=fixture();cases=[]
    def reject(name,fn,text='',kind=ValueError):
        try:fn()
        except kind as exc:need(text in str(exc),'Unexpected rejection:'+name+':'+str(exc));cases.append(dict(name=name,rejected=True,exception=type(exc).__name__,message=str(exc)))
        else:raise AssertionError('Expected rejection missing:'+name)
    def declared(level,raw,count=3,bits=None):return w.PackedAppend(level,count,count*w.STRIDES[level]if bits is None else bits,lambda:fragment(raw))
    for level in [6,5]:
        raw=dense([row(level,10+i)for i in range(3)],w.STRIDES[level]);bad=bytearray(raw);bad[-1]|=1<<(3*w.STRIDES[level]%8)
        reject('level'+str(level)+'_nonzero_final_tail',lambda level=level,bad=bad:b''.join(declared(level,bytes(bad)).chunks()),'unused final bits')
        badmap=bytearray(raw);bit=w.STRIDES[level];badmap[bit//8]&=~(1<<(bit%8))
        reject('level'+str(level)+'_mapordinal_across_byte_boundary',lambda level=level,badmap=badmap:b''.join(declared(level,bytes(badmap)).chunks()),'mapordinal1')
        badrow=bytearray(row(level,0));badrow[-1]|=1<<(w.STRIDES[level]%8)
        reject('level'+str(level)+'_individual_nonzero_unused',lambda level=level,badrow=badrow:b''.join(w.pack_records(level,[badrow],1)),'unused high bits')
        reject('level'+str(level)+'_per_record_padded_stream',lambda level=level:b''.join(declared(level,b''.join(row(level,i)for i in range(3))).chunks()),'mapordinal1')
    raw=dense([row(6,i)for i in range(3)],68)
    reject('explicit_bit_length_mismatch',lambda:plan(f,appends={**declarations(),6:declared(6,raw,bits=205)}),'count times stride')
    reject('packed_short_byte_count',lambda:b''.join(declared(6,raw[:-1]).chunks()),'truncated')
    reject('packed_oversized_byte_count',lambda:b''.join(declared(6,raw+b'x').chunks()),'exceeds declared')
    reject('packed_bare_bytes_supplier',lambda:b''.join(w.PackedAppend(6,3,204,lambda:raw).chunks()),'iterable')
    reject('packed_empty_chunk',lambda:b''.join(w.PackedAppend(6,3,204,lambda:iter([b'',raw])).chunks()),'nonempty')
    reject('packed_non_bytes_chunk',lambda:b''.join(w.PackedAppend(6,3,204,lambda:iter([123])).chunks()),'contain bytes')
    reject('packed_count_bool',lambda:plan(f,appends={**declarations(),6:w.PackedAppend(6,True,68,lambda:iter(()))}),'finite')
    reject('packed_bit_length_overflow',lambda:plan(f,appends={**declarations(),6:w.PackedAppend(6,3,1<<32,lambda:iter(()))}),'finite')
    reject('packed_callback_noncallable',lambda:plan(f,appends={**declarations(),6:w.PackedAppend(6,3,204,raw)}),'callable')
    reject('packed_level_key_mismatch',lambda:plan(f,appends={**declarations(),6:w.PackedAppend.empty(5)}),'level/key')
    reject('missing_explicit_level',lambda:w.plan_multilevel_mdr(source(f['raw']),appends={6:w.PackedAppend.empty(6)},synthetic_fixture=True),'all levels')
    reject('float_mapping_key',lambda:plan(f,appends={4.0:declarations()[4],5:declarations()[5],6:declarations()[6]}),'integer levels')
    reject('individual_short_row',lambda:b''.join(w.pack_records(6,[row(6,0)[:-1]],1)),'padded byte length')
    reject('individual_short_count',lambda:b''.join(w.pack_records(6,[row(6,0)],2)),'truncated explicit')
    reject('individual_extra_count',lambda:b''.join(w.pack_records(6,[row(6,0),row(6,1)],1)),'exceeds explicit')
    reject('individual_invalid_level',lambda:b''.join(w.pack_records(3,[],0)),'level')
    reject('original5_nonbyte_end',lambda:plan(fixture(2)),'byte-aligned original')
    reject('selected_next6_wrong_table_limit',lambda:plan(f,selected=(w.SelectedRange(1,6,1,6,6),)),'corresponding table count')
    narrow={**declarations(),5:w.PackedAppend.empty(5)}
    reject('selected_next5_cannot_use_L4_count',lambda:plan(f,appends=narrow,selected=(w.SelectedRange(2,5,1,5,5),)),'corresponding table count')
    reject('selected_raw13_cannot_be_flag5',lambda:plan(f,selected=(w.SelectedRange(4,5,3,5,5),)),'flags/nextlevel')
    reject('selected_raw8_not_implicit_next4',lambda:plan(f,selected=(w.SelectedRange(5,5,3,4,8),)),'branch conversion')
    reject('selected_next5_not_next4',lambda:plan(f,selected=(w.SelectedRange(2,5,3,4,5),)),'branch conversion')
    reject('selected_count12_overflow',lambda:plan(f,selected=(w.SelectedRange(1,3,4096,6,6),)),'count12')
    reject('selected_first23_overflow',lambda:plan(f,selected=(w.SelectedRange(1,1<<23,1,6,6),)),'firstchild23')
    reject('selected_duplicate_street',lambda:plan(f,selected=(DEFAULT_RANGES[0],DEFAULT_RANGES[0])),'Duplicate')
    reject('selected_flag9_overflow',lambda:plan(f,selected=(w.SelectedRange(1,3,3,6,512),)),'original flags')
    reject('new_corresponding_count_overflow',lambda:plan(f,appends={**declarations(),6:w.PackedAppend(6,0x7fffff,0x7fffff*68,lambda:iter(()))}),'child table exceeds')
    p=plan(f,src=source(f['raw'],chunks=lambda at,n:fragment(f['raw'][at:at+n-1])))
    reject('multilevel_old_table_stream_truncated',lambda:b''.join(p.chunks()),'Source supplier truncated')
    unstable=dict(value=True);p=plan(f,src=source(f['raw'],unchanged=lambda:unstable['value']));unstable['value']=False
    reject('source_changed_after_plan',lambda:b''.join(p.chunks()),'changed since')
    mutable=bytearray(f['raw']);p=plan(f,src=source(mutable));mutable[f['starts'][2]]^=1
    reject('real_L2_changed_after_plan',lambda:b''.join(p.chunks()),'lookahead changed')
    def failed():yield raw[:9];raise RuntimeError('Deliberate packed supplier failure')
    reject('supplier_failure_kept_as_failure',lambda:b''.join(w.PackedAppend(6,3,204,failed).chunks()),'Deliberate',RuntimeError)
    with tempfile.TemporaryFile(dir=HERE)as file:
        data,_=tiny_IMG(f['raw']);file.write(data);file.flush();file.seek(0);a=w.ContainerAdapter.original_4k(w.core.StreamIMG(file))
        p=plan(f)
        reject('capacity_adapter_different_MDR_source',lambda:p.bind_container(a),'own original MDRSource')
    return dict(all_passed=True,rejection_count=len(cases),cases=cases)


def original_plan():
    deeper_path=ROOT/'staging/navigation-native-deeper-address-plan-v1/deeper-address-plan.json'
    raw=deeper_path.read_bytes();need(sha(raw)=='289e502c427e1798927f0187e170909b545ca8ae9b5ab1351bce270f4ae160fd','Frozen deeper source changed')
    deeper=json.loads(raw);branches={b['native_street']['low28_id']:b for b in deeper['representative_street_branches']}
    witness_path=ROOT/'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json'
    witness_raw=witness_path.read_bytes();need(sha(witness_raw)=='628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774','Cached old84 changed')
    cached={4:[bytes.fromhex(r['record_hex'])for r in json.loads(witness_raw)['all84_rows_with_frozen_boundaries']]}
    for level,ID in [(6,1),(5,2)]:
        branch=branches[ID];need(branch['direct_child_complete'],'Cached selected deeper group incomplete')
        cached[level]=[]
        for child in branch['children']:
            r=child['record'];bits=(int.from_bytes(bytes.fromhex(r['span_hex']),'little')>>r['initial_bit_offset'])&((1<<w.STRIDES[level])-1)
            cached[level].append(bits.to_bytes((w.STRIDES[level]+7)//8,'little'))
    need({level:len(rows)for level,rows in cached.items()}=={4:84,5:10,6:1},'Cached clone group counts differ')
    calls=[]
    def supplier(level):calls.append(level);return iter(cached[level])
    appends={level:w.PackedAppend.from_records(level,len(cached[level]),lambda level=level:supplier(level))for level in [4,5,6]}
    ranges=(w.SelectedRange(1,1973317,1,6,6),w.SelectedRange(2,2341097,10,5,5),w.SelectedRange(16707,2133949,84,4,4))
    path=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img';before=path.stat()
    with path.open('rb')as f:
        image=w.core.StreamIMG(f);adapter=w.ContainerAdapter.original_4k(image)
        p=w.plan_multilevel_mdr(adapter.mdr_source,appends=appends,selected_ranges=ranges)
        bound=p.bind_container(adapter)
        need(p.old_tables[2]['start']==91983716 and p.old_tables[2]['bytes']==664197,'Actual original derived L3 differs')
        need(p.size==92661094 and p.new_directory_start==92660974,'Actual clone-only multilevel suffix size differs')
        for c in ranges:
            fields=parent_fields(p.L3,c.one_based_street_ID,23)
            need(fields[2:5]==[c.first_child,c.count,c.original_flags],'Actual selected multilevel fields differ')
        need(parent_fields(p.L3,5,23)[4]==13,'Original unselected raw13 changed')
        need(not calls,'Actual plan consumed clone suppliers/full MDR')
        need(sum(r['bytes']for r in image.read_log)==722437,'Actual multilevel bounded reads differ')
        log=list(image.read_log)
        need(adapter.mdr_source.unchanged(),'Actual original changed')
    after=path.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Original AP stat changed')
    return dict(all_passed=True,actual_original_plan=p.report,original_source=str(path.relative_to(ROOT)),source_stat_unchanged=True,
        cached_clone_sources=[dict(path=str(deeper_path.relative_to(ROOT)),sha256=sha(raw)),dict(path=str(witness_path.relative_to(ROOT)),sha256=sha(witness_raw))],
        cached_original_counts={level:len(rows)for level,rows in cached.items()},cached_clone_suppliers_executed=0,
        actual_original_L3_reads=1,actual_pure_bit_insertion_calls=1,actual_original_bytes_read=722437,
        original_read_log=log,original4K_container_plan=dict(image_bytes=bound.capacity_plan['image_bytes'],declared_capacity=bound.capacity_plan['original_declared_capacity']),
        actual_new_house_records=0,clone_only_preparation=True,actual_complete_MDR_or_IMG_output=False,native_CPU_executed=False,
        all47870_old_field_suite_or_old_synthetic_suite_replayed=False,unselected_original_raw13_preserved=True)


def main():
    output=HERE/'multilevel-MDR-streaming-writer-proof-v1.json';need(not output.exists(),'Refuse overwrite terminal multilevel proof')
    positive=positives();negative=negatives();actual=original_plan()
    proof=dict(schema='multilevel-native-MDR-streaming-writer/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_sha256=sha((HERE/'multilevel_mdr_writer.py').read_bytes()),test_sha256=sha(Path(__file__).read_bytes()),
        sealed_singlelevel_validator_sha256=w.SINGLE_SHA,sealed8K_container_source_sha256=w.EIGHT_SHA,
        new_critical_packing_and_boundaries=positive,new_multilevel_negative_controls=negative,actual_bounded_original_plan=actual,
        all_checks_passed=True,whole_original_map_read_copy_or_output=False,CPU_or_USB_or_service_IO=False,canonical_or_ZIP_mutated=False,
        complete_country_update=False,new_street_or_JAI_writer=False,
        limits=['Only the exact corrected original stock source profile is accepted; old6/5/4record bits must end byte-aligned. Appended packed streams may end at nonbyte bit positions and require zero final padding.',
            'MDR semantics and container capacity are independent. Explicit4K binding rejects above134217728bytes; explicit8K binding targets268435456bytes with separately documented unknown AP header checksum/device acceptance.',
            'All original raw flags/nextlevels remain exact. Explicit original_flags and nextlevel checks prevent branch conversion; raw8/13query semantics remain unproved.',
            'L3first widens23bits for all branches; existing L4first22/L5first21and nested child counts stay unchanged. New preencoded records must respect those original widths and validated label/coordinate relationships.',
            'The real-source scope is one bounded clone-only multilevel plan; supplied cached groups were not streamed and no new addresses/candidate/full query or device result was generated.',
            'Suppliers/partial destinations fail on truncation, overrun, bad bitlength, mapordinal or tail padding. Integrating caller owns cleanup and source/ordering/labels/JAI/query verification.'])
    output.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),all_passed=True,
        packing_controls=len(positive['packing_controls']),rejections=negative['rejection_count'],original_bytes_read=722437,
        actual_plan_new_MDR_size=actual['actual_original_plan']['new_size'],actual_full_stream_executed=False)))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        failed=HERE/'unfinalized-failure-v1.json'
        if not failed.exists():failed.write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_sha256=sha((HERE/'multilevel_mdr_writer.py').read_bytes()),test_sha256=sha(Path(__file__).read_bytes()),exception=repr(exc)),indent=2)+'\n')
        raise
