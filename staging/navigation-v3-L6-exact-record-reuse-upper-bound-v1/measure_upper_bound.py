"""Once-only normal DATA L6 exact opaque-key optimistic bound, never map writer."""
from pathlib import Path
from array import array
from collections import Counter
from datetime import datetime,timezone
import ast,builtins,dis,gzip,hashlib,json,os,struct,sys,types

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
INPUT=HERE/'captured-inputs'
SOURCE='staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
SOURCE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
STOCK_COUNT=1973316;TOTAL_COUNT=2062771;TARGET_COUNT=89455;WIDTH=68
MASK=(1<<68)-1
IMG_CAP=20000000;MM_CAP=131072;DICT_CAP=33554432
STATE={'IMG_bytes':0,'IMG_ops':0,'phase':'notstarted','handle_open':False,'handle_closed':True}

class ScopeError(Exception):pass
def need(value,message):
    if not value:raise ScopeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(name):return json.loads((INPUT/name).read_text())
def write(name,value):
    p=HERE/name
    with p.open('w') as f:f.write(json.dumps(value,indent=2)+'\n');f.flush();os.fsync(f.fileno())
    return dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))
def fingerprint(p):
    s=p.stat();return dict(dev=s.st_dev,ino=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,
        ctime_ns=s.st_ctime_ns,nlink=s.st_nlink,mode=oct(s.st_mode&0o7777))
def ceildiv(value,unit):return (value+unit-1)//unit

class PhaseLog:
    def __init__(self):
        self.f=(HERE/'phase-observations.jsonl').open('xb');self.rows=0;self.bytes=0;self.h=hashlib.sha256();self.peak=0
    def point(self,phase,detail=None):
        current={}
        with open('/proc/self/status') as f:
            for line in f:
                key,sep,value=line.partition(':')
                if key not in {'VmRSS','VmHWM'}:continue
                parts=value.split()
                need(sep and len(parts)==2 and parts[1]=='kB' and parts[0].isascii() and parts[0].isdigit(),'Valid proc current-mm fields')
                need(key not in current,'No duplicate proc fields');current[key]=int(parts[0])
        need(set(current)=={'VmRSS','VmHWM'},'Both current-mm fields present')
        guarded=max(current.values());self.peak=max(self.peak,guarded);STATE['phase']=phase
        row=dict(ordinal=self.rows,phase=phase,utc=datetime.now(timezone.utc).isoformat(),
            current_mm_KiB=current,guarded_KiB=guarded,cap_KiB=MM_CAP,
            IMG_bytes=STATE['IMG_bytes'],IMG_ops=STATE['IMG_ops'],detail=detail)
        raw=json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n'
        need(self.bytes+len(raw)<250000,'Phase output bound250KB')
        self.f.write(raw);self.f.flush();os.fsync(self.f.fileno());self.h.update(raw)
        self.bytes+=len(raw);self.rows+=1
        need(guarded<=MM_CAP,'Current-mm128MiB cap; no fallback/retry')
    def close(self):
        self.f.flush();os.fsync(self.f.fileno());self.f.close()
        return dict(rows=self.rows,bytes=self.bytes,sha256=self.h.hexdigest(),max_current_mm_KiB=self.peak,closed=True)

class Budget:
    def __init__(self):
        self.bytes=0;self.ops=0;self.h=hashlib.sha256();self.first=[];self.last=[];self.purposes=Counter()
    def read(self,image,at,size,purpose):
        need(type(at) is int and type(size) is int and 0<=at<=at+size<=image.size,'Physical read bounds')
        need(self.bytes+size<=IMG_CAP,'Hard actual IMG20000000B cap')
        image.f.seek(at);raw=image.f.read(size);need(len(raw)==size,'Exact physical read')
        row=dict(ordinal=self.ops,physical_offset=at,bytes=size,sha256=sha(raw),purpose=purpose)
        encoded=json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n'
        self.h.update(encoded);self.bytes+=size;self.ops+=1
        STATE['IMG_bytes']=self.bytes;STATE['IMG_ops']=self.ops
        self.purposes[purpose.split(';')[0]]+=size
        if len(self.first)<6:self.first.append(row)
        self.last.append(row)
        if len(self.last)>6:self.last.pop(0)
        return raw
    def summary(self):
        return dict(bytes=self.bytes,ops=self.ops,cap=IMG_CAP,rolling_receipt_sha256=self.h.hexdigest(),
                    bytes_by_purpose=dict(self.purposes),first=self.first,last=self.last)

def build_mapper():
    raw=(INPUT/'mapper-source.py.txt').read_bytes();tree=ast.parse(raw.decode())
    names=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Image')
    env={'need':need,'struct':struct}
    module=ast.Module(body=[names,cls],type_ignores=[])
    exec(compile(module,'captured safe mapper Image/NAMES only','exec'),env)
    required=set();code_names=[]
    def scan(code,label):
        code_names.append(label)
        required.update(i.argval for i in dis.get_instructions(code) if i.opname=='LOAD_GLOBAL')
        for ordinal,value in enumerate(code.co_consts):
            if isinstance(value,types.CodeType):scan(value,label+':nested'+str(ordinal))
    for name,value in env['Image'].__dict__.items():
        if isinstance(value,types.FunctionType):scan(value.__code__,name)
    missing=sorted(required-set(env)-set(vars(builtins)))
    need(not missing,'All original mapper globals/nested globals resolved beforeIMGopen')
    witness=dict(source_sha256=sha(raw),source_bytes=len(raw),
        original_Image_AST_sha256=sha(ast.dump(cls,include_attributes=False).encode()),
        only_Image_and_NAMES_compiled=True,historical_main_executed=False,
        checked_code_objects=code_names,required_globals=sorted(required),unresolved_globals=missing,IMG_bytes=0)
    return env['Image'],witness

def keys(raw,first_ordinal,count,global_byte_start):
    need(type(count) is int and count>=0 and 0<=first_ordinal<=first_ordinal+count<=TOTAL_COUNT,'Record bounds')
    firstbit=first_ordinal*WIDTH-global_byte_start*8
    need(0<=firstbit<8,'Raw chunk begins at global byte containing first record')
    need(len(raw)*8>=firstbit+count*WIDTH,'All full68 significant bits in raw chunk')
    for index in range(count):
        bit=firstbit+index*WIDTH;at,shift=divmod(bit,8)
        yield (int.from_bytes(raw[at:at+9],'little')>>shift)&MASK

def geometry(L6_savings,components):
    counts={4:3781594,5:3035559,6:TOTAL_COUNT-L6_savings}
    need(0<=L6_savings<=TOTAL_COUNT,'Arithmetic L6 savings bounds')
    sizes={i:ceildiv(counts[i]*w,8) for i,w in {4:128,5:126,6:68}.items()}
    mdr=4870967+sum(sizes.values());components=dict(components);components['00004171.MDR']=mdr
    blocks={name:ceildiv(n,4096) for name,n in components.items()}
    parts={name:ceildiv(n,240) for name,n in blocks.items()};rows=1+sum(parts.values())
    metadata=max(73728,ceildiv(4096+rows*512,4096)*4096);image=metadata+sum(blocks.values())*4096
    return dict(L6_savings=L6_savings,counts=counts,lower_bytes=sizes,MDR_bytes=mdr,
        component_blocks=blocks,component_parts=parts,FAT_rows=rows,metadata_bytes=metadata,
        IMG_bytes=image,margin=134217728-image,fits=image<=134217728)

def arithmetic():
    actual=read('L5-reuse-capacity.json')['combined_reuse'];components=actual['full_six_component_sizes']
    initial=geometry(0,components)
    need(initial['MDR_bytes']==actual['MDR_bytes']==130720080,'Closed L4/L5 combined MDR baseline')
    need(initial['IMG_bytes']==actual['projected_IMG_bytes']==134828032,'Combined IMG baseline')
    need(initial['margin']==-610304,'Combined original-capacity shortage')
    low,high=0,TARGET_COUNT
    need(geometry(high,components)['fits'],'Optimistic all-target L6 saving could fit arithmetic')
    while low<high:
        mid=(low+high)//2
        if geometry(mid,components)['fits']:high=mid
        else:low=mid+1
    previous=geometry(low-1,components);minimum=geometry(low,components)
    need(not previous['fits'] and minimum['fits'],'Exact adjacent L6 threshold')
    nonmdr=sum(n for name,n in minimum['component_blocks'].items() if name!='00004171.MDR')
    max_mdr=((134217728-minimum['metadata_bytes'])//4096-nonmdr)*4096
    fixed=4870967+minimum['lower_bytes'][4]+minimum['lower_bytes'][5]
    max_l6_count=((max_mdr-fixed)*8)//68
    need(TOTAL_COUNT-max_l6_count==low,'Independent floor closed-form agrees')
    return dict(baseline=initial,threshold_minus_one=previous,threshold=minimum,
        exact_L6_savings_required=low,closed_form_max_MDR_bytes=max_mdr,
        fixed_nonL6_bytes=fixed,closed_form_max_L6_count=max_l6_count,
        original_capacity_not_hardware_maximum=True)

def prepare():
    need(not(HERE/'preflight.json').exists(),'Fresh preflight output')
    Image,mapper_witness=build_mapper()
    fixture=[0,MASK,1,1<<67,0x123456789abcdef01,3,MASK-1]
    packed=sum(v<<(i*68) for i,v in enumerate(fixture)).to_bytes(ceildiv(len(fixture)*68,8),'little')
    need(list(keys(packed,0,len(fixture),0))==fixture,'68bit packed fixture exact')
    # A global odd record begins at shift4, exercising the other nibble.
    first,n=1,4;byte=first*68//8;end=ceildiv((first+n)*68,8)
    need(list(keys(packed[byte:end],first,n,byte))==fixture[first:first+n],'Global shift4 extraction')
    rejected=[]
    for label,args in [('short',(packed[:-1],0,len(fixture),0)),('outside',(b'',TOTAL_COUNT,1,TOTAL_COUNT*68//8)),('misorigin',(packed,1,1,0))]:
        try:list(keys(*args))
        except ScopeError:rejected.append(label)
        else:raise ScopeError('Extraction negative fixture did not reject '+label)
    need(len(rejected)==3,'Bound controls reject')
    facts=read('layout-facts.json')['profiles']['lane_v3'];l6=next(t for t in facts['tables'] if t['level']==6)
    need(l6['count']==TOTAL_COUNT and l6['stride_bits']==68,'Closed actual L6 profile')
    need(l6['bytes']==ceildiv(TOTAL_COUNT*68,8),'Closed L6 byte span')
    need(STOCK_COUNT*68%8==0 and TARGET_COUNT==TOTAL_COUNT-STOCK_COUNT,'True stock boundary andtargetcount')
    source_row=next(r for r in read('v3-sealed-files.json')['files'] if r['path']==SOURCE)
    need(source_row['sha256']==SOURCE_SHA and source_row['bytes']==153346048,'Inherited exact v3 imagepin')
    image_before=fingerprint(ROOT/SOURCE)
    need([image_before[k] for k in ('dev','ino','bytes','mtime_ns')]==source_row['stat_at_seal'][:4],'Source original content identitystat')
    need(image_before==read('v5-L6-receipt.json')['source_stat_after'],'Fresh currentstat equals lastclosed readwitness')
    planned=70144+772+120+l6['bytes']
    need(planned==17604590 and planned<=IMG_CAP,'Actual-byte preflight')
    payload_bound=TARGET_COUNT*(36+28)+5242960+TARGET_COUNT*8+l6['bytes']-STOCK_COUNT*68//8
    need(payload_bound<DICT_CAP,'Conservative targetdict+counter/tail payload preflight')
    math=arithmetic()
    write('arithmetic-preflight.json',math)
    result=dict(all_preflight_checks_passed=True,mapper=mapper_witness,
        pure_bit_controls=dict(valid=2,rejects=rejected,global_shifts=[0,4],whole68bit_mask=True),
        stock_count=STOCK_COUNT,target_count=TARGET_COUNT,source_count=TOTAL_COUNT,
        L6=l6,expected_DIR=facts['directory_source'],source_stat=image_before,
        inherited_whole_IMG_sha256=SOURCE_SHA,fresh_full_IMG_hash=False,
        planned_IMG_bytes=planned,IMG_cap=IMG_CAP,current_mm_cap_KiB=MM_CAP,
        target_dictionary_cap_bytes=DICT_CAP,conservative_target_payload_bytes=payload_bound,
        stock_2M_dictionary_or_full_L6_cache=False,IMG_bytes_read=0,
        exact_L6_savings_required=math['exact_L6_savings_required'])
    write('preflight.json',result)
    print(json.dumps(dict(all_preflight_checks_passed=True,IMG_bytes=0,
        planned_IMG_bytes=planned,exact_L6_savings_required=math['exact_L6_savings_required'],
        mapper_unresolved_globals=mapper_witness['unresolved_globals'])))

def run():
    need((HERE/'preflight.json').exists() and not(HERE/'actual-run-start.json').exists(),'Preflight and once-only actualrun')
    pre=json.loads((HERE/'preflight.json').read_text());need(pre['all_preflight_checks_passed'],'Passed preflight')
    write('actual-run-start.json',dict(source_sha256=sha(Path(__file__).read_bytes()),source_bytes=Path(__file__).stat().st_size,
        utc=datetime.now(timezone.utc).isoformat(),IMG_cap=IMG_CAP,MM_cap_KiB=MM_CAP,once_only=True))
    budget=Budget();log=PhaseLog();Image,mapper_witness=build_mapper()
    initial=fingerprint(ROOT/SOURCE);need(initial==pre['source_stat'],'Source stable since preparation')
    partial={'tail_complete':False,'prefix_complete':False};success=False
    try:
        log.point('before actualsource open')
        with (ROOT/SOURCE).open('rb',buffering=0) as f:
            STATE['handle_open']=True;STATE['handle_closed']=False
            image=Image('v3',f,dict(bytes=153346048,block_bytes=8192),budget)
            header=image.logical('00004171.MDR',0,772,'actual MDR header')
            need(struct.unpack_from('<H',header)[0]==772 and header[2:12]==b'GARMIN MDR','Actual MDR header')
            dir_start,span,stride,one=struct.unpack_from('<4I',header,600)
            need((dir_start,span,stride,one)==(pre['expected_DIR']['offset'],120,20,1),'Actual header-derived directory')
            directory=image.logical('00004171.MDR',dir_start,span,'actual MDR six DIR')
            need(directory.hex()==pre['expected_DIR']['hex'],'Actual complete directory matches closed profile')
            l6row=directory[100:120];start,length,bits,word3,word4=struct.unpack('<5I',l6row)
            need(l6row.hex()==pre['L6']['raw_directory_entry_hex'],'True exact L6 descriptor')
            need(bits==68 and (length*8)//bits==TOTAL_COUNT and length==ceildiv(TOTAL_COUNT*bits,8),'Derived actual L6 bounds')
            need(start+length==pre['expected_DIR']['offset'] or start+length<pre['expected_DIR']['offset'],'L6 table withinMDR')
            log.point('metadata binding complete',dict(actual_L6start=start,bytes=length,descriptor_sha256=sha(l6row)))
            split=STOCK_COUNT*bits//8;tail_length=length-split
            tail=image.logical('00004171.MDR',start+split,tail_length,'poststock L6 exact68bit tail')
            need(tail[-1]>>4==0,'Actual final unused4bits zero')
            target={};multiplicity=array('I');hits=array('I')
            for key in keys(tail,STOCK_COUNT,TARGET_COUNT,split):
                index=target.get(key)
                if index is None:
                    index=len(multiplicity);target[key]=index;multiplicity.append(1);hits.append(0)
                else:multiplicity[index]+=1
            dictionary_bytes=sys.getsizeof(target)+sum(sys.getsizeof(k)+sys.getsizeof(v) for k,v in target.items())
            need(dictionary_bytes<DICT_CAP,'Actual targetdictionary below32MiB')
            need(sum(multiplicity)==TARGET_COUNT,'All target multiplicities counted')
            partial.update(tail_complete=True,tail_bytes=len(tail),tail_sha256=sha(tail),target_unique_keys=len(target),dictionary_bytes=dictionary_bytes)
            write('partition-read-receipts.json',partial)
            log.point('targettail decoded',dict(unique=len(target),dictionary_bytes=dictionary_bytes))
            prefix_h=hashlib.sha256();whole_h=hashlib.sha256();ordinal=0;prefix_bytes=0;stock_matching_rows=0
            while ordinal<STOCK_COUNT:
                count=min(32768,STOCK_COUNT-ordinal);byte_start=ordinal*bits//8
                need(ordinal*bits%8==0 and count*bits%8==0,'Byte-aligned stock streamingchunk')
                size=count*bits//8
                raw=image.logical('00004171.MDR',start+byte_start,size,'stockprefix L6 exacttarget-key lookup')
                prefix_h.update(raw);whole_h.update(raw);prefix_bytes+=len(raw)
                for key in keys(raw,ordinal,count,byte_start):
                    index=target.get(key)
                    if index is not None:hits[index]+=1;stock_matching_rows+=1
                ordinal+=count
                log.point('stockprefix streamed',dict(records=ordinal,prefix_bytes=prefix_bytes))
            need(ordinal==STOCK_COUNT and prefix_bytes==split,'Stockprefix exact EOF')
            whole_h.update(tail)
            expected=next(t for t in read('v5-L6-receipt.json')['stream']['segments'] if t.get('level')==6)['sha256']
            need(whole_h.hexdigest()==expected,'Actual whole L6 hash matches closed complete readback')
            partial.update(prefix_complete=True,prefix_bytes=prefix_bytes,prefix_records=ordinal,
                prefix_sha256=prefix_h.hexdigest(),full_L6_sha256=whole_h.hexdigest(),full_L6_digest_matches_closed=True,
                source_L6_bytes_read_once=prefix_bytes+len(tail),boundary_overlap_bytes=0)
            write('partition-read-receipts.json',partial)
            # Only counters, never opaque68bit keys, labels, coordinates or IDs, persist.
            pairs=array('I')
            histogram=Counter();stock_hit_keys=0;stock_hit_target_rows=0;new_only_keys=0;new_only_rows=0
            for count,stockhits in zip(multiplicity,hits):
                pairs.extend((count,stockhits));histogram[(count,stockhits)]+=1
                if stockhits:stock_hit_keys+=1;stock_hit_target_rows+=count
                else:new_only_keys+=1;new_only_rows+=count
            rawpairs=pairs.tobytes()
            need(sys.byteorder=='little' and pairs.itemsize==4,'Counter ledger u32le ABI')
            with (HERE/'target-multiplicity-stock-hits.u32le.gz').open('wb') as g:
                g.write(gzip.compress(rawpairs,compresslevel=9,mtime=0));g.flush();os.fsync(g.fileno())
            upper=TARGET_COUNT-new_only_keys
            need(upper==stock_hit_target_rows+new_only_rows-new_only_keys,'Upper bound decomposition')
            summary=dict(target_rows=TARGET_COUNT,target_unique_keys=len(target),
                target_duplicate_multiplicity_histogram=dict(Counter(multiplicity)),
                all_internal_new_duplicate_rows=TARGET_COUNT-len(target),
                stock_hit_unique_target_keys=stock_hit_keys,stock_hit_target_rows=stock_hit_target_rows,
                matching_stock_rows=stock_matching_rows,
                unique_new_keys_not_in_stock=new_only_keys,new_only_target_rows=new_only_rows,
                new_only_internal_duplicate_rows=new_only_rows-new_only_keys,
                optimistic_L6_rows_savings_upper_bound=upper,
                joint_multiplicity_stockhit_histogram=[dict(target_multiplicity=k[0],stock_hit_multiplicity=k[1],unique_keys=v)
                    for k,v in sorted(histogram.items())],
                deidentified_samples=[dict(opaque_sample='counter'+str(i),target_multiplicity=k[0],stock_hit_multiplicity=k[1],keys_in_class=v)
                    for i,(k,v) in enumerate(sorted(histogram.items())[:8])],
                ledger=dict(records=len(target),fields=['target_multiplicity_u32le','stock_hit_multiplicity_u32le'],
                    uncompressed_bytes=len(rawpairs),uncompressed_sha256=sha(rawpairs),
                    gzip_bytes=(HERE/'target-multiplicity-stock-hits.u32le.gz').stat().st_size,
                    gzip_sha256=sha((HERE/'target-multiplicity-stock-hits.u32le.gz').read_bytes()),
                    no_raw_keys_labels_coordinates_or_record_IDs=True),
                actual_target_dictionary_accounted_bytes=dictionary_bytes,target_dictionary_cap=DICT_CAP,
                stock_dictionary_or_full_L6_cache_created=False,
                only_poststock_tail_raw_buffer_bytes=len(tail))
            math=json.loads((HERE/'arithmetic-preflight.json').read_text())
            threshold=math['exact_L6_savings_required']
            summary['exact_L6_savings_required_for_capacity']=threshold
            summary['optimistic_upper_bound_sufficient_for_arithmetic']=upper>=threshold
            summary['shortfall_in_L6_rows_at_optimistic_upper_bound']=max(0,threshold-upper)
            components=read('L5-reuse-capacity.json')['combined_reuse']['full_six_component_sizes']
            summary['capacity_at_optimistic_upper_bound']=geometry(upper,components)
            write('result-summary.json',summary)
            need(fingerprint(ROOT/SOURCE)==initial,'Actual source unchanged throughnormalread')
        STATE['handle_open']=False;STATE['handle_closed']=True
        final=fingerprint(ROOT/SOURCE);need(final==initial,'Actual source statafter close equalsbefore')
        log.point('source handles closed')
        observation=log.close();success=True
        read_receipt=write('actual-read-receipts.json',dict(budget=budget.summary(),source_stat_before=initial,
            source_stat_after=final,unbuffered_source_handle=True,source_handles_closed=True,
            inherited_whole_IMG_sha256=SOURCE_SHA,fresh_whole_IMG_hash=False,
            table_digest_fresh=True,partial=partial,observations=observation))
        result=write('proof.json',dict(schema='garmin-L6-exact-record-reuse-optimistic-upper-bound/v1',
            all_assigned_checks_passed=True,actual_normal_DATA_source_read=True,
            target_rows=TARGET_COUNT,stock_prefix_count=STOCK_COUNT,full_L6count=TOTAL_COUNT,full_key_bits=68,
            actual_IMG_bytes=budget.bytes,actual_IMG_cap=IMG_CAP,
            sampled_current_mm_peak_KiB=observation['max_current_mm_KiB'],current_mm_cap_KiB=MM_CAP,
            actual_target_dict_bytes=dictionary_bytes,target_dict_cap=DICT_CAP,
            whole_actual_L6_digest_matches_closed=True,
            optimistic_L6_savings_upper_bound=upper,exact_L6_capacity_savings_required=threshold,
            optimistic_bound_sufficient=upper>=threshold,
            exact_row_sharing_capacity_route_excluded_under_this_fixed_profile=upper<threshold,
            other_encoding_size_or_policy_routes_excluded=False,
            safe_actual_group_reuse_or_compactor_ready=False,
            ignored_contiguous_group_reference_highflag_constraints=True,
            all_original_stock_numeric_IDs_required_preserved=True,all_new_address_keys_required_preserved=True,
            stock2M_key_dictionary_or_fullL6cache=False,
            all_actual_source_handles_closed=True,source_stat_before=initial,source_stat_after=final,
            map_writer_or_IMG_MAIN_CPU_guest_PBF_audio_device_IO=0,
            scanner_is_new_normal_DATA_read_not_closed_suite_rerun=True,
            private_addresses_coordinates_labels_rawkeys_or_device_IDs_not_output=True,
            native_graph_ABI_renderer_UI_route_install_v3fix_fullgoal=False,
            source_original_prefix_and_wholeIMG_hash_inherited_not_freshstock_or_wholeIMGhash=True,
            artifacts=dict(summary='result-summary.json',partition='partition-read-receipts.json',read_receipt=read_receipt)))
        print(json.dumps(dict(all_assigned_checks_passed=True,actual_IMG_bytes=budget.bytes,
            upper_bound=upper,required=threshold,optimistic_sufficient=upper>=threshold,
            new_only_keys=new_only_keys,target_unique_keys=len(target),stock_hit_keys=stock_hit_keys,
            dictionary_bytes=dictionary_bytes,max_current_mm_KiB=observation['max_current_mm_KiB'],
            proof=result,source_handles_closed=True)),flush=True)
    except BaseException as exc:
        STATE['handle_open']=False;STATE['handle_closed']=True
        failure=dict(error_type=type(exc).__name__,error=str(exc),state=STATE,
            partial=partial,budget=budget.summary(),source_stat_after=fingerprint(ROOT/SOURCE),
            actual_caps_not_raised=True,no_retry_or_context_change=True,
            source_handles_closed=True,IMGwriter_MAIN_CPU_guest_PBF_audio_device=0)
        write('actual-failure.json',failure)
        if not success:
            try:log.close()
            except Exception:pass
        raise

if __name__=='__main__':
    need(sys.argv[1:] in [['--prepare'],['--run']],'Exact prepare orrun command')
    prepare() if sys.argv[1]=='--prepare' else run()
