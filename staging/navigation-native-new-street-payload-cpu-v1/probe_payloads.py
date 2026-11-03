#!/usr/bin/env python3
"""Three new source-bound payload prefixes and one proposed LBL fragment.

No candidate IMG is opened. DIR, FS frame, four following bytes and label
metadata are explicitly proposed fixtures. Original metadata is never entered.
"""
import datetime,gc,hashlib,importlib.util,json,struct,sys,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from unicorn import UC_HOOK_CODE,UC_PROT_READ
from unicorn.arm_const import *
CTX,FILE,DIR,OUT,RET,BUF,STACK=0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09006000,0x09010000
DEPS=[]
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def bind(rel,digest,limit=800000):
    p=ROOT/rel;b=stat(p);need(b[2]<=limit,'Small binding ceiling:'+rel);raw=p.read_bytes();need(sha(raw)==digest and stat(p)==b,'Binding:'+rel)
    DEPS.append(dict(path=rel,bytes=len(raw),sha256=digest,stat_before=b,old_main_or_cases_executed=False));return raw
def method(rel,digest,name):
    bind(rel,digest);spec=importlib.util.spec_from_file_location(name,ROOT/rel);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
class BoundedMAIN:
    def __init__(self):
        self.path=ROOT/'evidence/firmware-analysis/main_02bd.bin';self.before=stat(self.path);self.f=self.path.open('rb');self.log=[]
        section=json.loads(bind('evidence/firmware-analysis/native-sections.json','07e37b4eef51a0844b8e8207fdfc1dd91161bdefe1870d038577f0df6aa98d9b'))
        self.copies=section['copies'];self.expected=section['stock_sha256'];need(self.expected=='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8','Exact MAIN inherited digest')
    def runtime_to_load(self,a,n=1):
        c=[x for x in self.copies if x['runtime_start']<=a and a+n<=x['runtime_end']];need(len(c)==1,'Unique mapped page');return c[0]['load_start']+a-c[0]['runtime_start']
    def read(self,a,n):
        need(0<=a-0x50000<=a-0x50000+n<=self.before[2] and n<=8192,'Bounded MAIN page');self.f.seek(a-0x50000);raw=self.f.read(n);need(len(raw)==n,'MAIN short');self.log.append(dict(load=a,bytes=n,sha256=sha(raw)));return raw
    def close(self):
        self.f.close();need(stat(self.path)==self.before,'MAIN changed')

def prefix(cpu,native_dir,layout,ID,raw,offset,size,expected,projection,source):
    initial=((ID-1)*layout['record_bits'])%8;span=(initial+layout['record_bits']+7)//8
    need(len(raw)==span+4,'Proposed true packed span plus four explicit canary bytes')
    value=(int.from_bytes(raw[:span],'little')>>initial)&((1<<layout['record_bits'])-1)
    normalized=value.to_bytes((layout['record_bits']+7)//8,'little')
    direct,progress=projection(normalized,layout);need(direct==expected,'Independent semantic contract versus proposed wire')
    u,pages=cpu.machine([0x044B1000,0x0448E000,0x0448F000,0x00307000,0x001C8000,0x00112000,0x00427000,0x00373000])
    u.mem_write(DIR,native_dir);u.mem_write(DIR+0x154,struct.pack('<I',CTX));u.mem_write(CTX+0x20,struct.pack('<2I',FILE,0));u.mem_write(FILE+0xc,struct.pack('<2I',size,0))
    pointer=BUF+4096-len(raw);u.mem_write(pointer,raw);u.mem_protect(BUF,4096,UC_PROT_READ)
    trace=[];maps=[];events=[];stops=[]
    boundaries={0x044B1190:8,0x044B11DE:28,0x044B122E:16,0x044B1268:0,0x044B12A4:12,0x044B12DE:4,0x044B1314:20,0x044B1344:24}
    def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
    def observe(uc,pc,n,_):
        trace.append((pc,bytes(uc.mem_read(pc,n)).hex()))
        if pc==0x00112194:
            fp,dst,mode=[uc.reg_read(r)for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
            need(fp==FILE and word(FILE+0x10)==offset and mode==0 and not maps,'Only declared proposed FS slice')
            uc.mem_write(dst,struct.pack('<I',pointer));uc.reg_write(UC_ARM_REG_R0,len(raw));uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            maps.append(dict(logical_offset=offset,bytes=len(raw),initial_shift=initial,source_is_proposed_payload=True,fixture_realigned=False,four_following_bytes_are_explicit_canaries=True,canary_hex=raw[-4:].hex(),readonly_fixture_tail_at_unmapped_page=True))
        elif pc in boundaries:
            reader=uc.reg_read(UC_ARM_REG_SP)+0x10;bits=(word(reader+8)-offset)*8-word(reader)
            events.append(dict(native_pc=hex(pc),output_offset=boundaries[pc],record_bits_consumed=bits-initial))
        elif pc==0x0448F740:stops.append(pc);uc.emu_stop()
        elif pc==RET:raise ValueError('Full metadata return unexpectedly completed')
    hook=u.hook_add(UC_HOOK_CODE,observe)
    for r,v in [(UC_ARM_REG_R0,DIR),(UC_ARM_REG_R1,ID),(UC_ARM_REG_R2,layout['level']),(UC_ARM_REG_R3,OUT)]:u.reg_write(r,v)
    u.emu_start(0x044B10E5,RET+2,count=30000,timeout=1000000)
    output=bytes(u.mem_read(OUT,32));actual={f'+{x:02x}':struct.unpack_from('<I',output,x)[0]for x in range(0,32,4)}
    need(actual==expected and len(maps)==1 and stops==[0x0448F740],'New original prefix independent contract')
    need([(x['output_offset'],x['record_bits_consumed'])for x in events]==[(x['output_offset'],x['bits_consumed'])for x in progress],'Original dynamic bit consumption')
    need(bytes(u.mem_read(pointer,len(raw)))==raw,'Readonly proposed payload/canary mutated')
    result=dict(level=layout['level'],lowID=ID,proposed_MDR_offset=offset,initial_bit_shift=initial,record_bits=layout['record_bits'],source_payload=source,proposed_span_hex=raw[:span].hex(),normalized_payload_hex=normalized.hex(),four_explicit_following_canary_bytes_hex=raw[-4:].hex(),independent_expected_native_fields=expected,actual_original_native_fields=actual,actual_output_hex=output.hex(),actual_bit_events=events,instructions=len(trace)-1,trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages,FS_fixture=maps[0],stop_before_metadata='0x0448F740',actual_candidate_IMG_bytes_read=0,full_getter_or_query_return=False)
    u.hook_del(hook);del u;gc.collect();return result

def main():
    need(not(HERE/'proof.json').exists(),'New terminal proof only')
    rootproof=json.loads(bind('staging/navigation-native-new-street-family-payload-v1/proof.json','ff51c96544d01de68a4630fe25490e3d9857005d0f308c5796bfedbe058eab6d'))
    source=json.loads(bind('staging/navigation-native-new-street-source-example-v1/candidate.json','d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c'))
    layout=json.loads(bind('staging/navigation-country-native-lane-candidate-v3/actual-output-layout.json','4abdc75c4af78dbfcdae421d68e838042e1756f978bff0f342c793bc4d411a9a'))
    need(rootproof['all_passed'] and rootproof['current_family_records_copied_verbatim']==441 and rootproof['new_street_ID']==48312 and rootproof['source_candidate_name']==source['streettext']=='敦富六街','Pinned finite street/house identity')
    need(not rootproof['installable'] and not rootproof['source_alias_history_verified'] and not rootproof['district_polygon_verified'],'Outstanding source gates retained')
    payloads={a['path'].split('/')[-1]:bind(a['path'],a['sha256'],7000)for a in rootproof['artifacts']}
    need(len(payloads['L3-family-append.bin'])==6188 and len(payloads['L4-house-append.bin'])==len(payloads['L2-patch-record.bin'])==16,'Exact assigned payloads')
    machine=method('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','newstreet_cpu_machine')
    projected=method('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py','bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','newstreet_direct_projection')
    lbl=method('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py','bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','newstreet_lbl_body')
    # Geometry below is explicitly proposed from sealed metadata, not an actual candidate DIR.
    original={x['level']:x for x in layout['tables']};proposed={}
    need(original[3]['stride']==112 and original[3]['count']==47870 and original[4]['count']==4896236,'Current-profile metadata contract')
    cursor=original[6]['start']
    for level in [6,5,4,3,2,1]:
        t=original[level];count=t['count']+(442 if level==3 else 1 if level==4 else 0);n=(count*t['stride']+7)//8
        proposed[level]=dict(level=level,start=cursor,bytes=n,count=count,record_bits=t['stride'],widths=t['widths'],flags=t['flags']);cursor+=n
    proposed_size=cursor+120;need(proposed_size==149226560,'Proposed table geometry arithmetic')
    native_dir=bytearray(struct.pack('<I',6))
    for level in range(1,7):
        t=proposed[level];native_dir.extend(struct.pack('<4I',t['count'],t['record_bits'],t['start'],t['bytes'])+bytes(t['widths'])+bytes(t['flags'])+bytes(2))
    need(len(native_dir)==172,'Proposed original native directory shape')
    coords=source['raw24'];need(coords==rootproof['source_raw24']==[1127253,5625400],'Independent coordinate source contract')
    common={'+08':1,'+14':coords[0],'+18':coords[1]}
    street=dict(common,**{'+1c':0xffffffff,'+10':475679,'+00':4896237,'+0c':1,'+04':4})
    house=dict(common,**{'+1c':0xffffffff,'+10':2967,'+00':0,'+0c':0,'+04':0})
    oldL2=source['original_city_district_relationship']['independent_actual_original_family_snapshot']['actual_original_L2_fields']
    district={'+08':oldL2['mapordinal'],'+1c':oldL2['secondary_ref'],'+10':oldL2['primary_ref'],'+00':47871,'+0c':442,'+04':oldL2['child_level_and_flags'],'+14':oldL2['raw_location_a'],'+18':oldL2['raw_location_b']}
    need((district['+1c'],district['+10'],district['+04'])==(24068,24067,3),'Independent original district record fields')
    oldwindow=bytes.fromhex(rootproof['actual_L2']['hex']);need(oldwindow.hex()==oldL2['span_hex'],'Independent original L2 window')
    district_value=int.from_bytes(payloads['L2-patch-record.bin'],'little');need(district_value>>122==0,'L2 normalized padding zero')
    mask=((1<<122)-1)<<2;oldmixed=int.from_bytes(oldwindow,'little');mixed=(oldmixed&~mask)|(district_value<<2)
    need(((mixed^oldmixed)&~mask)==0,'Proposed L2 mixed window retains actual neighboring bits')
    source_rows=[(2,74,mixed.to_bytes(16,'little'),district,'L2-patch-record.bin',bytes.fromhex('5aa53cc3')),
                 (3,48312,payloads['L3-family-append.bin'][-14:],street,'L3-family-append.bin final14 bytes',bytes.fromhex('decafbad')),
                 (4,4896237,payloads['L4-house-append.bin'],house,'L4-house-append.bin',bytes.fromhex('a17e09c4'))]
    firmware=BoundedMAIN();cpu=machine.CPU(firmware)
    try:
        cases=[]
        for level,ID,raw,expected,payload,canary in source_rows:
            t=proposed[level];offset=t['start']+(ID-1)*t['record_bits']//8
            cases.append(prefix(cpu,bytes(native_dir),t,ID,raw+canary,offset,proposed_size,expected,projected.projection,payload))
        pointer,size=struct.unpack('<2I',payloads['LBL-header-pointer-size.bin']);need((pointer,size)==(3812824,3805448),'Proposed label metadata bytes')
        fields=dict(label_start=pointer,label_size=size,shift=3,encoding=10,codepage=950)
        extension=payloads['LBL-label-extension.bin'];need(extension.split(b'\0',1)[0].decode('cp950')==source['streettext'] and len(extension)==16,'Source-bound CP950 extension')
        text=lbl.fragment_case(cpu.read,475679,fields,extension)
        text['fixture_scope']='Proposed metadata start3812824/size3805448/shift3/CP950 and actual source-bound16-byte extension supplied explicitly. No GMP file, original full header/parser, getter, FS or registry is executed.'
        need(text['actual_GMP_offset']==7618256 and text['host_CP950_display_of_actual_native_output']=='敦富六街' and text['actual_byte_copy_and_termination_passed'],'One proposed new label address and byte-copy')
        firmware.close()
        for dep in DEPS:need(stat(ROOT/dep['path'])==dep['stat_before'],'Input modified during finite CPU scope:'+dep['path'])
        result=dict(schema='garmin-proposed-new-street-payload-native-prefix/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_sha256=sha(Path(__file__).read_bytes()),all_assigned_checks_passed=True,dependencies=DEPS,
            original_MAIN=dict(sha256_inherited=firmware.expected,stat_before=firmware.before,stat_after=stat(firmware.path),bounded_reads=firmware.log,total_bytes_read=sum(x['bytes']for x in firmware.log),handle_closed=True,full_MAIN_hash_rerun=False),
            source_street='敦富六街',source_house='368號',source_ids=source['source_ids'],source_alias_history_verified=False,district_polygon_verified=False,
            proposed_native_directory_hex=bytes(native_dir).hex(),proposed_tables=list(proposed.values()),proposed_MDR_size=proposed_size,proposed_directory_from_existing_layout_metadata_only=True,full_MDR_GMP_or_IMG_constructed=False,
            new_original_prefix_cases=cases,new_original_prefix_case_count=3,L2_mixed_bits=dict(initial_shift=2,original_window_hex=oldwindow.hex(),proposed_window_hex=mixed.to_bytes(16,'little').hex(),changed_significant_bits_only=True,neighboring_head2_tail4_bits_retained=True),
            new_proposed_LBL_address_and_bytecopy=text,new_proposed_LBL_fragment_case_count=1,proposed_LBL_metadata=fields,label_extension_sha256=sha(extension),actual_candidate_IMG_bytes_read=0,device_IO=False,
            full_getter_metadata_registry_query_UI_route=False,installable=False,full_Taiwan_update_complete=False,
            limits=['Three original packed-reader prefixes run on explicitly proposed DIR and FS frames; synthetic following canaries are not real candidate following bytes.',
                    'Proposed L2 byte window preserves original captured neighboring bits; this does not assemble a whole table or repair JAI relationships.',
                    'The label address/byte-copy fragment runs on source-bound CP950 extension and proposed metadata; it is not a successful complete GMP getter or map-registry result.',
                    'Aliases, district polygon, JAI prefix/segments/frontend, full query, 8K acceptance, destination and route remain unverified. No existing candidate or device was opened.'])
        out=HERE/'proof.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(proof_path=str(out.relative_to(ROOT)),proof_sha256=sha(out.read_bytes()),all_assigned_checks_passed=True,original_prefixes=3,proposed_LBL_fragments=1,IMG_bytes=0,MAIN_bytes=result['original_MAIN']['total_bytes_read'],handles_closed=True,query_or_device=False),ensure_ascii=False))
    finally:firmware.f.close()
if __name__=='__main__':
    try:main()
    except Exception as e:
        p=HERE/'failure-receipt.json';need(not p.exists(),'Preserve first failure');p.write_text(json.dumps(dict(source_sha256=sha(Path(__file__).read_bytes()),error=repr(e),traceback=traceback.format_exc(),IMG_opened=False,device_IO=False),indent=2)+'\n');raise
