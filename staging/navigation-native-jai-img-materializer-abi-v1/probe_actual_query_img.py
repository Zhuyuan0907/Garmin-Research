#!/usr/bin/env python3
"""One genuine JAI materializer branch and independently chained actual IMG readers.

Never claims an uninterrupted native UI/full-getter result. No old cases/main.
"""
import ast, gc, hashlib, importlib.util, json, re, sqlite3, struct, sys
from datetime import datetime, timezone
from pathlib import Path
sys.dont_write_bytecode=True
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;BASE=0x04420000
DEPS=[]
CTX,FILE,DIR,OUT,RET,BUF,STACK=0x09000000,0x09001000,0x09002000,0x09003000,0x09004000,0x09006000,0x09010000
IMG='staging/navigation-new-street-v2-4k-offline-prototype-v2/new-street-v2-original4k-experiment.img.disabled'

def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def bind(rel,digest,cap=500000):
    p=ROOT/rel;before=stat(p);need(before[2]<=cap,'Small bound input');raw=p.read_bytes()
    need(sha(raw)==digest and stat(p)==before,'Pinned source:'+rel)
    DEPS.append(dict(path=rel,bytes=len(raw),sha256=digest,stat_before=before,old_main_or_cases_executed=False));return raw
def method(rel,digest,name):
    bind(rel,digest);spec=importlib.util.spec_from_file_location(name,ROOT/rel);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def save(name,row):
    with (HERE/name).open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n')

class BudgetMAIN:
    def __init__(self):
        self.path=ROOT/'evidence/firmware-analysis/main_02bd.bin';self.before=stat(self.path);self.f=self.path.open('rb',buffering=0)
        meta=json.loads(bind('evidence/firmware-analysis/native-sections.json','07e37b4eef51a0844b8e8207fdfc1dd91161bdefe1870d038577f0df6aa98d9b'))
        self.copies=meta['copies'];self.expected=meta['stock_sha256'];self.cache={};self.log=[]
        initial=json.loads((HERE/'initial-code-capture-receipt.json').read_text());raw=(HERE/'MAIN-page-002cd000.bin').read_bytes()
        need(initial['stat_after']==self.before and sha(raw)==initial['sha256'],'Existing first page original identity')
        self.cache[0x2cd000]=raw;self.log.append(dict(runtime=0x2cd000,load=0x2cd000,bytes=4096,sha256=sha(raw),initial_capture=True))
    def runtime_to_load(self,a,n=1):
        c=[x for x in self.copies if x['runtime_start']<=a and a+n<=x['runtime_end']];need(len(c)==1,'Unique actual startup mapping');return c[0]['load_start']+a-c[0]['runtime_start']
    def load_to_runtime(self,a):
        c=[x for x in self.copies if x['load_start']<=a<x['load_end']]
        return c[0]['runtime_start']+a-c[0]['load_start'] if len(c)==1 else a
    def read(self,a,n):
        need(n in(4096,8192),'Bounded original pages only');out=bytearray()
        for off in range(0,n,4096):
            load=a+off
            if load not in self.cache:
                need(sum(r['bytes']for r in self.log)+4096<=65536,'New original MAIN content cap')
                self.f.seek(load-0x50000);raw=self.f.read(4096);need(len(raw)==4096,'Original shortread')
                runtime=self.load_to_runtime(load);self.cache[load]=raw
                (HERE/('MAIN-page-%08x.bin'%runtime)).write_bytes(raw)
                self.log.append(dict(runtime=runtime,load=load,bytes=4096,sha256=sha(raw),initial_capture=False))
            out.extend(self.cache[load])
        return bytes(out)
    def close(self):self.f.close();need(stat(self.path)==self.before,'Original MAIN changed')

def header_directory_fragment(cpu,header):
    u,pages=cpu.machine([0x002cd000,0x0038c000]);sp=u.reg_read(UC_ARM_REG_SP)
    u.mem_write(sp+0x68,header[600:616]);u.mem_write(sp+0xa4,struct.pack('<I',CTX+0x2c0));u.reg_write(UC_ARM_REG_R7,CTX+0x280)
    trace=[];stop=[]
    def hook(uc,a,n,_):
        trace.append((a,bytes(uc.mem_read(a,n)).hex()))
        if a==0x2cd49e:stop.append(a);uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x2cd481,0x2cd4a0,count=1000,timeout=1000000)
    need(stop==[0x2cd49e],'Actual provider fragment stop')
    fields=struct.unpack('<4I',u.mem_read(CTX+0x2b4,16));need(fields[1:]==(20,1,6),'Actual directory item width/flags/count')
    result=dict(entry='0x002CD480',stop='0x002CD49E',full_header_function_executed=False,
        input_actual_MDR_header_slice600_616_hex=header[600:616].hex(),actual_context_fields2b4_2c0=list(fields),
        native_context_slice280_2c4=bytes(u.mem_read(CTX+0x280,0x44)).hex(),
        fixture='Actual header bytes staged at observed stack seam; genuine stores and real division helper; full FS parser/init not executed.',
        instructions=len(trace)-1,trace_sha256=sha(json.dumps(trace).encode()),original_RX_pages=pages)
    del u;gc.collect();return result

def lbl_parser_fragment(cpu,header):
    u,pages=cpu.machine([0x002cf000]);sp=u.reg_read(UC_ARM_REG_SP);u.reg_write(UC_ARM_REG_R7,CTX+0x340)
    trace=[]
    def phase(entry,end,data):
        u.mem_write(sp+0x14,data);stop=[]
        def hook(uc,a,n,_):
            trace.append((a,bytes(uc.mem_read(a,n)).hex()))
            if a==end:stop.append(a);uc.emu_stop()
        h=u.hook_add(UC_HOOK_CODE,hook);u.emu_start(entry|1,end+2,count=100,timeout=100000);u.hook_del(h);need(stop==[end],'Actual LBL field fragment')
    phase(0x2cf44a,0x2cf45c,header[21:31]);phase(0x2cf83c,0x2cf842,header[170:192])
    fields=dict(label_start=struct.unpack('<I',u.mem_read(CTX+0x364,4))[0],label_size=struct.unpack('<I',u.mem_read(CTX+0x368,4))[0],
        shift=bytes(u.mem_read(CTX+0x345,1))[0],encoding=bytes(u.mem_read(CTX+0x346,1))[0],codepage=struct.unpack('<H',u.mem_read(CTX+0x34c,2))[0])
    need(fields==dict(label_start=3812824,label_size=3805448,shift=3,encoding=10,codepage=950),'Actual newstreet GMP LBL metadata')
    out=dict(actual_metadata_fields=fields,original_RX_pages=pages,instructions=len(trace)-2,trace_sha256=sha(json.dumps(trace).encode()),
        fixture='Actual new GMP/LBL header fields staged at original parser field-store seams; no complete header FS or registry getter.')
    del u;gc.collect();return out

def jai_materializer():
    rel='staging/navigation-native-jai-frontend-abi-v1/probe_native_jai_frontend.py'
    code_src=bind(rel,'e3f26aaa55d6fb3b95072629ae147f6826ec3cf4fe3066dd17d5f72769ef9013')
    nodes=[n for n in ast.parse(code_src).body if isinstance(n,ast.ClassDef)and n.name=='Guest'];need(len(nodes)==1,'Only prior sealed Guest class, not cases/main')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),rel,'exec'),globals())
    class MaterializerGuest(Guest):
        def hook(self,uc,a,n,_):
            if a==0x044259FA: # previously bounded stop: continue genuine branch
                self.steps+=1;self.addresses.append(a);return
            if a in(0x0448FC58,0x0448D0D8):
                self.steps+=1
                if a==0x0448FC58:
                    x,y,count=self.r(0),self.r(1),self.r(2);need(count<=128,'Bounded encoded-token compare')
                    left=bytes(uc.mem_read(x,count));right=bytes(uc.mem_read(y,count));result=0 if left==right else(0xffffffff if left<right else 1)
                    self.events.append(dict(kind='fixture_encoded_ASCII_byte_compare',bytes=count,result=result));self.ret(result)
                else:
                    need(bytes(uc.mem_read(self.r(0),1))[0]<128,'ASCII encoded token advance fixture only');self.ret(1)
                return
            # The external encoding/compare veneers are outside the old landing
            # pages; mapped stub landings are declared, never native code.
            super().hook(uc,a,n,_)
    # Read only two relevant saved original JAI pages; no new original read.
    code=bytearray(65536);p=ROOT/'staging/navigation-native-jai-frontend-abi-v1/JAI-runtime-code-64KiB.bin';before=stat(p)
    with p.open('rb',buffering=0)as f:f.seek(0x4000);raw=f.read(8192)
    need(len(raw)==8192 and stat(p)==before,'Saved JAI window immutable');code[0x4000:0x6000]=raw
    dispatch=json.loads(bind('staging/navigation-firmware-address-v1/address-dispatch-evidence.json','ec01bf743cf465c3d6008542e143e5b07eb4208845b2fbf7a3c0f6242a55d92a'))
    table=bind('staging/navigation-native-jai-prefix-consumer-v1/SQL-table-window.bin','60b8a502db6f7239c1b5633bed0a4d970ac337f79530ffef22ad5e48ca4179d4')
    token='tkfadgjtkgdjedtkgbdgctkldhfi'
    db=ROOT/'staging/navigation-native-jai-full-db-adapter-prototype-v1/TWNJAI-offline-prototype.sqlite';db_before=stat(db)
    con=sqlite3.connect(db.resolve().as_uri()+'?mode=ro&immutable=1',uri=True);con.execute('PRAGMA query_only=ON');con.execute('PRAGMA cache_size=64')
    try:
        g=MaterializerGuest(bytes(code),table,dispatch['sql_table'],con,'new-full-token-through-real-parent-materializer',token,caller=0x04425726)
        g.u.mem_map(0x0448D000,4096,UC_PROT_READ|UC_PROT_EXEC)
        g.w32(g.OBJ+4,0x9004);g.statements[0x9004]=dict(sql=next(e['text']for e in dispatch['sql_table']if e['offset']=='0x18'),bindings={})
        descriptor=g.DATA+0x400;chain=g.DATA+0x500
        for a,v in [(g.out,0),(g.out+4,1),(g.out+8,descriptor),(descriptor,0),(descriptor+4,3),(descriptor+8,chain)]:g.w32(a,v)
        result=g.run('caller')
        need(result['stop_reason']=='native_function_return'and result['native_return_r0']==0,'One real caller/materializer branch actual return0')
        actual=list(struct.unpack('<9I',g.u.mem_read(chain,36)));expected=[3,48312,0,2,74,0xffffffff,1,8,0xffffffff]
        need(actual==expected and g.read32(g.out)==1 and g.read32(descriptor)==3,'Genuine result vector contains exact street/district/city chain')
        result.update(actual_query_result_vector_count=1,actual_native_chain_12byte_records=[actual[i:i+3]for i in range(0,9,3)],
            actual_result_descriptor_hex=bytes(g.u.mem_read(descriptor,12)).hex(),
            genuine_materializer_entry='0x04425304',genuine_parent_lookup='actual full readonly DB via declared external SQL fixtures',
            vector_and_chain_buffers_preallocated_fixture=True,allocator_not_executed=True,
            original_code_saved_pages=dict(path=str(p.relative_to(ROOT)),offset=0x4000,bytes=8192,sha256=sha(raw)),
            whole_UI_and_IMG_getter_not_called=True)
        del g;gc.collect()
    finally:con.close()
    need(stat(db)==db_before,'Complete offline DB unchanged')
    result['full_DB_identity']=dict(path=str(db.relative_to(ROOT)),stat_before=db_before,stat_after=stat(db),
        inherited_sealed_sha256='de631819f2829f465b7cb8a0888ea5b816e3190f231cb10178ec69ed98e00a85',wholehash_not_repeated=True,handles_closed=True)
    return result

def main():
    started=datetime.now(timezone.utc).isoformat();need(not(HERE/'proof.json').exists(),'Finite new proof only')
    producer=json.loads(bind('staging/navigation-new-street-v2-4k-offline-prototype-v2/proof.json','a03ba7d4a5a01138c5109610224be3aeec07f767632cf0aec70b3d793573b576'))
    seal=json.loads(bind('staging/navigation-new-street-v2-4k-offline-prototype-v2/sealed-files.json','5dc142d545ad114c727e7ecad97b8e42ef8df348aaaf406291a631e36496ba03'))
    source=json.loads(bind('staging/navigation-native-new-street-source-example-v1/candidate.json','d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c'))
    entry=next(e for e in seal['files']if e['path']==IMG);need(stat(ROOT/IMG)==entry['stat_at_seal'],'Exact frozen actual new4K IMG')
    machine=method('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','actual_newIMG_FAT_machine')
    reused=method('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py','bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','actual_newIMG_DIR_projection')
    v1=method('staging/navigation-country-native-cpu-v1/probe_country_candidate.py','312d8dc58e2c2cf7e6c6ab1b295e5befece64929dc8e56625561220d1c2f22ff','actual_newIMG_dynamic_prefix')
    lbl=method('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py','bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','actual_newIMG_LBL_copy')
    class BoundedCandidate(machine.CandidateIMG):
        def physical(self,off,n,purpose):
            need(0<=off<=off+n<=self.before[2] and sum(r['bytes']for r in self.log)+n<=131072,'Actual IMG read cap')
            self.stream.raw.seek(off);raw=self.stream.raw.read(n);need(len(raw)==n,'Actual raw IMG shortread')
            self.log.append(dict(purpose=purpose,physical_offset=off,bytes=n,sha256=sha(raw)));return raw
    candidate=BoundedCandidate(ROOT/IMG);firmware=BudgetMAIN();cpu=machine.CPU(firmware)
    try:
        need(candidate.block_size==4096 and candidate.before[2]==132173824,'Exact real original4K container')
        wh,header=candidate.read('00004171.MDR',0,772,'actual_newstreet_MDR_header')
        header_fragment=header_directory_fragment(cpu,header);directory_start=header_fragment['actual_context_fields2b4_2c0'][0]
        need(directory_start+120==candidate.components['00004171.MDR']['bytes']==124261511,'Original fragment gives actual component directory EOF')
        wd,raw_dir=candidate.read('00004171.MDR',directory_start,120,'actual_newstreet_DIR')
        native_dir,layouts,dirproof=reused.directory(cpu,header_fragment,raw_dir,directory_start)
        need((layouts[2]['count'],layouts[3]['count'])==(48312,3781595),'Actual native directory new tables')
        raw24=source['raw24'];old=source['original_city_district_relationship']['independent_actual_original_family_snapshot']['actual_original_L2_fields']
        expected2={'+00':47871,'+0c':442,'+04':3,'+08':1,'+10':old['primary_ref'],'+1c':old['secondary_ref'],'+14':old['raw_location_a'],'+18':old['raw_location_b']}
        expected3={'+00':3781595,'+0c':1,'+04':4,'+08':1,'+10':475679,'+1c':0xffffffff,'+14':raw24[0],'+18':raw24[1]}
        expected4={'+00':0,'+0c':0,'+04':0,'+08':1,'+10':2967,'+1c':0xffffffff,'+14':raw24[0],'+18':raw24[1]}
        records=[]
        for level,ID,expected in [(2,74,expected2),(3,48312,expected3),(4,3781595,expected4)]:
            t=layouts[level-1];bit=(ID-1)*t['record_bits'];offset=t['start']+bit//8;length=(bit%8+t['record_bits']+7)//8+4
            w,raw=candidate.read('00004171.MDR',offset,length,'actual_newstreet_L%d_ID%d'%(level,ID))
            result=v1.native_record(cpu,reused,native_dir,t,ID,raw,offset,124261511,expected);result['actual_IMG_source']=w;records.append(result)
        wg,gmp=candidate.read('I053061A.GMP',0,57,'actual_GMP_header');need(gmp[2:12]==b'GARMIN GMP','Actual GMP')
        lbl_start=struct.unpack_from('<7I',gmp,25)[2];wl,headerLBL=candidate.read('I053061A.GMP',lbl_start,661,'actual_new_LBL_header')
        need(struct.unpack_from('<H',headerLBL)[0]==661 and headerLBL[2:12]==b'GARMIN LBL','Actual LBL header')
        lbl_parse=lbl_parser_fragment(cpu,headerLBL);metadata=lbl_parse['actual_metadata_fields'];labels=[]
        for ref,text,length in [(475679,'敦富六街',16),(2967,'368號',32)]:
            off=metadata['label_start']+(ref<<metadata['shift']);w,raw=candidate.read('I053061A.GMP',off,length,'actual_newstreet_LBL_ref%d'%ref)
            actual=lbl.fragment_case(cpu.read,ref,metadata,raw);need(actual['actual_byte_copy_and_termination_passed']and actual['host_CP950_display_of_actual_native_output']==text,'Actual new IMG label copy')
            labels.append(dict(expected_text=text,native_ref=ref,actual_IMG_source=w,actual_original_copy_fragment=actual))
        candidate.close();firmware.close()
        materializer=jai_materializer();save('actual-native-materializer-case.json',materializer)
        need(materializer['actual_native_chain_12byte_records'][0][1]==records[1]['lowID'],'Native query materialized street is actual IMG lowID')
        reads=sum(x['bytes']for x in candidate.log);codebytes=sum(x['bytes']for x in firmware.log)
        proof=dict(schema='one-source-native-JAI-materializer-actual4K-IMG-linkage/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
            all_assigned_checks_passed=True,script_sha256=sha(Path(__file__).read_bytes()),dependencies=DEPS,
            candidate=dict(path=IMG,bytes=candidate.before[2],inherited_complete_SHA256=entry['sha256'],wholehash_not_repeated=True,
                stat_before=candidate.before,stat_after=stat(ROOT/IMG),stat_unchanged=True,handles_closed=True,block_bytes=4096,FAT_extent=candidate.extent),
            actual_IMG_read_log=candidate.log,total_actual_IMG_bytes_read=reads,IMG_read_cap=131072,
            original_MAIN=dict(inherited_whole_SHA256=firmware.expected,stat_before=firmware.before,stat_after=stat(firmware.path),
                bounded_page_reads=firmware.log,total_actual_new_MAIN_bytes=codebytes,cap=65536,handle_closed=True,fullhash_not_repeated=True),
            saved_previous_JAI_code_bytes_reused=8192,old_suites_or_old_cases_executed=False,
            actual_MDR_header_source=wh,actual_header_directory_provider_fragment=header_fragment,
            actual_directory_source=wd,actual_original_directory_execution=dirproof,
            exact_actual_new_container_native_prefix_count=3,actual_native_prefixes=records,
            actual_GMP_source=wg,actual_GMP_derived_LBL_offset=lbl_start,actual_LBL_header_source=wl,
            actual_new_LBL_parser_fragments=lbl_parse,actual_partial_original_LBL_labels=labels,
            true_native_JAI_materializer_branch_returned=True,true_JAI_chain=[[3,48312,0],[2,74,0xffffffff],[1,8,0xffffffff]],
            newstreet_child_L4_ID=3781595,actual_source_coords_raw24=raw24,
            actual_container_and_query_record_crossbinding_verified=True,
            uninterrupted_query_to_MDR_to_full_LBL_getter_execution=False,
            unknown_map_registry_metadata_query_provider_connections_not_fabricated=True,
            SQL_libc_object_vector_initialization_are_explicit_fixtures=True,
            source_OSM_geometry_inherited_complete=True,source_official_alias_still_held=True,
            native_UI_device_acceptance_installable=False,no_device_report_IMG_or_sealed_source_mutation=True,
            all_handles_closed=True,full_Taiwan_complete=False,
            limits=['One new actual container path, not replay of proposed three payload CPU scope.',
                'JAI full-token branch genuine prefix→fallback→family materializer returns0 with preallocated vector and real readonly SQLite boundary fixtures; no native SQLite/UTF/UI execution.',
                'Actual MDR header directory fields use original store/division fragment with explicit stack seam; full file/header parser not executed.',
                'Actual directory and packed prefixes execute separately with actual FS slices; prefix stops before0x0448F740 metadata/registry.',
                'Actual new LBL field stores/address/CP950 bytecopy execute separately, not a successful complete map-registry getter.',
                'Same lowID48312/city8/district74 binds query vector to actual container; unbroken frontend/provider path remains a gap.',
                'Official alias/physical road/UI/install acceptance remain unverified; original working device v2 unchanged.'])
        save('proof.json',proof)
        print(json.dumps(dict(all_assigned_checks_passed=True,actual_IMG_bytes=reads,new_MAIN_bytes=codebytes,
            native_materializer_return=materializer['native_return_r0'],native_chain=proof['true_JAI_chain'],prefixes=3,actual_labels=2,all_handles_closed=True)))
    finally:
        if not candidate.stream.closed:candidate.stream.close()
        if not firmware.f.closed:firmware.f.close()

if __name__=='__main__':main()
