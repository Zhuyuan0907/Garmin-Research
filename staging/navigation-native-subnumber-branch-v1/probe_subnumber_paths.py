#!/usr/bin/env python3
"""New finite stock subnumber/body scope; never run an inherited main/suite.

The numeric callback starts after its real getter call, with actual stock CP950
label bytes explicitly placed in its frame. No getter success hook is used.
"""
import datetime, gc, hashlib, importlib.util, json, struct, sys, traceback
from pathlib import Path
sys.dont_write_bytecode = True
ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from unicorn import UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB

def need(ok,msg):
    if not ok: raise ValueError(msg)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
DEPS=[]
def bind(rel,digest):
    p=ROOT/rel;b=stat(p);raw=p.read_bytes();need(sha(raw)==digest and stat(p)==b,'Dependency:'+rel)
    DEPS.append(dict(path=rel,bytes=len(raw),sha256=digest,stat=b,old_main_or_cases_executed=False))
    return raw
def mod(rel,digest,name):
    bind(rel,digest);s=importlib.util.spec_from_file_location(name,ROOT/rel);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

class BoundedMAIN:
    """Only mapped source pages; exact complete MAIN digest inherited, not rerun."""
    def __init__(self):
        self.path=ROOT/'evidence/firmware-analysis/main_02bd.bin';self.before=stat(self.path);self.f=self.path.open('rb');self.log=[]
        sections=json.loads(bind('evidence/firmware-analysis/native-sections.json','07e37b4eef51a0844b8e8207fdfc1dd91161bdefe1870d038577f0df6aa98d9b'))
        self.copies=sections['copies'];self.expected=sections['stock_sha256']
        need(self.expected=='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8','MAIN source reference')
    def runtime_to_load(self,a,n=1):
        ms=[c for c in self.copies if c['runtime_start']<=a and a+n<=c['runtime_end']]
        need(len(ms)==1,'No unique runtime mapping');return ms[0]['load_start']+a-ms[0]['runtime_start']
    def read(self,a,n):
        need(0<=a-0x50000<=a-0x50000+n<=self.before[2],'MAIN bound')
        self.f.seek(a-0x50000);raw=self.f.read(n);need(len(raw)==n,'MAIN short read')
        self.log.append(dict(load=a,bytes=n,sha256=sha(raw)));return raw
    def close(self):
        self.f.close();need(stat(self.path)==self.before,'MAIN modified')

def main():
    need(not (HERE/'proof.json').exists(),'Refuse terminal proof overwrite')
    container=mod('staging/navigation-native-general-writer-v1/native_ap_writer.py','cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8','sub_stock_stream')
    reused=mod('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py','bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','sub_projection')
    prefix=mod('staging/navigation-country-native-cpu-v1/probe_country_candidate.py','312d8dc58e2c2cf7e6c6ab1b295e5befece64929dc8e56625561220d1c2f22ff','sub_native_prefix')
    machine=mod('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py','2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','sub_machine')
    sort=mod('staging/navigation-firmware-sort-v1/probe_original_sort_units_v4.py','4c2382f3f0142e9f108e457c88915651418d1afd09628cb40aef0af969d7fcd1','sub_sort_machine')
    observations=json.loads(bind('staging/navigation-native-deeper-address-plan-v1/deeper-address-plan.json','289e502c427e1798927f0187e170909b545ca8ae9b5ab1351bce270f4ae160fd'))
    consumer=json.loads(bind('staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json','2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60'))
    native_dir=bytes.fromhex(consumer['cases'][0]['output_hex']);layouts={}
    for x in consumer['cases'][0]['decoded_records']:
        layouts[x['ordinal_zero_based']+1]=dict(level=x['ordinal_zero_based']+1,start=x['span_start'],bytes=x['span_bytes'],count=x['native_floor_spanbits_div_scalar'],record_bits=x['third_scalar'],widths=x['six_bit_values_at_record_offsets_10_to_17'],flags=x['flags_at_record_offsets_18_19'])
    firmware=BoundedMAIN();cpu=machine.CPU(firmware)
    path=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img';before=stat(path);stream=path.open('rb');img=container.StreamIMG(stream)
    logical_reads=[];labels={};records={};native=[]
    def rd(name,start,n,purpose):
        need(n<=102400,'Logical per-read cap');raw=b''.join(img.iter_component(name,offset=start,length=n,chunk_bytes=65536));need(len(raw)==n,'Logical short')
        logical_reads.append(dict(component=name,offset=start,bytes=n,purpose=purpose,sha256=sha(raw)));return raw
    def label(ref):
        if ref not in labels:
            raw=rd('I053061A.GMP',6566+ref*8,64,'selected actual CP950 label');nul=raw.index(0)
            labels[ref]=dict(ref=ref,label=raw[:nul].decode('cp950'),raw_hex=raw[:nul+1].hex(),window_hex=raw.hex())
        return labels[ref]
    def record(level,ID,reason,run=False):
        key=(level,ID)
        if key not in records:
            l=layouts[level];bit=(ID-1)*l['record_bits'];start=l['start']+bit//8;span=(bit%8+l['record_bits']+7)//8
            need(1<=ID<=l['count'],'Record ID');raw=rd('00004171.MDR',start,span+4,reason)
            norm=((int.from_bytes(raw,'little')>>(bit%8))&((1<<l['record_bits'])-1)).to_bytes((l['record_bits']+7)//8,'little')
            fields,_=reused.projection(norm,l);r=dict(level=level,ID=ID,offset=start,initial=bit%8,span=span,raw_hex=raw.hex(),payload=norm.hex(),fields=fields)
            r['label']=label(fields['+10']);records[key]=r
        r=records[key]
        if run:
            native.append(prefix.native_record(cpu,reused,native_dir,layouts[level],ID,bytes.fromhex(r['raw_hex']),r['offset'],img.components['00004171.MDR'].size,r['fields']))
        return r
    try:
        need(before[2]==96739328 and img.components['00004171.MDR'].size==92653600,'Exact stock source size')
        d=rd('00004171.MDR',92653480,120,'exact original six-entry DIR bytes')
        need(all(struct.unpack_from('<3I',d,(lev-1)*20)==(l['start'],l['bytes'],l['record_bits']) for lev,l in layouts.items()),'Frozen original directory versus actual')
        selected=[]
        # New cases chosen because they are subnumber/integer boundaries at three real table levels.
        for branch,indices in [(1,[1,2,3,4,5,6,7]),(7,[0,1,2,3,4,5]),(11,[5,6,7,8,9])]:
            b=observations['representative_street_branches'][branch];group=[]
            for ix in indices:
                observed=b['children'][ix]['record'];r=record(observed['level'],observed['one_based_ID'],'finite stock subnumber boundary',run=True)
                need(r['label']['label']==observed['primary_label']['label'] and r['fields']['+04']==observed['child_level_and_flags'],'Original observed subnumber source differs')
                group.append(r)
            selected.append(dict(native_street=b['native_street'],sampled_adjacent_records=group,whole_street_group_scanned=False))
        # Resolve known raw13 root using only its actual original bounded59-child group.
        root=record(3,26718,'raw13 known original root')
        f=root['fields'];need(f['+04']==4 and f['+0c']<=64,'Bounded raw13 root original branch')
        raw13=[]
        for ID in range(f['+00'],f['+00']+f['+0c']):
            r=record(4,ID,'bounded original raw13 root child')
            if r['fields']['+04']==13:raw13.append(r)
        need(len(raw13)==1 and raw13[0]['label']['label']=='88巷','Finite original raw13 witness expected')
        r13=raw13[0];native.append(prefix.native_record(cpu,reused,native_dir,layouts[4],r13['ID'],bytes.fromhex(r13['raw_hex']),r13['offset'],92653600,r13['fields']))
        need(r13['fields']['+00']==1417151 and r13['fields']['+0c']==1,'Original raw13 unchanged child references')
        child=record(5,1417151,'single raw13 actual child',run=True)
        # Original SRT parser builds the actual CP950 descriptor. Entire101KB SRT is bounded, not a map scan.
        srt=rd('00004171.SRT',0,img.components['00004171.SRT'].size,'actual original CP950 SRT')
        p=sort.Probe(firmware,srt)
        # Do not invoke inherited .call(), which writes failures into its old scope.
        sp=sort.STACK+0x1f00
        p.u.mem_write(sort.DESC,struct.pack('<2I',sort.SRT,2)+bytes(100))
        for reg,val in [(UC_ARM_REG_CPSR,0x3f),(UC_ARM_REG_SP,sp),(UC_ARM_REG_LR,sort.RET|1),(UC_ARM_REG_R0,sort.DESC),(UC_ARM_REG_R1,21),(UC_ARM_REG_R2,2),(UC_ARM_REG_R3,0)]:p.u.reg_write(reg,val)
        p.u.emu_start(0x23ce93,sort.RET+2,count=20000,timeout=1000000)
        desc=bytes(p.u.mem_read(sort.DESC,108));need(p.trace[-1]['pc']==sort.RET and p.u.reg_read(UC_ARM_REG_R0)==0 and struct.unpack_from('<H',desc,12)[0]==950,'Actual CP950 SRT descriptor')
        parser=dict(entry='0x23CE92',returned=0,descriptor_hex=desc.hex(),flags=struct.unpack_from('<I',desc,16)[0],instructions=len(p.trace),input_SRT_sha256=sha(srt),memory_kind2_explicit_fixture=True)
        for page in [0x044B1000,0x044B2000,0x0448C000,0x0448D000,0x0448E000,0x0448F000]:
            raw=cpu.read(page,4096);p.u.mem_map(page,4096);p.u.mem_write(page,raw);p.u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
        comparisons=[]
        def compare(left,right,name):
            a=bytes.fromhex(left['raw_hex']);b=bytes.fromhex(right['raw_hex']);need(len(a)<80 and len(b)<80,'Small actual labels')
            frame=sort.STACK+0x1700;p.u.mem_write(frame,bytes(0x150));p.u.mem_write(frame+0x6c,b);p.u.mem_write(frame+0x68,struct.pack('<I',sort.DESC));p.u.mem_write(frame+4,struct.pack('<I',sort.DESC));p.u.mem_write(sort.STRING,a)
            for reg,val in [(UC_ARM_REG_CPSR,0x3f),(UC_ARM_REG_SP,frame),(UC_ARM_REG_R0,0),(UC_ARM_REG_R6,sort.STRING),(UC_ARM_REG_R7,0)]:p.u.reg_write(reg,val)
            p.trace.clear();stopped=[]
            def stop(uc,pc,size,_):
                if pc==0x044B1E9C:stopped.append(pc);uc.emu_stop()
                need(pc!=0x044B153A and pc!=0x0448F740,'Body attempted full getter/metadata')
            hook=p.u.hook_add(UC_HOOK_CODE,stop)
            p.u.emu_start(0x044B19FD,0x044B1EA2,count=30000,timeout=1000000)
            result=p.u.reg_read(UC_ARM_REG_R7);need(stopped==[0x044B1E9C] and result in (0,1,2),'Original callback body did not reach finite stop')
            trace=p.trace[:];p.u.hook_del(hook)
            comparisons.append(dict(name=name,left=left,right=right,native_body_result=result,entry='0x044B19FC',stop='0x044B1E9C',instructions=len(trace),trace_sha256=sha(json.dumps(trace).encode()),actual_PC_samples=sorted({hex(x['pc'])for x in trace if x['pc'] in [0x044B1D14,0x044B1D8E,0x044B1E12,0x044B1E1A,0x044B175A]}),getter_executed=False,successful_getter_return_not_hooked=True,explicit_source_backed_postgetter_frame=True))
        for group in selected:
            rr=group['sampled_adjacent_records']
            for a,b in zip(rr,rr[1:]):compare(a['label'],b['label'],'actual adjacent L'+str(a['level']))
        samples={x['label']:x for x in observations['stock_label_samples']}
        for a,b in [('1號','1之1號'),('1之1號','1號'),('1之1號','1之1號'),('1之2號','1之3號'),('22之2號','22之5號'),('100之1號','100號')]:
            refs={x['label']:x['reference']for x in observations['stock_label_samples']}
            # Minquan refs22之... are actual small group labels, not all in standalone sample index.
            refs.update({r['label']['label']:r['label']['ref']for g in selected for r in g['sampled_adjacent_records']})
            compare(label(refs[a]),label(refs[b]),'new asymmetric/equal/same-base control')
        need(all(c['native_body_result']==1 for c in comparisons if c['name'].startswith('actual adjacent')),'Original adjacent source order differs from actual numeric callback body')
        # New static evidence excludes embedded literal pool.
        md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);fragments=[]
        for a,n,why in [(0x044B19D8,0x2c,'numeric callback getter ABI and postgetter entry'),(0x044B1F68,0x66,'callback selection and binary versus linear dispatch'),(0x001ACA74,0xc2,'general comparator ABI'),(0x00173C54,0x5a,'child descriptor flags')]:
            raw=cpu.read(a,n);fragments.append(dict(address=hex(a),bytes=n,sha256=sha(raw),raw_hex=raw.hex(),purpose=why,instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in md.disasm(raw,a)]))
        limits=['Only real stock packed prefixes and source-backed original numeric callback body execute. The callback getter, map registry, metadata lifecycle, entire query and UI are not executed.',
                'The numeric callback is selected under range-search attributes; its complete live selector prerequisites remain unproved. CP950/SRT metadata derive from original bytes, but frame/iterator and file-kind2 storage are explicit fixtures.',
                'Raw13 is preserved next5+unknown bit8; one actual88巷 child is read, not a proof that every raw13 is a subnumber or that flag8 has a known semantic name.',
                'No source ledger, PBF, candidate v3, complete IMG hash, installation, route or device operations. No automatic new subnumber records generated.']
        stream.close();firmware.close();need(stat(path)==before,'Original stock changed');need(sum(x['bytes']for x in img.read_log)<200000,'Actual stock read ceiling')
        proof=dict(schema='garmin-native-stock-subnumber-body/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),all_assigned_checks_passed=True,source_sha256=sha(Path(__file__).read_bytes()),dependencies=DEPS,
                   original_AP=dict(path=str(path.relative_to(ROOT)),bytes=before[2],sha256_inherited='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',stat_before=before,stat_after=stat(path),full_hash_rerun=False,handle_closed=True),original_MAIN=dict(sha256_inherited=firmware.expected,stat_unchanged=True,handle_closed=True,bounded_read_log=firmware.log),actual_IMG_reads=img.read_log,actual_IMG_read_bytes=sum(x['bytes']for x in img.read_log),logical_reads=logical_reads,
                   selected_original_groups=selected,raw13=dict(original_root=root,original_record=r13,actual_single_child=child,raw_flags_preserved=True,unknown_branch_semantic_not_inferred=True),new_original_prefix_case_count=len(native),new_original_prefix_cases=native,
                   actual_CP950_SRT_parser=parser,new_numeric_callback_body_comparison_count=len(comparisons),numeric_comparisons=comparisons,static_new_fragments=fragments,
                   all_sampled_original_adjacent_records_ordered_in_original_callback_body=True,native_result_code_1='left/query before right/candidate (grounded by original numeric and weight branches)',full_getter_registry_query_UI_device=False,no_sort_or_getter_policy_hook=True,source_records_modified=False,installable=False,limits=limits)
        (HERE/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_assigned_checks_passed=True,proof_path=str((HERE/'proof.json').relative_to(ROOT)),proof_sha256=sha((HERE/'proof.json').read_bytes()),IMG_bytes=proof['actual_IMG_read_bytes'],prefix_cases=len(native),numeric_body_comparisons=len(comparisons),SRT_flags=hex(parser['flags']),handles_closed=True,full_query_or_device=False),ensure_ascii=False))
    finally:
        stream.close();firmware.f.close()

if __name__=='__main__':
    try: main()
    except Exception as e:
        p=HERE/'failure-receipt.json';need(not p.exists(),'Retain first failure receipt')
        p.write_text(json.dumps(dict(source_sha256=sha(Path(__file__).read_bytes()),error=repr(e),traceback=traceback.format_exc(),old_artifacts_modified=False,device_IO=False),indent=2)+'\n');raise
