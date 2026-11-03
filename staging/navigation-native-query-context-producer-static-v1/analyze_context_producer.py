#!/usr/bin/env python3
"""Finite static-only MDR context producer audit. No emulator or IMG open."""
import hashlib, json, struct
from datetime import datetime, timezone
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
PFX = 'staging/navigation-native-'
def sha(b): return hashlib.sha256(b).hexdigest()
def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
def need(x, msg):
    if not x: raise ValueError(msg)
def write(name, value):
    with (HERE/name).open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n')

def main():
    started = datetime.now(timezone.utc).isoformat()
    reads, manifests, loaded = [], {}, {}
    def read(rel, cap=100000, expected=None):
        if rel in loaded: return loaded[rel]
        p = ROOT/rel; before = stat(p)
        need(before[2] <= cap, 'Bounded local artifact: '+rel)
        b = p.read_bytes()
        need(stat(p) == before, 'Unchanged artifact: '+rel)
        if expected: need(sha(b) == expected, 'Sealed artifact identity: '+rel)
        reads.append(dict(path=rel, bytes=len(b), sha256=sha(b), stat_before=before,
                          stat_after=stat(p), original_MAIN_source_read=False,
                          original_IMG_source_read=False))
        loaded[rel] = b
        return b
    def sealed(stage, leaf, cap=100000):
        if stage not in manifests:
            rel='staging/'+stage+'/sealed-files.json'; raw=read(rel,25000)
            manifests[stage] = json.loads(raw)
        rel='staging/'+stage+'/'+leaf
        row=next(x for x in manifests[stage]['files'] if x['path']==rel)
        raw=read(rel,cap,row['sha256']); need(len(raw)==row['bytes'],'Sealed size')
        return raw
    vec='navigation-native-query-vector-provider-binding-v1'
    con='navigation-native-query-dir-constructor-v1'
    mat='navigation-native-jai-img-materializer-abi-v1'
    get='navigation-native-query-provider-full-getter-v1'
    pages={}
    for st,leaf,base in [
        (vec,'MAIN-page-0032d000.bin',0x32d000),
        (vec,'MAIN-page-044dc000.bin',0x44dc000),
        (vec,'MAIN-page-044db000.bin',0x44db000),
        (get,'MAIN-page-0032b000.bin',0x32b000),
        (con,'MAIN-page-00173000.bin',0x173000),
        (mat,'MAIN-page-002cd000.bin',0x2cd000),
        (mat,'MAIN-page-0448e000.bin',0x448e000),
        (mat,'MAIN-page-044b2000.bin',0x44b2000),
    ]: pages[base]=(sealed(st,leaf,4096),'staging/'+st+'/'+leaf)
    captures=[]
    for p in sorted(HERE.glob('capture-*-receipt.json')):
        receipt=json.loads(read(str(p.relative_to(ROOT)),10000))
        need(receipt['IMG_bytes_read']==0 and receipt['guest_cases_executed']==0,'Static capture only')
        for row in receipt['new_source_reads']:
            pages[row['runtime']]=(read(row['path'],4096,row['sha256']),row['path'])
        captures.append(receipt)
    need(sum(x['new_source_bytes'] for x in captures)==12288,'Three fresh original pages')
    need(sum(x['new_source_bytes'] for x in captures)<=24576,'New MAIN budget')
    cs_t=Cs(CS_ARCH_ARM,CS_MODE_THUMB);cs_a=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    def span(a,b,mode='thumb', expect=None, disasm=True):
        base=a&~4095; raw,path=pages[base];need(b<=base+4096,'Single-page exact span')
        out=raw[a-base:b-base]
        if expect: need(out.hex()==expect,'Expected opcode at '+hex(a))
        return dict(start=a,end_exclusive=b,mode=mode,source_path=path,bytes=len(out),
                    hex=out.hex(),sha256=sha(out),instructions=[dict(address=i.address,
                    hex=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                    for i in (cs_t if mode=='thumb' else cs_a).disasm(out,a)] if disasm else [])
    witnesses=[]
    def witness(wid,title,spans,facts,limits):
        witnesses.append(dict(id=wid,title=title,evidence_kind='original exact bytes; static only',
                              spans=spans,facts=facts,limits=limits))
    witness('W1','Options+C is native context storage from reply/cache+18',[
        span(0x32dc5c,0x32dc86),span(0x32bb3c,0x32bb8c)],{
        'cache_guard':'*(reply[0]+0x10)==0x12435687',
        'cached':'32DC78 unwrap(cache+18 handle), 32DC7C adds4, 32DC7E stores local options+C',
        'cold':'32DC72 calls32BB3C(&cache+18,&options)',
        'storage_bytes':'options byte16 * 0x408 + 4; block firstword stores byte16; options+C=unwrapped block+4',
        'classification_byte16_meaning':'Number of context slots as corroborated by 1F19F0/19F4 iteration; no live value established'
    },['Allocation does not itself initialize a valid MDR context, filename, native FS pair, GMP or registry.',
        'No allocator, mutex or heap guest was executed.'])
    need(int.from_bytes(pages[0x448e000][0][0xd7c:0xd80],'little')==0x1f18cd,'True context-loader veneer')
    need(pages[0x17d000][0][0xbae:0xbb0].hex()=='7047','17DBAE true no-op')
    witness('W2','Query engine conditionally invokes a genuine per-slot context initializer',[
        span(0x44dcaac,0x44dcaee),span(0x448ed78,0x448ed7c,'arm'),
        span(0x448ed7c,0x448ed80,'data',disasm=False),
        span(0x1f18cc,0x1f18f8),span(0x1f1908,0x1f195a),
        span(0x1f19d6,0x1f1a0a),span(0x17dbae,0x17dbb0)],{
        'direct_path':'044DCAE4 BLX0448ED78 -> original ARM LDR-PC veneer literal001F18CD -> Thumb001F18CC',
        'caller_arguments':'r0=options; r1=encoded-source-key cursor at SP40; r2=selector in r6',
        'source':'1F18DE takes options+C into r7; 1F19E0..E4 advances r7 by 0x408 per slot',
        'guards':'Keys terminate at FFFFFFFF; high byte must be80; slots bounded by options byte16. Original 32C4BE and 1EE324 outputs are checked.',
        'native_call':'1F194A..52 sets r0=context slot, r1=local name buffer, r2=local optional buffer, r3=*key cursor; BL2CDAAC',
        'correction':'044DC11A veneer0448E160 points to17DBAE; its exact BX LR does not initialize context.'
    },['Static conditional route; no runtime key cursor, options slot count, original dispatch, or helper result was supplied or executed.',
        '1EE324 name construction and 32C4BE key-to-record lookup remain unexamined contracts here.',
        'This is not proof that the street fallback result reaches this route uninterrupted.'])
    need(pages[0x2cd000][0][0xb3a:0xb3e].hex()=='fef787fc','True parser BL')
    witness('W3','True producer 2CDAAC fills context then calls MDR parser2CC44C',[
        span(0x2cdaac,0x2cdb76),span(0x2cc44c,0x2cc508),
        span(0x2cc520,0x2cc568),span(0x2cd378,0x2cd37e),
        span(0x2cd448,0x2cd49e)],{
        'entry_ABI':'r0=context; r1=primary name; r2=optional secondary name; r3=encoded source key (saved caller r3 at SP+20 after 36B push and20B frame)',
        'clear':'2CDAD0 calls35B4F4(ctx,0x408), not a native-return fixture',
        'writes':'Primary bytes copied to ctx+0 with <=12-character loop; optional secondary bytes at ctx+0D; 2CDB34 stores original r3 at ctx+1C',
        'true_parser_call':'2CDB38 movr0,r4; 2CDB3A BL2CC44C; error path2CDB68 calls2CC344 cleanup',
        'parser_input':'2CC44E saves r0 in r5; primary name converted then literal MDR suffix appended; ctx+1C becomes1C8682 r0; open-pair output=&ctx+20',
        'MDR_fields':'2CC4FE stores codepage at ctx+28;2CC548 stores MDR1 offset atctx+58;2CC54E stores stride u16 atctx+5C;2CC566 stores size/stride count atctx+64',
        'DIR_fields':'2CD378..37C proves r7=ctx+280;2CD482/486/48A writesctx+2B4/start,+2B8/stride,+2BC/flags;2CD49C writes size/stride countctx+2C0',
        'scope_correction':'32BB3C allocates storage;2CDAAC is a separate actual original initializer/parser call.'
    },['35B4F4, filename helpers, original FS open and parser were not executed this scope.',
        '2CC44C old sealed CPU evidence used explicit synthetic bottom FS and stops2CD49E; it is referenced separately, not replayed or upgraded to full native context bootstrap.',
        'New IMG header values below are checked only from prior sealed windows, not reread from IMG.'])
    witness('W4','DIR parser and callback preserve the distinct context and level sources',[
        span(0x44b209e,0x44b20e8),span(0x173b9c,0x173bba),
        span(0x173c1a,0x173c54),span(0x173ce2,0x173cee)],{
        'parser_ABI':'044B209E r0=MDRctx/r1=DIR; 044B20C0 stores ctx atDIR+140+14=DIR+154; ctx+2C0 tablecount copied toDIR+0',
        'cold_callback':'173BA0 BLX2E3834; prior sealed veneer maps it to044B209E',
        'cached_callback':'173BB8 writes input options+C toDIR+154',
        'level_selected':'Selected descriptor byte9 low6 minus2 supplies packed-reader input level; its outputflags low3 becomeDIR+160 at173C44',
        'level_fallback':'173CE2..E6 setsDIR+160=1 for absent selected descriptor/mapID0',
        'tuple_level_is_distinct':'Materializer [3,48312,0] uses record level3; callback DIR+160 selected-child output and fallback1 are not justified by tuple level3'
    },['DIR+154 was manually assigned in the old getter fixture; the exact original field-store exists but the old fixture is not retroactively a native constructor.',
        'No DIR callback/consumer case executed or hand-filled this scope.'])
    binding=json.loads(sealed(mat,'query-to-container-binding.json',4000))
    windows=json.loads(sealed(get,'actual-source-windows.json',15000))
    contract=sealed(get,'FIXTURE-CONTRACT.md',5000).decode()
    probe=sealed(get,'probe_actual_provider_getter.py',25000).decode()
    for s in windows['sources']: need(sha(bytes.fromhex(s['hex']))==s['sha256'],'Saved actual window checksum')
    header=bytes.fromhex(next(s['hex'] for s in windows['sources'] if s['component']=='00004171.MDR' and s['offset']==0))
    need(len(header)==772 and header[2:12]==b'GARMIN MDR','Actual inherited MDR header')
    mdr1start,mdr1size=struct.unpack_from('<2I',header,29);mdr1stride=struct.unpack_from('<H',header,37)[0]
    codepage=struct.unpack_from('<H',header,21)[0]
    first,size,width,flags=struct.unpack_from('<4I',header,600)
    need((mdr1start,mdr1size,mdr1stride,codepage,first,size,width,flags)==(772,4,4,950,124261391,120,20,1),'New IMG sealed parser-data contract')
    need(binding['exact_native_chain']==[[3,48312,0],[2,74,0xffffffff],[1,8,0xffffffff]],'Frozen true materializer tuple')
    need(binding['actual_IMG_L2']['last_inclusive']==48312 and binding['actual_IMG_L3']['fields']['+00']==3781595,'Native hierarchy crossbinding')
    need(binding['actual_IMG_L3']['fields']['+10']==475679 and binding['actual_IMG_L4']['fields']['+10']==2967,'Exact refs')
    need([x['text'] for x in binding['actual_native_LBL_labels']]==['敦富六街','368號'],'Native label outputs inherited')
    need('self.w32(DIR+0x154,CTX)' in probe and 'self.w32(DIR+0x160,level)' in probe,'Manual old getter provider relation explicitly retained')
    cross=dict(schema='one-source-materializer-to-MDR-context-static-crossbinding/v1',
        candidate_inherited_sha256=windows['inherited_whole_SHA256'],candidate_bytes=windows['candidate_bytes'],
        IMG_reread=False,exact_native_chain=binding['exact_native_chain'],street_ID=48312,house_ID=3781595,
        parent_district_ID=74,parent_city_ID=8,native_street_ref=475679,native_house_ref=2967,
        street_text='敦富六街',house_text='368號',source_node_ID=binding['source_node_ID'],source_group_ID=binding['source_group_ID'],
        required_MDR_context_fields={'0x20/0x24':'original FS open pair; prior fixtureFILE/mode0; no genuine handle constructed now',
            '0x28':codepage,'0x58':mdr1start,'0x5C':mdr1stride,'0x64':mdr1size//mdr1stride,
            '0x2B4':first,'0x2B8':width,'0x2BC':flags,'0x2C0':size//width,
            '0x3F4/0x3F8':'prior fixture cached GMP/marker; true producer/ownership not established'},
        table_schema_binding='Prior actual native directory/prefix endpoint and materializer IDs; no new host prefix decoding or CPU replay',
        actual_header_witness_sha256=sha(header),prior_getter_relation_is_fixture=True,
        required_original_route=['044DCAE4','0448ED78','001F18CC','002CDAAC','002CC44C','00173B50','044B209E'],
        original_route_executed_this_scope=False,uninterrupted_query_to_getter_proven=False,
        cold_registry_and_FS_initialized=False,native_UI_device_installable_full_Taiwan_verified=False,
        historical_alias_368_address_and_2026_name_continuity_held=True)
    write('materializer-context-crossbinding.json',cross)
    witness('W5','Frozen new-IMG tuple matches concrete MDR context data; fixture boundary remains',[],{
        'saved_tuple':binding['exact_native_chain'],'street_record':48312,'house_record':3781595,
        'saved_candidate_SHA':windows['inherited_whole_SHA256'],'saved_candidate_bytes':windows['candidate_bytes'],
        'derived_header_fields':cross['required_MDR_context_fields'],
        'true_parser_metadata_agrees_with_prior_getter_fixture':True,
        'actual_saved_labels':['敦富六街','368號'],'crossbinding_artifact':'materializer-context-crossbinding.json'
    },['Static data consistency to inherited actual native endpoints, not a new original instruction result.',
        'No original query options/key cursor, original filename output, cold FS handle or cached GMP marker producer was established.',
        'SQLite, uninterrupted provider/getter/UI/device/installable/full Taiwan all remain unverified.'])
    need(len(witnesses)==5,'Finite five witness stop')
    # Historical parser source/receipt remains immutable; never import or execute it.
    oldmanrel='staging/navigation-native-MDR-provider-fields-v1/sealed-parser-manifest-v1.json'
    oldman=json.loads(read(oldmanrel,2000))
    row=next(x for x in oldman['files'] if x['path'].endswith('native-MDR-header-fields-proof-v1.json'))
    old=json.loads(read(row['path'],40000,row['sha256']))
    need(old['entry']=='0x2cc44c' and old['stop']=='0x2cd49e','Historical parser exact scope')
    need(old['physical_query_verified'] is False,'Keep original parser boundary')
    write('context-producer-witnesses.json',dict(schema='garmin-native-query-context-producer-five-static-witnesses/v1',
          witness_count=5,CPU_cases_executed=0,witnesses=witnesses))
    write('source-artifact-read-ledger.json',dict(schema='static-artifact-read-ledger/v1',reads=reads,
          original_MAIN_source_bytes=sum(x['new_source_bytes'] for x in captures),
          saved_code_artifact_bytes=sum(len(v[0]) for k,v in pages.items() if not v[1].startswith(str(HERE.relative_to(ROOT)))),
          original_IMG_source_bytes=0,whole_MAIN_IMG_hash_repeated=False,all_artifact_stats_unchanged=True))
    proof=dict(schema='garmin-native-query-context-producer-static-proof/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        scope_work_completed=True,script_sha256=sha(Path(__file__).read_bytes()),exact_byte_witness_count=5,
        new_MAIN_bytes_read=12288,new_MAIN_bytes_cap=24576,new_IMG_bytes_read=0,CPU_cases_executed=0,
        original_cold_heap_mutex_or_music_guests_executed=False,original_unknown_returns_faked=False,
        original_firmware_or_shared_canonicals_mutated=False,all_actual_source_handles_closed=True,
        true_context_initializer_callsite_identified_static=True,true_context_initializer_executed=False,
        query_to_getter_uninterrupted_proven=False,native_query_UI_device_App_installable_full_Taiwan_verified=False,
        historical_parser_scope=dict(entry=old['entry'],stop=old['stop'],proof_sha256=row['sha256'],
            physical_query_verified=old['physical_query_verified'],replayed_this_scope=False),
        next_minimum_entry_contract=dict(entry='002CDAAC',caller='001F1952',inputs=['context slot from options+C',
            'true1EE324 emitted primary name','optional secondary name','actual encoded source key'],
            prerequisites='Validate1EE324/32C4BE from original registry/descriptor evidence and original FS provider contract; do not fabricate success or resume allocator bootstrap'),
        retained_gaps=['1EE324 exact primary/secondary filename output and32C4BE encoded-key lookup',
            'Original query key cursor/options slot count reaching this initializer',
            'Cold original FS open pair and cached GMP/marker ownership',
            'Native dispatch/preprocess/callback uninterrupted path and level setter for chosen tuple',
            'Real SQLite/UI/device acceptance,368 address/history/2026 continuity/full Taiwan'])
    write('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,witnesses=5,new_MAIN_bytes_read=12288,IMG_bytes_read=0,
                         CPU_cases_executed=0,proof_sha256=sha((HERE/'proof.json').read_bytes()))))

if __name__=='__main__':main()
