#!/usr/bin/env python3
"""Exact static cache allocator/read-span preflight after frozen38139 failure."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM

ROOT=Path('/root/garmin');sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage,scan_calls
from analyze_sdp_activation import trace

OUT=Path(__file__).with_name('font-cache-span-preflight.json')
AUDIT='staging/native-player-controller-gir-integration/previous-audit.json'
TERMINAL='staging/native-player-controller-gir-integration/runtime/terminal-probe.json'
RUNNER='scripts/probe_native_controller_gir_component.py'
RUNNER_SHA='024714df092fd98d1817b774456b94ff039c58219bc47b6e0e358b259879e63f'
ENTRIES=(0x140878,0x265f16,0x26852a,0x263f60,0x26475c,0x264580,
    0x2645c6,0x2645e2,0x26467e,0x2643ee,0x2648c8,0x26404c)


def require(ok,why):
    if not ok:raise ValueError(why)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def sha(path):return digest((ROOT/path).read_bytes())


def check(registry):
    for path,h in registry.items():require(sha(path)==h,'Frozen source changed '+path)


def main():
    require(not OUT.exists(),'Preserve frozen cache preflight')
    require('unicorn' not in sys.modules,'No emulator import in static preflight')
    protected=json.loads((ROOT/AUDIT).read_text())['protected_sources']
    require(len(protected)==608,'Expected immutable608 registry');check(protected)
    require(sha(RUNNER)==RUNNER_SHA,'Frozen38139 source changed')
    terminal=json.loads((ROOT/TERMINAL).read_text())
    require(not terminal['completed'] and not terminal['full_scoped_final_guards_passed'] and
        terminal['source_sha256_before_run']==RUNNER_SHA and
        terminal['error']=='Font lower input destination is not writable','Frozen38139 terminal differs')
    regs=terminal['registers'];require(regs['r1']=='0x35b7f1c' and regs['r2']=='0x1cfc','Failed span differs')
    stock=NativeImage();image=RuntimeImage(stock);functions={}
    for entry in ENTRIES:
        fn=trace(image,entry,2400);require(not fn['instruction_limit_reached'],'CFG exhausted '+hex(entry))
        for row in fn['instructions']:
            a=int(row['address'],16);i=next(image.md.disasm(image.read(a,4),a,count=1))
            row['bytes']=i.bytes.hex();row['load_address']=hex(stock.runtime_to_load(a,i.size))
        fn['bounded_intrafunction_not_transitive']=True;functions[hex(entry)]=fn
    expected={0x140880:'lsls r0, r0, #0x12',0x140882:'cmp r4, r0',0x140886:'ldr r5, [pc, #0x150]',
        0x265f5a:'str r0, [r4, #0x58]',0x265f78:'str r5, [r0, #0x14]',
        0x265fae:'str r0, [r1, #0x28]',0x265fc2:'strb r0, [r1, #0xc]',0x268596:'str r0, [r4, #0x58]',
        0x263f62:'movs r4, r0',0x263fea:'ldr r0, [sp, #0x10]',0x263fee:'adds r0, r0, #7',
        0x263ff0:'lsrs r2, r0, #3',0x263ff6:'adds r2, r2, #1',0x264016:'str r2, [r0, #4]',
        0x264030:'adds r0, #8',0x264032:'bx r3',0x264042:'movs r0, #0',0x264044:'bx r3',
        0x264760:'subs r1, #8',0x26476a:'ldr r5, [r1, #4]',0x264770:'str r3, [r2, #0x18]',
        0x2647d0:'str r2, [r0, r1]',0x2647d2:'pop {r4, r5, r6, r7}',0x2647d4:'movs r0, #0',0x2647d6:'bx lr',
        0x2645aa:'bl #0x263f60',0x264638:'bl #0x263f60',0x2646c4:'bl #0x263f60',
        0x264918:'movs r5, r0',0x26491a:'beq #0x264938',0x26492c:'ldr r1, [r4, #8]',
        0x26492e:'ldr r0, [sp, #4]',0x264930:'movs r3, r7',0x264932:'movs r2, r5',0x264934:'bl #0x14f084'}
    assertions=[]
    for a,wanted in expected.items():
        i=next(image.md.disasm(image.read(a,4),a,count=1));actual=i.mnemonic+' '+i.op_str
        require(actual==wanted,'Exact allocator/read instruction differs '+hex(a))
        assertions.append(dict(address=hex(a),bytes=i.bytes.hex(),instruction=actual))
    require(image.word(0x1409d8)==0x34fa3bc,'Static cache pointer literal differs')
    arm=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    arm_rows=[dict(address=hex(i.address),bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
        for i in arm.disasm(image.read(0x13ef74,24),0x13ef74)]
    require(len(arm_rows)==6 and image.word(0x13ef8c)==0x51eb851f and image.word(0x13ef90)==0xfffffce0,
        'ARM cache-partition division constants differ')
    base=0x34fa3bc;capacity=0xc0000;end=base+capacity
    zero=next(r for r in stock.zeros if r['runtime_start']<=base and end<=r['runtime_end'])
    calls=scan_calls(stock,{0x263f60,0x26475c})
    alloc_calls=[r for r in calls['candidates']if r['target']=='0x263f60']
    require([r['address']for r in alloc_calls]==['0x2645aa','0x264638','0x2646c4'],'Direct allocator callers differ')
    known=[]
    for row in terminal['font_raw_input_ledger']:
        p=int(row['destination'],16);n=row['bytes']
        if base<=p and p+n<=end:known.append(dict(start=hex(p),exclusive_end=hex(p+n),bytes=n,
            path=row['path'],offset=row['offset'],raw_sha256=row['raw_input_sha256'],
            observed_read_span_is_not_independent_live_allocation_proof=True))
    p=0x35b7f1c;n=0x1cfc;units=((n+7)>>3)+1;payload=(units-1)*8
    sources={str(Path(__file__).relative_to(ROOT)),AUDIT,TERMINAL,RUNNER,
        'staging/native-player-controller-gir-integration/runtime/runner-at-run.py',
        'staging/native-player-controller-gir-integration/runtime/inputs-before-run.json',
        'staging/native-player-controller-gir-integration/resource-static/font-stream-owner-supplement.json',
        'scripts/analyze_native_sections.py','scripts/analyze_native_vpm_acceptance_path.py',
        'scripts/analyze_sdp_activation.py','evidence/firmware-analysis/main_02bd.bin'}
    source_sha={path:sha(path)for path in sorted(sources)}
    header_sites={0x263fce:'Initial free-block units',0x263fd8:'Initial free-block next',
        0x26400a:'Remove exact-fit block through previous/sentinel next',
        0x264010:'Split remaining free-block units',0x264016:'Publish allocated-block units',
        0x2647a6:'Coalesce upper neighbor units',0x2647ac:'Coalesce upper neighbor next',
        0x2647b0:'Publish freed block next',0x2647c0:'Coalesce lower neighbor units',
        0x2647c4:'Coalesce lower neighbor next',0x2647c8:'Insert freed block through previous/sentinel next'}
    header_opcodes=[]
    for address,role in header_sites.items():
        i=next(image.md.disasm(image.read(address,4),address,count=1))
        require(i.mnemonic.startswith('str'),'Cache-header native store differs')
        header_opcodes.append(dict(PC=hex(address),opcode_hex=i.bytes.hex(),
            instruction=i.mnemonic+' '+i.op_str,role=role,
            effective_target_requires_actual_native_registers=True))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        static_only=True,source_sha256=source_sha,protected_sources=protected,protected_count=len(protected),
        bounded_CFG_count=len(functions),functions=functions,exact_instruction_checks=assertions,
        direct_allocator_and_free_call_candidates=calls,
        frozen_failure=dict(session=38139,source_sha256=RUNNER_SHA,terminal_sha256=source_sha[TERMINAL],
            completed=False,full_scoped_final_guards_passed=False,error=terminal['error'],registers=regs,
            helpers_returned=sum(r['returned']for r in terminal['component_calls']),
            font_raw_input_before_failure=known,
            original_parser_stream_owners=terminal['font_stream_owners'],
            native_font_initializer_returned=False),
        original_cache_provenance=dict(
            malloc_special_case='140878 receivesN;140880 computes3<<18=C0000;140882 compare. ExactN takes140886 literal1409D8=34FA3BC and returns it. This special cache has no opaque malloc/prefix.',
            whole_byte_span={'start':hex(base),'exclusive_end':hex(end),'bytes':capacity},
            startup_zero_range={'start':hex(zero['runtime_start']),'exclusive_end':hex(zero['runtime_end'])},
            broad_startup_zero_range_is_not_font_whitelist=True,
            control='K=word(C+58), original265F54 allocates26C-byte control via140878;265F5A publishes it. word(K+214)=C0000 from265F78;word(K+228)=34FA3BC from265FAE;byte(K+22C)=100 from265FC2.',
            shared_ownership='268592 readsparentC+58;268596 installs sameK atnewC+58. A free context may differ from the original allocation context while sharingK.',
            initial_cells='263F60 initializes free list;13EF70 BXPC enters ARM13EF74 reciprocal0x51EB851F/shift8 and subtract800 via MLA. For C0000*100 this yields18000 eight-byte cells spanning exactlyC0000 bytes.',
            division_ARM_instructions=arm_rows,division_literals={'13EF8C':'51EB851F','13EF90':'FFFFFCE0'},
            cache_membership_alone_is_not_live_allocation=True),
        native_control_publication_observations=[
            dict(store_PC='265F5A',after_PC='265F5C',registers='r4=C,r0=K',target='C+58',
                check='word(C+58)==K. K is a live original fontmalloc26C-byte userpayload:word(K-8)=originalhandle,word(K-4)=26C,entrypointer=K-8,length>=26C+8,original388804 query andcanaries. K0 recordsinitfailure.'),
            dict(store_PC='265F78',after_PC='265F7A',registers='r0=K+200hex,r5=C0000',target='K+214hex',
                check='Original store thenword(K+214)==C0000'),
            dict(store_PC='265FAE',after_PC='265FB0',registers='r0=34FA3BC,r1=K+200hex,r4=C',target='K+228hex',
                check='Original store thenword(K+228)==34FA3BC; correlate actual140878 C0000 special-case return'),
            dict(store_PC='268596',after_PC='268598',registers='r4=newC,r5=parentC,r0=word(parentC+58)=K',target='newC+58',
                check='word(newC+58)==word(parentC+58)==original liveK; do notwrite/reconstructpointer')],
        known_cache_header_store_opcode_table=header_opcodes,
        complete_cache_writer_whitelist_identified=False,
        whole_cache_chronological_replay=dict(bytes=capacity,
            baseline='Before component/font initialization, maponlyunmappedknowncachepages withstartup-zero provenance as explicitofflineinputs, preservealready-mappedbytes andcapturewhole786432-byteactualbaseline. Do notseedpointer/header/free-list/cachecontrol.',
            CPU='Append eachactualCPUstore in order with fullbeforebytes/value/actualtask/CPSR/PC andopcode bytes equal exactMAIN(runtime_to_load forcopiedcode). STR/STM/SWP-family andARM STRD8-byte stores need their own decoded exactwidth admission; unknowninstruction stops.',
            raw='At lowerrawfilecopy append sourcepath/hash/offset/count/fullbeforebytes/exactpayload orresolvablebackupbytes to the same chronologicalhistory. DirectUCmem_write doesnot emitCPUstorehooks. Verify allpayloadchunks unchangedraw backupandcontext/stream/livepayload binding.',
            endpoint='Replay everyCPU andrawinputevent againstoneinitialbaseline with beforebytes continuity; compareentirecache. Do notclearhistoricalevents, hostrestorebaselineorclaim same-value/restoredhostwritesexcluded.',
            limitation='Allocatorheaderwriters are exact above, butfont parser/memzero/memcpy/byte-XOR andfutureglyphwriters extend beyond this fixedtable. A complete transitivefixedPC whitelist isnotidentified; typednativeCPUhistory plusownership/endpoints is the declared scope.'),
        allocator_exact_contract=dict(entry='0x263f60',ABI={'r0':'C font context','r1':'N requested bytes'},
            frame='Pushr0,r1,r4-r7,LR28bytes;subSP12. localSP=entrySP-40; savedN atlocalSP+10hex.',
            live_control_check='C is an actual fresh font record.context;K=word(C+58) must be the original live26C font-control allocation with prefix/query/canaries;word(K+214)==C0000 andword(K+228)==34FA3BC.',
            success_observation_PC='264032, beforeBXr3, after264030 incrementsheaderpointer8',
            success='r0=P, SP==capturedentrySP, r3==capturedentryLR; actualcontroller/SYS/Thumb andoriginalopcode/frame. H=P-8; word(H+4)=U=((N+7)>>3)+1; payloadcapacity=(U-1)*8.',
            requested_window='[P,P+N) is the admission window; roundedpayload[P,P+(U-1)*8) remains a separate guard/slack range. Wholeallocation includesheader[P-8,P+(U-1)*8).',
            whole_span_checks='0<N<C0000; nonwrapping8bytecell header alignment relative tocachebase; wholeallocation within[34FA3BC,35BA3BC); exactheaderU; nointersection withanotherlivecacheallocation orcriticalobject. Header+0 may be stale; do not inventmagic/zero.',
            failure_observation_PC='264044, r0=0; record failure and no live payload',
            direct_caller_returns=[dict(site=r['address'],return_PC=hex(int(r['address'],16)+4),
                entry_LR=hex(int(r['address'],16)+5),opcode_hex=r['bytes'])for r in alloc_calls],
            indirect_callers_not_excluded=True),
        free_exact_contract=dict(entry='0x26475c',ABI={'r0':'C context','r1':'P returned payload'},
            entry_admission='Match exactly one live allocation P/generation, K=word(C+58)==thatallocation.K. FreeC may differ fromallocC withsameK. CaptureentrySP/LR andheaderunits before264760 subtracts8.',
            native_writes='264770 decrementsallocatedunits atK+218. Native neighbor coalescing mutatesfreeheaders;2647D0 publishesnewfreehead atK+224.',
            completed_observation_PC='2647D6, beforeBXLR, afterPOP at2647D2 andr0=0 at2647D4',
            completed='SP==entrySP,LR==entryLR,r0=0,actualcontroller/nativeopcode. Only nowmarkgenerationfreed; neverhostmerge/clearheader orrestorefreehead.',
            caller_scope='24 directfreecall candidates preserved, including cleanup2643EE andrealloc2645E2; do not admit only264057. Unresolvedindirectcallers remain unknown.',
            native_reclaim='264580 retries after2643EE. Realloc2645E2 allocatesnew via264638, copiesnativebytes, thenfreesold at26465C. Ledger must preserve everyallocation/free andallowreuse withnewgeneration.'),
        raw_read_binding=dict(
            native_route='2648C8(C,PARSER,...,N) savescontext inframe;264918 storesreturnedbuffer inr5. At26491C capture C=word(SP+4),PARSER=r4,BUFFER=r5,N=r7; requireBUFFER matchesonecurrentlive263F60 record(C,K,N).',
            stream_route='26492C r1=word(PARSER+8)=stream;26492E r0=savedC;264930 r3=N;264932 r2=BUFFER;264934→14F084→14098C→31CF22.',
            provider='Match captured(C,stream,BUFFER,N) fromactualnativeframe before rawinput; partialEOF mayreturnless but neverwriteoutside[P,P+N). Native1409AE XORstores occur afterlowercallback andneedseparate CPU history.',
            stack_alternative='Classifier/headerreads mayuseactuallivecontrollerstack; bounds/excludeleadingcanary/TCB andcurrentSP. Neveruseold085FE fixtureaddresses.',
            cache_alternative='One live cachepayload requestedwindow plusoriginalctx/control/stream mapping. No blanket cacheBSS or any-font/all-handle fallback.',
            critical_exclusions='ActualnativeTCB108, savedframes, semaphores, timednodes, cachecontrolK26C, fontsmetadata/records, liveparserP98, code/GIR, component/config/result, allocationheaders/slack/canaries andotherfontlivepayloads mustnotintersect therawwrite span.'),
        rejected_span=dict(start=hex(p),requested_bytes=n,exclusive_end=hex(p+n),
            derived_header=hex(p-8),derived_units=hex(units),derived_rounded_capacity=hex(payload),
            rounded_payload_end=hex(p+payload),
            parsed_font_object={'start':'0x35b9e24','bytes':0x98,'exclusive_end':hex(0x35b9e24+0x98)},
            span_numbers_are_static_derivation_not_recorded_native_header_words=True,
            broad_range_35B7F1C_to35B9E18_not_admitted=True),
        contiguous_RW_coverage=dict(
            rule='Walksortedguestregionswithcursor=start; rejectgaps/nonRWintersection; advancecursor=min(end,region_end+1). Successonlycursor==exclusive_end. Anysingle_regionfullspan istoo strictforadjacentRWpages.',
            mapping='Maponlyunmappedpageswhoseactualrequestedbytes arealreadyadmittedbylivepayload/cacheprovenance orlivecontrollerstack. Mappinga4096-byte page doesnotauthorizeitsotherbytes.',
            fail_closed='Anyunknownspan/owner/free-generation/header/control/permission rejectswithactualentryLR/PC/C/H/P/N and regioncoverage serialized; nofakecopyreturn ordecodedfontseeding.'),
        modified_old_source_artifact_or_canonical=False,new_native_execution=False,emulator_imported=False,
        device_io=False,sounds_emitted=False,physical_App_or_package_acceptance_proven=False,
        limits='Exact MAIN static instructions and frozen failed native evidence only. Proposed allocation/free/read ownership and per-page RW checks require a new separately authorized native run. Derived units are not substitutes for actualheader/read/free witnesses. Entirefontarena membership is not allocation success, safe unload orhardwareI/O proof.')
    check(protected);check(source_sha)
    with OUT.open('x',encoding='utf-8')as f:f.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(report=str(OUT.relative_to(ROOT)),sha256=digest(OUT.read_bytes()),CFGs=len(functions),
        instruction_checks=len(assertions),protected=len(protected),direct_alloc_callers=len(alloc_calls),
        direct_free_callers=len(calls['candidates'])-len(alloc_calls))))


if __name__=='__main__':main()
