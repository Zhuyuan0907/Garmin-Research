#!/usr/bin/env python3
"""Read-only exact-source peer review. Never imports or executes guest runners."""
from pathlib import Path
from datetime import datetime, timezone
import ast, hashlib, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path('/root/garmin')
BASE = 'staging/native-player-dispatcher-fp/'
OUT = BASE+'fp-static/multiowner-vfp-helper-peer-review-8fc0a2bcf631.json'
HELPER = 'scripts/probe_native_multiowner_vfp.py'
VERIFIER = 'scripts/verify_native_multiowner_vfp_micro.py'
EXPECTED = {
    HELPER: '8fc0a2bcf6319f9a2b5a00c15c1f9c213b1717f6c55105b0785433e594a4cab4',
    VERIFIER: '9f83f16fc7ab6800a524d6a5a73949dfe439e903b23ce55ea9f71f9b530abf3e',
    'scripts/probe_native_lazy_vfp.py': 'ece96af88a411bbaca92715c45595a20d59b0f26e928f5961f9026f6acf3ca24',
    'evidence/firmware-analysis/main_02bd.bin': '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8',
    BASE+'fp-static/native-multiowner-vfp-observer-contract.json': '142ee737b8f7dd75e24fc52e6f96d1a17aba40c5c20b932b38634ec574efb419',
    BASE+'fp-static/native-vfp-retry-and-control-branch-clarification.json': 'ed5ac88a1a7578829e961b6f9ef867a170b74d5788a1db6398277ff23c1984c8',
}

def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def read(path): return json.loads((ROOT/path).read_text())
def require(value, message):
    if not value: raise AssertionError(message)

def main():
    require(not (ROOT/OUT).exists(), 'Preserve unique exact-source peer review')
    for p,h in EXPECTED.items(): require(sha(p)==h, 'Reviewed source changed '+p)
    meta_path=BASE+'micro-vfp/terminal-metadata.json'
    probe_path=BASE+'micro-vfp/terminal-probe.json'
    inputs_path=BASE+'micro-vfp/inputs-before-run.json'
    proof_path='evidence/firmware-analysis/native-multiowner-vfp-fragment-controls.json'
    metadata,probe,inputs,proof=map(read,[meta_path,probe_path,inputs_path,proof_path])
    require(metadata['terminal_exit_code']==0 and metadata['authoritative_terminal_result_received_from_exec'] and probe['all_passed'], 'Root terminal result missing')
    require(metadata['runner_sha256']==EXPECTED[HELPER]==sha(metadata['runner_snapshot']), 'Executed helper mismatch')
    for key in ['runner','runner_snapshot','probe','inputs']:
        require(sha(metadata[key])==metadata[key+'_sha256'], 'Frozen terminal dependency changed '+key)
    deps=dict(EXPECTED)
    for registry in [inputs['source_sha256'], proof['source_sha256']]:
        for p,h in registry.items():
            require(sha(p)==h, 'Frozen registered dependency changed '+p)
            require(p not in deps or deps[p]==h, 'Conflicting dependency '+p)
            deps[p]=h
    for p in [meta_path,probe_path,inputs_path,proof_path,str(Path(__file__).resolve().relative_to(ROOT))]: deps[p]=sha(p)
    text=(ROOT/HELPER).read_text();tree=ast.parse(text);ast.parse((ROOT/VERIFIER).read_text())
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='MultiOwnerVFPState')
    require([ast.unparse(x) for x in cls.bases]==['LazyVFPState'],'Unexpected helper MRO')
    methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
    required=['__init__','metadata','enter','decode','journal','finish_push','observe','verify']
    require(all(n in methods for n in required), 'Reviewed observer method missing')
    source_methods={n:dict(line=methods[n].lineno,end_line=methods[n].end_lineno,
        source_sha256=hashlib.sha256(ast.get_source_segment(text,methods[n]).encode()).hexdigest()) for n in required}
    main_bytes=(ROOT/'evidence/firmware-analysis/main_02bd.bin').read_bytes()
    ds={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
    # Only previously bounded observer instruction sites; no new CFG exploration.
    sites=[(0x20ebd4,False),(0x20ebe0,False),(0x20ec78,False),(0x20ec80,False),(0x20ec90,False),
        (0x20ec94,False),(0x20ec98,False),(0x20ecb4,False),(0x20ecd8,False),(0x20ece0,False),
        (0x20ece8,False),(0x20ecf0,False),(0x20ecf8,False),(0x20ed0c,False),(0x20ed24,False),
        (0x20ed30,False),(0x20ed38,False),(0x20ed3c,False),(0x6e0830,False),(0x6e0858,False),
        (0xf6e14,True),(0xf6e2e,True),(0xf6e32,True),(0xf6e36,True),(0xf6e3c,True),(0xf6e40,True),
        (0xf6edc,True),(0xf6f02,True),(0xf6f10,True),(0xf6f18,True)]
    instructions=[]
    for a,thumb in sites:
        raw=main_bytes[a-0x50000:a-0x50000+4];ins=list(ds[thumb].disasm(raw,a,count=1))
        require(len(ins)==1,'Original reviewed instruction unavailable')
        instructions.append(dict(PC=hex(a),mode='Thumb' if thumb else 'ARM',opcode_hex=ins[0].bytes.hex(),instruction=ins[0].mnemonic+' '+ins[0].op_str))
    expected_stages=[(False,False),(True,False),(True,True),(True,True),(False,False)]
    rows=probe['original_handler_rows'];require(len(rows)==len(probe['cases'])==5,'Expected five exact controls')
    require(probe['VSTM_observed_callback_widths']==[8],'Actual reported VSTM width differs')
    require([a['request'] for a in probe['native_allocations']]==[148,148,40] and [a['advance'] for a in probe['native_allocations']]==[152,152,40],'Allocation observations differ')
    expected_controls=[None,['0x40000000','0x9503f90','0x20ecc4','0x3000000'],['0x40000000','0x0','0x0','0x3000000'],['0x40000000','0xa00','0x12345003','0x3000000'],None]
    cases=[];push_checked=0
    for index,(row,stage) in enumerate(zip(rows,expected_stages)):
        require((row['save_complete'],row['restore_complete'])==stage,'Observed stage differs')
        require(row.get('actual_control_register_words')==expected_controls[index],'Observed control provenance differs')
        before=row['before'];GP=[int(v,16) for v in before['GP15']];old,new=int(row['old_owner'],16),int(row['new_owner'],16)
        require(before['GP15']==row['after_native_handler']['GP15'] and before['CPSR']==row['after_native_handler']['CPSR'],'Retry GP/status differs')
        ctx=next((int(a['result'],16) for a in row['allocation_rows'] if a['request']==148),None)
        U=0x18310fe0
        for push in row['push_rows']:
            pc=int(push['PC'],16)
            if pc==0x20ebe0: pre,vals=U,[GP[i] for i in [0,1,2,3,4,12]]
            elif pc==0x20ec78: pre,vals=U-24,[GP[5],int(before['PC'],16)+4]
            elif pc==0x6e0830: pre,vals=U-32,[ctx,0x20ecd4]
            elif pc==0xf6e14: pre,vals=U-40,[ctx,new,GP[6],0x6e0858]
            elif pc==0xf6edc and push['before_SP']==U-32: pre,vals=U-32,[old,new,GP[6],0x20ecc4]
            elif pc==0xf6edc and push['before_SP']==U-56:
                oldmeta=inputs['task_inputs'][str(old)]['metadata'];pre,vals=U-56,[oldmeta,old,GP[6],0xf6e2d]
            else: raise AssertionError('Unreviewed observed push')
            after=pre-4*len(vals);expected_words={hex(after+4*i):hex(v) for i,v in enumerate(vals)}
            require(push['before_SP']==pre and push['after_SP']==after and push['expected_words']==expected_words,'Observed push ABI/payload differs')
            require(sorted(push['seen'])==sorted(int(a,16) for a in expected_words),'Observed push address coverage differs')
            push_checked+=1
        cases.append(dict(index=index,name=probe['cases'][index]['name'],save=stage[0],restore=stage[1],retry_bank_source=row['expected_retry_bank_source'],actual_control_words=row.get('actual_control_register_words'),UND_pushes=len(row['push_rows'])))
    zones=proof['independent_whole_zone_replays'];stores=sum(len(z['stores']) for z in probe['partial_zone_journals'].values())
    require(len(zones)==8 and stores==proof['exact_original_CPU_store_events']==145,'Root journal inventory differs')
    require(not proof['complete_cold_boot_or_Dispatcher_integration_scenario'] and proof['original_fragment_controls'],'Published scope differs')
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,guest_executed_by_this_review=False,
        device_io=False,sounds_emitted=False,frozen_source_proof_or_canonical_modified=False,
        MAIN_sha256=EXPECTED['evidence/firmware-analysis/main_02bd.bin'],source_sha256=deps,
        reviewed_helper_sha256=EXPECTED[HELPER],reviewed_verifier_sha256=EXPECTED[VERIFIER],
        review_result='No concrete blocker found for the five declared original-fragment controls. Actual cold/task scheduling integration requires the separate gates below.',
        concrete_micro_blockers=[],method_source_inventory=source_methods,original_instruction_sites=instructions,
        bounded_CFG_reused=True,new_CFG_nodes_explored=0,
        observed_root_terminal=dict(metadata=meta_path,exec_chunk_id=metadata['exec_chunk_id'],exec_session_id=metadata['exec_session_id'],authoritative_exit_code=metadata['terminal_exit_code'],
            proof=proof_path,case_count=5,VSTM_callback_widths=[8],whole_zones=8,CPU_store_events=145,independent_replay_published=True,
            terminal_execution_by_root=True,execution_repeated_by_this_review=False),
        five_case_contract=cases,observed_push_frames_independently_compared=push_checked,
        ABI_review=dict(undefined_entry='Explicit architectural UND entry, original mode SYS/USR ARM, original CP10/11 VFP opcode, FPEXC exactly0, CPACR access readback F00000; banked UND SP/LR and SPSR fixture only.',
            original_getter='358D24 returns0 when F09094 is nonzero; otherwise dereferences F09090. Micro uses F09090 as declared selected task and mapped zero marker.',
            original_return='20ED30 inner pop,20ED38 outer pop,20ED3C MOVS PC,LR restores original SPSR and retries same original fault opcode with exact GP15.',
            native_context=dict(request_bytes=148,allocation_advance=152,D16_bytes=128,hole_offset=128,hole_bytes=4,controls_offset=132,control_registers=['r1/FPEXC','r2/FPINST-or-actual-residual','r3/FPINST2-or-actual-residual','ip/FPSCR'],controls_bytes=16,padding_offset=148,padding_bytes=4),
            controls='Native-enabled FPEXC40000000 has neither exceptional bit. +136/+140 preserve branch-dependent actual r2/r3: mutable first-save oldTCB/20ECC4, readonly clone oldM+36/oldM+24, existing-slot opcode&F00/faultGP3. Observer captures actual registers rather than assumes zero.',
            same_owner='20EC94 directly selects20ED30; never VLDM even with a valid slot. Retry retains actual fault D16/FPSCR.',
            different_owner='Save old owner when nonzero. New slot0 retains fault bank; valid new slot restores its saved D16/FPSCR and expected retry compares that saved bank.',
            allocator='Original F6EDC rounds148 to152, clone40 to40; header magic FCE3E2CA, native cursor atpool+4, cold cursor align_up(pool+8,8). Native has no capacity check.',
            clone='Original F6E2E/F6E32/F6E36 copies40 bytes, F6E3C sets writable byte4, F6E40 publishes only oldTCB+28,6E0858 publishes clonedmetadata+28=context. Original readonly40 preserved.',
            journal='Original opcode and mode rechecked. Eight-byte VSTM callbacks tile exactly128 bytes without overlap and equal captured D16 bytes; exact four4-byte control stores equal captured r1/r2/r3/ip. Every pending push checks exact PC/SP/mode/address/payload and complete coverage. Whole-zone replay catches unjournaled changes.',
            pool_guard='External256-byte capacity admission and320-byte typed pool journal; trailing64FF; cursor exactctx+152+(40 for readonly). This is observer capacity enforcement, not a recovered native limit.'),
        explicit_fixtures=dict(TCBs='Two108-byte host-supplied5A TCBs, only metadata word28 typed. They are not cold-builder products.',
            selection='Host task selection writesF09090 and sets ordinary caller SP/LR/r0 between cases; no native scheduler switch.',
            metadata='Mutable C metadata and readonly D metadata/pools are declared inputs; D fixture word0=261E30 and word32=8805220 deliberately tests nonzero clone object32. Actual Dispatcher metadata word0=5D2544/word32=0 is a separate cold-builder inventory.',
            pools='Host FF320 backing imitates native-filled cold pool shape; first256 budget plus trailing64 guard, no builder execution.',
            access_and_exception='CPACR explicit declared virtual input and architectural UND entry fixture; no native FPboot20ED68, hardware vector or physical fault-entry proof.',
            original_executed='Root executed unchanged original disable/handler/currentgetter/allocator/clone/IRQ helpers/conversion fragments; owner/context/FPEXC enable/bank exchange were produced by original guest instructions.'),
        next_integration_gates=[
            dict(id='actual-current-getter',blocking_for_micro=False,required_for_actual_integration=True,
                 requirement='Before any architectural UND entry require F09094==0 and original358D24/F09090 result equals the task from the actual native restore destination. Getter(current) must not silently substitute a ready-head task for the running task.'),
            dict(id='runtime-fault-mapping',blocking_for_micro=False,required_if_copied_code_faults=True,
                 requirement='enter uses stock.read(pc,4) with load-domain pc. Exact current MAIN3404DC is valid; copied440/540 fault sites require native runtime-to-load mapping and declared unchanged opcode before admission.'),
            dict(id='cold-native-inputs',blocking_for_micro=False,required_for_actual_integration=True,
                 requirement='Supply controller metadata by cold descriptor+16 before original358BF8 builder. Borrow actual Dispatcher readonlyM40 and preserve Thread object32 separately. No host write to live TCB+28, FPowner, context, bank or allocator headers.'),
            dict(id='full-guard-delta',blocking_for_micro=False,required_for_actual_integration=True,
                 requirement='Replace cold slot0/all256FF assertions only after observed native148/152 and optionalclone40 stores. Compare per-trapTCB108 with only original clone+28 publication allowed, replay cold-to-final metadata/pool whole zones, retain trailing64FF and actual stack/context-frame bounds.'),
            dict(id='live-actors-and-clock',blocking_for_micro=False,required_for_actual_integration=True,
                 requirement='Keep originalALL/ready/owned mutex chains, background resident frames, Thread timednode20 and clock invariants. Nonexclusive journal mode needs independent original-kernel/actor CPU histories outside activeUND; this micro does not supply them.'),
            dict(id='native-three-stage-exchange',blocking_for_micro=False,required_for_actual_integration=True,
                 requirement='Actual controller-to-Dispatcher firstslot0 savesC without restoringD; subsequent actualD-to-C must saveD/clone40 and restoreC; laterC-to-D must restore savedD. Do not report firstD fault/retry or metadata slot alone as complete multiowner scheduling.'),
        ],
        nonblocking_review_limits=['Standalone constructor occurs before the case try; construction/hook failure journaling is not covered by terminal-probe generation in this source. Root terminal metadata remains necessary.',
            'Observer admits reported VSTM widths1/2/4/8 but actual sealed run observed only8. Other Unicorn widths or exceptionalFPEXC paths require new controls.',
            'Five controls omit owner0 plus already-valid-newslot and a third FP-owning task. This source requires exactly two admitted task inputs.',
            'Static verifier relies on runtime pending-push value gates; this review additionally compares all observed push ABI/address/value records against the previously bounded native flow.'],
        actual_cold_Dispatcher_body_verified=False,multiowner_native_scheduling_verified=False,
        physical_App_direct_phone_music_package_acceptance_verified=False,
        assertions_passed=True)
    with (ROOT/OUT).open('x') as f: json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(artifact=OUT,sha256=sha(OUT),generator_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),assertions_passed=True,source_dependencies=len(deps),original_instruction_sites=len(instructions),observed_push_frames=push_checked)))

if __name__=='__main__': main()
