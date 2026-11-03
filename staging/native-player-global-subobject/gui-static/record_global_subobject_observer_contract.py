#!/usr/bin/env python3
"""Pure host/static global-object admission seal. No VM module or guest call."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
SOURCE=STAGE/'global_subobject_observer.py'
RUNNER=ROOT/'scripts/probe_native_dispatcher_global_subobject.py'
AUDIT=STAGE.parent/'previous-audit.json'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while block:=f.read(1024*1024):h.update(block)
    return h.hexdigest()
def relative(p):return str(p.relative_to(ROOT))
def main():
    assert sha(AUDIT)=='0804ee3b65a6a5f2c64bb630582711ce4d0c15ae1170aaa9489688f90a5a2f98'
    registry=json.loads(AUDIT.read_text())['protected_sources'];assert len(registry)==1274
    # Root validates the fresh full registry; do not reread all4GB here.
    source_text=SOURCE.read_text();tree=ast.parse(source_text);compile(source_text,relative(SOURCE),'exec')
    forbidden={'mem_write','reg_write','mem_map','mem_unmap','emu_start','emu_stop','invoke','kernel_invoke','ret','put','load'}
    called={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
    assert not forbidden&called
    spec=importlib.util.spec_from_file_location('global_subobject_pure_contract',SOURCE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    controls=[]
    for T in (0x8804100,0x8804500):
        for function,(continuation,delta) in module.FRAMES.items():
            row=module.global_subobject_frame_shape(function,continuation,T)
            assert row['entry_SP']==T and row['body_SP']==T-delta and row['LR']==continuation|1
            controls.append(dict(kind='frame',input=[function,continuation,T],accepted=True,shape=row))
    for B,D in [(0x8804098,0x88040E8),(0x8804498,0x88044E8)]:
        for pc in module.STORES:
            row=module.global_subobject_store_shape(pc,B,D)
            assert row['SP']==(D-80 if pc==0x11EABE else B-8) and row['address'] in (0x3AAF844,0x3AAF848)
            assert row['size']==4 and row['Thumb']
            controls.append(dict(kind='store',input=[pc,B,D],accepted=True,shape=row))
    for name,args in [('global_subobject_frame_shape',(0x26DE32,0x11EABA,0x8804098)),
        ('global_subobject_frame_shape',(0x26DE3C,0x344E1E,0x8804098)),
        ('global_subobject_frame_shape',(0x11EAB2,0x114630,0x88040E9)),
        ('global_subobject_store_shape',(0x362A36,0x8804098,0x88040E8)),
        ('global_subobject_store_shape',(0x26DE42,None,0x88040E8))]:
        try:getattr(module,name)(*args)
        except RuntimeError as e:controls.append(dict(kind=name,input=args,accepted=False,reason=str(e)))
        else:raise AssertionError('Unreviewed actor/writer/frame accepted')
    for initial in (bytes(8),bytes.fromhex('aabbccdd01020304')):
        whole=bytearray(initial);history=[]
        for pc in [0x26DE42,0x26DE6C,0x11EABE]:
            shape=module.global_subobject_store_shape(pc,0x8804098,0x88040E8)
            low=shape['address']-module.OBJECT
            history.append(dict(address=shape['address'],before_hex=whole[low:low+4].hex(),value=shape['value']))
            whole[low:low+4]=shape['value'].to_bytes(4,'little')
        assert whole.hex()=='502dc10008edaa03'
        replay=bytearray(initial)
        for row in history:
            low=row['address']-module.OBJECT;assert replay[low:low+4].hex()==row['before_hex']
            replay[low:low+4]=row['value'].to_bytes(4,'little')
        assert replay==whole
        controls.append(dict(kind='whole8_before_value_replay',initial_hex=initial.hex(),
            preserved_actual_before=True,after_hex=whole.hex(),passed=True,guest_observation=False))
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    evidence=[];by_pc={}
    ranges=[(0x1152C8,0x1152D6),(0x114612,0x114652),(0x26DE3C,0x26DE72),
        (0x11EAB2,0x11EACA),(0x11EC24,0x11EC32),(0x385448,0x38545A),
        (0x26DD94,0x26DDA0),(0x362A2C,0x362A40)]
    for low,high in ranges:
        data=stock.read(low,high-low);rows=[]
        for i in md.disasm(data,low):
            row=dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),size=i.size,instruction=i.mnemonic+' '+i.op_str)
            if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
                literal=((i.address+4)&~3)+i.operands[1].mem.disp
                row.update(literal=hex(literal),literal_value=hex(stock.word(literal)))
            by_pc[i.address]=row;rows.append(row)
        evidence.append(dict(start=hex(low),end_exclusive=hex(high),byte_sha256=hashlib.sha256(data).hexdigest(),instructions=rows))
    for pc,(_,_,_,_,opcode) in module.STORES.items():assert by_pc[pc]['opcode_hex']==opcode
    for pc,value in [(0x11462A,0x3AAF844),(0x26DE40,0xC035F8),(0x26DE6A,0x3AAED08),
        (0x11EABA,0xC12D50),(0x114614,0xF701FC),(0x26DE44,0xF701F8)]:
        assert int(by_pc[pc]['literal_value'],16)==value
    assert by_pc[0x26DD9A]['instruction']=='movs r0, r4'
    assert by_pc[0x26DE6E]['instruction']=='movs r0, r4'
    assert by_pc[0x11EC2C]['instruction']=='movs r0, r4'
    assert by_pc[0x26DE70]['instruction']=='pop {r4, pc}'
    runner=RUNNER.read_text();lines=runner.splitlines()
    snippets=['ActorMixin=_module.GlobalSubobjectDispatcherActorObserverMixin',
        'vm.begin_body_observer(D)','vm.capture_decoder_inputs()',
        'vm.capture_dispatcher_settings_inputs()',"S=vm.kernel_invoke(0x3954cc,(80,))"]
    refs={s:next(i for i,line in enumerate(lines,1) if s in line) for s in snippets}
    assert refs[snippets[1]]<refs[snippets[2]]<refs[snippets[3]]<refs[snippets[4]]
    assert 'if self.dispatcher_body_active and self.observe_dispatcher_actor(uc,address,size,data):return' in runner
    dependencies=[SOURCE,Path(__file__).resolve(),AUDIT,RUNNER,module.PARENT,
        ROOT/'staging/native-player-settings-scope/gui-static/settings-global-subobject-next-writer-contract.json',
        ROOT/'staging/native-player-settings-scope/gui-static/settings-actor-observer-contract.json',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'scripts/probe_native_task_mutex.py',ROOT/'scripts/probe_mainmenu_native_settings_journal.py',
        ROOT/'scripts/probe_native_heap_settings_boot.py']
    digest={relative(p):sha(p) for p in dependencies}
    assert sha(module.PARENT)==module.PARENT_SHA
    for p,h in digest.items():
        if p in registry:assert registry[p]==h,p
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=sha(SOURCE),
        source=relative(SOURCE),class_name='GlobalSubobjectDispatcherActorObserverMixin',dependency_sha256=digest,
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        status='unexecuted pure static integration candidate',guest_execution=False,VM_import_or_instantiation=False,
        device_io=False,canonical_or_frozen_sources_modified=False,
        protected_registry=dict(path=relative(AUDIT),sha256=sha(AUDIT),entries=1274,
            referenced_protected_hashes_verified=True,full1274_scan_performed_by_this_producer=False,
            full_registry_validation_owned_by_root=True),
        pure_host_controls=controls,pure_host_controls_passed=len(controls),
        AST_no_guest_mutator_or_executor=dict(forbidden_calls=sorted(forbidden),passed=True),
        interface=dict(init='init_dispatcher_actor_observer; inherited init first',
            capture='Same capture_dispatcher_settings_inputs; frozen parent capture first, automatically adds global_subobject_inputs to returned record',
            observe='Same observe_dispatcher_actor(uc,address,size,data); always delegate frozen parent after own read-only entry/return/once witnesses',
            journal='Override journal_settings_actor_write only for26DE42/26DE6C/11EABE; every other write delegates unchanged frozen full-page/backend observer',
            snapshot='snapshot_dispatcher_actor_observer adds nested global_subobject_observer',
            verify='All inherited full guards first; three native stores + three containing returns + two native once returns + exact whole8 replay',
            root_draft_SHA=sha(RUNNER),root_line_numbers=refs),
        scope=dict(global_storage='0x3aaf844',bytes=8,storage_provenance='Original literal114688/startup-zero global, not551C804 or allocated MainMenu subobject',
            actual_actor='Dispatcher8804FB8 == running_task == F09090 current, native live TCB/current original stack; Thumb boundaries and original opcodes',
            input='Real whole8 from captured original whole4096 page beforeimage; preserve existing bytes; native cold once wordsF701FC/F701F8 captured0, never seeded',
            containing_frames=[module.global_subobject_frame_shape(p,c,0x8804100) for p,(c,_) in module.FRAMES.items()],
            relative_frame_nesting='11EAB2entry=114612entry-24;26DE3Centry=11EAB2entry-80',
            property_argument='Original1152CE→114612 R1 captured with one live native raw allocation containing4 bytes; actual MainMenu frame/lifetime stays required',
            once='Original385448/385450 onF701FC caller114626 andF701F8 caller26DE52; real0→1 CPU bank store plus returnedR0=1/SPsame, no hostreturn',
            writers=[module.global_subobject_store_shape(p,0x8804098,0x88040E8) for p in module.STORES],
            fixed_store_sequence=['26DE42→3AAF844=C035F8','26DE6C→3AAF848=3AAED08','11EABE→3AAF844=C12D50'],
            second_store='Requires actual nested26DCE8 return26DE5C:R0=3AAED08/SPsame plus inherited SFS/settings/raw/zero observations',
            third_store='Requires actual26DE3C return11EABA:R0=3AAF844/SPsame; original11EABA literal R1=C12D50',
            whole8='Each native beforeimage matches chronological virtual8; same rows append exactly once to existing parent whole-page journal; final whole8 exact native store replay',
            native_returns='26DE3C→11EABA and11EAB2→114630 require original objectR0/SPsame;114612→1152D2 requires SPsame and captures actualR0 without inventing success',
            lifetime='Original once-gated global ctor with prospective original3896F8 destructor registrations; no destructor execution/quiescence claim',
            parent_raw_begin_and300A0A_30092A_epilogues_unchanged=True,
            parent_GIR_font_cache_unknown_callbacks_and_hardware_guards_unchanged=True),
        remaining_boundaries=dict(container_scope_admitted=False,container_guest_tested=False,
            next_entry='Original362A2C call11EB28/return11EB2C, R0global+8=3AAF84C',
            first_container_writers=['362A36 STM r0!,{r1=0}→3AAF84C','362A38 STR r1=0→3AAF850'],
            action='Frozen parent page hook hard-stops these and all other unreviewed writers; no broad-vtable/container/heap permission',
            unexecuted_raw_allocation_after_prefix='Original11EAC6 size8 and later362A3C size3C require actual native live-pointer/return/container contract before any broader admission'),
        original_bounded_instruction_evidence=evidence,bounded_instruction_count=sum(len(r['instructions']) for r in evidence),
        qualification=dict(new_native_runtime_positive=False,settings_closure=False,fullbody=False,foreground=False,physicalApp=False,
            prior39489_stop='Earlier actual26DE42 page writer; old frozen009cee settings raw/default/zero were empty',
            prior44634_proof_preserved_with_its_original_scope=True))
    path=STAGE/'global-subobject-observer-contract.json'
    with path.open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(path=relative(path),sha256=sha(path),source_sha256=sha(SOURCE),
        pure_controls=len(controls),bounded_instructions=doc['bounded_instruction_count'],guest_execution=False)))
if __name__=='__main__':main()
