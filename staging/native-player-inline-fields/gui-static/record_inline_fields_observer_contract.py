#!/usr/bin/env python3
"""Pure-host/static inline-fields admission; no VM module/instance/guest."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
SOURCE=STAGE/'inline_fields_observer.py'
RUNNER=ROOT/'scripts/probe_native_dispatcher_inline_fields.py'
AUDIT=STAGE.parent/'previous-audit.json'
STATIC=ROOT/'staging/native-player-global-subobject/gui-static/next-sfs-inline-setter/next-sfs-inline-setter-contract-v2.json'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while chunk:=f.read(1024*1024):h.update(chunk)
    return h.hexdigest()
def relative(p):return str(p.relative_to(ROOT))
def main():
    assert sha(AUDIT)=='52f879fb8a67b981b3c3265f5ebecb0804032929e7f321e0e2c92a673d5febde'
    registry=json.loads(AUDIT.read_text())['protected_sources'];assert len(registry)==1363
    assert sha(STATIC)=='c67bd1321a4f8259c55ad769d63461054388c8a002f80cca7df4a55e7608d3b8'
    assert sha(RUNNER)=='9585208df30e30f11e8151c5c910d86cd0082835add9890da233bb2bdee2e3e8'
    text=SOURCE.read_text();tree=ast.parse(text);compile(text,relative(SOURCE),'exec')
    forbidden={'mem_write','reg_write','mem_map','mem_unmap','emu_start','emu_stop','invoke','kernel_invoke','ret','put','load','hook_add'}
    invoked={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
    assert not forbidden&invoked
    spec=importlib.util.spec_from_file_location('garmin_inline_field_pure_contract',SOURCE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    controls=[]
    for T in (0x8804090,0x8804490):
        for caller in module.CALLS:
            row=module.inline_field_call_shape(caller,T)
            assert row['entry_SP']==T-72 and row['entry_R1']==0xB14 and row['LR']==caller|1
            controls.append(dict(kind='call_shape',input=[caller,T],accepted=True,shape=row))
            for pc in module.STORE_SHAPES:
                shape=module.inline_field_store_shape(caller,pc,T)
                assert shape['R0']==row['target'] and shape['R1']==0xB14 and shape['SP']==T-72
                assert shape['value']==0 and shape['R2']==0 and shape['Thumb']
                controls.append(dict(kind='store_shape',input=[caller,pc,T],accepted=True,shape=shape))
    rejected=[('inline_field_call_shape',(0x26DE5C,0x8804090)),
        ('inline_field_call_shape',(0x26DD04,0x8804091)),('inline_field_call_shape',(0x26DD04,None)),
        ('inline_field_store_shape',(0x26DD04,0x44F76D6,0x8804090))]
    for name,args in rejected:
        try:getattr(module,name)(*args)
        except RuntimeError as error:controls.append(dict(kind=name,input=args,accepted=False,reason=str(error)))
        else:raise AssertionError('Unreviewed actor/writer/frame admitted')
    reuse=[(module.LEAF,0x26DD04,False,True),(module.LEAF,0x26DD0C,False,True),
        (module.LEAF,0x115000,False,False),(module.LEAF+2,0x115000,False,False),
        (module.LEAF,0x115000,True,True),(module.LEAF_END,0x26DD04,True,False)]
    for address,caller,pending,expect in reuse:
        actual=module.inline_field_observes_leaf(address,caller,pending);assert actual==expect
        controls.append(dict(kind='non_SFS_leaf_delegate',input=[address,caller,pending],handled=actual,expected=expect))
    for original in (bytes(range(24)),b'\xA5'*24):
        after=bytearray(original)
        for caller in module.CALLS:
            for pc in module.STORE_SHAPES:
                shape=module.inline_field_store_shape(caller,pc,0x8804090)
                i=shape['address']-(module.BASE+0xB14);after[i:i+shape['size']]=bytes(shape['size'])
        assert after[:9]==after[12:21]==bytes(9)
        assert after[9:12]==original[9:12] and after[21:24]==original[21:24]
        controls.append(dict(kind='padding_preserved',before_hex=original.hex(),after_hex=after.hex(),passed=True,guest_observation=False))
    stock=NativeImage();dis={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    leaf=list(dis[True].disasm(stock.read(module.LEAF_LOAD,10),module.LEAF))
    assert [(i.address,i.bytes.hex()) for i in leaf]==list(module.LEAF_OPS)
    assert [i.mnemonic+' '+i.op_str for i in leaf]==['movs r2, #0','str r2, [r0]','str r2, [r0, #4]','strb r2, [r0, #8]','bx lr']
    assert stock.runtime_to_load(module.LEAF,10)==module.LEAF_LOAD
    veneer=list(dis[False].disasm(stock.read(module.VENEER,4),module.VENEER))
    assert len(veneer)==1 and veneer[0].bytes.hex()=='04f01fe5' and veneer[0].mnemonic+' '+veneer[0].op_str=='ldr pc, [pc, #-4]'
    assert stock.word(module.VENEER+4)==module.LEAF|1
    caller=stock.instructions(0x26DCE8,0x26DD26);by_pc={i.address:i for i in caller}
    assert stock.word(0x26E0B8)==0xFFFFF4EC
    for continuation,(call,target) in module.CALLS.items():
        assert by_pc[call].mnemonic+' '+by_pc[call].op_str=='blx #0x462fa4'
        assert continuation==call+4 and target in (0x3AAF81C,0x3AAF828)
    assert by_pc[0x26DD04].mnemonic+' '+by_pc[0x26DD04].op_str=='adds r4, r0, r4'
    assert by_pc[0x26DD06].mnemonic+' '+by_pc[0x26DD06].op_str=='adds r0, r4, r5'
    assert by_pc[0x26DD0C].mnemonic+' '+by_pc[0x26DD0C].op_str=='movs r1, r5'
    runner=RUNNER.read_text();lines=runner.splitlines()
    snippets=['ActorMixin=_module.InlineFieldDispatcherActorObserverMixin','vm.begin_body_observer(D)',
        'vm.capture_decoder_inputs()','vm.capture_dispatcher_settings_inputs()',"S=vm.kernel_invoke(0x3954cc,(80,))"]
    refs={s:next(i for i,line in enumerate(lines,1) if s in line) for s in snippets}
    assert refs[snippets[1]]<refs[snippets[2]]<refs[snippets[3]]<refs[snippets[4]]
    assert 'if self.dispatcher_body_active and self.observe_dispatcher_actor(uc,address,size,data):return' in runner
    deps=[SOURCE,Path(__file__).resolve(),RUNNER,AUDIT,STATIC,module.PARENT,
        ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'staging/native-player-settings-scope/gui-static/settings_actor_observer.py',
        ROOT/'staging/native-player-decoder-scope/gui-static/decoder_actor_observer_v2.py',
        ROOT/'scripts/probe_native_task_mutex.py']
    hashes={relative(p):sha(p) for p in deps}
    assert sha(module.PARENT)==module.PARENT_SHA
    for p,h in hashes.items():
        if p in registry:assert registry[p]==h,p
    methods={method.name:method.lineno for node in tree.body if isinstance(node,ast.ClassDef)
        for method in node.body if isinstance(method,ast.FunctionDef)}
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_path=relative(SOURCE),source_sha256=sha(SOURCE),
        class_name='InlineFieldDispatcherActorObserverMixin',dependency_sha256=hashes,
        status='unexecuted static integration candidate',guest_execution=False,VM_import_or_instantiation=False,
        device_io=False,canonical_or_frozen_sources_modified=False,new_guest_memory_hooks=False,
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        registry=dict(path=relative(AUDIT),sha256=sha(AUDIT),entries=1363,referenced_protected_hashes_match=True,
            complete3_879GB_rescan_by_this_producer=False,full_registry_validation_owned_by_root=True),
        pure_host_controls=controls,pure_host_controls_passed=len(controls),
        AST_control=dict(forbidden_mutator_executor_and_new_hook_calls=sorted(forbidden),passed=True),
        interface=dict(init='Same init_dispatcher_actor_observer; all frozen parents first',
            capture='Same capture_dispatcher_settings_inputs, frozen parent first; adds inline_fields_inputs',
            journal='Existing parent full-page hook resolves override; exactlysix inline tuples with active native pending caller/leaf, otherPCs delegate',
            observe='Same observe_dispatcher_actor; pure read ledgers plus frozen parent delegation, no native instruction skip',
            snapshot='Same snapshot_dispatcher_actor_observer adds inline_fields_observer',
            verify='All frozen inherited guards first then two native returns/six stores/padding',
            source_method_lines=methods,root_source_sha256=sha(RUNNER),root_line_numbers=refs),
        admission=dict(actor='Actual Dispatcher8804FB8 == running_task == F09090 current, native TCB/backing/current live stack',
            containing_function='Captured original26DCE8 caller26DE58/LR26DE5D, argumentbase3AAED08; entrySP T and original bodySP T-72',
            inputs='Actual9-byte fields from same existing whole4096 page beforeimage; actual padding captured; no zero input assumption/reset/seed',
            calls=[module.inline_field_call_shape(c,0x8804090) for c in module.CALLS],
            stores=[module.inline_field_store_shape(c,p,0x8804090) for c in module.CALLS for p in module.STORE_SHAPES],
            mode='ActualARM at462FA4 veneer, actualThumb at44F76CE..D6 and26DD04/26DD0C returns; no inherited mode assumption',
            exact_leaf_sequence='MOVS r2,0 →STR wordoffset0 →STR wordoffset4 →STRB offset8 →BXLR; every original opcode/copy mapping checked',
            entry_R1='B14 for both calls; native26DD0C setsB20 only after second actual return',
            native_return='Full5-code/3-store history + actual caller return/SPsame/R0same/R1B14/R2zero/R3capturedsame/LRsame; no fake return',
            field_journal='Each current whole9 compared to actualbefore+chronological own stores; six rows appendonce to same parent wholepage journal',
            padding=[dict(start=hex(p),bytes=n) for p,n in module.GAPS],
            other_copied_leaf_callers='Delegate code observation when no exact26DD00/08LR/pending; same leaf reused elsewhere is not globally intercepted',
            unknown_page_leaf_writer='MEM_WRITE inside parent page at leafPC still requires exact own pending/span/order; otherwise strict stop',
            unchanged_scopes=['native300A0A/30092A epilogues','settings/global/decoder scopes','FP','GIR/fonts/cache','unknown callback/hardware','wholepage and mutablebank guards']),
        complete_original_leaf_CFG=[dict(PC=hex(i.address),load_PC=hex(stock.runtime_to_load(i.address,i.size)),opcode_hex=i.bytes.hex(),
            instruction=i.mnemonic+' '+i.op_str,successors=[hex(i.address+2)] if i.mnemonic!='bx' else [],returns_to_native_LR=i.mnemonic=='bx') for i in leaf],
        ARM_veneer=dict(PC=hex(module.VENEER),opcode_hex=veneer[0].bytes.hex(),instruction='ldr pc, [pc, #-4]',
            literal=hex(module.VENEER+4),literal_value=hex(stock.word(module.VENEER+4))),
        original_SFS_caller_instructions=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in caller],
        qualification=dict(actual_two_call_native_closure=False,settings_native_closure=False,global_three_store_closure=False,
            fullbody=False,foreground=False,physicalApp=False,no_new_helper_for_container_or_other_writers=True))
    path=STAGE/'inline-fields-observer-contract.json'
    with path.open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(path=relative(path),sha256=sha(path),source_sha256=sha(SOURCE),pure_controls=len(controls),guest_execution=False)))
if __name__=='__main__':main()
