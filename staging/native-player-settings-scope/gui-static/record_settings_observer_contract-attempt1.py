#!/usr/bin/env python3
"""Pure host/static seal for the settings observer; never import a VM runner."""
from pathlib import Path
from datetime import datetime, timezone
import ast, hashlib, importlib.util, json, sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM

SOURCE=STAGE/'settings_actor_observer.py'
RUNNER=ROOT/'scripts/probe_native_dispatcher_settings.py'
AUDIT=STAGE.parent/'previous-audit.json'
EXPECTED_AUDIT='dd3f1c3ea6743f6801d9bbb3edff3e0556dbfc1332243c6ee149b86999664f39'
EXPECTED_RUNNER='cbd72f3786b058d38894ae1339d47fd49f1367c4850c208a8dfd40aeebd32312'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def relative(path):return str(path.relative_to(ROOT))
def require(condition,message):
    if not condition:raise AssertionError(message)

def main():
    require(sha(AUDIT)==EXPECTED_AUDIT,'Frozen previous audit changed')
    require(sha(RUNNER)==EXPECTED_RUNNER,'Reviewed root draft changed')
    registry=json.loads(AUDIT.read_text())['protected_sources']
    require(len(registry)==1078,'Protected registry cardinality differs')
    for p,d in registry.items():require(sha(ROOT/p)==d,'Protected dependency changed '+p)
    text=SOURCE.read_text();tree=ast.parse(text);compile(text,relative(SOURCE),'exec')
    forbidden={'mem_write','reg_write','mem_map','mem_unmap','emu_start','emu_stop',
        'invoke','kernel_invoke','ret','put','load','resume_same_native_work'}
    invoked={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
    require(not forbidden&invoked,'Observer contains a guest-mutating/executing API')
    # Import only pure shape/observer definitions, not a runner/VM constructor.
    spec=importlib.util.spec_from_file_location('settings_observer_pure_contract',SOURCE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    controls=[]
    for T in (0x8804030,0x8804430):
        for entry,continuation in module.PAIR:
            row=module.settings_raw_shape(entry,continuation,T)
            require(row['entry_SP']==T-24 and row['pointer']==0x148E6CC and
                row['LR']==continuation|1 and row['tag']==0x2CBF6C and row['classification_byte']==0,
                'Pure raw shape valid input rejected/misstated')
            controls.append(dict(input=[hex(entry),hex(continuation),hex(T)],accepted=True,shape=row))
    for entry,continuation,T in [(0x3009A0,0x2CAC08,0x8804030),(0x3008B0,0x2CABFA,0x8804030),
        (0x3009A0,0x2CABFA,0x8804031),(0x3009A0,0x2CABFA,None)]:
        try:module.settings_raw_shape(entry,continuation,T)
        except AssertionError as e:controls.append(dict(input=[entry,continuation,T],accepted=False,reason=str(e)))
        else:raise AssertionError('Malformed raw shape accepted')
    require(module.BASE+0xB10-module.PAGE==2072 and (2072//4)==518,'Page memzero span differs')
    require((0xB10//4)==708 and ((module.PAGE-module.BASE)//4)==190,'Full native memzero partition differs')
    stock=NativeImage();evidence=[];by_pc={}
    ranges=[(0x2CABBC,0x2CAC22,'Thumb'),(0x2CAD0A,0x2CAD5E,'Thumb'),
        (0x26DCE8,0x26DD42,'Thumb'),(0x26DE56,0x26DE5E,'Thumb'),
        (0x40434C,0x40435E,'Thumb'),(0x4053B0,0x4053C4,'Thumb'),
        (0x2CBD4E,0x2CBD5C,'Thumb'),(0x35B4F4,0x35B544,'ARM')]
    for start,end,mode in ranges:
        raw=stock.read(start,end-start);md=Cs(CS_ARCH_ARM,CS_MODE_THUMB if mode=='Thumb' else CS_MODE_ARM)
        instructions=[]
        for ins in md.disasm(raw,start):
            row=dict(PC=hex(ins.address),opcode_hex=ins.bytes.hex(),size=ins.size,
                instruction=ins.mnemonic+' '+ins.op_str,Thumb=mode=='Thumb')
            instructions.append(row);by_pc[ins.address]=row
        evidence.append(dict(start=hex(start),end_exclusive=hex(end),mode=mode,
            byte_sha256=hashlib.sha256(raw).hexdigest(),instructions=instructions))
    exact={0x26DD38:('0028','cmp r0, #0'),0x26DD3A:('00dc','bgt #0x26dd3e'),
        0x26DD3C:('3e63','str r6, [r7, #0x30]'),0x26DD22:('edf0e8eb','blx #0x35b4f4'),
        0x26DD34:('5cf0e9ff','bl #0x2cad0a'),0x2CABF6:('35f0d3fe','bl #0x3009a0'),
        0x2CAC04:('35f054fe','bl #0x3008b0')}
    for pc,(opcode,instruction) in exact.items():
        require(by_pc[pc]['opcode_hex']==opcode and by_pc[pc]['instruction']==instruction,
            'Original bounded opcode/argument provenance differs '+hex(pc))
    require(stock.word(0x26E0BC)==0x100D,'Native source100D literal differs')
    direct=[]
    for pc,(address,n,register,offset) in module.DIRECT.items():
        require(by_pc[pc]['instruction'].startswith('str'),'Direct write is not an original store')
        direct.append(dict(PC=hex(pc),address=hex(address),size=n,value=0,
            destination_register=register,offset=hex(offset),source_register='r6',instruction=by_pc[pc]))
    require(len(direct)==6,'Five setup plus one default direct writer scope differs')
    runner=RUNNER.read_text();runner_tree=ast.parse(runner)
    lines=runner.splitlines()
    refs={needle:next(i for i,line in enumerate(lines,1) if needle in line) for needle in
        ['ActorMixin=_module.SettingsDispatcherActorObserverMixin','0x3aaf000]:',
         'vm.begin_body_observer(D)','vm.capture_decoder_inputs()',
         'vm.capture_dispatcher_settings_inputs()',"S=vm.kernel_invoke(0x3954cc,(80,))",
         "result['initialized_data_journal']['before_hex']",'mutable_bank_initial_before_hex=']}
    require(refs['vm.begin_body_observer(D)']<refs['vm.capture_decoder_inputs()']<
        refs['vm.capture_dispatcher_settings_inputs()']<refs['S=vm.kernel_invoke(0x3954cc,(80,))'],
        'Root native input capture/publication sequence differs')
    require('if self.dispatcher_body_active and self.observe_dispatcher_actor(uc,address,size,data):return' in runner,
        'Root observer-first dispatch chain differs')
    require('existing_mapped_bytes_reset=False' in runner and 'if not any(lo<=page' in runner,
        'Root new page does not preserve existing bytes')
    require(runner.count('(0x3aaf000,4096)')==1,'Root bounded whole-page journal missing or duplicate')
    observer_refs={node.name:node.lineno for node in tree.body if isinstance(node,ast.ClassDef)
        for node in node.body if isinstance(node,ast.FunctionDef)}
    dependencies={relative(p):sha(p) for p in [SOURCE,Path(__file__).resolve(),RUNNER,AUDIT,
        module.PARENT,module.parent.PARENT,module.parent.parent.SHAPE_SOURCE,
        ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'scripts/probe_native_task_mutex.py',ROOT/'scripts/probe_native_heap_settings_boot.py',
        ROOT/'scripts/probe_mainmenu_native_settings_journal.py']}
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=sha(SOURCE),
        observer_source=relative(SOURCE),observer_class='SettingsDispatcherActorObserverMixin',
        status='unexecuted_static_integration_candidate',guest_execution=False,VM_instantiation=False,
        device_io=False,canonical_or_frozen_source_modified=False,protected_files_verified=1078,
        protected_registry_sha256=sha(AUDIT),dependency_sha256=dependencies,
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        pure_host_controls=controls,pure_host_controls_passed=len(controls),
        guest_mutator_AST_controls=dict(forbidden_calls=sorted(forbidden),observed_forbidden_calls=[],passed=True),
        integration_interface=dict(init='init_dispatcher_actor_observer after super constructor',
            capture='capture_dispatcher_settings_inputs once after completed cold/controller begin_body_observer and decoder capture, before Signal80 publication',
            observe='observe_dispatcher_actor(uc,address,size,data); True only exact admitted raw begins; other entries delegate frozen parents',
            snapshot='snapshot_dispatcher_actor_observer adds settings_actor_observer',
            verify='verify_dispatcher_actor_observer preserves parent full closure then exact own closure',
            method_line_numbers=observer_refs,root_draft_source_sha256=sha(RUNNER),root_line_numbers=refs),
        settings_raw_contract=dict(pointer='0x148e6cc',tag='0x2cbf6c',class_byte=0,
            actor='actual Dispatcher8804FB8 == running_task == F09090 current; original live TCB and stack',
            containing_frames=['original405340 callback','PageMainMenu40434C','SFS26DCE8','2CAD0A','2CABBC'],
            source_setting_id='0x100d',source_literal='0x26e0bc',
            pairs=[module.settings_raw_shape(e,c,0x8804030) for e,c in module.PAIR],
            initializer='Original3008A0 caller2CBD54 sixzero CPU stores3008A2..3008AC and original2CBD58 tag store observed under controller before new actor',
            capture='real whole24 compared to last native controller unlock; preserve genuine released +0/+4 stale links; owner/waiter0/tag/class/depth exact',
            pending_ledger='native_mutex_runs plus task_mutex_ops[actualD], same frozen300A0A/30092A epilogue consumer; exact original caller/SP/r0 witnessed',
            whole24_chronological_before_value_replay_required=True,host_seed_or_reset=False,host_return_success=False),
        bounded_SFS_page_contract=dict(page='0x3aaf000',bytes=4096,
            initial_mapping='Root only-if-unmapped original startup-zero declared fixture; preserve actual existing bytes; not physical beforeRAM proof',
            actual_before_hex_captured=True,whole_page_chronological_replay_required=True,
            direct_writers=direct,setup_writer_count=5,absent100D_default_writer_count=1,
            native_memzero=dict(entry='0x35b4f4',call='0x26dd22',continuation='0x26dd26',
                processor_mode='ARM',entry_SP='captured26DCE8entrySP-72',body_SP='entry_SP-4',
                arguments=['0x3aaed08','0xb10'],full_words=708,prior3AAEpage_words=190,
                new3AAFpage_words=518,new_page_span=['0x3aaf000','0x3aaf818 exclusive'],
                actual_return_r0='0x3aaf818',original_writers=['0x35b50c','0x35b510','0x35b520','0x35b524','0x35b530'],
                actual_sequential_four_byte_zero_events_required=True,host_zeroing=False),
            default_branch=dict(native_wrapper_r0='0xffffffff',store_source='r6=0',
                store_time_r0='0xffffffff',R7='0x3aaf808',effective_address='0x3aaf838',
                original_opcode='3e63',original_instruction='str r6, [r7, #0x30]',
                root_rejected_static_hypothesis='STR r0 / MOVS r0,#0 at26DD3A contradicted exact MAIN:26DD3A is BGT; no helper edit or observed runtime contradiction'),
            all_other_page_writers='hard stop with actual mapped/span/before evidence; no broad BSS/font/GIR/cache admission'),
        original_instruction_evidence=evidence,bounded_instruction_count=sum(len(r['instructions']) for r in evidence),
        qualification=dict(inherited_no_record_lower_lookup_fixture='Frozen inherited2CAB14 behavior unchanged; this observer witnesses actual100D arguments/localword/result without supplying return',
            native_lower_storage_hardware_proven=False,settings_queued_body_closure_proven=False,
            fullbody_proven=False,foreground_proven=False,physical_App_proven=False,
            unknown_decoder_callback_or_hardware='frozen v2 hard stop unchanged',
            next_unknown_GIR_font_cache_actor_or_original_page_writer='preserved strict boundary; new contract does not admit it'))
    target=STAGE/'settings-actor-observer-contract.json'
    with target.open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(artifact=relative(target),artifact_sha256=sha(target),source_sha256=sha(SOURCE),
        protected_files=1078,pure_controls=len(controls),bounded_instructions=doc['bounded_instruction_count'],guest_execution=False)))
if __name__=='__main__':main()
