#!/usr/bin/env python3
"""Read-only exact runner/mixin source and supplied constructor-record review."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,json
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
BASE='staging/native-player-decoder-scope/'
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def main():
    runner='scripts/probe_native_dispatcher_decoder.py'
    mixin=BASE+'gui-static/decoder_actor_observer_v2.py'
    contract=BASE+'gui-static/decoder-actor-observer-contract-v2.json'
    assert sha(runner)=='a9deadbbeb89b8cf5ca3550164736f852abb16c522a953c6e6dc84009ddc644e'
    assert sha(mixin)=='9ac6b6d8a1139e0ff41413b0bfe0ba715b69b290c60be360629216bd266fa9a1'
    assert sha(contract)=='226178cb735579ba3a83d63f24b45661da06dc001e1752478b1701f21ac6af44'
    protected=read(BASE+'previous-audit.json')['protected_sources']
    inputs=read(BASE+'runtime/inputs-before-run.json')['source_sha256']
    assert len(protected)==892 and len(inputs)==895
    assert all(sha(p)==s for p,s in protected.items())
    assert all(sha(p)==s for p,s in inputs.items())
    preflight=read(BASE+'constructor-preflight/provenance.json')
    assert preflight['all_passed'] and preflight['guest_execution'] is False
    snapshots=[]
    for row in preflight['source_snapshots']:
        assert sha(row['path'])==sha(row['snapshot'])==row['sha256']
        snapshots.extend([row['path'],row['snapshot']])
    r=(ROOT/runner).read_text();m=(ROOT/mixin).read_text()
    assert "GUI_SOURCE=BASE+'gui-static/decoder_actor_observer_v2.py'" in r
    assert 'ActorMixin=_module.DecoderDispatcherActorObserverMixin' in r
    assert r.index('vm.begin_body_observer(D)')<r.index('vm.capture_decoder_inputs()')<r.index('S=vm.kernel_invoke(0x3954cc,(80,))')
    assert 'for page in [0x34f9000,0x3aae000,0x2d16000,0x2d1f000]:' in r
    assert 'existing_mapped_bytes_reset=False' in r
    assert 'if not any(lo<=page and page+4095<=hi' in r
    assert "result['body_full_guards_passed']=False" in r
    assert 'thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)' in m and 'self._da_actor(uc,thumb=thumb)' in m
    assert 'if self.word(CALLBACKS+16):self._decoder_boundary' in m
    assert 'if self.word(CALLBACKS):self._decoder_boundary' in m
    assert 'if address in (0x396D6E,0x39799E):' in m
    tree=ast.parse(m);banned={'mem_write','reg_write','mem_map','emu_start','emu_stop','invoke','kernel_invoke','ret','put'}
    assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in banned for n in ast.walk(tree))
    paths=[str(Path(__file__).resolve().relative_to(ROOT)),runner,mixin,contract,
        BASE+'previous-audit.json',BASE+'runtime/inputs-before-run.json',BASE+'runtime/runner-at-run.py',
        BASE+'constructor-preflight/provenance.json',
        BASE+'gui-static/decoder_actor_observer.py',BASE+'gui-static/decoder-observer-v1-mode-qualification.json',
        'scripts/probe_native_dispatcher_body_fp.py',
        'staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py',
        'scripts/probe_native_task_mutex.py','scripts/probe_native_dispatcher_condition.py']+snapshots
    paths=list(dict.fromkeys(paths))
    assert sha(BASE+'runtime/runner-at-run.py')==sha(runner)
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_review=True,guest_execution=False,
        VM_imported_or_instantiated_by_this_review=False,device_IO=False,frozen_sources_modified=False,
        source_sha256={p:sha(p) for p in paths},
        reviewed_runner_sha256=sha(runner),reviewed_mixin_sha256=sha(mixin),
        protected_registry=dict(path=BASE+'previous-audit.json',count=892,changed_or_missing=[]),
        verified_protected_sources=protected,verified_run_input_source_dependencies=inputs,
        supplied_root_constructor_preflight=preflight,
        root_preflight_distinction='Root instantiated VM but did not execute guest in constructor preflight. This peer review only read its file-backed record and source snapshots.',
        source_changes_vs_frozen_a031=['New exclusive BASE, v2 GUI_SOURCE and subclass name',
            'Add0x2D16000/0x2D1F000 to verified startupzero/unmapped-only mapping list',
            'Add those two4096byte ranges to existing whole body CPU-store journals',
            'Add finalv2 contract to exact dependencies',
            'Capture decoder input after begin_body_observer and before original Signal allocation/publication'],
        callback_order='Complete cold5boot/22component/cache prefix deep copy and synchronous seal → begin_body_observer → actual decoder24/slot32/callback24 reads/hooks → original Signal80 ctor/register/queue → native controller WAIT → actual Dispatcher callback boundary → resume same native callback body.',
        native_epilogues='New exact four raw entries append compatible native_mutex_runs/task_mutex_ops[D] rows and return True;300A0A/30092A delegate through frozen parent/NativeTaskMutexVM, then actual native caller/SP/result is checked.',
        before_image_qualification='Actual bytes must satisfy this cold-zero input admission. No native39799E completion is inferred, no tag/owner/list/callback bytes are seeded, and captured before rows are independent deep copies of later stores.',
        unknown_boundaries='Nonzero callback+16/+0 stops before original indirect jump;39799E ctor/396D6E hardware and any callback-table writer stop. Unreviewed actor/raw caller/backend/store shape remains strict.',
        mode_qualification='V1 is an unexecuted superseded static candidate; no observed runtime mode failure. Exact immediate raw stores are Thumb while ARM IRQ save/restore blocks contain no stores. V2 validates actual CPSR mode and original opcode; raw entry/actual continuation remain Thumb.',
        no_new_wiring_blocker_identified=True,
        observed_guest_result='Parent reported44634 live; this review does not poll/run guest or infer any terminal result.',
        fullbody_guard_or_foreground_or_App_verified=False)
    out=STAGE/'runner-wiring-review-a9deadbb.json'
    with out.open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),
        inputs=len(inputs),protected=len(protected),guest_execution=False)))
if __name__=='__main__':main()
