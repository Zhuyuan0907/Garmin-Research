"""Independent AST/data review; never import or execute the scanner."""
from pathlib import Path
import ast
import copy
import hashlib
import json

HERE = Path(__file__).resolve().parent
CAPTURE = HERE / 'captured-inputs'

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def dump(node):
    return ast.dump(node, include_attributes=False)

def adigest(node):
    return digest(dump(node).encode())

def defs(tree):
    return {n.name:n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))}

def same_expr(a, source):
    return dump(a) == dump(ast.parse(source, mode='eval').body)

def find_assign(nodes, target):
    return next(n for n in ast.walk(nodes) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == target for t in n.targets))

def assignments(tree):
    return [n for n in tree.body if isinstance(n, (ast.Assign,ast.AnnAssign))]

def read(name):
    return (CAPTURE / name).read_text()

def jread(name):
    return json.loads(read(name))

def strip_report_changes(node):
    node=copy.deepcopy(node)
    for assign in ast.walk(node):
        if not isinstance(assign, ast.Assign):
            continue
        target=next((t.id for t in assign.targets if isinstance(t,ast.Name)),None)
        if target not in {'stream_receipt','proof','row'}:
            continue
        value=assign.value
        if target in {'stream_receipt','proof'}:
            assert isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and value.func.id=='save'
            value=value.args[1]
        assert isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and value.func.id=='dict'
        removable=({'schema'} if target=='stream_receipt' else
                   {'schema','measurement_changes','actual_RSS_measurement'} if target=='proof' else
                   {'schema','guard_measurement','historical_ru_maxrss_diagnostic_only',
                    'guard_ru_maxrss_diagnostic_KiB','guard_proc_accounting_errors'})
        value.keywords=[k for k in value.keywords if k.arg not in removable]
    return node

def main():
    source3=read('v3-observed-analyzer.py.txt')
    source4=read('v4-observed-analyzer.py.txt')
    core=read('core-analyze-reachable.py.txt')
    mapper=read('mapper-prepare-control.py.txt')
    t3,t4,tc,tm=map(ast.parse,(source3,source4,core,mapper))
    d3,d4,dc,dm=map(defs,(t3,t4,tc,tm))
    assert set(d3)==set(d4)
    unchanged={name:adigest(d4[name]) for name in d3 if dump(d3[name])==dump(d4[name])}
    changed=[name for name in d3 if name not in unchanged]
    assert changed==['Observer','main']
    assert len(unchanged)==11
    assert [dump(n) for n in assignments(t3)]==[dump(n) for n in assignments(t4)]
    constants={}
    for node in assignments(t4):
        if len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            constants[node.targets[0].id]=node.value
    assert same_expr(constants['RSS_CAP_KIB'],'384*1024')
    assert ast.literal_eval(constants['IMG_CAP'])==160000000
    assert ast.literal_eval(constants['COUNTS'])=={3:47870,4:4896236,5:3077845,6:2062771}
    assert ast.literal_eval(constants['STOCK'])=={4:2133948,5:2341096,6:1973316}
    assert same_expr(constants['SUMMARY_CAP'],'1<<20')
    assert ast.literal_eval(constants['RANGE_CAP'])==2000000
    assert ast.literal_eval(constants['ALGORITHM_SHA'])==digest(core.encode())
    assert ast.literal_eval(constants['MAPPER_SHA'])==digest(mapper.encode())
    assert dump(strip_report_changes(d3['main']))==dump(strip_report_changes(d4['main']))
    run3=next(n for n in t3.body if isinstance(n,ast.If))
    run4=next(n for n in t4.body if isinstance(n,ast.If))
    assert dump(strip_report_changes(run3))==dump(strip_report_changes(run4))
    imports3=[dump(n) for n in t3.body if isinstance(n,(ast.Import,ast.ImportFrom))]
    imports4=[dump(n) for n in t4.body if isinstance(n,(ast.Import,ast.ImportFrom))]
    assert imports3==imports4
    observer_methods3=defs(d3['Observer'])
    observer_methods4=defs(d4['Observer'])
    assert dump(observer_methods3['__init__'])==dump(observer_methods4['__init__'])
    assert dump(observer_methods3['close'])==dump(observer_methods4['close'])
    snapshot=observer_methods4['snapshot']
    guarded=find_assign(snapshot,'guarded')
    assert same_expr(guarded.value,"max(proc['VmRSS_KiB'],proc['VmHWM_KiB']) if not proc_errors else None")
    gate=next(n for n in ast.walk(snapshot) if isinstance(n,ast.If)
              and same_expr(n.test,'enforce and (proc_errors or guarded>RSS_CAP_KIB)'))
    gate_names={n.id for n in ast.walk(gate.test) if isinstance(n,ast.Name)}
    assert gate_names=={'enforce','proc_errors','guarded','RSS_CAP_KIB'}
    assert 'ru' not in gate_names
    raises=[n for n in ast.walk(gate) if isinstance(n,ast.Raise)]
    assert len(raises)==2
    assert all(isinstance(n.exc,ast.Call) and isinstance(n.exc.func,ast.Name)
               and n.exc.func.id=='OwnBudgetError' for n in raises)
    proc_open=next(n for n in ast.walk(snapshot) if isinstance(n,ast.Call)
                   and isinstance(n.func,ast.Name) and n.func.id=='open')
    assert [ast.literal_eval(x) for x in proc_open.args]==['/proc/self/status','r']
    required=next(n for n in ast.walk(snapshot) if isinstance(n,ast.For)
                  and isinstance(n.iter,ast.Tuple))
    assert ast.literal_eval(required.iter)==('VmRSS_KiB','VmHWM_KiB')
    assert any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               and n.func.attr=='append' for n in ast.walk(required))
    test_need=ast.parse("len(parts)!=2 or parts[1]!='kB' or not parts[0].isascii() or not parts[0].isdigit()",mode='eval').body
    assert any(isinstance(n,ast.If) and dump(n.test)==dump(test_need) for n in ast.walk(snapshot))
    duplicate=ast.parse("key+'_KiB' in proc",mode='eval').body
    assert any(isinstance(n,ast.If) and dump(n.test)==dump(duplicate)
               and any(isinstance(k,ast.Continue) for k in n.body) for n in ast.walk(snapshot))
    proc_try=next(n for n in snapshot.body if isinstance(n,ast.Try)
                  and any(isinstance(k,ast.With) for k in n.body))
    assert len(proc_try.handlers)==1
    handler=proc_try.handlers[0]
    assert isinstance(handler.type,ast.Name) and handler.type.id=='Exception'
    assert any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               and isinstance(n.func.value,ast.Name) and n.func.value.id=='proc_errors'
               and n.func.attr=='append' for n in ast.walk(handler))
    writes=[n for n in ast.walk(snapshot) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and n.func.attr in {'write','flush','fsync'}]
    assert len(writes)==3 and all(n.lineno<gate.lineno for n in writes)
    assert isinstance(snapshot.args.defaults[-1],ast.Constant) and snapshot.args.defaults[-1].value is True
    assert isinstance(snapshot.body[-1],ast.Return) and same_expr(snapshot.body[-1].value,'guarded')
    calls=[n for n in ast.walk(t4) if isinstance(n,ast.Call)
           and isinstance(n.func,ast.Attribute) and n.func.attr=='snapshot']
    bypass=[n for n in calls if any(k.arg=='enforce' for k in n.keywords)]
    assert len(bypass)==1
    assert any(k.arg=='enforce' and isinstance(k.value,ast.Constant) and k.value.value is False
               for k in bypass[0].keywords)
    assert ast.literal_eval(bypass[0].args[0])=='exception durable final snapshot'
    assert bypass[0].lineno>run4.lineno
    assert all(len(n.args)<=2 for n in calls)
    assert isinstance(run4.body[0],ast.Try)
    outer=run4.body[0].handlers[0]
    assert isinstance(outer.body[-1],ast.Raise) and outer.body[-1].exc is None
    assert not any(isinstance(n,ast.Continue) for n in ast.walk(run4))
    initial=next(n for n in calls if n.args and isinstance(n.args[0],ast.Constant)
                 and n.args[0].value=='initial before any input parse or field array allocation')
    mainload=[n for n in ast.walk(d4['main']) if isinstance(n,ast.Call)
              and isinstance(n.func,ast.Name) and n.func.id in {'load','load_bytes'}]
    assert all(initial.lineno<n.lineno for n in mainload)
    selected=ast.literal_eval(find_assign(d4['main'],'selected').value)
    assert selected=={'stream_actual','prefix_mask','fill_all','mark','contains','make_rank','mapped_ID','analyze'}
    core_hashes={name:adigest(dc[name]) for name in sorted(selected)}
    assert 'main' not in selected
    mapper_names=next(n for n in assignments(tm)
                      if any(isinstance(x,ast.Name) and x.id=='NAMES' for x in n.targets))
    failure=jread('v3-actual-failure.json')
    assert failure['actual_RSS_guard_value_KiB']==424240
    assert failure['actual_RSS_guard_threshold_KiB']==393216
    assert failure['actual_IMG_bytes_read']==0 and failure['actual_IMG_read_ops']==0
    assert failure['observations']['actual_max_observed']['VmRSS_KiB']==17824
    assert failure['observations']['actual_max_observed']['VmHWM_KiB']==17824
    notes=jread('memory-measurement-evidence.json')
    assert notes['host_running_kernel_source_not_fully_verified'] is True
    assert notes['scanner_or_runtime_guard_cases_executed'] is False
    pins=jread('v4-prepared-source.json')
    producer=jread('producer-static-source-review.json')
    assert unchanged==producer['unchanged_function_class_AST']
    assert pins['normal_DATA_program_executed'] is False
    receipts=json.loads((HERE/'input-read-receipts.json').read_text())
    assert receipts['external_artifact_bytes']==126054<=131072
    detail={
        'schema':'garmin-observer-guard-independent-static-detail/v1',
        'all_static_assertions_passed':True,
        'unchanged_function_class_AST':unchanged,
        'all_module_assignment_ASTs_identical':True,
        'imports_identical':True,
        'main_after_only_schema_measurement_report_removal_AST_identical':True,
        'exception_entry_after_only_schema_measurement_report_removal_AST_identical':True,
        'Observer_init_and_close_AST_identical':True,
        'guard_expression':ast.unparse(gate.test),
        'guard_expression_AST':dump(gate.test),
        'guard_metric':ast.unparse(guarded.value),
        'enforcement_dependencies':sorted(gate_names),
        'memory_cap_KiB':393216,'IMG_cap_bytes':160000000,
        'same_current_counts':ast.literal_eval(constants['COUNTS']),
        'same_stock_counts':ast.literal_eval(constants['STOCK']),
        'same_lower_strides_source':[128,126,68],
        'same_original_RAM_selected_function_AST':core_hashes,
        'same_mapper_Image_AST_sha256':adigest(dm['Image']),
        'same_mapper_NAMES_AST_sha256':adigest(mapper_names),
        'original_analyzer_mains_not_in_selected_AST':True,
        'guard_fail_closed_static_paths':[
            'required VmRSS/VmHWM missing','malformed field numeric format',
            'non-kB unit','duplicate parsed memory field','proc open/read error',
            'either current RSS or current-mm high-water exceeds393216KiB'],
        'durable_write_flush_fsync_before_guard_branch':True,
        'valid_proc_error_short_circuit_prevents_None_threshold_comparison':True,
        'historical_ru_maxrss_diagnostic_only':True,
        'normal_snapshot_calls_use_default_enforce_true':True,
        'only_enforce_false_call':dict(line=bypass[0].lineno,
            purpose='exception final receipt; outer handler still bare-reraises'),
        'original_failed_v3_observation':dict(ru_maxrss_KiB=424240,
            VmRSS_KiB=17824,VmHWM_KiB=17824,actual_IMG_bytes_read=0),
        'primary_notes_reviewed':notes,
        'primary_man_fullfiles_or_remote_sources_independently_reread':False,
        'source_review_executed_analyzer_or_guard_helper':False,
        'retained_algorithm_caveat':'force_all may conservatively retain all suffix records while earlier range census remains incomplete; alias_complete alone is not closure proof',
    }
    (HERE/'static-detail.json').write_text(json.dumps(detail,indent=2)+'\n')
    proof={
        'schema':'garmin-compaction-observer-guard-independent-review/v1',
        'all_assigned_checks_passed':True,
        'review_kind':'ordinary DATA/source AST, no scanner or helper execution',
        'prepared_v4_source_sha256':digest(source4.encode()),
        'baseline_v3_source_sha256':digest(source3.encode()),
        'preparation_sha256':'c280de5f6888ea334a4527d5e03613dd86898db2752eb9ed80f220b0d72e94ef',
        'source_algorithm_and_mapper_sha_pins_passed':True,
        '11_unrelated_function_class_ASTs_identical':True,
        'all_module_assignments_and_imports_AST_identical':True,
        'only_Observer_metric_and_report_fields_changed':True,
        'unchanged_numerical_memory_cap_KiB':393216,
        'unchanged_actual_IMG_read_cap_bytes':160000000,
        'unchanged_analyzer_mapper_counts_RAM_transform_ASTs':True,
        'guard_metric':'max(current-mm VmRSS,VmHWM) from /proc/self/status',
        'historical_ru_maxrss_only_diagnostic':True,
        'missing_invalid_duplicate_units_or_proc_read_failures_closed':True,
        'threshold_or_proc_errors_persist_before_raise':True,
        'exception_diagnostic_snapshot_does_not_resume_failed_scan':True,
        'no_counter_reset_numerical_cap_raise_or_context_retry':True,
        'primary_notes':'Pinned preparation local man/upstream Linux notes reviewed; primary full files/remote code not reread here',
        'memory_observation_limitations':'Sampled approximate process accounting; not exact allocations, physical RAM or kernel-enforced hard memory limit',
        'old_v3_failure':'424240KiB historical vs17824KiB currentRSS/HWM; failed beforeIMGread, preserved as original host guard failure',
        'external_artifact_bytes':receipts['external_artifact_bytes'],
        'external_artifact_limit_bytes':131072,
        'capture_history':'initial4825B partial stopped on equal-octal-mode string-format assertion; corrected continuation121229B, no repeated external file reads',
        'external_all_handles_closed':True,
        'normal_DATA_scanner_or_runtime_guard_cases_executed':False,
        'IMG_MAIN_PBF_CPU_guest_audio_device_reads_or_execution':0,
        'shared_source_preparation_seals_canonical_report_changed':False,
        'root_future_actual_execution_required':True,
        'reachability_capacity_compact_IMG_renderer_UI_install_or_v3_fix_certified':False,
        'algorithm_caveat_retained':'force_all/anomaly means alias_complete is not sufficient range-census closure; external lower-ID references remain unknown',
        'details':'static-detail.json',
    }
    (HERE/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,
                      'unchanged_function_classes':len(unchanged),
                      'core_function_hashes':len(core_hashes),
                      'external_artifact_bytes':receipts['external_artifact_bytes'],
                      'proof_sha256':digest((HERE/'proof.json').read_bytes()),
                      'no_scanner_or_IMG_execution':True}))

if __name__=='__main__':
    main()
