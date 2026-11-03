#!/usr/bin/env python3
"""AST-only guard copy review. Does not import or construct runtime VMs."""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import json
import textwrap

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    stage = Path(__file__).parent
    output = stage / 'cold-fp-guard-copies-peer-review.json'
    assert not output.exists(), 'Keep every review immutable'
    provenance_path = 'staging/native-player-cold-fp-controller/guard-copy-provenance.json'
    provenance = json.loads((ROOT / provenance_path).read_text())
    assert sha(provenance_path) == '448ce2c02379b429928a55b5b6bd0e5b62a1b2c9d81e861cad6cd30e188fa8c6'
    guard_path = provenance['guard_source']
    assert sha(guard_path) == provenance['guard_source_sha256'] == 'b6849ca9dc226078ac83754ea9bb02acae60a8cae13a3f6da95f8c1ba278079b'
    guard_tree = ast.parse((ROOT / guard_path).read_text())
    classes = [node for node in guard_tree.body if isinstance(node, ast.ClassDef)]
    assert len(classes) == 1 and classes[0].name == 'ColdFPGuardMixin' and not classes[0].bases
    methods = {node.name: node for node in classes[0].body if isinstance(node, ast.FunctionDef)}
    assert set(methods) == {'verify_memory','_verify_component_base','verify_component_memory','verify_heap'}
    rows = []
    for frozen in provenance['frozen_methods']:
        source_path = frozen['source']
        assert sha(source_path) == frozen['source_sha256']
        source = (ROOT / source_path).read_text()
        tree = ast.parse(source)
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == frozen['class_name'])
        function = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == frozen['method'])
        segment = ast.get_source_segment(source, function)
        assert hashlib.sha256(segment.encode()).hexdigest() == frozen['source_method_sha256']
        lines = source.splitlines()
        expected = '\n'.join(lines[function.lineno - 1:function.end_lineno])
        for replacement in frozen['declared_changes']:
            assert expected.count(replacement['before']) == 1
            expected = expected.replace(replacement['before'], replacement['after'])
        expected_function = ast.parse(textwrap.dedent(expected)).body[0]
        actual_function = methods[expected_function.name]
        expected_AST = ast.dump(expected_function, include_attributes=False)
        actual_AST = ast.dump(actual_function, include_attributes=False)
        assert actual_AST == expected_AST
        # The four copied guards themselves must not write guest memory or CPU.
        forbidden = []
        for node in ast.walk(actual_function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ['mem_write','reg_write','put','ret','emu_start','context_restore']:
                    forbidden.append(node.func.attr)
        assert not forbidden
        rows.append(dict(source=source_path, class_name=frozen['class_name'], original_method=frozen['method'],
            new_method=expected_function.name, frozen_file_sha256=sha(source_path),
            exact_source_segment_sha256=frozen['source_method_sha256'], declared_changes=frozen['declared_changes'],
            normalized_AST_sha256=hashlib.sha256(actual_AST.encode()).hexdigest(),
            exact_declared_changes_only=True, guest_mutating_calls_in_copied_method=[]))
    dependencies = [str(Path(__file__).relative_to(ROOT)), provenance_path, guard_path,
        *[row['source'] for row in provenance['frozen_methods']],
        'staging/native-player-cold-fp-controller/fp-static/cold-fp-first-controller-boot-contract.json',
        'staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json']
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), static_only=True,
        guest_executed=False, device_io=False, frozen_source_proof_or_canonical_modified=False,
        source_sha256={path: sha(path) for path in dependencies}, guard_methods_reviewed=rows,
        conclusion='Fourcopiedmethods are exactly frozenAST plusdeclaredcoldinput/FPlistener/basecall changes. Noothermethodsemanticdifference.',
        boundary_helper_requirement='verify_cold_controller_or_idle_boundary must require witnessedoriginalcontrollerwholeFFfill/poolprefix FF/noFPalloc forfirstsame, idleA5exact; it cannot rewrite bytes or relaxboth to eitherpattern.',
        listener_requirement='OriginalFPbootregisteronce; exact150->160->3AB1028 andFPnode[0,7FFFFFFF,20EDB1,0]. Whole96/8192recipes andbothheapnative0returns/pendinglockguards remain.',
        component_base_requirement='NewmixininMRObeforeDeclaredCacheVM/ContiguousVM. verify_component_memory invokescopiedbase plus unchangedcache/fullfont/frees/rawreads/CPUreplayguards; newrunner must actually callit atcomplete11helperendpoint.',
        original_guard_checks_preserved=['voiceRAM/40exports/private12/player2API/RXcode',
            'alloriginalcodeimages/initializedregions and wholeGUIjournal',
            'storage/descriptor/allocation/opaque/canaries',
            'idleTimerGUIstacks/sentinels/DB/SQL/providerinputs/GIRcatalog',
            'fonts/nativeparserstreamownership/resident8streams/rawinputledger',
            'wholecacheindependentreplay/nativeallocfreeandreaderreturnbindings/fontactivationandselection',
            'heap96/8192/prefix/freeheader/backendzero-retag/twoheaplistenerreturns/pendinglocks'],
        runner_MRO_initialization_helper_and_endpoint_not_yet_reviewed=True,
        copied_guards_do_not_replace_needed_boot_TCB_metadata_pool_owner_UND_journals=True,
        assertion_passed=True,
        limits='StaticAST/sourcehashonly. No runtime import/guestexecution, rootrunnerreview, bootregister/nativeFF/newmetadata/11helper/fullmemory/multiowner orphysicalApp proof. Frozenmethods retaintheiroriginalscopequalifiers.')
    with output.open('x') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(artifact=str(output.relative_to(ROOT)), sha256=sha(str(output.relative_to(ROOT))),
        generator_sha256=sha(str(Path(__file__).relative_to(ROOT))),methods=4,AST_exact=True,guest_executed=False)))


if __name__ == '__main__':
    main()
