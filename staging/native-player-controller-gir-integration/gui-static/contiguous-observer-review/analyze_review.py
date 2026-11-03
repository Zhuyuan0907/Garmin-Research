#!/usr/bin/env python3
"""Static source/MAIN review; never import or execute a VM or Unicorn."""
from datetime import datetime, timezone
from pathlib import Path
import ast, hashlib, json, sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage

STAGE = Path(__file__).resolve().parent
RUNNER = 'scripts/probe_native_controller_gir_component_contiguous.py'
PREFLIGHT = 'staging/native-player-controller-gir-integration/resource-static/font-cache-span-preflight.json'
PREVIOUS = 'staging/native-player-controller-gir-integration/previous-audit.json'

def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()

def main():
    runner = (ROOT / RUNNER).read_text()
    digest = sha(RUNNER)
    assert digest == '738b46d3a4254370f8c1a27875b71620a1c4625a4bf091bdc5654beaea54d541', 'Review final agreed source only'
    tree = ast.parse(runner)
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ContiguousFontControllerGIRVM')
    methods = {n.name: n for n in klass.body if isinstance(n, ast.FunctionDef)}
    excerpts = {name: dict(line=node.lineno, end_line=node.end_lineno,
        source=ast.get_source_segment(runner, node)) for name, node in methods.items()}
    previous = json.loads((ROOT / PREVIOUS).read_text())
    preflight = json.loads((ROOT / PREFLIGHT).read_text())
    protected = previous['protected_sources']
    assert len(protected) == 608 and protected == preflight['protected_sources']
    mismatches = [p for p, expected in protected.items() if sha(p) != expected]
    assert not mismatches, mismatches
    srcs = [RUNNER, PREFLIGHT, PREVIOUS, str(Path(__file__).resolve().relative_to(ROOT)),
        'scripts/probe_native_controller_gir_component.py', 'scripts/emulate_native_player_external_fonts.py',
        'scripts/emulate_native_player_text.py', 'scripts/probe_native_heap_settings_boot.py',
        'scripts/analyze_native_sections.py', 'evidence/firmware-analysis/main_02bd.bin',
        'staging/native-player-controller-gir-integration/runtime/terminal-probe.json']
    stock = NativeImage()
    ranges = [(0x264020, 0x264046), (0x26475c, 0x2647d8), (0x2648c8, 0x264952),
        (0x265f46, 0x265fc4), (0x268592, 0x26859c), (0x140878, 0x1408b0)]
    insns = [dict(address=hex(i.address), opcode_hex=i.bytes.hex(), instruction=i.mnemonic+' '+i.op_str)
        for lo, hi in ranges for i in stock.instructions(lo, hi)]
    assert 'row[\'handle\']==handle' in excerpts['observe']['source']
    assert 'self.cache_live.get(allocation[\'pointer\']) is allocation' in excerpts['observe']['source']
    assert 'self.live_font_payload(pointer,length)' not in excerpts['map_verified_file_destination']['source']
    assert 'live_native_font_parser' in excerpts['map_verified_file_destination']['source']
    assert 'resident_native_timed_thread_node' in excerpts['map_verified_file_destination']['source']
    positive_request = '0<requested<CACHE_BYTES' in excerpts['observe']['source']
    assert positive_request
    assert 'if address==0x26491c' in excerpts['observe']['source']
    assert 'caller==0x264939' in excerpts['observe']['source']
    assert 'sp==route[\'SP\']' in excerpts['observe']['source']
    assert 'self.cache_reader_route_pending is None and not self.cache_alloc_pending' in excerpts['verify_component_memory']['source']
    findings = [
        dict(id='LOWER_STREAM_BINDING', status='fixed in reviewed source', original_reviewed_sha256=
            'f7ce9154d782cbebc8e9288c4d1525dd2eac2591d54ec6823622682db83f96f1',
            method='observe', problem='The initial cache admission matched only destination range, allowing a different live file handle.',
            fix='Before lower callback, require one pending read matching actual handle and range, live allocation object identity, and context/control.'),
        dict(id='CRITICAL_NATIVE_OBJECTS', status='fixed in reviewed source', method='map_verified_file_destination',
            problem='Generic live font malloc payload admission included cache control/parser bodies and lacked their exclusions.',
            fix='Generic malloc raw admission removed. Only current-controller stack or original live cache read payload admitted; controls, published parsers/contexts, metadata/records, timed nodes, TCBs, saved frames, semaphores and component regions excluded.'),
        dict(id='REQUEST_DOMAIN', status='strict positive bounded request verified' if positive_request else 'remaining source/preflight difference',
            method='observe', detail='Preflight success admission is 0<N<C0000. Initial observer allowed zero and the whole cache length. The known 2648C8 route returns before allocation when N=0.'),
        dict(id='NATIVE_EPILOGUES', status='matches exact original instructions', method='observe',
            detail='264032/264044 capture after native pops: entry SP restored, r3=entry LR, r0=payload or0. 2647D6 follows POP r4-r7 and r0=0; native shared K permits a distinct free context. Allocation generations are row objects retained in append-only history; cache_live identity prevents old generation reuse admission.'),
        dict(id='RW_COVERAGE', status='adjacent writable mappings admitted; gaps/nonwritable mappings rejected',
            method='map_verified_file_destination', detail='ExternalFontVM maps only missing startup-zero slices; sorted cursor advances region_end+1 through the complete admitted chunk. The original single-region condition is bypassed explicitly.'),
        dict(id='CHRONOLOGICAL_CACHE_REPLAY', status='source reconstruction is complete for declared CPU and lower raw-input events',
            methods=['journal_cache_CPU_write','journal_cache','verify_component_memory'],
            detail='CPU and raw events share before-byte continuity and ordered replay from admitted zero input. Every original MAIN store checks unchanged opcode even after decode memoization. Parent confirms exact backup bytes before raw event recorded. Final mapped slices match replay and unmapped slices must have zero expectation.'),
        dict(id='WHOLE_CACHE_BASELINE_SCOPE', status='explicit offline zero input, not an observed fully mapped physical cache',
            detail='Constructor verifies startup-zero provenance and every already mapped cache slice is zero; it does not map/read every cache byte. Endpoint zero expectation for unmapped slices is a declared input inference. Do not claim all 786432 bytes were independently mem_read or hardware initialized.'),
        dict(id='DEEP_NATIVE_READ_FRAME', status='exact source observations added; runtime still pending', method='observe',
            detail='26491C captures saved C atSP+4, parser r4, buffer r5, N r7 and parser+8 stream. It requires the live allocation requested N and previously published parser/context/stream tuple. 14F084 requires exact LR264939, unchanged264934 BL bytes, same SP and all four arguments matching route. Route is consumed and final verifier requires no pending route.'),
        dict(id='CPU_HISTORY_SCOPE', status='typed exact MAIN store history; no complete transitive writer PC whitelist',
            detail='Generic original STR/STM/SWP-family decoder and observed width are admitted over whole cache. This proves bytes arise from recorded original CPU stores within the declared task, not application semantic correctness of every destination. STRD width/value depends on later native hook observation.'),
        dict(id='FIRST_COMPANION_STRD', status='observed two4-byte stores in frozen failed first run',
            evidence='staging/native-player-controller-gir-integration/runtime/terminal-probe.json',
            detail='Original compiled EA10174 STRD emitted address18320100/size4/value80 then18320104/size4/value1. The former static8-byte possibility is not an actual blocking finding for this compiled store. Other new cache writer widths remain unknown until observed.'),
        dict(id='FAILURE_SCOPE', status='intentional fail closed',
            detail='K=0/cache initialization failure, EOF, unknown destination, missing native return or new indirect caller without exact supported BL remain rejected. A development rejection is not a firmware failure.'),
        dict(id='READ_RETURN_SCOPE', status='actual return PC/SP observed; returned byte-count not independently checked here',
            detail='Lower provider records actual available count and parent validates exact supplied bytes; this observer checks14F084 continuation SP but not itsr0. Final font activation/errors impose a separate endpoint check.'),
        dict(id='NO_RUNTIME_RESULT', status='static only',
            detail='No emulator, VM, device, service, sound or canonical source executed or changed; this review cannot certify a completed font initializer or foreground App.')]
    artifact = dict(updated_utc=datetime.now(timezone.utc).isoformat(), static_only=True,
        reviewed_runner=RUNNER, runner_sha256=digest, exact_preflight=PREFLIGHT, preflight_sha256=sha(PREFLIGHT),
        MAIN_sha256=sha('evidence/firmware-analysis/main_02bd.bin'), source_sha256={p:sha(p) for p in srcs},
        protected_source_count=608, verified_protected_sources=protected, protected_hash_mismatches=mismatches,
        method_evidence=excerpts, exact_original_instruction_evidence=insns, findings=findings,
        reviewed_configuration=dict(cache_start='0x34fa3bc', cache_exclusive_end='0x35ba3bc', cache_bytes=786432,
            live_control_user_bytes=620, parser_user_bytes=152, published_context_exclusion_bytes=100,
            font_metadata=[hex(0x14b3c60),hex(0x14b3c60+64*13)],
            font_records=[hex(0x14b4014),hex(0x14b4014+816*13)], selected_font_record='0x14b5004'),
        new_emulation_executed=False, emulator_imported=False, frozen_source_modified=False,
        device_io=False, sounds_emitted=False, canonical_modified=False,
        pending_unknowns=['actual callback widths and copied-code store paths','complete native font return and scoped guards','foreground Dispatcher Manager/UI','physical allocation/filesystem/package acceptance'])
    assert sha(RUNNER) == digest, 'Runner changed during static review; rerun against final version'
    target=STAGE / ('review-'+digest[:12]+'.json')
    with target.open('x') as out:
        json.dump(artifact,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps(dict(path=str(target.relative_to(ROOT)),sha256=sha(str(target.relative_to(ROOT))),
        runner_sha256=digest,protected_sources=len(protected),original_instruction_count=len(insns),static_only=True)))

if __name__=='__main__':main()
