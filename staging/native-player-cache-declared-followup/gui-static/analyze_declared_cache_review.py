#!/usr/bin/env python3
"""Narrow static review of explicit cache mapping and observer provenance."""
from datetime import datetime, timezone
from pathlib import Path
import ast, hashlib, json, sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage

RUNNER='scripts/probe_native_controller_gir_cache_declared.py'
EXPECTED='3b190aa2cd832191863815c083572273fc4c99279ef019e0d5425df7e83d70b8'
AUDIT='evidence/firmware-analysis/native-controller-gir-checkpoint-audit.json'
MICRO='staging/native-player-controller-gir-integration/cache-hook-micro-v3/hook-order-controls.json'
BOUNDARY='staging/native-player-controller-gir-integration/resource-static/cache-write-observer-boundary-review.json'

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def main():
    assert sha(RUNNER)==EXPECTED
    audit=json.loads((ROOT/AUDIT).read_text());protected=audit['protected_sources']
    assert len(protected)==665
    bad=[p for p,w in protected.items() if sha(p)!=w]
    assert not bad,bad
    micro=json.loads((ROOT/MICRO).read_text())
    assert micro['all_passed'] and micro['case_count']==3
    for p,w in micro['source_sha256'].items():assert sha(p)==w,p
    boundary=json.loads((ROOT/BOUNDARY).read_text())
    for p,w in boundary['source_sha256'].items():assert sha(p)==w,p
    source=(ROOT/RUNNER).read_text();tree=ast.parse(source)
    methods={n.name:dict(line=n.lineno,end_line=n.end_lineno,source=ast.get_source_segment(source,n))
        for c in tree.body if isinstance(c,ast.ClassDef) for n in c.body if isinstance(n,ast.FunctionDef)}
    outer_main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    stock=NativeImage();low=0x34fa3bc;high=low+0xc0000
    page_low=low&~4095;page_high=(high+4095)&~4095
    pages=list(range(page_low,page_high,4096));assert len(pages)==193
    provenance=[]
    for page in pages:
        rows=[r for r in stock.zeros if r['runtime_start']<=page and page+4096<=r['runtime_end']]
        assert len(rows)==1
        provenance.append(dict(page=hex(page),bytes=4096,original_startup_zero_range=
            [hex(rows[0]['runtime_start']),hex(rows[0]['runtime_end'])]))
    assert stock.read(0x263fce,2).hex()=='4160'
    deps=[RUNNER,AUDIT,MICRO,BOUNDARY,str(Path(__file__).resolve().relative_to(ROOT)),
        'scripts/probe_native_controller_gir_component_contiguous.py',
        'scripts/probe_native_controller_gir_component.py','scripts/probe_native_settings_lazy_vfp_v2.py',
        'scripts/probe_native_lazy_vfp.py','scripts/analyze_native_sections.py',
        'evidence/firmware-analysis/main_02bd.bin',
        'staging/native-player-controller-gir-integration/runtime-contiguous/terminal-metadata.json']
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,
        reviewed_source=RUNNER,reviewed_source_sha256=EXPECTED,source_sha256={p:sha(p)for p in deps},
        exact_PLATFORM=dict(HWID=1352,software='8.00',MAIN_sha256=sha('evidence/firmware-analysis/main_02bd.bin')),
        protected_registry=dict(path=AUDIT,sha256=sha(AUDIT),count=665,changed_or_missing=[]),
        verified_protected_sources=protected,source_locations=methods,
        outer_main=dict(line=outer_main.lineno,end_line=outer_main.end_lineno,
            source=ast.get_source_segment(source,outer_main)),
        declared_memory_input=dict(cache_low=hex(low),cache_high_exclusive=hex(high),cache_bytes=high-low,
            page_low=hex(page_low),page_high_exclusive=hex(page_high),total_cache_covering_pages=193,
            leading_padding_bytes=low-page_low,trailing_padding_bytes=page_high-high,
            pages_with_exact_startup_zero_provenance=provenance,
            whole_zero_baseline_sha256=hashlib.sha256(bytes(high-low)).hexdigest(),
            actual_runtime_pages_not_observed=True,
            total_pages_does_not_equal_new_mapping_record_count=True),
        findings=[
            dict(id='NO_CONCRETE_BLOCK',status='no concrete blocker found in narrow static review',
                detail='Declared scope changes only pre-emulation memory mapping and error diagnostics; original native cache allocator/body/input ownership and inherited final guards remain required.'),
            dict(id='PAGE_ZERO_PROVENANCE',status='all193wholepages statically covered',
                detail='Every page34FA000..35BAFFF lies inside exact original startup-zero rangeF7224C..3AB106C. Missing pages are mappedRW/verifiedzero after parent construction and before original native calls. Existing writable pages are retained, not reset.'),
            dict(id='CACHE_BASELINE',status='source now reads complete786432-byte baseline',
                detail='Outer constructor readsCACHE_LOW/CACHE_BYTES only after complete page declaration and requires allzero. Parent expected/replay starts from same zero value. This fixes before-read on originally unmapped cache backing without native header/pointer seeding.'),
            dict(id='MAPPING_RECORD_COUNT',status='qualifier required',
                detail='declared_startup_zero_cache_pages records only newly mapped pages; existing writable pages are skipped.193 is total covering pages and must not be required as len(newpages). Leading956/trailing3140 padding bytes acquire mapped zero backing but remain outside cache raw-payload admission.'),
            dict(id='MEMORY_PERMISSIONS',status='fail closed for unexpected existing nonwritable page',
                detail='A preexisting nonwritable page is not overwritten or silently madeRW; attempted overlappingmem_map would raiseUcError before emulation. Missing partial mapping is similarly rejected. No known inherited cache RX overlap was identified.'),
            dict(id='UCERROR_RETHROW',status='non-INSN_INVALID original error preserved',
                detail='Captured cache hookUcError logs errno/message/PC/span/regions and uses bare raise. Wrappedlazy.enter records non-INSN_INVALID before calling original lazy handler and raises the original error. It supplies no fake VFP return, FPEXC enable, owner or decoded result. UnsupportedINSN_INVALID still follows original strict lazy guard.'),
            dict(id='SOURCE_ATTRIBUTION',status='three distinct source identities are coherent',
                detail='outer-observer-at-run.py=cache-declared3b190; observer-at-run.py=contiguous738b46; runner-at-run.py=original024714. Outer/inner module STAGE redirected, while each __file__ remains its own frozen source. Different metadata source hashes identify different layers and must not be conflated. Actual VM type inheritsDeclaredCacheVM and LazySettingsVM.last_VM is assigned via type(self).'),
            dict(id='HOOK_DISPATCH',status='subclass hook intercepts inherited registered callback',
                detail='Parent hook_add uses self.journal_cache_CPU_write during construction, so the bound callback resolves to outer diagnostic override. No emulator run occurs between hook registration and subsequent whole-cache mapping.'),
            dict(id='MICRO_SCOPE',status='3 root-produced exact-instruction controls consumed, not repeated',
                detail='Frozen micro uses original263FCE opcode4160 STRr1,[r0,#4] with explicit register/page fixtures: writehook precedes native unmapped callback, before-read yields capturederrno6, predeclaredzero backing avoids that error. It proves hook ordering only. Old85428 original error was not captured, so its cause remains an inference.'),
            dict(id='ENDPOINT_PENDING',status='native fullrun not executed by reviewer',
                detail='First headerstore history, allocator epilogue/current-TCB caller returns, font/parser/live generations, all13fonts/8streams, SQL closure, whole-cache replay and inherited guards remain requirements for root runtime. Physical App/UI/Bluetooth/package acceptance is unproven.')],
        micro_evidence=dict(path=MICRO,sha256=sha(MICRO),all_passed=True,case_count=3,
            original_PC='0x263fce',opcode_hex='4160',not_a_controller_fonts_endpoint=True),
        new_emulator_execution=False,emulator_imported=False,device_io=False,sounds_emitted=False,
        old_source_or_canonical_modified=False,complete_native_font_endpoint_claimed=False)
    assert sha(RUNNER)==EXPECTED
    target=Path(__file__).resolve().parent/'cache-declared-review-3b190aa2cd83.json'
    with target.open('x')as out:json.dump(payload,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps(dict(path=str(target.relative_to(ROOT)),sha256=sha(str(target.relative_to(ROOT))),
        reviewed_source_sha256=EXPECTED,protected_sources=665,declared_total_pages=193,static_only=True)))

if __name__=='__main__':main()
