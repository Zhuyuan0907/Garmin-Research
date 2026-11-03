#!/usr/bin/env python3
"""Static peer review of frozen stock-v2 GIR/font/menu SQL contracts.

Parses source without importing any emulator module; reads only exact MAIN,
frozen proofs and backup font/DB files. Creates one exclusive new JSON output.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import ast
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
import struct

ROOT = Path('/root/garmin')
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage
from analyze_sdp_activation import trace

OUT = Path(__file__).with_name('font-provider-SQL-peer-review.json')
AUDIT = 'staging/native-player-controller-gir-integration/previous-audit.json'
CONTRACT = 'staging/native-player-settings-vfp-context/gui-static/controller-gir-native-integration-contract.json'
MANIFEST = 'staging/controller-gir-prep-stock-v2/verification.json'
FONT_PROOF = 'evidence/firmware-analysis/native-player-external-fonts-emulation.json'
DB = 'backups/20261002T154458Z/files/.System/SQLite/custom_mm_icons.db'
METHODS = [
    ('scripts/emulate_native_player_external_fonts.py','ExternalFontVM','__init__'),
    ('scripts/emulate_native_player_external_fonts.py','ExternalFontVM','map_verified_file_destination'),
    ('scripts/emulate_native_player_external_fonts.py','ExternalFontVM','observe'),
    ('scripts/emulate_native_player_external_fonts.py','ExternalFontVM','verify_released'),
    ('scripts/emulate_native_player_text.py','TextVM','fonts'),
    ('scripts/emulate_native_player_text.py','TextVM','verify_released'),
    ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','observe'),
    ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','init_DB_fixture'),
    ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','set_cell'),
    ('scripts/emulate_native_player_grid.py','GridVM','observe'),
    ('scripts/emulate_native_player_grid.py','GridVM','finish'),
    ('scripts/emulate_native_player_widget.py','WidgetVM','record_region_write'),
    ('scripts/emulate_native_player_menu_loaded.py','LoadedPlayerVM','__init__'),
    ('scripts/emulate_native_task_runtime_full.py','FullTaskVM','verify_memory'),
    ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','journal_mutable_write'),
    ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','verify_mutable_scope'),
    ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','__init__'),
    ('scripts/probe_native_player_resources.py','ResourceVM','register_stock_GIR'),
]
ENTRIES = (0x14093e,0x14098c,0x140936,0x1409be,0x1409d0,
    0x14f034,0x14f050,0x14f068,0x14f084,0x2654e4,0x266a82,
    0x4df248,0x4de236,0x4de0e0,0x316276,0x2361ae,
    0x23762c,0x2378ae,0x2376b8,0x41cc46,0x41b15a)


def require(ok, why):
    if not ok:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return digest((ROOT/path).read_bytes())


def method(path, cls, name):
    raw=(ROOT/path).read_text(); tree=ast.parse(raw)
    node=next(n for c in tree.body if isinstance(c,ast.ClassDef) and c.name==cls
        for n in c.body if isinstance(n,ast.FunctionDef) and n.name==name)
    code='\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno])+'\n'
    return dict(path=path,qualified_name=cls+'.'+name,line=node.lineno,end_line=node.end_lineno,
        method_text_sha256=digest(code.encode()),source=code)


def check_registry(registry):
    for path, wanted in registry.items():
        require(sha(path)==wanted,'Protected source changed: '+path)


def main():
    require(not OUT.exists(),'Exclusive review already exists; do not overwrite')
    require('unicorn' not in sys.modules,'Static analyzer must not import emulator modules')
    audit=json.loads((ROOT/AUDIT).read_text()); protected=audit['protected_sources']
    require(len(protected)==608,'Expected immutable previous checkpoint608 registry')
    check_registry(protected)
    old=json.loads((ROOT/CONTRACT).read_text())
    manifest=json.loads((ROOT/MANIFEST).read_text())
    proof=json.loads((ROOT/FONT_PROOF).read_text())
    require(proof['all_passed'] and proof['MAIN_sha256']==EXPECTED,'Frozen font proof differs')
    sources={p for p,c,n in METHODS}|{AUDIT,CONTRACT,MANIFEST,FONT_PROOF,DB,
        'scripts/analyze_native_sections.py','scripts/analyze_native_vpm_acceptance_path.py',
        'scripts/analyze_sdp_activation.py','scripts/emulate_native_player_external_fonts_integration.py',
        'scripts/test_native_font_file_wrappers.py','scripts/emulate_native_player_text_integration.py',
        'native/controller-gir-prep/stock-gir-v2/controller_gir_prep.c',
        'native/controller-gir-prep/stock-gir-v2/controller_gir_prep.h',
        'native/controller-gir-prep/stock-gir-v2/exact_abi.c',
        'evidence/firmware-analysis/main_02bd.bin',
        str(Path(__file__).relative_to(ROOT))}
    sources.update([manifest['ELF'],manifest['flat_binary']])
    require(sha(manifest['ELF'])==manifest['ELF_sha256'] and
        sha(manifest['flat_binary'])==manifest['flat_binary_sha256'],'Frozen ARM component changed')
    flat=(ROOT/manifest['flat_binary']).read_bytes()
    for pc,wanted in {0xea108b0:'001080e5',0xea108b8:'0010c0e5'}.items():
        offset=pc-manifest['load_base']
        require(flat[offset:offset+4].hex()==wanted,'Companion DB writer opcode differs')
    stock=NativeImage(); image=RuntimeImage(stock)
    methods=[method(*spec)for spec in METHODS]
    fn={}
    for entry in ENTRIES:
        graph=trace(image,entry,2500)
        require(not graph['instruction_limit_reached'],'CFG budget exhausted '+hex(entry))
        for row in graph['instructions']:
            addr=int(row['address'],16)
            ins=next(image.md.disasm(image.read(addr,4),addr,count=1))
            row['bytes']=ins.bytes.hex()
            row['load_address']=hex(stock.runtime_to_load(addr,ins.size))
        graph['bounded_intrafunction_only']=True
        fn[hex(entry)]=graph
    expected={0x140974:'bl #0x31d09a',0x140998:'bl #0x31cf22',
        0x1409a8:'movs r3, #0x76',0x1409ac:'eors r2, r3',0x1409ae:'strb r2, [r4, r1]',
        0x26551e:'bl #0x14f034',0x265524:'str r0, [r4, #8]',
        0x14f096:'bl #0x14098c',0x14f09e:'beq #0x14f0ac',0x14f0aa:'str r0, [r5, #0x24]'}
    exact=[]
    for addr,wanted in expected.items():
        ins=next(image.md.disasm(image.read(addr,4),addr,count=1))
        actual=ins.mnemonic+' '+ins.op_str
        require(actual==wanted,'Original native instruction differs '+hex(addr))
        exact.append(dict(address=hex(addr),instruction=actual,bytes=ins.bytes.hex()))

    table=image.read(0xf088b0,208); inputs=[]
    for n in range(13):
        pointer,kind,length,flags=struct.unpack_from('<4I',table,n*16)
        row=dict(index=n,pointer=hex(pointer),kind=kind,length=length,flags=hex(flags))
        if kind!=2:
            filename=image.read(pointer+50,100).split(b'\0',1)[0].decode('ascii')
            path='backups/20261002T154458Z/files/.System/ExtData/'+filename
            row.update(filename=filename,backup_path=path,exists=(ROOT/path).is_file())
            if row['exists']:
                sources.add(path);raw=(ROOT/path).read_bytes()
                row.update(raw_bytes=len(raw),raw_sha256=digest(raw))
        inputs.append(row)
    case=proof['cases'][1]; streams=proof['resident_font_stream_inventory']
    resident=[]
    contexts={int(row['context'],16):row['index'] for row in case['font_inventory']}
    for key,entry in streams.items():
        if entry['closed']:
            continue
        handle=int(key)
        reads=[row for row in proof['native_font_file_wrapper_calls']
            if row['entry']=='0x14f084' and row['arguments'][1]==handle]
        owners=sorted({row['arguments'][0]for row in reads})
        require(len(owners)==1 and owners[0] in contexts,'Frozen resident stream owner not identified')
        resident.append(dict(frozen_handle=hex(handle),path=entry['path'],closed=False,
            frozen_position=entry['position'],frozen_owner_context=hex(owners[0]),
            font_index=contexts[owners[0]],original_14F084_calls=len(reads)))
    require(len(resident)==8 and sorted(r['font_index']for r in resident)==[0,1,2,7,8,9,10,12],
        'Frozen resident stream count/index differs')
    require(case['external_font_streams_remain_native_resident'] and
        old['font_input_table']['endpoint_inventory'].startswith('All external_files closed'),
        'Contract correction target changed')
    readonly_db=sqlite3.connect((ROOT/DB).as_uri()+'?mode=ro',uri=True)
    try:
        baseline=[list(row)for row in readonly_db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')]
    finally:
        readonly_db.close()
    require(len(baseline)==15 and any(row[0]==12 for row in baseline),'Exact DB rows differ')
    selected=[([12,0x7f135201,0]if row[0]==12 else row)for row in baseline]
    sources_sha={p:sha(p)for p in sorted(sources)}
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        scope='Readonly static peer review; no emulator module import or native execution',
        source_sha256=sources_sha,direct_dependency_count=len(sources_sha),
        protected_sources=protected,protected_count=len(protected),protected_unchanged_before_after=True,
        bounded_CFG_count=len(fn),bounded_CFGs=fn,exact_instruction_checks=exact,
        frozen_source_methods=methods,
        component=dict(manifest=MANIFEST,ELF_sha256=manifest['ELF_sha256'],
            flat_binary_sha256=manifest['flat_binary_sha256'],entry='0xea1004c',
            native_settings_endpoint_precondition='Caller must independently establish settings returned/full guards; flags15 only attests inputs',
            return_status=1,return_name='CG_DB_OBSERVATION_NEEDED',
            font_return_is_not_inventory_or_Glyph_display_proof=True,db_setter_void_r0_discarded=True),
        corrections_and_specific_failure_guards=[
            dict(id='RESIDENT_FONT_STREAMS',severity='Blocking false-negative endpoint',
                previous_contract_path=CONTRACT,previous_field='font_input_table.endpoint_inventory',
                previous_rule=old['font_input_table']['endpoint_inventory'],
                evidence_path=FONT_PROOF,evidence_fields=['cases[1].external_font_streams_remain_native_resident','resident_font_stream_inventory','native_font_file_wrapper_calls'],
                observed_resident_streams=resident,
                exact_bounded_change='In a new runner require eight live resident streams owned by successful external font contexts, unique expected raw paths, valid positions and continuing read/seek access. Require original close only for temporary/control streams; retain resident streams and module through future glyph callbacks. Keep VPM FILE closure checks separate.',
                fresh_runtime_addresses='Derive handles/context pointers from fresh original callbacks; never copy frozen handle/pointer numbers.',
                native_owner_witness='Observe original parser 26551E→14F034 open and 265524 storing returned stream in allocated parser record+8; correlate actual 14F084(r0=font context,r1=stream,r2=destination,r3=bytes) with native font inventory. This is not a claim that font context+8 has the same layout.'),
            dict(id='MAPPED_FONT_WRITE_PROVENANCE',severity='Incomplete lower-provider write guard',
                evidence_method='ExternalFontVM.map_verified_file_destination',
                existing_guard='Already mapped pages continue before the recovered-BSS check; observe then host mem_write copies raw bytes. Mapping permission alone does not identify writable font storage.',
                exact_bounded_change='Before every raw read write, validate the entire nonwrapping chunk against a declared live font allocation, actual controller stack slice or separately declared verified-zero font buffer, including already mapped pages. Reject code/GIR/TCB/frame/semaphore/foreign allocations. Validate open out-handle cells and native SQL prepare out-cells with the same typed live-range discipline.',
                native_stack='Use current native SP and active controller range; frozen 085FE... destinations came from old direct-invoke stack and do not authorize the new controller stack.',
                ledger='Record raw file identity/SHA, position, destination, full before bytes and returned chunk SHA as lower-provider inputs. The native 1409AE XOR stores are a separate CPU-store history; host callback writes do not trigger UC_HOOK_MEM_WRITE.'),
            dict(id='SELECTED_SQL_ENDPOINT',severity='Blocking inherited baseline guard',
                evidence_method='FullTaskVM.verify_memory',
                existing_guard='Requires not self.statements and baseline DB. The original setter legitimately retains finalized statement history and selected row12.',
                exact_bounded_change='Add a new typed selected endpoint: row12 exactly [12,7F135201,0], other14 rows byte/value baseline, every retained statement closed with matching native finalizer events, actual update bound values [icon,size,id], original step SQLITE_DONE101, no unresolved completion, backup DB SHA unchanged. Retain history; never clear statements or host-restore SQL rows.',
                lifetime='Only after the actual foreground callback returns to controller may original316277 restore the prior row12; final baseline endpoint must still retain closed history.'),
            dict(id='RAW_BANK_AND_WRITER_PHASE',severity='Blocking inherited memory guard unless scoped',
                evidence_methods=['LoadedPlayerVM.__init__','FullTaskVM.verify_memory','JournalSettingsVM.journal_mutable_write','GridVM.finish'],
                existing_guard='F00000 bank excluded from initial_regions; FullTaskVM rejects any054 GUI changes. GridVM.finish permits exactly three historical385450 writes. Neither is a new component-wide initialized-bank guard.',
                exact_bounded_change='Preserve the actual whole F00000 CPU-store replay across settings/component/foreground. For054 retain ordered phase-specific native writer/value history and full-region comparison without changing initial_regions baseline. For copied044/054 writer PCs translate runtime_to_load before opcode comparison; direct stock.read(pc,4) is wrong there. Admit separately exact ARM companion DB-input stores after validating typed targets/caller/order.',
                remaining_limits='Net replay does not exclude all same-value or restored unjournaled host writes. Font raw-input ledger is separate; BSS metadata13x64 and records13x816 also require fresh typed native inventory/lifetime/canaries, not a blanket CPU-original permission.'),
            dict(id='LEGACY_FINISH_SIDE_EFFECTS',severity='Old artifact overwrite or stale endpoint',
                evidence_methods=['TextVM.verify_released','ExternalFontVM.verify_released','GridVM.finish'],
                exact_bounded_change='Do not invoke TextVM.verify_released, which writes frozen font-handle-ownership-development-probe.json. ExternalFontVM override avoids that write but temporarily filters live font handles and delegates old ownership checks; copy its read-only prefix/query/free/canary conditions into a pure new endpoint without generic cleanup, old finish or inventory mutation.'),
            dict(id='GIR_PROVIDER_AND_NATIVE_RAW_CALLS',severity='Native method admission',
                evidence_methods=['ExternalFontVM.__init__','HeapSettingsVM.__init__','ResourceVM.register_stock_GIR'],
                exact_bounded_change='Enable external_IO_active only after immutable raw-font provider admission. HeapSettingsVM instance resets RAW_CALLS to settings36; new subclass must add exact lock3009A0/LR11C510 and unlock3008B0/LR41CCD2 for native34F773C/tag41B544. Supply fresh actual catalog allocation range/canaries. Do not rerun bootstrap to prepare these.'),
        ],
        exact_font_inputs=dict(table_runtime='0xf088b0',table_load=hex(stock.runtime_to_load(0xf088b0,208)),
            table_sha256=digest(table),descriptors=inputs),
        proposed_font_endpoint=dict(metadata_base='0x14b3c60',metadata_stride=64,record_base='0x14b4014',record_stride=816,count=13,
            source='Native TextVM.fonts fields plus original table and frozen proof; fresh dynamic context pointers must be observed',
            active_indices=[0,1,2,3,4,5,7,8,9,10,12],external_indices=[0,1,2,7,8,9,10,12],embedded_indices=[3,4,5],
            absent_indices=[6,11],absent_context_error='0x66 from native14F044/14F046 open failure',
            active_context_error='0x0',global_current_record='F071F0 expected14B5004 with this exact input inventory',
            resident_streams='Eight open streams held by actual successful font contexts; do not require all closed',
            malloc_ownership='locks0, observed388804 pointer query, positive size prefix<=allocation-8, A5 head/tail32, live allocation backing; freed temporaries require original1408B0 release. No native pin1 claim.',
            optional_glyph_stage='26849F actual context queries can independently confirm caption glyph inventory. v2 does not call this API; it is not a display or rendering result.'),
        proposed_SQL_endpoint=dict(backup_database=DB,backup_sha256=sources_sha[DB],baseline_rows=baseline,selected_rows=selected,
            prepare_SQL='UPDATE custom_table SET icon = ?, size = ? WHERE id = ?',bind64_expected=[0x7f135201,0,12],
            engine_is_real_host_inmemory_copy_fixture=True,original_DB_open_schema_FAT_not_proven=True,
            original_prepare_bind_step_finalize=['2361AE','23762C','2378AE','2376B8'],
            lower_engine_boundaries=['2B4D70','2B2C10','2AEC46','2B299E','298528','21D546'],
            DB_binding_companion_native_writes=[{'PC':'0xea108b0','opcode':'001080e5','target':'actualmenu+24','value':'084C0000'},
                {'PC':'0xea108b8','opcode':'0010c0e5','target':'actualmenu+28','value':1},
                {'PC':'0xea108b0','opcode':'001080e5','target':'084C0000','value':0}]),
        new_native_execution=False,emulator_imported=False,device_io=False,sounds_emitted=False,
        old_source_artifact_proof_or_canonical_modified=False,native_App_or_package_acceptance_verified=False,
        limits='Static peer review of exact source/MAIN and frozen successful proofs. Existing offline native font/SQL proofs have their own fixtures and timing. New stock-v2 native integration, scheduling/IRQs, foreground/render/touch/physical App/direct-phone audio/package acceptance and safe unload remain outside this review.')
    check_registry(protected)
    require(sources_sha=={p:sha(p)for p in sorted(sources)},'Input changed during peer review')
    with OUT.open('x',encoding='utf-8') as output:
        output.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(report=str(OUT.relative_to(ROOT)),sha256=digest(OUT.read_bytes()),
        protected=len(protected),dependencies=len(sources_sha),CFGs=len(fn),instruction_checks=len(exact),resident_streams=len(resident))))


if __name__=='__main__':
    main()
