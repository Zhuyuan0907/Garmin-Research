#!/usr/bin/env python3
"""Static integration contract. Reads frozen inputs; never runs a firmware VM."""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

OUT = Path(__file__).with_name('controller-gir-native-integration-contract.json')
V2 = 'staging/controller-gir-prep-stock-v2/verification.json'
STATIC = 'staging/native-player-mainmenu-native-prep/gui-static/native-gir-calls-and-controller-placement.json'

def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()

def source_method(path, cls, name):
    text = (ROOT / path).read_text()
    tree = ast.parse(text)
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
    node = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == name)
    snippet = '\n'.join(text.splitlines()[node.lineno-1:node.end_lineno]) + '\n'
    return dict(path=path, class_name=cls, method=name, first_line=node.lineno,
                last_line=node.end_lineno, snippet_sha256=hashlib.sha256(snippet.encode()).hexdigest(),
                source=snippet)

def main():
    if OUT.exists():
        raise RuntimeError('Preserve existing static artifact')
    manifest = json.loads((ROOT / V2).read_text())
    old_static = json.loads((ROOT / STATIC).read_text())
    dependencies = dict(manifest['source_sha256'])
    protected = dict(manifest['verified_protected_previous_source_hashes'])
    for registry in [dependencies, protected]:
        for path, digest in registry.items():
            if sha(path) != digest:
                raise RuntimeError('Frozen dependency changed: ' + path)
    paths = [V2, STATIC, 'staging/controller-gir-prep-stock-v2/controller-gir-prep-armv6.elf',
             'staging/controller-gir-prep-stock-v2/controller-gir-prep-armv6.bin',
             'scripts/probe_native_heap_settings_boot.py', 'scripts/probe_mainmenu_native_settings_journal.py',
             'scripts/emulate_native_player_external_fonts.py', 'scripts/emulate_native_player_text.py',
             'scripts/emulate_native_player_menu_selection.py', 'scripts/probe_native_player_resources.py',
             'scripts/emulate_native_task_runtime_full.py', 'scripts/emulate_native_player_menu_loaded.py',
             'scripts/emulate_native_mainmenu_constructor.py', 'scripts/emulate_native_vpm_filesystem.py',
             'staging/native-player-heap-settings-boot/terminal-metadata.json',
             'staging/native-player-heap-settings-boot/heap-settings-terminal-probe.json']
    # The manifest is authoritative about the exact flat-binary filename.
    paths[3] = manifest['flat_binary']
    dependencies.update({p: sha(p) for p in paths})
    dependencies[str(Path(__file__).relative_to(ROOT))] = sha(Path(__file__).relative_to(ROOT))
    terminal = json.loads((ROOT / paths[-1]).read_text())
    meta = json.loads((ROOT / paths[-2]).read_text())
    if meta['session_id'] != 46928 or terminal['completed'] or terminal['registers']['pc'] != '0x3404dc':
        raise RuntimeError('Frozen settings failure evidence differs')
    stock = NativeImage()
    functions = {k: old_static['functions'][k] for k in [
        '0x2ca82c', '0x2cabbc', '0x395980', '0x2db540', '0x25dc80', '0x41b198',
        '0x11c504', '0x41cc46', '0x41b15a', '0x4df248', '0x4de236', '0x4de0e0',
        '0x4a388a', '0x316276']}
    exact_instruction_count = 0
    for graph in functions.values():
        if not graph['local_CFG_complete']:
            raise RuntimeError('Incomplete copied local graph')
        for row in graph['instructions']:
            raw = bytes.fromhex(row['bytes_hex'])
            if stock.read(int(row['load_address'], 16), len(raw)) != raw:
                raise RuntimeError('Static instruction differs from exact MAIN')
            exact_instruction_count += 1
    flat = (ROOT / manifest['flat_binary']).read_bytes()
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    compiled_observations = []
    for pc, wanted in [(0xea1004c, 'push'), (0xea10254, 'add'), (0xea102cc, 'add'),
                       (0xea104b0, 'add'), (0xea108b0, 'str'), (0xea108b8, 'strb'),
                       (0xea108c0, 'mov'), (0xea108c8, 'mrs'), (0xea108e0, 'bx'),
                       (0xea1091c, 'bx')]:
        raw = flat[pc-manifest['load_base']:pc-manifest['load_base']+4]
        insn = next(arm.disasm(raw, pc, count=1))
        if insn.mnemonic != wanted:
            raise RuntimeError('Compiled ABI observation differs')
        compiled_observations.append(dict(PC=hex(pc), opcode_hex=raw.hex(),
                                          instruction=insn.mnemonic+' '+insn.op_str,
                                          compiled_companion_not_original_MAIN=True))
    font_table_load = stock.runtime_to_load(0xf088b0, 13*16)
    font_table = stock.read(font_table_load, 13*16)
    font_inputs = []
    for n in range(13):
        pointer, kind, length, flags = struct.unpack_from('<4I', font_table, 16*n)
        row = dict(index=n, descriptor_runtime=hex(0xf088b0+16*n), descriptor_load=hex(font_table_load+16*n),
                   raw_descriptor_hex=font_table[16*n:16*n+16].hex(), pointer=hex(pointer),
                   kind=kind, length=length, flags=hex(flags))
        if kind != 2:
            name = stock.read(pointer+50, 100).split(b'\0', 1)[0].decode('ascii')
            path = 'backups/20261002T154458Z/files/.System/ExtData/' + name
            row.update(logical_path='0:/.System/ExtData/'+name, readonly_backup=path,
                       present=(ROOT/path).is_file())
            if row['present']:
                row.update(backup_bytes=(ROOT/path).stat().st_size, backup_sha256=sha(path))
                dependencies[path] = sha(path)
        else:
            row['provider'] = 'Original embedded descriptor; do not seed decoded font metrics'
        font_inputs.append(row)
    spans = [(0x34f7730, 36, 'GIR catalog vector12/raw backend24'),
             (0x34f9b60, 24, 'Widget registry'), (0x34a5614, 24, 'Display-list registry'),
             (0x14b3c60, 13*64, 'Font metadata13'), (0x14b4014, 13*0x330, 'Font records13'),
             (0x14b6984, 12, 'Font registry vector'), (0x3471b58, 8*36, 'MenuSignal objects8'),
             (0xf071e8, 12, 'Font runtime selectors'), (0xf2953c, 12, 'GIR/catalog once guards'),
             (0xf11e04, 12, 'Menu registry globals')]
    resource_inventory = []
    for ptr, length, purpose in spans:
        copied = next((r for r in stock.copies if r['runtime_start']<=ptr and ptr+length<=r['runtime_end']), None)
        zero = next((r for r in stock.zeros if r['runtime_start']<=ptr and ptr+length<=r['runtime_end']), None)
        row = dict(start=hex(ptr), bytes=length, purpose=purpose, live_value_observed=False)
        if copied:
            load = stock.runtime_to_load(ptr, length)
            row.update(provenance='initialized-copy', load_start=hex(load),
                       initial_file_bytes_sha256=hashlib.sha256(stock.read(load, length)).hexdigest())
        elif zero:
            row.update(provenance='startup-zero-range', containing_range=zero,
                       static_live_zero_value_inferred=False)
        else:
            raise RuntimeError('Requested resource span has no recovered provenance')
        resource_inventory.append(row)

    config_names = ['magic', 'bytes', 'flags', 'controller_tcb', 'controller_stack_low',
                    'controller_stack_high', 'stock_gir', 'stock_gir_bytes', 'stock_gir_directory_bytes',
                    'gir_input_low', 'gir_input_high', 'catalog_record_low', 'catalog_record_high',
                    'settings_data_low', 'settings_data_high', 'lower_db_provider', 'player_id',
                    'selected_cell', 'selected_size']
    config_values = [0x13520800, 76, 15, 0x9503f90, 0x9500040, 0x9503f90,
                     0xb800000, 29146504, 731912, 0xb800000, 0xd3cbd88, None, None,
                     0x18001000, 0x18009000, 0x84c0000, 0x7f135201, 12, 0]
    config = [dict(field=n, offset=4*i, value=v, hex_value=hex(v) if v is not None else None)
              for i,(n,v) in enumerate(zip(config_names, config_values))]
    result_names = ['bytes','phase','completed_call_mask','status','controller_before','controller_after',
                    'adapter_sp','settings_return','settings_length','settings_data','platform_hash',
                    'gir_return','gir_kind','gir_catalog','gir_record','font_return','menu',
                    'lower_db_provider','db_setter_returned','db_row_or_closed_SQL_verified']
    imports = manifest['exact_native_imports']
    api_return_PCs = [0xea10264,0xea102dc,0xea10380,0xea103dc,0xea10438,0xea104bc,
                      0xea10534,0xea10654,0xea106b4,0xea10724,0xea107e8]
    # Check return landmarks against actual BL instruction/compiled symbol.
    for row, pc in zip(imports, api_return_PCs):
        before = pc-4
        insn = next(arm.disasm(flat[before-manifest['load_base']:pc-manifest['load_base']], before, count=1))
        symbol = manifest['symbols'][row['symbol']]['address']
        if insn.mnemonic!='bl' or int(insn.op_str[1:],16)!=symbol:
            raise RuntimeError('Compiled API return-PC landmark differs: '+row['symbol'])
        row['compiled_return_PC'] = hex(pc)
        row['original_entry_SP'] = 'P = actual cg_controller_prepare-entry SP minus 40 bytes'

    methods = [source_method(*spec) for spec in [
        ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','__init__'),
        ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','verify_heap'),
        ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','verify_native_endpoint'),
        ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','journal_mutable_write'),
        ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','verify_mutable_scope'),
        ('scripts/emulate_native_player_text.py','TextVM','fonts'),
        ('scripts/emulate_native_player_external_fonts.py','ExternalFontVM','observe'),
        ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','observe'),
        ('scripts/emulate_native_task_runtime_full.py','FullTaskVM','verify_memory')]]
    report = dict(
        updated_utc=datetime.now(timezone.utc).isoformat(), MAIN_sha256=EXPECTED,
        scope='Static integration contract over frozen controller-gir-prep-stock-v2; no firmware/emulator execution',
        new_ARM_emulation_executed=False, device_io=False, sounds_emitted=False,
        frozen_source_proof_or_canonical_modified=False,
        source_sha256=dependencies, verified_frozen_previous_source_hashes=protected,
        direct_dependency_count=len(dependencies), freshly_verified_protected_count=len(protected),
        exact_copied_bounded_local_CFG_count=len(functions), exact_MAIN_instruction_bytes_checked=exact_instruction_count,
        functions=functions, frozen_source_method_evidence=methods,
        compiled_static_instruction_observations=compiled_observations,
        prior_settings_admission=dict(session=46928, terminal_exit_code=meta['terminal_exit_code'],
            phase=terminal['phase'], error=terminal['error'], registers=terminal['registers'],
            native_initializer_returned=False, full_final_guards_passed=False,
            missing_FPEXC_observation=True, VFP_cause_not_confirmed=True,
            ready_F06EF7_not_completion=True, new_root_VFP_runtime_not_assumed_successful=True),
        exact_component=dict(manifest=V2, manifest_sha256=sha(V2), ELF_sha256=manifest['ELF_sha256'],
            flat_sha256=manifest['flat_binary_sha256'], entry='0xea1004c', BSS='0xea11000', BSS_bytes=4,
            linked_OFFLINE_fixture=True, ARMv6_soft_float=True, host_stub_controls=29,
            native_runtime_verified=False, original_Manager_or405340_absent=True),
        config=dict(bytes=76, fields=config, runnable_complete_config=False,
            incomplete_fields=['catalog_record_low','catalog_record_high','config/result live guarded addresses',
                               'successful native settings/VFP endpoint evidence'],
            flags_15_are_caller_attestations_not_enable_actions=True,
            explicit_flags={'bit0':'Unchanged full readonly stock GIR input admitted',
                            'bit1':'Original native settings initializer returned and full endpoint guards passed',
                            'bit2':'Readonly lower external-font provider explicitly configured',
                            'bit3':'Real in-memory copy of readonly backup DB lower provider explicitly admitted'},
            original_firmware_boot_GIR_map_not_recovered=True),
        call_sequence=imports,
        result_contract=dict(bytes=80, fields=[dict(field=n,offset=4*i) for i,n in enumerate(result_names)],
            returned_status=1, name='CG_DB_OBSERVATION_NEEDED', completed_call_mask='0x2ffc', phase=14,
            settings_return=0, settings_length=4, settings_data_u32=1, platform_hash='0x40a730',
            GIR_return=1, catalog='0x34f7730', external_fonts_return=0,
            db_setter_returned=1, db_row_or_closed_SQL_verified=0,
            return_1_is_not_native_DB_font_UI_completion=True,
            void_returns_discarded=['395981','2DB541','4DF249','4A388B','316277'],
            failures='Negative status records partial phase. No retry/reset/rollback/unload, even after a failed admission beyond resident_started.'),
        storage_lifetime=dict(
            source_validation='Only non-null and four-byte alignment checks for config/result; range/overlap/provenance must be checked by new root runner',
            config_result='Declare separate guarded writable live storage, nonoverlapping each other, active stack/canaries, code, GIR input, TCBs/frames/semaphores. Keep through all blocking calls; preserve result and its full 80-byte history.',
            component='Load RX text exact flat hash and explicitly initialize only new four-byte NOLOAD BSS before first call. Keep resident through callbacks; never rerun existing voice bootstrap.',
            settings_stack_input='setting_one=P+8 and data output cell=P+12; original synchronous calls may block with the native frame live',
            GIR_kind_cell='P+7 one-byte output, initialized CC by original compiled component; survives blocked registration',
            GIR_payload='Readonly B800000..D3CBD88 full29146504 bytes. Catalog record retains this pointer after register returns, so keep it alive through resolver/UI callbacks.',
            catalog='Original vector34F7730 [begin,end,capacity], exact live one24-byte record. Require begin4aligned/end-begin24/capacity>=end/full capacity span within actual declared allocator backing. Preserve allocation/canaries/native current query/released-links evidence; do not use old8800320 addresses.',
            catalog_fields={'byte0':'returned kind','byte1':1,'word12':'0xb800000','word16':731912,
                            'unexplained_record_bytes':'Serialize whole24; v2 does not check every other field'},
            external_fonts='Resident context allocations/prefixes and metadata survive all callbacks. Temporary handles require actual original free records; no safe unload claim.',
            menu_signals='Eight original36-byte objects3471B58..3471C78 plus original native subscription/holder allocations remain resident. Decode actual holder types and preserve original callbacks.',
            DB='Provider84C0000 mapping/statements live until all actual native finalizers have returned; preserve closed statement history and SQL row states.'),
        stack_observations=dict(
            notation='E=actual cg_controller_prepare entrySP;P=E-40; all original ABI wrappers tail BX restore temporary LR pushes before entering original API',
            admission='Compare currentF09090/controller, SYS mode31, IRQmarkerF09094=0, P in declared controller stack and P stable after every API; return must restore actual E.',
            current_fixture_example={'E':'0x9503f90','P':'0x9503f68','setting_one':'0x9503f70',
                'data_out_cell':'0x9503f74','kind_out_cell':'0x9503f6f',
                'GIR_local_SP':'0x9503f38','GIR_RAII_guard_cell':'0x9503f50',
                'GIR_raw_lock_entry_SP':'0x9503f30','GIR_raw_unlock_entry_SP':'0x9503f38'},
            GIR='Original41CC46 push20/sub28 => localSP=P-48; guard cell=localSP+24=P-24; guard11C504 push8 => raw3009A0 SP=P-56. Unlock3008B0 SP=P-48 loads identical guard cell. Use observed SP rather than old directAPI hardcoded9503F60/78.',
            nested_static_stack_bounds={'395980':'P-16 before recursive callees','2DB540':'P-16 before recursive callees',
                '41B198':'GIRlocalSP-8 before recursive callees','41B15A':'API entrySP-16 before recursive callees',
                '4DF248':'P-16 before recursive callees','4DE236':'P-24 before recursive callees',
                '4DE0E0':'when called from4DE236, P-24-312=P-336 before recursive callees',
                '4A388A':'P-112 before recursive callees','316276':'P-40 before recursive callees'},
            recursive_callee_max_stack_not_proven=True,
            endpoint='Require RETURN on actual controller, SP=E, current/ALL/ready/state/priority/owned/timed inventories; preserve nonconsumed four background52-byte frames/20-byte Thread timednode and stack canaries.'),
        original_GIR_raw_contract=dict(old_static['GIR_raw_backend'],
            old_direct_API_SP_examples_are_not_component_frame_values=True,
            controller_current_adapter_SP_formulas='See stack_observations'),
        known_root_integration_gaps=[
            dict(id='GIR_RAW_PAIRS',finding='HeapSettingsVM.__init__ rebuilds instance RAW_CALLS from settings36 only. Add exact(3009A0,11C510)->34F773C/41B544 and(3008B0,41CCD2)->same in new subclass; inherited init41B1B2 alone is insufficient.'),
            dict(id='FONT_PROVIDER',finding='ExternalFontVM.external_IO_active defaults false. Admit/activate readonly lower FONT_IO provider before fonts call; flags15 do not enable the VM field. No decoded-font seeding.'),
            dict(id='LIVE_CATALOG_RANGE',finding='v2 requires actual begin/capacity guarded backing span and exactly one record; root must inventory cold catalog/current allocator before call. Existing unrelated native heap extent is not automatically the lower C++raw allocator.'),
            dict(id='INPUT_PROVENANCE',finding='v2 cannot establish writable nonoverlapping config/result or typed DB pointer provenance. Root must explicitly validate guards/backing and preserve all live storage.'),
            dict(id='HEAP_GUARD_PHASE',finding='Cold verify_heap exact8192 private-prefix/free-header recipe is valid only at its declared cold endpoint. New native allocations need allocator block/free/header/list inventory and whole-zone store replay, not unchanged cold recipe.'),
            dict(id='COMPILED_INPUT_STORES',finding='Companion writes three declared lower DB input fields; journal that covers them must use separate exact companion CPU opcode scope, never claim original MAIN PC.'),
            dict(id='SQL_ENDPOINT',finding='FullTaskVM.verify_memory requires no statements and baseline DB, which rejects legal selected row and retained closed history. Add selected endpoint guard without clearing statements/host restoring rows.'),
            dict(id='FONT_ENDPOINT',finding='Return0 alone proves no font inventory. Check fonts13, actual file closure/raw input provenance, handle prefix/query/free/canaries and returned parser calls separately. Do not invoke legacy finish/verify_released that writes frozen development paths or manipulates inventories.'),
            dict(id='MAPPED_WRITER_PC',finding='Journal stock.read(PC,4) is direct-load only; original runtime044/054 code writer PCs need startup-copy translation before exactMAIN compare, or stop as unsupported. Do not compare wrong file location.'),
            dict(id='VFP_ADMISSION',finding='Frozen46928 has no original settings initializer return and no FPEXC record. Await root explicit VFP/native returned/full-guard evidence; neither early readybyte nor host result1 establishes this precondition.')],
        initialized_GUI_CPU_write_contract=dict(
            immutable_original_code='Whole original MAIN/code_images/044 copy/existing voice40/imports/private12/player2/RX extension and readonly GIR/font/DB backup stay byte exact',
            F00000=dict(bytes=467532, source='Original initialized copy CB1980',
                existing_initial_regions_skip_bank=True, requirement='Continuous actual native CPU-store before/value replay and full-bank final comparison; preserve complete journal across heap/settings/component/Dispatcher phases. Do not silently host seed F0.',
                known_prep_globals=['F06EF4..settings','F071E8..font selectors','F11E04..menu registry','F2953C/F29540/F29544 GIR/catalog once'],
                writer_opcodes='CPSR ARM/Thumb, actual opcode bytes equal translated exact MAIN and original STR/STM/SWP-family; no blanket original-byte store permission',
                limits='Net replay detects intervening differing unjournaled writes; same-value/restored host writes not comprehensively disproven'),
            optional05400000=dict(baseline='Inherited whole optional initialized region including separately declared original platform byte fixture',
                known_seven_events=old_static['minimal_explicit_guard_changes']['seven_original_writer_events'],
                requirement='Phase-label prep and Dispatcher events, preserve actual order/value/PC and rebuild expected whole region from immutable host baseline. Seven historical events are conditional inventory, not proof every prep or future callback emits exactly all seven.',
                no_guest_reset_or_history_clear=True,
                new_writer_or_order_requires_new_bounded_static_evidence=True),
            recovered_BSS='Map only documented startup-zero ranges as explicit storage inputs; native constructors and typed final inventories prove initialization, not static file-byte zero inference',
            new_companion=dict(BSS='only EA11000 resident_started1', result='declared80byte output native stores', stack='actual controller frame native stores',
                lower_DB_inputs=[{'CPU_PC':'0xea108b0','opcode_hex':'001080e5','target':'actual native menu+24','size':4,'value':'0x84c0000'},
                                 {'CPU_PC':'0xea108b8','opcode_hex':'0010c0e5','target':'same menu+28','size':1,'value':1},
                                 {'CPU_PC':'0xea108b0','opcode_hex':'001080e5','target':'0x84c0000','size':4,'value':0}],
                requirements='Exact compiled RX hash, ARM CPSR, original component return callsite, exact target/value/order and typed provider input range. Keep separate from MAIN-origin journal.'),
            raw_release='Compare whole24 against actual last original native epilogue; owner0/waiter0/depth0/tag correct and ownedhead restored. Raw+0/+4 stale links need not clear.',
            native_kernel='No SP/current/ready/owner/savedcontext/vtable patch. Existing dual Timer tokens must retain exact ownedchain tags/magic; no Thread clock/timednode mutation.') ,
        resource_inventory=resource_inventory, readonly_stock_GIR=manifest['stock_GIR_input'],
        font_input_table=dict(runtime='0xf088b0', load=hex(font_table_load), bytes=208,
            table_sha256=hashlib.sha256(font_table).hexdigest(), descriptors=font_inputs,
            lower_boundaries={'31D09A':'open(mode1,out_handle), caller140978', '31CF22':'read(handle,destination,bytes<=1MiB)',
                '31D1CE':'seek(handle,unused,r2/r3 signed64; fifth stackword origin0/1/2)',
                '31CE8C':'close(handle)', '31D2E0':'tell(handle)->r0 low/r1 high0'},
            host_raw_read_writes='Readonly file callback copies exact raw bytes into provenance-checked recovered BSS. These lower-provider host writes need separate input ledger/full destination hash; they are not CPU-store events or decoded-font seeding.',
            endpoint_inventory='All external_files closed; paths/positions/byte SHA/chunk destinations within guarded zeroBSS; four existing VPM FILE objects closure checked separately. Serializer fonts13 metadata64@14B3C60,record816@14B4014,context/error+24,flags+3C/3D,metadata+34/+38,name/source_metadata,globalF071F0.'),
        font_handle_guard=dict(resident='For every live native font_malloc handle require locks0, original388804 query observed, user_prefix word0 handle/word4 size<=allocation-8 and positive, 32-byte A5 head/tail canaries, whole context live backing.',
            temporary='Every freed font handle has actual original1408B0 release record and locks0; no synthetic pin1 claim',
            future_glyph_query='Original26849F current-controller API can be a separately admitted native glyph inventory stage; it is absent from v2 and return0 fonts alone is not glyph/display success'),
        SQL_selected_endpoint=dict(database='backups/20261002T154458Z/files/.System/SQLite/custom_mm_icons.db',
            backup_sha256=sha('backups/20261002T154458Z/files/.System/SQLite/custom_mm_icons.db'),
            lower_DB='0x84c0000 in-memory copy; no backup DB write', selected_row={'id':12,'icon':'0x7f135201','size':0},
            native_setter='316277(menu,PLAYER_ID,12,0); unspecified r0 discarded',
            original_wrappers=['2361AE prepare','23762C bind64 x3','2378AE step','2376B8 finalize'],
            engine_boundaries=['2B4D70 prepare','2B2C10 bind64','2AEC46 step','2B299E column','298528 finalize','21D546 lower completion notification'],
            SQL='UPDATE custom_table SET icon = ?, size = ? WHERE id = ?',
            checks='Actual selected row12 and exact allotherrows baseline; every retained statement closed with finalizer event; no pending SQL/notification; backup SHA unchanged; provider and statement/output canaries.',
            eventual_restore='Only after actual controller resumes from callback, original316277 restores original row12 icon/size; require complete DB baseline and allclosed history again. Never host SQL reset or empty statement history.'),
        Manager_only_actual_Dispatcher=old_static['defer_manager_to_actual_Dispatcher'],
        boundary='After all independent settings/GIR/font/SQL/lifetime/whole-memory/native-task guards pass on controller, original new native Signal registration4B571D and queue5D28FF may follow. Manager initialization/registry/currentDispatcher identity/root transition require actual405340 body; absent here.',
        limits='Static source/opcode/input inventory only. Config lacks dynamic allocation span and successful settings/VFP gate. No new ARM execution, complete helper signatures, native font/GIR/SQL completion, MainMenu frame/root foreground/render/touch/native IRQ/physical App/package/phone/audio/safe unload proof.')
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(output=str(OUT.relative_to(ROOT)),sha256=sha(OUT.relative_to(ROOT)),
                         direct_dependencies=len(dependencies),protected=len(protected),CFGs=len(functions),
                         exact_instructions=exact_instruction_count,font_descriptors=len(font_inputs))))

if __name__ == '__main__':
    main()
