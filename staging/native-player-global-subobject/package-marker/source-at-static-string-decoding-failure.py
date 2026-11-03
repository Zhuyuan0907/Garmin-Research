#!/usr/bin/env python3
"""Exact stock caller/cache contract only; no VM, payload or device action."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage
from analyze_native_loader import scan_calls
from analyze_sdp_activation import trace

AUDIT = ROOT / 'staging/native-player-global-subobject/previous-audit.json'
AUDIT_SHA = '0804ee3b65a6a5f2c64bb630582711ce4d0c15ae1170aaa9489688f90a5a2f98'
PRIOR = ROOT / 'staging/native-player-settings-scope/package-static/passive-code-marker/passive-code-marker-visible-caller-contract.json'
PRIOR_SHA = '16243e5922c46e4f5dd99c661e5f9c3bcf0ac83ea3858331c09054cb7e22a77f'
REPORT = OUT / 'runtime-cache-code-marker-contract.json'
CFG = OUT / 'runtime-cache-code-marker-bounded-functions.json'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for raw in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(raw)
    return h.hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def rel(path):
    return str(path.relative_to(ROOT))


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def main():
    need(not REPORT.exists() and not CFG.exists(), 'New exclusive outputs only')
    need(sha(AUDIT) == AUDIT_SHA, 'Exact immutable1274 snapshot')
    need(sha(PRIOR) == PRIOR_SHA, 'Prior AudVer contract retained unchanged')
    protected = json.loads(AUDIT.read_text())['protected_sources']
    need(len(protected) == 1274, 'Expected1274 protected files')
    for path, expected in protected.items():
        need(sha(ROOT / path) == expected, 'Before: protected file changed ' + path)
    stock = NativeImage()
    image = RuntimeImage(stock)

    def word(a):
        return struct.unpack('<I', image.read(a, 4))[0]

    def wide(a, limit=100):
        return image.read(a, limit).decode('utf-16le').split('\0')[0]

    def ascii_string(a, limit=64):
        return image.read(a, limit).split(b'\0')[0].decode('ascii')

    exact = {
        0x255068: 'bl #0x3008a0', 0x25506e: 'adr r0, #0x2e8',
        0x255070: 'str r0, [r1, #0x10]',
        0x2749a2: 'lsls r0, r0, #3', 0x2749a6: 'bl #0x38853c',
        0x2749ba: 'str r2, [r1, #0x34]', 0x2749c0: 'bl #0x274978',
        0x274a12: 'str r4, [r0, #0x34]', 0x274a20: 'str r1, [r0, #0x34]',
        0x274a2e: 'str r1, [r0, #4]', 0x274988: 'blx #0x39129c',
        0x27498c: 'str r6, [r4, #0x34]', 0x27498e: 'str r5, [r4, #0x30]',
        0x273bfa: 'str r1, [r0, #4]', 0x273c1e: 'bl #0x3887a2',
        0x273c48: 'bl #0x273bea', 0x273c5c: 'bl #0x1d897c',
        0x1d874e: 'bl #0x274978',
        0x273e76: 'bl #0x3b0d06', 0x273f02: 'ldr r6, [r0, #0x34]',
        0x273f20: 'movs r0, r5', 0x273a94: 'ldr r5, [r0, #4]',
        0x273aa6: 'ldr r7, [r0, #0x34]',
        0x274b2a: 'movs r0, #0xff', 0x274b2e: 'lsls r0, r0, #2',
        0x274b52: 'bl #0x359820', 0x274b68: 'bl #0x35980c',
        0x274b7a: 'adr r1, #0x148', 0x274b7c: 'bl #0x3598b8',
        0x2404a2: 'bl #0x2741f4', 0x2404ba: 'bl #0x2747cc',
        0x2404c2: 'bl #0x23c3c4', 0x2404c6: 'cmp r0, #0xb',
        0x2404ca: 'str r6, [r4, #4]', 0x2404d0: 'str r5, [r4, #4]',
        0x3b332e: 'ldr r1, [r4, #0x18]', 0x3b3330: 'movs r0, r4',
        0x3b3332: 'blx r1', 0x23c434: 'cmp r0, #6',
        0x23c438: 'movs r4, #0xb', 0x23c46c: 'cmp r0, #5',
        0x1fb328: 'ldr r0, [pc, #0xc4]', 0x1fb32a: 'ldrb r0, [r0, #8]',
        0x1fb32c: 'bl #0xfe648', 0x1d8524: 'ldrb r1, [r4, #8]',
        0xfeab2: 'bl #0x2d30ae', 0xfeabe: 'bl #0x31e3be',
        0xfeac4: 'bne #0xfea94', 0xfeaec: 'adds r0, r7, #6',
        0xfeaee: 'bl #0x35984e', 0xfeafc: 'str r5, [r7]',
        0x1fdb9c: 'bl #0x3009a0', 0x1fdbce: 'str r0, [r6]',
        0x1fdbea: 'ldr r0, [sp]', 0x1fdbec: 'bl #0x3597c4',
        0x38881a: 'ldr r0, [r0, #4]', 0x38881c: 'lsrs r4, r0, #3',
        0x38881e: 'lsls r4, r4, #3', 0x388b22: 'bx lr',
        0x3887a2: 'mov r1, lr', 0x3887a4: 'b #0x388746',
        0x27450e: 'bl #0x388804', 0x274518: 'movs r2, #5',
        0x27451c: 'bl #0x3598b8', 0x6817d2: 'blx #0x52c5ec',
        0x68184e: 'bl #0x39274e', 0x3598c8: 'ldrh r3, [r1]',
        0x3598cc: 'strh r3, [r0]',
        0x5c15f4: 'ldr r0, [pc, #0x21c]', 0x5c15fe: 'bl #0x612154',
        0x5c17a2: 'bl #0x240a10', 0x5c17b6: 'bl #0x254b2e',
        0x5c17c6: 'bl #0x254b2e', 0x5c17d6: 'bl #0x254b2e',
        0x254b8e: 'blx #0x2fcf44',
    }
    assertions = []
    for pc, wanted in exact.items():
        op = next(image.md.disasm(image.read(pc, 4), pc, count=1))
        need(op.mnemonic + ' ' + op.op_str == wanted, 'Exact opcode differs ' + hex(pc))
        assertions.append(dict(PC=hex(pc), bytes=op.bytes.hex(), instruction=wanted,
            load_address=hex(stock.runtime_to_load(pc, op.size))))
    need(word(0x273e88) == 0xf09664 and word(0x273e8c) == 0x344cf00, 'Native registry/listmutex globals')
    need(word(0x274bc0) == 0x344cf00 and word(0x274bec) == 0xf09664, 'Insertion globals')
    need(word(0x255354) == 0x344cf00 and ascii_string(0x255358) == '&vpm_voice_list_smphr', 'Native listmutex initializer/tag')
    need(word(0x240660) == 0xf095ac and word(0x1fb3f0) == 0xf09658, 'Selectedindex and active loader descriptor')
    need(word(0x1d88f0) == 0xf09638 and word(0xfebe8) == 0x10425dc, '42byte descriptorarray and retained namehandle array')
    need(wide(0x274c68) == '<voice_name>' and wide(0x274c4c) == '</voice_name>', 'Record+3FC source isvoice_name')
    need(wide(0x274c84) == 'mei-ling' and wide(0x274c98) == 'Chinese_Big5_MeiLing' and wide(0x274cc4) == 'mei-lingb', 'Big5 native ID specialcase')
    need(wide(0x5c17f0) == 'Voice(TTS) Test' and wide(0x5c1808) == 'Speak', 'Original diagnostic labels')
    need(word(0x5c1814) == 0x9d689c and struct.unpack('<2I', image.read(0x9d689c, 8)) == (0x5c179d, 0), 'Speak literal direct member descriptor')

    entries = [0x255058, 0x274978, 0x274992, 0x273bea, 0x273c2a,
        0x273a84, 0x273af6, 0x273abc, 0x273e52, 0x2741f4, 0x2744f6,
        0x2747cc, 0x240498, 0x3b331a, 0x23c3c4, 0x1d8514,
        0x1fb304, 0xfe648, 0xfea50, 0x2d30ae, 0x31e3be, 0x1fdb8e,
        0x388804, 0x388b22, 0x388746, 0x388e92, 0x3887a6,
        0x5c1558, 0x5c179c, 0x254b2e]
    functions = {}
    for entry in entries:
        f = trace(image, entry, 4000)
        need(not f['instruction_limit_reached'] and not f['unresolved_exits'], 'Unclosed localCFG ' + hex(entry))
        for row in f['instructions']:
            pc = int(row['address'], 16)
            op = next(image.md.disasm(image.read(pc, 4), pc, count=1))
            row.update(bytes=op.bytes.hex(), load_address=hex(stock.runtime_to_load(pc, op.size)))
        f['scope'] = 'Local Thumb CFG only; callees and indirect callbacks are not recursively closed.'
        functions[hex(entry)] = f
    old_metadata = ROOT / 'evidence/firmware-analysis/native-voice-metadata-emulation.json'
    producer = json.loads(old_metadata.read_text())['static_functions']['0x274acc']
    kept_producer_rows = [r for r in producer['instructions'] if
        0x274b12 <= int(r['address'], 16) <= 0x274b9e or 0x274e88 <= int(r['address'], 16) <= 0x274ec8]
    for row in kept_producer_rows:
        pc = int(row['address'], 16)
        op = next(image.md.disasm(image.read(pc, 4), pc, count=1))
        need(op.mnemonic + ' ' + op.op_str == row['instruction'], 'Frozen producer differs ' + hex(pc))
    calls = scan_calls(stock, {0x274978, 0x274992, 0x273bea, 0x273c2a, 0x240498})
    need(calls['0x274978'] == ['0x1d874e', '0x2749c0'], 'Known normalcall copy sites')
    need(calls['0x273bea'] == ['0x273c48'], 'Known normalcall cacheclear site')
    imports = list(struct.unpack('<40I', image.read(0xf092c4, 160)))
    need(imports[15] == 0xf09560 and imports[23] == 0xf09548 and imports[39] == 0xf092c0, 'Original40 storage binding')
    save(CFG, dict(MAIN_sha256=EXPECTED, functions=functions,
        reused_original_metadata_source=rel(old_metadata), exact_identity_and_version_writer=kept_producer_rows,
        direct_normal_Thumb_BL_candidates=calls, direct_scan_excludes_no_indirect_ARM_or_conditional_callers=True,
        full_transitive_DLL_or_UI_or_signature_policy_closed=False))

    registry_path = ROOT / 'evidence/firmware-analysis/native-voice-registry-emulation.json'
    selector_path = ROOT / 'evidence/firmware-analysis/native-voice-selection-emulation.json'
    original_path = ROOT / 'evidence/firmware-analysis/original-tts-module-emulation.json'
    registry = json.loads(registry_path.read_text())
    selection = json.loads(selector_path.read_text())
    original = json.loads(original_path.read_text())
    need(registry['all_passed'] and selection['all_passed'] and original['all_passed'], 'Frozen controls passed only in ownscope')
    identities = []
    for case, wanted in zip(registry['cases'][:3], ['mei-lingb', 'mei-ling', 'jill']):
        row = case['result']['registry'][0]
        need(row['volume_id'] == wanted and row['bytes'] == 1912 and row['type'] == 1, 'Frozen native record identity')
        identities.append(dict(case=case['name'], native_voice_name=row['volume_id'],
            fixture_pathname=row['filename'], metadata_checksum=hex(row['metadata_checksum']),
            opaque_handle_is_fixture=True, pathname_namespace_is_fixture=True,
            not_physical_selected_record_proof=True))
    selected = selection['cases'][0]['selection']
    need(selected['selected_index'] == 0 and selected['loader_result_captured_before_native_compare'] == 11 and
        selected['original40_trampolines_identical'] and selected['temporary_handles_released_native_registry_retained'], 'Prior selector limitedcorroboration')
    need(len(original['cases']) == 3 and all(len(c['trampolines_verified']) == 40 for c in original['cases']), 'Prior all40 registrationcontrols')
    source_paths = [Path(__file__), AUDIT, CFG, PRIOR,
        ROOT / 'staging/native-player-settings-scope/package-static/passive-code-marker/passive-code-marker-bounded-functions.json',
        ROOT / 'staging/native-player-settings-scope/package-static/native-outer-VPM-completion-and-FAT-contract.json',
        ROOT / 'staging/native-player-cold-fp-controller/package-static/original-jill-file-export-binding.json',
        ROOT / 'evidence/firmware-analysis/main_02bd.bin', old_metadata, registry_path, selector_path, original_path,
        ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json',
        ROOT / 'scripts/analyze_native_sections.py', ROOT / 'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT / 'scripts/analyze_native_loader.py', ROOT / 'scripts/analyze_sdp_activation.py',
        ROOT / 'scripts/emulate_native_voice_registry.py', ROOT / 'scripts/emulate_native_voice_selection.py',
        ROOT / 'scripts/build_native_voice_extension.py', ROOT / 'native/sbc-prototype/voice_extension.c']
    hashes = {rel(p): sha(p) for p in source_paths}
    for path, expected in protected.items():
        need(sha(ROOT / path) == expected, 'After: protected file changed ' + path)
    need(sha(AUDIT) == AUDIT_SHA and sha(PRIOR) == PRIOR_SHA, 'Immutableinput hashes afteranalysis')
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        assertion_count=len(assertions), exact_instruction_assertions=assertions,
        source_sha256=hashes, static_only=True, guest_or_VM_executed_this_task=False,
        exact_target=dict(HWID=1352, software='Taiwan8.00', MAIN_sha256=EXPECTED),
        protected_registry=dict(path=rel(AUDIT), sha256=AUDIT_SHA, count=1274,
            checked_before_and_after=True, changed_or_missing=[]),
        bounded_functions=dict(path=rel(CFG), sha256=sha(CFG), count=len(functions),
            instruction_count=sum(len(f['instructions']) for f in functions.values()),
            local_CFG_complete=True, full_transitive_closure=False),
        prior_Aud_Ver_contract_preserved=dict(path=rel(PRIOR), sha256=PRIOR_SHA,
            earlier_AudVer_vs_checksum_correction_remains=True,
            new_direction='Actual appended instructions may change volatile cache, with originalDLLINFO unchanged. This was not proposed or executed by the prior metadata-only contract.'),
        pointer_provenance=dict(
            wrong_pointer_to_avoid='F09638 is the base of42byte voice descriptors, not an opaque cachedrecord.',
            registry='F09664 global; head handle atF09668. 273A84(index) follows originalopaque nextlinks record+774.',
            record_size=1912, next_opaque_handle_offset='0x774', private_770_semantics='Preserved privatefield; not established as a previouslink.',
            native_handle='Use original388804(handle), whose actual wrapper locks heap3A7F18C and derives alignedpayload fromnativeheader+4; never reinterpret fixtureD000xxxx handle asrealpointer.',
            pointer_release='388B22 is original BX LR; it does not release a native lifetime reference. Actual free3887A2 tail-routes388746 andclears handlecell.',
            mutex=dict(pointer='0x344CF00', initializer='255068 BL3008A0; continuation25506C',
                tag_store='255070 writes&vpm_voice_list_smphr literal255358 tosem+16',
                raw_lock='3009A0', raw_unlock='3008B0',
                original_lock_continuations=['273AC8', '273E5A', '274200', '274502', '2747DE', '27499E'],
                marker_requires_actual_native_task_and_original_mutex_body=True),
            native_identity='record+3FC comesfrom<voice_name>, not <vol_name>/partnumber;273E52 compares up to20 UTF16codeunits(case-sensitive3B0D06).',
            Big5_specialcase='274B4C..B90:mei-ling plusdll_file prefixChinese_Big5_MeiLing rewrites ID to mei-lingb literal274CC4; GB staysmei-ling, Jilljill.',
            frozen_fixture_identity_corroboration=identities),
        initialization_and_selection_order=dict(
            ordinary_native_selector='2404D6 operation1 loadsindex fromrequest+8 andslotbyte+6, calls240498 at2405F0.',
            actual_component_entry='3B3332 BLXr1; r0=loaderdescriptor0304BB74;r1=descriptor+24 imageentry02D4BB74; entryLR3B3335.',
            before_entry='240498→2741F4 copiedrequested recordID;2747CC lockslist,looks upID/path,binds/mountsselectedVPM,thenunlocks;23C3C4 opensreadsclosesDLLIMG andcallsentry.',
            return_success='23C3C4 first rawentryreturn6 maps11 at23C434..43A; raw11passes. Retry raw6 isnotmapped11. marker mustpreserve rawreturn, neverconvert failure/success.',
            conservative_marker_gate='Onlyrawbootstrapreturn11; permitfirst6 onlyaftera separateactual witness andexact descriptor[0]==50000 first-attempt proof. Default skip6/5/other.',
            selected_index='F095B0=*(F095AC+4) onlypublished2404CA after23C3C4returns11. Entrycannot useoldselectedindex. Failedselectorstores255 at2404D0.',
            record_rewrite_after_success_in_local_selector=False,
            local_selector_not_full_firmware_concurrency_or_lifetime_proof=True,
            prior_fixture_control='FrozenSelectionVM executesoriginal240498 andchecksregistrybefore==after, retainednodes andall40stubtargets unchanged. OuterFS/kernelheap/mountactivation/diagnosticcontrols remainfixtures.'),
        live_mapped_path_alternative=dict(
            source='Original loader1FB328 usesF09658 descriptor,regionbyte+8(F09660),thenFE648 toembeddeddrive; itdoesnotreadselectedindex.',
            per_slot='1D8514 usesF09638+42*slot+32+8. Onlyslot0 matchesdefaultF09658 usedbyloaderopen; do notinferallslotsusematchingDLLregion.',
            native_cached_path='FEA50 activation:FEAB2→2D30AE(region) returnsgenericfile;FEABE→31E3BE(file,&newpathnamehandle) succeeds0;thenoriginalcopyFEAEE writespathname toretainedCACHE_NAMES10425DC[drive]payload+6 andFEAFC storesfilepointer+0.',
            allocation_and_cleanup='31E3BE→1FDB8E locksfile+32 andallocatesnewopaque UTF16pathname. Extraentry query requiresactualheap/lowerlifetime control, andproper3887A2 handlecell release; allocationfailure isnotageneric safezero result.',
            pathname_equality_or_aliases_observed_here=False,
            earlier_pathcopy_unit_correction='273ABC r2=255 at273ADA means255 UTF16codeunits(max510bytes), not255bytes; existingpriorFATartifact retainedunchanged.',
            why_not_minimal='Native mapped/cachehandle lifecycle andpathcanonicalidentity duringentry addguards. Useonlyafter exactnativebinding/permissions/volumeactiveness arewitnessed. Regionbindret0 aloneisnotmountcompletion.'),
        proposed_minimal_execution_marker=dict(
            category='Volatile RAM overlay writtenbyappendedARM instructions; notanon-diskDLLINFO modification andnotanexportreturn.',
            example_visible_text='M7Q9', encoding='UTF16LE:fourprintableunitsplusNUL;exact10bytesatrecord+6B8..6C1',
            instructions='FivecompiledSTRH(actualCPUstores) atoffsets6B8,6BA,6BC,6BE,6C0; instructionlocationsarefuturedeclaredinput, notgeneratedhere.',
            preserving_entry='CallunchangedoriginalARMbootstrap, savetheexactrawreturn, registeronlyoriginal40exports; markerattemptafterbootstrapreturns; returntherawresultunchanged.',
            lookup='ForoneexplicitBig5component, useoriginalID mei-lingb heldinnewprivatecode; acquireoriginal344CF00; original273E52(ID)->index;273A84(index)->handle;388804(handle)->payload; noF095B0read.',
            admission=['Bootstraprawreturn11 andall40originalexporttargets/imports/descriptor/wholeoriginalmoduleRAM matchunchangedcontrol.',
                'Originallyinitialized344CF00/tag/currentTCB ownership; actual3009A0/3008B0, nohostfake return.',
                'Unique currentlylinkednativeopaque record; allocated1912bytesorcapacityatleast1912; stablehead/nextlinks while344CF00held.',
                'IDmei-lingb;typebyte+760==1;unchangedmetadata checksum+764==0CA73F5A;versionfieldcurrentlyoriginal2.10\0; expectedoriginalfilenamebasenameandoriginalparsedmetadataidentity.',
                'Nextindependentselector run mustwitnessrequestedindex matchesmarkerchosenindex andpostreturn2404CA publishesit; forphysicalproposal onlyordinarysupportedvoice-selection scope, notamanualentrycall.',
                'Noenumeration/rebuild/regionunbinding inmarkerinterval. Ifa guardcannotbeestablished, leavecacheunchanged andforwardoriginalstatus.'],
            writes_allowed='Cachepayload10bytesonly;privateappendedcodeBSS/stack andnativeheap/mutex writes separatelyboundedandjournaled. NohostRAMmarker seed.',
            rollback='Saveoriginal10bytesinprivateownedBSS; neverdereferenceoldrecordafterunlock/rebuild. Normalreboot/re-enumeration restoresoriginalDLLINFOversion. Anyexplicitrestore mustfreshlookup+identitycheck+heldlistmutex andonlyrestoreifcurrentfieldexactlymatchesownedmarker.',
            per_entry_repeat='IfmarkerfieldalreadyM7Q9, do notrecaptureit asoriginalversion orrewrite savedoriginalbytes. Dynamicsecondload/unload behavior mustbedeclared.',
            safe_physical_install_candidate_ready=False,
            payload_binary_or_modified_VPM_or_SIG_generated=False),
        native_visible_consumer=dict(
            route='OriginalAudioTest Aud Ver button→GUI::PageTestAudioList681720; sameaspriorsealedcontract.',
            not_only_selected_voice='Pagecounts273AF6 anditeratesallcachedindices; perrow6817CA copiespathname,6817D2 reads5versionunits. Existinglistopenbeforemarker keepsoldownedcopies; open/reopenthepageaftermarker.',
            getter='6817D2 BLX52C5EC ARMveneer→2744F6(r0=cacheindex,r1=stack+2BC),held344CF00→273A84→388804→3598B8(record+6B8,count5);LR6817D7.',
            GUI_copy='68184E constructsownedstringfromcopiedUTF16 buffer. NewmarkerdisplaydoesnotdependonDLLexportreturn.',
            expected_evidence='Aunique marker absentfromunchangedDLLINFO andcontrol appearsintheintendedvoicerowonlyafteractualmodifiedentryCPUstoresandactualnativegetter/UIconsumer. Listingoriginalmetadataorharnessprintedhostvalueisnotexecutionevidence.',
            actual_button_click_or_rendering_verified_this_task=False),
        expiration_and_rebuild=dict(
            clear='273BEA: under344CF00detachheadF09668=0 at273BFA;afterunlockwalkoldnext774 andoriginalfree3887A2 at273C1E. Retainedpointeracrossthisisunsafe.',
            rebuild='273C2A calls273BEA at273C48, thenoriginal1D897C enumerateat273C5C; nativeparser/registration createsfreshversioncache.',
            update_existing='1D874E calls274978, copying1912bytesandrestoringprivate770/774; thisoverwritesversion+6B8 evenifopaquehandleunchanged.',
            insert='274992 allocates1912bytes,copy274978,publisheshead/nextunder344CF00;originalcalloc/headercapacitynotfromhostmetadata.',
            no_lifetime_reference='388B22 noopdoesnotpinrecord;nativecachemutex pluscurrentlinkedidentity aretheonlyshownrecordlifetime protection.'),
        export_and_Speak_followup=dict(
            original40_storage_table='F092C4', original40_storage=[hex(v) for v in imports],
            trampolines='2D4B994,stride12;original2356BC installs40targetwords;cachemarkerentrydoesnotwrapreplaceanyexport.',
            genuine_UI_bound_callback='5C1558 Voice(TTS) Test ctor useslabel5C17F0,Speak5C1808anddirectmember9D689C=(5C179D,0) via612154 at5C15FE.',
            callback='5C179C enables240A10(1),queues40byteoperation5 requeststhrough254B2E(SP,1,0) withtypebyte+8 E,D,8;POSTevent2tooriginalaudioTCB.',
            unresolved_join='Queueconsumer→actualoriginal40exportcall/typecontract stillnotclosed. FrozenJillbindinghasMAIN21C512→storageF09560→slot15 andmodule1BDD0 fileopen; nojoinedSpeak typedcall/visiblepureexportresult yet.',
            next_original_dynamic_callsite='Observe21C512 loadedpointer/trampoline+8/currentvoice/exportregistration andcalleeoriginalslot15 togetherwithqueuedrequestorigin; neverinvokeguessedABIorallowaudiothistask.',
            visible_export_result_marker_ready=False,
            manual_slot39_query_is_not_UI_evidence=True),
        next_bounded_runnable_contract=dict(
            execute_in_future_new_namespace_only=True, executed_here=False,
            preferred='OneBig5 preservingentry-only RAM marker, noSBC/audio/newUI/worker; originalenumerationandselectorwithdeclaredouterFS/kernelheapfixtures, nevermetadata/markerhostseed.',
            positive_sequence=['Originalenumeration→originalparsed2.10 cache/controlandnative1912bytelinkedrecord.',
                'Actualoriginal240498→3B3332→unchangedoriginalbootstrap→newguardedCPUSTRH onlyafterrawsuccess.',
                '2404C6 observesnative11 and2404CA nativepublishesmarkerindex; opaqueID/handle/wholelinksandall40targetsremainexact.',
                'Original2744F6 readsM7Q9 throughnativecopy andoriginalGUIstringconstruction; separatelyactualphysicalrenderingstillrequired.'],
            controls=['Unchangedentrycontrolstill2.10.', 'Missing/mismatcheduniqueID/oldversion/nativefailure leavescacheunchangedandforwardsstatus.',
                'Repeatedentrydoesnotoverwriteoriginalsaved10bytes.', 'Original273BEA/re-enumerationrestores2.10 andoldpointerisneverused.'],
            whole_guard_requirements=['Whole1912bytecacheeachrecord,opaqueheader/heap,headandnextlinks,allTCB108ownedchains/currenttask/context/stack.',
                'ExactCPUstorejournalreplayofnew10bytesplusnativeheap/mutex writes; originalDLLINFO/SIG/backuphashesremainunchanged.',
                'WholeoriginalDLLimports/40targets/trampolines/descriptor/relocatedRAMmatchunchangedvoice; onlyheaderbranch/declaredappendprivatepagesdiffer.',
                'RawentryreturnandMAINLR/SPpreserved; pageownedstringlifetimeisindependentofcachepointer.'],
            independent_SIG_requester_or_physical_changed_package_acceptance_proof=False,
            physical_next_step_blocker='72byteDLLIMG.SIG requester/enforcement andactualhigherFATalias/outerpermissions/mountcompletion stillunknown. Staticcachemarkerdesign isnotauthorization/evidencethatachangedVPMwillload.'),
        limits=[
            'All_passed means exactstaticassertions/protectedhash checks. Itdoesnotmeanamarkerpayload,emulatorcontrol,physicalcodeacceptanceorvisibleGUIhasrun.',
            'Aud Ver isnotanoriginalDLLexport. Diskmetadata aloneisnotexecutionevidence; onlyactualappendedCPUstoreswithunchangedmetadataandnativeconsumercouldmakeitanevidencecarrier.',
            'FixedBig5-ID recipeisboundedtoexplicitnormalvoice-selection inputs. Dynamicidentity/sharedcacheconcurrency/actualrawbootstrapreturn/absenceofrebuild mustbewitnessedbeforediscussingphysicalcandidate.',
            'Existingfixturehandles/pathnames/mountactivation/kernelheapstatusareclearlyseparatefromoriginalhardwarebehavior. /Garmin/Voice isafrozenfixturealias; actualbackupmembersare/Voice.',
            'LocalCFGs/directcallscan donotcloseallindirectARM/conditionalcallers,filesystempolicy,signaturegate,all40semanticAPIs/navigationTTSorrealApp/audio.'],
        device_io=False, sound=False, backup_or_frozen_sources_modified=False,
        installation_candidate=False, actual_modified_code_or_marker_execution_verified=False,
        physical_package_acceptance_verified=False, native_App_or_direct_phone_audio_verified=False)
    save(REPORT, result)
    print(json.dumps(dict(path=rel(REPORT), sha256=sha(REPORT), all_passed=True,
        source=rel(Path(__file__)), source_sha256=sha(Path(__file__)),
        assertions=len(assertions), local_CFGs=len(functions), protected_files=1274,
        static_only=True), ensure_ascii=False))


if __name__ == '__main__':
    main()
