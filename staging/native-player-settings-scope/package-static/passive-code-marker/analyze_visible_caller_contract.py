#!/usr/bin/env python3
"""Exclusive read-only Aud Ver caller contract; no VM, device or candidate."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage
from analyze_sdp_activation import trace
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

AUDIT = ROOT / 'staging/native-player-settings-scope/previous-audit.json'
REPORT = OUT / 'passive-code-marker-visible-caller-contract.json'
CFG = OUT / 'passive-code-marker-bounded-functions.json'


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
    need(not REPORT.exists() and not CFG.exists(), 'Exclusive new outputs required')
    need(sha(AUDIT) == 'dd3f1c3ea6743f6801d9bbb3edff3e0556dbfc1332243c6ee149b86999664f39', 'Exact protected snapshot')
    protected = json.loads(AUDIT.read_text())['protected_sources']
    need(len(protected) == 1078, 'Expected1078 protected files')
    for path, expected in protected.items():
        need(sha(ROOT / path) == expected, 'Protected file changed ' + path)
    stock = NativeImage()
    image = RuntimeImage(stock)

    def word(address):
        return struct.unpack('<I', image.read(address, 4))[0]

    def wide(address, count=100):
        return image.read(address, count).decode('utf-16le').split('\0')[0]

    need(wide(0x673338) == 'Aud Ver', 'Original Aud Ver label')
    need(word(0x673234) == 0xc05d90, 'PageTestSound constructor vtable')
    rtti = word(0xc05d90 - 4)
    need(image.read(word(rtti + 4), 26).split(b'\0')[0] == b'N3GUI13PageTestSoundE', 'Exact PageTestSound RTTI')
    need(struct.unpack('<2I', image.read(0x9d4d50, 8)) == (0xe4, 1), 'Original virtual member descriptor')
    need(word(0xc05d90 + 0xe4) == 0x673d01, 'Original button member entry')
    need(word(0x681a38) == 0xc0d0a8, 'Original PageTestAudioList constructor vtable')
    need(wide(0x275240) == '</ver_nmbr>' and wide(0x275258) == '<ver_nmbr>', 'Native DLLINFO version tags')
    need(wide(0x111e48) == '.sum' and wide(0x672b90) == '0x%08X', 'Separate checksum branch literals')

    exact = {
        0x6731d6: 'adr r1, #0x160', 0x6731d8: 'blx #0x469e4c',
        0x673374: 'movs r7, #0xcd', 0x673376: 'lsls r7, r7, #5',
        0x673380: 'blx #0x5270d0', 0x6739cc: 'movs r0, #0xcd',
        0x6739de: 'bl #0x6867f0', 0x6739e6: 'bl #0x686fc4',
        0x6739f2: 'bl #0x376e5e', 0x673da0: 'cmp r1, r3',
        0x673da6: 'blx #0x3954cc', 0x673dae: 'bl #0x681720',
        0x673dbc: 'bl #0x36c00a', 0x681744: 'blx #0x52c5dc',
        0x6817ca: 'blx #0x52c5e4', 0x6817d2: 'blx #0x52c5ec',
        0x274504: 'bl #0x273a84', 0x27450e: 'bl #0x388804',
        0x274512: 'movs r1, #0xd7', 0x274514: 'lsls r1, r1, #3',
        0x274518: 'movs r2, #5', 0x27451c: 'bl #0x3598b8',
        0x68184e: 'bl #0x39274e', 0x3598c8: 'ldrh r3, [r1]',
        0x3598cc: 'strh r3, [r0]', 0x3598be: 'adds r1, r1, #2',
        0x274e94: 'bl #0x274a8a', 0x274ea2: 'movs r0, #0xd7',
        0x274ea6: 'lsls r0, r0, #3', 0x274eb0: 'bl #0x3598b8',
        0x274ec2: 'movs r2, #5', 0x274ec4: 'bl #0x3598b8',
        0x672a30: 'blx #0x5250f4', 0x111ab4: 'bl #0x111a46',
        0x111ac6: 'bl #0x2cabbc', 0x111a60: 'bl #0x31d09a',
        0x111a6e: 'bl #0x31cf22', 0x111a7a: 'bl #0x31ce8c',
    }
    assertions = []
    for pc, wanted in exact.items():
        op = next(image.md.disasm(image.read(pc, 4), pc, count=1))
        need(op.mnemonic + ' ' + op.op_str == wanted, 'Exact instruction differs ' + hex(pc))
        assertions.append(dict(PC=hex(pc), bytes=op.bytes.hex(), instruction=wanted,
            load_address=hex(stock.runtime_to_load(pc, op.size))))
    functions = {}
    for entry in [0x672ecc, 0x673d00, 0x681720, 0x273af6, 0x273abc,
                  0x2744f6, 0x273a84, 0x3598b8, 0x6867f0, 0x686fc4,
                  0x672670, 0x111a90, 0x111a46, 0x111632, 0x11157c, 0x1115fc]:
        f = trace(image, entry, 3500)
        need(not f['instruction_limit_reached'] and not f['unresolved_exits'], 'Unclosed local CFG ' + hex(entry))
        for row in f['instructions']:
            pc = int(row['address'], 16)
            op = next(image.md.disasm(image.read(pc, 4), pc, count=1))
            row.update(bytes=op.bytes.hex(), load_address=hex(stock.runtime_to_load(pc, op.size)))
        f['not_transitive_UI_or_DLL_policy_closure'] = True
        functions[hex(entry)] = f
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for entry, expected_target in [(0x52c5dc, 0x273af7), (0x52c5e4, 0x273abd),
                                    (0x52c5ec, 0x2744f7), (0x5250f4, 0x111a91)]:
        need(word(entry) == 0xe51ff004 and word(entry + 4) == expected_target, 'Exact original ARM veneer')
        op = next(arm.disasm(image.read(entry, 4), entry))
        functions[hex(entry)] = dict(mode='ARM', explicit_instruction_bytes=4,
            original_literal_target=hex(expected_target), instructions=[dict(address=hex(entry),
                bytes=op.bytes.hex(), instruction=op.mnemonic + ' ' + op.op_str)],
            not_transitive_UI_or_DLL_policy_closure=True)
    metadata = ROOT / 'evidence/firmware-analysis/native-voice-metadata-emulation.json'
    old = json.loads(metadata.read_text())
    version_rows = [r for r in old['static_functions']['0x274acc']['instructions']
                    if 0x274e88 <= int(r['address'], 16) <= 0x274ec8]
    need(version_rows and all(next(image.md.disasm(image.read(int(r['address'],16),4),int(r['address'],16),count=1)).mnemonic + ' ' +
        next(image.md.disasm(image.read(int(r['address'],16),4),int(r['address'],16),count=1)).op_str == r['instruction'] for r in version_rows), 'Frozen metadata version writer differs')
    save(CFG, dict(MAIN_sha256=EXPECTED, functions=functions,
        DLLINFO_version_writer_reused_from=rel(metadata), exact_version_writer=version_rows,
        full_transitive_signature_or_UI_policy_closed=False))

    original_exports = ROOT / 'evidence/firmware-analysis/original-tts-module-emulation.json'
    extension = ROOT / 'evidence/firmware-analysis/native-voice-extension-emulation.json'
    containers = ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json'
    original = json.loads(original_exports.read_text())
    need(len(original['cases']) == 3 and all(len(c['trampolines_verified']) == 40 for c in original['cases']), 'Frozen original40 binding controls')
    source_paths = [Path(__file__), AUDIT, CFG, metadata, original_exports, extension, containers,
        ROOT / 'scripts/analyze_native_sections.py', ROOT / 'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT / 'scripts/analyze_sdp_activation.py', ROOT / 'scripts/emulate_native_voice_metadata.py',
        ROOT / 'scripts/emulate_native_voice_extension.py', ROOT / 'evidence/firmware-analysis/main_02bd.bin',
        ROOT / 'staging/native-player-settings-scope/package-static/native-outer-VPM-completion-and-FAT-contract.json']
    hashes = {rel(p): sha(p) for p in source_paths}
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        exact_target=dict(HWID=1352, software='Taiwan8.00', MAIN_sha256=EXPECTED),
        source_sha256=hashes, static_only=True,
        protected_registry=dict(snapshot=rel(AUDIT), count=1078, sha256=sha(AUDIT),
            checked_before_and_after=True, changed_or_missing=[]),
        assertion_count=len(assertions), exact_instruction_assertions=assertions,
        bounded_functions=dict(path=rel(CFG), sha256=sha(CFG), count=len(functions),
            instruction_count=sum(len(f['instructions']) for f in functions.values()), local_CFG_complete=True,
            transitive_callgraph_or_policy_closed=False),
        Aud_Ver_button=dict(label_runtime='673338', label_encoding='UTF16LE', label_text='Aud Ver',
            original_page='GUI::PageTestSound', ctor='672ECC', vtable='C05D90',
            button_object='page+0x19A0; original673374..380 builds it',
            bound_member_descriptor='9D4D50 words(0xE4,1); original ctor6739CC..F2 binds the same member as other buttons',
            actual_static_virtual_entry='C05D90+0xE4 contains673D01; Thumb673D00 takesr0=Page,r1=Button',
            exact_branch='673D9A..A2 comparesr1 toPage+0x19A0; matching path allocates0x7AC at673DA6, original681720 ctor at673DAE, publishes child via36C00A at673DBC(r2=10)',
            child_page='GUI::PageTestAudioList; vtableC0D0A8', runtime_button_click_observed_here=False),
        visible_version_data=dict(list_ctor='681720',
            count_call='681744 BLX52C5DC->273AF6 counts original cached opaque-record chain',
            pathname_call='6817CA BLX52C5E4->273ABC copies selected cached record pathname',
            version_call='6817D2 BLX52C5EC->2744F6; normalizedreturn6817D6, ThumbgetterentryLR6817D7',
            ABI='r0=zero-based cache index;r1=calleroutput; 2744F6 uses273A84 indexlookup then388804 exposes opaque record',
            exact_source='cached record+0x6B8, derivedby0xD7<<3 at274512..16',
            transfer='274518..1C copies5 UTF16 codeunits with original3598B8, maximum10bytes; this is a copy-return ABI, not a DLL string pointer.',
            encoding='UTF16LE, 5-unit outputfield includes terminator; native parser overwrites fifthunit atrecord+0x6C0 withNUL forlength>=5, leavingat most4 visibleunits.',
            original_producer='274ACC DLLINFO parser274E88..C8 searches original<ver_nmbr>/</ver_nmbr>, copiesstring torecord+0x6B8 andterminatesrecord+0x6C0 forlength>=5.',
            GUI_lifetime='68184E constructs own C++GUI string fromstack+0x2BC output; list owns copied strings; native ctor destroys temporarystring/vector objects before returning. FullGUIallocation/lifetime runtime is unverified here.',
            depends_on_DLL_export_callback=False, proves_changed_DLL_instructions_executed=False),
        separate_checksum_refresh=dict(entry='672670', belongs_to_Aud_Ver_button=False,
            call='672A30 BLX5250F4->111A90(r0=10,r1=&stackword)',
            type4_branch='111AB4->111A46 buildsassetpath with111632 andoriginal.sum suffix111E48; native31D09A open,31CF22 reads4bytes,31CE8C closes.',
            other_type_branch='111AC6 settings2CABBC(ID0x108) retrieves word whenstatus>=0',
            formatting='672A9C original392938 usesUTF16 0x%08X literal672B90',
            not_a_verified_DLL_export_marker=True, not_Aud_Ver_data_provenance=True),
        draft_correction_log=[dict(stage='Before any artifact was sealed',
            preliminary_claim='Sibling checksum refresh was initially described as the Aud Ver source.',
            correction='Aud Ver is a bound button opening681720 PageTestAudioList; its exact versiongetter is2744F6 from cached DLLINFO text.',
            discarded_checksum_association=True, preliminary_UI_to_getter_join_was_not_proven=True)],
        known_original40_controls=dict(source=rel(original_exports),
            original_export_counts=[len(c['trampolines_verified']) for c in original['cases']],
            subset_query='Frozen extension evidence manually callsoriginalslot39 via originalARMtrampoline: query(0,out,1)returns1/storesword0; selector1returns0/leavesoutunchanged.',
            actual_visible_UI_caller_for_slot39_recovered=False,
            manually_invoked_callback_is_not_a_physical_visible_execution_probe=True,
            original40_forwarding_and_navigation_or_speech_functionality_all_verified=False),
        minimal_next_contract=dict(ready_for_changed_package_generation=False,
            eligible_existing_visible_callback=None,
            missing=['An original visible caller loadingone ofF092C4 original40 export-pointer storages mustbe joined toits exact ordinal andactuallyobserved/correcttyped ABI.',
                'That callback musthave an output/result consumer makinga unique appended-code marker visible, with exact encoding,length,lifetime andno effecton navigation/TTS contract.',
                'A future preserving wrapper mustforward allother40 originalinterfaces, retainnative imports/relocation/RAM andmodulelifetime, andneverhost-seed the marker or alterDLLINFO/.sum tosimulate execution.',
                'Original higherFAT alias/acceptance and72-byteDLLIMG.SIG requester/enforcement remainunknown; this contract providesno reason to installa changedVPM.'],
            no_fullApp_or_audio_UI_integration_needed_to_close_the_first_visible_callback_gap=True),
        limits=dict(Aud_Ver_is_not_DLL_export_callback=True, Aud_Ver_is_cached_DLLINFO_version_data=True,
            checksum_refresh_is_a_separate_branch=True, global_absence_of_visible_DLL_callback_proven=False,
            static_CFG_is_not_native_runtime_proof=True, original_metadata_controls_reused_not_rerun=True,
            native_SIG_or_physical_changed_code_acceptance_verified=False,
            original_all40_navigation_TTS_forwarding_functionality_verified=False,
            guest_or_emulator_executed=False, candidate_or_modified_DLL_VPM_SIG_generated=False,
            device_or_service_IO=False, canonical_or_frozen_sources_modified=False))
    for path, expected in protected.items():
        need(sha(ROOT / path) == expected, 'Protected file changed after analysis ' + path)
    save(REPORT, result)
    print(json.dumps(dict(report=rel(REPORT), sha256=sha(REPORT), source_sha256=sha(Path(__file__)),
        all_passed=True, assertions=len(assertions), bounded_functions=len(functions),
        visible_code_marker_ready=False, guest_execution=False)))


if __name__ == '__main__':
    main()
