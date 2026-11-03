#!/usr/bin/env python3
"""Exact original Voice/DLL loader and linked crypto-boundary static analysis.

Only immutable MAIN/backup/snapshot bytes are read. No Unicorn import, guest
execution, candidate package, signature generation, device I/O or publication.
The bounded CFGs are deliberately not transitive/indirect policy closure.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import json
import re
import struct
from datetime import datetime, timezone

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage, scan_calls, wide
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

REPORT = OUT / 'native-voice-code-acceptance-boundary.json'
FUNCTIONS = OUT / 'bounded-acceptance-functions.json'
PRIOR = ROOT / 'staging/native-player-decoder-scope/previous-audit.json'
ENTRIES = (0x273f64, 0x1d8514, 0xfea50, 0x2d3166, 0x2d3380,
           0x2747cc, 0x240498, 0x23c3c4, 0x3b3294, 0x3b331a,
           0x38a398, 0x221d2c, 0x3ee9c4, 0x3fc938, 0x3fc7b6,
           0x41797c, 0x417aa6, 0x4c38c0, 0x4c4c54, 0x4c75e8,
           0x4c7418, 0x4c7462, 0x4b0e14, 0x4b10e2)
SCAN_TARGETS = {0x273f64, 0x15c3e0, 0x41611c, 0x41797c,
                0x417aa6, 0x3fc938, 0x3ee9c4, 0x4c38c0,
                0x4c4c54, 0x4c75e8}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def need(ok, message):
    if not ok:
        raise ValueError(message)


def save_new(path, data):
    with path.open('x') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def literal_hits(raw, payload):
    return [hex(0x50000 + m.start())
            for m in re.finditer(re.escape(payload), raw)]


def function_rows(stock, image):
    result = {}
    for entry in ENTRIES:
        fn = trace(image, entry, 3500)
        need(not fn['instruction_limit_reached'], 'Bounded CFG exhausted ' + hex(entry))
        need(not fn['unresolved_exits'], 'CFG branch unresolved ' + hex(entry))
        for row in fn['instructions']:
            address = int(row['address'], 16)
            ins = next(image.md.disasm(image.read(address, 4), address, count=1))
            row['bytes'] = ins.bytes.hex()
            row['load_address'] = hex(stock.runtime_to_load(address, ins.size))
        fn['direct_call_targets'] = sorted({r['direct_call'] for r in fn['instructions']
                                            if 'direct_call' in r})
        fn['entry_runtime'] = hex(entry)
        fn['instruction_bytes_sha256'] = sha(b''.join(
            bytes.fromhex(r['bytes']) for r in fn['instructions']))
        fn['bounded_CFG_not_transitive_call_closure'] = True
        result[hex(entry)] = fn
    # Actual ARM leaf and branch veneer close the former cache-sync fixture's
    # instruction identity. This is static only; no cache/CP15 effects asserted.
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for entry, size in [(0x33e674, 4), (0x6f0360, 52), (0x278964, 188)]:
        rows = [{'address': hex(x.address), 'bytes': x.bytes.hex(),
                 'instruction': x.mnemonic + ' ' + x.op_str,
                 'load_address': hex(stock.runtime_to_load(x.address, x.size))}
                for x in arm.disasm(image.read(entry, size), entry)]
        need(sum(len(bytes.fromhex(r['bytes'])) for r in rows) == size,
             'ARM explicit span did not decode completely')
        result[hex(entry)] = dict(entry_runtime=hex(entry), mode='ARM',
            explicit_span_bytes=size, instructions=rows,
            bounded_CFG_not_transitive_call_closure=True,
            instruction_bytes_sha256=sha(image.read(entry, size)))
    return result


def main():
    need(not REPORT.exists() and not FUNCTIONS.exists(), 'New outputs must be exclusive')
    audit = json.loads(PRIOR.read_text())
    protected = audit['protected_sources']
    need(len(protected) == 892, 'Expected frozen892 source snapshot')
    for path, digest in protected.items():
        need(sha((ROOT/path).read_bytes()) == digest, 'Frozen source changed: ' + path)
    stock = NativeImage()
    image = RuntimeImage(stock)
    funcs = function_rows(stock, image)
    expected = {
        0x273f7e: 'movs r1, #0x1d', 0x273f80: 'lsls r1, r1, #6',
        0x273f84: 'ldr r4, [r0, #0x24]', 0x273f94: 'bl #0x3008b0',
        0x38a398: 'movs r0, #0xb', 0x38a39a: 'bx lr',
        0x3b32e0: 'blx r7', 0x3b32e2: 'ldr r0, [r5, #0x18]',
        0x3b32ee: 'bl #0x38a398', 0x3b3304: 'cmp r0, r1',
        0x3b3322: 'blx #0x278964', 0x3b3326: 'cmp r0, #0',
        0x3b3328: 'bne #0x3b332e', 0x3b3332: 'blx r1',
        0x221d2e: 'blx #0x33e674',
        0x3eea3a: 'bl #0x31cf22', 0x3eea66: 'bl #0x3fc938',
        0x3eea86: 'bl #0x3fc7b6', 0x3fc95a: 'bl #0x41797c',
        0x3fc9bc: 'bl #0x417a0c', 0x3fc862: 'strb r6, [r3, #4]',
        0x3fc868: 'strb r0, [r3, #5]', 0x3fc870: 'blx #0x3794f0',
        0x3fc880: 'blx #0x3732c8', 0x3fc88c: 'blx #0x3732c8',
        0x4c7438: 'adr r0, #0x27c', 0x4c743a: 'bl #0x45dd40',
        0x4c7616: 'bl #0x4c4c54', 0x4c7620: 'str r2, [r4]',
        0x670552: 'adr r1, #0x2a0', 0x670556: 'blx #0x469e4c',
    }
    assertions = []
    for address, wanted in expected.items():
        ins = next(image.md.disasm(image.read(address, 4), address, count=1))
        need(ins.mnemonic + ' ' + ins.op_str == wanted,
             f'Original instruction changed at {address:#x}')
        assertions.append(dict(address=hex(address), bytes=ins.bytes.hex(), instruction=wanted))
    literals = {
        'BIN_filename': (0x23c4e8, b'dllimg.bin\0'),
        'loader_invalid_sentinel': (0x3b3358, b'Invalid\0'),
        'GMA_header': (0x4c76b8, b'GARMIN GMA\0'),
        'SHA1_DigestInfo_DER': (0x3fc920, bytes.fromhex('3021300906052b0e03021a05000414')),
    }
    for name, (address, payload) in literals.items():
        need(image.read(address, len(payload)) == payload, 'Exact literal changed: ' + name)
    need(wide(image, 0x3eeaa8) == '/.System/GUPDATE.GCD', 'GCD path differs')
    need(wide(image, 0x3eeae0) == '/Garmin/GUPDATE.GCD', 'GCD path differs')
    need(wide(image, 0x3eead4) == '%d:%s', 'GCD formatter differs')
    need(wide(image, 0x6707f4) == 'Voice Checksum', 'Diagnostic label differs')
    init = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    for address in [0x15c6b0, 0x4161e8, 0x417ad0, 0x4c3cc4]:
        need(image.read(address, 20) == struct.pack('<5I', *init), 'SHA1 IV table differs')
    scan = scan_calls(stock, SCAN_TARGETS)
    getter_calls = [r for r in scan['candidates'] if int(r['target'], 16) == 0x273f64]
    pointer_hits = {hex(a): literal_hits(stock.data, struct.pack('<I', a))
                    for a in [0x273f64, 0x273f65]}
    need(not getter_calls and not any(pointer_hits.values()), 'Getter caller inventory changed')
    literal_scan = {name: {'ASCII': literal_hits(stock.data, name.encode()),
                          'UTF16LE': literal_hits(stock.data, name.encode('utf-16le'))}
                    for name in ['DLLIMG.SIG', 'dllimg.sig', '.sig', '.SIG', 'dllimg.bin']}
    originals = []
    deps = [Path(__file__), PRIOR, ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'scripts/analyze_native_sections.py', ROOT/'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT/'scripts/analyze_sdp_activation.py', ROOT/'scripts/analyze_tts_vpm.py',
        ROOT/'scripts/emulate_native_voice_registry.py', ROOT/'scripts/emulate_native_voice_metadata.py',
        ROOT/'scripts/emulate_native_vpm_filesystem.py', ROOT/'scripts/emulate_native_voice_selection.py',
        ROOT/'staging/native-player-dispatcher-fp/package-static/native-outer-voice-load-and-sig-request-contract.json',
        ROOT/'staging/native-player-cold-fp-controller/package-static/native-sig-request-contract-v2.json',
        ROOT/'staging/native-player-cache-declared-followup/package-static/vpm-sig-format-and-gate-preflight.json',
        ROOT/'staging/native-player-settings-vfp-context/acceptance-static/acceptance-policy-provenance.json']
    for name in ['Chinese_Big5_MeiLing', 'Chinese_GB_MeiLing', 'English_American_Jill']:
        path = ROOT/'backups/20261002T154458Z/files/Voice'/(name+'.vpm')
        package = path.read_bytes(); files, geometry = parse_image(package)
        info = files['DLLINFO.TXT']['content']
        value = re.search(rb'<dll_chksum>([^<]*)</dll_chksum>', info).group(1)
        originals.append(dict(path=rel(path), outer_bytes=len(package), outer_sha256=sha(package),
            member_identity={n:dict(bytes=len(files[n]['content']), sha256=sha(files[n]['content']))
                             for n in ['DLLIMG.BIN', 'DLLIMG.SIG', 'DLLINFO.TXT', 'IMGEND.TST']},
            declared_metadata_dll_chksum=int(value, 0),
            host_DLL_byte_sum=sum(files['DLLIMG.BIN']['content']) & 0xffffffff,
            native_checksum_comparison_or_signature_verification_executed_here=False))
        deps.append(path)
    cfg_data = dict(MAIN_sha256=EXPECTED, functions=funcs,
        limitations='Exact bounded functions/ARM spans only; direct callees, BX/BLX register targets and hardware policy are not a completed transitive call graph.')
    save_new(FUNCTIONS, cfg_data)
    deps.append(FUNCTIONS)
    source_hashes = {rel(p):sha(p.read_bytes()) for p in deps}
    report = dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        exact_target=dict(HWID=1352, SW='8.00 Taiwan', MAIN_sha256=EXPECTED),
        static_only=True, all_exact_assertions_passed=True,
        source_sha256=source_hashes,
        protected_registry=dict(snapshot=rel(PRIOR), snapshot_sha256=sha(PRIOR.read_bytes()),
            count=892, all892_source_hashes_revalidated=True, modified_protected_files=0),
        bounded_functions=dict(path=rel(FUNCTIONS), sha256=sha(FUNCTIONS.read_bytes()),
            count=len(funcs), instruction_rows=sum(len(f['instructions']) for f in funcs.values()),
            not_transitive_call_or_crypto_policy_closure=True),
        exact_instruction_assertions=assertions,
        original_TTS_identity=originals, literal_scan=literal_scan,
        direct_call_encoding_inventory=scan,
        metadata_checksum_boundary=dict(entry='0x273f64', registry_lookup='0x273a84',
            pointer_query='0x388804', value_field='registry record +0x764',
            read_PC='0x273f84', invalid_registry_value='0xffffffff',
            initialized_at='0x2755ca', parsed_tag_store_call='0x27544a->0x2734e6',
            direct_call_candidates=getter_calls, exact_pointer_literal_candidates=pointer_hits,
            statement='This original getter reads the DLLINFO numeric field. It does not read DLLIMG bytes, compute SHA1, request SIG or compare expected/actual digest. Its lack of scanned direct callers/pointers is bounded evidence, not global unreachability.'),
        voice_checksum_diagnostic=dict(label_address='0x6707f4', label='Voice Checksum',
            original_ADR='0x670552', native_text_constructor='0x670556->ARM0x469e4c',
            scope='Exact original GUI label construction only. No assertion about all diagnostic producers/worker branches, actual digest semantics or Voice40 selection enforcement.'),
        exact_loader_policy_boundary=dict(
            selected_outer_chain='240498 ->2741F4/2747CC ->1D8514 ->2D3166/FEA50 ->23C3C4 ->3B3294 ->3B331A ->3B3332 BLX',
            original_callbacks={'close':'0x1fb2f9','open':'0x1fb305','read':'0x1fb3a3','seek':'0x1fb3cf','tell':'0x1fb3e5'},
            filename='dllimg.bin', BIN_open_PC='0x3b32a2', BIN_read_PC='0x3b32e0',
            actual_file_read_count_checked=False, overwritten_read_result_PC='0x3b32e2',
            native_validator=dict(entry='0x38a398', bytes=image.read(0x38a398,4).hex(),
                exact_body=['movs r0, #0xb', 'bx lr'], ignores_all_arguments=True,
                native_caller='0x3b32ee', body_is_original_not_host_ret11_fixture=True),
            actual_checks=['3B32C0/C2: file length <= descriptor+28 reservation.',
                '3B3300..06: loaded header+4 RAM requirement <= descriptor+28.',
                '3B3322 ->ARM278964 compares descriptor filename against ASCII Invalid; equal rejects with2, unequal proceeds to original module image entry.'],
            strcmp_ARM_span='0x278964..0x278a20', strcmp_is_digest_check=False,
            cache_sync=dict(chain='3B32D2 ->221D2C ->ARM33E674 B6F0360',
                exact_leaf_bytes=52, leaf_starts='0x6f0360', leaf_return='0x6f0390',
                operations='Save CPSR, mask IRQ, drain write buffer, read translation-table register, synchronize pipeline, invalidate instruction cache/I-TLB, restore CPSR, BX LR.',
                native_file_hash_or_signature_operation_in_this_leaf=False,
                actual_CP15_or_physical_cache_effect_verified=False),
            SIG_requester_identified=False, higher_physical_storage_signature_policy_closed=False),
        original_crypto_candidates_distinguished=dict(
            SHA1_initial_vectors=dict(literal_tables=[hex(a) for a in [0x15c6b0,0x4161e8,0x417ad0,0x4c3cc4]], values=[hex(a) for a in init],
                existence_of_firmware_crypto_is_not_VPM_enforcement=True),
            GUPDATE_GCD=dict(entry='0x3ee9c4', exact_direct_caller='0x3ee790',
                path_literals={'0x3eeaa8':'/.System/GUPDATE.GCD','0x3eeae0':'/Garmin/GUPDATE.GCD','0x3eead4':'%d:%s'},
                signature_read='3EEA3A ->31CF22 reads256 bytes after seek(file_size-256).',
                file_SHA1=dict(entry='0x3fc938', only_scanned_direct_caller='0x3eea66',
                    ABI='r0=UTF16 filepath; r1=20-byte digest destination; r2=start offset; r3=signed bytes to hash.',
                    initializer='0x3fc95a->0x41797c', finalizer='0x3fc9bc->0x417a0c',
                    read_chunk_bytes=102400, complete_IO_status_or_digest_runtime_verified=False),
                verification='3EEA86->3FC7B6, fifth argument0 uses supplied20-byte hash; original encoded block begins00 01, FF padding,00,15-byte SHA1 DigestInfo DER,20-byte hash before big-integer compare.',
                DigestInfo_address='0x3fc920', DigestInfo_hex=literals['SHA1_DigestInfo_DER'][1].hex(),
                format_is_72byte_OpenPGP_DSA_DLLIMG_SIG=False,
                native_runtime_or_complete_RSA_trust_proof=False),
            GMA=dict(header_validator='0x4c7418', header_ADR_PC='0x4c7438',
                header_address='0x4c76b8', header='GARMIN GMA', wrapper='0x4c7462',
                typed_crypto_consumers=['0x4b0e14','0x4b10e2'],
                digest_dispatch='0x4c75e8', SHA1_branch='0x4c7616->0x4c4c54',
                declared_output_bytes=20, SHA1_initializer='0x4c4c60->0x4c38c0',
                direct_dispatch_callers=['0x4b1052','0x4b1064','0x4b12ee','0x4b1300'],
                same_header_or_packet_format_as_DLLIMG_SIG=False,
                voice_filename_or_SIG_file_handle_joined=False)),
        remaining_original_boundary_contract=[
            dict(entry='0x2d3166', containing_caller='0x1d8528', ABI='r0=0,r1=mapped-region99,r2=original UTF16 outer VPM path',
                original_actions='Original open31D09A,32-bit handle publication in mapped slot stride36 at+28, original opaque allocation/query/name copy, region byte pair and24-byte semaphore init.',
                next_guard='Do not retain RegistryVM host ret0. Capture native open status, actual handle, name identity, region byte pair, slot+28/+32 and read fileops. Trace all actual file callbacks.'),
            dict(entry='0xfea50', containing_caller='0x1d8542', ABI='r0=original drive7 from FE648,r1=1',
                original_actions='Calls1E86CE then actual mapped handle31E3BE/388804 and copies6 metadata bytes; updates retained outer handle through exact original stores/release.',
                next_guard='Do not tail-route directly to1E86CE. Capture full before/after outer slot/descriptor and actual caller returns;1D8514 only returns binding success, not parser/authentication status.'),
            dict(entry='0x2d3380', ABI='r0=region99,r1=outer file offset,r2=byte count,r3=destination',
                original_actions='Mapped bytepair ->slot36+28; original tell31D2E0, seek31D1CE, read31CF22; native attribute/bounds paths may pad outside-file ranges withFF.',
                next_guard='Replace exact backup lower byte-read fixture with native wrapper/actual fileops plus explicit immutable backup block input. Preserve raw read status/count/cursor/completed destination bytes; cannot use fread capped count as completeimage proof.'),
            dict(entry='0x3b3332', ABI='BLX descriptor+24 image entry,r0=descriptor',
                next_guard='Before BLX compare complete native loaded file bytes to independent BIN extraction, record native filename/handle/read/status/callers and actual changed-code entry execution. Keep original40 API/export relocation and resident lifetime guards.')],
        next_experiment=dict(kind='separate source offline original outer binding/activation/read contract',
            micro_harness_written=False, native_or_emulator_run=False,
            reason='Newly identified digest functions belong to GUPDATE.GCD/GMA; executing those would not test VPM acceptance. Full original outer VPM fileops/binding/storage callback closure remains the useful next scope.',
            physical_modified_code_experiment_supported=False,
            device_install_candidate=False,
            exact_blocker='No original native DLLIMG.SIG filename/key requester joined to handle/read/consumer/result; actual outer VPM native storage policy/lifetime is still replaced at2D3166/FEA50/2D3380 in previous tests. No safe changed-code physical observation and recovery contract is established.'),
        policy_and_scope_claims=dict(native_SIG_requester_identified=False,
            full_VPM_signature_policy_proven_absent=False,
            complete_higher_Voice40_gate_executed=False,
            modified_code_accepted_on_device=False, App_installation_candidate=False,
            candidate_or_signature_generated=False, emulator_or_guest_execution=False,
            device_or_service_IO=False, protected_or_canonical_files_changed=False,
            renamed_VPM_or_metadata_listing_is_code_acceptance=False))
    save_new(REPORT, report)
    print(json.dumps(dict(artifact=rel(REPORT), sha256=sha(REPORT.read_bytes()),
        bounded_functions=rel(FUNCTIONS), bounded_function_count=len(funcs),
        all_exact_assertions_passed=True, native_SIG_requester_identified=False,
        physical_modified_code_experiment_supported=False)))


if __name__ == '__main__':
    main()
