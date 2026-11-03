#!/usr/bin/env python3
"""Exclusive static signature-format/reader-boundary/acceptance preparation.

Only original backed-up bytes, bounded exact MAIN disassembly and host SHA1
are evaluated. No emulator import, native execution, device I/O, modified
package, signature/key generation, policy bypass or canonical update.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import struct

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage, scan_calls
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image
from parse_vpm_detached_signature import (parse_v4_dsa_sha1_signature,
                                         candidate_document_association,
                                         SignatureFormatError)

REPORT = OUT/'vpm-sig-format-and-gate-preflight.json'
FUNCTIONS = OUT/'bounded-sig-reader-functions.json'
PRIOR = 'staging/native-player-cache-declared-followup/previous-audit.json'
ISSUER = bytes.fromhex('c7b0e78013851910')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def write_exclusive(path, data):
    with path.open('x') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def check_registry(registry):
    for path, digest in registry.items():
        check(sha((ROOT/path).read_bytes()) == digest, 'Frozen dependency changed '+path)


def parser_controls(signature, parsed):
    # Meaningful trust-boundary controls: complete bounded consumption,
    # subpacket/MPI bounds, canonical bit counts, and wrong document binding.
    mutations = []
    def altered(offset, payload):
        value = bytearray(signature)
        value[offset:offset+len(payload)] = payload
        return bytes(value)
    mutations.extend([
        ('missing_header_bit', altered(0, bytes([signature[0] & 127]))),
        ('different_packet_tag', altered(0, b'\x8c')),
        ('body_length_short', altered(1, bytes([signature[1]-1]))),
        ('trailing_bytes', signature+b'\x00'),
        ('truncated_last_MPI', signature[:-1]),
        ('wrong_signature_version', altered(parsed['version']['offset'], b'\x03')),
        ('different_signature_type', altered(parsed['signature_type']['offset'], b'\x01')),
        ('different_public_algorithm', altered(parsed['public_key_algorithm']['offset'], b'\x01')),
        ('different_hash_algorithm', altered(parsed['hash_algorithm']['offset'], b'\x08')),
        ('hashed_area_exceeds_packet', altered(parsed['hashed_subpacket_length']['offset'], b'\xff\xff')),
        ('empty_subpacket_body', altered(parsed['hashed_subpackets'][0]['offset'], b'\x00')),
        ('unhashed_area_exceeds_packet', altered(parsed['unhashed_subpacket_length']['offset'], b'\xff\xff')),
        ('MPI_zero_bit_length', altered(parsed['signature_MPIs'][0]['bit_count_offset'], b'\x00\x00')),
        ('MPI_noncanonical_bit_count', altered(parsed['signature_MPIs'][0]['bit_count_offset'],
            (parsed['signature_MPIs'][0]['bits']-1).to_bytes(2, 'big'))),
    ])
    controls = []
    for name, payload in mutations:
        try:
            parse_v4_dsa_sha1_signature(payload)
        except SignatureFormatError as error:
            controls.append(dict(name=name, passed=True, rejected_as=str(error),
                                 synthetic_bytes_only=True, saved_as_SIG_or_package=False))
        else:
            raise ValueError('Malformed parser control accepted: '+name)
    # Alternate complete packet headers exercise actual format boundaries,
    # while the original body and DSA values stay intact.
    body = signature[parsed['packet_header_bytes']:]
    for name, header in [('old_two_octet_length', b'\x89'+len(body).to_bytes(2, 'big')),
                         ('new_one_octet_length', b'\xc2'+bytes([len(body)]))]:
        row = parse_v4_dsa_sha1_signature(header+body)
        check(row['fully_consumed'] and row['signature_MPIs'][0]['integer_hex'] ==
              parsed['signature_MPIs'][0]['integer_hex'], 'Alternate header parser differs')
        controls.append(dict(name=name, passed=True, synthetic_bytes_only=True,
                             saved_as_SIG_or_package=False))
    return controls


def canonical_DSA_key_body_candidates(raw):
    rows = []
    # Only canonical v4 raw public-key bodies with p/q/g/y MPIs. This is not
    # a whole firmware key search and does not cover transformed parameters.
    for match in re.finditer(b'\x04', raw):
        offset = match.start()
        if offset+8 >= len(raw) or raw[offset+5] != 17:
            continue
        cursor = offset+6
        bits_rows = []
        try:
            for index in range(4):
                bits = int.from_bytes(raw[cursor:cursor+2], 'big')
                count = (bits+7)//8
                if not 0 < bits <= 4096:
                    raise ValueError()
                if index == 0 and bits not in [512, 768, 1024, 2048, 3072, 4096]:
                    raise ValueError()
                if index == 1 and bits not in [160, 224, 256]:
                    raise ValueError()
                integer = raw[cursor+2:cursor+2+count]
                if len(integer) != count or int.from_bytes(integer, 'big').bit_length() != bits:
                    raise ValueError()
                bits_rows.append(bits)
                cursor += 2+count
            body = raw[offset:cursor]
            fingerprint = hashlib.sha1(b'\x99'+len(body).to_bytes(2, 'big')+body).digest()
            rows.append(dict(file_offset=offset, body_bytes=len(body), MPI_bits=bits_rows,
                             candidate_fingerprint_SHA1=fingerprint.hex(),
                             candidate_key_ID=fingerprint[-8:].hex(),
                             matches_unhashed_signature_issuer=fingerprint[-8:] == ISSUER))
        except ValueError:
            continue
    return rows


def proposed_metadata_control(package, files, geometry):
    info = files['DLLINFO.TXT']['content']
    # One inter-tag CR becomes an ASCII space. Every tag/value, actual file
    # length, DLL bytes, allocation/header/index/identity and SIG stay intact.
    anchor = b'</voice_name>\r\n<lang_name>'
    where = info.index(anchor)+len(b'</voice_name>')
    check(info[where] == 13, 'Proposal original inter-tag CR differs')
    proposal = info[:where]+b' '+info[where+1:]
    tag_values = lambda value: re.findall(rb'<([a-z_]+)>([^<]*)</\1>', value)
    check(tag_values(info) == tag_values(proposal), 'Proposal changes a tag/value')
    block_bytes = geometry['block_bytes']
    outer_offset = files['DLLINFO.TXT']['blocks'][where//block_bytes]*block_bytes+where%block_bytes
    check(package[outer_offset] == 13 and len(proposal) == len(info), 'Proposal physical mapping differs')
    return dict(status='preparation contract only; no candidate VPM written',
                member='DLLINFO.TXT', member_offset=where, physical_package_offset=outer_offset,
                original_byte_hex='0d', proposed_byte_hex='20', changed_bytes=1,
                original_member_sha256=sha(info), hypothetical_member_sha256=sha(proposal),
                unchanged_host_extracted_tag_value_count=len(tag_values(info)),
                host_tag_equivalence_is_not_native_parser_or_device_acceptance=True,
                unchanged_required_members={name:files[name]['sha256'] for name in
                    ['DLLIMG.BIN', 'DLLIMG.SIG', 'IMGEND.TST']},
                unchanged_package_file_length=len(package),
                unchanged_directory_geometry_and_allocation=True,
                original_code_audio_UI_logic_changes=0,
                code_modified_acceptance_test=False,
                signature_or_policy_mutation=False)


def main():
    check(not REPORT.exists() and not FUNCTIONS.exists(), 'Keep new outputs exclusive/immutable')
    audit = json.loads((ROOT/PRIOR).read_text())
    protected = audit['protected_sources']
    check(len(protected) == 665, 'Expected current665 frozen registry')
    check_registry(protected)
    deps = [Path(__file__), OUT/'parse_vpm_detached_signature.py', OUT/'rfc4880.txt',
            OUT/'rfc4880-source.json', ROOT/PRIOR,
            ROOT/'scripts/analyze_native_sections.py', ROOT/'scripts/analyze_native_vpm_acceptance_path.py',
            ROOT/'scripts/analyze_sdp_activation.py', ROOT/'scripts/analyze_tts_vpm.py',
            ROOT/'evidence/firmware-analysis/main_02bd.bin',
            ROOT/'evidence/firmware-analysis/tts-vpm-containers.json',
            ROOT/'staging/native-player-heap-settings-boot/package-static/vpm-acceptance-preflight.json',
            ROOT/'staging/native-player-settings-vfp-context/acceptance-static/acceptance-policy-provenance.json']
    inventory = json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())
    old = {Path(row['file']).name:row for row in inventory['containers']}
    voices, tts, all_scan_paths = [], [], []
    for path in sorted((ROOT/'backups/20261002T154458Z/files/Voice').glob('*.vpm')):
        raw = path.read_bytes()
        check(path.name in old and sha(raw) == old[path.name]['sha256'], 'Original voice backup changed')
        deps.append(path);all_scan_paths.append(path)
        row = dict(path=rel(path), bytes=len(raw), sha256=sha(raw))
        if raw.startswith(b'AUDIMG'):
            row.update(format=raw[:9].decode('ascii'), directory_SIG_inventory_parsed=False,
                       no_SIG_or_policy_absence_claim=True)
        else:
            files, geometry = parse_image(raw)
            signature = files['DLLIMG.SIG']['content']
            parsed = parse_v4_dsa_sha1_signature(signature)
            assoc = candidate_document_association(files['DLLIMG.BIN']['content'], parsed)
            check(assoc['left16_matches'], 'Original BIN candidate signed digest prefix differs')
            meta = files['DLLIMG.SIG'];directory = meta['directory_offsets'][0]
            sig_base = meta['blocks'][0]*geometry['block_bytes']
            check(len(meta['blocks']) == 1 and raw[sig_base:sig_base+len(signature)] == signature,
                  'Original SIG physical allocation mapping differs')
            for member in ['DLLIMG.SIG', 'DLLIMG.BIN']:
                extract = ROOT/'evidence/firmware-analysis/voice-modules'/path.stem/member
                check(extract.read_bytes() == files[member]['content'], 'Extracted original member differs')
                deps.append(extract);all_scan_paths.append(extract)
            parsed['creation_time_UTC'] = datetime.fromtimestamp(
                parsed['hashed_subpackets'][0]['creation_time_unix_seconds'], timezone.utc).isoformat()
            record = dict(package=rel(path), package_sha256=sha(raw), geometry=geometry,
                          member_count=len(files), member_type_inventory=[
                              dict(name=name, length=member['bytes'], first_directory_offset=member['directory_offsets'][0],
                                   type_byte_offset=member['directory_offsets'][0]+16,
                                   type_byte=raw[member['directory_offsets'][0]+16],
                                   part_count=member['parts'], sha256=member['sha256'])
                              for name,member in files.items()],
                          signature_member=dict(name='DLLIMG.SIG', bytes=len(signature), sha256=sha(signature),
                              directory_offset=directory, directory_entry_SHA256=sha(raw[directory:directory+512]),
                              directory_first32_hex=raw[directory:directory+32].hex(),
                              ordinary_file_type_byte_offset=directory+16, ordinary_file_type_byte=raw[directory+16],
                              first_block=meta['blocks'][0], physical_payload_offset=sig_base,
                              physical_issuer_key_ID_offset=sig_base+18),
                          parsed_signature=parsed, candidate_BIN_digest_association=assoc,
                          metadata_only_test_proposal=proposed_metadata_control(raw, files, geometry),
                          original_signature_cryptographically_verified=False,
                          signature_reader_or_native_enforcement_identified=False)
            tts.append(record)
            row.update(format='DSKIMG TTS', member_count=len(files), signature_bytes=len(signature),
                       SIG_standard_format='OpenPGP v4 binary-document DSA/SHA1',
                       SIG_sha256=sha(signature), original_BIN_left16_association=True)
        voices.append(row)
    check(len(voices) == 13 and len(tts) == 3, 'Expected13 voices and3 TTS')
    check(all(row['parsed_signature']['unhashed_subpackets'][0]['issuer_key_ID_hex'] == ISSUER.hex()
              for row in tts), 'Original signature issuer IDs differ')
    tests = parser_controls(
        (ROOT/'evidence/firmware-analysis/voice-modules/Chinese_Big5_MeiLing/DLLIMG.SIG').read_bytes(),
        next(row['parsed_signature'] for row in tts if 'Chinese_Big5_' in row['package']))
    association_matrix = []
    for sigrow in tts:
        for binrow in tts:
            module = ROOT/'evidence/firmware-analysis/voice-modules'/Path(binrow['package']).stem/'DLLIMG.BIN'
            associated = candidate_document_association(module.read_bytes(), sigrow['parsed_signature'])
            same = binrow['package'] == sigrow['package']
            check(associated['left16_matches'] == same, 'Cross-original BIN association control differs')
            association_matrix.append(dict(signature_package=sigrow['package'], document_package=binrow['package'],
                                           expected_match=same, passed=True, **associated))
    gcd = ROOT/'evidence/live-device/GUPDATE.GCD'
    deps.append(gcd);all_scan_paths.extend([ROOT/'evidence/firmware-analysis/main_02bd.bin', gcd])
    searches = []
    for path in sorted(set(all_scan_paths)):
        raw = path.read_bytes()
        searches.append(dict(path=rel(path), bytes=len(raw), sha256=sha(raw),
            issuer_byte_patterns={kind:[m.start() for m in re.finditer(re.escape(pattern),raw)]
                                  for kind,pattern in [('as_encoded',ISSUER),('reversed_eight_bytes',ISSUER[::-1])]},
            fixed_issuer_literal_is_not_public_key_or_verifier_proof=True))
    stock = NativeImage();image = RuntimeImage(stock)
    key_candidates = canonical_DSA_key_body_candidates(stock.data)
    entries = [0x122fbc,0x123f6c,0x11d678,0x11d5d0,0x11e048,0x123920,
               0x2fb988,0x128620,0x128670,0x3324b8,0x2fba70,0x1fb304,0x1fb3a2,
               0x274a8a,0x359958,0x4c7418,0x4c7462]
    functions, assertions = {}, []
    for entry in entries:
        fn = trace(image,entry,2400)
        check(not fn['instruction_limit_reached'], 'Bounded CFG instruction limit')
        for row in fn['instructions']:
            a = int(row['address'],16)
            ins = next(image.md.disasm(image.read(a,4),a,count=1))
            row.update(bytes=ins.bytes.hex(),load_address=hex(stock.runtime_to_load(a,ins.size)))
        fn['direct_call_targets'] = sorted({r['direct_call'] for r in fn['instructions'] if 'direct_call' in r})
        fn['bounded_CFG_not_global_policy_absence'] = True
        functions[hex(entry)] = fn
    expected = {
        0x12405a:'ldrb r1, [r3]',0x12405c:'cmp r1, #1',0x124066:'ldrb r1, [r3, #0x11]',
        0x12407c:'ldrb r2, [r4, r1]',0x124072:'cmp r1, #0xb',0x124084:'ldrb r7, [r7, #1]',
        0x2fb9e6:'movs r2, #1',0x2fb9e8:'movs r1, #0',0x2fb9ea:'bl #0x123f6c',
        0x2fba08:'ldrb r1, [r6, #0x10]',0x2fba0c:'lsls r1, r1, #0x1e',
        0x2fba12:'strb r2, [r0, #0xb]',0x2fba34:'ldr r0, [r6, #0xc]',
        0x332514:'bl #0x123920',0x332536:'blx #0x3732c8',
        0x274a96:'bl #0x359958',0x274aa0:'bl #0x359958',
        0x4c7438:'adr r0, #0x27c',0x4c743a:'bl #0x45dd40',0x4c7440:'bne #0x4c7456',
    }
    for a,wanted in expected.items():
        ins = next(image.md.disasm(image.read(a,4),a,count=1))
        check(ins.mnemonic+' '+ins.op_str == wanted, 'Exact MAIN instruction changed '+hex(a))
        assertions.append(dict(address=hex(a), bytes=ins.bytes.hex(), instruction=wanted))
    direct_open = scan_calls(stock,{0x1fb304})
    host99 = list(struct.unpack('<99I',image.read(0xf09364,396)))
    write_exclusive(FUNCTIONS,dict(MAIN_sha256=EXPECTED, functions=functions,
        limits='Bounded static instruction CFG; all indirect or transitive callers are not closed.'))
    deps.append(FUNCTIONS)
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        exact_target=dict(model='Taiwan nuvi2565RT',HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        source_sha256={rel(path):sha(path.read_bytes()) for path in sorted(set(deps))},
        protected_registry=dict(path=PRIOR,sha256=sha((ROOT/PRIOR).read_bytes()),unique_frozen_dependencies=len(protected),changed_or_missing=[]),
        primary_specification=dict(url='https://www.rfc-editor.org/rfc/rfc4880.html',
            local_text=rel(OUT/'rfc4880.txt'),local_text_sha256=sha((OUT/'rfc4880.txt').read_bytes()),
            sections=['4.2.1','5.2.3','5.2.3.4','5.2.3.5','5.2.4','9.1','9.4'],
            publish_scope='Packet labels/declared algorithms and hash construction only; no Garmin enforcement claim'),
        original_voice_inventory=voices,TTS_signature_analysis=tts,
        pure_host_parser_controls=dict(all_passed=True,case_count=len(tests),cases=tests,not_native_or_device_proof=True),
        original_document_association_controls=dict(all_passed=True,case_count=len(association_matrix),cases=association_matrix,
            left16_bits_only=True,full_public_key_DSA_authentication=False),
        fixed_issuer_search=searches,
        canonical_v4_DSA_public_key_body_search=dict(scope='Exact raw MAIN v4 body with canonical p/q/g/y MPIs; positives would require independent key/trust review',
            candidates=key_candidates,transformed_or_external_key_storage_not_excluded=True),
        bounded_CFG_count=len(functions),bounded_functions_artifact=rel(FUNCTIONS),exact_MAIN_instruction_assertions=assertions,
        bounded_unresolved_exits={key:fn['unresolved_exits'] for key,fn in functions.items() if fn['unresolved_exits']},
        embedded_SIG_index_and_reader=dict(
            original_backup_fact='All65 TTS members including3 DLLIMG.SIG use ordinary directory type byte0 atentry+16; root directory uses3. SIG is a named72-byte ordinary member, not a special directory authentication record.',
            key='DLLIMG  SIG',
            directory_match='123F6C r0=fileobject,r1=directory part/FFFF,r2=search behavior.12405A/5C require entry marker1;124066 compares entry+17 part;124072 bounds11 keybytes and124084 reads entry+1+i. Open2FB988 sets part0 before2FB9EA.',
            type_byte_use='2FBA08 loads entry+16,2FBA0C/0E extracts low2 bits and2FBA12 merges fileobjectflags. No special SIG type among exact backup entries; this alone does not exclude separate policy.',
            read='1FB3A2→3324B8→123920 allocation translation/cache/FEB36 byteinput;332536 copies bytes. Original directory/allocation path can resolve SIG by full8+3 key when a caller requests it.',
            native_program_SIG_request_caller_identified=False,
            old_emulator_explicit_SIG_open_is_harness_request_not_native_verifier=True),
        direct_open_candidates=direct_open,
        initialized_original_host99=dict(runtime_base='0xf09364',words=[hex(w)for w in host99],
            original_file_slots=[dict(slot=i,target=hex(host99[i]))for i in range(54,60)],
            mutable_runtime_table_not_current_device_inventory=True),
        separate_GMA_boundary=dict(original_header_string_address='0x4c76b8',original_header='GARMIN GMA',
            validator='4C7418→4C743A memcmp10; mismatch4C7440→4C7456 return0.4C7462 returns4 on failedstructure.',
            original_OpenPGP_SIG_is_not_that_GMA_header=True,
            GMA_cryptographic_validator_or_voice_connection_identified=False),
        acceptance_gate_status=dict(signature_file_format_identified=True,signature_declared_algorithm='OpenPGP v4 DSA/SHA1 binary-document signature',
            original_BIN_digest_prefix_association_cases=3,public_key_identified=False,full_DSA_verification=False,
            native_SIG_reader=False,native_SIG_verifier_algorithm_or_enforcement=False,
            native_policy_absence_proven=False,physical_modified_VPM_accepted=False,
            physical_modified_DLL_code_accepted=False,physical_App_or_direct_A2DP_complete=False),
        minimal_reversible_acceptance_test_contract=dict(
            preparation_only=True,no_install_candidate_written=True,
            separately_scoped_tiers=[
                dict(tier='renamed-original', status='not prepared or run',
                     change='Outer USB basename only; retain all original package bytes and internal identities.',
                     limit='Must independently establish filename policy, current selection and reversible replacement; adding a duplicate-volume copy is excluded. Success would prove only name/location acceptance.'),
                dict(tier='metadata-only', status='reviewable one-byte proposal only',
                     change='Inter-tag whitespace in DLLINFO.TXT; DLLIMG.BIN and SIG remain byte-identical.',
                     limit='Success cannot establish changed executable acceptance.'),
                dict(tier='DLLdigest-changed', status='not prepared; safe inert byte not proven',
                     change='Requires a specifically proven unused executable-container byte with bounded loader/relocation/read references and original ABI preserved.',
                     limit='Do not guess that arbitrary padding or an unreferenced byte is inert. No modified DLL or signature has been written; native enforcement and accepted executable changes remain unknown.')
            ],
            candidate_scope='One inter-tag metadata whitespace byte; unchanged executable/native exports/audio/UI logic/SIG/identity/directory/length. A metadata control cannot prove modified executable acceptance.',
            preconditions=[
                'Confirm current physical selected voice and filename; backup inventory/defaultjill/model does not identify it.',
                'Complete stock voice control with original package first; capture no-speech/no-route-preview observation and an independently recoverable exact original file.',
                'Require verified USB recovery while package is unselected, exact original path/hash restoration, and absence of install/update tasks that would independently alter package data.',
                'Select only one exact original TTS package; do not add duplicate volume IDs or rename internal identities. Do not auto load experimental EMULATION-ONLY DLLs.'
            ],
            observation_levels=[
                dict(level='data inventory',evidence='Fresh originalboot inventory lists identical identity/required metadata after candidate byte is read; mere USB readback is not runtime acceptance.'),
                dict(level='selected data package',evidence='Original selection/cache/mount result corresponds to candidate current bytes, including actualvolumeactive and selectedindex; UI choice alone may not expose native loader status.'),
                dict(level='original stock DLL initialization',evidence='If separately observable, original23C3C4 return11 and selectedF095AC+4 store2404CA; no audio or customUI logic trigger. Otherwise record this level unknown.'),
                dict(level='modified executable accepted',evidence='Not tested by this control; requires separate authorized benign executable change, trusted acceptance evidence and original40ABI/lifetime proof.')
            ],
            restore='Restore exact original package bytes at the exact original path; verify full readbackSHA256 and original selected package state. Current source/settings and physical recovery feasibility remain prerequisite observations, not assumed.',
            failure_interpretation='A metadata-control rejection is an observed data/package boundary, not proof DSA enforcement; capture exact status. A metadata-control success does not authenticate a changedDLLIMG.'),
        next_bounded_work=[
            'Observe actual original filename/request key whenSIG72bytes are read, save entryLR/functionpointer provenance and fullread status; current explicit harnessSIG read cannot supply that caller.',
            'Follow that realreader to OpenPGP tag2/version4/DSA17/SHA1-2 parsing, key acquisition, native verification return and rejecting branch; unjoinedMAIN crypto/GMA candidates are not verifier proof.',
            'If a candidate trustedpublickey is recovered, compute full keyfingerprint and verify3 originals independently without generating signatures. Matching issuerID alone is advisory and not trust.',
            'Prepare only the singlebyte metadata acceptance control once physical selection/recovery prerequisites are available; keep executablemodified acceptance a separate unresolved milestone.'
        ],
        limits=dict(static_only=True,emulator_imported=False,native_code_executed=False,device_service_IO=False,sounds_emitted=False,
                    original_packages_SIG_or_frozen_sources_modified=False,modified_package_written=False,
                    signature_key_or_bypass_generated=False,canonical_updated=False,
                    previous_algorithm_unknown_artifacts_preserved=True))
    write_exclusive(REPORT,result)
    check_registry(protected)
    print(json.dumps(dict(report=rel(REPORT),report_SHA256=sha(REPORT.read_bytes()),source_dependencies=len(result['source_sha256']),
                         protected_dependencies=len(protected),TTS=3,format_controls=len(tests),association_controls=len(association_matrix),
                         bounded_CFG=len(functions),exact_assertions=len(assertions),native_enforcement=False),ensure_ascii=False))


if __name__ == '__main__':
    main()
