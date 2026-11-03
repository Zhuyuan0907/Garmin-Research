#!/usr/bin/env python3
"""Exclusive, exact-HWID1352 static outer voice-load contract.

No emulation, device I/O, candidate packages, signatures, keys, patches or
canonical writes. Prior module host55 profiles are referenced, not repeated.
The bounded CFG and direct encoding scan do not close indirect/native policy.
"""
import sys
sys.dont_write_bytecode = True
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage, scan_calls, wide
from analyze_sdp_activation import trace

REPORT = OUT / 'native-outer-voice-load-and-sig-request-contract.json'
CFG = OUT / 'outer-voice-load-bounded-functions.json'
AUDIT = ROOT / 'staging/native-player-dispatcher-fp/previous-audit.json'
FORMAT = ROOT / 'staging/native-player-cache-declared-followup/package-static/vpm-sig-format-and-gate-preflight.json'
POLICY = ROOT / 'staging/native-player-settings-vfp-context/acceptance-static/acceptance-policy-provenance.json'
FOPEN = ROOT / 'staging/native-player-cold-fp-controller/package-static/native-sig-request-contract-v2.json'
EXPORT = ROOT / 'staging/native-player-cold-fp-controller/package-static/original-jill-file-export-binding.json'
PROOF = ROOT / 'evidence/firmware-analysis/native-cold-fp-controller-emulation.json'
MANIFEST = ROOT / 'staging/native-app-component-emulation/Chinese_Big5_MeiLing/manifest.json'
INVENTORY = ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json'

# Starts and explicitly decoded switch-case roots are separate. A case-root
# trace is not claimed to be a native function entry or full actor closure.
ENTRIES = (0x2748a0, 0x273c2a, 0x1d897c, 0x254b2e, 0x254cc2,
           0x254d4a, 0x254dbe, 0x254dc2, 0x2404d6, 0x240498,
           0x2741f4, 0x274452, 0x2747cc, 0x1d8514, 0x24e83a,
           0x23c3c4, 0x3b3294, 0x3b331a, 0x1fb304, 0x1fb3a2,
           0x3324b8, 0x38a398)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rel(path):
    return str(path.relative_to(ROOT))


def need(condition, message):
    if not condition:
        raise ValueError(message)


def write_new(path, value):
    with path.open('x') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def frozen_check(registry):
    for name, expected in registry.items():
        need(sha((ROOT / name).read_bytes()) == expected,
             'Changed protected source: ' + name)


def exact(stock, image, address):
    ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
    need(ins is not None, 'Undecodable exact instruction: ' + hex(address))
    row = {'address': hex(address), 'load_address': hex(stock.runtime_to_load(address, ins.size)),
           'bytes': ins.bytes.hex(), 'instruction': ins.mnemonic + ' ' + ins.op_str}
    if (ins.mnemonic == 'ldr' and len(ins.operands) == 2 and
        ins.operands[1].type == ARM_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC):
        literal = ((address + 4) & ~3) + ins.operands[1].mem.disp
        row.update(literal_runtime=hex(literal), literal_load=hex(stock.runtime_to_load(literal, 4)),
                   literal_value=hex(image.word(literal)))
    return ins, row


def bounded(stock, image, address):
    fn = trace(image, address, 2000)
    need(not fn['instruction_limit_reached'], 'CFG budget reached: ' + hex(address))
    indirect, terminals = [], []
    for n, row in enumerate(fn['instructions']):
        ins, observation = exact(stock, image, int(row['address'], 16))
        # The inherited tracer's optional ASCII string is unsuitable for the
        # native UTF16 enumeration wildcard/format. Save exact operands/bytes;
        # decode only separately checked named strings below.
        row.pop('string', None)
        row.update(observation)
        if ins.mnemonic == 'blx' and ins.operands[0].type != ARM_OP_IMM:
            indirect.append({'PC': hex(ins.address), 'instruction': row['instruction'],
                             'target_provenance_requires_separate_binding': True})
        if ins.mnemonic == 'bx' and ins.op_str != 'lr':
            previous = fn['instructions'][n-1] if n else None
            saved_return = bool(previous and previous['instruction'] == 'pop {' + ins.op_str + '}')
            terminals.append({'PC': hex(ins.address), 'instruction': row['instruction'],
                              'saved_LR_pop_return_pattern': saved_return,
                              'other_indirect_target_unresolved': not saved_return})
    fn.update(entry_runtime=hex(address), entry_load=hex(stock.runtime_to_load(address, 2)),
              explicit_case_root_not_function_entry=address in (0x254dbe, 0x254dc2),
              indirect_call_sites=indirect, non_LR_BX_terminals=terminals,
              bounded_CFG_not_transitive_or_indirect_or_global_policy_closure=True,
              instruction_bytes_sha256=sha(b''.join(bytes.fromhex(r['bytes']) for r in fn['instructions'])))
    return fn


def main():
    need(not REPORT.exists() and not CFG.exists(), 'Exclusive records already exist')
    audit = json.loads(AUDIT.read_text())
    protected = audit['protected_sources']
    need(len(protected) == 751, 'Requires fresh751 snapshot')
    frozen_check(protected)
    stock = NativeImage()
    image = RuntimeImage(stock)

    expected = {
        0x2748b6: 'bl #0x273c2a', 0x273c5c: 'bl #0x1d897c',
        0x1d8998: 'adr r1, #0x184', 0x1d899a: 'bl #0x31d8fe',
        0x1d89f6: 'ldr r2, [r3, #0x38]', 0x1d89f8: 'movs r3, r4',
        0x1d89fa: 'adr r1, #0x130', 0x1d89fc: 'bl #0x38756a',
        0x1d8a04: 'bl #0x1d8514', 0x1d8a12: 'bl #0x275590',
        0x1d8a26: 'bne #0x1d8a66', 0x1d8a32: 'bl #0x278194',
        0x1d8a62: 'bl #0x274992', 0x2748ea: 'strh r0, [r3, #0x28]',
        0x2748f2: 'str r0, [sp, #0x30]', 0x274900: 'strb r5, [r3, #0xe]',
        0x274902: 'bl #0x254b2e', 0x27491a: 'strh r6, [r3, #0x28]',
        0x274920: 'str r0, [sp, #0x30]', 0x27492c: 'bl #0x254b2e',
        0x254b32: 'strb r1, [r0, #2]', 0x254b36: 'strb r0, [r5, #3]',
        0x254b38: 'strb r0, [r5, #4]', 0x254b66: 'ldm r5!, {r1, r2, r3, r6}',
        0x254b6e: 'stm r0!, {r1, r2, r3, r6}', 0x254b70: 'ldm r5!, {r1, r2, r3, r6}',
        0x254b72: 'stm r0!, {r1, r2, r3, r6}', 0x254b74: 'ldm r5!, {r1, r2}',
        0x254b76: 'stm r0!, {r1, r2}', 0x254b8e: 'blx #0x2fcf44',
        0x254d56: 'bl #0x2fd034', 0x254d7a: 'bl #0x254cc2',
        0x254d96: 'cmp r0, #0x15', 0x254d98: 'bhs #0x254e5c',
        0x254d9a: 'adr r3, #8', 0x254d9c: 'ldrb r3, [r3, r0]',
        0x254d9e: 'adds r3, r3, r3', 0x254da0: 'add pc, r3',
        0x254dc0: 'strb r5, [r3, #0xe]', 0x254dc4: 'ldrb r0, [r3, #0x14]',
        0x254dcc: 'bne #0x254df4', 0x254df4: 'bl #0x2741f4',
        0x254e0e: 'bl #0x35980c', 0x254e14: 'bne #0x254e1e',
        0x254eea: 'bl #0x274452', 0x254ef0: 'bne #0x254f1a',
        0x254f1a: 'movs r0, #1', 0x254f1e: 'strh r0, [r3, #0x28]',
        0x254f22: 'bl #0x2404d6', 0x254f2e: 'bl #0x2404d6',
        0x2404fe: 'beq #0x2405ec', 0x2405ec: 'ldrb r1, [r4, #6]',
        0x2405ee: 'ldr r0, [r4, #8]', 0x2405f0: 'bl #0x240498',
        0x2405f6: 'bl #0x33f8de', 0x2404a2: 'bl #0x2741f4',
        0x2404b0: 'beq #0x2404d0', 0x2404ba: 'bl #0x2747cc',
        0x2404c0: 'beq #0x2404d0', 0x2404c2: 'bl #0x23c3c4',
        0x2404c6: 'cmp r0, #0xb', 0x2404c8: 'bne #0x2404d0',
        0x2404ca: 'str r6, [r4, #4]', 0x2404d0: 'str r5, [r4, #4]',
        0x24e8a2: 'ldr r1, [r0, #8]', 0x24e8a6: 'blx r1',
        0x24e8aa: 'bne #0x24e8b0', 0x24e8ae: 'strb r0, [r4]',
        0x23c422: 'bl #0x3b3294', 0x23c42e: 'bl #0x3b331a',
        0x3b3298: 'ldr r2, [r1, #4]', 0x3b32a2: 'blx r2',
        0x3b32d6: 'ldr r7, [r4, #8]', 0x3b32dc: 'ldr r2, [sp, #4]',
        0x3b32de: 'movs r1, #1', 0x3b32e0: 'blx r7',
        0x3b32e2: 'ldr r0, [r5, #0x18]', 0x3b3332: 'blx r1',
        0x1fb3a6: 'muls r2, r5, r2', 0x1fb3c0: 'bl #0x3324b8',
        0x1fb3c4: 'movs r1, r5', 0x1fb3c6: 'movs r0, r4',
        0x1fb3c8: 'blx #0x38c168', 0x332514: 'bl #0x123920',
        0x332536: 'blx #0x3732c8', 0x33253c: 'str r4, [r7, #0x10]',
        0x38a398: 'movs r0, #0xb', 0x38a39a: 'bx lr',
        0x1d8894: 'movs r0, #4', 0x1d889e: 'bl #0x2404d6',
        0x1d88a2: 'movs r0, #2', 0x1d88aa: 'bl #0x2404d6',
    }
    assertions = []
    for address, wanted in expected.items():
        ins, row = exact(stock, image, address)
        need(row['instruction'] == wanted, f'{address:#x}: {row["instruction"]} != {wanted}')
        assertions.append(row)

    table = image.read(0x254da4, 21)
    need(table.hex() == 'f5e9f3f3f3dc0d5c5c5c5cf20ffd5c5c5c5cde0bfd', 'Actor byte switch differs')
    cases = [{'control_type': n, 'byte': b, 'target': hex(0x254da4+2*b)} for n,b in enumerate(table)]
    need(cases[6]['target'] == '0x254dbe' and cases[12]['target'] == '0x254dc2', 'Load case roots differ')
    need(image.word(0x89e1f0) == 2, 'Directory count differs')
    directories = []
    for n in range(2):
        pointer = image.word(0xf07124+n*4)
        text = wide(image, pointer)
        need(text == ('0:/Voice/', '0:/Garmin/Voice/')[n], 'Native folder differs')
        directories.append({'index': n, 'pointer_record': hex(0xf07124+n*4),
                            'pointer': hex(pointer), 'UTF16LE': text,
                            'bytes': image.read(pointer, (len(text)+1)*2).hex()})
    named = []
    for address, wanted in ((0x1d8b20, '*.vpm'), (0x1d8b2c, '%s%s'), (0x274bf4, 'jill')):
        need(wide(image, address) == wanted, 'Checked UTF16 literal differs')
        named.append({'runtime': hex(address), 'load': hex(stock.runtime_to_load(address, (len(wanted)+1)*2)),
                      'UTF16LE': wanted, 'bytes': image.read(address, (len(wanted)+1)*2).hex()})
    need(image.read(0x23c4e8, 11) == b'dllimg.bin\0', 'Actual loader filename differs')
    functions = {hex(a): bounded(stock, image, a) for a in ENTRIES}
    write_new(CFG, {'updated_utc': datetime.now(timezone.utc).isoformat(), 'MAIN_sha256': EXPECTED,
                   'functions': functions, 'actor_switch': {'guard': '254D96 CMP type,21;254D98 BHS default',
                   'table_runtime': '0x254da4', 'bytes': table.hex(), 'PC_operand_base': '0x254da4',
                   'cases': cases, 'only_case6_and12_traced_as_explicit_roots': True},
                   'no_native_execution': True, 'no_global_call_or_verifier_closure': True})
    calls = scan_calls(stock, {0x1fb3a2,0x24e83a,0x1d8514,0x1d897c,0x240498,0x23c3c4})
    read_direct = [r for r in calls['candidates'] if r['target'] == '0x1fb3a2']
    need({r['address'] for r in read_direct} == {'0x275ab4','0x275b10'}, 'Known MAIN direct read candidates differ')

    inventory = json.loads(INVENTORY.read_text())
    originals = [{'outer_VPM': r['file'], 'bytes': r['bytes'], 'sha256': r['sha256'],
                  'original_DLL_sha256': r['files']['DLLIMG.BIN']['sha256'],
                  'original_SIG_sha256': r['files']['DLLIMG.SIG']['sha256']}
                 for r in inventory['containers'] if r.get('module')]
    need(len(originals) == 3, 'Original TTS container count differs')
    for record in originals:
        need(sha((ROOT/record['outer_VPM']).read_bytes()) == record['sha256'], 'Original outer VPM differs')
    manifest = json.loads(MANIFEST.read_text())
    proof = json.loads(PROOF.read_text())
    source_paths = [Path(__file__).resolve(), CFG, AUDIT, FORMAT, POLICY, FOPEN, EXPORT,
                    PROOF, MANIFEST, INVENTORY, ROOT/'scripts/analyze_native_sections.py',
                    ROOT/'scripts/analyze_native_vpm_acceptance_path.py', ROOT/'scripts/analyze_sdp_activation.py',
                    ROOT/'evidence/firmware-analysis/main_02bd.bin']
    source_paths += [ROOT/r['outer_VPM'] for r in originals]
    deps = {rel(p): sha(p.read_bytes()) for p in source_paths}
    frozen_check(protected)
    report = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': {'model': 'Taiwan nuvi2565RT', 'HWID': 1352, 'software': '8.00', 'MAIN_sha256': EXPECTED},
        'scope': 'New pure static outer voice enumeration/queue/selection/loader contract; previous fopen2/2/4 and Jill exports15/23 profiles reused without rerun.',
        'source_sha256': deps,
        'protected_registry': {'snapshot': rel(AUDIT), 'sha256': deps[rel(AUDIT)], 'source_count': len(protected),
                               'all_hashes_checked_before_and_after': True, 'unchanged': True},
        'bounded_functions': {'artifact': rel(CFG), 'sha256': deps[rel(CFG)], 'count': len(functions),
                              'explicit_case_roots': ['0x254dbe','0x254dc2'],
                              'unresolved_exits': {k:v['unresolved_exits'] for k,v in functions.items() if v['unresolved_exits']},
                              'full_native_policy_or_indirect_call_closure': False},
        'exact_instruction_assertions': assertions,
        'original_TTS_outer_identity': originals,
        'actual_filename_and_registry_chain': {
            'enumeration': '2748A0→273C2A; count89E1F0=2, runtime pointer tableF07124;273C5C→1D897C(r0=folder).',
            'directories': directories, 'checked_native_UTF16_literals': named,
            'candidate_path': '1D899A original directory enumeration31D8FE uses *.vpm.1D89F6 r2=original folder;1D89F8 r3=enumerated UTF16 name;1D89FA format%s%s→38756A.1D8A04 mapped bind→1D8514;1D8A12 metadata275590;duplicate/type guards precede registry274992.',
            'identity_not_acceptance': 'Registry entry or UI name is metadata acceptance only.1D8514 returns mapped-binding bool and ignores original DSKIMG parser return; require original embedded active/parser state separately (prior policy provenance).',
            'initial_selected_control': '2748CA settings→274232 then2748DE existence2745CC;configured ID yields type12 at2748EA/index+8 at2748F2/context+6=0 at274900→274902 native producer.Otherwise known Jill fallback type6 at27491A/index+8 at274920→27492C; fallback first record also possible. jill literal is not a captured live selected voice.',
            'native_registry_index_and_actual_path_not_captured': True},
        'native_outer_actor_contract': {
            'producer': '254B2E r0=40-byte control,r1=queue index;writes control+2=index,+3/+4=0;global344CBB8 queue stride408;ring element stride40;copies16+16+8 bytes at254B66..76 under344CF18 mutex;post2FCF44 bit2 at254B8E viaF095C4+8 TCB.',
            'consumer': '254D4A persistent actor;original wait2FD034 at254D56,mailbox bit2 at254D74/76,get254CC2 at254D7A;40-byte local M=SP+68 copied to344CF30;type=M+0 halfword,context=M+6 byte,registry index=M+8 word,settings-only flag=M+12 byte.',
            'computed_switch': {'guard': 'control_type<21', 'table': '0x254da4', 'bytes': table.hex(), 'cases': cases,
                                'case6': '254DBE clears M+6 then falls into case12 at254DC2.',
                                'case12': 'M+12==1 takes settings-only2745A0 branch at254DD8;M+12!=1 passes native previous/current identity and action checks.254EEA→274452 gets selected registry type;nonzero branch254EF0→254F1A builds type1 and254F22→2404D6.',
                                'case19': '254DBA invokes2748A0 enumeration; no full switch/runtime proof claimed.'},
            'control_load': '2404D6 type1 recognized2404FC/FE;2405EC r1=M+6 and2405EE r0=M+8→2405F0→240498. Context byte is preserved identity, not asserted hardware audio channel.',
            'before_and_after_boundaries': '240498 getsvolume ID2741F4;empty ID reject2404B0;2747CC maps native selected path1D8514;zero reject2404C0;23C3C4 at2404C2;onlyreturn11 storesregistry indexF095AC+4 at2404CA,allrejects storeFF at2404D0. After call2405F6→33F8DE andactor254F2E type3 action can cause audio/task effects; static test plan must stop/observe before those effects rather than assume silent.',
            'incorrect_higher_caller_excluded': '1D889E and1D88AA belong1D8868, not1D854E;controltypes4/2 from1D8894/1D88A2, not type1 load.'},
        'mount_status_contract': {
            'entry': '0x24e83a', 'not_function_entry_or_reader': '0x24e8ae',
            'callback': '24E8A2 loads type_record+8 callback;24E8A4 r0=volume record;24E8A6 BLXr1. type table1057810 stride24, volume arrayF001A8 count/F001AC pointer stride64;volume+32 lower block descriptor.',
            'status_and_enforcement_limit': 'Only callback return0 enables24E8AC/AE STRB1 tovolume+0;function returns callbackstatus at24E8C2. generic active/status0 is not voice selection,signature verification,module load or code acceptance.',
            'indirect_callback_binding': 'Type1 mount39E9E7 install/lower FAT/physical I/O provenance is inherited in hashed acceptance-policy-provenance.json; no live binding or physical mount obtained here.'},
        'BIN_reader_and_generic_member_boundary': {
            'original_initializer_callbacks': ['close1FB2F9','open1FB305','read1FB3A3','seek1FB3CF','tell1FB3E5'],
            'filename': {'runtime': '0x23c4e8', 'ASCII': 'dllimg.bin', 'bytes': image.read(0x23c4e8,11).hex()},
            'open_identity': '23C3C4 installs five original callback pointers on stack;3B3298 loads open callback+4;3B329C r0=descriptor+4 filename;3B32A2 BLXr2 actualknown target1FB305.1FB304 prefixes currentinternalindexF09658+8→FE648 with %i: before generic2FBA70,valid member flag required; selected index is not USB root filename.',
            'read_identity': '3B32D6 reads callback+8;3B32D8 r3=member handle;3B32DA r0=imagebase2D4BB74;3B32DC r2=tell-filelength;3B32DE r1=1;3B32E0 BLXr7 target1FB3A3 from initializer. This is original BIN read, not a SIG request.',
            'read_return_not_full_acceptance': '3B32E2 overwrites read return without comparing length.1FB3A2 multiplies size/count,caps by member remaining,1FB3C0 calls3324B8,then1FB3C4/C6 overwrites status with size/capped-bytecount anddivides38C168. Therefore wrapper return alone is not evidence all bytes actually read.',
            'generic_read': '3324B8 originalnative read requires validhandle/type flag,bounds offset+requestedbytes to length,512-byte block translation/cache via123920 at332514,copy3732C8 at332536,updateshandle+16 at33253C;returns native status. Lower block/member translation and driver are external bounded-call dependencies, no global closure here.',
            'entry_execution': '23C42E→3B331A;3B332E r1=descriptor+24 imagebase;3B3332 BLXr1 entersoriginal modulebootstrap. Export callback/bootstrap status at23C434..47E must retain actual original40 APIs; onlyreturn11 is selectedindexgate, not signature or physical new-code proof.',
            'direct_encoding_scan': calls,
            'direct_read_candidates_meaning': 'Only275AB4(IMGEND.TST) and275B10(DLLINFO.TXT) among scanned direct MAIN read calls; known actualBIN read is indirect3B32E0. This demonstrates why absence from directscan cannot exclude indirectSIGreader.',
            'ordinary_SIG_resolution': 'Prior exact backup/parser record: DLLIMG  SIG is ordinary directorytype0,72 bytes;generic123F6C key search/2FB988/2FBA08 andread1FB3A2→3324B8 canresolve it if requested. No nativeMAIN filename/key/handle/caller joined toSIG has been identified.',
            'SIG_requester_identified': False, 'SIG_native_verifier_publickey_or_enforcement_identified': False,
            'native_policy_absence_proven': False},
        'current_offline_extension_scope': {
            'manifest': rel(MANIFEST), 'manifest_sha256': deps[rel(MANIFEST)],
            'original_binary_sha256': manifest['original_binary_sha256'], 'combined_binary_sha256': manifest['combined_sha256'],
            **{k:manifest[k] for k in ['original_bytes_after_header_unchanged','modified_vpm_generated','signature_modified','signature_acceptance_verified','device_install_candidate','device_io','tasks_auto_booted','firmware_hooks_installed']},
            'limitations': manifest['limitations'], 'cold_runtime_proof': rel(PROOF), 'cold_runtime_sha256': deps[rel(PROOF)],
            'cold_runtime_complete_scenarios': proof['case_count'],
            'multiowner_FP_or_foreground_or_accepted_package_or_physical_App_or_direct_music_verified': proof['multiowner_FP_or_foreground_or_accepted_package_or_physical_App_or_direct_music_verified'],
            'this_static_analysis_executes_guest': False,
            'declared_signature_only_prior_reference': 'Hashed format record establishes original OpenPGPv4 declaredDSA17/SHA1=2 andthree BIN-left16 associations;notfullDSA/trust/enforcement. Parser/profile controls not repeated.'},
        'minimal_acceptance_observation_contract': {
            'next_offline_highest_original_calls': ['2748A0 actualbackupVoice directory enumeration andregistry selection',
                '254B2E actual40-byte control→2FCF44 post', '254D4A→2FD034 wait→254CC2 nativeget→type6/12 branch',
                '254F22→2404D6 type1→2405F0/240498→2747CC/1D8514 selectedoutermount',
                '2404C2→23C3C4→3B3294 actualBIN callback/memberread→3B331A/3B3332 originalbootstrap'],
            'required_identity_and_bytes': 'Full immutable outerVPM SHA,actualnativecandidatefolder/name/registryindex/controlbytes/internalvolumeID;originalDSKIMG active/parserstatus andmountcallbackbinding;actualnative BIN open key/memberhandle/length/readreturn+lowerstatus,completedloadedimage SHA beforeentry,actualentry/export targets. Any futureSIGopen needsnativePC/LR/filenameor11-bytekey→samehandle→readconsumer andactual verificationstatus; no manufacturedSIGrequest.',
            'forbidden_proof_substitutions': ['Seed selectedregistry/index/mountsuccess or SIGrequest', 'Host directloader call as proofhighergate ran', 'UIlisting,metadataaccepted,renamedoriginalaccepted ormountactive as changedcode acceptance', 'loader11 orfreadcappedcount as completeimage read', 'arbitrary guessed unused/padding byte as proven inert change'],
            'after_bootstrap_test_boundary': 'Observe2404CA/2404D0 and40APIbinding independently.2405F6/33F8DE and254F2E action/audio effects remain separate native runtime boundaries; do not execute them in this static branch.',
            'acceptance_layers': [
                {'layer':'metadata-only','success_scope':'Directory/metadata enumeration andidentity parsing only;cannotestablish modifiedDLLdigest/code acceptance.'},
                {'layer':'renamed-original','success_scope':'Originalunchanged DLL/package underdifferent reviewedidentity maycheck path/cacheambiguity only;notmodifiedcodeaccepted.'},
                {'layer':'DLL-digest-changed','success_scope':'Requires independentlyreviewed purposeful unchanged-functionality codechange or verifiedunusedbyte purpose,currently no suchcandidate prepared. Complete actualmodifiedimage identity andnativeentry execution required;no arbitraryinertpatch assumption.'}],
            'what_counts_as_offline_code_execution': 'Actual original higherselection/member/loaderchain consumes exactchangedDLL bytes andexecutes uniquelyidentified changedentry through3B3332;alloriginalAPI/lifetime guards retained. This wouldstill be emulation only andwouldnotprovephysicalSIGpolicy/acceptance.',
            'what_counts_as_physical_modified_code_accepted': 'Readback-verifiable exactmodifiedDLL-containing outerVPM plusactualstockselection/coldboot andobservableexecution ofknownchanged code uniquelydistinguishable fromstock/cache/duplicate,withoriginal40API/residentlifetime andrecovery constraints separately checked. UIlisting,mountactive,metadataacceptance,signatureleft16 orloaderstatus alone areinsufficient.',
            'physical_or_offline_acceptance_run_performed_here': False,
            'candidate_or_signature_or_key_generated': False,
            'remaining_preconditions': ['NativeSIGrequester/publickey/enforcement stillunknown;boundedcoverageisnotclosure',
                'No proveninertcodechange or physicalnon-audio marker/recoverytestcandidate prepared',
                'Actualphysicalhighest-selection/completeinput/loadedcode witness unavailable;requires distinctfutureauthorizedtest'],
        },
        'limits': {'static_instruction_bytes_captured': True, 'native_registers_branch_outcomes_and_runtime_file_IO_captured': False,
                   'emulator_executed': False, 'device_IO': False, 'audio': False, 'candidate_written': False,
                   'canonical_or_report_modified': False, 'physical_modified_VPM_accepted': False,
                   'physical_modified_DLL_code_accepted': False, 'physical_App_or_direct_A2DP_complete': False,
                   'AA_and_Maps': 'deferred', 'objective_active': True},
    }
    write_new(REPORT, report)
    print(json.dumps({'report': rel(REPORT), 'sha256': sha(REPORT.read_bytes()),
                      'CFG': rel(CFG), 'CFG_sha256': sha(CFG.read_bytes()),
                      'source_sha256_count': len(deps), 'bounded_count': len(functions),
                      'MAIN_instruction_assertions': len(assertions), 'protected_unchanged': len(protected),
                      'native_SIG_requester_identified': False, 'guest_or_device_execution': False}))


if __name__ == '__main__':
    main()
