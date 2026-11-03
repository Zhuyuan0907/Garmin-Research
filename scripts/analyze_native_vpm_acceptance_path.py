#!/usr/bin/env python3
"""Exact Taiwan MAIN/backup-only VPM acceptance-path preflight.

Creates exclusive new static artifacts. Does not import/run any emulator,
modify packages, construct signatures, patch code, or perform device I/O.
Absence of a literal or a verifier in this bounded chain is not global policy
absence. All file/crypto/driver/runtime boundaries remain explicit.
"""
import sys
sys.dont_write_bytecode = True

import array
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM
from analyze_native_sections import NativeImage, ROOT, BASE, EXPECTED
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image

OUT = ROOT / 'staging/native-player-heap-settings-boot/package-static'
REPORT = OUT / 'vpm-acceptance-preflight.json'
CFG = OUT / 'bounded-functions.json'
BACKUP = ROOT / 'backups/20261002T154458Z/files/Voice'
AUDIT = ROOT / 'evidence/firmware-analysis/native-mainmenu-prep-checkpoint-audit.json'
ENTRIES = (
    0x1d854e, 0x1d897c, 0x1d8514, 0x275590, 0x274acc, 0x274a8a,
    0x2734e6, 0x2754ca, 0x278194, 0x274992, 0x274978,
    0x240498, 0x2741f4, 0x2747cc, 0x2745cc, 0x273e52, 0x273abc,
    0x222a34, 0x2229c4, 0x2744f6, 0x274452, 0x274488, 0x240aa2,
    0x2d3166, 0x2d32de, 0xfe648, 0xfea50, 0x1e86ce, 0x1e8046,
    0x31d09a, 0x31d032, 0x31cfe4, 0x1fdc0c, 0x24e790,
    0x3a1318, 0x3a0e2a, 0x39e9e6, 0x31cf22, 0x1fde12, 0x2d3380,
    0x1fb304, 0x1fb3a2, 0x1fb3ce, 0x1fb3e4, 0x1fb2f8,
    0x2fba70, 0x2fb988, 0x122fbc, 0x123f6c, 0x123920,
    0x23c3c4, 0x3b3268, 0x3b3294, 0x38a398, 0x3b331a, 0x2356bc,
    0x102d32, 0x04400054, 0x044004fc, 0x04400542,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def rel(path):
    return str(path.relative_to(ROOT))


class RuntimeImage:
    def __init__(self, stock):
        self.stock = stock
        self.md = stock.md

    def read(self, address, length):
        return self.stock.read(self.stock.runtime_to_load(address, length), length)

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]


def wide(image, address, limit=256):
    raw = image.read(address, limit)
    end = next((n for n in range(0, len(raw), 2) if raw[n:n+2] == b'\0\0'), len(raw))
    return raw[:end].decode('utf-16le')


def functions(stock, image):
    result = {}
    for address in ENTRIES:
        fn = trace(image, address, 3500)
        require(not fn['instruction_limit_reached'], 'CFG limit: ' + hex(address))
        require(not fn['unresolved_exits'], 'Unresolved CFG: ' + hex(address))
        fn['entry_runtime'] = hex(address)
        fn['entry_load'] = hex(stock.runtime_to_load(address, 2))
        fn['bounded_CFG_not_transitive_call_closure'] = True
        fn['direct_call_targets'] = sorted({r['direct_call'] for r in fn['instructions']
                                            if 'direct_call' in r})
        indirect, returns = [], []
        for index, row in enumerate(fn['instructions']):
            a = int(row['address'], 16)
            ins = next(image.md.disasm(image.read(a, 4), a, count=1))
            row['bytes'] = ins.bytes.hex()
            row['load_address'] = hex(stock.runtime_to_load(a, ins.size))
            if ins.mnemonic == 'blx' and ins.operands[0].type != ARM_OP_IMM:
                indirect.append({'address': hex(a), 'instruction': row['instruction'],
                    'preceding_instructions': fn['instructions'][max(0, index-5):index],
                    'following_instructions': fn['instructions'][index+1:index+4]})
            if ins.mnemonic == 'bx' and ins.op_str != 'lr':
                # Existing bounded tracer treats BX as terminal. Preserve its
                # exact predecessor; do not silently call every BX a return.
                previous = fn['instructions'][index-1] if index else None
                known_return = bool(previous and previous['instruction'] == 'pop {' + ins.op_str + '}')
                returns.append({'address': hex(a), 'instruction': row['instruction'],
                    'saved_LR_pop_return_pattern': known_return,
                    'previous_instruction': previous,
                    'other_indirect_target_unresolved': not known_return})
        fn['indirect_call_sites'] = indirect
        fn['non_LR_BX_terminals'] = returns
        fn['instruction_bytes_sha256'] = sha(b''.join(bytes.fromhex(r['bytes'])
                                                    for r in fn['instructions']))
        result[hex(address)] = fn
    return result


def assert_instructions(image):
    expected = {
        0x1d8632: 'bl #0x275590', 0x1d8638: 'beq #0x1d868a',
        0x1d8a12: 'bl #0x275590', 0x1d8a18: 'beq #0x1d8a66',
        0x1d8a26: 'bne #0x1d8a66', 0x1d8a2e: 'cmp r0, #1',
        0x1d8a32: 'bl #0x278194', 0x1d8a42: 'bne #0x1d8a66',
        0x1d8a4a: 'bne #0x1d8a66', 0x1d8a62: 'bl #0x274992',
        0x2755ca: 'str r1, [r7, #0x24]', 0x275442: 'ldr r0, [pc, #0x3ec]',
        0x27544a: 'bl #0x2734e6', 0x275aa4: 'bl #0x1fb304',
        0x275ab4: 'bl #0x1fb3a2', 0x275ac4: 'bl #0x45dd40',
        0x275aca: 'beq #0x275ad0', 0x275acc: 'movs r4, #0',
        0x2404b0: 'beq #0x2404d0', 0x2404c0: 'beq #0x2404d0',
        0x2404c2: 'bl #0x23c3c4', 0x2404c8: 'bne #0x2404d0',
        0x2404ca: 'str r6, [r4, #4]', 0x2404d0: 'str r5, [r4, #4]',
        0x274804: 'movs r4, r0', 0x274810: 'bne #0x27481c',
        0x274816: 'bl #0x3316ec', 0x27482a: 'movs r0, r4',
        0x1d8528: 'bl #0x2d3166', 0x1d852e: 'bne #0x1d8548',
        0x1d853e: 'beq #0x1d8548', 0x1d8542: 'bl #0xfea50',
        0x1d8546: 'b #0x1d854a', 0x1d854a: 'movs r0, r5',
        0x3b32a2: 'blx r2', 0x3b32a8: 'movs r7, #0',
        0x3b32c2: 'bhs #0x3b32c8', 0x3b32c4: 'movs r7, #4',
        0x3b32e0: 'blx r7', 0x3b32ee: 'bl #0x38a398',
        0x38a398: 'movs r0, #0xb', 0x38a39a: 'bx lr',
        0x3b32f8: 'movs r0, #8', 0x3b3306: 'bls #0x3b330a',
        0x3b3308: 'movs r7, #9', 0x3b332a: 'movs r0, #2',
        0x3b3332: 'blx r1', 0x2356cc: 'cmp r2, #3',
        0x2356d0: 'cmp r2, #4', 0x2356d4: 'cmp r2, #5',
        0x2356e6: 'movs r0, #6', 0x235700: 'str r5, [r6, r3]',
        0x235710: 'movs r0, #5', 0x23c438: 'movs r4, #0xb',
        0x23c44a: 'subs r0, r0, r5', 0x23c456: 'str r0, [r7, #0x28]',
        0x1fdcb8: 'blx r2', 0x1fdd74: 'blx r1', 0x1fde86: 'blx r5',
        0x3a131c: 'bl #0x3a0e2a', 0x275528: 'bl #0x31d09a',
        0x275538: 'bl #0x31cf22', 0x275546: 'add r0, sp, #0x1c',
        0x275548: 'blx #0x27a2e4', 0x27554e: 'bl #0x358fdc',
    }
    rows = []
    for a, wanted in expected.items():
        ins = next(image.md.disasm(image.read(a, 4), a, count=1))
        got = ins.mnemonic + ' ' + ins.op_str
        require(got == wanted, f'{a:#x}: {got} != {wanted}')
        rows.append({'address': hex(a), 'bytes': ins.bytes.hex(), 'instruction': got})
    require(image.word(0x275830) == 0x764, 'Checksum field offset changed')
    require(wide(image, 0x275814) == '<dll_chksum>', 'Checksum tag changed')
    require(wide(image, 0x2757f0) == '%i', 'Checksum format changed')
    require(wide(image, 0x275898) == '.unl', 'License helper is not expected UNL path')
    require(image.read(0x23c4e8, 11) == b'dllimg.bin\0', 'Loader filename changed')
    require(image.read(0x275c3c, 11) == b'IMGEND.tst\0', 'END filename changed')
    return rows


def scan_calls(stock, targets):
    """Encoding candidates, not proof every matching byte is reachable code."""
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm.detail = True
    hits = []
    regions = [r for r in stock.copies if r['size'] >= 1000000]
    for region in regions:
        raw = stock.read(region['load_start'], region['size'])
        half = array.array('H', raw[:len(raw)//2*2])
        if sys.byteorder != 'little': half.byteswap()
        for n in range(len(half)-1):
            a, b = half[n:n+2]
            if a & 0xf800 != 0xf000 or b & 0xf800 != 0xf800: continue
            immediate = ((a & 0x7ff) << 12) | ((b & 0x7ff) << 1)
            if immediate & 0x400000: immediate -= 0x800000
            address = region['runtime_start'] + n*2
            target = address + 4 + immediate
            if target not in targets: continue
            ins = next(stock.md.disasm(raw[n*2:n*2+4], address, count=1), None)
            if ins and ins.mnemonic == 'bl' and ins.operands[0].imm == target:
                hits.append({'mode': 'Thumb BL', 'address': hex(address),
                    'load_address': hex(region['load_start']+n*2), 'target': hex(target),
                    'bytes': ins.bytes.hex(), 'conditional_copy': region['conditional']})
        words = array.array('I', raw[:len(raw)//4*4])
        if sys.byteorder != 'little': words.byteswap()
        for n, word in enumerate(words):
            blx = word & 0xfe000000 == 0xfa000000
            bl = word & 0x0f000000 == 0x0b000000 and word >> 28 != 15
            if not blx and not bl: continue
            immediate = (word & 0xffffff) << 2
            if immediate & 0x2000000: immediate -= 0x4000000
            address = region['runtime_start'] + n*4
            target = address + 8 + immediate + (((word >> 24) & 1)*2 if blx else 0)
            if target not in targets: continue
            ins = next(arm.disasm(raw[n*4:n*4+4], address, count=1), None)
            if ins and ins.mnemonic in ('bl', 'blx') and ins.operands[0].imm == target:
                hits.append({'mode': 'ARM ' + ins.mnemonic.upper(), 'address': hex(address),
                    'load_address': hex(region['load_start']+n*4), 'target': hex(target),
                    'bytes': ins.bytes.hex(), 'conditional_copy': region['conditional']})
    return {'regions': regions, 'targets': [hex(a) for a in sorted(targets)],
        'candidates': sorted(hits, key=lambda r:int(r['address'],16)),
        'indirect_or_computed_callers_excluded': False,
        'data_false_positives_excluded_for_all_hits': False,
        'live_conditional_copy_flag_verified': False}


def name_hits(raw, needle):
    return {'ASCII_offsets': [m.start() for m in re.finditer(re.escape(needle.encode()), raw)],
        'UTF16LE_offsets': [m.start() for m in re.finditer(re.escape(needle.encode('utf-16le')), raw)]}


def package_inventory(evidence):
    rows = []
    expected = {Path(r['file']).name:r for r in evidence['containers']}
    require(len(expected) == 13, 'Expected thirteen backup voices')
    for path in sorted(BACKUP.glob('*.vpm')):
        raw = path.read_bytes()
        old = expected[path.name]
        require(sha(raw) == old['sha256'], 'Backup differs from original inventory: ' + path.name)
        row = {'path':rel(path), 'bytes':len(raw), 'sha256':sha(raw)}
        if raw.startswith(b'AUDIMG'):
            row.update(format=raw[:9].decode('ascii'), parsed=False,
                native_TTS_container=False, embedded_signature_presence_or_policy_examined=False)
        else:
            files, geometry = parse_image(raw)
            for name in ('DLLIMG.BIN','DLLIMG.SIG','DLLINFO.TXT','IMGEND.TST'):
                require(name in files, 'Missing original member: ' + name)
            module, signature, info = (files[n]['content'] for n in
                                       ('DLLIMG.BIN','DLLIMG.SIG','DLLINFO.TXT'))
            tags = {m[1]:m[2] for m in re.finditer(r'<([a-z_]+)>([^<]*)</\1>', info.decode('ascii'))}
            require(len(signature) == 72, 'Unexpected original signature length')
            require(sum(module) & 0xffffffff == int(tags['dll_chksum'],0), 'Original additive sum mismatch')
            require(struct.unpack_from('<I',module,8)[0] == len(module), 'Original file header length mismatch')
            row.update(format='DSKIMG TTS', parsed=True, native_TTS_container=True,
                geometry=geometry, module_header_ram_bytes=struct.unpack_from('<I',module,4)[0],
                module_header_file_bytes=struct.unpack_from('<I',module,8)[0],
                metadata_identity={k:tags[k] for k in ('part_nmbr','ver_nmbr','dll_file','vol_name','lang_enum','dll_cp','sample_rate')},
                additive_byte_sum=sum(module)&0xffffffff,
                members={n:{k:v for k,v in files[n].items() if k!='content'}
                         for n in ('DLLIMG.BIN','DLLIMG.SIG','DLLINFO.TXT','IMGEND.TST')},
                signature={'bytes':72, 'sha256':sha(signature), 'first8_bytes':signature[:8].hex(),
                    'remaining_bytes':64, 'algorithm':None, 'first8_semantics':None,
                    'size_is_not_evidence_of_RSA_DSA_ECDSA_or_checksum':True},
                module_name_search={needle:name_hits(module,needle) for needle in
                                    ('dllimg.sig','DLLIMG.SIG','.sig','.SIG','signature','Signature')})
        rows.append(row)
    require(len(rows)==13 and sum(r['native_TTS_container'] for r in rows)==3, 'Backup count changed')
    return rows


def old_evidence_summary(path):
    data=json.loads(path.read_text())
    keys=('case_count','all_passed','stock_metadata_function_uses_only_dllinfo_and_END_files',
        'dll_checksum_or_SIG_not_an_acceptance_gate_in_tested_metadata_function',
        'stale_checksum_and_zero_SIG_loaded_only_under_declared_fixtures',
        'real_outer_storage_mount_and_live_platform_values_verified',
        'global_signature_policy_absence_proven','device_package_acceptance_verified',
        'actual_filesystem_driver_table_board_storage_cache_settings_initializer_verified',
        'real_modified_package_acceptance_or_signature_policy_verified','device_install_candidate')
    return {'path':rel(path),'sha256':sha(path.read_bytes()),
        'historical_proof_not_rerun':True,'claims':{k:data[k]for k in keys if k in data},
        'limits':data.get('limits'),
        'cases_summary':[{k:c[k] for k in ('name','voice','kind','passed','metadata_status','metadata_open_attempts') if k in c}
                         for c in data.get('cases',[])],
        'RAM_only_controls_summary':[{k:c[k] for k in ('name','voice','kind','passed','metadata_status') if k in c}
                         for c in data.get('memory_only_controls',[])]}


def check_registry(registry):
    require(all(sha((ROOT/p).read_bytes())==h for p,h in registry.items()),
            'A protected exact source changed')


def write_exclusive(path, data):
    with path.open('x', encoding='utf-8') as out:
        out.write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')


def main():
    require(not REPORT.exists() and not CFG.exists(), 'Outputs are immutable; use a new namespace')
    audit=json.loads(AUDIT.read_text())
    protected=audit['protected_sources']
    require(len(protected)==465, 'Expected frozen checkpoint 465 source registry')
    check_registry(protected)
    stock=NativeImage(); image=RuntimeImage(stock)
    paths=[Path(__file__), ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_sdp_activation.py', ROOT/'scripts/analyze_tts_vpm.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin', AUDIT,
        ROOT/'evidence/firmware-analysis/tts-vpm-containers.json']
    inventory_evidence=json.loads(paths[-1].read_text())
    inventory=package_inventory(inventory_evidence)
    paths.extend(ROOT/r['path'] for r in inventory)
    observations=assert_instructions(image)
    cfg=functions(stock,image)
    calls=scan_calls(stock,{0x23c3c4,0x3b3294,0x3b331a,0x2356bc,0x275590,
                           0x274acc,0x2754ca,0x3a1318,0x3a0e2a})
    old=[]
    for name in ('native-voice-metadata-emulation','native-voice-registry-emulation',
        'native-voice-selection-emulation','native-voice-outer-emulation',
        'native-voice-compatibility-emulation'):
        p=ROOT/'evidence/firmware-analysis'/f'{name}.json';paths.append(p)
        old.append(old_evidence_summary(p))
    manifests=[]
    for namespace in ('native-music-continuous','native-player-resources','native-player-menu-loaded'):
        p=ROOT/'staging'/namespace/'manifest.json';d=json.loads(p.read_text());paths.append(p)
        package=ROOT/d['package'];paths.append(package)
        require(sha(package.read_bytes())==d['package_sha256'], 'Frozen package hash mismatch')
        members,geo=parse_image(package.read_bytes())
        original_big5=next(row for row in inventory if Path(row['path']).name=='Chinese_Big5_MeiLing.vpm')
        require(members['DLLIMG.SIG']['sha256']==original_big5['members']['DLLIMG.SIG']['sha256'],
                'Original SIG not retained')
        manifests.append({'path':rel(p),'sha256':sha(p.read_bytes()),
            'claims':{k:d[k]for k in ('package','package_sha256','package_bytes',
                'combined_file_bytes','combined_ram_bytes','VM_MAIN_patch_bytes',
                'device_install_candidate','real_package_acceptance_verified','package_checks')},
            'actual_SIG_sha256':members['DLLIMG.SIG']['sha256'],
            'actual_SIG_matches_original_but_not_validated_for_modified_module':True,
            'actual_DLL_sha256':members['DLLIMG.BIN']['sha256'],
            'limits':d['limits']})
    paths=sorted(set(paths))
    before={rel(p):sha(p.read_bytes())for p in paths}
    signatures={needle:name_hits(stock.data,needle)for needle in
                ('dllimg.sig','DLLIMG.SIG','.sig','.SIG','signature','Signature')}
    for hits in signatures.values():
        for key in hits:
            hits[key]=[{'load_address':hex(BASE+n),'raw_MAIN_offset':n}for n in hits[key]]
    prefix=bytes.fromhex('8846040011020006')
    prefix_hits=[hex(BASE+m.start())for m in re.finditer(re.escape(prefix),stock.data)]
    requirements=[{'index':i,'volume_id':wide(image,0x9bb86c+i*0x24c,40),
        'minimum_text':wide(image,0x9bb86c+i*0x24c+0x226,10)}for i in range(94)]
    result={
        'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'model':'Taiwan nuvi2565RT','HWID':1352,'software':'8.00','MAIN_sha256':EXPECTED},
        'static_only':True,'all_static_assertions_passed':True,'bounded_CFG_count':len(cfg),
        'exact_instruction_assertions':observations,'source_sha256':before,
        'protected_checkpoint':{'path':rel(AUDIT),'sha256':before[rel(AUDIT)],
            'exact_source_count':len(protected),'all_hashes_match_before_after':True,
            'registry':protected},
        'backup_inventory':inventory,'voice_count':13,'TTS_count':3,'AUDIMG_count':10,
        'signature_search':{'raw_MAIN_bytes_examined':len(stock.data),'raw_MAIN_ASCII_UTF16LE':signatures,
            'shared_SIG_first8_bytes':prefix.hex(),'full_first8_MAIN_literal_hits':prefix_hits,
            'known_signature_word1_unaligned_accidental_hit':'0xea65c9 is within a conditional code pointer table, not a verifier witness',
            'two_signature_literals_context':'0x27B537 and0x6A7F33 are PNG signature diagnostics',
            'SIG_reader_caller_identified':False,'SIG_validation_algorithm_identified':False,
            'SIG_cryptographic_or_crc_classification':None,'SIG_enforcement_proven_absent':False,
            'complete_policy_search':False,
            'limitations':'Exact DLLIMG.SIG/.sig names absent in ASCII/UTF16LE MAIN and three original DLL modules. Names may be computed, other representations/boot modules/caches may exist; byte search is not enforcement proof. Three72-byte members with common8-byte prefix are opaque, not identified crypto.'},
        'direct_call_candidate_scan':calls,
        'bounded_callchain':[
            {'stage':'enumeration','entry':'0x1d897c','native_operations':['*.vpm inventory','1d8514 mapped bind','275590 metadata','2745cc duplicate ID','278194 type1 platform predicate','274992 sorted registry'],
             'failure_branches':['1D8A0A mapped-bind boolean0 skips','1D8A18 metadata0 skips','1D8A26 duplicate nonzero skips','type1 predicate0 falls back only type0 plus subtype1'],
             'not_verified':'Actual boot inventory/physical FAT mount, current storage/config/cache values.'},
            {'stage':'metadata','entry':'0x275590','opens':['dllinfo.txt','IMGEND.tst','dllinfo.txt'],
             'checks':['IMGEND first3 bytes equal END at275AC4/275ACA','Required nonempty identity/language/version fields near275B98..275BFC','record defaults inclchecksum FFFFFFFF at2755CA'],
             'checksum_action':'274ACC/27544A parses %i <dll_chksum> into record+0x764; this is numeric metadata, not a demonstrated byte-sum enforcement or CRC.',
             'optional_license':'2754CA changes outer filename suffix to.unl, reads25 bytes then decode27A2E4/parse358FDC and unit/record fields; not DLLIMG.SIG. Full license semantics not closed here.',
             'failure_status':0,'metadata_success_status':1,'SIG_open_in_this_bounded_function':False},
            {'stage':'selection','entry':'0x240498','requires':['2741F4 returns nonempty UTF16volume ID','2747CC returns nonzero','23C3C4 returns11'],
             'success':'selected index storeF095AC+4 at2404CA','failure':'storeFF at2404D0',
             'selector_return_not_dedicated_boolean':'240498 leaves return from loader/earlier helper; selected-index store is the explicit state evidence.'},
            {'stage':'mapped bind and activation','entry':'0x1d8514','chain':['2D3166→31D09A→1FDC0C→driverops+0','FE648 translation','FEA50→1E86CE→1E8046 DSKIMG parser'],
             'critical_scope':'1D8514 checks bind result0 and translateddrive!=80; callsFEA50 but returns preexistingr5=1 without testing itsr0. This wrapper boolean alone is not a mount-parser success witness.',
             'raw_branches':['1D852E','1D853E','1D8542','1D8546','1D854A'],
             'embedded_parser_checks':['DSKIMG/DSDIMG andGARMIN literals','sector512','allocation/header geometry'],
             'embedded_parser_DIRECT_call_targets':cfg['0x1e8046']['direct_call_targets']},
            {'stage':'compatibility','entry':'0x2747cc→222A34→2229C4','check':'94 volumeID records at9BB86C/stride24C; version text+226 compared through359820 mode2; unknown/low version fallback requires type0 subtype1/2.',
             'important_branch':'2747CC saves mount boolean inr4 at274804. Compatibility0 emitsdiagnostic409 but does not clear r4; returns r4 at27482A. Diagnostic alone is not selector rejection.',
             'minimum_table_matches':[r for r in requirements if r['volume_id'] in ('mei-lingb','mei-ling','jill')],
             'identity_is_not_HWID_or_signature':'Volume IDs/versions andplatform predicate storagekey13A/configbyte20 are distinct checks; no comparison with literal1352 identified here.'},
            {'stage':'component initialization','entry':'0x23c3c4','file':'dllimg.bin','chain':['3B3268 creates40 ARM export stubs','3B3294 actualcallbacks opens/seeks/tells/reads/closes','3B331A BLX loaded entry','2356BC exportregistration called byoriginalTTS initializer'],
             'descriptor':'0304BB74 with image02D4BB74, max00300000; callbackblock contains original1FB2F9/1FB305/1FB3A3/1FB3CF/1FB3E5',
             'statuses':{'trampoline_or_read_not11':'return thatcode','first execute6':'maps to11','execute5':'retry ABIhighword5→4→3→2→1→0 with050000 decremented010000','retry read_not11':'returns readcode','retry execute6':'returned6 unchanged','version_zero_exhaustion':'diagnostic409; returns saved executecode'},
             'no_SIG_callback_supplied':True},
            {'stage':'read and execute','entry':'0x3b3294→3b331a','status_branches':[
                {'condition':'open returnsNULL','branch':'3B32A6','status':0},
                {'condition':'actual file length>descriptor max3MiB','branch':'3B32C2','status':4},
                {'condition':'postprocess38A398!=11','branch':'3B32F6','status':8,'stock_postprocess':'38A398 immediately returns11'},
                {'condition':'loaded headerword+4 RAM length>max3MiB','branch':'3B3306','status':9},
                {'condition':'remaining read path','status':11},
                {'condition':'descriptor filename equalsInvalid','branch':'3B3328','status':2},
                {'condition':'valid name','entry_call':'3B3332 BLX r1=imagebase','status':'module-return'}],
             'not_checked_in_read_body':['fread returned length','DLL headerfileword+8 equalsactualfilelength','RAMword+4>=actualfilelength','minimalfileheaderlength','DLL byte-sum againstvoice record+764','DLLIMG.SIG'],
             'safety_interpretation':'Independent parser/header checks remain required candidate checks; this absence is not permission to exploit malformed loader input.'},
            {'stage':'export ABI','entry':'0x2356bc','accepts_version_highword':[3,4,5],
             'matching_lowword_status':11,'different_lowword_status':6,'unsupported_highword_status':5,
             'writes':'module exports[i]→loader trampolinebase+12*i+8 for module suppliedexportcount',
             'checks_not_seen':'No bounded exportcount40/maxRAM or pointerrange checks in thiscallback; preserve exact original40 ABI/counted arrays independently.',
             'signature_or_package_identity_check':False},
        ],
        'unclosed_native_boundaries':[
            {'site':'1FDCB8','dispatch':'driver record+18→fileops+0','static_type1_target':'3A1319→3A0E2A','gap':'Actualboot drive registration andphysicalstorage callbacktable/policy not recovered.'},
            {'site':'1FDD74','dispatch':'filedriver additionalop+18','gap':'Mode-dependent additional/truncateoperation is indirect; not aSIG witness.'},
            {'site':'1FDE86','dispatch':'filedriverreadops+8','static_type1_target':'3A132D','gap':'Physicaldriver reads in oldproof remain fixture, no currenthardwarestatus.'},
            {'site':'39EA36/39ECE0','dispatch':'lower blockdevicecallback+8','gap':'FATmount requires actualvolume/block I/O andcallbacks, outside bounded native acceptancechain.'},
            {'site':'275548/27554E','dispatch':'UNL decode27A2E4 / parse358FDC','gap':'Licensehelper is distinct fromSIG; no crypto class asserted, calleeclosure remainsunreviewed.'},
            {'site':'originalmodule BLX/conditionalcopies','gap':'Originalbootstrap imports99host functions/executesmodule; filename negatives do not cover alltransitive/indirect behavior. No realpackage boot/cache or possiblepolicy outsideMAIN proved.'},
        ],
        'historical_proofs_with_scope':old,'frozen_EMULATION_ONLY_manifest_comparison':manifests,
        'minimal_next_acceptance_boundaries':[
            {'priority':1,'work':'Read-only nativeboot registration / FATlowerdevice andvoice-cache provenance analysis','observe':['actualtype1ops86DF7C selectedbydrive','39E9E6 lowerdevicecallback origin','mappedrecord105E624 andstate105E424','F09638 cachedvoiceID/settings init'],'reason':'Old outerproof substitutes these; closes remainingpreselection policy boundary without assumingSIG absence.'},
            {'priority':2,'work':'Use a future NEW nativefixture to observe originalselection errors with physicaldriver contract represented explicitly','observe':['1D8514 versus actualFEA50/1E8046 return andactivevolume','allopen/readstatus/lengths','record+764 usage aftermetadata','preentry3B3332 boundary'],'authorized_in_this_static_run':False,'reason':'Booleanselect/mount wrapper doesnotproveparse acceptance; avoid executingunknown candidate first.'},
            {'priority':3,'work':'Prepare a separately reviewed resident single-bootstrapcandidate only afterpackage policy andrecovery conditions are established','required':['one coherentGUI+music initialization','original40 exports/TTS memory preserved','legalGUIentry andnativeownership/admissioncall-sites','noIRQ-activeunload/reset','exactoriginalbackup/restore hash andpreselectionrecovery procedure','no reliance on unchangedoriginalSIG toauthenticatechangedDLL'],'ready_now':False},
        ],
        'modified_VPM_accepted_on_device':False,'SIG_verifier_identified':False,
        'signature_algorithm':None,'signature_bypass_or_signed_package_generated':False,
        'safe_reversible_physical_candidate_ready':False,'device_install_candidate':False,
        'firmware_or_voice_package_mutated':False,'emulator_or_original_code_executed':False,
        'device_service_IO':False,'sounds_emitted':False,'canonical_state_modified':False,
        'limits':'Staticinstruction/byte assertions andoriginalbackup structural parsing only. Neither noSIG literal nor fixture zeroSIG success proves completepolicy absence or deviceacceptance. There is no identifiedDLLIMG.SIG caller/verifier/algorithm. Metadata additive checksum isnotCRC or cryptographic signature. Existing3MiB preserving packages remain EMULATION-ONLY; protocol/UI/ownership/nativekernel/hardwareproof remains separate. No signaturebypass, modifiedpackage generation ortransfer.'}
    check_registry(protected)
    require(before=={rel(p):sha(p.read_bytes())for p in paths}, 'Input changed during static review')
    OUT.mkdir(parents=True,exist_ok=True)
    write_exclusive(CFG,{'MAIN_sha256':EXPECTED,'functions':cfg,
        'limitations':'Each bounded Thumb CFG is not transitiveclosure; indirectcall sites/nonLRBXterminals retained explicitly. Conditional runtimeaddresses use exactstartupcopy bytes, not observedliveRAM.'})
    result['bounded_functions_artifact']={'path':rel(CFG),'sha256':sha(CFG.read_bytes())}
    write_exclusive(REPORT,result)
    print(json.dumps({'report':rel(REPORT),'sha256':sha(REPORT.read_bytes()),
        'bounded_CFGs':len(cfg),'exact_instruction_assertions':len(observations),
        'protected_sources_unchanged':len(protected),'SIG_verifier_identified':False,
        'device_install_candidate':False}))


if __name__=='__main__':
    main()
