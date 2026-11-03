#!/usr/bin/env python3
"""Read-only exact Taiwan mount/cached-voice/UNL provenance analysis.

All outputs are exclusive new static records. No emulation, signing, package
construction, bypass, live memory, device/service I/O, or old artifact writes.
"""
import sys
sys.dont_write_bytecode = True

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM
from analyze_native_sections import NativeImage, ROOT, BASE, EXPECTED
from analyze_sdp_activation import trace, BRANCHES
from analyze_native_vpm_acceptance_path import RuntimeImage, scan_calls, wide

OUT = ROOT / 'staging/native-player-settings-vfp-context/acceptance-static'
REPORT = OUT / 'acceptance-policy-provenance.json'
FUNCTIONS = OUT / 'bounded-functions.json'
PRIOR = ROOT / 'staging/native-player-heap-settings-boot/package-static/vpm-acceptance-preflight.json'
PRIOR_SHA = 'dd99f29c2f321befa0104a96c1ec96589cb99f12246d8e8d4c101309608b3009'
AUDIT = ROOT / 'evidence/firmware-analysis/native-heap-settings-checkpoint-audit.json'
ENTRIES = (
    0x3feef4, 0x3fe668, 0x3feabe, 0x3fe7e8, 0x3fe876,
    0x3fea36, 0x3fe9e0, 0x3fe9a8, 0x3fe712, 0x3fe75a,
    0x3fec80, 0x3feca4, 0x3fecd6,
    0x21b8f0, 0x31e60e, 0x217488, 0x2174b2, 0x217470,
    0x39e998, 0x24e968, 0x24e83a, 0x39e9e6,
    0x1d84c4, 0x2251c0, 0x224748, 0x224e70,
    0x225b18, 0x225acc, 0x22577c, 0x1e2cca,
    0x1e2f56, 0x1e2f62, 0x1e2bdc,
    0x1d8514, 0x1d84ec, 0xfea50, 0x1e86ce, 0x1e8046, 0x2fb988,
    0x24f260, 0x2748a0, 0x273c2a, 0x274846, 0x274232,
    0x273ca8, 0x23cd50, 0x23cd60, 0x273e18, 0x274572,
    0x2745a0, 0x23ce30, 0x23ce06, 0x23cd9c, 0x23cdbc, 0x23cd64,
    0x2cad0a, 0x2cabbc, 0x2cab14, 0x254b2e,
    0x275590, 0x2754ca, 0x358fdc, 0x3985d8, 0x2caee2,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rel(path):
    return str(path.relative_to(ROOT))


def check_hashes(registry):
    require(all(sha((ROOT/path).read_bytes()) == digest for path, digest in registry.items()),
            'Frozen dependency changed')


def collect_functions(stock, image):
    functions = {}
    for start in ENTRIES:
        fn = trace(image, start, 3500)
        require(not fn['instruction_limit_reached'], 'CFG exhausted: ' + hex(start))
        require(fn['instructions'], 'Empty CFG: ' + hex(start))
        fn['entry_load_address'] = hex(stock.runtime_to_load(start, 2))
        fn['bounded_CFG_is_not_transitive_call_closure'] = True
        fn['direct_calls'] = []
        fn['indirect_calls'] = []
        fn['non_LR_BX_terminals'] = []
        rows = fn['instructions']
        for index, row in enumerate(rows):
            address = int(row['address'], 16)
            ins = next(image.md.disasm(image.read(address, 4), address, count=1))
            row['bytes'] = ins.bytes.hex()
            row['load_address'] = hex(stock.runtime_to_load(address, ins.size))
            if 'direct_call' in row:
                fn['direct_calls'].append({'site': hex(address), 'target': row['direct_call']})
            if ins.mnemonic == 'blx' and ins.operands[0].type != ARM_OP_IMM:
                fn['indirect_calls'].append({'site': hex(address), 'instruction': row['instruction'],
                    'context': rows[max(0,index-5):index+3]})
            if ins.mnemonic == 'bx' and ins.op_str != 'lr':
                # Saved-LR POP can precede stack adjustment or return-value
                # setup. Preserve that pattern, not an invented function call.
                previous = rows[max(0,index-4):index]
                pops = [r for r in previous if r['instruction'] == 'pop {' + ins.op_str + '}']
                fn['non_LR_BX_terminals'].append({'site': hex(address),
                    'instruction': row['instruction'], 'preceding': previous,
                    'saved_LR_pop_pattern_present': bool(pops),
                    'unresolved_indirect_tail': not bool(pops)})
        fn['instruction_bytes_sha256'] = sha(b''.join(bytes.fromhex(r['bytes']) for r in rows))
        functions[hex(start)] = fn
    return functions


def arm_memory_move(image):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    raw = image.read(0x27a2e4, 0x80)
    instructions = [{'address':hex(i.address), 'bytes':i.bytes.hex(),
        'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(raw,0x27a2e4)]
    by_address = {int(r['address'],16):r for r in instructions}
    for address, wanted in {
        0x27a2e4:'subs r3, r0, r1', 0x27a2ec:'bls #0x39129c',
        0x27a31c:'ldmdb r1!, {r3, r4, ip, lr}',
        0x27a324:'stmdb r0!, {r3, r4, ip, lr}', 0x27a360:'bx lr',
    }.items():
        require(by_address[address]['instruction']==wanted, 'ARM move changed')
    return {'entry':'0x27a2e4','bytes_sha256':sha(raw), 'instructions':instructions,
        'observed_behavior':'Overlap test, forward-copy tail branch to 39129C, backward byte/halfword/word/LDM-STM copying. This is a memory-move routine, not evidence of UNL decryption.',
        'native_executed':False}


def exact_assertions(image):
    expected = {
        0x3fef34:'bl #0x3fe668', 0x3fef4c:'bl #0x21b8f0',
        0x3fe688:'str r6, [r0, #0x24]', 0x3feafc:'adds r1, #0xc',
        0x3feafe:'blx r2', 0x3feb40:'str r0, [r4, #0x6c]',
        0x3feb44:'str r0, [r4, #0x70]', 0x3feb48:'str r0, [r4, #0x74]',
        0x3feb5c:'str r0, [r5, #0xc]', 0x3feb72:'str r0, [r4, #0x78]',
        0x3feb8e:'str r0, [r5, #0xc]', 0x3febc6:'bl #0x3fe7e8',
        0x3fe826:'strb r7, [r4, #8]',
        0x3fe82e:'ldr r3, [sp, #8]', 0x3fe830:'bl #0x24e83a',
        0x3fe834:'movs r6, r0', 0x3fe840:'strb r6, [r3, #1]',
        0x3fe84c:'beq #0x3fe858', 0x3fe850:'strb r0, [r4, #8]',
        0x3fe852:'movs r0, #0xa1', 0x3fe858:'movs r0, #0xa0',
        0x3fe85c:'strb r7, [r4, #8]',
        0x24e8a0:'str r1, [r4, #0x20]', 0x24e8a6:'blx r1',
        0x24e8aa:'bne #0x24e8b0', 0x24e8ae:'strb r0, [r4]',
        0x39ea2e:'ldr r5, [r1, #8]', 0x39ea36:'blx r5',
        0x39ea38:'cmp r0, #1', 0x39ece0:'blx r5',
        0x39ed24:'movs r7, #0x11', 0x39edd8:'str r0, [r6, #0x18]',
        0x39eddc:'str r0, [r6, #0x1c]', 0x39ede0:'str r0, [r6, #0x24]',
        0x39edfa:'movs r0, r7',
        0x3feaa8:'ldr r7, [r3, #0xc]', 0x3feab6:'blx r7',
        0x1d84c8:'bl #0x2251c0', 0x1d84d8:'str r1, [r4]',
        0x1d84dc:'str r1, [r4, #4]', 0x225b48:'bl #0x225acc',
        0x225b6e:'bl #0x225acc', 0x1e2ea6:'blx r7',
        0x1e86b6:'movs r2, #1', 0x1e86b8:'strb r2, [r0, r1]',
        0x2fb9c6:'ldrb r1, [r0, r5]', 0x2fb9ca:'bne #0x2fb9d2',
        0x1e899c:'bl #0x1e8046', 0x1e89a2:'bl #0x3008b0',
        0x24f2b6:'bl #0x2748a0', 0x2748ca:'bl #0x274232',
        0x2748d4:'bl #0x3598b8', 0x2748da:'strh r5, [r0, #0x26]',
        0x274248:'bl #0x23cd60', 0x27426a:'bl #0x23cd50',
        0x27427e:'bl #0x23cd50', 0x27458c:'bl #0x3598b8',
        0x274592:'strh r0, [r4, #0x26]',
        0x23ce44:'bl #0x23ce06', 0x23ce50:'bl #0x2cad0a',
        0x23cd74:'bl #0x2ca82c', 0x2745aa:'bl #0x23cd9c',
        0x2745be:'bl #0x23cdbc', 0x2cad4c:'blx #0x3732c8',
        0x275614:'bne #0x2756f8', 0x2756f8:'b #0x275a9c',
        0x275a48:'bl #0x2754ca', 0x275548:'blx #0x27a2e4',
        0x27554e:'bl #0x358fdc', 0x358fec:'bl #0x3985d8',
        0x359018:'lsls r0, r0, #0x18', 0x359020:'cmp r0, r1',
        0x359024:'movs r0, #3', 0x359030:'movs r0, #0',
    }
    records = []
    for address,wanted in expected.items():
        ins=next(image.md.disasm(image.read(address,4),address,count=1))
        got=ins.mnemonic+' '+ins.op_str
        require(got==wanted,f'{address:#x}: {got} != {wanted}')
        records.append({'address':hex(address),'bytes':ins.bytes.hex(),'instruction':got})
    for address,value in {0x3fea74:0x1d84c5,0x3feebc:0x3fea37,
            0x3feec0:0x3fe9e1,0x3feec4:0x3fe9a9}.items():
        require(image.word(address)==value,'Callback literal changed')
    for address,value in {0x1d84d6:0x225b19,0x1d84da:0x225c15}.items():
        ins=next(image.md.disasm(image.read(address,4),address,count=1))
        pool=((address+4)&~3)+ins.operands[1].mem.disp
        require(image.word(pool)==value,'Original query callback changed')
    require(wide(image,0x23ce70,32)=='jill','Preference default changed')
    require(wide(image,0x274bf4,32)=='jill','Enumeration fallback changed')
    return records


def metadata_subgraph(image, function):
    nodes={int(row['address'],16):row for row in function['instructions']}
    pending=[0x275a9c]; seen=set();exits=[]
    while pending:
        address=pending.pop()
        if address in seen:continue
        if address not in nodes:
            exits.append(hex(address));continue
        seen.add(address)
        ins=next(image.md.disasm(image.read(address,4),address,count=1))
        if ins.mnemonic=='bx' or (ins.mnemonic=='pop' and 'pc' in ins.op_str):continue
        if ins.mnemonic in BRANCHES:
            pending.append(ins.operands[0].imm)
            if ins.mnemonic=='b':continue
        pending.append(address+ins.size)
    require(len(seen)==160 and 0x275a48 not in seen and 0x275b7a in seen,
            'DLLINFO-present path no longer characterized')
    return {'entry':'0x275a9c','selection':'275614 BNE when initial dllinfo fopen is nonNULL; 2756F8 tail branch',
        'reachable_instruction_count':len(seen),'instructions':[nodes[a]for a in sorted(seen)],
        'missing_nodes':sorted(set(exits)), 'UNL_call_275A48_reachable':False,
        'END_check_and_DLLINFO_parser_reachable':True,
        'limited_to_original_275590_intrafunction_graph':True,
        'transitive_or_global_UNL_SIG_absence_proven':False}


def literal_provenance(stock, image, values):
    output={}
    for value in values:
        pools=[BASE+m.start() for m in re.finditer(re.escape(struct.pack('<I',value)),stock.data)
               if m.start()%4==0]
        loads=[]
        for pool in pools:
            for address in range(max(BASE,pool-1024),pool,2):
                word=struct.unpack('<H',stock.read(address,2))[0]
                if word&0xf800==0x4800 and ((address+4)&~3)+(word&255)*4==pool:
                    ins=next(image.md.disasm(image.read(address,4),address,count=1))
                    loads.append({'site':hex(address),'pool':hex(pool),'bytes':ins.bytes.hex(),
                                  'instruction':ins.mnemonic+' '+ins.op_str})
        output[hex(value)]={'aligned_raw_word_pools':[hex(p)for p in pools],
            'normal_Thumb_literal_load_candidates':loads,
            'ARM_dynamic_or_conditional_literal_consumers_excluded':False}
    return output


def write_exclusive(path, data):
    with path.open('x',encoding='utf-8') as out:
        out.write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')


def main():
    require(not REPORT.exists() and not FUNCTIONS.exists(),'Immutable outputs already exist')
    require(sha(PRIOR.read_bytes())==PRIOR_SHA,'Frozen preflight changed')
    audit=json.loads(AUDIT.read_text());protected=audit['protected_sources']
    require(len(protected)==535,'Expected current frozen535 registry')
    check_hashes(protected)
    stock=NativeImage();image=RuntimeImage(stock)
    sources=[Path(__file__), ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_sdp_activation.py',ROOT/'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin',PRIOR,AUDIT,
        ROOT/'backups/20261002T154458Z/verification.json']
    before={rel(p):sha(p.read_bytes())for p in sources}
    functions=collect_functions(stock,image)
    assertions=exact_assertions(image)
    memmove=arm_memory_move(image)
    subgraph=metadata_subgraph(image,functions['0x275590'])
    calls=scan_calls(stock,{0x3feef4,0x3fe7e8,0x3feabe,0x24e83a,0x21b8f0,
        0x2748a0,0x274572,0x23ce30,0x23cd50,0x23cd60,0x23cd9c,0x23cdbc})
    pools=literal_provenance(stock,image,[0xf09638,0xf09664,0x344c844,0x344c874,
        0x2cea340,0x2cea408,0x86df64,0x86df7c])
    initialized_cache=image.read(0xf09638,0x30)
    descriptor=struct.unpack('<9I',image.read(0x8dcea8,36))
    require(descriptor[0]==0x3fecd7,'Filesystem task entry changed')
    unresolved={entry:fn['unresolved_exits']for entry,fn in functions.items()if fn['unresolved_exits']}
    result={
        'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'model':'Taiwan nuvi2565RT','HWID':1352,'software':'8.00','MAIN_sha256':EXPECTED},
        'static_only':True,'all_exact_assertions_passed':True,
        'bounded_CFG_count':len(functions),'bounded_CFG_unresolved_exits':unresolved,
        'instruction_assertions':assertions,'source_sha256':before,
        'protected_checkpoint':{'path':rel(AUDIT),'sha256':before[rel(AUDIT)],
            'source_count':len(protected),'all_exact_hashes_unchanged_before_after':True,'registry':protected},
        'prior_acceptance_preflight':{'path':rel(PRIOR),'sha256':PRIOR_SHA,'unchanged':True},
        'direct_call_candidates':calls,'literal_reference_candidates':pools,
        'original_mount_callback_provenance':{
            'boot':'3FEEF4 clears two contexts at 02CEA340, stride 200, and two 16-byte partition records at 02CEA4D0; calls 3FE668 then 21B8F0.',
            'original_filesystem_task_descriptor':{'address':'0x8dcea8','words':[hex(v)for v in descriptor],
                'entry':'0x3fecd7','construction_sites':['3FEF3E→358BF8','3FEF48→2FBBBE'],
                'actual_task_started_or_storage_event_received':False},
            'type1_registration':'21B8F0→31E60E→217488 initializes the type table; 39E998→2174B2 installs descriptor 86DF64 at type 1. Type descriptor+8 is mount callback 39E9E7.',
            'device_query':'3FE668 installs 1D84C5 at context+A4. 3FEABE calls it via 3FEAFE with r0=device byte and r1=context+C. 1D84C4→2251C0 obtains original device metadata, then installs read 225B19/write 225C15 at context+C/+10.',
            'descriptor_construction':'3FEB40 installs 3FEA37 at context+6C=block descriptor+8; 3FEB44 installs 3FE9E1 at +70; 3FEB48 installs 3FE9A9 at +74. Header starts at context+64; native query metadata at context+60 supplies sector/flags.',
            'partition_mount_call':'3FE7E8 reads context+BC partition table, stride 16: +9 volume index, +B filesystem type, +C flags. 3FE826 premarks partition+8=1. 3FE82E sets r3=context+64; 3FE830→24E83A. 24E8A0 publishes this pointer as volume record+20 before the indirect mount callback 39E9E6.',
            'FAT_mount_READ_39EA36_39ECE0':'39E9E6 reads driver record+20→descriptor+8; the identified original writer resolves callback 3FEA36. It requests one block and requires returned count 1 at 39EA38/39ECE2.',
            'read_dispatch':'3FEA36 checks partition byte+8 (also premarked during mount), index<2, partition count/LBA bounds, parent context byte0 identity and context+A1 availability, then 3FEAB6 calls context+8C; relative LBA is translated by partition+0.',
            'cache_branch':'3FEB5C publishes 1E2CCB into context+8C, stores original query read 225B19 into context+78. 1E2CCA cache path has an indirect read at 1E2EA6; physical execution and completion remain unobserved.',
            'direct_branch':'When context+C4 cache flag is zero, 3FEB8E copies original query read from context+C to context+8C, expected 225B19. 225B18→225ACC→22577C reaches unresolved switch 2257EC.',
            'no_native_execution_claim':True,
            'remaining_dynamic_values':['Which physical device/context is the outer voice drive','Partition 0/1 filesystem type/flags/LBA/size','Actual query 2251C0 status','Context+C4 cache flag','Native cache/runtime callbacks and block I/O completion'],
            'SIG_or_UNL_check_identified_in_mount_wrappers':False,
            'all_physical_block_IO_or_transitive_policy_closed':False},
        'mount_success_witnesses':{
            'generic_FAT':{'dispatcher':'24E83A','success_return':0,
                'publication':['39E9E6 r7=0 at return 39EDFA','Fileops 86DF7C→record+18 at 39EDD8','Other ops 86DF9C→record+1C at 39EDDC','Retained FS handle→record+24 at 39EDE0','24E8AE sets record+0=1 only if mount callback returns 0'],
                'errors':{'24E84C':14,'24E856':15,'24E86A':16,'24E87A':1,
                    '39EA06':'1 allocation failure','39ECE6':'1 block-read count failure','39ED24':'17 FAT32 FSInfo structural marker mismatch'},
                'partition_marker_alone_is_not_success':'3FE826 writes partition+8=1 before calling 24E83A; it is an in-progress read-admission marker. Failure clears it at 3FE850. Observe callback status and volume record publication as well.',
                'dispatcher_events':'3FE7E8 sends event 9F with volume/status, then A0 on status 0 retaining partition+8=1, A1 on nonzero clearing partition+8. These are static branches; no delivered native event was observed.',
                'structural_checks_are_not_crypto':['Boot sector marker 0xAA55 at 39EA4C/39EA4E','FAT32 FSInfo marker 0x61417272 at 39ED1C/39ED20'],
                'physical_success_observed':False},
            'embedded_DSKIMG':{'parser':'1E8046','context':'F7B3DC',
                'volume_array_pointer':'context+1C','volume_stride':116,
                'active_write':'1E86B6 mov 1; 1E86B8 stores byte 1 at array+index*116 only on parser r5==0 path',
                'reader_checks_active':'2FB9C6/2FB9CA rejects inactive volume; original 2FB988 then resolves directory/read operations',
                'remount_r0_not_parser_result':'1E899C calls the parser, then 1E89A2 calls unlock. 1E86CE does not preserve parser r0 as a return witness; 1D8514 also ignores FEA50 return. Observe published active volume and actually opened/read member bytes.',
                'static_paths_not_hardware_mount':True},
            'module_entry_is_separate':'Neither FAT nor DSKIMG active flag certifies metadata identity, original 40-export ABI, modified SIG acceptance or safe component lifecycle.'},
        'cached_voice_and_settings_provenance':{
            'current_cache':'F09638, slot stride 42; first 20 UTF16 units hold the current volume ID; mapped-region byte at slot+28 (base F09660) starts at 19 in exact initialized data.',
            'initialized_cache':{'runtime':'0xf09638','load':hex(stock.runtime_to_load(0xf09638,len(initialized_cache))),
                'bytes':initialized_cache.hex(),'sha256':sha(initialized_cache),
                'empty_ID_at_startup':initialized_cache[:40]==bytes(40),'actual_live_ID_verified':False},
            'boot_chain':['24F260→2748A0','2748A0→273C2A enumeration /274846 optional voice path','274232 preference resolver','23CD60 returns pointer 344C874, saved filename; 23CD50 returns 344C844+slot*560, saved volume ID','2748D4 copies 19 UTF16 units→F09638; 2748DA terminates +26'],
            'resolver_branches':'If the registry is empty, output is empty. With a saved filename, 273CA8 resolves the record, then 2741F4 gets its volume ID; empty lookup falls back to the saved volume ID. With an empty saved filename, 23CD50 directly provides the default/persisted ID.',
            'settings_initializer':'23CE30 initializes mutex 344CA74 and handle F095B4; 23CE06 defaults volume ID to jill, type word+28=1, word+2C=2, empty filename+30. 23CE50→2CAD0A requests key 118D, at most 22E bytes, into 344C844.',
            'storage_read_scope':'2CAD0A checks storage initialized at F06EF4+3, calls 2CABBC→2CAB14, copies only a positive returned length limited to 22E. Persistent contents and final default versus loaded ID are unknown; USB logical backup does not expose the whole NOR/settings store.',
            'runtime_cache_setter':'274572 locks 344CF00, writes 19 UTF16 units to F09638+slot*42, terminates +26. Identified normal callers 254EE4/25554E use the 2741F4 volume-ID result before mount/activation flow.',
            'persistent_setter_is_distinct':'2745A0→23CD9C(volume ID)/23CDBC(filename)→23CD64 writes key 118D/22E via 2CA82C, using 0344C844 and F095B4; this does not directly write F09638.',
            'original_boot_2748A0_callers':['24F2B6','1D8972','254DBA'],
            'default_jill_does_not_prove_current_device_voice':'Three TTS backup files are inventory only. A modified Big5 package cannot be assumed selected merely from the Taiwan model; the current selected ID is unread.',
            'no_seeded_cache_or_settings_success':True},
        'UNL_policy_distinct_from_DLLIMG_SIG':{
            'DLLINFO_present_subpath':subgraph,
            'branch_scope':'Normal TTS DLLINFO-present entry 275A9C cannot reach UNL call 275A48 within 275590. The UNL helper belongs to the dllinfo-missing legacy metadata fallback; it is not evidence of TTS DLLIMG.SIG authentication.',
            'filename_and_read':'2754CA replaces the outer voice filename suffix with .unl, opens via 31D09A, reads 25 bytes via 31CF22. Unit value 2CAEE2 returns F06EF4+20 only when storage is initialized; the helper has a unit-value==1 early-accept branch. No branch is forced here.',
            'memory_copy_not_decryption':memmove,
            'UNL_parser':'358FDC→3985D8 decodes formatted fields; computed switch 3987DA in 3985D8 remains unresolved. 358FF4..359020 sums decoded fields/truncated bytes and compares low 8 bits; mismatch returns 3, match returns 0. This is observed additive 8-bit integrity; CRC or public-key signature is not identified.',
            'unit_and_record_checks':'275556 compares decoded word0 with unit value; unless record language==FFFF, it compares language/subfields at decoded+8/+C/+10/+14. The helper returns 1/0; the legacy caller stores its result flag at record+76E.',
            'license_decode_algorithm_fully_identified':False,
            'SIG_reader_algorithm_or_enforcement_identified':False,
            'global_signature_policy_absent':False,
            'no_UNL_generation_or_acceptance_bypass':True},
        'next_readonly_or_separate_runtime_boundaries':[
            {'priority':1,'boundary':'Native physical-device query/block completion: 22577C switch 2257EC remains unresolved; the original callback writers are now identified.',
             'needed_observations':['02CEA340/02CEA408 query-filled fields +0C/+10/+60..64','Partition 02CEA4D0 byte8/LBA/count/filesystem type, including premark and completion','Actual 24E83A result 0 and published volume-record active/fileops 86DF7C','Actual 1E8046 embedded-volume active state and unaltered member reads'],
             'emulation_or_device_execution_authorized_in_this_script':False},
            {'priority':2,'boundary':'Native voice preference 23CE30→2CAD0A must complete using an explicit storage contract before 24F260/2748A0; observe F095B4/344C844/F09638 and selected index F095AC+4.',
             'reason':'Existing seeded F09638 cache fixtures cannot prove original boot/current voice or modified voice selection.'},
            {'priority':3,'boundary':'Retain modified packages as EMULATION-ONLY until the accepted modified-member path and safe resident GUI/music initialization have independent proof.',
             'reason':'Resolved FAT callback provenance and bounded TTS UNL exclusion are static progress; SIG policy absence and hardware acceptance remain unproven. The legacy UNL format decoder at 3987DA is still unresolved.'}],
        'modified_package_accepted_on_device':False,'device_install_candidate':False,
        'signed_or_bypass_package_generated':False,'old_artifacts_sources_canonical_modified':False,
        'emulator_or_native_code_execution':False,'device_service_IO':False,'sounds_emitted':False,
        'limits':'Exact MAIN static bytes/branches and file-backed startup-copy mapping only. Callback addresses now trace original writers, but live physical drive/query/cache/task/storage values are unknown. Firmware/boot code outside MAIN and transitive/computed policy are not closed. The normal TTS UNL call is unreachable within the bounded 275590 subpath; this does not prove DLLIMG.SIG enforcement absent elsewhere. No modified VPM, signature/key/license generation, device installation or safe unload proof.'}
    check_hashes(protected)
    require(before=={rel(p):sha(p.read_bytes())for p in sources},'Inputchangedduringanalysis')
    OUT.mkdir(parents=True,exist_ok=True)
    write_exclusive(FUNCTIONS,{'MAIN_sha256':EXPECTED,'functions':functions,
        'unresolved_exits':unresolved,'limits':'Bounded function graphs with all raw instruction bytes/load addresses; indirect/computed exits remain explicit. No execution or transitive closure claim.'})
    result['functions_artifact']={'path':rel(FUNCTIONS),'sha256':sha(FUNCTIONS.read_bytes())}
    write_exclusive(REPORT,result)
    print(json.dumps({'report':rel(REPORT),'sha256':sha(REPORT.read_bytes()),
        'bounded_CFGs':len(functions),'unresolved_CFGs':len(unresolved),
        'instruction_checks':len(assertions),'protected_sources':len(protected),
        'SIG_enforcement_identified':False,'device_install_candidate':False}))


if __name__=='__main__':
    main()
