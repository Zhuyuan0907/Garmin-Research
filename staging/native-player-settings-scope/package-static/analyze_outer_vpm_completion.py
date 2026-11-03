#!/usr/bin/env python3
"""Read-only original outer-VPM completion and actual FAT32 input contract.

No emulator is imported, no package is generated, and no device is accessed.
The 3.88GB immutable logical-disk image is streamed and read by bounded offsets.
"""
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
from analyze_native_vpm_acceptance_path import RuntimeImage, scan_calls
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

AUDIT = ROOT / 'staging/native-player-settings-scope/previous-audit.json'
DISK = ROOT / 'backups/20261002T154458Z/sda.img'
PRIOR = ROOT / 'staging/native-player-decoder-scope/package-static/native-voice-code-acceptance-boundary.json'
CFG = OUT / 'outer-VPM-completion-bounded-functions.json'
INPUT = OUT / 'actual-FAT32-outer-VPM-input.json'
REPORT = OUT / 'native-outer-VPM-completion-and-FAT-contract.json'
ENTRIES = (
    0x240498, 0x2747cc, 0x1d8514, 0x2d3166, 0x2d32de, 0x2d30ae,
    0xfe648, 0xfea50, 0x33e93c, 0x2d3380, 0xfeb36,
    0x31d09a, 0x31d032, 0x31cfe4, 0x1fdc0c, 0x1fde12, 0x1fdaca,
    0x31ce8c, 0x31cf22, 0x31cf5c, 0x31d1ce, 0x31d2e0,
    0x31e3be, 0x31e3c6, 0x1fdb8e, 0x1fe2be, 0x1fe20e,
    0x24e790, 0x24e7a4, 0x24e83a, 0x24e968, 0x217488, 0x2174b2,
    0x31e60e, 0x21b8f0, 0x39e998, 0x39e9e6, 0x2d36fc,
    0x3a1318, 0x3a0e2a, 0x3a132c, 0x39e9ca, 0x39f038, 0x39ef8a,
    0x3a0926, 0x3a04da, 0x3a0416, 0x3a0248, 0x3a0904, 0x3b0d46,
    0x39efda, 0x39fbf2, 0x39f12c,
    0x3feef4, 0x3fe668, 0x3fe7e8, 0x3fe876, 0x1d84c4, 0x2251c0,
    0x2741f4, 0x2745cc, 0x273e52, 0x273abc, 0x1e86ce, 0x1e8046,
    0x1fdb3c, 0x1fda26,
)


def digest(path):
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


class ActualFAT32:
    """Independent byte-identity check only; does not replace original FAT code."""
    def __init__(self, path):
        self.f = path.open('rb')
        self.capacity = path.stat().st_size
        self.boot = self.read_at(0, 512)
        b = self.boot
        self.bps = struct.unpack_from('<H', b, 11)[0]
        self.spc = b[13]
        self.reserved = struct.unpack_from('<H', b, 14)[0]
        self.fats = b[16]
        self.fat_sectors = struct.unpack_from('<I', b, 36)[0]
        self.root = struct.unpack_from('<I', b, 44)[0]
        self.total = struct.unpack_from('<I', b, 32)[0]
        self.first_data = self.reserved + self.fats * self.fat_sectors
        self.cache = {}
        need(b[-2:] == b'\x55\xaa' and b[82:90] == b'FAT32   ', 'FAT32 identity')
        need((self.bps, self.spc, self.reserved, self.fats, self.fat_sectors, self.root) ==
             (512, 8, 6, 1, 7386, 2), 'Exact original BPB differs')

    def read_at(self, offset, count):
        need(0 <= offset and count > 0 and offset + count <= self.capacity, 'Raw image read range')
        self.f.seek(offset)
        data = self.f.read(count)
        need(len(data) == count, 'Short immutable image read')
        return data

    def next_cluster(self, cluster):
        sector, offset = divmod(cluster * 4, self.bps)
        if sector not in self.cache:
            self.cache[sector] = self.read_at((self.reserved + sector) * self.bps, self.bps)
        return struct.unpack_from('<I', self.cache[sector], offset)[0] & 0x0fffffff

    def chain(self, start):
        seen = set()
        cluster = start
        while cluster < 0x0ffffff8:
            need(2 <= cluster < (self.total - self.first_data) // self.spc + 2 and
                 cluster not in seen, 'Invalid or cyclic FAT chain')
            seen.add(cluster)
            yield cluster
            cluster = self.next_cluster(cluster)

    def cluster_bytes(self, cluster):
        return self.read_at((self.first_data + (cluster - 2) * self.spc) * self.bps,
                            self.spc * self.bps)

    def directory(self, start):
        result, lfn = [], {}
        for cluster in self.chain(start):
            block = self.cluster_bytes(cluster)
            for offset in range(0, len(block), 32):
                e = block[offset:offset + 32]
                if e[0] == 0:
                    return result
                if e[0] == 0xe5:
                    lfn = {}
                    continue
                if e[11] == 15:
                    lfn[e[0] & 31] = e[1:11] + e[14:26] + e[28:32]
                    continue
                base, ext = e[:8].decode('cp437').rstrip(), e[8:11].decode('cp437').rstrip()
                name = base + ('.' + ext if ext else '')
                if lfn:
                    name = b''.join(lfn[x] for x in sorted(lfn)).decode('utf-16le')
                    name = name.split('\0')[0].replace('\uffff', '')
                lfn = {}
                if e[11] & 8:
                    continue
                result.append(dict(name=name, attributes=e[11],
                    start_cluster=(struct.unpack_from('<H', e, 20)[0] << 16) |
                                  struct.unpack_from('<H', e, 26)[0],
                    bytes=struct.unpack_from('<I', e, 28)[0]))
        return result


def main():
    need(all(not p.exists() for p in (CFG, INPUT, REPORT)), 'Exclusive new outputs required')
    audit = json.loads(AUDIT.read_text())
    need(digest(AUDIT) == 'dd3f1c3ea6743f6801d9bbb3edff3e0556dbfc1332243c6ee149b86999664f39', 'Exact1078 snapshot')
    protected = audit['protected_sources']
    need(len(protected) == 1078, 'Expected1078 protected files')
    for path, h in protected.items():
        need(digest(ROOT / path) == h, 'Protected source changed ' + path)
    need(digest(PRIOR) == 'b5695613a3b6c900c4dca46736917c6aaab552a48d4e25e723f54dfd94c0abe7', 'Prior acceptance result changed')
    stock = NativeImage()
    image = RuntimeImage(stock)
    functions = {}
    for entry in ENTRIES:
        f = trace(image, entry, 3500)
        need(not f['instruction_limit_reached'] and not f['unresolved_exits'], 'Unclosed bounded CFG ' + hex(entry))
        indirect = []
        for index, row in enumerate(f['instructions']):
            pc = int(row['address'], 16)
            ins = next(image.md.disasm(image.read(pc, 4), pc, count=1))
            row['bytes'] = ins.bytes.hex()
            row['load_address'] = hex(stock.runtime_to_load(pc, ins.size))
            if ins.mnemonic == 'blx' and '#' not in ins.op_str:
                indirect.append(dict(PC=hex(pc), instruction=row['instruction'],
                    predecessor=f['instructions'][max(0, index - 8):index]))
        f.update(entry_runtime=hex(entry), entry_load=hex(stock.runtime_to_load(entry, 2)),
            direct_call_targets=sorted({r['direct_call'] for r in f['instructions'] if 'direct_call' in r}),
            indirect_call_sites=indirect, bounded_function_not_transitive_policy_closure=True)
        functions[hex(entry)] = f
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for entry, size in [(0x2fbaa0, 12), (0x349314, 4), (0x70e424, 8)]:
        functions[hex(entry)] = dict(mode='ARM', explicit_span_bytes=size,
            instructions=[dict(address=hex(x.address), bytes=x.bytes.hex(),
                instruction=x.mnemonic + ' ' + x.op_str,
                load_address=hex(stock.runtime_to_load(x.address, x.size)))
                for x in arm.disasm(image.read(entry, size), entry)],
            bounded_function_not_transitive_policy_closure=True)
    expected = {
        0x2d31d8: 'bl #0x31d09a', 0x2d31f6: 'bl #0x31d09a',
        0x2d3292: 'bl #0x3008a0', 0x2d32a6: 'str r1, [r0, #0x14]',
        0x1d852c: 'cmp r0, #0', 0x1d8542: 'bl #0xfea50',
        0x1d8546: 'b #0x1d854a', 0x33e93c: 'bx lr',
        0x1fdcb8: 'blx r2', 0x1fde86: 'blx r5',
        0x31d0d2: 'cmp r0, #0', 0x31d0dc: 'str r4, [r5]',
        0x2d33f0: 'bl #0x31cf22', 0x2d33f8: 'subs r4, r4, r0',
        0x2d343e: 'blx #0x2fbaa0', 0x2d34ae: 'blx #0x349314',
        0x2d3512: 'movs r2, #0xff', 0x2d3514: 'blx #0x3794f0',
        0x2d3532: 'subs r0, r0, r4', 0x24e8a0: 'str r1, [r4, #0x20]',
        0x24e8a6: 'blx r1', 0x24e8ae: 'strb r0, [r4]',
        0x3fe80a: 'adds r0, #0x64', 0x3fe830: 'bl #0x24e83a',
        0x39ea36: 'blx r5', 0x39ea38: 'cmp r0, #1',
        0x39ece0: 'blx r5', 0x39edd8: 'str r0, [r6, #0x18]',
        0x39eddc: 'str r0, [r6, #0x1c]', 0x39f058: 'blx r6',
        0x3a147e: 'blx r7', 0x3a1482: 'cmp r0, r1',
        0x3a131a: 'movs r2, #0', 0x3a131c: 'bl #0x3a0e2a',
        0x31e634: 'bl #0x3008a0', 0x1fe2e0: 'bl #0x3008a0',
        0x24e988: 'bl #0x3008a0', 0x2d371a: 'bl #0x3008a0',
        0x39ea16: 'bl #0x3008a0', 0x3fef4c: 'bl #0x21b8f0',
        0xfeafe: 'ldr r0, [r6, r4]', 0xfeb00: 'bl #0x388b22',
        0x2404a2: 'bl #0x2741f4', 0x2404be: 'cmp r0, #0',
        0x2404c2: 'bl #0x23c3c4', 0x2404c6: 'cmp r0, #0xb',
        0x273ade: 'bl #0x3598b8', 0x1fdc3e: 'movs r0, #9',
        0x1e899c: 'bl #0x1e8046', 0x31cf0c: 'bl #0x1fdb3c',
    }
    assertions = []
    for pc, wanted in expected.items():
        x = next(image.md.disasm(image.read(pc, 4), pc, count=1))
        need(x.mnemonic + ' ' + x.op_str == wanted, 'Instruction differs ' + hex(pc))
        assertions.append(dict(PC=hex(pc), bytes=x.bytes.hex(), instruction=wanted))
    file_ops = struct.unpack('<8I', image.read(0x86df7c, 32))
    need(file_ops[:3] == (0x3a1319, 0x39e9cb, 0x3a132d), 'Native FAT file ops')
    mapped_tag = image.read(0x2d3454, 64).split(b'\0')[0].decode('ascii')
    need(mapped_tag == '&mapped_rgn_list[rgn_idx_list[rgn_idx].idx].smphr', 'Mapped region tag')
    scan = scan_calls(stock, {0x24e83a, 0x21b8f0, 0x39e998, 0x39e9e6})
    need({r['address'] for r in scan['candidates']} == {'0x21b916', '0x3fe830', '0x3fef4c'}, 'Registration direct scan differs')
    disk_meta = json.loads((DISK.parent / 'sda.json').read_text())
    disk_hash = digest(DISK)
    need(disk_hash == disk_meta['sha256'] == 'df393136d4d14dd31906c1f161fc354cb097c56e3bf8c2278433d01ca2f1c6e2', 'Actual raw disk SHA')
    fs = ActualFAT32(DISK)
    root = fs.directory(fs.root)
    voice = next(r for r in root if r['name'].lower() == 'voice')
    garmin = next(r for r in root if r['name'].lower() == 'garmin')
    need(not any(r['name'].lower() == 'voice' for r in fs.directory(garmin['start_cluster'])), 'Physical path alias inventory changed')
    voices = fs.directory(voice['start_cluster'])
    members, backup_paths = [], []
    for name in ['Chinese_Big5_MeiLing.vpm', 'Chinese_GB_MeiLing.vpm', 'English_American_Jill.vpm']:
        row = next(r for r in voices if r['name'].lower() == name.lower())
        remaining, h, chain = row['bytes'], hashlib.sha256(), []
        for cluster in fs.chain(row['start_cluster']):
            chain.append(cluster)
            data = fs.cluster_bytes(cluster)
            n = min(remaining, len(data)); h.update(data[:n]); remaining -= n
        need(remaining == 0, 'Raw FAT file short')
        path = DISK.parent / 'files/Voice' / name
        need(h.hexdigest() == digest(path), 'Raw FAT/extracted VPM identity ' + name)
        files, geometry = parse_image(path.read_bytes())
        identity = {}
        for key in ['DLLIMG.BIN', 'DLLIMG.SIG', 'DLLINFO.TXT', 'IMGEND.TST']:
            f = files[key]
            identity[key] = dict(bytes=f['bytes'], sha256=f['sha256'],
                block_count=len(f['blocks']), directory_offsets=f['directory_offsets'],
                block_list_sha256=hashlib.sha256(struct.pack('<' + 'I' * len(f['blocks']), *f['blocks'])).hexdigest())
        members.append(dict(physical_path='/Voice/' + name, generic_native_baseline_path='0:/Voice/' + name,
            exact_outer_bytes=row['bytes'], outer_sha256=h.hexdigest(), root_directory=row,
            FAT_cluster_count=len(chain), fragmented=any(b != a + 1 for a, b in zip(chain, chain[1:])),
            FAT_chain_sha256=hashlib.sha256(struct.pack('<' + 'I' * len(chain), *chain)).hexdigest(),
            member_identity=identity, embedded_container_geometry=geometry))
        backup_paths.append(path)
    fs.f.close()
    save(CFG, dict(MAIN_sha256=EXPECTED, functions=functions, direct_registration_scan=scan,
        complete_bounded_function_or_explicit_span_count=len(functions),
        full_transitive_storage_or_signature_policy_closure=False))
    raw_input = dict(exact_target=dict(HWID=1352, software='8.00', MAIN_sha256=EXPECTED),
        original_snapshot=rel(DISK), image_bytes=DISK.stat().st_size, image_sha256=disk_hash,
        disk_hash_streamed=True, whole_disk_loaded_into_host_RAM=False,
        sector0_sha256=hashlib.sha256(fs.boot).hexdigest(), byte_sector=512, sectors_per_cluster=8,
        reserved_sectors=6, FAT_count=1, FAT_sectors=7386, first_data_sector=7392,
        root_cluster=2, USB_image_sector_count=DISK.stat().st_size // 512,
        BPB_filesystem_sector_count=fs.total, BPB_is_at_image_sector0=True, MBR_partition_translation_required=False,
        directory_identity=dict(Voice_root_cluster=voice['start_cluster'], Garmin_root_cluster=garmin['start_cluster'],
            physical_Garmin_Voice_exists=False, old_fixture_Garmin_Voice_is_not_this_physical_FAT_path=True),
        original_voice_members=members, no_changed_DLL_VPM_SIG_created=True, guest_execution=False)
    save(INPUT, raw_input)
    deps = [Path(__file__), AUDIT, PRIOR, CFG, INPUT, DISK, DISK.parent / 'sda.json',
        DISK.parent / 'verification.json', ROOT / 'evidence/firmware-analysis/main_02bd.bin',
        ROOT / 'scripts/analyze_native_sections.py', ROOT / 'scripts/analyze_native_vpm_acceptance_path.py',
        ROOT / 'scripts/analyze_sdp_activation.py', ROOT / 'scripts/analyze_tts_vpm.py',
        ROOT / 'scripts/emulate_native_voice_outer.py', ROOT / 'scripts/emulate_native_voice_selection.py',
        ROOT / 'scripts/emulate_native_vpm_filesystem.py', ROOT / 'scripts/probe_native_heap_settings_boot.py'] + backup_paths
    hashes = {rel(p): disk_hash if p == DISK else digest(p) for p in deps}
    report = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True, static_only=True,
        exact_target=dict(HWID=1352, software='8.00 Taiwan', MAIN_sha256=EXPECTED),
        source_sha256=hashes, large_source_hashing_requires_streaming=[rel(DISK)],
        protected_registry=dict(snapshot=rel(AUDIT), sha256=digest(AUDIT), count=1078,
            checked_before_and_after=True, modified_files=0),
        bounded_functions=dict(path=rel(CFG), sha256=digest(CFG), count=len(functions),
            instruction_count=sum(len(f['instructions']) for f in functions.values()),
            local_CFG_complete=True, transitive_indirect_policy_closure=False),
        exact_instruction_assertions=assertions,
        actual_raw_input=dict(path=rel(INPUT), sha256=digest(INPUT),
            original_FAT32_and_three_VPM_byte_identities_recovered=True,
            raw_input_proves_physical_modified_code_acceptance=False),
        outer_bind=dict(entry='0x2d3166', ABI='r0=kind byte; r1=region ID; r2=UTF16 decimal-drive:absolute pathname',
            caller='1D8528', caller_inputs='kind0; mapped region from F09658+42*slot+40; pathname argument',
            mutex='105EAA4', bound_array='105E424,2 bytes per region', record_array='105E624,36 bytes per record,max32',
            record_fields={'+0':'fallback-path kind byte','+1':'in-use byte','+2':'input kind byte',
                '+4':'native semaphore24','+20':'semaphore tag pointer','+28':'generic file object pointer',
                '+32':'fallback UTF16 pathname opaque handle'},
            normal_open='2D31D8 calls31D09A(path,0x23,&record+28); any nonzero status retries at2D31F6 with0x21.',
            statuses={'0':'one native generic open returned0; file pointer published; bound1',
                '1':'max32 pool reached or unclassified nonzero generic open failure; intermediate r4=4 is converted to1 at2D32CC..D0/2D318A',
                '2':'region already bound',
                '3':'final generic open status2 or4 enters copied-path fallback; bound1 without open file'},
            result3_is_not_normal_open_success=True,
            fallback_allocation_failure='2D324E branches to2D3284 even when the pathname opaque handle is0; result3/bound1 therefore does not prove retained pathname allocation.',
            initializer='3008A0 continuation2D3296,record+4; tag store2D32A6 from literal2D3454',
            initializer_tag=mapped_tag,
            current_TCB_internal_guard='1C0600 at2D31AE; if nonzero1C0624 at2D32C8; not a join.',
            unbind='2D32DE clears bound before record lock; native31CE8C closes+28;3887A2 releases+32; unlock then originalzero36.',
            lifetime='Do not unbind while embedded member callbacks/selected DLL loader still consume this region.'),
        mount_completion=dict(wrapper='0x1d8514', true_conditions=['2D3166 returns0','FE648 translation !=0x80'],
            no_op_boot_hook='33E93C is original BX LR',
            FEA50_status_checked=False, embedded_volume_active_checked=False,
            critical_gap='1D8542 callsFEA50 and1D8546 unconditionally branches to returnr5=1. Bool success does not witness original1E8046 completion.',
            FEA50='Actual1E86CE remount first, then on activation1 cache generic path through2D30AE/31E3BE, allocatepathname+8, copyUTF16 into+6, storefile+0 and drivebyte+4.',
            FEA50_deactivation='Original3887A2 releases CACHE_NAMES10425DC+4*legacy_drive; not proof of worker unload.',
            required_witness='Original embedded volume116-byte record active+0==1, parsedgeometry and all member byte reads; never substitute wrapper return.'),
        physical_registration=dict(boot='3FEF4C->21B8F0->31E60E/39E998/2D36FC',
            type_registry='1057810,5 records24', type1_source_descriptor='86DF64',
            type1_register='39E998->2174B2 copies24; low registered flag bit set originally.',
            drive_count='F001A8', drive_array='F001AC,boot1057888,2 records64',
            record_fields={'+0':'active byte only after mount returns0','+1':'drive index',
                '+2':'permission flags','+3':'type index','+24':'native file-op table',
                '+28':'other-op table','+32':'lower block parameter descriptor','+36':'opaque FAT context handle',
                '+40':'native semaphore24'},
            actual_registration='3FE7E8 loop of16-byte partition records:3FE828 r2=entry+12,3FE82A r1=entry+11,3FE82C r0=entry+9,3FE82E r3=storage_actor+0x64;3FE830 calls24E83A.',
            original_mount_dispatch='24E8A0 publishes r3 todrive+32;24E8A2..A6 loads registered type+8 andBLX; active written1 only if native return0.',
            storage_actor_array='2CEA340 +0xC8*actor0/1; partition pointer actor+0xBC; count byte actor+0xC6',
            actual_unexposed_board_lower_callback_values_recovered=False,
            FAT_file_ops={'table':'86DF7C','open':'3A1319','close':'39E9CB','read':'3A132D'},
            original_open_dispatch='1FDCB8: drive+24->ops+0; r0=drive64,r1=file72. Original3A1318 setsr2=0 and calls3A0E2A.',
            original_read_dispatch='1FDE86: child+44->drive+24->ops+8; r0=child80,r1=destination,r2=offsetlow,r3=offsethigh,stack0=count.',
            original_close='31CE8C->1FDACA clearsfileactive, releasespathname/buffer, unlinkschild, decrementschild+2, optional native1FDA26 flush/close, clearsfile+12.',
            closure_limit='Mapped generic/FAT code recovered; actual storage actor setup/hardware callbacks and logical /Garmin alias are not supplied by USB file identities.'),
        FAT_lower_read_contract=dict(native_mount='39E9E6', parameter_pointer='drive+32',
            sector_size='first uint16 is log2sectorbytes; exact input9 for512', callback_pointer='*(params+8)',
            ABI='r0=drive+1 byte;r1=sector index;r2=sector count;r3=destination;returnr0=completed sectors',
            mount_calls=['39EA36: sector0,count1;39EA38 requiresreturned1','39ECE0: later originalBPB/FAT setup reads'],
            cache_call='39F058 readssectorcache request1 and checksreturn1',
            direct_file_call='3A147E readscontiguous sectors;3A1482 requiresreturn==requestedcount, otherwise returns accumulated actualbytes.',
            requested_memory_extent='sector_count<<9 bytes; every request must staywithinactual rawinput and guarded destination.',
            sole_future_IO_fixture='Read exact immutable sda.img offsetsector*512; never identify or validate VPM/SIG at this hook; reject write callback and out-of-range request.',
            hardware_mount_or_SIG_policy_not_modelled=True),
        read_count_and_identity=dict(generic_read='31CF22->1FDE12 bounds cursor64 againstchild+32/+36 filelength, requiresfilemode bit0, advancescursor byactualreturnedbytes.',
            mapped_region_read='2D3380(region,offset,destination,count) locksrecord+4; seek31D1CE if needed; read31CF22; stat31CF5C.',
            padding='2D3512..14 originalmemset0xFF beyond EOF up to computed capacity;2D3532 returnsrequested-minusremaining including filler.',
            exact_capacity_arithmetic='2FBAA0 UMULL computes stat+16 * stat+20; if24E7A4 returns0,349314->70E424 UMLAL adds drive-info+12 * drive-info+20.',
            requested_count_is_not_backing_VPM_identity=True,
            required_record=['generic actual count beforepadding','file size fromnative stat','every0xFF padding PC/address/count','raw VPM byte SHA versus immutable member source']),
        signature_request_status=dict(real_DLLIMG_SIG_requester_identified=False,
            real_SIG_verifier_publickey_or_enforcement_recovered=False,
            FAT_open_uses_passed_outer_VPM_path_not_a_new_DLLIMG_SIG_member_name=True,
            native_FAT_and_lower_callbacks_closed_transitively=False,
            prior_crypto_distinction_preserved='b5695613: GUPDATE/GMA SHA1 is not the72-byte DLLIMG.SIG policy.',
            reason_no_acceptance_claim='Raw FAT access and1D8514 success can be witnessed independently of embedded mount, bytepadding, filenamealias and pre-DLL gate. None proves modifiedcode would be accepted physically.'),
        higher_DLL_entry_gate=dict(entry='240498',
            ordered_native_calls=['2404A2->2741F4 loads20-byte descriptor from selected opaque cache record+1020; descriptor firstu16 must be nonzero.',
                '2404B2->221D2C executes beforeselection wrapper; transitive sideeffects not closed here.',
                '2404BA->2747CC calls2745CC membershipcheck,273E52 indexlookup,273ABC cachedpathnamecopy,1D8514 outerbind/remount.',
                'Only2747CC return!=0 reaches2404C2->23C3C4. Only23C3C4 return11 publishes requested selection at2404CA.'],
            path_producer='273ABC calls273A84 to obtain selected opaque cache record,388804 to expose it, then3598B8(r0=output,r1=record,r2=255) copiesits initial pathname; no alias rewrite occurs in this boundedfunction.',
            post_bind_calls='274808->222A34 then either3316EC(0x199) or240AA2(1), before2747CC mutexunlock/return. These original sideeffects and their transitive policy remain nextscope.',
            immediate_gate_recovered=True, all_preentry_native_policy_closed=False,
            runtime_reached_23C3C4_with_actual_FAT_input=False),
        next_runnable_contract=dict(type='NEW isolated native FAT baseline first; original unmodified bytes only',
            actual_path='0:/Voice/Chinese_Big5_MeiLing.vpm',
            exact_readonly_input='drive+2 permission byte1. Original1FDC32..3E rejects mode0x23 withstatus9 becausemode&0x16!=0, but permits0x21; original2D3166 retry mustexecute.',
            steps=['Declare cold file72/child80/drive64 tables as inputs; run original31E60E,39E998 and2D36FC constructors without resetting live root data.',
                'Register drive0,type1 with original24E83A and typed512-byte blockdescriptor. Explicitly declare readonly permission input and reject actual write attempts.',
                'Execute original39E9E6 through registration; check actual return, active byte1, pointers86DF7C/86DF9C and native BPB context.',
                'Call31D09A on actual /Voice baseline path, mode0x21; observe1FDCB8 entering3A1318/3A0E2A and actual callerreturnstatus/pointer.',
                'Read via31CF22 in bounded chunks with actual cursor; hashentire returned file and verifybackupidentity; calloriginal31CE8C->1FDB3C->1FDACA and guard native file/child references/opaquehandles/ownedmutexes.',
                'Only afterbaseline succeeds, bind actualregion through2D3166, remountfullFEA50, verifyembedded activevolume and memberidentities, then observe higherselection and stopBEFORE3B3332 BLX.',
                'Trace all genuine filename requests and required verifier entry/return. Do not injectDLLIMG.SIG name or fake hashverification.'],
            concrete_remaining_blockers=['Raw FAT /Garmin/Voice is absent; original higher pathalias/producer remains unrecovered. Explicit /Voice baseline is not higher1D8514 policy closure.',
                'A sole-block-read fixture micro still needs separately admitted originalheap/opaqueallocation/native mutex/TCB constructors and observer scopes; existing OuterVM additionally fakes these and cannot be relabeled sole-fixture.',
                'Native readonly record input and original writeback behaviour must be explicit; do not silently allowFAT writes or fakeclosecompletion.',
                'Actual USB image does not reveal unexposed board volume mappings/callbacks or signaturekey/enforcement.'],
            runtime_started_here=False, modified_package_experiment_ready=False,
            physical_experiment='No changedVPM install yet; first close the original raw FAT + alias + preentry request path on immutable backups.'),
        guard_inputs=dict(file_record_bytes=72, child_record_bytes=80, drive_record_bytes=64,
            file_init='31E634->3008A0 atfile+32;tag31E63E',child_init='1FE2E0->3008A0 atchild+56;tag1FE2EA',
            drive_init='24E988->3008A0 atdrive+40;tag24E992',
            mapped_init='2D371A->3008A0 at105EAA4;tag2D3722',
            FAT_context_init='39EA16->3008A0 atctx+64;tag39EA1E',
            retained_exit_listeners='31E60E registers2 original nodes105E404/105E414 into2D226B4 withorders1FFFFE0/2000020; do not reset existingTimer/heap/VFP listeners.',
            required_whole_regions=['all liveTCB108/ownedlists/contextframes','nativeheapextent/workspace and allocationboundaries','file72/child80/drive64/poolcounts/type5x24','mapped2x255 and36x32 arrays','FATcontext/BPB/cache/clusterlist handles','destinationguard pages andwhole originalcode','exitlist plus bothnew listeners andall retainednodes']),
        new_guest_or_emulator_executed=False, device_io=False, modified_backup_or_VPM_SIG=False,
        canonical_or_frozen_source_modified=False, physical_changed_code_acceptance_verified=False,
        complete_native_storage_or_signature_policy_verified=False, device_install_candidate=False)
    for path, h in protected.items():
        need(digest(ROOT / path) == h, 'Protected source changed after analysis ' + path)
    save(REPORT, report)
    print(json.dumps(dict(report=rel(REPORT), sha256=digest(REPORT), source_sha256=digest(Path(__file__)),
        bounded_functions=len(functions), assertions=len(assertions), protected_files=1078,
        actual_raw_FAT_VPM_identities=3, SIG_requester=False, guest_execution=False)))


if __name__ == '__main__':
    main()
