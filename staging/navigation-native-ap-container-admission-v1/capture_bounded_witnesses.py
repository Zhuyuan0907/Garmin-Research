#!/usr/bin/env python3
"""Freeze <=5 static witnesses from exact MAIN; no CPU/device/full IMG reads."""
from pathlib import Path
import hashlib
import json
import struct
import capstone

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
SECTIONS = ROOT / 'evidence/firmware-analysis/native-sections.json'
EXPECTED_MAIN_SHA = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'


def stat(p):
    q = p.stat()
    return [q.st_dev, q.st_ino, q.st_size, q.st_mtime_ns, q.st_ctime_ns]


def main():
    sections_bytes = SECTIONS.read_bytes()
    sections = json.loads(sections_bytes)
    assert sections['stock_sha256'] == EXPECTED_MAIN_SHA
    before = stat(MAIN)
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    reads = []
    fragments = []
    with MAIN.open('rb') as f:
        def read(address, count, purpose):
            candidates = [s for s in sections['copies']
                          if s['runtime_start'] <= address
                          and address + count <= s['runtime_start'] + s['size']]
            assert len(candidates) == 1
            sec = candidates[0]
            assert not sec['conditional'], 'Witness requires unconditional startup mapping'
            load = sec['load_start'] + address - sec['runtime_start']
            f.seek(load - 0x50000)
            data = f.read(count)
            assert len(data) == count
            reads.append(dict(runtime_start=hex(address), load_start=hex(load),
                              file_offset=load - 0x50000, bytes=count, purpose=purpose))
            return data

        # All disassembly spans start at known Thumb instruction boundaries.
        spans = [
            ('ap_filename_caller', 0x16726c, 50),
            ('ap_filename_callee', 0x1670d0, 106),
            ('ap_metadata_record_lookup', 0x16713a, 194),
            ('shared_signature_probe', 0x1e7e40, 72),
            ('shared_cache_to_mount', 0xfea98, 10),
            ('shared_mount_to_parser', 0x1e8982, 32),
            ('shared_header_pointer_origins', 0x1e80cc, 72),
            ('shared_header_geometry_arithmetic', 0x1e82c8, 104),
            ('shared_sector_512_guard', 0x1e83b8, 16),
        ]
        for name, address, count in spans:
            data = read(address, count, name)
            insns = [dict(address=hex(i.address), bytes=i.bytes.hex(),
                          mnemonic=i.mnemonic, operands=i.op_str)
                     for i in cs.disasm(data, address)]
            assert sum(len(bytes.fromhex(i['bytes'])) for i in insns) == count
            fragments.append(dict(name=name, runtime_start=hex(address), bytes=count,
                                  sha256=hashlib.sha256(data).hexdigest(),
                                  raw_hex=data.hex(), instructions=insns))

        street_file_name = read(0x167410, 28, 'exact UTF16 AP filename')
        assert street_file_name.decode('utf-16le') == 'gmapprom1.img\0'
        literals = {}
        for addr in [0x1e8228, 0x1e822c, 0x1e8230]:
            b = read(addr, 4, 'exact signature-probe literal')
            literals[hex(addr)] = hex(struct.unpack('<I', b)[0])
        assert literals == {'0x1e8228':'0xf7b3dc', '0x1e822c':'0xb9decb',
                            '0x1e8230':'0xb9dec4'}
        signatures = [read(0xb9decb, 7, 'DSKIMG signature string').decode('ascii'),
                      read(0xb9dec4, 7, 'DSDIMG signature string').decode('ascii')]
        assert signatures == ['DSKIMG\0', 'DSDIMG\0']

    assert stat(MAIN) == before
    by_address = {int(i['address'], 16): i for fr in fragments for i in fr['instructions']}
    expected = {0x167282:'63a2', 0x167290:'fff71eff',
                0x1e7e54:'16f76ffe', 0xfea9e:'e9f016fe',
                0x1e899c:'fff753fb', 0x1e82da:'9040',
                0x1e82fc:'8840', 0x1e8316:'7352',
                0x1e83c4:'00d0', 0x1e83c6:'71e7'}
    for addr, raw in expected.items():
        assert by_address[addr]['bytes'] == raw, (hex(addr), raw)

    witnesses = [
        dict(number=1, name='Exact AP filename passed to a metadata-shaped caller',
             instructions=[by_address[a] for a in [0x167282,0x167284,0x167290]],
             runtime_data_address='0x167410', UTF16_text='gmapprom1.img',
             inference='ADR computes align(0x167282+4,4)+0x18c = 0x167410. '
                       'Caller places this pointer on stack and calls 0x1670d0. '
                       'That callee issues formatting/property-style calls to '
                       '0x1d52ea/0x1d5248/0x1d52be. This does not bind a renderer '
                       'or admission function.'),
        dict(number=2, name='Generic container signature probe',
             instructions=[by_address[a] for a in [0x1e7e50,0x1e7e52,0x1e7e54,
                                                  0x1e7e5c,0x1e7e5e,0x1e7e64]],
             inference='Read 0x16 bytes through 0xfeb36, compare header+0x10 '
                       'against six-byte DSKIMG; fallback compares DSDIMG. '
                       'This identifies a shared container type, not AP drawing.'),
        dict(number=3, name='Shared cache/mount/parser direct-call edges',
             instructions=[by_address[a] for a in [0xfea98,0xfea9a,0xfea9c,0xfea9e,
                                                  0x1e8994,0x1e8996,0x1e8998,
                                                  0x1e899a,0x1e899c]],
             inference='0xfea50 branch at 0xfea9e calls 0x1e86ce; branch at '
                       '0x1e899c in 0x1e86ce calls 0x1e8046. Prior sealed evidence '
                       'binds this chain to VPM. The present scope has no exact '
                       'AP-file-to-mount or mount-to-renderer binding.'),
        dict(number=4, name='Shared geometry uses two dynamic shifts',
             instructions=[by_address[a] for a in [0x1e82cc,0x1e82da,0x1e82e2,
                                                  0x1e82f0,0x1e82fc,0x1e8316,
                                                  0x1e8320,0x1e832a]],
             inference='Header+0x61 exponent gives sector bytes 1<<e1, stored '
                       'as u16 at volume+0x48. Header+0x62 gives sectors/block '
                       '1<<e2, masks and 240-block continuation coverage. '
                       'Header+0x63/64 block count is stored as u16 at +0x4e. '
                       'For 9+3 vs 9+4 these operations compute 4K vs 8K; '
                       'there is no fixed delta==3 compare in this 104-byte '
                       'fragment. Arithmetic alone is not container acceptance.'),
        dict(number=5, name='Shared branch requires 512-byte sectors',
             instructions=[by_address[a] for a in [0x1e83bc,0x1e83be,0x1e83c0,
                                                  0x1e83c2,0x1e83c4,0x1e83c6]],
             inference='Subtracting 7, 255 and 250 compares stored sector size '
                       'with 512. Equality continues at 0x1e83c8; mismatch '
                       'branches to 0x1e82ac. Both 9+3 and 9+4 have sector512, '
                       'so this is not a block-size-4096 guard.'),
    ]
    result = dict(schema='bounded-exact-MAIN-container-static-witnesses/v1',
                  source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  MAIN_identity_sha256_inherited=EXPECTED_MAIN_SHA,
                  MAIN_sha256_not_recomputed=True,
                  sections_metadata_sha256=hashlib.sha256(sections_bytes).hexdigest(),
                  MAIN_stat_before=before, MAIN_stat_after=stat(MAIN),
                  actual_explicit_read_operations=len(reads),
                  actual_explicit_read_bytes=sum(r['bytes'] for r in reads),
                  actual_read_receipts=reads, witnesses=witnesses,
                  bounded_supporting_instruction_fragments=fragments,
                  literal_bindings=literals, exact_signature_strings=signatures,
                  AP_renderer_or_admission_binding_proved=False,
                  exponent_8K_hard_limit_proved=False,
                  boundary_128MiB_hard_limit_proved=False,
                  CPU_not_executed='True AP binding unresolved; shared VPM geometry '
                                   'execution would not answer the AP admission question.',
                  no_IMG_device_USB_installer_firmware_or_old_suite_access=True)
    out = HERE / 'bounded-static-witnesses.json'
    assert not out.exists()
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(dict(witness_count=len(witnesses), actual_read_bytes=result['actual_explicit_read_bytes'],
                          operations=len(reads), MAIN_stat_stable=True,
                          AP_binding_proved=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
