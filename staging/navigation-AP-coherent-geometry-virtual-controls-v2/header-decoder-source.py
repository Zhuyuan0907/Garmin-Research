"""Finite ordinary IMG header arithmetic; does not run or modify Garmin code."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT/'staging/navigation-AP-header-geometry-arithmetic-review-v1'
SOURCES = {
    'stock': ('backups/20261002T154458Z/files/.System/gmapprom1.img', 'b8afc5f2833a380541e1caf6ce729cb523bcf16739769f935ce17fbd9fbeb191'),
    'healthy_v2': ('staging/navigation-country-native-candidate-v2/gmapprom1.img', 'b8afc5f2833a380541e1caf6ce729cb523bcf16739769f935ce17fbd9fbeb191'),
    'regressed_v3': ('staging/navigation-country-native-lane-candidate-v3/gmapprom1.img', 'e3b9dad35486683869b4bfc811e591a2af020c5764b12cfb4d9cf31a441e0ca3'),
    'expanded_4K': ('staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled', '3ec84ec4bec34f19eb7970600eee244bf2f3b1fd1d7b48a925e924519bf1684b'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, indent=2, ensure_ascii=False)+'\n').encode()
    path = OUT/name
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o444)


def stamp(path):
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def decode(header):
    def u16(offset): return int.from_bytes(header[offset:offset+2], 'little')
    def u32(offset): return int.from_bytes(header[offset:offset+4], 'little')
    assert len(header) == 512 and header[0] == 0
    assert header[0x10:0x16] == b'DSKIMG' and header[0x1fe:] == b'\x55\xaa'
    sectors, heads, cylinders = u16(0x18), u16(0x1a), u16(0x1c)
    assert 0 < sectors <= 63 and 0 < heads <= 256 and cylinders > 0
    eh = header[0x1c3]
    es = header[0x1c4] & 63
    ec = header[0x1c5] | ((header[0x1c4] & 192) << 2)
    end_lba = (ec*heads+eh)*sectors + es-1
    declared_sectors = u32(0x1ca)
    block_bytes = 1 << (header[0x61]+header[0x62])
    return dict(block_bytes=block_bytes, declared_blocks_u16=u16(0x63),
        declared_block_capacity_bytes=u16(0x63)*block_bytes,
        declared_sectors=declared_sectors, declared_sector_capacity_bytes=declared_sectors*512,
        geometry=dict(sectors=sectors,heads=heads,cylinders=cylinders,
                      total_geometry_bytes=sectors*heads*cylinders*512,
                      repeated_heads_equal=heads==u16(0x5d), repeated_sectors_equal=sectors==u16(0x5f)),
        partition_start=list(header[0x1bf:0x1c2]), relative_LBA=u32(0x1c6),
        partition_end_CHS=dict(head=eh,sector=es,cylinder=ec),
        end_CHS_interpreted_sector_count=end_lba+1,
        end_CHS_matches_declared_sector_count=end_lba+1==declared_sectors,
        declared_capacity_within_geometry=declared_sectors<=sectors*heads*cylinders,
        opaque_checksum_byte_0F=header[15],
        diagnostic_sum_first512_mod256=sum(header)%256,
        diagnostic_sum_first128_mod256=sum(header[:128])%256,
        checksum_algorithm_verified=False)


def main():
    OUT.mkdir(mode=0o700)
    reads=[]; results={}
    try:
        reference=ROOT/'sources/maps/format-reference/ImgHeader.java'
        initial=stamp(reference)
        assert reference.stat().st_size <= 25000
        raw=reference.read_bytes()
        assert stamp(reference)==initial
        save('reference-ImgHeader.java',raw)
        reads.append(dict(path=str(reference.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),stat=initial))
        for name,(relative,pin) in SOURCES.items():
            path=ROOT/relative; before=stamp(path)
            with path.open('rb') as stream:
                header=stream.read(512)
            assert stamp(path)==before and sha(header)==pin
            save(name+'-header.bin',header)
            result=decode(header)
            result.update(path=relative, source_file_bytes=before[2], header_sha256=pin,
                          actual_IMG_read_bytes=512, source_stat_unchanged=True, handle_closed=True,
                          file_within_declared_capacity=before[2]<=result['declared_sector_capacity_bytes'])
            results[name]=result
            reads.append(dict(path=relative,bytes=512,sha256=pin,stat_before=before,stat_after=stamp(path)))
        assert results['stock']=={**results['stock']}
        assert results['stock']['header_sha256']==results['healthy_v2']['header_sha256']
        save('input-read-receipts.json',reads)
        save('proof.json',dict(schema='ordinary-AP-IMG-header-geometry-arithmetic/v1',
            all_assigned_checks_completed=True,actual_IMG_read_bytes=2048,
            reference_source_bytes=len(raw),headers=results,
            local_reference_claims_are_not_exact_device_policy=True,
            reading_header_and_sums_does_not_verify_checksum=True,
            unchanged_geometry_does_not_prove_road_loss_cause=True,
            original_declared_128MiB_is_not_proven_platform_limit=True,
            device_IO=False,firmware_execution=False,IMG_modified=False,installable=False,
            rendering_or_route_verified=False,full_goal_complete=False))
        paths=sorted(path for path in OUT.iterdir() if path.is_file())
        save('sealed-files.json',dict(files=[dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,
            sha256=sha(path.read_bytes()),mode=oct(path.stat().st_mode&0o777)) for path in paths],
            actual_IMG_read_bytes=2048,additional_IMG_reads_at_seal=0))
        print(json.dumps(dict(all_assigned_checks_completed=True, actual_IMG_read_bytes=2048,
            capacity_comparison={name:{key:value[key] for key in ['end_CHS_matches_declared_sector_count',
                'declared_capacity_within_geometry','diagnostic_sum_first512_mod256']} for name,value in results.items()},
            proof_sha256=sha((OUT/'proof.json').read_bytes()))))
    except BaseException as error:
        save('failure.json',dict(type=type(error).__name__,message=str(error),finished_input_receipts=reads))
        raise


if __name__ == '__main__':
    main()
