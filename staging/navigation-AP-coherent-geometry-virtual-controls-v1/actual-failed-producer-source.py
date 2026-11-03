"""Two data-only header controls, with full virtual hashes and no new IMG."""
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from review_ap_IMG_header_geometry_v1 import decode

ROOT = Path('/root/garmin')
OUT = ROOT/'staging/navigation-AP-coherent-geometry-virtual-controls-v1'
INPUT = ROOT/'staging/navigation-AP-header-geometry-arithmetic-review-v1'
IMG_BUDGET = 320000000
RAM_BUDGET_KIB = 65536
IMG_INPUTS = {
    'eightK_end_mirror': dict(path='staging/navigation-country-native-lane-candidate-v3/gmapprom1.img',
        bytes=153346048, sha256='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
        header='regressed_v3-header.bin'),
    'expanded_fourK_geometry': dict(path='staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled',
        bytes=153337856, sha256='cc019c5f83c7fce442d0a6b64d8cc216dbc39e1cfa08dfe3f57c757f3bdfbfe9',
        header='expanded_4K-header.bin'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(path):
    s=path.stat()
    assert stat.S_ISREG(s.st_mode)
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def save(name,value):
    raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2,ensure_ascii=False)+'\n').encode()
    path=OUT/name
    with path.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    path.chmod(0o444)


def usage():
    fields={}
    for line in Path('/proc/self/status').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in ['VmRSS','VmHWM']:
            pieces=value.split()
            assert len(pieces)==2 and pieces[1]=='kB' and key not in fields
            fields[key]=int(pieces[0])
    assert fields.keys()=={'VmRSS','VmHWM'}
    assert max(fields.values())<=RAM_BUDGET_KIB
    return fields


def patch(header, expand):
    source=decode(header)
    output=bytearray(header)
    if expand:
        # Keep the original head/cylinder counts. A source-observed32-sector
        # geometry covers this full image; update the repeated field as well.
        output[0x18:0x1a]=(32).to_bytes(2,'little')
        output[0x5f:0x61]=(32).to_bytes(2,'little')
    sectors=int.from_bytes(output[0x18:0x1a],'little')
    heads=int.from_bytes(output[0x1a:0x1c],'little')
    last=int.from_bytes(output[0x1ca:0x1ce],'little')-1
    cylinder=last//(heads*sectors)
    head=(last//sectors)%heads
    sector=last%sectors+1
    assert 0<=cylinder<1024 and 0<=head<256 and 1<=sector<=63
    output[0x1c3]=head
    output[0x1c4]=sector|((cylinder>>2)&192)
    output[0x1c5]=cylinder&255
    changed=[index for index,(a,b) in enumerate(zip(header,output)) if a!=b]
    expected=[0x18,0x5f,0x1c4,0x1c5] if expand else [0x1c4]
    assert changed==expected
    decoded=decode(bytes(output))
    assert decoded['end_CHS_matches_declared_sector_count']
    assert decoded['declared_capacity_within_geometry']
    assert decoded['geometry']['repeated_heads_equal'] and decoded['geometry']['repeated_sectors_equal']
    assert decoded['declared_sector_capacity_bytes']==decoded['declared_block_capacity_bytes']
    assert decoded['opaque_checksum_byte_0F']==source['opaque_checksum_byte_0F']
    assert decoded['block_bytes']==source['block_bytes']
    return bytes(output), dict(changed_byte_offsets=changed,source=source,virtual=decoded,
        original_byte_values=[header[index] for index in changed],
        new_byte_values=[output[index] for index in changed],
        checksum_preserved_not_verified=True)


def main():
    OUT.mkdir(mode=0o700)
    receipts=[];completed={};actual_read=0;peak=0
    try:
        proof_raw=(INPUT/'proof.json').read_bytes()
        assert sha(proof_raw)=='61c836cbee7e7faabfdf76d391a8ca0531e831ed9cf8b380700195b25081614b'
        proof=json.loads(proof_raw)
        assert proof['all_assigned_checks_completed'] and not proof['device_IO']
        assert sum(item['bytes'] for item in IMG_INPUTS.values())==306683904<IMG_BUDGET
        prepared={}
        for name,item in IMG_INPUTS.items():
            original=(INPUT/item['header']).read_bytes()
            key='expanded_4K' if name.startswith('expanded') else 'regressed_v3'
            assert len(original)==512 and sha(original)==proof['headers'][key]['header_sha256']
            corrected,metadata=patch(original,name.startswith('expanded'))
            assert item['bytes']<=metadata['virtual']['declared_sector_capacity_bytes']
            save(name+'-header.bin',corrected)
            prepared[name]=(original,corrected,metadata)
        save('prepared-control-plan.json',{name:{**item,**prepared[name][2],
             'source_header_sha256':sha(prepared[name][0]),'corrected_header_sha256':sha(prepared[name][1])}
             for name,item in IMG_INPUTS.items()})
        peak=max(usage().values())
        for name,item in IMG_INPUTS.items():
            path=ROOT/item['path'];before=stamp(path)
            assert before[2]==item['bytes']
            original,corrected,metadata=prepared[name]
            baseline_hash=hashlib.sha256();virtual_hash=hashlib.sha256();offset=0
            with path.open('rb') as stream:
                while offset<item['bytes']:
                    size=min(1048576,item['bytes']-offset)
                    assert actual_read+size<=IMG_BUDGET
                    raw=stream.read(size);actual_read+=len(raw)
                    assert len(raw)==size
                    baseline_hash.update(raw)
                    if offset==0:
                        assert raw[:512]==original
                        virtual_hash.update(corrected);virtual_hash.update(memoryview(raw)[512:])
                    else:
                        virtual_hash.update(raw)
                    offset+=size
                    peak=max(peak,max(usage().values()))
            assert stamp(path)==before and baseline_hash.hexdigest()==item['sha256']
            receipt=dict(name=name,source_path=item['path'],bytes_read=offset,
                source_actual_full_SHA256=baseline_hash.hexdigest(),virtual_full_SHA256=virtual_hash.hexdigest(),
                source_stat_before=before,source_stat_after=stamp(path),source_handle_closed=True,
                source_header_matches_prepared_control=True,all_nonheader_output_bytes_source_identical=True,
                changed_byte_offsets=metadata['changed_byte_offsets'])
            receipts.append(receipt);completed[name]=receipt
            save(name+'-actual-stream-receipt.json',receipt)
        save('proof.json',dict(schema='ordinary-AP-header-controls-virtual-full-stream/v1',
            created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_completed=True,
            controls=completed,total_actual_IMG_bytes_read=actual_read,actual_IMG_read_cap=IMG_BUDGET,
            sampled_current_mm_peak_KiB=peak,current_mm_cap_KiB=RAM_BUDGET_KIB,
            all_existing_original_SHA256_reverified=True,
            all_188870_v3_supplement_records_logical_bytes_preserved=True,
            actual_new_header_bytes_only_changes=True,
            no_new_full_IMG_saved=True,original_IMG_modified=False,device_IO=False,firmware_execution=False,
            checksum_algorithm_verified=False,device_header_policy_verified=False,
            road_loss_rootcause_proven=False,rendering_UI_route_verified=False,
            installable=False,full_Taiwan_update_complete=False,full_goal_complete=False,
            next='Independent patch arithmetic review, then materialize only for attended comparison after user returns.'))
        script=Path(__file__)
        save('producer-source.py',script.read_bytes())
        save('header-decoder-source.py',(ROOT/'scripts/review_ap_IMG_header_geometry_v1.py').read_bytes())
        paths=sorted(path for path in OUT.iterdir() if path.is_file())
        save('sealed-files.json',dict(files=[dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,
             sha256=sha(path.read_bytes()),mode=oct(path.stat().st_mode&0o777)) for path in paths],
             additional_IMG_reads_at_seal=0,full_images_not_saved=True))
        print(json.dumps(dict(all_assigned_checks_completed=True,actual_IMG_read_bytes=actual_read,
             current_mm_peak_KiB=peak,controls={name:dict(virtual_SHA256=item['virtual_full_SHA256'],
             changed_bytes=len(item['changed_byte_offsets'])) for name,item in completed.items()},
             proof_sha256=sha((OUT/'proof.json').read_bytes()))))
    except BaseException as error:
        save('failure.json',dict(type=type(error).__name__,message=str(error),actual_IMG_read_bytes=actual_read,
             completed_stream_receipts=receipts))
        raise


if __name__=='__main__':
    main()
