"""Compose one-source new street on v2; disabled output, no install bundle.

Original 4K header and capacity are retained. Full source component identities
are checked during the actual new composition, not by rerunning old suites.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-new-street-v2-4k-offline-prototype-v2'
SOURCE = ROOT/'staging/navigation-country-native-candidate-v2/gmapprom1.img'
FAMILY = ROOT/'staging/navigation-native-new-street-v2-family-payload-v1'
WRITER = ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
WRITER_SHA = 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
EXPECTED_BYTES = 132173824


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def saved(name, value):
    raw = value if type(value) is bytes else (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    with (OUT/name).open('xb') as f:
        need(f.write(raw)==len(raw), 'Full new evidence write')
        f.flush();os.fsync(f.fileno())
    return dict(path=str((OUT/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def load_writer():
    raw = WRITER.read_bytes()
    need(sha(raw)==WRITER_SHA, 'Exact closed original4K writer API')
    spec=importlib.util.spec_from_file_location('new_street_v2_original4k_writer',WRITER)
    mod=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
    return mod


def main():
    need(not OUT.exists(), 'Independent new prototype namespace')
    began=datetime.now(timezone.utc)
    seal_raw=(FAMILY/'sealed-files.json').read_bytes()
    need(sha(seal_raw)=='1a59bb59337ecd9f71fef7ae1834bbe36100238add3355519012c14b8b892601', 'Completed v2 family seal')
    pins={Path(r['path']).name:r for r in json.loads(seal_raw)['files']}
    def family(name):
        raw=(FAMILY/name).read_bytes()
        need(len(raw)==pins[name]['bytes'] and sha(raw)==pins[name]['sha256'], 'Family artifact binding '+name)
        return raw
    payload=json.loads(family('proof.json'))
    need(payload['all_assigned_checks_passed'] and payload['source_and_raw24_in_exact_source_district'] and
         payload['new_street_ID']==48312 and payload['new_L4_house_ID']==3781595 and not payload['installable'], 'Exact proposed v2 source payload')
    L3append=family('L3-family-append.bin');L4append=family('L4-house-append.bin')
    L2patch=family('L2-patch-record.bin');label_extension=family('LBL-label-extension.bin')
    label_header=family('LBL-header-pointer-size.bin')
    original_receipt=json.loads((ROOT/'staging/navigation-country-native-candidate-v2/stream-write-receipt.json').read_text())
    source_before=stat(SOURCE)
    need(source_before==payload['actual_v2_stat_before'] and not SOURCE.stat().st_mode&0o222, 'Exact unchanged v2 source')
    api=load_writer()
    OUT.mkdir()
    target=OUT/'new-street-v2-original4k-experiment.img.disabled'
    source_hashes={}
    with SOURCE.open('rb') as stream:
        image=api.StreamIMG(stream)
        need(image.size==128356352 and image.capacity==134217728, 'Original v2 capacity')
        def exact(name, at, n):
            raw=b''.join(image.iter_component(name,offset=at,length=n))
            need(len(raw)==n, 'Exact source logical read')
            return raw
        mdr='00004171.MDR';gmp='I053061A.GMP'
        old_header=exact(mdr,0,772)
        dstart,dbytes,dstride,dflags=struct.unpack_from('<4I',old_header,600)
        need((dbytes,dstride,dflags)==(120,20,1) and dstart+120==image.components[mdr].size, 'Actual original MDR directory')
        old_directory=exact(mdr,dstart,120)
        old_tables=[]
        for i in range(6):
            start,size,stride=struct.unpack_from('<3I',old_directory,i*20)
            count=size*8//stride
            need(size==(count*stride+7)//8, 'Exact current packed span')
            old_tables.append(dict(level=i+1,start=start,bytes=size,stride=stride,count=count))
        need(tuple(t['count'] for t in old_tables)==(22,343,47870,3781594,2667573,1984066), 'Current v2 profile')
        need(tuple(t['stride'] for t in old_tables)==(122,122,112,128,126,68), 'Unchanged packed widths')
        old_L2=exact(mdr,old_tables[1]['start'],old_tables[1]['bytes'])
        low,shift=divmod((74-1)*122,8);n=(shift+122+7)//8
        patchmask=((1<<122)-1)<<shift
        original_window=int.from_bytes(old_L2[low:low+n],'little')
        altered=(original_window&~patchmask)|(int.from_bytes(L2patch,'little')<<shift)
        new_L2=bytearray(old_L2);new_L2[low:low+n]=altered.to_bytes(n,'little')
        need((original_window^altered)&~patchmask==0 and len(new_L2)==len(old_L2), 'Mixed source window adjacent bits preserved')
        new_tables=[dict(t) for t in old_tables]
        new_tables[2].update(count=48312,bytes=old_tables[2]['bytes']+len(L3append))
        new_tables[3].update(count=3781595,bytes=old_tables[3]['bytes']+len(L4append))
        cursor=old_tables[5]['start']
        for level in (6,5,4,3,2,1):
            t=new_tables[level-1];t['start']=cursor;cursor+=t['bytes']
        new_header=bytearray(old_header);struct.pack_into('<I',new_header,600,cursor)
        new_directory=bytearray(old_directory)
        for i,t in enumerate(new_tables):struct.pack_into('<II',new_directory,i*20,t['start'],t['bytes'])
        new_mdr_bytes=cursor+120
        need(new_mdr_bytes==payload['proposed_MDR_bytes'] and new_mdr_bytes==124261511, 'Proposed actual MDR size')
        original_gmp_pointer=exact(gmp,874+21,8)
        need(struct.unpack('<II',original_gmp_pointer)==(6566,3805432), 'Original label pool')
        new_gmp_bytes=image.components[gmp].size+3805432+len(label_extension)
        need(new_gmp_bytes==payload['proposed_GMP_bytes']==7618272, 'Proposed actual GMP size')
        # Stream original source in its complete logical order, updating its
        # digest once while emitting changed headers/appends separately.
        def mdr_chunks():
            digest=hashlib.sha256()
            digest.update(old_header);yield bytes(new_header)
            for raw in image.iter_component(mdr,offset=772,length=old_tables[5]['start']-772):digest.update(raw);yield raw
            for level in (6,5,4,3,2,1):
                t=old_tables[level-1]
                if level==2:
                    digest.update(old_L2);yield bytes(new_L2)
                else:
                    for raw in image.iter_component(mdr,offset=t['start'],length=t['bytes']):digest.update(raw);yield raw
                if level==4:yield L4append
                if level==3:yield L3append
            digest.update(old_directory);yield bytes(new_directory)
            source_hashes[mdr]=digest.hexdigest()
        def gmp_chunks():
            digest=hashlib.sha256()
            for raw in image.iter_component(gmp,offset=0,length=895):digest.update(raw);yield raw
            digest.update(original_gmp_pointer);yield label_header
            for raw in image.iter_component(gmp,offset=903,length=image.components[gmp].size-903):digest.update(raw);yield raw
            source_hashes[gmp]=digest.hexdigest()
            yield from image.iter_component(gmp,offset=6566,length=3805432)
            yield label_extension
        replacements={mdr:api.Replacement(new_mdr_bytes,mdr_chunks),gmp:api.Replacement(new_gmp_bytes,gmp_chunks)}
        capacity=api.plan_repack(image,{k:r.size for k,r in replacements.items()})
        need(capacity['image_bytes']==EXPECTED_BYTES and capacity['directory_end']==payload['proposed_metadata_bytes'], 'Unchanged capacity profile fits')
        compact_restore=saved('v2-exact-restore-metadata.json',dict(schema='v2-to-new-street-inverse-descriptor/v1',
            original_source_sha256=payload['actual_v2_source_SHA_inherited'],original_source_bytes=128356352,
            original_IMG_metadata_hex=image.physical(0,image.directory_end,'compact_inverse_source_metadata').hex(),
            original_MDR_header_hex=old_header.hex(),original_MDR_directory_hex=old_directory.hex(),
            original_tables=old_tables,original_L2_hex=old_L2.hex(),original_GMP_label_pointer_hex=original_gmp_pointer.hex(),
            original_components=original_receipt['components'],original_GMP_bytes=3812824))
        with target.open('xb') as destination:
            written=api.repack_stream(image,destination,replacements);destination.flush();os.fsync(destination.fileno())
        for r in original_receipt['components']:
            observed=source_hashes[r['name']] if r['name'] in source_hashes else next(x['sha256'] for x in written['components'] if x['name']==r['name'])
            need(observed==r['sha256'], 'Complete original v2 component provenance '+r['name'])
        read_log_summary=dict(physical_reads=len(image.read_log),total_bytes=sum(r['bytes'] if 'bytes' in r else r['length'] for r in image.read_log))
        need(stat(SOURCE)==source_before, 'Original v2 unchanged during composition')
    with target.open('rb') as output:
        complete_SHA=hashlib.file_digest(output,'sha256').hexdigest()
        actual=api.StreamIMG(output)
        need(actual.prefix==image.prefix and actual.size==EXPECTED_BYTES and actual.capacity==134217728, 'Actual output original header/prefix retained')
        readback=[]
        for r in written['components']:
            digest=hashlib.sha256();total=0
            for raw in actual.iter_component(r['name']):digest.update(raw);total+=len(raw)
            need(total==r['bytes'] and digest.hexdigest()==r['sha256'], 'Complete actual output component readback '+r['name'])
            c=actual.components[r['name']];padding=(-c.size)%4096
            if padding:
                output.seek(c.blocks[-1]*4096+4096-padding);need(output.read(padding)==bytes(padding), 'Actual zero allocation tail')
            readback.append(dict(name=r['name'],bytes=total,sha256=digest.hexdigest(),tail_padding_zero=True))
        exact_out=lambda name,at,n:b''.join(actual.iter_component(name,offset=at,length=n))
        need(exact_out(mdr,0,772)==new_header and exact_out(mdr,cursor,120)==new_directory, 'Actual new MDR header/directory')
        need(exact_out(mdr,new_tables[2]['start']+old_tables[2]['bytes'],len(L3append))==L3append and
             exact_out(mdr,new_tables[3]['start']+old_tables[3]['bytes'],16)==L4append and
             exact_out(mdr,new_tables[1]['start'],len(new_L2))==new_L2, 'Actual family/house/L2 payload readback')
        need(exact_out(gmp,895,8)==label_header and exact_out(gmp,new_gmp_bytes-len(label_extension),len(label_extension))==label_extension,
             'Actual LBL source label pointer/suffix')
    need(stat(SOURCE)==source_before, 'Original v2 still unchanged after readback')
    target.chmod(0o444)
    saved('stream-write-receipt.json',written)
    saved('actual-output-layout.json',dict(schema='one-source-v2-new-street-original4K-layout/v1',candidate_bytes=EXPECTED_BYTES,
        MDR_bytes=new_mdr_bytes,GMP_bytes=new_gmp_bytes,MDR_directory_start=cursor,tables=new_tables,
        components=[dict(name=c.name,size=c.size,blocks=list(c.blocks)) for c in actual.components.values()],installable=False))
    proof=dict(schema='source-bound-v2-new-street-full-offline-prototype/v2',started_utc=began.isoformat(),finished_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,script_sha256=sha(Path(__file__).read_bytes()),family_seal_sha256=sha(seal_raw),
        closed_original4K_writer_sha256=WRITER_SHA,output=str(target.relative_to(ROOT)),output_bytes=EXPECTED_BYTES,output_sha256=complete_SHA,
        current_v2_inherited_full_sha256=payload['actual_v2_source_SHA_inherited'],original_v2_source_unchanged=True,
        complete_original_components_checked_during_new_stream=True,complete_actual_output_component_readback=readback,
        original_header_and_capacity_prefix_byte_identical=True,original_checksum_CHS_and_capacity_not_changed=True,
        original_lower_L6_L5_L4_byte_prefixes_retained=True,original_L3_prefix_and_current_v2_child_refs_retained=True,
        L2_only_one_family_first_count_changed=True,L2_mixed_window_adjacent_bits_retained=True,
        family_cloned_verbatim=441,new_street_ID=48312,new_house_L4_ID=3781595,new_street='敦富六街',new_house='368號',source_node_ID=8280986017,
        source_and_raw24_complete_Beitun_geometry_passed=True,source_history_alias_or_official_street_verified=False,
        source_physical_read_summary=read_log_summary,compact_restore_metadata=compact_restore,
        compact_restore_execution_verified=False,original_TWNJAI_backup_not_modified=True,
        compatible_offline_full_JAI_prototype='staging/navigation-native-jai-full-db-adapter-prototype-v1/TWNJAI-offline-prototype.sqlite',
        native_CPU_query_mount_renderer_UI_or_device_acceptance_verified=False,
        original_40_voice_exports_or_bluetooth_audio_modified=False,device_IO=False,installable=False,full_Taiwan_update_complete=False,
        limits=['One primary source-backed new street/house offline prototype, not a complete country update.',
                'Only compact inverse descriptor prepared; execute exact v2 restore before any future bundle.',
                'Original native frontend/whole mount/display/routing and official aliases remain unverified.',
                'The full JAI prototype is separate; no DB bundled or device installed.',
                'Actual image remains disabled and immutable; original device working v2 untouched.'])
    savedproof=saved('proof.json',proof)
    print(json.dumps(dict(all_passed=True,proof=savedproof,output_bytes=EXPECTED_BYTES,output_sha256=complete_SHA,installable=False)))


if __name__=='__main__':
    main()
