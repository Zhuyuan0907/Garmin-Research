"""Hash the exact reconstructed v2 from the new disabled IMG, no full copy."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'staging/navigation-new-street-v2-4k-offline-prototype-v2'
OUT=ROOT/'staging/navigation-new-street-v2-exact-inverse-v1'
PIN='5dc142d545ad114c727e7ecad97b8e42ef8df348aaaf406291a631e36496ba03'


def need(ok,msg):
    if not ok:
        raise ValueError(msg)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def main():
    need(not OUT.exists(),'New independent inverse verification namespace')
    began=datetime.now(timezone.utc)
    sealed=(SOURCE/'sealed-files.json').read_bytes();need(sha(sealed)==PIN,'Sealed complete new prototype')
    pins={Path(row['path']).name:row for row in json.loads(sealed)['files']}
    def bind(name):
        row=pins[name];raw=(SOURCE/name).read_bytes()
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'Pinned small descriptor '+name)
        return json.loads(raw)
    restore=bind('v2-exact-restore-metadata.json');layout=bind('actual-output-layout.json');host=bind('proof.json')
    need(host['all_assigned_checks_passed'] and not host['installable'],'Noninstallable complete source checks')
    image_path=SOURCE/'new-street-v2-original4k-experiment.img.disabled';before=stat(image_path)
    row=pins[image_path.name]
    need(before==row['stat_at_seal'] and row['sha256']==host['output_sha256'],'Frozen actual output identity; no wholeSHA repeat')
    api_path=ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
    need(sha(api_path.read_bytes())=='cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8','Exact readonly source mapper')
    spec=importlib.util.spec_from_file_location('newstreet_inverse_original4K_mapper',api_path)
    api=importlib.util.module_from_spec(spec);sys.modules[spec.name]=api;spec.loader.exec_module(api)
    whole=hashlib.sha256();whole_bytes=0;component_checks=[]
    def consume(raw):
        nonlocal whole_bytes
        whole.update(raw);whole_bytes+=len(raw)
    metadata=bytes.fromhex(restore['original_IMG_metadata_hex']);need(len(metadata)==73728,'Original exact metadata extent')
    consume(metadata)
    with image_path.open('rb') as stream:
        image=api.StreamIMG(stream)
        need(image.size==host['output_bytes']==132173824,'Frozen original4K experiment')
        new={t['level']:t for t in layout['tables']};old={t['level']:t for t in restore['original_tables']}
        def ranges(name,at,n):yield from image.iter_component(name,offset=at,length=n)
        def restore_mdr():
            yield bytes.fromhex(restore['original_MDR_header_hex'])
            yield from ranges('00004171.MDR',772,old[6]['start']-772)
            for level in (6,5,4,3,2,1):
                if level==2:yield bytes.fromhex(restore['original_L2_hex'])
                else:yield from ranges('00004171.MDR',new[level]['start'],old[level]['bytes'])
            yield bytes.fromhex(restore['original_MDR_directory_hex'])
        def restore_gmp():
            yield from ranges('I053061A.GMP',0,895)
            yield bytes.fromhex(restore['original_GMP_label_pointer_hex'])
            yield from ranges('I053061A.GMP',903,restore['original_GMP_bytes']-903)
        for pin in restore['original_components']:
            name=pin['name']
            pieces=restore_mdr() if name=='00004171.MDR' else restore_gmp() if name=='I053061A.GMP' else ranges(name,0,pin['bytes'])
            digest=hashlib.sha256();amount=0
            for raw in pieces:
                need(type(raw)is bytes and raw and amount+len(raw)<=pin['bytes'],'Finite inverse component stream')
                consume(raw);digest.update(raw);amount+=len(raw)
            need(amount==pin['bytes'] and digest.hexdigest()==pin['sha256'],'Exact prior component reconstruction '+name)
            padding=(-amount)%4096
            if padding:consume(bytes(padding))
            component_checks.append(dict(name=name,bytes=amount,sha256=digest.hexdigest(),exact_prior_v2=True,padding_bytes=padding))
        physical_read_count=len(image.read_log)
        physical_bytes=sum(r['bytes'] if 'bytes'in r else r['length'] for r in image.read_log)
    need(stat(image_path)==before,'Source unchanged and all handles closed')
    need(whole_bytes==restore['original_source_bytes']==128356352 and
         whole.hexdigest()==restore['original_source_sha256']=='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
         'Whole exact prior v2 bytes independently reconstructed')
    OUT.mkdir()
    proof=dict(schema='newstreet-original4K-to-exact-v2-inverse/v1',all_assigned_checks_passed=True,
        started_utc=began.isoformat(),finished_utc=datetime.now(timezone.utc).isoformat(),script_sha256=sha(Path(__file__).read_bytes()),
        source_seal_sha256=PIN,source_candidate_full_SHA_inherited=host['output_sha256'],source_candidate_stat_unchanged=True,
        reconstructed_v2_bytes=whole_bytes,reconstructed_v2_sha256=whole.hexdigest(),complete_inverse_component_checks=component_checks,
        actual_source_physical_reads=physical_read_count,actual_source_physical_bytes=physical_bytes,
        whole_inverse_output_stream_reconstructed=True,inverse_output_written_only_to_SHA_sink=True,
        original_v2_source_image_opened_or_rehashed=False,second_full_IMG_backup_created=False,
        native_CPU_or_query_or_mount_renderer_or_UI_verified=False,device_IO=False,installable=False,
        full_Taiwan_update_complete=False,all_handles_closed=True,
        limits=['Actual complete inverse bytes are independently streamed into a SHA sink; no duplicate full map/backup created.',
                'This proves reversibility to previous countryv2, not original stock or hardware acceptance.',
                'Native frontend, official aliases, map display/navigation and original device unchanged.'])
    with (OUT/'proof.json').open('xb')as f:
        f.write((json.dumps(proof,ensure_ascii=False,indent=2)+'\n').encode());f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(all_passed=True,reconstructed_v2_bytes=whole_bytes,reconstructed_v2_sha256=whole.hexdigest(),
        source_physical_bytes=physical_bytes,proof_sha256=sha((OUT/'proof.json').read_bytes()),second_full_backup=False)))


if __name__=='__main__':main()
