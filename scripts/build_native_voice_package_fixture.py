#!/usr/bin/env python3
"""Repack the known preserving component in a LOCAL emulation-only VPM.

Retains directory geometry/member records; extends DLL block inventory without
claiming native signature acceptance. Output is not a device install candidate.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
from analyze_native_sections import ROOT
from analyze_tts_vpm import parse_image,sha,require

OUT=ROOT/'staging/native-voice-package-fixture'
APP=ROOT/'staging/native-app-component-emulation/Chinese_Big5_MeiLing/manifest.json'


def repack(data,module,*,checksum=True,zero_signature=False):
    files,g=parse_image(data);old=files['DLLIMG.BIN'];block=g['block_bytes']
    needed=(len(module)+block-1)//block
    require(len(old['blocks'])<=needed<=240*old['parts'],'Fixture must fit existing continuation records')
    # Native reader of this exact compact VPM treats the DLL's extent as
    # contiguous. A sparse append after SIG/END passed independent extraction
    # but failed native readback, so retain contiguous DLL layout and move
    # colliding SIG/END allocations without changing their payloads.
    require(old['blocks']==list(range(old['blocks'][0],old['blocks'][0]+len(old['blocks']))),
        'Original DLL allocation must be contiguous')
    blocks=list(range(old['blocks'][0],old['blocks'][0]+needed));end=blocks[-1]+1
    collisions=[(k,r) for k,r in files.items() if k!='DLLIMG.BIN' and set(r['blocks'])&set(blocks)]
    cursor=max(len(data)//block,end);moves={}
    for k,r in collisions:
        moves[k]=list(range(cursor,cursor+len(r['blocks'])));cursor+=len(r['blocks'])
    extra=max(0,cursor-len(data)//block);result=bytearray(data+bytes(extra*block))
    require(blocks[-1]<65535,'16-bit IMG block index overflow')
    for i,offset in enumerate(old['directory_offsets']):
        struct.pack_into('<I',result,offset+12,len(module) if i==0 else 0)
        members=blocks[i*240:(i+1)*240]
        struct.pack_into('<240H',result,offset+32,*(members+[65535]*(240-len(members))))
    for i,b in enumerate(blocks):
        chunk=module[i*block:(i+1)*block];result[b*block:(b+1)*block]=chunk+bytes(block-len(chunk))
    for key,newblocks in moves.items():
        record=files[key]
        for i,offset in enumerate(record['directory_offsets']):
            members=newblocks[i*240:(i+1)*240]
            struct.pack_into('<240H',result,offset+32,*(members+[65535]*(240-len(members))))
        for i,b in enumerate(newblocks):
            chunk=record['content'][i*block:(i+1)*block];result[b*block:(b+1)*block]=chunk+bytes(block-len(chunk))
    if checksum:
        info=bytearray(files['DLLINFO.TXT']['content'])
        import re
        oldsum=re.search(rb'<dll_chksum>(0x[0-9A-Fa-f]{8})</dll_chksum>',info)[1]
        info=info.replace(oldsum,('0x%08X'%(sum(module)&0xffffffff)).encode())
        require(len(info)==files['DLLINFO.TXT']['bytes'],'Metadata allocation changed')
        for i,b in enumerate(files['DLLINFO.TXT']['blocks']):
            chunk=info[i*block:(i+1)*block];result[b*block:b*block+len(chunk)]=chunk
    if zero_signature:
        for b in moves.get('DLLIMG.SIG',files['DLLIMG.SIG']['blocks']):
            result[b*block:b*block+files['DLLIMG.SIG']['bytes']]=bytes(files['DLLIMG.SIG']['bytes'])
    reread,newg=parse_image(bytes(result))
    require(reread['DLLIMG.BIN']['content']==module,'Repacked module readback differs')
    changed={'DLLIMG.BIN'}|({'DLLINFO.TXT'} if checksum else set())|({'DLLIMG.SIG'} if zero_signature else set())
    require(all(reread[k]['sha256']==r['sha256'] for k,r in files.items() if k not in changed),'Unrelated VPM member changed')
    return bytes(result),{'appended_blocks':extra,'all_other_members_byte_identical':True,'changed_members':sorted(changed),
        'DLL_blocks_contiguous':True,'allocation_relocated_members':sorted(moves),
        'directory_geometry_unchanged':all(newg[k]==g[k] for k in ['block_bytes','directory_start','directory_end']),
        'unidentified_outer_header_size_fields_not_changed':True,'signature_algorithm_or_enforcement_verified':False}


def main():
    app=json.loads(APP.read_text())
    for path,h in app['source_sha256'].items():require(sha((ROOT/path).read_bytes())==h,'Frozen component source changed: '+path)
    module=(ROOT/app['combined_binary']).read_bytes();require(sha(module)==app['combined_sha256'],'Component binary changed')
    source=ROOT/app['voice_package'];data=source.read_bytes();OUT.mkdir(exist_ok=True,parents=True)
    package,checks=repack(data,module);path=OUT/'preserving-app-EMULATION-ONLY.vpm';path.write_bytes(package)
    files,g=parse_image(package)
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),'package':str(path.relative_to(ROOT)),
        'package_sha256':sha(package),'package_bytes':len(package),'original_package':str(source.relative_to(ROOT)),
        'original_package_sha256':sha(data),'component_manifest':str(APP.relative_to(ROOT)),
        'component_manifest_sha256':sha(APP.read_bytes()),'module_sha256':sha(module),'module_file_bytes':len(module),
        'module_ram_bytes':app['combined_ram_bytes'],'geometry':g,'checks':checks,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in [Path(__file__),ROOT/'scripts/analyze_tts_vpm.py',ROOT/'scripts/analyze_native_sections.py']},
        'original_signature_retained_but_not_validated_for_changed_module':True,
        'signature_acceptance_verified':False,'real_outer_mount_verified':False,'device_io':False,
        'backup_modified':False,'device_install_candidate':False,
        'limits':'Local repacking fixture preserves contiguous DLL extent, relocates collidingSIG/END allocation only and updates byte-sum metadata; all other member payloads and originalSIG retained. Earlier sparse append passed independent parser but failed native readback and was rejected. Opaque outer header size semantics and global signature policy remain unverified. This file is for offline execution only and must not be transferred to navigator as an install candidate.'}
    (OUT/'manifest.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),'package_bytes':len(package),
        'appended_blocks':checks['appended_blocks'],'device_install_candidate':False}))


if __name__=='__main__':main()
