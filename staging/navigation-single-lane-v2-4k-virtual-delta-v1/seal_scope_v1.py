#!/usr/bin/env python3
"""Seal only ordinary small artifacts; never opens an IMG or original source gzip."""
import gzip,hashlib,json,os,struct
from pathlib import Path
ROOT=Path('/root/garmin');P=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def load(n):return json.loads((P/n).read_bytes())
def check(t,msg):
    if not t:raise ValueError(msg)
def stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
proof=load('proof.json');stream=load('stream-receipt.json');index=load('actual-stream-windows-index.json')
capture=(P/'actual-stream-windows.bin').read_bytes();inv=load('inverse-metadata.json');delta=load('delta-manifest.json')
readback=load('actual-captured-readback-proof.json');closure=load('handle-closure.json')
check(proof['all_passed'] and readback['all_passed'],'Actual saved pass flags')
check(stream['source_inverse_IMG_SHA256']==proof['original_full_SHA256']==
 '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb','Actual inverse hash equality')
check(closure['readonly_source_handle_closed'] and closure['source_unchanged'],'Source closure/stat')
check(stat(ROOT/closure['source_path'])==closure['stat_after'],'Source stat at seal; no source bytes read')
check(all(not v for v in proof['falseflags'].values()),'False CPU/UI/device/music flags')
check(sum(r['bytes'] for r in index)==len(capture)==88047,'Complete finite actual captures')
for r in index:
    b=capture[r['artifact_offset']:r['artifact_offset']+r['bytes']]
    check(sha(b)==r['SHA256'],'Actual capture SHA')
def actual(at,n):
    for r in index:
        if r['physical_offset']<=at and at+n<=r['physical_offset']+r['bytes']:
            low=r['artifact_offset']+at-r['physical_offset'];return capture[low:low+n]
    raise ValueError('Uncaptured actual saved output request')
newmetadata=actual(0,inv['new_layout']['directory_end'])
oldmetadata=bytearray(newmetadata[:inv['old_layout']['directory_end']])
packed=(P/'inverse-metadata-runs.bin').read_bytes()
check(sha(packed)==inv['metadata_diff_runs_SHA256'],'Packed inverse metadata pin')
at=0;seen=0;lastend=0
while at<len(packed):
    offset,n=struct.unpack_from('<IH',packed,at);at+=6
    check(n>0 and offset>=lastend and offset+n<=len(oldmetadata),'Ordered bounded inverse byte runs')
    old,new=packed[at:at+n],packed[at+n:at+2*n];at+=2*n
    check(len(old)==len(new)==n and oldmetadata[offset:offset+n]==new,'Actual emitted metadata matches inverse newbytes')
    oldmetadata[offset:offset+n]=old;seen+=1;lastend=offset+n
check(at==len(packed) and seen==inv['metadata_diff_run_count'],'All packed inverse runs recoverable')
check(oldmetadata[:4096]==newmetadata[:4096],'Actual original header/checksum/CHS/prefix unchanged')
padding=inv['original_component_padding'];compressed=(P/padding['artifact']).read_bytes()
check(sha(compressed)==padding['artifact_SHA256'],'Padding compressed pin')
b=gzip.decompress(compressed);check(len(b)==padding['uncompressed_bytes']==11999,'Full original padding recoverable')
for r in padding['components'].values():
    check(sha(b[r['offset']:r['offset']+r['bytes']])==r['SHA256'],'Each actual original padding hash')
check(sum(n for _,n in inv['MDR_keep_new_offset_old_length'])==124255307,'Exact inverse span bytes')
check(delta['COW_report']['L3_stride']==112 and delta['COW_report']['L3_first_width']==23,'Actual current profile')
check(delta['appended_L4_count']==267 and delta['appended_L5_count']==5 and delta['appended_L6_count']==0,'Only finite COW appends')
mdrbase=inv['new_layout']['allocations']['00004171.MDR']['first_block']*4096
t=delta['COW_report']['new_tables'];l4=t[3];l5=t[4]
saved4=(P/'append-L4-267-significant.bin').read_bytes()
check(actual(mdrbase+l4['start']+(3781595-1)*16,4272)==saved4,'Saved actual emitted L4 append equality')
bit=(2667574-1)*126;off,shift=divmod(bit,8)
wire=actual(mdrbase+l5['start']+off,(shift+630+7)//8)
bits=(int.from_bytes(wire,'little')>>shift)&((1<<630)-1)
saved5=(P/'append-L5-5-significant.bin').read_bytes()
check(bits.to_bytes(79,'little')==saved5 and saved5[-1]>>6==0,'Actual emitted cross-byte L5 append significantbits')
first=load('prestream-failure-receipt.json');failed=gzip.decompress((P/first['failed_source_snapshot']).read_bytes())
check(sha(failed)==first['failed_source_SHA256'] and first['exit_code']==1,'Actual first failure retained')
totalreads=stream['source_read_receipt']['actual_bytes_read']+first['source_actual_bytes_read']
check(totalreads==129272567 and totalreads<=150000000,'Aggregate source IMG bytes includes prestream repeated reads')
for r in proof['normal_inputs']:
    p=ROOT/r['path'];check(stat(p)==r['stat_after'],'Old normal input stat unchanged')
    check(sha(p.read_bytes())==r['SHA256'],'Old small normal input hash unchanged')
audit={'all_small_artifact_seal_checks_passed':True,'actual_IMG_bytes_read_by_sealer':0,
 'actual_saved_capture_bytes_audited':len(capture),'actual_inverse_metadata_runs_checked':seen,
 'actual_original_padding_bytes_recovered':len(b),'actualcrossbyte_L5_appended630bits_verified':True,
 'aggregate_IMG_source_reads_all_attempts':totalreads,'old_normal_input_pins_unchanged':True,
 'original_full_inverse_evidence':'Computed during actual forward emission; sealer verifies stored receipt and exact small inverse recipe/captures, does not repeat full inverse stream or fullIMGhash.',
 'original_fullsource_MDR_digest_scope_separate':True,'no_second_fullIMG_readback':True}
(P/'small-artifact-seal-audit.json').write_text(json.dumps(audit,separators=(',',':'))+'\n')
files=[]
for p in sorted(P.iterdir()):
    if p.is_file() and p.name not in ('sealed-files.json','actual-sealer-receipt.json'):
        b=p.read_bytes();files.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),
          'stat_at_seal':stat(p),'mode':oct(p.stat().st_mode&0o777)})
seal={'schema':'hash-size-stat-seal/single-lane-virtual-v1','files':files,'sealed_artifact_bytes':sum(r['bytes'] for r in files),
 'scope_payload_limit_bytes':262144,'seal_kind':'Hash/size/stat, no chmod or claim of immutable access mode.',
 'no_IMG_file_created':True,'actual_virtual_terminal':'ab0374 EXIT0','nativeCPU_device_audio':False}
raw=(json.dumps(seal,separators=(',',':'))+'\n').encode()
check(sum(r['bytes'] for r in files)+len(raw)+2048<=262144,'All scope payloads plus seal/final receipt <=256KiB')
(P/'sealed-files.json').write_bytes(raw)
print(json.dumps({'all_passed':True,'sealed_files':len(files),'seal_SHA256':sha(raw),
 'proof_SHA256':sha((P/'proof.json').read_bytes()),'sealed_and_seal_bytes':sum(r['bytes'] for r in files)+len(raw),
 'aggregate_IMG_source_reads':totalreads,'IMG_reads_this_sealer':0}))
