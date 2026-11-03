#!/usr/bin/env python3
"""Audit saved new matrix evidence and seal own outputs; no guest/IMG reread."""
from pathlib import Path
import json,hashlib,struct,os
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def save(name,x):(HERE/name).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
x=json.loads((HERE/'matrix-proof.json').read_bytes());ledger=json.loads((HERE/'read-ledger.json').read_bytes())
assert x['all_assigned_checks_passed'] and x['handles_closed'] and len(x['inputs'])==3
metadata=[]
for result,inp in zip(x['results'],x['inputs']):
 p=ROOT/next(r[2]for r in __import__('run_matrix').INPUTS if r[0]==result['input']);seal=p.parent/'sealed-files.json';sb=seal.read_bytes();s=json.loads(sb);row=next(v for v in s['files']if v['path']==str(p.relative_to(ROOT)));pb=p.read_bytes();assert sha(pb)==row['sha256']
 imrow=next(v for v in s['files']if v['path']==inp['path']);assert imrow['sha256']==result['inherited_full_IMG_sha256'] and imrow['bytes']==inp['stat_before'][2]
 # Bundling legitimately changes inode ctime/link count after source seal; dev/ino/size/mtime remain exact.
 if 'stat_at_seal'in imrow:assert inp['stat_before'][:4]==imrow['stat_at_seal'][:4]
 assert inp['stat_before']==inp['stat_after'] and inp['total_actual_read_bytes']<=262144
 metadata.append(dict(proof_path=str(p.relative_to(ROOT)),proof_sha256=sha(pb),seal_sha256=sha(sb),IMG_SHA256_inherited_without_reread=result['inherited_full_IMG_sha256'],stat_preservation_dev_inode_size_mtime=True,ctime_and_linkcount_bound_fresh_at_this_read_phase=True))
windows=[]
for p in HERE.glob('windows-*.json'):windows+=json.loads(p.read_bytes())['windows']
ins={int(i['address'],0):i for w in windows for i in w['instructions']}
def witness(title,addresses,interpretation):
 return dict(title=title,instructions=[ins[a]for a in addresses],interpretation=interpretation)
witnesses=[
 witness('Original mapped region chooses outer generic file handle',[0x2d3394,0x2d33a8,0x2d33aa,0x2d33ac,0x2d33ae,0x2d33b0,0x2d33b6],'region table second byte selects36-byte device entry; entry+0x1C is outer file handle passed to31D2E0, not embedded83 descriptor'),
 witness('Actual read callback selected through child/drive/operations',[0x1fde78,0x1fde7a,0x1fde7c,0x1fde7e,0x1fde80,0x1fde82,0x1fde84,0x1fde86],'outer+0xC→child; child+0x2C→drive; drive+0x18→ops; ops+8→read; BLX r5. ABI child,destination,offset_low,offset_high,stack:count'),
 witness('Original I/O count remains512 across block profiles',[0x11d7b6,0x11d7b8,0x11d7ba,0x11d7bc,0x11d7be,0x11d7c0,0xfeb40,0xfebbc],'11D678 asks512 bytes fromFEB36; FEB36 multiplies requested sector by512 before2D3380. No fixed4K data-block calculation in these instructions'),
 witness('Original FAT mapping dynamically uses block delta',[0x123940,0x123942,0x123974,0x123984,0x123988,0x123990,0x123996,0x1239d0,0x1239d6,0x123a44,0x123a46,0x123a48,0x123a4a],'volume+2 is3 or4; original divider uses240*8 or240*16 sectors per FAT continuation; blocklist index is within-part remainder>>delta; selected block<<delta plus withinblocksector. Fixture values are explicitly derived actualheader, not produced by originalmount parser'),
 witness('Original FREAD uses512-byte logical sectors and rejects component EOF',[0x3324f4,0x3324f6,0x3324f8,0x3324fa,0x3324fc,0x332510,0x332514,0x332520,0x332522,0x332524],'bytepos+count compared unsigned against componentlength; beyondlength returns0xFFFFFFFE beforeI/O. Sectorpos is signed ASR9; that raises an untested≥2GiB issue, not a128MiB branch. No such broader limit was tested')]
geometry=[]
for r,i in zip(x['results'],x['inputs']):
 events=r['positive_guest']['backend_events'];data=[e for e in events if e['offset_low']>=i['metadata_end']]
 geometry.append(dict(input=r['input'],delta=i['block_shift'],sectorbytes=512,sectorsperblock=1<<i['block_shift'],blockbytes=i['block_bytes'],FATpart_sectorcoverage=240*(1<<i['block_shift']),declaredblockcount=i['declared_blocks'],declaredcapacitysentinel_sectors=i['declared_blocks']*(1<<i['block_shift']),actual_GMP_lowest_physical_offset=min(e['offset_low']for e in data),actual_GMP_highest_physical_offset=max(e['offset_low']for e in data),actual_GMP_backend_read_above128MiB=any(e['offset_low']>=134217728 for e in data),positive_backend_callbacks=len(events),native_seek_calls=r['positive_guest']['original_entry_visits']['0x31d1ce']))
# One native v3 seek is skipped when already at desired offset: preserve genuine control difference.
assert geometry[1]['native_seek_calls']==14 and geometry[1]['positive_backend_callbacks']==15
assert geometry[1]['actual_GMP_backend_read_above128MiB'] and geometry[2]['actual_GMP_backend_read_above128MiB']
receipts=[dict(chunk_id=c,exit_code=e,stage=s)for c,e,s in[
 ('1f75ed',0,'own capture source created'),('fcebc6',0,'root functions new MAIN capture'),('117c5d',0,'lower reader new MAIN capture'),('a517ad',0,'device operations new MAIN capture'),('8193b0',0,'generic callback new MAIN capture'),('c86fe7',0,'FREAD/mapper/memcpy/divide new MAIN capture'),('96d794',0,'division tail/comparison/new small initialized data'),('f20581',1,'source syntax check failed; no IMG opened'),('a15726',1,'source import failed; no IMG opened'),('c3839d',1,'first actual v2 partial run stopped at unmapped39129C'),('f6ca8c',1,'diagnostic second v2 partial run stopped same39129C; actual71225B receipt saved'),('0f3fc7',0,'actual reached aligned memcpy tail captured480B'),('330238',0,'corrected full threeimage matrix15 corecases/6guards, all handlesclosed')]]
save('actual-tool-receipts.json',dict(schema='bounded-reader-actual-tool-receipts/v1',receipts=receipts,first_failed_partial_actual_read_total_not_persisted=True,first_partial_perimage_limit_enforced_by_savedsource=262144,second_failed_partial_actual_read_bytes=71225,failed_partial_runs=2,corrected_complete_runs=1,not_claiming_only_one_overall_IMG_read=True,timings_not_performance_tests=True))
save('proof.json',dict(schema='bounded-original-sector-reader-AP-content-matrix-summary/v1',all_assigned_checks_passed=True,metadata_pins=metadata,matrix_proof_sha256=sha((HERE/'matrix-proof.json').read_bytes()),new_MAIN_readbytes=ledger['bytes'],new_MAIN_read_operations=ledger['operations'],new_MAIN_max=65536,MAIN_stat_stable=True,instruction_witnesses=witnesses,geometry=geometry,read_guards=dict(original_componentEOF_rejected=True,original_shortread511_rejected=True),errata=[dict(issue='Earliermessage region≥0x63 wording too broad',correction='FEB36 only has special path region==0x67; allother values call2D3380, which checks actualregion activebyte. This matrix explicitly suppliesregion0x63.'),dict(issue='Linear disassembly may continueinto literaldata or nextfunction',correction='Only exact selected reachable instructions above areclaimed; initialized_generic_file_global is8B data-only; region_write function actual stubFEB D2..D6 returns0 and isnevercalled in readonly matrix.'),dict(issue='2D3380 is generic mappedregion file reader',correction='Neither this reader nor prior embeddedVPM DSKIMG parser establishes physicalAP mount/renderer linkage.')],AP_physical_renderer_failure_reproduced=False,AP_admission_tested=False,live_boarddriver_operations_table_recovered=False,fixtures=dict(embedded83_file=True,actualheader_derived_volume=True,cache_frames=True,FATrowcache=True,outer72bytefile=True,child_drive_operations=True,task_mutex_IRQ=True,lowest_storagecallback=True),remaining_blockers=['ExactAP physicalfilename opener and mountedvolume/frame inventory remainunbound','Real board storage readslot registration/function notidentified; ops+8 fixture suppliesactual readonly hostbytes','Map admission,CHS/checksum handling,render-layer selection andNT renderer notexecuted','Genericreader byte-equivalence doesnotestablish cause orfix forphysicalv3 road disappearance'],no_whole_IMG_or_MAIN_hash=True,no_sealed_input_changes=True,no_device_IO=True,installable_or_bugfix_claim=False,handles_closed=True))
hand='''New bounded original sector reader matrix (read-only)

Corrected full run EXIT0 /330238:15 corecases,6 guards. Threeimages each read79096/78584/95480B, below262144B limit. NewMAIN capture6472B below65536B. No wholeIMG/MAIN hash, oldclosed suites, device or sharedsealed writes.

Code executes original3324B8→123920→123F6C→11D678→FEB36→2D3380→31D2E0/31D1CE/31CF22→1FDE12→1FDE86 BLX. Hostfixture onlyhandles task/mutex/IRQ and actualstorage callback ops+8. Embedded83 file,header-derivedvolume,cacheframe,rowcache,outer72-bytefile/child/drive/ops are explicitsynthetic RAM. Original mount/AP opener/boarddriver/renderer are notexecuted.

SameGMP offsets0/4080/8176/983024/1966064; boundaries cross512sectors,4K/8Kblocks,and240-block FATcontinuations. Allactual bytes same in countryv2_4K,lanev3_8K,expanded4K.disabled. Native componentEOF returnsFFFFFFFE beforebackend. Actualcallback511-byte shortread becomesoriginalFFFFFFF failure.

Originalvolume+2 dynamically selects8 vs16 sectors/block; actual native divider/fatindex/blockLSL use those values. All data sector transfersremain512. v3GMP begins149413888; expanded4KGMP begins149417984, both above134217728; genericfixture-boundreader still succeeds. This doesnotreproduce v3 roads disappearance orprovewholeplatform128MiB/8Ksupport. v2 remainsphysicallyhealthy perroot; physicalrootcause unresolved.

Preserved failures:source syntax/import occurred beforeIMGopen. Twoactualv2 partial runs stoppedat missing39129C alignedARM memcpy tail; diagnostic secondread71225B saved. Firstpartial total wasnotpersisted; savedsource enforced262144B. Captured480B originaltail thenonecorrected complete matrix. No claim of onlyoneoverall source read.

Inputs/pins/freshstable stats,exactbranchbytes,actualreadcallbacksandtoolchunks in proof.json,matrix-proof.json,read-ledger.json,actual-tool-receipts.json. Handlesclosed beforeseal; no replayneeded.

Nextminimum scope:find actual AP physicalfile opener/drive ops registration feedingchild+2C→drive+18→ops+8, thenbindrealmountedvolume beforeadmission/renderer experiments. Do notinfer VPM binding or guess checksum/priority. 4Kexpandeddisabled remainsnoninstallable; no installcandidate produced.
'''
(HERE/'HANDOFF.txt').write_text(hand)
# Scope-local evidence only. Exclude generated pycache and final seal itself.
files=[]
for p in sorted(HERE.iterdir()):
 if not p.is_file() or p.name=='sealed-files.json':continue
 p.chmod(0o444);b=p.read_bytes();s=p.stat();files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode='0o444',stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
save('sealed-files.json',dict(schema='bounded-original-sector-reader-matrix-seal/v1',all_assigned_checks_passed=True,file_count=len(files),files=files,workspace_relative_paths=True,actual_terminal_chunk='330238',actual_terminal_exit_code=0,no_device_IO=True,AP_admission_or_renderer_success=False));(HERE/'sealed-files.json').chmod(0o444)
print(json.dumps(dict(seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),proof_sha256=sha((HERE/'proof.json').read_bytes()),matrix_sha256=sha((HERE/'matrix-proof.json').read_bytes()),file_count=len(files),handles_closed=True)))
