#!/usr/bin/env python3
"""User-authorized exact duplicate removal, preserving immutable read paths."""
import os,json,hashlib,subprocess,shutil,tempfile,collections
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'staging/garminos-storage-cleanup-v1';BACKUP=ROOT/'backups/20261002T154458Z';FILES=BACKUP/'files'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 out=BASE/'cleanup-result.json';assert not out.exists()
 plan=json.loads((BASE/'verified-cleanup-plan.json').read_text());assert plan['all_passed']and plan['backup_verified_files']==1402
 before=shutil.disk_usage(ROOT);manifest=json.loads((BACKUP/'files-manifest.json').read_text());expected={r['path']:r for r in manifest};actual={str(p.relative_to(FILES))for p in FILES.rglob('*')if p.is_file()}
 assert not FILES.is_mount()and actual==set(expected),'Unexpected extracted file; no removal'
 for rel,row in expected.items():
  p=FILES/rel;assert not p.is_symlink()and p.stat().st_size==row['size']and sha(p)==row['sha256'],'Extracted file changed: '+rel
 print(json.dumps(dict(extracted1402_files_match_retained_image=True,ready_for_exact_duplicate_removal=True)),flush=True)
 image=BACKUP/'sda.img';unit_name=subprocess.check_output(['systemd-escape','--path','--suffix=mount',str(FILES)],text=True).strip();unit=Path('/etc/systemd/system')/unit_name;assert not unit.exists()
 unit_text=f'''[Unit]
Description=Garmin sole original backup image, read-only research view
After=local-fs.target

[Mount]
What={image}
Where={FILES}
Type=vfat
Options=loop,ro,nodev,nosuid,noexec,umask=0077
TimeoutSec=30

[Install]
WantedBy=multi-user.target
'''
 create(BASE/'backup-image-view-preflight.json',dict(image_sha256=plan['backup_image_sha256'],all_extracted_files_verified=True,unit_name=unit_name,unit_text=unit_text,sole_full_backup_image=plan['backup_image'],device_IO=False))
 extracted=BACKUP/'files.extracted-cleanup-v1';assert not extracted.exists()
 FILES.rename(extracted);FILES.mkdir()
 try:
  unit.write_text(unit_text);subprocess.run(['systemd-analyze','verify',str(unit)],capture_output=True,text=True,check=True);subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','enable','--now',unit_name],capture_output=True,text=True,check=True)
  assert FILES.is_mount();fs=json.loads(subprocess.check_output(['findmnt','--json','--mountpoint',str(FILES),'-o','TARGET,SOURCE,FSTYPE,OPTIONS'],text=True))['filesystems'][0];assert fs['fstype']=='vfat'and 'ro'in fs['options'].split(',')
  # Recheck every saved file on the actual permanent mount before deleting data.
  for rel,row in expected.items():
   p=FILES/rel;assert p.is_file()and p.stat().st_size==row['size']and sha(p)==row['sha256'],rel
 except BaseException:
  subprocess.run(['systemctl','disable','--now',unit_name],capture_output=True);unit.unlink(missing_ok=True)
  assert not FILES.is_mount();FILES.rmdir();extracted.rename(FILES);raise
 # At this point the retained image has twice been checked, and all extracted
 # files have been checked individually. Only that exact duplicate tree goes.
 shutil.rmtree(extracted)
 check=Path(plan['read_only_mountpoint']);subprocess.run(['umount',str(check)],check=True);check.rmdir()
 operations=[];groups=plan['exact_duplicate_groups'];journal=BASE/'duplicate-link-operations.jsonl';assert not journal.exists()
 def rank(row):
  p=row['path'];return (0 if p.startswith('backups/20261002T154458Z/files/')else 1 if p.startswith('evidence/firmware-analysis/')else 3 if 'GarminOS-2565RT-research/'in p else 2,p)
 with journal.open('x')as log:
  for g in groups:
   paths=g['paths'];canonical=min(paths,key=rank);source=ROOT/canonical['path'];assert source.is_file()and sha(source)==g['sha256']
   image_backed=source.is_relative_to(FILES);source_stat=source.stat()
   for row in paths:
    target=ROOT/row['path'];st=target.stat()
    if target==source or(st.st_dev,st.st_ino)==(source_stat.st_dev,source_stat.st_ino):continue
    assert target.is_file()and not target.is_symlink()and st.st_size==g['bytes']and sha(target)==g['sha256'],row['path']
    if not image_backed and (st.st_dev!=source_stat.st_dev or(st.st_mode&0o777)!=(source_stat.st_mode&0o777)):continue
    temporary=target.parent/('.garmin-dedup-'+target.name);assert not temporary.exists()and not temporary.is_symlink()
    if image_backed:os.symlink(os.path.relpath(source,target.parent),temporary);kind='read_only_backup_image_symlink'
    else:os.link(source,temporary);kind='single_shared_inode_hardlink'
    assert sha(temporary)==g['sha256'];os.replace(temporary,target);assert sha(target)==g['sha256']
    operation=dict(path=row['path'],canonical=canonical['path'],bytes=g['bytes'],sha256=g['sha256'],operation=kind,old_inode=st.st_ino,new_inode=target.stat().st_ino,old_content_removed_only_after_verified_canonical=True);operations.append(operation);log.write(json.dumps(operation)+'\n');log.flush();os.fsync(log.fileno())
   if len(operations)and len(operations)%20==0:print(json.dumps(dict(duplicate_copies_removed_so_far=len(operations))),flush=True)
 # No protected bytes or record paths were sacrificed for space. Working C
 # sources were not part of the large immutable-file duplicate plan.
 audit=json.loads((ROOT/'evidence/firmware-analysis/native-platform-readonly-probe-ROOT-checkpoint-audit.json').read_text());protected=audit['protected_sources']
 for path,digest in protected.items():assert sha(ROOT/path)==digest,path
 assert all(sha(ROOT/path)==digest for path,digest in audit['canonical_after_sha256'].items())
 os.sync();after=shutil.disk_usage(ROOT)
 result=dict(all_passed=True,user_authorized_duplicate_cleanup=True,sole_complete_backup=plan['backup_image'],sole_backup_sha256=plan['backup_image_sha256'],backup_image_unchanged=True,complete_original1402_file_readback_verified=True,duplicate_extracted_tree_removed=True,old_file_paths_preserved_by_readonly_image_mount=True,backup_view_mount_unit=unit_name,duplicate_copies_removed=len(operations),dedup_hardlinks=sum(o['operation']=='single_shared_inode_hardlink'for o in operations),readonly_image_symlinks=sum(o['operation']=='read_only_backup_image_symlink'for o in operations),before_free_bytes=before.free,after_free_bytes=after.free,freed_bytes=after.free-before.free,protected4596_sources_rechecked=len(protected),protected_source_content_preserved=True,original_working_C_source_removed=False,distinct_prototype_results_removed=False,VS_Code_archive_retained='reports/downloads/GarminOS-2565RT-research-v1.zip',device_IO=False,created_utc=datetime.now(timezone.utc).isoformat())
 create(out,result);print(json.dumps(result),flush=True)
if __name__=='__main__':main()
