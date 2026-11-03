#!/usr/bin/env python3
"""Read-only exact-content duplicate inventory and sole-image backup check."""
import json,hashlib,collections,os,subprocess
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'staging/garminos-storage-cleanup-v1';BACKUP=ROOT/'backups/20261002T154458Z';MOUNT=Path('/run/garmin-backup-readonly-check')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
def main():
 out=BASE/'verified-cleanup-plan.json';assert not out.exists()
 disk=json.loads((BACKUP/'sda.json').read_text());image=BACKUP/'sda.img';assert image.stat().st_size==disk['size']and sha(image)==disk['sha256']
 assert MOUNT.is_mount();r=subprocess.check_output(['findmnt','--json','--mountpoint',str(MOUNT),'-o','TARGET,SOURCE,FSTYPE,OPTIONS'],text=True);fs=json.loads(r)['filesystems'][0];assert fs['fstype']=='vfat'and 'ro'in fs['options'].split(',')
 files=json.loads((BACKUP/'files-manifest.json').read_text());checked=[]
 for row in files:
  p=MOUNT/row['path'];assert p.is_file()and p.stat().st_size==row['size']and sha(p)==row['sha256'],row['path'];checked.append(row)
 assert len(checked)==1402 and sum(row['size']for row in checked)==1253249038
 print(json.dumps(dict(original_backup_image_SHA256_verified=True,all1402_image_files_verified=True,extracted_duplicate_bytes=1253249038)),flush=True)
 inventory=json.loads((BASE/'size-candidate-inventory.json').read_text());groups=[];inode_hash={};hashed=0
 for size,rows in inventory.items():
  match=collections.defaultdict(list)
  for row in rows:
   p=ROOT/row['path'];st=p.stat();assert p.is_file()and not p.is_symlink()and st.st_size==int(size)
   key=(st.st_dev,st.st_ino)
   if key not in inode_hash:inode_hash[key]=sha(p);hashed+=st.st_size
   match[inode_hash[key]].append(dict(row,device=st.st_dev,inode=st.st_ino,nlink=st.st_nlink,mode=st.st_mode&0o777))
  for digest,entries in match.items():
   if len({(x['device'],x['inode'])for x in entries})>1:groups.append(dict(bytes=int(size),sha256=digest,paths=entries))
 plan=dict(all_passed=True,read_only_plan=True,backup_image=str(image.relative_to(ROOT)),backup_image_sha256=disk['sha256'],backup_verified_files=len(checked),backup_verified_file_bytes=1253249038,duplicate_extracted_tree=str((BACKUP/'files').relative_to(ROOT)),read_only_mountpoint=str(MOUNT),exact_duplicate_groups=groups,large_file_bytes_hashed=hashed,sole_full_backup_strategy='Keep original sda.img as sole complete backup. Verify all extracted files in image, replace extracted tree with permanent read-only image mount; preserve old research paths. Identical immutable research files share one inode or read-only-image symlink, distinct bytes retained.',immutable_index_paths_may_remain=True,source_workspace_editable_C_not_deduplicated=True,device_IO=False,created_utc=datetime.now(timezone.utc).isoformat())
 with out.open('x')as f:json.dump(plan,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,exact_duplicate_groups=len(groups),duplicate_candidate_paths=sum(len(g['paths'])for g in groups),hashed_bytes=hashed,device_IO=False)),flush=True)
if __name__=='__main__':main()
