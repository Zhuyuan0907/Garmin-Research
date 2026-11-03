#!/usr/bin/env python3
"""Single authorized-device voice-file test; default read-only preflight.
Install/restore require an already mounted actual Garmin USB FAT volume.
Never flashes MAIN/BOOT or touches another voice, maps, or configuration.
"""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,shutil,subprocess,tempfile
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'staging/native-platform-readonly-probe'
MANIFEST=BASE/'local-platform-probe-bundle-v1.json'
BACKUP_XML=ROOT/'backups/20261002T154458Z/files/Garmin/GarminDevice.xml'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
 return h.hexdigest()
def identity(p):
 d=ET.parse(p).getroot();ns=d.tag.split('}')[0]+'}' if '}'in d.tag else ''
 m=d.find(ns+'Model');assert m is not None
 return tuple((e.text or '').strip()for e in (d.find(ns+'Id'),m.find(ns+'PartNumber'),m.find(ns+'SoftwareVersion')))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--mountpoint',type=Path,required=True)
 ap.add_argument('--action',choices=['preflight','install','restore'],default='preflight');a=ap.parse_args()
 mount=a.mountpoint.resolve();assert mount.is_mount(),'Expected mounted USB volume'
 r=subprocess.run(['findmnt','--json','--mountpoint',str(mount),'--output','TARGET,FSTYPE,SOURCE,OPTIONS'],capture_output=True,text=True,check=True)
 fs=json.loads(r.stdout)['filesystems'];assert len(fs)==1
 fs=fs[0];assert fs['fstype']=='vfat' and fs['source'].startswith('/dev/'),'Expected actual FAT block volume'
 assert identity(mount/'Garmin/GarminDevice.xml')==identity(BACKUP_XML),'Exact authorized device identity does not match'
 proof=json.loads((BASE/'ROOT-platform-reader-file-proof-v1.json').read_text());assert proof['all_passed']and proof['case_count']==2 and not proof['device_IO']
 for relpath,digest in proof['source_sha256'].items():assert sha(ROOT/relpath)==digest,'Frozen CPU diagnostic input changed'
 m=json.loads(MANIFEST.read_text());assert m['exact_target']['HWID']==1352 and m['exact_target']['SW']=='8.00'
 paths={role:ROOT/m[role+'_path']for role in ('candidate','rollback')}
 for role,p in paths.items():assert p.stat().st_size==m[role+'_bytes'] and sha(p)==m[role+'_sha256'],role+' changed'
 target=mount/'Voice/Chinese_Big5_MeiLing.vpm'
 assert target.is_file()and not target.is_symlink()and target.parent.resolve().parent==mount,'Unexpected voice path'
 old=sha(target);assert old in (m['candidate_sha256'],m['rollback_sha256']),'Live voice differs from original and this exact candidate; preserve it'
 data=dict(action=a.action,identity_matches_original=True,live_voice_sha256=old,
  target='Voice/Chinese_Big5_MeiLing.vpm',other_files_written=False,firmware_flashed=False)
 if a.action=='preflight':print(json.dumps(data));return
 assert 'rw'in fs['options'].split(','),'USB volume must be mounted writable'
 role='candidate'if a.action=='install'else'rollback';source=paths[role];expected=m[role+'_sha256']
 if old==expected:data['already_matches_requested_file']=True;print(json.dumps(data));return
 assert shutil.disk_usage(mount).free>source.stat().st_size+1024*1024,'Insufficient temporary copy space'
 stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
 local=ROOT/'backups'/('voice-test-'+stamp);local.mkdir(exist_ok=False)
 backup=local/target.name;shutil.copyfile(target,backup);assert sha(backup)==old,'Fresh live backup verification failed'
 temporary=None
 try:
  fd,name=tempfile.mkstemp(prefix='.nuvi-platform-probe-',suffix='.tmp',dir=target.parent);temporary=Path(name)
  with os.fdopen(fd,'wb')as out,source.open('rb')as inp:
   shutil.copyfileobj(inp,out,1024*1024);out.flush();os.fsync(out.fileno())
  assert sha(temporary)==expected,'USB temporary read-back differs'
  os.replace(temporary,target);temporary=None
  os.sync();assert sha(target)==expected,'Final USB read-back differs'
  data.update(updated_utc=datetime.now(timezone.utc).isoformat(),fresh_backup=str(backup.relative_to(ROOT)),
   installed_sha256=expected,readback_verified=True,bytes=target.stat().st_size,
   unmount_and_cold_restart_still_required=True,physical_execution_unverified=True)
  (local/'operation.json').write_text(json.dumps(data,indent=2)+'\n')
  print(json.dumps(data))
 finally:
  if temporary is not None:temporary.unlink(missing_ok=True)
if __name__=='__main__':main()
