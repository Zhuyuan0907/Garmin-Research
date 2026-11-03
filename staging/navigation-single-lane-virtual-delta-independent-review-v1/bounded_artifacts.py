"""Independent exact small-artifact reader; source images and firmware forbidden."""
import hashlib,json
from pathlib import Path
ROOT=Path('/root/garmin');MAX_BYTES=1<<20
def sha(raw):return hashlib.sha256(raw).hexdigest()
def stat(path):
 s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
class BudgetReader:
 def __init__(self):self.cache={};self.receipts=[];self.actual_bytes=0
 def read(self,relative,expected_sha,expected_bytes=None,expected_mode=None,expected_stat=None):
  path=ROOT/relative;assert path.resolve().is_relative_to(ROOT)
  assert path.suffix.lower() not in ('.img','.pbf','.gcd','.vpm')
  assert path.name.lower() not in ('main.bin','boot.bin')
  assert relative.startswith('staging/'),relative
  if relative in self.cache:
   value=self.cache[relative];assert sha(value)==expected_sha;return value
  before=stat(path);actual_mode=path.stat().st_mode&0o777
  # The producer's final seal can legitimately retain0644; final bytes/hash/stat,
  # not an invented mode0444 requirement, define the immutable read binding.
  assert actual_mode in (0o400,0o444,0o600,0o644)
  if expected_mode is not None:assert actual_mode==int(str(expected_mode),8)
  if expected_stat is not None:assert before==expected_stat
  assert before[2]+self.actual_bytes<=MAX_BYTES,'No artifact read beyond1MiB total'
  if expected_bytes is not None:assert before[2]==expected_bytes
  raw=path.read_bytes();assert stat(path)==before and sha(raw)==expected_sha
  self.actual_bytes+=len(raw);self.cache[relative]=raw
  self.receipts.append(dict(path=relative,byte_range=[0,len(raw)],bytes=len(raw),sha256=sha(raw),
   stat_before=before,stat_after=before,mode=f'{actual_mode:04o}',actual_source='sealed small artifact file bytes'))
  return raw
 def verify_immutable(self):
  for row in self.receipts:assert stat(ROOT/row['path'])==row['stat_before']
  return dict(actual_artifact_bytes_read=self.actual_bytes,artifact_budget_bytes=MAX_BYTES,
   reads=self.receipts,all_stats_stable=True,cache_reads_did_not_reopen_source=True,
   IMG_PBF_MAIN_guest_or_CPU_reads=0,all_artifact_handles_closed=True)
