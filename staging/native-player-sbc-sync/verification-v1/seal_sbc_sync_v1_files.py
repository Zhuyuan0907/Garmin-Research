#!/usr/bin/env python3
"""Seal completed FILE-only six-case verification, no VM/guest/canonical writes."""
import hashlib,json
from pathlib import Path
B=Path(__file__).resolve().parent;ROOT=B.parents[2]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for v in iter(lambda:f.read(1024*1024),b''):h.update(v)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def write(p,d):
 with p.open('x') as f:json.dump(d,f,indent=2);f.write('\n')
p=B/'sbc-sync-v1-independent-file-verification.json';d=json.loads(p.read_text())
assert sha(p)=='b60179c4ece53bf0b3ce82682b5a029d69a7b2b0af38cdf013fa297ceca2ca0c' and d['all_passed'] and d['independent_FILE_ONLY']
r=B/'sbc-sync-v1-independent-terminal-tool-receipt.json';receipt=json.loads(r.read_text())
assert receipt['terminal'] and receipt['started_session_id']==36517 and receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='53d269'
assert d['totals']['CPU_stores']==412189 and d['totals']['joint_events']==412491 and d['totals']['actual_decoder_full_returns']==34 and d['totals']['full_original_returns']==128 and d['totals']['full_original_sync_returns']==7
c=d['per_copy_live_guard_totals']
assert c==dict(whole_FIFO_READY_publications=16,compressed_queue_copied_bytes=2882,FIFO_COPYING_reservations=16,whole_compressed_queue_publications=18,PCM_COPYING_bytes=4206,FIFO_free_after_inflight_zero=16,exact_compiled_memcpy_source_bytes=15594,Mixer_copy_inflight_bytes=4206)
assert d['totals']['music_bytes']==c['PCM_COPYING_bytes']==c['Mixer_copy_inflight_bytes']
sources=dict(d['source_sha256']);outputs={rel(p):sha(p),rel(r):sha(r)}
for q in sorted(B.iterdir()):
 if q.is_file() and q not in (p,r):sources[rel(q)]=sha(q)
for path,h in sources.items():assert sha(ROOT/path)==h,path
ledger=B/'sbc-sync-v1-independent-source-output-ledger.json'
write(ledger,dict(all_passed=True,independent_FILE_ONLY=True,source_sha256=sources,output_sha256=outputs,VM_import_or_instantiation=False,guest_rerun=False,device_io=False,canonical_write=False))
seal=B/'sbc-sync-v1-independent-file-seal.json'
write(seal,dict(all_passed=True,independent_FILE_ONLY=True,proof=rel(p),proof_sha256=sha(p),ledger=rel(ledger),ledger_sha256=sha(ledger),source_sha256=sources,output_sha256=outputs,actual_verifier_session=36517,actual_verifier_terminal_chunk='53d269',actual_verifier_exit_code=0,actual_ROOT_session=35422,actual_ROOT_terminal_chunk='27fd35',actual_ROOT_exit_code=0,VM_import_or_instantiation=False,guest_rerun=False,complete_player_or_phone_receiver_or_physical_audio_verified=False,device_io=False,canonical_write=False))
for q in B.iterdir():
 if q.is_file():q.chmod(0o444)
print(json.dumps(dict(all_passed=True,proof=rel(p),proof_sha256=sha(p),seal=rel(seal),seal_sha256=sha(seal),ledger_sha256=sha(ledger),receipt_sha256=sha(r),source_count=len(sources),guest_execution=False)))
