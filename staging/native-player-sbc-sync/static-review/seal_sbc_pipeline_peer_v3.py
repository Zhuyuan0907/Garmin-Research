#!/usr/bin/env python3
"""Seal only NEW completed FILE review; never import a VM."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def write(p,d):
 with p.open('x') as f:json.dump(d,f,indent=2);f.write('\n')
p=BASE/'sbc-pipeline-build-v3-peer-review.json'
d=json.loads(p.read_text());assert d['all_passed'] and not d['guest_executed_by_reviewer']
sources=dict(d['source_sha256']);sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
for path,h in sources.items():assert sha(ROOT/path)==h,path
outputs={rel(p):sha(p),rel(BASE/'sbc-pipeline-build-v3-static-terminal-tool-receipt.json'):sha(BASE/'sbc-pipeline-build-v3-static-terminal-tool-receipt.json')}
ledger=BASE/'sbc-pipeline-build-v3-static-source-output-ledger.json'
write(ledger,dict(all_passed=True,source_sha256=sources,output_sha256=outputs,static_only=True,guest_executed=False))
seal=BASE/'sbc-pipeline-build-v3-static-seal.json'
write(seal,dict(all_passed=True,proof=rel(p),proof_sha256=sha(p),ledger=rel(ledger),ledger_sha256=sha(ledger),source_sha256=sources,output_sha256=outputs,review_kind='FILE/static-only source/ELF/typed-input review',guest_executed=False,device_io=False))
for q in BASE.iterdir():
 if q.is_file():q.chmod(0o444)
print(json.dumps(dict(all_passed=True,proof=rel(p),proof_sha256=sha(p),seal=rel(seal),seal_sha256=sha(seal),ledger_sha256=sha(ledger),source_count=len(sources),guest_executed=False)))
