#!/usr/bin/env python3
"""NEW package seal: read-only streamhash prior files, no guest/device/canonical."""
import json,hashlib,sys
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise ValueError(m)
def norm(p):
 q=Path(p);return str(q.relative_to(ROOT)) if q.is_absolute() else str(q)
old=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/sealed-source-output-ledger.json').read_text())
for registry in [old['source_sha256'],old['output_sha256']]:
 for p,h in registry.items():require(sha(ROOT/p)==h,'Earlier frozen source/output changed: '+p)
previous=json.loads((ROOT/'staging/native-player-inline-fields/previous-audit.json').read_text());protected=previous['protected_sources']
for p,h in protected.items():require(sha(ROOT/p)==h,'Earlier protected source changed: '+p)
checks={}
for name in ['strict-marker-control-proof.json','strict-controls-and-local-bundle-verification.json','candidate-embedded-reader-control.json','candidate-embedded-reader-metadata-control-v2.json','candidate-embedded-reader-independent-verification-v2.json','local-marker-bundle-manifest-v2.json','raw-return-gate-native-caller-review.json']:
 x=json.loads((OUT/name).read_text());require(x['all_passed'],name+'notpassed');checks[name]=True
sources={norm(p):h for p,h in old['source_sha256'].items()}
for p in OUT.rglob('*.json'):
 x=json.loads(p.read_text());reg=x.get('source_sha256') if isinstance(x,dict) else None
 if isinstance(reg,dict):
  for q,h in reg.items():
   if isinstance(h,str) and len(h)==64:require(sha(ROOT/norm(q))==h,'New source registry mismatch: '+str(q));sources[norm(q)]=h
for p in OUT.rglob('*'):
 if p.is_file() and p.suffix in ['.py','.c','.elf','.bin','.ld','.map'] and '__pycache__' not in p.parts:sources[str(p.relative_to(ROOT))]=sha(p)
outputs={str(p.relative_to(ROOT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name not in ['sealed-package-source-output-ledger.json','strict-marker-package-seal.json']}
ledger={'final_frozen':True,'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'source_sha256':dict(sorted(sources.items())),'output_sha256':dict(sorted(outputs.items())),'source_count':len(sources),'output_count':len(outputs),'source_and_output_overlap_intentional':True,'previous1363protected_count':len(protected),'previous_protected_all_unchanged':True,'earlier5controls18sources60outputs_unchanged':True,'new_complete_App_or_device_acceptance_claim':False,'exclude_only_ledger_and_seal_self_hashes':True}
lp=OUT/'sealed-package-source-output-ledger.json';lp.open('x').write(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n')
seal={'final_frozen':True,'all_passed':True,'ledger_path':str(lp.relative_to(ROOT)),'ledger_sha256':sha(lp),'source_sha256':dict(sorted(sources.items())),'output_sha256':dict(sorted(outputs.items())),'source_count':len(sources),'output_count':len(outputs),'all_old_frozen_controls_and1363protected_unchanged':True,'verified_artifacts':checks,'handoff_summary':'staging/native-player-inline-fields/marker-package-prep/handoff-summary-and-scope.json','actual_device_install_or_signature_acceptance_verified':False,'actual_UI_marker_guaranteed':False,'complete_App_or_music_goal':False,'future_variant_requires_newnamespace_source_proof_and_package':True}
sp=OUT/'strict-marker-package-seal.json';sp.open('x').write(json.dumps(seal,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_passed':True,'source_count':len(sources),'output_count':len(outputs),'previous_protected_count':len(protected),'ledger_sha256':sha(lp),'seal_sha256':sha(sp),'seal':str(sp.relative_to(ROOT))}))
