#!/usr/bin/env python3
"""NEW file reader handles packet input in independently checked RX."""
from pathlib import Path
import json,hashlib
B=Path(__file__).resolve().parent;p=B/'verify_sbc_sync_v1_files_v2.py';s=p.read_text()
s=s.replace('self.final_RX_verified=len(final_rx)','self.final_RX_verified=len(final_rx);self.actual_RX_bytes={int(a):bytes.fromhex(raw) for a,raw in final_rx.items()}')
s=s.replace("gp=st['GP16'];size=word(z,gp[13]);raw=get(z,gp[3],size)","gp=st['GP16'];size=word(z,gp[13]);raw=get({**z,**rp.actual_RX_bytes},gp[3],size)")
s=s.replace("Path(__file__).resolve().parent/'file-verifier-v1-terminal-failure-receipt.json'):sources[rel(p)]=sha(p)","Path(__file__).resolve().parent/'file-verifier-v1-terminal-failure-receipt.json',Path(__file__).resolve().parent/'file-verifier-v2-terminal-failure-receipt.json',Path(__file__).resolve().parent/'verify_sbc_sync_v1_files_v2.py',Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v3.py'):sources[rel(p)]=sha(p)")
s=s.replace("'412189 captured CPU stores", "'FILE verifier v2 missed compiled compressed packet bytes in RX when reading an RW-only replay dictionary. NEW v3 uses independently reconstructed and actual-final-RX-checked bytes plus replayed RW; preserved v2 source/actual EXIT1, no guest rerun. 412189 captured CPU stores")
with (B/'verify_sbc_sync_v1_files_v3.py').open('x') as f:f.write(s)
for name in ['verify_sbc_sync_v1_files_v2.py','prepare_sbc_file_verifier_v2.py','file-verifier-v2-terminal-failure-receipt.json']:(B/name).chmod(0o444)
print(json.dumps(dict(all_passed=True,new_source='staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v3.py',sha256=hashlib.sha256((B/'verify_sbc_sync_v1_files_v3.py').read_bytes()).hexdigest(),guest_execution=False)))
