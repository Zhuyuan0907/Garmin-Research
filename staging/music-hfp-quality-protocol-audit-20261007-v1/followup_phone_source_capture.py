#!/usr/bin/env python3
"""Small offline follow-up: phone volume log and original RFCOMM source only."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import re
import stat

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent

def redact(text):
    text=re.sub(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}','<private-peer>',text)
    return re.sub(r'dev_(?:[0-9A-Fa-f]{2}_){5}[0-9A-Fa-f]{2}','dev_<private-peer>',text)

def main():
    os.umask(0o077)
    receipts=[]
    sources={}
    for rel in ('evidence/phone-a2dp-service.log','sources/deep-research/bluez-alsa-4.3.1/src/ba-rfcomm.c'):
        p=ROOT/rel;a=p.lstat();b=p.read_bytes();z=p.lstat()
        key=lambda s:[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode&0o777]
        if not stat.S_ISREG(a.st_mode) or key(a)!=key(z):raise ValueError('Source changed')
        receipts.append({'path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'stat_before':key(a),'stat_after':key(z)})
        sources[rel]=b
    cumulative=637321+sum(r['bytes'] for r in receipts)
    if cumulative>1048576:raise ValueError('Raw input cap')
    phone=sources['evidence/phone-a2dp-service.log']
    raw=gzip.compress(phone,mtime=0)
    (OUT/'private-phone-log.jsonless.txt.gz').write_bytes(raw)
    (OUT/'private-phone-log.jsonless.txt.gz').chmod(0o600)
    selected=[{'line':i+1,'text':redact(s)} for i,s in enumerate(phone.decode().splitlines())
              if any(w in s.lower() for w in ('volume','sbc','sampling','channels','configuration','codec'))]
    # Source callbacks are captured without importing or executing any daemon code.
    lines=sources['sources/deep-research/bluez-alsa-4.3.1/src/ba-rfcomm.c'].decode().splitlines()
    funcs={}
    for name in ('rfcomm_handler_brsf_set_cb','rfcomm_handler_nrec_set_cb','rfcomm_handler_vgs_set_cb','rfcomm_handler_vgm_set_cb'):
        hits=[i for i,s in enumerate(lines) if name+'(' in s]
        if not hits:continue
        start=hits[0];depth=0;opened=False;snippet=[]
        for i in range(start,min(len(lines),start+100)):
            text=lines[i];snippet.append({'line':i+1,'text':text})
            depth+=text.count('{')-text.count('}')
            opened=opened or '{' in text
            if opened and depth==0:break
        funcs[name]=snippet
    old=json.loads((OUT/'sanitized-protocol-observations.json').read_text())
    commands=[]
    for hit in old['excerpts']:
        match=re.search(r'command:\+(BRSF|BAC|BCS|NREC|VGS|VGM), value:([0-9,]+)',hit['text'])
        if match:
            commands.append({'source':hit['path'],'line':hit['line'],'command':match.group(1),
                'value':match.group(2),'direction':'AG transmit response' if 'Sending AT message' in hit['text'] else 'HF received set'})
    payload={'schema':'hfp-quality-targeted-followup/v1','phone_log_excerpts':selected,
        'correctly_parsed_retained_HFP_commands':commands,'source_callbacks':funcs,
        'first_capture_erratum':'Original numeric regex expected X=Y; actual log uses command:+X, value:Y. Empty first numeric summary is unavailable, not proof of zero commands.',
        'command_counts_scope':'retained excerpt rows only; no whole-log BAC/BCS absence claim',
        'private_phone_log_sha256':hashlib.sha256(phone).hexdigest()}
    (OUT/'phone-volume-and-source-followup.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    receipt={'rows':receipts,'raw_followup_bytes':sum(r['bytes'] for r in receipts),
        'cumulative_raw_external_input_bytes':cumulative,'raw_limit':1048576,
        'private_full_phone_log_compressed_bytes':len(raw),'private_full_phone_log_gzip_sha256':hashlib.sha256(raw).hexdigest(),
        'all_handles_closed':True,'Bluetooth_PCM_daemon_playback_operations':0}
    (OUT/'followup-input-read-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'cumulative_raw_bytes':cumulative,'phone_excerpt_count':len(selected),'private_gzip_bytes':len(raw)}))
    print(json.dumps(payload,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
