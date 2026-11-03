#!/usr/bin/env python3
"""Offline bounded capture of existing logs/source. No Bluetooth/PCM access."""
from pathlib import Path
import hashlib
import gzip
import json
import os
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
CAP = 1024 * 1024
PATHS = ['evidence/audio-quality-investigation.json', 'evidence/bluealsa-garmin.log',
    'evidence/phone-a2dp-service.log', 'evidence/bluealsa-research.log',
    'evidence/phone-bridge-initial-preflight.log', 'evidence/phone-capture-20261003T091111465498Z.log',
    'sources/deep-research/bluez-alsa-4.3.1/src/hfp.h',
    'sources/deep-research/bluez-alsa-4.3.1/src/ba-rfcomm.c',
    'sources/deep-research/bluez-alsa-4.3.1/doc/bluealsa-plugins.7.rst',
    'scripts/garmin_phone_audio_bridge.py']

def stable(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode & 0o777]

def redact(text):
    text = re.sub(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', '<private-peer>', text)
    return re.sub(r'dev_(?:[0-9A-Fa-f]{2}_){5}[0-9A-Fa-f]{2}', 'dev_<private-peer>', text)

def main():
    os.umask(0o077)
    receipts = []
    loghits = []
    sources = {}
    raw_private = []
    consumed = 647  # one earlier compact JSON read, retained separately in tool receipt
    expression = re.compile(r'BRSF|\bBAC\b|\bBCS\b|\bNREC\b|\bVGS\b|\bVGM\b|CVSD|mSBC|SCO.*(?:codec|format|rate|PCM)|Sampling|Channels|Volume|volume|underrun|overrun|xrun', re.I)
    for rel in PATHS:
        p = ROOT / rel
        a = p.lstat()
        if not stat.S_ISREG(a.st_mode) or consumed + a.st_size > CAP:
            raise ValueError('Regular bounded input required')
        raw = p.read_bytes()
        z = p.lstat()
        if len(raw) != a.st_size or stable(a) != stable(z):
            raise ValueError('Input log/source changed during bounded capture')
        consumed += len(raw)
        digest = hashlib.sha256(raw).hexdigest()
        receipts.append({'path':rel,'bytes':len(raw),'sha256':digest,'stat_before':stable(a),'stat_after':stable(z)})
        text = raw.decode('utf-8', errors='replace')
        if rel.endswith('.log'):
            for line_number, line in enumerate(text.splitlines(), 1):
                if expression.search(line):
                    loghits.append({'path':rel,'line':line_number,'source_sha256':digest,'text':redact(line)})
                    raw_private.append({'path':rel,'line':line_number,'text':line})
        elif rel.endswith('.json'):
            sources[rel] = json.loads(raw)
        else:
            lines = text.splitlines()
            selected = set()
            # Source-only local primary definitions and pipeline options.
            for i, line in enumerate(lines):
                if any(k in line for k in ('HFP_HF_FEAT_', 'HFP_AG_FEAT_CODEC', 'HFP_VOLUME_GAIN_',
                    'rfcomm_handler_brsf_set_cb', 'rfcomm_handler_nrec_set_cb', 'rfcomm_handler_vgs_set_cb',
                    'rfcomm_handler_vgm_set_cb', 'HFP_CODEC_CVSD', 'HFP_CODEC_MSBC',
                    'hf_features & HFP_HF_FEAT_CODEC', 'SOFTVOL', 'soft-volume', 'soft_volume',
                    "'-af'", 'volume=', '8000', "'-ar'", "'-ac'", '44100', 'volume', 'gain')):
                    selected.update(range(max(0,i-2), min(len(lines),i+7)))
            sources[rel] = [{'line':i+1,'text':redact(lines[i])} for i in sorted(selected)]
    # Full matched raw is private and bounded. It is not copied into public prose.
    private_raw = (json.dumps(raw_private, ensure_ascii=False, separators=(',', ':'))+'\n').encode()
    if len(private_raw) > 50000:
        # Keep deterministic raw witness excerpts; full hit counts remain in sanitized index.
        raw_private = raw_private[:35] + raw_private[-35:]
        private_raw = (json.dumps(raw_private, ensure_ascii=False, separators=(',', ':'))+'\n').encode()
    private_compressed = gzip.compress(private_raw, mtime=0)
    command_values = {}
    for hit in loghits:
        for command, value in re.findall(r'(BRSF|BAC|BCS|NREC|VGS|VGM)[=: ]+([0-9,]+)',hit['text'],re.I):
            key = hit['path'] + '|' + command.upper() + '|' + value
            record = command_values.setdefault(key, {'source':hit['path'],'command':command.upper(),
                'value':value,'count':0,'first_line':hit['line'],'last_line':hit['line']})
            record['count'] += 1
            record['last_line'] = hit['line']
    picked = loghits if len(loghits) <= 140 else loghits[:70] + loghits[-70:]
    observations = {'all_matched_log_lines':len(loghits),'recorded_excerpt_lines':len(picked),
                    'command_value_counts':list(command_values.values()),'excerpts':picked}
    observed_raw = (json.dumps(observations,ensure_ascii=False,indent=2)+'\n').encode()
    source_raw = (json.dumps(sources,ensure_ascii=False,indent=2)+'\n').encode()
    if len(source_raw) > 50000:
        for name, values in sources.items():
            if isinstance(values,list) and len(values)>120:
                sources[name]=values[:60]+values[-60:]
        source_raw=(json.dumps(sources,ensure_ascii=False,indent=2)+'\n').encode()
    if len(observed_raw)+len(source_raw)+len(private_compressed)+Path(__file__).stat().st_size > 105000:
        raise ValueError('Small output reserve before writing')
    (OUT/'private-protocol-witnesses.json.gz').write_bytes(private_compressed)
    (OUT/'private-protocol-witnesses.json.gz').chmod(0o600)
    (OUT/'sanitized-protocol-observations.json').write_bytes(observed_raw)
    (OUT/'source-definition-excerpts.json').write_bytes(source_raw)
    receipt = {'schema':'offline-hfp-quality-input-capture/v1','inputs':receipts,
        'external_raw_read_bytes':consumed,'raw_cap':CAP,'selected_log_lines':len(loghits),
        'private_witness_plain_bytes':len(private_raw),'private_witness_plain_sha256':hashlib.sha256(private_raw).hexdigest(),
        'private_witness_compressed_bytes':len(private_compressed),
        'private_witness_compressed_sha256':hashlib.sha256(private_compressed).hexdigest(),
        'private_raw_mode':384,'earlier_compact_read_bytes':647,'all_handles_closed':True,
        'Bluetooth_pair_PCM_playback_daemon_operations':0,'MAIN_guest_native_systemrisk_reruns':0}
    (OUT/'input-capture-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'raw_bytes':consumed,'matched_lines':len(loghits),'private_bytes':len(private_compressed),
        'output_bytes_so_far':sum(p.stat().st_size for p in OUT.iterdir() if p.is_file())}))
    # Human review output contains only redacted, relevant observations.
    print(json.dumps(loghits[:25]+loghits[-50:],ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
