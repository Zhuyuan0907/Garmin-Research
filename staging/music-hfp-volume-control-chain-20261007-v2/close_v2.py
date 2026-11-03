#!/usr/bin/env python3
"""Own small metadata finalization only; no external source or runtime reads."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 98304
os.umask(0o077)


def read(name):
    return json.loads((HERE/name).read_bytes())


def replace(name, value):
    with (HERE/name).open('w') as f:
        json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


api = {
    'interface': 'org.bluealsa.PCM1',
    'Volume': {'dbus_type': 'uint16', 'dbus_signature': 'q', 'unit': 'packed per-channel loudness-control values plus mute bits; not dB', 'ch1_gain': '(raw >> 8) & 0x7f', 'ch1_mute': 'bool(raw & 0x8000)', 'ch2_gain': 'raw & 0x7f', 'ch2_mute': 'bool(raw & 0x80)', 'gain_ranges': {'A2DP': [0,127], 'SCO': [0,15]}, 'mono': 'Getter writes lowerbyte0; with Channels1, ch2 is absent, not a measured second-channel zero gain.'},
    'SoftVolume': {'dbus_type': 'boolean', 'dbus_signature': 'b', 'unit': 'whether BlueALSA internally scales PCM; property readwrite but diagnostic must read only'},
    'Codec': {'dbus_type': 'string', 'dbus_signature': 's', 'access': 'readonly', 'absence': 'available only after codec selected; record absent/unknown without calling SelectCodec'},
    'namespace_difference': 'BlueZ MediaTransport1.Volume is a single0..127 value. It is different from BlueALSA PCM1 packed Volume and AT VGS0..15.',
    'source_anchors': [{'path':'sources/deep-research/bluez-alsa-4.3.1/doc/org.bluealsa.PCM1.7.rst','lines':[151,168,173]}, {'path':'sources/deep-research/bluez-alsa-4.3.1/src/shared/dbus-client-pcm.h','lines':[68,138]}, {'path':'sources/deep-research/bluez-alsa-4.3.1/src/bluealsa-dbus.c','lines':[280,284,288,295]}],
    'primary_reference': 'https://github.com/arkq/bluez-alsa/blob/v4.3.1/doc/org.bluealsa.PCM1.7.rst',
}
# Pure numeric controls using fabricated packed values; no protocol operations.
cases=[]
for raw,channels,expected in [(0x7f7f,2,(127,False,127,False)),(0xffff,2,(127,True,127,True)),(0x0f00,1,(15,False,None,None)),(0x8f00,1,(15,True,None,None))]:
    decoded=((raw>>8)&127,bool(raw&0x8000),raw&127 if channels==2 else None,bool(raw&0x80) if channels==2 else None)
    if decoded!=expected:raise ValueError('synthetic packed control arithmetic mismatch')
    cases.append({'raw_uint16':raw,'channels':channels,'decoded':decoded,'passed':True})

audit=read('gain-chain-audit.json');audit['PCM1_property_API']=api
audit['source_pin_time_rule']='Current means snapshot source at capture. Later root metering edits are not re-read or called.'
replace('gain-chain-audit.json',audit)
schema=read('controlled-diagnostic-schema.json');schema['PCM1_property_API']=api
observed=schema['configuration']['observed']
for key in ['A2DP_volume_levels_db','SCO_volume_level_db']:
    observed.pop(key,None)
observed['A2DP_PCM1_Volume']='raw_uint16 plus parsed channel loudness/mute fields or null; not dB'
observed['SCO_PCM1_Volume']='raw_uint16 plus parsed valid mono loudness/mute fields or null; not dB'
schema['protocol_volume']['range']='BlueZ Volume0..127; VGS0..15; PCM1.Volume is packeduint16 with per-channel ranges above.'
schema['configuration']['observed']['read_only_rule']='Future opt-in collector may only read properties. No Set, SelectCodec, Open, connect, pair or authorization change. No collector run during this scope.'
replace('controlled-diagnostic-schema.json',schema)
proof=read('proof.json');proof['measured_python_source_read_bytes']=433158;proof['cumulative_external_read_upper']=483158
proof['PCM1_API_source_read']='74fb1c EXIT0,50877B, stable before/after stats/EOF, no runtime.'
proof['synthetic_packed_arithmetic_controls']=cases
proof['source_api_receipt']='PCM1-property-read-receipt.json'
proof['lossless_closed_receipt_archive']='private-input-and-storage-receipts.json.gz'
proof['lossless_own_review_source_archive']='private-review-sources.json.gz'
proof['output_storage_exception']['final_close_failure']='4028d1 EXIT1 before seal: own namespace104090B+prospective seal exceeded96KiB. Own review scripts/receipts archived losslessly, broad source excerpts narrowed with explicit omissions; no external reread.'
proof['STOP_after_own_seal']=True
replace('proof.json',proof)
receipts=read('actual-tool-receipts.json');receipts['calls'] += [
    {'terminal':'4028d1','exit_code':1,'operation':'Own final output cap guard halted before seal; no external reads/live operations'},
    {'terminal':'7b4545','exit_code':0,'operation':'Own sources losslessly archived'},
    {'terminal':'1811c8','exit_code':0,'operation':'Own source/storage receipts losslessly archived'},
    {'terminal':'74fb1c','exit_code':0,'operation':'Exact three-file PCM1 API source capture','read_bytes':50877},
    {'terminal':'5d7d7b','exit_code':0,'operation':'Narrow saved API evidence; no external reads'},
]
receipts['final_external_read_upper']=483158;receipts['measured_Python_read_bytes']=433158;receipts['source_cap']=524288
replace('actual-tool-receipts.json',receipts)
with (HERE/'HANDOFF.txt').open('a') as f:
    f.write('\nFinal PCM1 API addendum: Volume is uint16/q packed channel loudness/mute, not dB: ch1 upperbyte, ch2 lowerbyte,bit7 mute; A2DP0..127,SCO0..15. Mono getter writes lowbyte0, so ch2 is absent. SoftVolume is boolean/b; Codec readonly string/s and only present if selected. BlueZ single Volume and AT VGS are distinct. Schema corrected to raw packed controls, not inferred observed dB. Four fabricated numeric decode controls passed; no D-Bus method used. Final source upper483158B (Python433158B+initial rg50000B allowance). Final-cap failed4028d1 is retained; own review code/receipts stored losslessly as gzip before finalseal.\n')
    f.flush();os.fsync(f.fileno())

def fingerprint(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode)]

public={'gain-chain-audit.json','controlled-diagnostic-schema.json','proof.json','actual-tool-receipts.json','HANDOFF.txt'}
members=[]
for path in sorted(HERE.iterdir()):
    if path.is_symlink() or not path.is_file() or path.name=='sealed-files.json':raise ValueError('invalid scope member/already sealed')
    before=fingerprint(path);raw=path.read_bytes();after=fingerprint(path)
    if before!=after:raise ValueError('own member changed')
    if path.name.startswith('private-') and before[-1]!=0o600:raise ValueError('private mode not600')
    if path.name in public and re.search(rb'(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',raw):raise ValueError('public identity pattern')
    members.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'stat':before,'sharing':'redacted_summary' if path.name in public else 'private_source_evidence'})
seal={'schema':'music-volume-chain-file-only-hash-closure/v2','status':'SEALED_STOP','files':members,'member_bytes':sum(r['bytes'] for r in members),'output_cap':CAP,'source_read_upper':483158,'source_cap':524288,'all_handles_closed':True,'actual_modes_preserved':True,'live_operations':0,'final_closure_checks_passed':True,'historical_host_partial_failures_retained':['9e281f AST unrelated default','4028d1 output cap before seal'],'runtime_mode_or_cause_or_hardware_claim':False}
while True:
    raw=(json.dumps(seal,ensure_ascii=False,indent=2)+'\n').encode();total=seal['member_bytes']+len(raw)
    if seal.get('final_namespace_bytes')==total:break
    seal['final_namespace_bytes']=total
if total>CAP:raise ValueError('final cap would be exceeded; no seal')
for r in members:
    if fingerprint(ROOT/r['path'])!=r['stat']:raise ValueError('scope changed before publication')
with (HERE/'sealed-files.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
fd=os.open(HERE,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'result':'EXIT0 gain-chain/API SEALED STOP','proof_sha256':next(r['sha256'] for r in members if r['path'].endswith('/proof.json')),'audit_sha256':next(r['sha256'] for r in members if r['path'].endswith('/gain-chain-audit.json')),'diagnostic_schema_sha256':next(r['sha256'] for r in members if r['path'].endswith('/controlled-diagnostic-schema.json')),'seal_sha256':hashlib.sha256(raw).hexdigest(),'seal_bytes':len(raw),'final_namespace_bytes':total,'source_read_upper':483158,'all_handles_closed':True,'external_reads_this_close':0}))
