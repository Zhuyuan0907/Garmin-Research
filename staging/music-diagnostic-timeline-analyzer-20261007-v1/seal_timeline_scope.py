#!/usr/bin/env python3
"""Close only own file-only analyzer evidence and own new script."""
import hashlib
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SOURCE=ROOT/'scripts/analyze_garmin_music_diagnostics.py'
os.umask(0o077)


def pin(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode)]


def write_new(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())


source_raw=SOURCE.read_bytes()
source={'path':str(SOURCE.relative_to(ROOT)),'bytes':len(source_raw),'sha256':hashlib.sha256(source_raw).hexdigest()}
if source['sha256']!='0eb165beb3c44f6f02e4577417628651b4681e9cfd6d8ddf336586af363d7b71':raise ValueError('final source pin changed')
final_path=HERE/'actual-trace-analysis-final-v3.json'
analysis_raw=final_path.read_bytes();analysis=json.loads(analysis_raw)
prior=[HERE/name for name in ['actual-trace-analysis.json','actual-trace-analysis-final.json']]
if any(p.read_bytes()!=analysis_raw for p in prior):raise ValueError('actual output changed between corrected versions')
for name in ['test-receipt.json','observer-followup-test-receipt.json','scalar-shape-test-receipt.json','bounded-numeric-test-receipt.json']:
    if json.loads((HERE/name).read_bytes()).get('success') is not True:raise ValueError('control receipt failure')
proof={
 'schema':'garmin-file-only-music-diagnostic-timeline-proof/v1',
 'all_assigned_checks_passed':True,'STOP':True,'source':source,
 'initial20actual':{'terminal':'ebe36a','exit_code':0,'tests':20,'source_sha256':'c7b1aa337aae0ace44efd228ac6eacdf40c4375ea3b886aa4c8d83206b14133b','source_archive':'source-at-first20-controls.py.gz','runner_and_receipt_preserved':True,'rerun':False},
 'independent_schema_followup':{'terminal':'4b17d7','exit_code':0,'tests':4,'source_sha256':'6bb900826ae2d3806e90d44328d94055651095d712eac88797fd10c2d7eb95ed','issues':['final events_dropped/output_cap_reached','mono unused byte','optional SoftVolume/Codec','everyrow clock/run completeness'],'earlier20_not_rerun':True},
 'safe_scalar_protocol_followup':{'terminal':'bb8a75','exit_code':0,'tests':3,'scope':['nonstring stop_reason','nonscalar pipeline roles/error kinds','typed mono gain>15 held protocol interpretation']},
 'numeric_followup':{'terminal':'01df21','exit_code':0,'checks':3,'scope':['oversize numeric guard','oversize frame/counter guard','CLI fixed huge-scalar refusal without traceback/output']},
 'actual_three_trace_run':{'terminal':'983085','exit_code':0,'source':source,'analysis_path':str(final_path.relative_to(ROOT)),'analysis_bytes':len(analysis_raw),'analysis_sha256':hashlib.sha256(analysis_raw).hexdigest(),'inputs':analysis['inputs'],'pipeline_input':analysis['pipeline_input'],'fixture_scope':'Root supplied ordinary host PCM/inert observer integration trace, not live phone/Bluetooth/speaker capture.'},
 'actual_run_history_retained':[{'terminal':'ebb89e','exit_code':0,'source_sha256':'6bb900826ae2d3806e90d44328d94055651095d712eac88797fd10c2d7eb95ed','output':'actual-trace-analysis.json'},{'terminal':'ea5b70','exit_code':0,'output':'actual-trace-analysis-final.json','source_scope':'intermediate safe-scalar version before final numeric guards'},{'terminal':'983085','exit_code':0,'source_sha256':source['sha256'],'output':'actual-trace-analysis-final-v3.json'}],
 'repeat_read_accounting':'Three finite actual analyzer runs each read three JSONL and one optional metadata JSON once; no overall one-pass claim. All results byte-identical. No raw PCM read by analyzer.',
 'input_limits':{'per_file_bytes':1048576,'JSONL_rows':4096,'line_bytes':65536,'regular_only':True,'no_symlink':True,'nonblocking_nofollow_FD':True,'EOF_and_stat_verified':True},
 'actual_findings':{'cross_file_declared_run_clock_binding':analysis['clock_provenance']['cross_file_monotonic_binding'],'phone_input_frames':analysis['meter_summaries']['phone_input']['complete_frames_in_rows'],'garmin_output_frames':analysis['meter_summaries']['garmin_output']['complete_frames_in_rows'],'volume_event_counts':analysis['volume_summary']['event_counts'],'observed_scalar_control_changes':analysis['volume_summary']['control_changes'],'volume_gaps':analysis['volume_summary']['gaps'],'volume_cap_counters':analysis['volume_summary']['summary_counters'],'ratios':analysis['descriptive_ratios']['status'],'cause':'not_available'},
 'timeline_time_limit':'Volume timestamps are sequential after-read observer snapshots, not atomic property/event occurrence times. Nearby host arrival intervals do not pinpoint when a control changed between polls or acoustic timing.',
 'row_schema_pin':{'path':'staging/music-readonly-volume-observer-20261007-v1/row-schema.json','bytes':1744,'sha256':'8603243a86324b5f59e36a05ccc0af457ac4750a0dd8c5cd842ddabd0254ca25','read_terminal':'340584'},
 'observer_source_pin_inherited':'e942be5c7fab5e0a2d93af4e40e1a02aebaf18c970404c6b9bc7c437fcdaca3e',
 'code_review_artifacts':['final-source-correction-review.diff','final-source-AST-change-witness.json'],
 'native_firmware_map_guest_Bluetooth_DBus_PCM_playback_service_device_operations':0,
 'root_bridge_meter_observer_shared_sources_edited':False,
 'raw_phone_device_id_or_raw_exception_in_public_analysis':False,
 'hardware_sound_quality_cause_or_fullgoal_completed':False,
}
write_new('proof.json',proof)
write_new('actual-tool-receipts.json',{'schema':'file-only-music-timeline-actual-tools/v1','calls':[{'terminal':'ebe36a','exit_code':0,'operation':'initial20 synthetic controls'},{'terminal':'4b17d7','exit_code':0,'operation':'independent4 observer-schema controls'},{'terminal':'bb8a75','exit_code':0,'operation':'3 safe-scalar/protocol-held controls'},{'terminal':'01df21','exit_code':0,'operation':'3 numeric assertions including real CLI refusal'},{'terminal':'ebb89e','exit_code':0,'operation':'actual root trace first corrected source'},{'terminal':'ea5b70','exit_code':0,'operation':'actual trace after safe-scalar controls'},{'terminal':'983085','exit_code':0,'operation':'actual trace final source'}],'all_case_handles_closed':True,'no_background_PID_session_started':True,'scope':'Ordinary JSONL files and own metadata CLI only; no root bridge/observer/audio execution.'})
handoff='''Offline analyzer is ready: scripts/analyze_garmin_music_diagnostics.py --phone-input INPUT.jsonl --garmin-output OUTPUT.jsonl --volume VOLUME.jsonl [--pipeline-evidence PIPELINE.json] --output NEW.json. Each file must be regular/no symlink, <=1MiB; no overwrite. The program imports no Bluetooth/D-Bus/audio module and never calls producers. Public output is allowlisted scalar metadata; raw device paths, error strings and run tokens are not echoed.

Initial20 controls remain pinned to the archived first source; independent4 final observer-schema controls,3 malformed/protocol controls and3 numeric checks were new focused scopes. The first20 runner/receipt were not overwritten or rerun. Root supplied three ordinary offline scalar traces plus metadata pipeline were analyzed three times as concrete source corrections landed, each EXIT0. Prior outputs/source are retained; final983085 binds final source. Three outputs are byte-identical, not a one-pass claim.

Final data: input13230 stereo frames, output2400 mono frames, one window each; matching run token and complete perrow monotonic clock establish declared file alignment. Volume has18 events, including2 rpc_unavailable and one scalar control change. No content/resampling alignment evidence: no RMS gain ratio. Missing state clears comparison; initial is baseline; optional SoftVolume/Codec remain unknown; unused mono lowbyte is metadata, not second-channel gain; gain>15 is held protocol interpretation, not malformed observer JSON. Host overlapping read intervals are valid coarse batch observations. Volume timestamps are sequential after-read snapshots; nearby time is not control occurrence, speaker SPL, DSP change, Bluetooth packetloss or acoustic cause.

Output includes cap/EOF/frame/tail/error gaps, normalized critical audio versus optional observer failures and cleanup counts without legacy raw strings. PCM meters sit after upstream A2DP gain and before SCO/speaker processing. Source/output frame equality alone cannot align content through resampling/buffering. A ratio requires explicit pinned supplied content/sample-span mapping and remains descriptive; waveform correspondence is not independently proved by metadata.

Source-review corrections are captured by exact6773B textual diff and AST witness from archived initial source. Old tests are inherited only in their actual source-version scope; final focused tests and actual trace are explicit. proof.json/all_assigned_checks_passed and STOP describe this finite metadata-tool task, not music quality/native/hardware completion. No shared producer/report/service edit. STOP after own seal; all handles closed.
'''
with (HERE/'HANDOFF.txt').open('x') as f:f.write(handoff);f.flush();os.fsync(f.fileno())
members=[]
paths=sorted(p for p in HERE.rglob('*') if p.is_file())+[SOURCE]
for path in paths:
    if path.is_symlink():raise ValueError('symlink scope member')
    before=pin(path);raw=path.read_bytes();after=pin(path)
    if before!=after:raise ValueError('member changed')
    members.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'stat':before})
seal={'schema':'file-only-music-timeline-hash-closure/v1','all_assigned_checks_passed':True,'STOP':True,'files':members,'source':source,'all_handles_closed':True,'live_operations':0,'actual_mode_preserved':True,'readonly_mode_claim':False,'member_bytes':sum(r['bytes'] for r in members)}
raw=(json.dumps(seal,indent=2)+'\n').encode()
for row in members:
    if pin(ROOT/row['path'])!=row['stat']:raise ValueError('member changed before seal')
with (HERE/'sealed-files.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
fd=os.open(HERE,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
proof_raw=(HERE/'proof.json').read_bytes()
print(json.dumps({'result':'EXIT0 analyzer SEALED STOP','source':source,'proof_bytes':len(proof_raw),'proof_sha256':hashlib.sha256(proof_raw).hexdigest(),'seal_bytes':len(raw),'seal_sha256':hashlib.sha256(raw).hexdigest(),'member_count':len(members),'member_bytes':seal['member_bytes'],'all_handles_closed':True}))
