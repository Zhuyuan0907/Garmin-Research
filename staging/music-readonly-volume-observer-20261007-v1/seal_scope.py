#!/usr/bin/env python3
"""Close fake-provider/trace evidence; never construct a live provider."""
import hashlib
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def put(name,value):
    file=HERE/name
    if file.exists():raise ValueError('Existing output '+name)
    raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2)+'\n').encode()
    file.write_bytes(raw);return raw


def main():
    host_raw=(HERE/'host-proof.json').read_bytes();host=json.loads(host_raw)
    if not host['all_assigned_checks_passed'] or host['methods']!=12 or host['failures'] or host['errors']:
        raise ValueError('Actual finite controls failed')
    source=ROOT/'scripts/garmin_audio_volume_observer.py';before=source.stat();raw=source.read_bytes();after=source.stat()
    pin=lambda s:[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    if pin(before)!=pin(after) or len(raw)!=host['source_bytes'] or SHA(raw)!=host['source_sha256']:
        raise ValueError('Tested source changed')
    put('current-garmin_audio_volume_observer.py',raw)
    schema={'schema':'garmin-audio-volume-observer-row/v1','all_rows':{
        'timestamp_utc':'UTC ISO8601 +00:00','monotonic_ns':'host monotonic int','clock_kind':'host_monotonic_ns',
        'diagnostic_run_id':'optional caller anonymous ASCII [A-Za-z0-9_-]{1,64}; absent means no epoch binding'},
        'roles':['phone','garmin','observer(final_summary only)'],
        'events':['initial','snapshot','snapshot_change','role_missing','role_ambiguous','parse_error','rpc_unavailable','final_summary'],
        'states':['ok','role_missing','role_ambiguous','parse_error','rpc_unavailable'],
        'ok_fields':{'volume':{'raw_q':'uint16','channels':[{'index':'1 or2','gain_0_127':'low7bits','mute':'bit7 bool'}]},
                     'soft_volume':'optional true bool','codec':'optional known safe token or other','codec_recognized':'optional bool'},
        'volume_order':'highbyte=channel1; lowbyte=channel2; mono emits onlychannel1',
        'missing_or_error_fields':'fixed state only; volume/codec not guessed','initial':'bool on eachrole first sample, even when state unavailable',
        'final_summary_fields':['stop_reason','polls','events_written','events_dropped','output_cap_reached','role_states','elapsed_seconds','sample_time_kind','acoustic_or_device_volume_dB_inferred'],
        'sample_time_kind':'after_read_snapshot; properties are sampled sequentially, not atomically with media',
        'no_boot_or_device_identity_read_for_clock':True,'crossfile_epoch_requires_external_matching_run_token_and_no_clock_reset':True}
    put('row-schema.json',schema)
    api='''# Optional read-only volume metadata observer

Source scripts/garmin_audio_volume_observer.py is import-safe: no D-Bus import, private configuration, live bus/provider construction, or media I/O occurs at import. LiveProvider alone lazily imports dbus and reads the existing authorized-phone.json plus matching_devices record. It requires a unique configured Garmin address. Exact internal selectors are phone bus org.bluealsa.phone + authorized Device + A2DP-sink/source and Garmin bus org.bluealsa + unique configured Device + HFP-AG/sink. Only ObjectManager.GetManagedObjects(timeout=...) is called, never Set, Open, SelectCodec, connect, pair, or phonebook. Ambiguous candidates are held; one is never selected arbitrarily.

CLI requires one explicit mode:

```text
python3 garmin_audio_volume_observer.py --trace-input TRACE.json --output NEW.jsonl --duration 1 --interval 0.5 --diagnostic-run-id anonymous_run
python3 garmin_audio_volume_observer.py --live --output NEW.jsonl --duration 345 --interval 0.5 --rpc-timeout 0.15 --diagnostic-run-id anonymous_run
```

The second example documents the future opt-in API; it was not executed in this scope. --live is for a later explicitly launched bridge diagnostic. --trace-input chooses TraceProvider before any live import/config/bus code. Trace input is a<=256KiB regular non-symlink JSON object with1..1024 frames. Each frame maps phone/garmin to {candidates:[{Volume,Channels,SoftVolume?,Codec?}]} or {status:rpc_unavailable/parse_error}; two candidates classify ambiguity. Missing roles are unavailable. Frames repeat the last snapshot; fixture-only raise_rpc_error triggers a fixed RPC-unavailable state. Arbitrary input details are not emitted.

API collect(provider, writer, duration_seconds=..., interval_seconds=0.5, diagnostic_run_id=None, stop_event=None, stop_reason=None) uses provider.read_snapshot(). BoundedWriter requires a NEW output path, O_EXCL/O_NOFOLLOW, exact0600 and<=1MiB. It keeps only two normalized role states plus one serialized line; event rows<=1024B, with1024B reserved for a final summary. Cap drops are counted while polling continues; the summary is always attempted. The maximum duration is3645s; interval0.01..0.5s; live RPC timeout0.001..0.2s each. Two role RPCs may consume up to0.4s before processing; real reply latency and scheduling were not measured. Missing backend, role, RPC, or type errors are nonfatal redacted rows; SIGTERM emits final summary and returns0. Output creation itself returns2 on failure for bridge isolation; later metadata failures return0. No media stdin/stdout or playback operation exists, and normal CLI stdout/stderr are empty.

Reusable sanitizer: sanitize_pcm_properties(properties, dbus_types=None). With normal JSON, Volume is a true int0..65535, Channels a true int1/2, SoftVolume a true bool, Codec a true str. Caller with DBus wrappers supplies the explicit class mapping {Volume:dbus.UInt16,Channels:dbus.Byte,SoftVolume:dbus.Boolean,Codec:dbus.String}; only instance-validated values are cast, so arbitrarystrings cannot become booleans. Returns state/volume/optionalsoft_volume/optionalcodec metadata, not the original object. Volume highbyte isch1, lowbytech2, bit7mute and low7gain. Mono omitsch2. No dB/acoustic gain is inferred. Safe Codec allowlist is CVSD/mSBC/SBC/AAC/aptX/aptX-HD/LDAC/LC3/FastStream/Opus/MP3; unrecognized strings become other. Addresses, paths, object names, arbitraryarrays, and raw exception text never enter output.

Exact row keys/events are documented in row-schema.json. Every row includes timestamp_utc, monotonic_ns, clock_kind=host_monotonic_ns; caller token is optional. No boot or device ID is read for clock binding. Root's same-run token and no-reset receipt must bind cross-file timing; an absent token is unbound. initial/snapshot are baselines, snapshot_change compares normalized state, and missing/error states do not fabricate current volume. Timestamps describe after_read_snapshot, not atomic audio/metadata observation.

Actual788c6a EXIT0: twelve inert methods in0.615s, including high/lowbit mono decode, strict/scalar codec privacy, fake DBus class wrappers and explicit bounded fake RPC, exact selectors, reconnect/change/error states,2048B output cap with38 drops/20 polls and parseable final1257B output, real trace CLI with D-Bus/privateconfig/socket barriers, real SIGTERM0 with PIDreaped, unavailable trace0, existing/symlink output2, and optional anonymous token validation. Real LiveProvider was never constructed; no actual private configuration or service query occurred. All trace files were synthetic and temporary. No audio, native/guest, firmware, or map task was run.

Root owns bridge/meter integration and any later live diagnostics. This source evidence is complete; live metadata availability, actual codec, speaker response, and causal volume changes remain unverified. Stop after sealing.
'''
    put('API.md',api.encode())
    put('actual-tool-receipts.json',{'schema':'music-readonly-volume-observer-actual-tools/v1','tools':[
        {'chunk_id':'788c6a','exit_code':0,'purpose':'12 pure/fake/inert CLI methods','terminal':'Ran12 tests in0.615s; OK','wall_time_seconds':.57268002},
        {'chunk_id':'7cfb86','exit_code':0,'purpose':'small source/case summary'}],
        'real_live_provider_or_privateconfig_constructed':False,'actual_dbus_BlueZ_PCM_services_device_queries':False})
    proof={'schema':'music-readonly-volume-observer-source-proof/v1','all_assigned_checks_passed':True,
        'source':{'path':str(source.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),'stat':pin(after)},
        'host_proof':{'bytes':len(host_raw),'sha256':SHA(host_raw)},'actual_methods':12,
        'exact_live_selectors':['org.bluealsa.phone/authorized Device/A2DP-sink/source','org.bluealsa/unique configured Garmin Device/HFP-AG/sink'],
        'read_only_RPC':['GetManagedObjects'],'mutating_RPC_or_PCM_open_present':False,
        'true_uint16_volume_highch1_lowch2_mute_gain_mono':True,'strict_wrapper_types_and_optional_scalars':True,
        'raw_private_exceptions_identifiers_or_paths_emitted':False,'diagnostic_run_id_optional_anon_ASCII':True,
        'maxduration_seconds':3645,'max_poll_interval_seconds':.5,'max_rpc_timeout_seconds':.2,
        'max_output_bytes':1048576,'tail_reserve_bytes':1024,'new_file_mode':'0600',
        'max_trace_raw_bytes':262144,'max_trace_frames':1024,'max_manager_objects':512,'selected_candidates_bound':2,
        'SIGTERM_final_summary_return0_verified_inert':True,'report_path_creation_failure_code':2,
        'metadata_unavailable_nonfatal_return0':True,'live_provider_constructed':False,
        'actual_dbus_BlueZ_PCM_device_services_sound_privateconfig_queries':False,
        'bridge_meter_player_edits':False,'native_guest_firmware_maps':False,'all_handles_closed':True,'STOP':True}
    put('proof.json',proof)
    files={str(file.relative_to(HERE)):file.read_bytes() for file in sorted(HERE.rglob('*')) if file.is_file()}
    if sum(map(len,files.values()))>=1048576:raise ValueError('Small output budget')
    for name in files:(HERE/name).chmod(0o444)
    rows=[]
    for name,data in files.items():
        file=HERE/name;s=file.stat();rows.append({'path':str(file.relative_to(ROOT)),'bytes':len(data),'sha256':SHA(data),'mode':'0444','stat':pin(s)})
    raw_seal=put('sealed-files.json',{'schema':'music-readonly-volume-observer-seal/v1','all_assigned_checks_passed':True,'files':rows,
        'source_binding':proof['source'],'persistent_output_bytes_before_seal':sum(map(len,files.values())),
        'all_handles_closed':True,'actual_device_or_bus_IO':False,'STOP':True})
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed':True,'source_bytes':len(raw),'source_sha256':SHA(raw),
        'proof_bytes':(HERE/'proof.json').stat().st_size,'proof_sha256':SHA((HERE/'proof.json').read_bytes()),
        'schema_bytes':(HERE/'row-schema.json').stat().st_size,'schema_sha256':SHA((HERE/'row-schema.json').read_bytes()),
        'seal_bytes':len(raw_seal),'seal_sha256':SHA(raw_seal),'output_bytes':sum(map(len,files.values()))+len(raw_seal),'STOP':True}))


if __name__=='__main__':main()
