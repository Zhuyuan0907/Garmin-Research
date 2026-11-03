#!/usr/bin/env python3
"""Ordinary host review of this scope's saved captures; no live/audio APIs."""
import gzip
import hashlib
import json
import os
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
os.umask(0o077)


def saved(name):
    raw = (HERE / name).read_bytes()
    if name.endswith('.gz'):
        raw = gzip.decompress(raw)
    return json.loads(raw)


def write(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    path = HERE / name
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


first = saved('input-capture-receipt.json')
follow = saved('followup-input-read-receipt.json')
tail = saved('NREC-tail-read-receipt.json')
storage = saved('capture-storage-closure.json')
observations = saved('sanitized-protocol-observations.json.gz')
definitions = saved('source-definition-excerpts.json.gz')
parsed = saved('phone-volume-and-source-followup.json.gz')
phone_raw = gzip.decompress((HERE / 'private-phone-log.jsonless.txt.gz').read_bytes())
phone_sha = hashlib.sha256(phone_raw).hexdigest()
phone_pin = next(row for row in first['inputs'] if row['path'] == 'evidence/phone-a2dp-service.log')
if phone_sha != phone_pin['sha256'] or len(phone_raw) != phone_pin['bytes']:
    raise ValueError('saved complete phone capture differs from input pin')

volume_pattern = re.compile(r'Updating A2DP volume:\s*(\d+)\s*\[(-?\d+(?:\.\d+)?) dB\]')
volume_rows = []
for line_number, line in enumerate(phone_raw.decode(errors='replace').splitlines(), 1):
    match = volume_pattern.search(line)
    if match:
        volume_rows.append({'line': line_number, 'value': int(match.group(1)), 'logged_db': float(match.group(2))})
if len(volume_rows) != 87:
    raise ValueError('saved full-phone volume event count unexpected')

commands = parsed['correctly_parsed_retained_HFP_commands']
hf_brsf = sorted({int(row['value']) for row in commands if row['command'] == 'BRSF' and row['direction'] == 'HF received set'})
ag_brsf = sorted({int(row['value']) for row in commands if row['command'] == 'BRSF' and row['direction'] == 'AG transmit response'})
vgs = sorted({int(row['value']) for row in commands if row['command'] == 'VGS' and row['direction'] == 'HF received set'})
nrec = sorted({int(row['value']) for row in commands if row['command'] == 'NREC' and row['direction'] == 'HF received set'})
if hf_brsf != [13, 15] or ag_brsf != [2784] or vgs != [15] or nrec != [0]:
    raise ValueError('retained HFP command summary unexpected')
if not any('value:ERROR' in line for row in tail['NREC_pairs'] for line in row['request_and_next_lines'][1:2]):
    raise ValueError('captured NREC immediate ERROR witness missing')

raw_total = first['external_raw_read_bytes'] + follow['raw_followup_bytes'] + tail['bytes_read']
if raw_total != tail['cumulative_external_raw_bytes'] or raw_total > 1048576:
    raise ValueError('external input read budget inconsistent')
for receipt in [first, follow, tail]:
    if receipt.get('all_handles_closed') is not True:
        raise ValueError('input handle closure absent')
    for row in receipt.get('inputs', receipt.get('rows', [])):
        if row['stat_before'] != row['stat_after']:
            raise ValueError('captured input changed during read')
if tail['stat_before'] != tail['stat_after']:
    raise ValueError('RFCOMM tail source changed')

primary = {
    'HFP_bits': 'https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/hfp.h',
    'RFCOMM_handlers': 'https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/ba-rfcomm.c',
    'PCM_volume_modes': 'https://github.com/arkq/bluez-alsa/blob/v4.3.1/doc/bluealsa-plugins.7.rst',
    'Bluetooth_spec_landing': 'https://www.bluetooth.com/specifications/specs/hands-free-profile-1-8/',
}
audit = {
    'schema': 'garmin-offline-HFP-quality-protocol-audit/v1',
    'status': 'closed_read_only_audit_no_sound_quality_fix_claim',
    'historical_snapshot': definitions['evidence/audio-quality-investigation.json'],
    'snapshot_limitation': '2026-10-02 snapshot and existing logs are historical; no live PID, daemon, D-Bus, PCM or speaker state checked. Current bridge source had newer conversion controls, so historic no-DSP fields are not a claim about current deployment.',
    'protocol_evidence': {
        'HF_BRSF_values_received': hf_brsf,
        'AG_BRSF_values_transmitted': ag_brsf,
        'HF_codec_negotiation_bit': 7,
        'AG_codec_negotiation_bit': 9,
        'HF_codec_negotiation_advertised': any(value & (1 << 7) for value in hf_brsf),
        'AG_codec_negotiation_advertised': all(value & (1 << 9) for value in ag_brsf),
        'HF_bit_sets': {str(value): [bit for bit in range(12) if value & (1 << bit)] for value in hf_brsf},
        'codec_observed': 'CVSD',
        'BRSF_consequence': 'BlueALSA v4.3.1 selects CVSD when received HF features lack codec-negotiation bit7. Pi AG bit9 or Pi mSBC support cannot establish Garmin mSBC support.',
        'NREC_received_values': nrec,
        'NREC_response_actual': 'immediate ERROR in captured last-20000-byte RFCOMM tail',
        'NREC_semantics': 'Request concerns Audio Gateway-side noise reduction/echo cancellation. It is not evidence of Garmin downlink/speaker DSP bypass, AGC operation or acoustic improvement. Original BlueALSA handler returns ERROR because AG NR/EC is unsupported.',
        'VGS_received_values_in_retained_excerpts': vgs,
        'VGS_range': [0, 15],
        'VGS_semantics': 'Remote speaker gain command; original handler acknowledges without changing PCM level when soft_volume is enabled, otherwise updates PCM volume. Actual mode/effective acoustic gain not captured.',
        'HF_remote_volume_bit4_advertised': any(value & (1 << 4) for value in hf_brsf),
        'VGS_capability_caveat': 'Observed VGS15 remains an actual command despite missing HF feature bit4.',
        'BAC_BCS_VGM_retained_excerpt_status': 'No such rows retained; not a whole-log absence test or universal peer capability exclusion.',
        'retained_command_row_count': len(commands),
        'retained_log_excerpt_count': observations['recorded_excerpt_lines'],
        'matched_log_lines_before_excerpt_selection': observations['all_matched_log_lines'],
        'primary_sources': primary,
    },
    'phone_volume_evidence': {
        'source_capture_sha256': phone_sha,
        'scope': 'Complete saved phone-a2dp-service.log; no fresh external reread at audit generation.',
        'A2DP_format_logged': {'codec': 'SBC', 'sampling_hz': 44100, 'channels': 2, 'mode': 'Joint Stereo', 'bitpool': 53},
        'event_count': len(volume_rows),
        'values_min_max': [min(row['value'] for row in volume_rows), max(row['value'] for row in volume_rows)],
        'unique_values': sorted({row['value'] for row in volume_rows}),
        'logged_db_min_max': [min(row['logged_db'] for row in volume_rows), max(row['logged_db'] for row in volume_rows)],
        'logged_db_span': round(max(row['logged_db'] for row in volume_rows) - min(row['logged_db'] for row in volume_rows), 2),
        'boundary_examples': volume_rows[:3] + volume_rows[-3:],
        'classification': 'volume-control changes proved; who initiated them and relation to subjective loudness fluctuation unproved',
        'measurement_limit': 'Logged dB mappings are not captured PCM RMS/peaks, speaker SPL, or synchronized listening observations.',
    },
    'quality_ceiling': {
        'observed_route': 'phone A2DP 44.1kHz stereo -> Pi conversion -> Garmin HFP CVSD / historical 8kHz mono PCM',
        'PCM_theoretical_Nyquist_hz': 4000,
        'recoverable_limits': 'Pi processing cannot restore original stereo or high-frequency music content through the observed mono narrowband HFP path. Exact acoustic passband and physical DAC rate unmeasured.',
        'forcing_mSBC_supported_by_evidence': False,
    },
    'Pi_improvement_items': [
        {'action': 'Use one explicit gain authority and fixed baseline, logging phone A2DP volume, SCO volume mode/VGS and FFmpeg gain together.', 'reason': 'Makes control changes attributable; does not assume double gain or promise a fix.'},
        {'action': 'Use deterministic mono downmix and anti-alias resampling with fixed headroom.', 'reason': 'Controls clipping and conversion quality inside the 8kHz mono ceiling.'},
        {'action': 'Consider gentle fixed EQ or peak limiting; avoid aggressive fast gain riding without measurements.', 'reason': 'May improve listening consistency, but AGC pumping is not proved here.'},
        {'action': 'Compare source/output PCM RMS, peak/clipping and queue/error timing in an authorized follow-up.', 'reason': 'Required to distinguish volume events, source dynamics and transport faults; no waveform or live correlation obtained in this audit.'},
    ],
    'unproved_causes': ['phone volume causing subjective fluctuations', 'Garmin speaker AGC/DSP behavior', 'Pi noise suppression causing fluctuations', 'packet loss causing fluctuations', 'double gain causing fluctuations', 'hardware DAC or speaker fault'],
    'retained_success_limit': 'Earlier user-confirmed 60-second phone -> Pi -> Garmin music run is one successful run, not long-term stability or current audibility.',
    'parent_new_offline_result': {'terminal': '6b7fb2', 'exit_code': 0, 'provenance': 'Parent message only; not independently captured here.', 'meaning': 'Offline phone+playlist pipeline result; no fresh speaker or Bluetooth acceptance.'},
    'native_direct_phone_App_and_hardware_complete': False,
    'systemrisk_native_os20_guest_rerun': False,
    'public_sharing': 'This audit is redacted. private-* captures and source-definition captures remain private; do not publish device/phone identities or raw logs.',
}

receipts = {
    'schema': 'music-offline-quality-actual-tool-receipts/v1',
    'completed_calls': [
        {'terminal': 'fe2e7d', 'exit_code': 0, 'operation': 'Owned MAP process stop/check', 'owned_scoped_map_processes': [], 'pending_unified_exec_sessions': 0, 'map_background_jobs_started_by_this_agent': 0, 'map_binding_script_executed': False, 'partials_retained': True},
        {'terminal': '1e84ed', 'exit_code': 0, 'operation': 'Initial compact evidence read', 'raw_bytes': 647},
        {'terminal': '8e0ad4', 'exit_code': 0, 'operation': 'Bounded protocol/source capture', 'cumulative_external_raw_bytes': first['external_raw_read_bytes']},
        {'terminal': '888931', 'exit_code': 0, 'operation': 'Explicit phone log and original RFCOMM source followup', 'additional_raw_bytes': follow['raw_followup_bytes']},
        {'terminal': 'c3f4d8', 'exit_code': 0, 'operation': 'Lossless own-capture gzip closure', 'intermediate_output_cap_violation_retained': True, 'external_reads': 0},
        {'terminal': '37e1f5', 'exit_code': 0, 'operation': 'Exact last 20000 bytes NREC request/reply capture', 'raw_bytes': tail['bytes_read'], 'file_offset': tail['file_offset'], 'EOF_confirmed': True},
        {'terminal': 'fe9037', 'exit_code': 0, 'operation': 'Saved-capture numeric summary', 'external_reads': 0},
        {'terminal': 'f08fcc', 'exit_code': 0, 'operation': 'Own receipts and compressed capture structure inspection', 'external_reads': 0},
        {'terminal': 'a8d982', 'exit_code': 0, 'operation': 'Own saved excerpts structure inspection', 'external_reads': 0},
    ],
    'external_raw_read_bytes_total_including_followups': raw_total,
    'external_raw_cap': 1048576,
    'external_read_accounting': '637321 first cumulative (includes compact read twice) + 98911 explicit followup + 20000 RFCOMM tail; multiple bounded reads, not one overall source pass.',
    'input_stat_stable_during_each_capture': True,
    'all_input_handles_closed': True,
    'primary_web_sources_opened': list(primary.values()),
    'web_scope': 'Official BlueALSA tagged source/docs and Bluetooth spec landing page; no spec PDF fullhash claimed.',
    'operations': {name: 0 for name in ['Bluetooth_connect_pair', 'D_Bus_live_query', 'PCM_open', 'playback', 'daemon_service_change', 'IMG_MAIN_PBF_open', 'native_guest_execution', 'device_operation', 'canonical_report_mutation', 'MAP_continuation']},
}

proof = {
    'schema': 'music-offline-quality-audit-proof/v1',
    'namespace': 'staging/music-hfp-quality-protocol-audit-20261007-v1',
    'finite_scope_finished': True,
    'findings': {'CVSD_narrowband_supported': True, 'Garmin_mSBC_support_proved': False, 'phone_volume_events': len(volume_rows), 'volume_fluctuation_cause_confirmed': False, 'NREC_speaker_DSP_bypass_proved': False, 'quality_fix_or_live_acceptance': False},
    'source_receipts': ['input-capture-receipt.json', 'followup-input-read-receipt.json', 'NREC-tail-read-receipt.json'],
    'external_raw_bytes': raw_total,
    'external_raw_limit': 1048576,
    'input_integrity_scope': 'Captured whole small input logs/sourcefiles hashed with stable before/after stats; one later RFCOMM tail pinned to inherited full source SHA. No source read repeated during final audit generation.',
    'numeric_recomputation_scope': 'Independent ordinary Python counts from own complete saved phone gzip, and capability bits from retained HFP command rows.',
    'BAC_BCS_scope': 'Retained-excerpt-only absence; omitted matched log rows prevent whole-log absence claim.',
    'source_command_parser_erratum': parsed['first_capture_erratum'],
    'output_storage_erratum': {'initial_representation_bytes': storage['intermediate_namespace_bytes_before_compression'], 'cap': storage['output_cap'], 'cap_was_exceeded_temporarily': True, 'correction': storage['correction'], 'original_gzip_roundtrips_verified': all(row['losslessly_verified'] for row in storage['representations'])},
    'all_live_audio_device_guest_operations': 0,
    'inherited_parent_offline_pipeline_only': '6b7fb2 EXIT0; not independently rerun or speaker-confirmed here.',
    'all_input_handles_closed': True,
    'MAP_cancelled_and_partial_preserved': True,
    'STOP_after_hash_closure': True,
}

written = [write('audit.json', audit), write('actual-tool-receipts.json', receipts), write('proof.json', proof)]
handoff = '''此有限 scope 已完成，只讀既有音訊證據；沒有 Bluetooth、PCM、播放、服務、device 或 native guest 操作。導航 runner 已取消，owned PID/session 0；未封存 MAP partial 原樣保留，不再跑地圖後續。

Garmin 實際 HF BRSF 曾為 15／13，均無 bit7 codec negotiation；Pi AG 回 2784 含 bit9。原 BlueALSA 4.3.1 會在 HF 不宣告此能力時選 CVSD，日誌亦有 CVSD。Pi 支援 mSBC 不等於 Garmin 支援；不強制 mSBC。原 bit 定義：[BlueALSA hfp.h](https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/hfp.h)，行為：[RFCOMM handlers](https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/ba-rfcomm.c)。

已保存 NREC=0 緊接 ERROR 的真日誌。它要求 Pi AG 端的 ECNR；不是 Garmin 喇叭 DSP bypass。原 handler 不提供 AG NR/EC，因此 ERROR 不能當作降噪已停或忽大忽小原因。VGS15 有實際記錄；soft_volume 開啟時原 handler 只回 OK，不改 PCM 音量。本 scope 沒有查當前 soft volume 或有效喇叭音量。BAC／BCS／VGM 只在 retained excerpts 沒看到，不能當全日誌不存在。

完整保存的手機日誌有 87 次 A2DP volume 更新，值 36..127，日誌 dB 映射 -18.18..0.00。這證明控制值變動，但沒有同時間 PCM/SPL／使用者聽感，發起者與忽大忽小因果均未確認。手機端 SBC 44.1kHz stereo 與 Garmin CVSD／歷史 8kHz mono 是不同鏈段；8kHz PCM 的理論 Nyquist 為 4kHz，Pi 調音不能補回原立體聲或高頻，實際 acoustic passband／DAC 時脈未測。

Pi 可採單一明示 gain authority、固定 baseline 並合記手機 volume／SCO mode/VGS／FFmpeg gain；確定的 mono downmix、anti-alias resampling 與固定 headroom；需要時用溫和固定 EQ／limiter，先量 RMS/peak/clipping 與 queue/errors 再判原因。PCM volume modes 參考 [BlueALSA plugin docs](https://github.com/arkq/bluez-alsa/blob/v4.3.1/doc/bluealsa-plugins.7.rst)。這些是具體準備項，並非本 scope 已部署或實測修正。

2026-10-02 compact snapshot 是歷史，不能當現在 daemon/PID/PCM 狀態；目前捕獲 bridge source 已有更新 conversion 控制。Root 6b7fb2 EXIT0 的 phone+playlist offline 結果僅繼承訊息，不重跑，不當新喇叭確認。以前 60 秒使用者確認只證明一次成功，不是長穩或目前仍出聲。native-os20 systemrisk 中斷 guest 未重跑；原機 direct phone／App／hardware acceptance 仍未完成。

累計外部 raw reads 756232B（含 initial647B重讀、98911B有限 followup、20000B tail），小於1MiB；不是一個總來源 pass。first parser 不合真日誌格式的 empty counts 已明示為 unavailable，followup 只修 saved excerpts。中間 JSON representation 148618B 曾超128KiB output cap，已以 durable lossless gzip 修正、沒有提高 cap／外部重讀或隱藏此例外。最後 hash closure 記 actual mode/stat，private-* 與 source/log captures 僅私密保留，不發布 phone／unit identity 或 raw logs。

交付 audit.json／proof.json／actual-tool-receipts.json／sealed-files.json。全部 handles closed。STOP，沒有音質修復、實機 acceptance 或 full-goal 完成宣告。
'''
path = HERE / 'HANDOFF.txt'
with path.open('x') as handle:
    handle.write(handoff)
    handle.flush()
    os.fsync(handle.fileno())
final_bytes = sum(path.stat().st_size for path in HERE.iterdir() if path.is_file())
if final_bytes > 131072:
    raise ValueError('final namespace exceeds unchanged output cap')
print(json.dumps({'result': 'EXIT0 own-capture-only audit prepared', 'written': written, 'namespace_bytes_before_seal': final_bytes, 'external_reads_this_run': 0, 'all_owned_capture_handles_closed': True}, ensure_ascii=False))
