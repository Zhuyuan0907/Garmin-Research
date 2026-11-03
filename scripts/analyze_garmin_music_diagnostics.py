#!/usr/bin/env python3
"""Bounded offline scalar-log review. No audio, Bluetooth, or service APIs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

MAX_BYTES = 1048576
MAX_ROWS = 4096
MAX_LINE = 65536
MAX_EVENTS = 64
MAX_OUTPUT = 262144
METER_SCHEMA = 'garmin-host-pcm-meter/v1'
VOLUME_SCHEMA = 'garmin-audio-volume-observer-row/v1'
RUN_PATTERN = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
KNOWN_CODECS = {'cvsd', 'msbc', 'sbc', 'aac', 'lc3', 'lc3-swb', 'faststream', 'opus', 'mp3', 'aptx', 'aptx-hd', 'ldac'}


class DataError(ValueError):
    def __init__(self, code, role=None):
        self.code, self.role = code, role
        super().__init__(code)


def integer(value, minimum=0, maximum=None):
    if maximum is None:
        maximum = 2**63 - 1
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def numeric(value, minimum=0, maximum=32768):
    return type(value) in (int, float) and minimum <= value <= maximum and math.isfinite(value)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DataError('duplicate_JSON_key')
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(DataError('nonfinite_JSON')))
    except DataError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise DataError('malformed_JSON') from None


def stat_key(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_input(path, role, jsonl=True):
    """Reject special files before open; recheck a nonblocking nofollow FD."""
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise DataError('not_regular_or_symlink', role)
        if before.st_size > MAX_BYTES:
            raise DataError('input_byte_cap', role)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or stat_key(opened) != stat_key(before):
                raise DataError('input_identity_changed', role)
            with os.fdopen(fd, 'rb', closefd=False) as f:
                raw = f.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES or f.read(1):
                    raise DataError('input_byte_cap', role)
            if len(raw) != before.st_size or stat_key(os.fstat(fd)) != stat_key(before):
                raise DataError('input_changed_during_read', role)
        finally:
            os.close(fd)
        if stat_key(os.lstat(path)) != stat_key(before):
            raise DataError('input_path_changed', role)
    except DataError:
        raise
    except OSError:
        raise DataError('input_unavailable', role) from None
    if jsonl:
        lines = raw.splitlines()
        if len(lines) > MAX_ROWS:
            raise DataError('input_row_cap', role)
        records = []
        for line in lines:
            if not line.strip() or len(line) > MAX_LINE:
                raise DataError('blank_or_overlong_JSONL_line', role)
            record = parse_json(line)
            if not isinstance(record, dict):
                raise DataError('row_not_object', role)
            records.append(record)
    else:
        records = parse_json(raw)
        if not isinstance(records, dict):
            raise DataError('pipeline_not_object', role)
    return {'rows': records, 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw), 'EOF_verified': True, 'stat_stable': True}


def utc_ns(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return None
        span = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (span.days * 86400 + span.seconds) * 1000000000 + span.microseconds * 1000
    except (ValueError, OverflowError):
        return None


def clock_summary(records):
    kinds, ids, last, reset, utc_last, utc_reset = set(), set(), None, False, None, False
    mono_missing, utc_missing, run_missing = 0, 0, 0
    for row in records:
        if row.get('diagnostic_run_id') is not None:
            run = row['diagnostic_run_id']
            if not isinstance(run, str) or not RUN_PATTERN.fullmatch(run):
                raise DataError('invalid_run_binding')
            ids.add(run)
        else:
            run_missing += 1
        mono = row.get('monotonic_ns')
        if mono is not None:
            if not integer(mono):
                raise DataError('invalid_monotonic_ns')
            if last is not None and mono < last:
                reset = True
            last = mono
            kind = row.get('clock_kind', 'unspecified')
            if not isinstance(kind, str):
                raise DataError('invalid_clock_kind')
            kinds.add(kind)
        else:
            mono_missing += 1
        when = utc_ns(row.get('utc', row.get('timestamp_utc')))
        if when is None:
            utc_missing += 1
        else:
            if utc_last is not None and when < utc_last:
                utc_reset = True
            utc_last = when
    return {'run_ids': ids, 'kinds': kinds, 'monotonic_reset': reset, 'UTC_reset': utc_reset,
            'rows_without_monotonic': mono_missing, 'rows_without_aware_UTC': utc_missing,
            'rows_without_run_id': run_missing}


def parse_meter(data, role):
    records = data['rows']
    starts = [r for r in records if r.get('type') == 'start']
    summaries = [r for r in records if r.get('type') == 'summary']
    gaps, windows = [], []
    if len(starts) != 1:
        raise DataError('meter_start_count', role)
    start = starts[0]
    if start.get('schema') != METER_SCHEMA or start.get('label') != role:
        raise DataError('meter_schema_or_role', role)
    rate, channels = start.get('sampling'), start.get('channels')
    if not integer(rate, 8000, 192000) or channels not in (1, 2) or type(channels) is not int or start.get('format') != 's16le':
        raise DataError('meter_format', role)
    if len(summaries) != 1 or not records or records[-1].get('type') != 'summary':
        gaps.append('missing_duplicate_or_nonfinal_summary')
    previous_end, indexes, frame_gaps = 0, set(), 0
    for row in records:
        if row.get('type') not in ('start', 'window', 'summary'):
            raise DataError('unknown_meter_row_type', role)
        if row.get('type') != 'window':
            continue
        levels = row.get('levels')
        if not isinstance(levels, dict) or not integer(levels.get('frames'), 1):
            raise DataError('window_levels', role)
        values = levels.get('channels')
        if not isinstance(values, list) or len(values) != channels:
            raise DataError('window_channel_count', role)
        for channel in values:
            if not isinstance(channel, dict) or not numeric(channel.get('rms_s16')) or not numeric(channel.get('peak_s16')) or not integer(channel.get('full_scale_sample_count'), 0, levels['frames']):
                raise DataError('window_scalar_values', role)
            if channel['rms_s16'] > channel['peak_s16'] + 0.001:
                raise DataError('RMS_above_peak', role)
        equal_mono = levels.get('equal_weight_mono_rms_s16')
        if equal_mono is not None and (channels != 2 or not numeric(equal_mono)):
            raise DataError('invalid_equal_weight_mono_RMS', role)
        index, end = row.get('index'), row.get('end_frame')
        begin = row.get('start_frame', end - levels['frames'] if integer(end) else None)
        if not integer(index, 1) or index in indexes or not integer(begin) or not integer(end, 1) or end - begin != levels['frames']:
            raise DataError('window_frame_or_index', role)
        indexes.add(index)
        if begin != previous_end:
            frame_gaps += 1
        previous_end = end
        arrival_begin, arrival_end = row.get('arrival_begin_monotonic_ns'), row.get('arrival_end_monotonic_ns')
        if arrival_begin is not None or arrival_end is not None:
            if not integer(arrival_begin) or not integer(arrival_end) or arrival_begin > arrival_end:
                raise DataError('invalid_arrival_interval', role)
        forward = row.get('forward_end_monotonic_ns')
        if forward is not None and (not integer(forward) or arrival_end is not None and forward < arrival_end):
            raise DataError('invalid_forward_time', role)
        windows.append({'index': index, 'start_frame': begin, 'end_frame': end,
                        'start_frame_inferred': 'start_frame' not in row,
                        'frames': levels['frames'], 'partial': bool(row.get('partial_window', False)),
                        'rms': [c['rms_s16'] for c in values], 'peak': [c['peak_s16'] for c in values],
                        'endpoints': [c['full_scale_sample_count'] for c in values],
                        'equal_mono_rms': equal_mono, 'monotonic_ns': row.get('monotonic_ns'),
                        'arrival': [arrival_begin, arrival_end] if arrival_begin is not None else None,
                        'utc_ns': utc_ns(row.get('utc'))})
    if frame_gaps:
        gaps.append('noncontiguous_window_frames')
    summary = summaries[0] if len(summaries) == 1 else {}
    allowed_flags = {}
    for key in ('returncode','input_bytes','forwarded_bytes','unmeasured_frame_tail_bytes','input_bytes_not_in_levels','windows_total','diagnostic_rows_skipped_at_byte_cap'):
        value = summary.get(key)
        if value is not None:
            if not (type(value) is int if key == 'returncode' else integer(value)):
                raise DataError('invalid_summary_counter', role)
            allowed_flags[key] = value
    for key in ('maximum_pipe_forward_wait_ms', 'total_pipe_forward_wait_ms'):
        value = summary.get(key)
        if value is not None:
            if not numeric(value, 0, 1e12):
                raise DataError('invalid_wait_counter', role)
            allowed_flags[key] = value
    for key in ('unmeasured_frame_tail_bytes','input_bytes_not_in_levels','diagnostic_rows_skipped_at_byte_cap','returncode'):
        if allowed_flags.get(key,0):
            gaps.append(key)
    if allowed_flags.get('input_bytes') != allowed_flags.get('forwarded_bytes'):
        gaps.append('input_forwarded_byte_mismatch')
    if 'windows_total' in allowed_flags and allowed_flags['windows_total'] != len(windows):
        gaps.append('missing_window_rows')
    reason = summary.get('stop_reason')
    safe_reason = reason if isinstance(reason,str) and reason in {'input_eof','downstream_closed','truncated_sample_frame','signal_2','signal_15'} else 'missing_or_other_error'
    if safe_reason != 'input_eof':
        gaps.append('non_EOF_stop')
    return {'role': role, 'sampling': rate, 'channels': channels, 'windows': windows,
            'gaps': sorted(set(gaps)), 'flags': allowed_flags, 'stop_kind': safe_reason,
            'clock': clock_summary(records), 'window_frame_gaps': frame_gaps}


def safe_volume(row):
    volume = row.get('volume')
    if not isinstance(volume, dict) or not integer(volume.get('raw_q'), 0, 65535):
        raise DataError('invalid_packed_volume')
    channels, raw = volume.get('channels'), volume['raw_q']
    if not isinstance(channels, list) or len(channels) not in (1,2):
        raise DataError('invalid_volume_channels')
    for index, channel in enumerate(channels,1):
        gain = (raw >> (8 if index == 1 else 0)) & 127
        mute = bool(raw & (0x8000 if index == 1 else 0x80))
        if not isinstance(channel, dict) or channel.get('index') != index or type(channel.get('index')) is not int or channel.get('gain_0_127') != gain or type(channel.get('gain_0_127')) is not int or type(channel.get('mute')) is not bool or channel['mute'] != mute:
            raise DataError('packed_volume_decode_mismatch')
    if 'soft_volume' in row and type(row['soft_volume']) is not bool:
        raise DataError('soft_volume_not_boolean')
    codec = row.get('codec')
    codec = codec.lower() if isinstance(codec,str) and codec.lower() in KNOWN_CODECS else ('absent' if codec is None else 'unknown_unlisted')
    result = {'raw_q': raw, 'channel_count': len(channels),
            'channel_controls': [{'gain_0_127': channel['gain_0_127'], 'mute': channel['mute']} for channel in channels],
            'unused_mono_low_byte_nonzero': len(channels) == 1 and bool(raw & 255),
            'soft_volume': row.get('soft_volume'), 'codec': codec}
    if row.get('role') == 'garmin' and any(channel['gain_0_127'] > 15 for channel in channels):
        result['protocol_interpretation']='held_SCO_0_15_range_not_established_by_this_metadata'
    return result


def parse_volume(data):
    previous, events, counts, summary = {}, [], {}, None
    gaps=[]
    for row in data['rows']:
        if row.get('schema') != VOLUME_SCHEMA:
            raise DataError('volume_schema')
        kind, role = row.get('event'), row.get('role')
        if kind == 'final_summary':
            if role != 'observer' or summary is not None:
                raise DataError('volume_final_summary')
            summary = row
            continue
        if summary is not None:
            raise DataError('volume_row_after_summary')
        if role not in ('phone','garmin') or kind not in ('initial','snapshot','snapshot_change','role_missing','role_ambiguous','parse_error','rpc_unavailable'):
            raise DataError('volume_event_or_role')
        counts[kind] = counts.get(kind,0)+1
        event={'role':role,'event':kind,'monotonic_ns':row.get('monotonic_ns'),
               'utc_ns':utc_ns(row.get('timestamp_utc')),'changed_fields':[]}
        if kind in ('initial','snapshot','snapshot_change'):
            if row.get('state') != 'ok':
                raise DataError('normal_volume_state_not_ok')
            current=safe_volume(row)
            before=previous.get(role)
            event['state']=current
            event['classification']='initial_or_baseline_after_gap' if before is None or kind=='initial' else 'no_change'
            if before is not None and kind != 'initial':
                if current['channel_controls'] != before['channel_controls']:
                    event['changed_fields'].append('Volume_channels')
                if current['soft_volume'] is not None and before['soft_volume'] is not None and current['soft_volume'] != before['soft_volume']:
                    event['changed_fields'].append('SoftVolume')
                if current['codec'] not in ('absent','unknown_unlisted') and before['codec'] not in ('absent','unknown_unlisted') and current['codec'] != before['codec']:
                    event['changed_fields'].append('Codec')
                event['optional_metadata_availability_changed']=(current['soft_volume'] is None) != (before['soft_volume'] is None) or (current['codec'] in ('absent','unknown_unlisted')) != (before['codec'] in ('absent','unknown_unlisted'))
                event['ignored_mono_low_byte_changed']=current['channel_count']==before['channel_count']==1 and current['channel_controls']==before['channel_controls'] and current['raw_q']!=before['raw_q']
                if event['changed_fields']:event['classification']='observed_control_change'
                elif event['optional_metadata_availability_changed']:event['classification']='optional_metadata_availability_change_only'
                elif event['ignored_mono_low_byte_changed']:event['classification']='ignored_mono_low_byte_metadata_change_only'
            if kind=='snapshot_change' and before is None:event['classification']='reported_change_without_previous_state'
            previous[role]=current
        else:
            if row.get('volume') is not None:
                raise DataError('error_row_has_volume')
            previous.pop(role,None)
            gaps.append(kind)
            event['classification']='missing_or_unavailable_state'
        events.append(event)
    if summary is None or not data['rows'] or data['rows'][-1].get('event')!='final_summary':
        gaps.append('missing_volume_final_summary')
    safe_counts={}
    if summary:
        for key in ('rows_written','rows_skipped','diagnostic_rows_skipped_at_byte_cap','cap_dropped_rows','rpc_errors','poll_count','events_written','events_dropped','polls'):
            value=summary.get(key)
            if value is not None:
                if not integer(value):raise DataError('invalid_volume_summary_counter')
                safe_counts[key]=value
                if value and key in ('rows_skipped','diagnostic_rows_skipped_at_byte_cap','cap_dropped_rows','events_dropped'):gaps.append('volume_rows_dropped_at_cap')
        if 'output_cap_reached' in summary:
            if type(summary['output_cap_reached']) is not bool:raise DataError('invalid_volume_cap_flag')
            safe_counts['output_cap_reached']=summary['output_cap_reached']
            if summary['output_cap_reached']:gaps.append('volume_output_cap_reached')
    return {'events':events,'event_counts':counts,'gaps':sorted(set(gaps)),
            'summary_counters':safe_counts,'clock':clock_summary(data['rows'])}


def nearby(event, meter, bound, near_ns):
    clock=event.get('monotonic_ns') if bound else event.get('utc_ns')
    if clock is None or meter['clock']['monotonic_reset'] and bound or meter['clock']['UTC_reset'] and not bound:
        return {'quality':'read_order_only_no_cross_file_alignment','candidate_count':0,'windows':[]}
    candidates=[]
    for window in meter['windows']:
        if bound:
            span=window['arrival']
            if span is None and integer(window['monotonic_ns']):span=[window['monotonic_ns']]*2
        else:
            span=[window['utc_ns']]*2 if window['utc_ns'] is not None else None
        if span is None:continue
        distance=max(span[0]-clock,clock-span[1],0)
        if distance<=near_ns:
            candidates.append({'window_index':window['index'],'interval_ns':span,'distance_ns':distance,
                               'control_minus_begin_ns':clock-span[0], 'control_minus_end_ns':clock-span[1],
                               'partial_window':window['partial']})
    candidates.sort(key=lambda x:(x['distance_ns'],x['window_index']))
    return {'quality':'declared_shared_run_monotonic_host_interval' if bound else 'weak_UTC_emit_time_only',
            'candidate_count':len(candidates),'ambiguous_multiple_windows':len(candidates)>1,
            'windows':candidates[:4],'omitted_candidates':max(0,len(candidates)-4)}


def ratios(pipeline, inputs, meters):
    """Only a pinned explicit content/resampling alignment may unlock ratios."""
    if not pipeline:return {'status':'not_attempted_no_content_alignment','pairs':[]}
    alignment=pipeline.get('diagnostic_alignment')
    if not isinstance(alignment,dict) or alignment.get('schema')!='garmin-music-diagnostic-alignment/v1':
        return {'status':'not_attempted_no_supported_content_alignment','pairs':[]}
    if alignment.get('source_sha256') != {role:inputs[role]['sha256'] for role in ('phone_input','garmin_output')}:
        raise DataError('alignment_input_hash_mismatch')
    pairs=alignment.get('window_pairs')
    if not isinstance(pairs,list) or len(pairs)>64:raise DataError('alignment_pair_cap_or_type')
    result=[]
    for pair in pairs:
        if not isinstance(pair,dict) or not all(pair.get(key) is True for key in ('source_content_verified','resampling_mapping_verified','complete_source_sample_spans')) or pair.get('relation')!='same_source_sample_span':
            raise DataError('alignment_evidence_incomplete')
        matched=[]
        for role,key in [('phone_input','phone_input_index'),('garmin_output','garmin_output_index')]:
            if not integer(pair.get(key),1):raise DataError('alignment_index')
            matches=[w for w in meters[role]['windows'] if w['index']==pair[key]]
            if len(matches)!=1:raise DataError('alignment_window_missing')
            matched.append(matches[0])
        left,right=matched
        if any(meters[r]['gaps'] for r in meters) or any(w['partial'] or w['start_frame_inferred'] for w in matched):
            result.append({'status':'held_incomplete_windows'});continue
        input_meter,output_meter=meters['phone_input'],meters['garmin_output']
        if output_meter['channels']!=1:raise DataError('alignment_output_not_mono')
        duration_left=left['frames']/input_meter['sampling'];duration_right=right['frames']/output_meter['sampling']
        if abs(duration_left-duration_right)>max(1/input_meter['sampling'],1/output_meter['sampling']):
            result.append({'status':'held_duration_mismatch'});continue
        if input_meter['channels']==2:
            if pair.get('input_basis')!='equal_weight_mono' or pair.get('mono_mode')!='average' or left['equal_mono_rms'] is None:
                result.append({'status':'held_stereo_basis_unproved'});continue
            denominator=left['equal_mono_rms']
        else:
            if pair.get('input_basis')!='mono':raise DataError('alignment_mono_basis')
            denominator=left['rms'][0]
        if denominator<=0:
            result.append({'status':'held_silent_denominator'});continue
        ratio=right['rms'][0]/denominator
        if not math.isfinite(ratio):
            result.append({'status':'held_nonfinite_RMS_ratio'});continue
        result.append({'status':'descriptive_under_supplied_alignment','phone_input_index':left['index'],
                       'garmin_output_index':right['index'],'RMS_ratio':round(ratio,8),
                       'ratio_db':round(20*math.log10(ratio),6) if ratio else None})
    return {'status':'supplied_content_alignment_not_independently_recomputed','pairs':result,
            'limit':'Scalar-only logs cannot verify waveform/content or speaker gain. Frames equality alone never unlocks this path.'}


def pipeline_summary(pipeline):
    if not pipeline:
        return {'status':'not_provided'}
    state=pipeline.get('supervision',pipeline)
    if not isinstance(state,dict):raise DataError('pipeline_supervision_not_object')
    children=state.get('children',[])
    if isinstance(children,dict):
        children=[dict(value,role=key) for key,value in children.items() if isinstance(value,dict)]
    if not isinstance(children,list) or len(children)>64:raise DataError('pipeline_children_type_or_cap')
    safe_roles={'capture','convert','player','phone_input','garmin_output','input_meter','output_meter','volume_observer','phone_capture','phone_convert','hfp_player'}
    normalized=[]
    for child in children:
        if not isinstance(child,dict):raise DataError('pipeline_child_not_object')
        role=child.get('role')
        if not isinstance(role,str) or role not in safe_roles:continue
        critical=child.get('critical')
        code=child.get('returncode')
        if type(critical) is not bool or code is not None and type(code) is not int:
            raise DataError('pipeline_child_fields')
        normalized.append({'role':role,'critical':critical,'returncode':code})
    starts=state.get('optional_start_failures',[])
    if not isinstance(starts,list) or len(starts)>64:raise DataError('pipeline_optional_start_fields')
    safe_classes={'FileNotFoundError','OSError','PermissionError','ValueError','RuntimeError','TimeoutExpired','NotADirectoryError','BlockingIOError','ImportError'}
    start_failures=[]
    for failure in starts:
        if not isinstance(failure,dict):raise DataError('pipeline_optional_start_fields')
        if isinstance(failure.get('role'),str) and failure['role'] in safe_roles:
            error_kind=failure.get('error_kind')
            start_failures.append({'role':failure['role'],'state':'optional_start_unavailable',
                'error_kind':error_kind if isinstance(error_kind,str) and error_kind in safe_classes else 'other'})
    optional=state.get('optional_observer_failures',[])
    if not isinstance(optional,list) or len(optional)>64:raise DataError('pipeline_optional_observer_fields')
    cleanup=state.get('cleanup_errors',[])
    cleanup_count=len(cleanup) if isinstance(cleanup,list) else int(bool(cleanup))
    return {'status':'allowlisted_metadata_only','children':normalized,'optional_start_failures':start_failures,
        'optional_observer_failures':[role for role in optional if isinstance(role,str) and role in safe_roles],
        'critical_nonzero_roles':[c['role'] for c in normalized if c['critical'] and c['returncode'] not in (None,0)],
        'optional_nonzero_roles':[c['role'] for c in normalized if not c['critical'] and c['returncode'] not in (None,0)],
        'cleanup_error_count':cleanup_count,'raw_error_or_cleanup_strings_retained':False,
        'limit':'Audio pipeline return0 never establishes observer completeness, acoustic success, or cleanup success.'}


def analyze(phone_path, output_path, volume_path, pipeline_path=None, near_ms=1000):
    if not integer(near_ms,0,5000):raise DataError('near_ms_range')
    inputs={role:read_input(path,role) for role,path in [('phone_input',phone_path),('garmin_output',output_path),('volume',volume_path)]}
    pipeline_data=read_input(pipeline_path,'pipeline',False) if pipeline_path is not None else None
    meters={role:parse_meter(inputs[role],role) for role in ('phone_input','garmin_output')}
    volume=parse_volume(inputs['volume'])
    clocks=[meters['phone_input']['clock'],meters['garmin_output']['clock'],volume['clock']]
    ids=[next(iter(c['run_ids'])) if len(c['run_ids'])==1 else None for c in clocks]
    bound=all(ids) and len(set(ids))==1 and all(c['kinds']=={'host_monotonic_ns'} and not c['monotonic_reset'] and c['rows_without_monotonic']==0 and c['rows_without_run_id']==0 for c in clocks)
    if pipeline_data and pipeline_data['rows'].get('diagnostic_run_id') is not None and bound and pipeline_data['rows']['diagnostic_run_id'] != ids[0]:
        raise DataError('pipeline_run_binding_mismatch')
    selected=[e for e in volume['events'] if e['classification']!='no_change']
    shown=selected if len(selected)<=MAX_EVENTS else selected[:MAX_EVENTS//2]+selected[-MAX_EVENTS//2:]
    timeline=[]
    for event in shown:
        row={key:event[key] for key in ('role','event','classification','changed_fields')}
        if 'state' in event:row['state']=event['state']
        for flag in ('optional_metadata_availability_changed','ignored_mono_low_byte_changed'):
            if flag in event:row[flag]=event[flag]
        row['measurement_windows']={role:nearby(event,meters[role],bound,near_ms*1000000) for role in meters}
        row['meaning']='Temporal proximity/control metadata only; no cause or acoustic attribution.'
        timeline.append(row)
    meter_summaries={}
    for role,meter in meters.items():
        windows=meter['windows']
        meter_summaries[role]={'sampling':meter['sampling'],'channels':meter['channels'],'window_count':len(windows),
            'complete_frames_in_rows':sum(w['frames'] for w in windows),'partial_windows':sum(w['partial'] for w in windows),
            'start_frame_inferred_windows':sum(w['start_frame_inferred'] for w in windows),'gaps':meter['gaps'],
            'summary_flags':meter['flags'],'stop_kind':meter['stop_kind'],
            'full_scale_endpoint_counts':[sum(w['endpoints'][i] for w in windows) for i in range(meter['channels'])],
            'maximum_peak_s16':[max((w['peak'][i] for w in windows),default=0) for i in range(meter['channels'])],
            'endpoint_limit':'Endpoint samples are saturation clues, not proof original content clipped; no raw PCM retained.'}
    provenance=[]
    for role,clock in zip(('phone_input','garmin_output','volume'),clocks):
        provenance.append({'role':role,'run_binding_present_unique':len(clock['run_ids'])==1,
            'clock_kind_is_host_monotonic_ns':clock['kinds']=={'host_monotonic_ns'},
            'monotonic_reset':clock['monotonic_reset'],'UTC_reset':clock['UTC_reset'],
            'rows_without_monotonic':clock['rows_without_monotonic'],'rows_without_run_id':clock['rows_without_run_id'],
            'rows_without_aware_UTC':clock['rows_without_aware_UTC']})
    return {'schema':'garmin-music-offline-diagnostic-timeline/v1',
        'inputs':{role:{k:value[k] for k in ('sha256','bytes','EOF_verified','stat_stable')} for role,value in inputs.items()},
        'pipeline_input':{k:pipeline_data[k] for k in ('sha256','bytes','EOF_verified','stat_stable')} if pipeline_data else None,
        'pipeline_summary':pipeline_summary(pipeline_data['rows'] if pipeline_data else None),
        'clock_provenance':{'cross_file_monotonic_binding':bool(bound),'source_clocks':provenance,
            'binding_limit':'Matching supplied run IDs and clock kind are declared file provenance, not live boot/device validation. Unbound files use weak UTC or read order.'},
        'meter_summaries':meter_summaries,'volume_summary':{'event_counts':volume['event_counts'],'gaps':volume['gaps'],'summary_counters':volume['summary_counters'],
            'control_changes':sum(e['classification']=='observed_control_change' for e in volume['events']),
            'initial_state_limit':'Initial/baseline is not a control change. Missing/error/ambiguous state clears prior comparison. VGS is not inferred from PCM1 Volume.'},
        'timeline':timeline,'timeline_events_omitted_at_report_cap':max(0,len(selected)-len(shown)),
        'near_ms':near_ms,'descriptive_ratios':ratios(pipeline_data['rows'] if pipeline_data else None,inputs,meters),
        'limits':['arrival intervals include host read waiting; not acoustic/sample capture times','post-arecord includes upstream A2DP gain; pre-aplay precedes SCO gain/speaker DSP','frame equality and matching durations alone cannot align source/output content through resampling/buffering','forward-wait/error flags are not Bluetooth packet-loss measurement'],
        'causal_verdict':'not_available','speaker_improvement_proved':False,'device_or_audio_operations':0}


def write_new(path, result):
    raw=(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
    if len(raw)>MAX_OUTPUT:raise DataError('output_byte_cap')
    parent=Path(path).parent
    temporary=None
    published=False
    try:
        fd,temporary=tempfile.mkstemp(prefix='.music-analysis-',suffix='.partial',dir=parent)
        with os.fdopen(fd,'wb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.link(temporary,path,follow_symlinks=False)
        published=True
        directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    except FileExistsError:
        raise DataError('output_already_exists') from None
    except OSError:
        raise DataError('published_output_sync_failed_retained' if published else 'output_publish_error') from None
    finally:
        if temporary is not None:os.unlink(temporary)
    return len(raw)


def main(argv=None):
    parser=argparse.ArgumentParser(description='Offline scalar JSONL timeline only; never opens PCM, Bluetooth or service APIs.')
    parser.add_argument('--phone-input',required=True,type=Path)
    parser.add_argument('--garmin-output',required=True,type=Path)
    parser.add_argument('--volume',required=True,type=Path)
    parser.add_argument('--pipeline-evidence',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--near-ms',type=int,default=1000)
    args=parser.parse_args(argv)
    try:
        if args.output.exists() or args.output.is_symlink():raise DataError('output_already_exists')
        result=analyze(args.phone_input,args.garmin_output,args.volume,args.pipeline_evidence,args.near_ms)
        count=write_new(args.output,result)
    except DataError as error:
        print(json.dumps({'error':error.code,'role':error.role,'device_or_audio_operations':0}))
        return 2
    except (TypeError,ValueError,OverflowError,RecursionError):
        print(json.dumps({'error':'malformed_metadata_shape','role':None,'device_or_audio_operations':0}))
        return 2
    print(json.dumps({'schema':result['schema'],'output_bytes':count,'cross_file_monotonic_binding':result['clock_provenance']['cross_file_monotonic_binding'],'causal_verdict':'not_available','device_or_audio_operations':0}))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
