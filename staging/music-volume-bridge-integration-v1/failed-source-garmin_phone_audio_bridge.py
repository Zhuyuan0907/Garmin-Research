#!/usr/bin/env python3
"""Forward the explicitly identified phone's A2DP audio to the Garmin HFP speaker."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys

from garmin_audio_conversion import conversion_plan, raw_ffmpeg_command, offline_raw_to_wav, MONO_MODES
from garmin_host_audio_pipeline import PipelineSupervisor
from garmin_audio_volume_observer import sanitize_pcm_properties

ROOT = Path(__file__).resolve().parents[1]
PHONE_BUS = 'org.bluealsa.phone'


def pipeline_commands(sample_rate, channels, address, max_seconds, live_cind, plan, stamp, diagnostics=False,
                      diagnostic_run_id=None):
    """Describe the original live route, with optional scalar-only pipe taps."""
    entries = [('capture', ['arecord', '-q', '-D', 'bluealsa:SRV='+PHONE_BUS+',DEV='+address+',PROFILE=a2dp',
                            '-t', 'raw', '-f', 'S16_LE', '-r', str(sample_rate), '-c', str(channels)])]
    run_id = diagnostic_run_id or stamp
    if diagnostics:
        entries.append(('input_meter', [sys.executable, str(ROOT / 'scripts/garmin_pcm_meter.py'),
                                        '--rate', str(sample_rate), '--channels', str(channels),
                                        '--label', 'phone_input', '--report',
                                        str(ROOT / 'evidence' / ('phone-input-levels-'+stamp+'.jsonl')),
                                        '--diagnostic-run-id', run_id]))
    entries.append(('convert', raw_ffmpeg_command(plan)))
    if diagnostics:
        entries.append(('output_meter', [sys.executable, str(ROOT / 'scripts/garmin_pcm_meter.py'),
                                         '--rate', '8000', '--channels', '1', '--label', 'garmin_output',
                                         '--report', str(ROOT / 'evidence' / ('garmin-output-levels-'+stamp+'.jsonl')),
                                         '--diagnostic-run-id', run_id]))
    command = [sys.executable, str(ROOT / 'scripts/test_hfp_call_audio.py'), '--raw-stdin',
               '--max-seconds', str(max_seconds), '--call-sequence', 'incoming']
    if live_cind:
        command.append('--live-cind-test')
    entries.append(('player', command))
    return entries


def volume_observer_command(stamp, max_seconds, *, diagnostic_run_id=None, trace_input=None):
    """A separate optional metadata process; never part of the PCM chain."""
    command = [sys.executable, str(ROOT / 'scripts/garmin_audio_volume_observer.py'),
               '--output', str(ROOT / 'evidence' / ('volume-controls-'+stamp+'.jsonl')),
               '--duration', str(max_seconds + 45), '--interval', '0.5',
               '--diagnostic-run-id', diagnostic_run_id or stamp]
    command.extend(['--live'] if trace_input is None else ['--trace-input', str(trace_input)])
    return command


def run_audio_pipeline(entries, max_seconds, stamp, observer_command=None):
    """Supervise every host stage; this function has no Bluetooth API calls."""
    supervisor = PipelineSupervisor(duration_seconds=max_seconds + 45)
    try:
        with supervisor:
            if observer_command is not None:
                supervisor.start('volume_observer', observer_command, critical=False,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            upstream = None
            for role, command in entries:
                log = None
                if role != 'player':
                    prefix = {'capture': 'phone-capture', 'convert': 'phone-resample'}.get(role, role)
                    log = supervisor.open_log(role, ROOT / 'evidence' / (prefix+'-'+stamp+'.log'))
                supervisor.start(role, command, input_from=upstream,
                                 stdout=subprocess.PIPE if role != 'player' else None, stderr=log)
                upstream = role
            return supervisor.wait('player')
    except KeyboardInterrupt:
        return supervisor.result
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print('音訊管線無法繼續，請查看私密管線程序紀錄。', file=sys.stderr)
        return supervisor.result


def scalar_pcm_properties(properties, dbus_types=None):
    """Retain selected initial properties, without devices or object paths."""
    try:
        result = sanitize_pcm_properties(properties, dbus_types)
        for key, low, high in (('Sampling', 8000, 192000), ('Format', 0, 65535)):
            if key in properties:
                value = properties[key]
                expected = dbus_types.get(key) if dbus_types is not None else int
                if expected is None or (not isinstance(value, expected) if dbus_types is not None else type(value) is not int):
                    raise ValueError('invalid_scalar')
                value = int(value)
                if not low <= value <= high:
                    raise ValueError('invalid_scalar')
                result[key.lower()] = value
        return result
    except (ValueError, TypeError):
        return {'state': 'parse_error'}


def main():
    parser = argparse.ArgumentParser(description='Pixel 音樂經 Pi 轉為 Garmin 免持音訊；需在 Garmin 接聽模擬來電。')
    parser.add_argument('--max-seconds', type=int, choices=range(1, 3601), default=300, metavar='1..3600')
    parser.add_argument('--volume', type=float, default=0.5)
    parser.add_argument('--headroom-db', type=float, default=0.0, help='可選固定衰減，0 到 24 dB；不作動態音量控制')
    parser.add_argument('--mono-mode', choices=MONO_MODES, default='auto', help='auto 保留原混音；left/right 可避開反相抵消，但會捨棄另一聲道')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan-conversion', action='store_true', help='只輸出 PCM 轉換計畫，不查詢藍牙或播放')
    modes.add_argument('--offline-only', action='store_true', help='只將一般 raw S16_LE 檔案轉為新的 WAV，不查詢藍牙或播放')
    parser.add_argument('--offline-input', type=Path)
    parser.add_argument('--offline-output', type=Path)
    parser.add_argument('--input-rate', type=int, default=44100, help='離線 raw PCM 的取樣率（預設 44100）')
    parser.add_argument('--input-channels', type=int, choices=(1, 2), default=2)
    parser.add_argument('--live-cind-test', action='store_true', help='現場實驗使用舊版 Garmin 音訊服務的暫時通話狀態同步')
    parser.add_argument('--diagnostics', action='store_true', help='手動實際播放時記錄兩段Pi PCM數值與唯讀音量控制，各最多1MiB；不保留音樂內容')
    modes.add_argument('--check-only', action='store_true', help='檢查服務與音訊介面，不模擬來電或播放')
    args = parser.parse_args()
    try:
        plan = conversion_plan(args.volume, args.headroom_db, args.mono_mode, args.input_rate, args.input_channels)
    except ValueError as exc:
        parser.error(str(exc))
    if args.plan_conversion:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    if args.offline_only:
        if args.offline_input is None or args.offline_output is None:
            parser.error('--offline-only 需要 --offline-input 與 --offline-output（新的 .wav）。')
        try:
            result = offline_raw_to_wav(args.offline_input, args.offline_output, plan, args.max_seconds)
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            parser.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.offline_input is not None or args.offline_output is not None:
        parser.error('offline 路徑只能與 --offline-only 一起使用。')
    os.umask(0o077)
    import dbus
    phone = json.loads((ROOT / 'evidence/authorized-phone.json').read_text())
    phone_path = '/org/bluez/hci0/dev_'+phone['address'].replace(':', '_')
    bus = dbus.SystemBus()
    if not bus.name_has_owner(PHONE_BUS) or not bus.name_has_owner('org.bluealsa'):
        parser.error('Pi 音訊接收服務或 Garmin 音訊服務尚未執行。')
    manager = dbus.Interface(bus.get_object(PHONE_BUS, '/org/bluealsa'), 'org.freedesktop.DBus.ObjectManager')
    pcm = [p['org.bluealsa.PCM1'] for p in manager.GetManagedObjects().values()
           if 'org.bluealsa.PCM1' in p and str(p['org.bluealsa.PCM1']['Device']) == phone_path
           and str(p['org.bluealsa.PCM1']['Mode']) == 'source'
           and str(p['org.bluealsa.PCM1']['Transport']) == 'A2DP-sink']
    if len(pcm) != 1:
        parser.error('指定手機尚未建立 A2DP 音訊介面；請先在 Pixel 配對 Garmin-Pi 並開啟媒體音訊。')
    pcm = pcm[0]
    if int(pcm['Format']) != 0x8210:
        parser.error('手機音訊不是目前支援的 S16_LE 格式。')
    sample_rate, channels = int(pcm['Sampling']), int(pcm['Channels'])
    if sample_rate <= 0 or channels not in (1, 2):
        parser.error('手機音訊介面格式無效。')
    try:
        plan = conversion_plan(args.volume, args.headroom_db, args.mono_mode, sample_rate, channels)
    except ValueError as exc:
        parser.error(str(exc))
    garmin = json.loads((ROOT / 'evidence/bluetooth-followup-scan.json').read_text())['matching_devices'][0]['address']
    prop = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/hci0/dev_'+garmin.replace(':', '_')), 'org.freedesktop.DBus.Properties')
    if not prop.Get('org.bluez.Device1', 'Connected'):
        parser.error('Garmin 連線尚未建立，先從導航機連接 Garmin-Pi。')
    daemon = dbus.Interface(bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
    audio_pid = int(daemon.GetConnectionUnixProcessID('org.bluealsa'))
    patched = b'Garmin external CIND state handler' in Path(f'/proc/{audio_pid}/exe').read_bytes()
    print(f'手機音訊已就緒：{sample_rate} Hz／{channels} 聲道；Garmin 已連線。', flush=True)
    if args.check_only:
        return 0
    if not patched and not args.live_cind_test:
        parser.error('Garmin 使用舊版音訊服務；本次現場實驗需加 --live-cind-test。')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    evidence = {'started_utc': stamp, 'phone_model': phone['model'], 'source_format': {'sampling': sample_rate, 'channels': channels},
                'output_format': 'mono 8000 Hz signed 16-bit PCM; HFP CVSD', 'phone_bus': PHONE_BUS,
                'volume_multiplier': args.volume, 'duration_limit_seconds': args.max_seconds,
                'phone_speaker_observation': None, 'native_garmin_app': False, 'conversion': plan}
    evidence['diagnostics'] = {'enabled': args.diagnostics, 'audio_samples_retained': False,
                               'diagnostic_run_id': stamp if args.diagnostics else None,
                               'initial_phone_pcm_properties': scalar_pcm_properties(pcm, {
                                   'Volume': dbus.UInt16, 'Channels': dbus.Byte, 'SoftVolume': dbus.Boolean,
                                   'Codec': dbus.String, 'Sampling': dbus.UInt32, 'Format': dbus.UInt16}) if args.diagnostics else None,
                               'tap_scope': 'input after receiver volume; output before SCO/speaker gain',
                               'volume_change_monitoring_requested': args.diagnostics,
                               'volume_observer_data_verified': False,
                               'physical_speaker_levels_measured': False}
    code = 1
    try:
        print('請在 Garmin 接聽模擬來電，再於 Pixel 播音樂；Garmin 掛斷或 Ctrl+C 可停止。', flush=True)
        entries = pipeline_commands(sample_rate, channels, phone['address'], args.max_seconds,
                                    args.live_cind_test, plan, stamp, args.diagnostics)
        observer = volume_observer_command(stamp, args.max_seconds) if args.diagnostics else None
        result = run_audio_pipeline(entries, args.max_seconds, stamp, observer_command=observer)
        evidence['pipeline'] = result
        evidence['hfp_helper_returncode'] = result['player_returncode']
        evidence['process_returncodes'] = [p['returncode'] for p in result['children'].values()]
        code = result['returncode']
        if args.diagnostics:
            evidence['diagnostics']['reports'] = {
                'phone_input': str(ROOT / 'evidence' / ('phone-input-levels-'+stamp+'.jsonl')),
                'garmin_output': str(ROOT / 'evidence' / ('garmin-output-levels-'+stamp+'.jsonl')),
                'volume_controls': str(ROOT / 'evidence' / ('volume-controls-'+stamp+'.jsonl'))}
            child = result['children'].get('volume_observer')
            evidence['diagnostics']['volume_observer_process_started'] = child is not None
            evidence['diagnostics']['volume_observer_process_returncode'] = child['returncode'] if child else None
    finally:
        evidence['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        evidence['pipeline_returncode'] = code
        (ROOT / 'evidence'/('phone-bridge-'+stamp+'.json')).write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
