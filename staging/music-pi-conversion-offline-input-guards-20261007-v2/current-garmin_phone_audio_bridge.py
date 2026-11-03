#!/usr/bin/env python3
"""Forward the explicitly identified phone's A2DP audio to the Garmin HFP speaker."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from garmin_audio_conversion import conversion_plan, raw_ffmpeg_command, offline_raw_to_wav, MONO_MODES

ROOT = Path(__file__).resolve().parents[1]
PHONE_BUS = 'org.bluealsa.phone'


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
    processes = []
    logs = []
    code = 1
    try:
        capture_log = (ROOT / 'evidence'/('phone-capture-'+stamp+'.log')).open('wb')
        convert_log = (ROOT / 'evidence'/('phone-resample-'+stamp+'.log')).open('wb')
        logs = [capture_log, convert_log]
        capture = subprocess.Popen(['arecord', '-q', '-D', 'bluealsa:SRV='+PHONE_BUS+',DEV='+phone['address']+',PROFILE=a2dp',
                                    '-t', 'raw', '-f', 'S16_LE', '-r', str(sample_rate), '-c', str(channels)],
                                   stdout=subprocess.PIPE, stderr=capture_log, start_new_session=True)
        processes.append(capture)
        convert = subprocess.Popen(raw_ffmpeg_command(plan),
                                   stdin=capture.stdout, stdout=subprocess.PIPE, stderr=convert_log, start_new_session=True)
        processes.append(convert)
        capture.stdout.close()
        command = [sys.executable, str(ROOT / 'scripts/test_hfp_call_audio.py'), '--raw-stdin',
                   '--max-seconds', str(args.max_seconds), '--call-sequence', 'incoming']
        if args.live_cind_test:
            command.append('--live-cind-test')
        print('請在 Garmin 接聽模擬來電，再於 Pixel 播音樂；Garmin 掛斷或 Ctrl+C 可停止。', flush=True)
        player = subprocess.Popen(command, stdin=convert.stdout, start_new_session=True)
        processes.append(player)
        convert.stdout.close()
        code = player.wait()
        evidence['hfp_helper_returncode'] = code
    except KeyboardInterrupt:
        code = 130
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT if process is processes[-1] else signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
        evidence['process_returncodes'] = [process.returncode for process in processes]
        evidence['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        (ROOT / 'evidence'/('phone-bridge-'+stamp+'.json')).write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
