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

import dbus

ROOT = Path(__file__).resolve().parents[1]
PHONE_BUS = 'org.bluealsa.phone'


def main():
    parser = argparse.ArgumentParser(description='Pixel 音樂經 Pi 轉為 Garmin 免持音訊；需在 Garmin 接聽模擬來電。')
    parser.add_argument('--max-seconds', type=int, choices=range(1, 3601), default=300, metavar='1..3600')
    parser.add_argument('--volume', type=float, default=0.5)
    parser.add_argument('--live-cind-test', action='store_true', help='現場實驗使用舊版 Garmin 音訊服務的暫時通話狀態同步')
    parser.add_argument('--check-only', action='store_true', help='檢查服務與音訊介面，不模擬來電或播放')
    args = parser.parse_args()
    if not 0 <= args.volume <= 1:
        parser.error('volume 必須是 0 到 1。')
    os.umask(0o077)
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
                'phone_speaker_observation': None, 'native_garmin_app': False}
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
        convert = subprocess.Popen(['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error',
                                    '-probesize', '32', '-analyzeduration', '0', '-blocksize', '4096',
                                    '-f', 's16le', '-ar', str(sample_rate), '-ac', str(channels), '-i', 'pipe:0',
                                    '-filter:a', f'volume={args.volume}', '-ar', '8000', '-ac', '1', '-f', 's16le', '-flush_packets', '1', 'pipe:1'],
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
