#!/usr/bin/env python3
"""Decode local music on the Pi and play through the verified Garmin HFP route."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import wave
from garmin_audio_conversion import conversion_plan, plan_for_track, MONO_MODES

ROOT = Path(__file__).resolve().parents[1]
EXTENSIONS = {'.mp3', '.m4a', '.aac', '.flac', '.ogg', '.opus', '.wav'}


def main():
    parser = argparse.ArgumentParser(description='在 Pi 解碼音樂，透過 Garmin 已配對的免持通道播放（單聲道 8 kHz、電話畫面）。')
    parser.add_argument('sources', nargs='*', type=Path, help='音訊檔案或包含音樂的資料夾')
    parser.add_argument('--shuffle', action='store_true', help='隨機排列歌曲')
    parser.add_argument('--volume', type=float, default=1.0, help='轉換音量倍率，0 到 1（預設 1）')
    parser.add_argument('--headroom-db', type=float, default=0.0, help='可選固定衰減，0 到 24 dB；不作動態音量控制')
    parser.add_argument('--mono-mode', choices=MONO_MODES, default='auto', help='auto 保留原混音；right/average 需要雙聲道來源')
    parser.add_argument('--plan-conversion', action='store_true', help='只輸出轉換計畫，不開啟音訊檔或查詢藍牙')
    parser.add_argument('--max-seconds', type=float, default=3600, help='整段播放上限，1 到 3600 秒（預設 3600）')
    parser.add_argument('--prepare-only', action='store_true', help='只轉換，不啟動電話畫面或播放')
    parser.add_argument('--call-sequence', choices=['active', 'outgoing', 'incoming'], default='active', help='模擬通話流程；incoming 需要在導航機接聽')
    parser.add_argument('--live-cind-test', action='store_true', help='現場實驗：暫時同步 Pi 音訊服務的通話狀態，結束時還原；供舊版服務重現已確認的播放方法')
    args = parser.parse_args()
    try:
        plan = conversion_plan(args.volume, args.headroom_db, args.mono_mode)
    except ValueError as exc:
        parser.error(str(exc))
    if args.plan_conversion:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    if not args.sources:
        parser.error('需要音訊來源，或使用 --plan-conversion。')
    if not (1 <= args.max_seconds <= 3600):
        parser.error('volume 必須為 0 到 1；max-seconds 必須為 1 到 3600。')
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        parser.error('Pi 缺少 ffmpeg 音訊解碼器。')
    tracks = []
    for source in args.sources:
        if source.is_dir():
            tracks.extend(sorted((p.resolve() for p in source.iterdir() if p.is_file() and p.suffix.lower() in EXTENSIONS), key=lambda p: p.name.lower()))
        elif source.is_file():
            tracks.append(source.resolve())
        else:
            parser.error(f'找不到音訊來源：{source}')
    if not tracks:
        parser.error('來源沒有可播放的音訊檔案。')
    if args.shuffle:
        random.shuffle(tracks)
    os.umask(0o077)
    if not args.prepare_only:
        import dbus
        address = json.loads((ROOT / 'evidence/bluetooth-followup-scan.json').read_text())['matching_devices'][0]['address']
        bus = dbus.SystemBus()
        if not bus.name_has_owner('org.bluealsa'):
            parser.error('Pi 的 Garmin 音訊服務未執行。')
        props = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/hci0/dev_' + address.replace(':', '_')), 'org.freedesktop.DBus.Properties')
        if not props.Get('org.bluez.Device1', 'Connected'):
            parser.error('Garmin 尚未連線；請先從導航機連接 Garmin-Pi。')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    cache = ROOT / 'staging/audio'
    cache.mkdir(parents=True, exist_ok=True)
    output = cache / ('playlist-' + stamp + '.wav')
    record_path = ROOT / 'evidence' / ('music-playback-' + stamp + '.json')
    evidence = {'started_utc': stamp, 'mode': 'prepare_only' if args.prepare_only else 'pi_to_garmin_hfp',
                'audio_format': 'mono 8000 Hz signed 16-bit PCM', 'volume_multiplier': args.volume,
                'duration_limit_seconds': args.max_seconds, 'tracks': [], 'output': str(output),
                'native_garmin_app': False, 'actual_speaker_observation': None, 'conversion': plan}
    evidence['temporary_host_cind_override_requested'] = args.live_cind_test
    frames = 0
    limit = int(args.max_seconds * 8000)
    succeeded = False
    try:
        with tempfile.TemporaryDirectory(prefix='garmin-music-') as temp, wave.open(str(output), 'wb') as joined:
            joined.setparams((1, 2, 8000, 0, 'NONE', 'not compressed'))
            for index, track in enumerate(tracks):
                if frames >= limit:
                    break
                decoded = Path(temp) / 'track.wav'
                remaining = (limit-frames)/8000
                try:
                    track_plan = plan_for_track(plan, track)
                except ValueError as exc:
                    raise RuntimeError(str(exc)) from exc
                command = [ffmpeg, '-nostdin', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(track),
                           '-t', str(remaining), '-vn', '-ac', '1', '-ar', '8000', '-filter:a', track_plan['filter'],
                           '-c:a', 'pcm_s16le', str(decoded)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                if result.returncode:
                    raise RuntimeError(f'無法解碼 {track.name}: {result.stderr[-2000:]}')
                with wave.open(str(decoded), 'rb') as wav:
                    count = min(wav.getnframes(), limit-frames)
                    left = count
                    while left:
                        chunk = wav.readframes(min(left, 65536))
                        if not chunk:
                            raise RuntimeError('解碼後 WAV 的長度不完整。')
                        joined.writeframesraw(chunk)
                        left -= len(chunk)//2
                evidence['tracks'].append({'file': str(track), 'frames': count, 'seconds': count/8000, 'conversion': track_plan})
                frames += count
                print(f'已轉換 {index+1}：{track.name}，{count/8000:.1f} 秒', flush=True)
        if not frames:
            raise RuntimeError('音訊來源沒有可播放的聲音。')
        evidence['duration_seconds'] = frames/8000
        evidence['limit_reached'] = frames >= limit
        if args.prepare_only:
            print(f'已準備音訊：{output}', flush=True)
            succeeded = True
            return 0
        print(f'開始播放 {frames/8000:.1f} 秒；按 Ctrl+C 或在 Garmin 結束電話畫面可停止。', flush=True)
        command = [sys.executable, str(ROOT / 'scripts/test_hfp_call_audio.py'), '--wav', str(output), '--repeat', '1', '--call-sequence', args.call_sequence]
        if args.live_cind_test:
            command.append('--live-cind-test')
        child = subprocess.Popen(command, start_new_session=True)
        try:
            code = child.wait()
        except KeyboardInterrupt:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
            code = 130
        evidence['playback_returncode'] = code
        succeeded = code == 0
        return code
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        evidence['error'] = str(exc)
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        evidence['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        evidence['succeeded'] = succeeded
        record_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
        # Keep a converted file only when preparation was explicitly requested.
        if not args.prepare_only or not succeeded:
            output.unlink(missing_ok=True)


if __name__ == '__main__':
    sys.exit(main())
