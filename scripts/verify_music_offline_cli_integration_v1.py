#!/usr/bin/env python3
"""Tiny, device-free end-to-end checks for both existing music CLIs."""
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import wave

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-offline-cli-root-integration-v1'
PINS = {
    'scripts/garmin_phone_audio_bridge.py': '8454b61d2dc329b6f9b1e2ba326f671aaf99ac92f61562774606728fe9abe72b',
    'scripts/garmin_music_player.py': 'f9e04d28632b60fc97dffb11e04432e1ba77614a3a94a5373885188878eef111',
    'scripts/garmin_audio_conversion.py': 'cfa0391ad6f121f55bc3523873621bcc8403b4837f463d161ffe0af5cb23087f',
}
guard_active = False
commands = []
rejected = []


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(event, args):
    if not guard_active:
        return
    forbidden = event.startswith('socket.') or (event == 'import' and str(args[0]).split('.')[0] == 'dbus')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        name = os.fsdecode(args[0])
        forbidden |= name.startswith(('/dev/', '/sys/'))
        forbidden |= name.endswith(('authorized-phone.json', 'bluetooth-followup-scan.json'))
    if event == 'subprocess.Popen':
        executable, argv = args[:2]
        forbidden |= Path(os.fsdecode(executable)).name not in ('ffmpeg', 'ffprobe') or not isinstance(argv, list)
        commands.append([os.fsdecode(x) for x in argv])
    if forbidden:
        rejected.append(event)
        raise RuntimeError('Unexpected service/device operation: ' + event)


def call(module, argv):
    global guard_active
    previous = sys.argv
    sys.argv = [str(module), *argv]
    captured = io.StringIO()
    guard_active = True
    try:
        with contextlib.redirect_stdout(captured):
            code = runpy.run_path(str(module), run_name='root_offline_music_check')['main']()
        assert code == 0
        return captured.getvalue()
    finally:
        guard_active = False
        sys.argv = previous


def wav_data(path):
    with wave.open(str(path), 'rb') as wav:
        assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (1, 2, 8000)
        return wav.readframes(wav.getnframes())


def main():
    OUT.mkdir(mode=0o700)
    generated = []
    record_path = None
    result = {'all_passed': False, 'source_pins': PINS, 'device_IO': False, 'played': False,
              'default_live_playback_tested': False, 'native_App_or_direct_A2DP_tested': False}
    sys.path.insert(0, str(ROOT / 'scripts'))
    sys.addaudithook(audit)
    try:
        assert all(digest(ROOT / p) == pin for p, pin in PINS.items())
        bridge = ROOT / 'scripts/garmin_phone_audio_bridge.py'
        player = ROOT / 'scripts/garmin_music_player.py'
        plans = [json.loads(call(p, ['--plan-conversion'])) for p in (bridge, player)]
        assert all(p['output']['sampling'] == 8000 and p['output']['channels'] == 1
                   and not p['automatic_level_control'] for p in plans)
        with tempfile.TemporaryDirectory(prefix='garmin-offline-root-') as temp:
            folder = Path(temp)
            tracks, reference_parts = [], []
            raw_first = None
            for index, frequency in enumerate((440, 880)):
                raw = b''.join(struct.pack('<hh', int(9000 * math.sin(2 * math.pi * frequency * n / 44100)),
                                          int(9000 * math.sin(2 * math.pi * frequency * n / 44100)))
                               for n in range(17640))
                if index == 0:
                    raw_first = raw
                track = folder / f'track-{index}.wav'
                with wave.open(str(track), 'wb') as wav:
                    wav.setparams((2, 2, 44100, 0, 'NONE', 'not compressed')); wav.writeframes(raw)
                tracks.append(track)
                reference = subprocess.run(['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error',
                                            '-f', 's16le', '-ar', '44100', '-ac', '2', '-i', 'pipe:0',
                                            '-filter:a', 'volume=0.5', '-ar', '8000', '-ac', '1',
                                            '-f', 's16le', 'pipe:1'],
                                           input=raw, capture_output=True, timeout=15, check=True)
                reference_parts.append(reference.stdout)
            raw_path = folder / 'phone.s16le'
            raw_path.write_bytes(raw_first)
            offline_path = folder / 'phone.wav'
            offline = json.loads(call(bridge, ['--offline-only', '--offline-input', str(raw_path),
                                              '--offline-output', str(offline_path), '--max-seconds', '1']))
            assert not offline['played'] and not offline['device_IO']
            assert wav_data(offline_path) == reference_parts[0]
            playlist_stdout = call(player, [*(str(t) for t in tracks), '--prepare-only', '--volume', '0.5',
                                            '--max-seconds', '1'])
            line = [s for s in playlist_stdout.splitlines() if s.startswith('已準備音訊：')]
            assert len(line) == 1
            playlist = Path(line[0].split('：', 1)[1].strip())
            assert playlist.parent == ROOT / 'staging/audio'
            generated.append(playlist)
            stamp = playlist.stem.removeprefix('playlist-')
            record_path = ROOT / 'evidence' / ('music-playback-' + stamp + '.json')
            record = json.loads(record_path.read_bytes())
            assert record['mode'] == 'prepare_only' and record['succeeded'] and len(record['tracks']) == 2
            assert record['actual_speaker_observation'] is None and not record['native_garmin_app']
            actual_playlist = wav_data(playlist)
            assert actual_playlist == b''.join(reference_parts)
            result.update(offline_bridge_frames=len(reference_parts[0]) // 2,
                          prepared_playlist_tracks=2, prepared_playlist_frames=len(actual_playlist) // 2,
                          prepared_playlist_sha256=digest(playlist),
                          playlist_record=str(record_path.relative_to(ROOT)),
                          original_fixed_filter_reference_byte_identical=True,
                          largest_fixture_seconds=0.4, persistent_fixture_bytes=0,
                          audited_conversion_subprocesses=len(commands), unexpected_device_operations=rejected,
                          all_passed=True)
        assert not rejected and all(digest(ROOT / p) == pin for p, pin in PINS.items())
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        for path in generated:
            path.unlink(missing_ok=True)
        result['generated_playlist_removed'] = all(not p.exists() for p in generated)
        (OUT / 'proof.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
