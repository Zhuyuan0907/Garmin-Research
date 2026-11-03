#!/usr/bin/env python3
"""Fixed-gain host PCM conversion plans; no Bluetooth or audio-device API."""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

MONO_MODES = ('auto', 'left', 'right', 'average')


def conversion_plan(volume=1.0, headroom_db=0.0, mono_mode='auto', input_rate=None, input_channels=None):
    if not math.isfinite(volume) or not 0 <= volume <= 1:
        raise ValueError('volume 必須為有限的 0 到 1。')
    if not math.isfinite(headroom_db) or not 0 <= headroom_db <= 24:
        raise ValueError('headroom-db 必須為有限的 0 到 24。')
    if mono_mode not in MONO_MODES:
        raise ValueError('無效的 mono-mode。')
    if input_rate is not None and (type(input_rate) is not int or not 8000 <= input_rate <= 192000):
        raise ValueError('input-rate 必須為 8000 到 192000 Hz。')
    if input_channels is not None and input_channels not in (1, 2):
        raise ValueError('input-channels 必須為 1 或 2。')
    if input_channels == 1 and mono_mode in ('right', 'average'):
        raise ValueError('right／average 模式需要雙聲道來源。')
    gain = volume * 10 ** (-headroom_db / 20)
    # Preserve the original default filter expression and FFmpeg downmix.
    filters = [f'volume={volume if headroom_db == 0 else gain}']
    pan = {'left': 'pan=mono|c0=c0', 'right': 'pan=mono|c0=c1',
           'average': 'pan=mono|c0=0.5*c0+0.5*c1'}
    if mono_mode != 'auto':
        filters.insert(0, pan[mono_mode])
    return {'schema': 'garmin-pi-fixed-conversion/v1',
            'input': {'sampling': input_rate, 'channels': input_channels},
            'output': {'sampling': 8000, 'channels': 1, 'sample_format': 's16le'},
            'volume': volume, 'headroom_db': headroom_db, 'fixed_gain': gain,
            'mono_mode': mono_mode, 'filter': ','.join(filters),
            'automatic_level_control': False, 'Garmin_voice_DSP_changed': False,
            'live_transport_negotiated': False,
            'mono_selection_requires_stereo_if_unknown': mono_mode in ('right', 'average')}


def raw_ffmpeg_command(plan, ffmpeg='ffmpeg'):
    rate = plan['input']['sampling']
    channels = plan['input']['channels']
    if rate is None or channels is None:
        raise ValueError('Raw PCM conversion requires a known input format.')
    return [ffmpeg, '-nostdin', '-hide_banner', '-loglevel', 'error',
            '-probesize', '32', '-analyzeduration', '0', '-blocksize', '4096',
            '-f', 's16le', '-ar', str(rate), '-ac', str(channels), '-i', 'pipe:0',
            '-filter:a', plan['filter'], '-ar', '8000', '-ac', '1',
            '-f', 's16le', '-flush_packets', '1', 'pipe:1']


def plan_for_track(plan, track):
    """Probe only opt-in channel selection, so a mono track cannot go silent."""
    if plan['mono_mode'] == 'auto':
        return plan
    ffprobe = shutil.which('ffprobe')
    if not ffprobe:
        raise ValueError('可選聲道模式需要 ffprobe 檢查來源聲道。')
    result = subprocess.run([ffprobe, '-v', 'error', '-select_streams', 'a:0',
                             '-show_entries', 'stream=channels', '-of', 'json', str(track)],
                            capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError('無法確認來源的聲道配置：' + result.stderr[-1000:])
    try:
        channels = json.loads(result.stdout)['streams'][0]['channels']
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise ValueError('來源沒有可辨識的聲道配置。') from exc
    return conversion_plan(plan['volume'], plan['headroom_db'], plan['mono_mode'], input_channels=channels)


def offline_raw_to_wav(source, output, plan, max_seconds):
    """Convert a regular raw file to a new WAV, without opening any device."""
    if not math.isfinite(max_seconds) or not 0 < max_seconds <= 3600:
        raise ValueError('Invalid offline duration limit.')
    output = Path(output)
    if output.suffix.lower() != '.wav' or output.exists() or output.is_symlink():
        raise ValueError('offline-output 必須是尚不存在的 .wav 檔案。')
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        raise ValueError('找不到 ffmpeg。')
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    temp_path = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError('offline-input 必須是一般 raw S16_LE 檔案。')
        if source_stat.st_size % (2 * plan['input']['channels']):
            raise ValueError('Raw PCM 長度未對齊完整 sample frame。')
        with tempfile.NamedTemporaryFile(prefix='.garmin-convert-', suffix='.wav', dir=output.parent, delete=False) as tmp:
            temp_path = Path(tmp.name)
        command = raw_ffmpeg_command(plan, ffmpeg)[:-5]
        # Use the same fixed filters/resampling, but save a WAV instead of pipe PCM.
        command += ['-t', str(max_seconds), '-c:a', 'pcm_s16le', '-y', str(temp_path)]
        with os.fdopen(source_fd, 'rb', closefd=False) as incoming:
            result = subprocess.run(command, stdin=incoming, capture_output=True, timeout=max_seconds + 30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace')[-2000:])
        final_stat = os.fstat(source_fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(final_stat, field) != getattr(source_stat, field) for field in fields):
            raise RuntimeError('Offline source changed during conversion.')
        with temp_path.open('rb') as saved:
            os.fsync(saved.fileno())
            digest = hashlib.file_digest(saved, 'sha256').hexdigest()
        os.link(temp_path, output)  # Atomic publish, never replace another file.
        return {'output': str(output), 'bytes': output.stat().st_size, 'sha256': digest,
                'conversion': plan, 'device_IO': False, 'played': False}
    finally:
        os.close(source_fd)
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
