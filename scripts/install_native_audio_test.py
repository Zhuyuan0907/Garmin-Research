#!/usr/bin/env python3
"""Add the stock Audio Test Page's WAV fixture to the identified navigator."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import wave

import garmin_backup
from install_taiwan_map import identity, same_usb, confirm_live_identity

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'backups/20261002T154458Z'
TARGET = Path('Garmin/test.wav')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sampling-hz', type=int, choices=(16000, 44100, 48000), default=16000)
    parser.add_argument('--channels', type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    os.umask(0o077)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    rate, channels = args.sampling_hz, args.channels
    source = ROOT / f'staging/audio/native-test-{rate}-{channels}ch.wav'
    source.parent.mkdir(parents=True, exist_ok=True)
    samples = bytearray()
    notes = [(1.0 + i * 0.7, freq, 0) for i, freq in enumerate((440, 660, 880, 660, 440))]
    if channels == 2:
        notes = ([(0.8 + i * 0.55, freq, 0) for i, freq in enumerate((440, 660, 880))] +
                 [(3.2 + i * 0.55, freq, 1) for i, freq in enumerate((880, 660, 440))])
    for i in range(rate * 8):
        t = i / rate
        for channel in range(channels):
            value = 0.0
            for start, freq, note_channel in notes:
                pos = t - start
                if note_channel == channel and 0 <= pos < 0.5:
                    envelope = min(1.0, pos / 0.015, (0.5 - pos) / 0.015)
                    value = 0.15 * envelope * math.sin(2 * math.pi * freq * pos)
                    break
            samples.extend(struct.pack('<h', round(value * 32767)))
    with wave.open(str(source), 'wb') as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(samples)
    payload = source.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    metadata = json.loads((BACKUP / 'sda.json').read_text())
    expected = identity((BACKUP / 'files/Garmin/GarminDevice.xml').read_bytes())
    candidates = [disk for disk in garmin_backup.disks() if same_usb(disk, metadata)]
    if len(candidates) != 1:
        raise RuntimeError('Exactly one matching navigator USB disk is required')
    disk = candidates[0]
    garmin_backup.ensure_source(disk)
    if disk.get('children'):
        raise RuntimeError('Unexpected partitioned layout')
    mountpoint = Path(tempfile.mkdtemp(prefix='garmin-wav-', dir='/run'))
    mounted = False
    result = {'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'device_file': str(TARGET), 'source': str(source),
              'format': {'encoding': 'PCM S16LE', 'sampling_hz': rate,
                         'channels': channels, 'duration_seconds': 8, 'peak_fraction': 0.15},
              'bytes': len(payload), 'sha256': digest,
              'firmware_modified': False, 'stock_files_replaced': 0,
              'stock_MAIN_sha256': '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8',
              'stock_path_literal': '0x9d50a8', 'stock_path_load': '0x673e88',
              'stock_audio_register_call': '0x525f14', 'stock_audio_start_call': '0x36b720',
              'speaker_observation': 'Pending attended diagnostic playback'}
    try:
        subprocess.run(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec',
                        disk['path'], str(mountpoint)], check=True, capture_output=True, timeout=15)
        mounted = True
        xml = mountpoint / 'Garmin/GarminDevice.xml'
        original_xml = xml.read_bytes()
        if identity(original_xml) != expected:
            raise RuntimeError('Navigator identity differs from verified backup')
        destination = mountpoint / TARGET
        partial = destination.with_suffix('.wav.partial')
        existing_matches = destination.exists() and destination.read_bytes() == payload
        previous = None
        if destination.exists():
            if not existing_matches:
                prior = json.loads((ROOT / 'evidence/native-wav-installation-latest.json').read_text())
                previous = destination.read_bytes()
                if (prior.get('state') not in ('installed_readback_verified', 'already_installed_readback_verified')
                        or not prior.get('unmounted') or prior.get('device_file') != str(TARGET)
                        or hashlib.sha256(previous).hexdigest() != prior['sha256']):
                    raise RuntimeError('Existing test.wav is not our verified fixture; left untouched')
                saved = ROOT / f'staging/audio/replaced-native-test-{stamp}.wav'
                with saved.open('xb') as backup:
                    backup.write(previous)
                    backup.flush()
                    os.fsync(backup.fileno())
                result['previous_project_fixture'] = str(saved)
                result['previous_project_fixture_sha256'] = prior['sha256']
        if existing_matches:
            result['state'] = 'already_installed_readback_verified'
        else:
            if partial.exists():
                raise RuntimeError('An existing partial fixture must be inspected first')
            space = os.statvfs(mountpoint)
            if space.f_bavail * space.f_frsize < len(payload) + 2 * 1024 * 1024:
                raise RuntimeError('Insufficient free space')
            confirm_live_identity(disk)
            subprocess.run(['mount', '-o', 'remount,rw,nosuid,nodev,noexec', str(mountpoint)],
                           check=True, capture_output=True, timeout=15)
            with partial.open('xb') as out:
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
            if partial.read_bytes() != payload:
                raise RuntimeError('Fixture readback mismatch')
            if previous is not None and destination.read_bytes() != previous:
                raise RuntimeError('Previous fixture changed while preparing replacement')
            partial.replace(destination)
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            if xml.read_bytes() != original_xml or destination.read_bytes() != payload:
                raise RuntimeError('Post-write readback mismatch')
            result['state'] = 'installed_readback_verified'
        result['device_readback_sha256'] = hashlib.sha256(destination.read_bytes()).hexdigest()
    except Exception as error:
        result.update(state='failed', error=str(error))
        raise
    finally:
        unmount = subprocess.run(['umount', str(mountpoint)], capture_output=True, timeout=20) if mounted else None
        result['unmounted'] = unmount is None or unmount.returncode == 0
        result['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        evidence = ROOT / 'evidence' / f'native-wav-installation-{stamp}.json'
        evidence.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        if result['unmounted']:
            mountpoint.rmdir()
        if result.get('state') in ('installed_readback_verified', 'already_installed_readback_verified'):
            (ROOT / 'evidence/native-wav-installation-latest.json').write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    if not result['unmounted']:
        raise RuntimeError('Unmount failed; leave the USB cable connected')
    print(json.dumps({'state': result['state'], 'file': str(TARGET), 'bytes': len(payload),
                      'rate': rate, 'channels': channels, 'unmounted': result['unmounted'], 'evidence': str(evidence)}))


if __name__ == '__main__':
    main()
