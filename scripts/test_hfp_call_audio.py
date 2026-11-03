#!/usr/bin/env python3
"""Send local HFP call indicators and a short melody; never dial a real call."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time
import tempfile
import wave
import sys

import dbus

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description='Play an 8-kHz mono 16-bit PCM WAV through the paired Garmin HFP speaker.')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--wav', type=Path, default=ROOT / 'staging/audio/garmin_test_melody.wav')
    source.add_argument('--raw-stdin', action='store_true', help='Read mono 8 kHz signed 16-bit PCM from stdin for a live bridge.')
    parser.add_argument('--max-seconds', type=int, choices=range(1, 3601), default=300, metavar='1..3600', help='Duration limit for a live PCM stream.')
    parser.add_argument('--repeat', type=int, choices=range(1, 11), default=2)
    parser.add_argument('--call-sequence', choices=['active', 'outgoing', 'incoming'], default='active')
    parser.add_argument('--live-cind-test', action='store_true', help='Attended test only: temporarily synchronize the current host daemon CIND format, then restore it.')
    args = parser.parse_args()
    if args.raw_stdin:
        if sys.stdin.isatty():
            parser.error('Live PCM input must be supplied by a pipe or file.')
        if args.repeat != 2:
            parser.error('A live input stream cannot be repeated; omit --repeat.')
        duration = args.max_seconds
    else:
        with wave.open(str(args.wav), 'rb') as wav:
            if (wav.getnchannels(), wav.getsampwidth(), wav.getframerate(), wav.getcomptype()) != (1, 2, 8000, 'NONE'):
                parser.error('WAV must be mono, signed 16-bit PCM, 8000 Hz. Convert the source before playing.')
            duration = wav.getnframes() / wav.getframerate()
    if duration <= 0 or duration > 3600:
        parser.error('WAV duration must be greater than zero and no longer than one hour.')
    os.umask(0o077)
    lock = (ROOT / 'evidence/hfp-playback.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error('Another Garmin audio playback is active; stop it before starting a second one.')
    address = json.loads((ROOT / 'evidence/bluetooth-followup-scan.json').read_text())['matching_devices'][0]['address']
    device_path = '/org/bluez/hci0/dev_' + address.replace(':', '_')
    bus = dbus.SystemBus()
    daemon = dbus.Interface(bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
    audio_pid = int(daemon.GetConnectionUnixProcessID('org.bluealsa'))
    external_cind = b'Garmin external CIND state handler' in Path(f'/proc/{audio_pid}/exe').read_bytes()
    props = dbus.Interface(bus.get_object('org.bluez', device_path), 'org.freedesktop.DBus.Properties')
    if not props.Get('org.bluez.Device1', 'Connected'):
        raise RuntimeError('Garmin connection is absent; restore connection before audio testing')
    rfcomm_path = '/org/bluealsa/hci0/dev_' + address.replace(':', '_') + '/rfcomm'
    iface = dbus.Interface(bus.get_object('org.bluealsa', rfcomm_path), 'org.bluealsa.RFCOMM1')
    unix_fd = iface.Open()
    sock = socket.socket(fileno=unix_fd.take())
    sock.setblocking(False)
    started = dt.datetime.now(dt.timezone.utc)
    evidence_path = ROOT / 'evidence' / ('audio-playback-' + started.strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    evidence = {'started': started.isoformat(), 'scope': 'Local simulated HFP indicators only; no real telephone call', 'call_sequence': args.call_sequence, 'wav': None if args.raw_stdin else str(args.wav.resolve()), 'input': 'raw_stdin' if args.raw_stdin else 'wav_file', 'duration_seconds': duration, 'events': [], 'playbacks': [], 'heard_on_device': 'Awaiting user observation'}
    evidence['external_cind_supported'] = external_cind
    call_active = args.call_sequence == 'active'
    incoming_wait = args.call_sequence == 'incoming'
    call_setup = 0
    proc = None
    pending = b''
    cind_override = None
    playback_failed = False

    def send(message):
        if cind_override is not None:
            cind_override.set(call_active, call_setup)
        data = ('\r\n' + message + '\r\n').encode('ascii')
        sock.sendall(data)
        evidence['events'].append({'direction': 'AG to HF', 'message': message})

    def receive(timeout):
        nonlocal call_active, pending, incoming_wait, call_setup
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ready, _, _ = select.select([sock], [], [], max(0, min(0.1, end-time.monotonic())))
            if not ready:
                continue
            data = sock.recv(4096)
            if not data:
                raise ConnectionError('HFP external handler closed')
            pending += data
            if len(pending) > 16384:
                raise ConnectionError('HFP command buffer exceeded its limit')
            lines = pending.replace(b'\r', b'\n').split(b'\n')
            pending = lines.pop()
            for raw in lines:
                command = raw.decode('ascii', errors='replace')
                command = command.strip()
                if not command:
                    continue
                # Keep the private log useful without exposing dialled digits.
                logged = 'ATD[redacted]' if command.startswith('ATD') else command
                evidence['events'].append({'direction': 'HF to AG', 'message': logged})
                if command == 'AT+CLCC':
                    if call_active:
                        send('+CLCC: 1,' + ('1' if args.call_sequence == 'incoming' else '0') + ',0,0,0')
                    elif incoming_wait:
                        send('+CLCC: 1,1,4,0,0')
                    elif call_setup in (2, 3):
                        send(f'+CLCC: 1,0,{call_setup},0,0')
                    send('OK')
                elif command.startswith('AT+CHLD=?'):
                    send('+CHLD: (0,1,2)')
                    send('OK')
                elif command.startswith('AT+CLIP='):
                    send('OK')
                elif command == 'ATA':
                    if incoming_wait:
                        incoming_wait = False
                        call_active = True
                        call_setup = 0
                        send('OK')
                        send('+CIEV: 2,1')
                        send('+CIEV: 3,0')
                    else:
                        send('OK')
                elif command == 'AT+CHUP':
                    call_active = False
                    incoming_wait = False
                    call_setup = 0
                    evidence['user_hung_up'] = True
                    send('OK')
                    send('+CIEV: 2,0')
                    send('+CIEV: 3,0')
                elif command.startswith('ATD'):
                    send('ERROR')
                elif command == 'AT+CIND?' and external_cind:
                    send(f'+CIND: 1,{int(call_active)},{call_setup},0,4,0,5')
                    send('OK')
                elif command.startswith(('AT+NREC=', 'AT+VGS=', 'AT+VGM=', 'AT+CIND', 'AT+CMER=', 'AT+BIA=', 'AT+BAC=', 'AT+BCS=')):
                    pass  # BlueALSA already handles these commands.
                elif command.startswith('AT'):
                    send('ERROR')

    try:
        if args.live_cind_test and not external_cind:
            from live_cind_test import LiveCindFormat
            cind_override = LiveCindFormat(audio_pid)
            evidence['temporary_host_cind_override'] = True
        send('+CIEV: 1,1')  # service available
        send('+CIEV: 5,4')  # signal strength
        if args.call_sequence == 'incoming':
            call_setup = 1
            send('+CIEV: 3,1')
            for ring in range(10):
                if not incoming_wait:
                    break
                send('RING')
                receive(3.0)
            evidence['incoming_answered'] = call_active
        if args.call_sequence == 'outgoing':
            call_setup = 2
            send('+CIEV: 3,2')  # simulated outgoing setup; no ATD or phone call
            receive(0.5)
            call_setup = 3
            send('+CIEV: 3,3')
            receive(0.5)
        if args.call_sequence != 'incoming':
            call_active = True
            send('+CIEV: 2,1')  # established indicator order from BlueALSA
        if args.call_sequence == 'outgoing':
            call_setup = 0
            send('+CIEV: 3,0')
        receive(1.0)
        print('Simulated call active; playing audio.' if call_active else 'Incoming test was not answered; no audio playback.', flush=True)
        for attempt in range(1 if args.raw_stdin else args.repeat):
            if not call_active:
                break
            with tempfile.TemporaryFile() as log:
                audio_source = ['-t', 'raw', '-f', 'S16_LE', '-r', '8000', '-c', '1', '-d', str(args.max_seconds)] if args.raw_stdin else [str(args.wav.resolve())]
                proc = subprocess.Popen(['aplay', '-D', 'bluealsa:DEV=' + address + ',PROFILE=sco', *audio_source], stdout=subprocess.DEVNULL, stderr=log)
                deadline = time.monotonic() + duration + 10
                while proc.poll() is None and call_active and time.monotonic() < deadline:
                    receive(0.1)
                if proc.poll() is None and call_active:
                    if args.raw_stdin:
                        evidence['stream_wall_time_limit_reached'] = True
                    else:
                        playback_failed = True
                        evidence['playback_timed_out'] = True
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                proc.wait()
                log.seek(0)
                stderr = log.read()
            evidence['playbacks'].append({'attempt': attempt+1, 'returncode': proc.returncode, 'stderr': stderr.decode(errors='replace')})
            if proc.returncode != 0:
                playback_failed = playback_failed or (call_active and not evidence.get('stream_wall_time_limit_reached'))
                break
            receive(0.5)
        receive(2.0)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        try:
            call_active = False
            call_setup = 0
            send('+CIEV: 2,0')
            send('+CIEV: 3,0')
            send('+CIEV: 1,0')
        except (OSError, ConnectionError):
            pass
        if cind_override is not None:
            cind_override.restore()
            evidence['host_cind_restored'] = True
        sock.close()
        evidence['playback_failed'] = playback_failed
        evidence['completed'] = dt.datetime.now(dt.timezone.utc).isoformat()
        evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'playbacks': [{'attempt': p['attempt'], 'returncode': p['returncode']} for p in evidence['playbacks']], 'events': evidence['events'], 'heard_on_device': evidence['heard_on_device']}, ensure_ascii=False), flush=True)
    if args.call_sequence == 'incoming' and not evidence.get('incoming_answered'):
        return 1
    return 1 if playback_failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
