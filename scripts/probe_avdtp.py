#!/usr/bin/env python3
"""Read-only AVDTP endpoint discovery; never configure or start an audio stream."""
import datetime as dt
import json
import os
from pathlib import Path
import socket

import dbus

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.umask(0o077)
    address = json.loads((ROOT / 'evidence/bluetooth-followup-scan.json').read_text())['matching_devices'][0]['address']
    bus = dbus.SystemBus()
    props = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/hci0/dev_' + address.replace(':', '_')), 'org.freedesktop.DBus.Properties')
    if not props.Get('org.bluez.Device1', 'Connected'):
        raise RuntimeError('Restore the Garmin HFP connection first')
    evidence = {'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'scope': 'AVDTP Discover and GetCapabilities only; no configuration/start/media traffic',
                'reference': 'https://github.com/bluez/bluez/blob/master/profiles/audio/avdtp.c',
                'transactions': [], 'endpoints': []}
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.settimeout(3)

    def request(label, signal, payload=b''):
        command = bytes([label << 4, signal]) + payload
        sock.sendall(command)
        response = sock.recv(4096)
        evidence['transactions'].append({'command_hex': command.hex(), 'response_hex': response.hex()})
        if len(response) < 2 or response[0] >> 4 != label or (response[0] >> 2) & 3 or response[1] & 63 != signal:
            raise ValueError('Unexpected AVDTP response header')
        return response[0] & 3, response[2:]

    try:
        sock.connect((address, 25))
        evidence['signalling_connected'] = True
        kind, body = request(1, 1)
        evidence['discover_response_type'] = kind
        if kind == 2:
            if len(body) % 2:
                raise ValueError('Invalid Discover endpoint list length')
            for index in range(0, min(len(body), 24), 2):
                first, second = body[index:index+2]
                endpoint = {'seid': first >> 2, 'in_use': bool(first & 2),
                            'role': 'sink' if second & 8 else 'source', 'media_type': second >> 4}
                evidence['endpoints'].append(endpoint)
                cap_kind, caps = request(2 + index//2, 2, bytes([endpoint['seid'] << 2]))
                endpoint['capabilities_response_type'] = cap_kind
                endpoint['capabilities'] = []
                if cap_kind == 2:
                    pos = 0
                    while pos < len(caps):
                        if pos + 2 > len(caps):
                            raise ValueError('Truncated capability header')
                        category, size = caps[pos:pos+2]
                        value = caps[pos+2:pos+2+size]
                        if len(value) != size:
                            raise ValueError('Truncated capability payload')
                        cap = {'category': category, 'data_hex': value.hex()}
                        if category == 7 and size >= 2:
                            cap['media_type'] = value[0] >> 4
                            cap['codec_id'] = value[1]
                        endpoint['capabilities'].append(cap)
                        pos += 2 + size
        else:
            evidence['discover_error_hex'] = body.hex()
    except (OSError, ValueError) as exc:
        evidence['error'] = str(exc)
    finally:
        sock.close()
        evidence['device_connected_after_probe'] = bool(props.Get('org.bluez.Device1', 'Connected'))
        evidence['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        target = ROOT / 'evidence' / ('avdtp-discovery-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
        target.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
