#!/usr/bin/env python3
"""Pairing restricted to the identified Garmin and the explicitly supplied phone."""
import datetime as dt
import json
import os
from pathlib import Path
import signal

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

ROOT = Path(__file__).resolve().parents[1]
AGENT = 'org.bluez.Agent1'
ADDRESS = json.loads((ROOT / 'evidence/bluetooth-followup-scan.json').read_text())['matching_devices'][0]['address']
DEVICE = '/org/bluez/hci0/dev_' + ADDRESS.replace(':', '_')
PATH = '/org/garmin/research/agent'
AUDIO = {'1108', '110a', '110b', '110c', '110d', '110e', '1112', '111e', '111f'}
PHONE_AUDIO = {'110a', '110b', '110c', '110d', '110e', '110f'}


def record(event, **details):
    item = {'time': dt.datetime.now(dt.timezone.utc).isoformat(), 'event': event, **details}
    with (ROOT / 'evidence/pairing-agent-events.jsonl').open('a') as f:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(json.dumps(item, ensure_ascii=False), flush=True)


class Rejected(dbus.DBusException):
    _dbus_error_name = 'org.bluez.Error.Rejected'


def check(device):
    if str(device) == DEVICE:
        return 'garmin'
    phone = ROOT / 'evidence/authorized-phone.json'
    if phone.exists():
        info = json.loads(phone.read_text())
        expected = '/org/bluez/hci0/dev_' + info['address'].upper().replace(':', '_')
        if str(device) == expected:
            return 'authorized_phone'
    record('rejected_other_device')
    raise Rejected('Only the identified Garmin and explicitly authorized phone are accepted')


class Agent(dbus.service.Object):
    @dbus.service.method(AGENT, in_signature='', out_signature='')
    def Release(self):
        record('agent_released')
        loop.quit()

    @dbus.service.method(AGENT, in_signature='o', out_signature='s')
    def RequestPinCode(self, device):
        check(device)
        record('legacy_pin_returned', pin='1234')
        return '1234'

    @dbus.service.method(AGENT, in_signature='os', out_signature='')
    def DisplayPinCode(self, device, pin):
        check(device)
        record('pin_display_requested', pin=str(pin))

    @dbus.service.method(AGENT, in_signature='o', out_signature='u')
    def RequestPasskey(self, device):
        check(device)
        record('passkey_returned', passkey=1234)
        return dbus.UInt32(1234)

    @dbus.service.method(AGENT, in_signature='ouq', out_signature='')
    def DisplayPasskey(self, device, passkey, entered):
        check(device)
        record('passkey_display_requested', passkey=int(passkey), entered=int(entered))

    @dbus.service.method(AGENT, in_signature='ou', out_signature='')
    def RequestConfirmation(self, device, passkey):
        target = check(device)
        record('identified_device_confirmed', target=target, passkey=int(passkey))

    @dbus.service.method(AGENT, in_signature='o', out_signature='')
    def RequestAuthorization(self, device):
        target = check(device)
        record('identified_device_pairing_authorized', target=target)

    @dbus.service.method(AGENT, in_signature='os', out_signature='')
    def AuthorizeService(self, device, uuid):
        target = check(device)
        service = str(uuid).lower()
        allowed = PHONE_AUDIO if target == 'authorized_phone' else AUDIO
        if service not in {'0000'+short+'-0000-1000-8000-00805f9b34fb' for short in allowed}:
            record('non_audio_service_rejected', uuid=service)
            raise Rejected('Only audio services are enabled for this test')
        record('identified_device_audio_authorized', target=target, uuid=service)

    @dbus.service.method(AGENT, in_signature='', out_signature='')
    def Cancel(self):
        record('pairing_request_canceled')


if __name__ == '__main__':
    os.umask(0o077)
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    agent = Agent(bus, PATH)
    manager = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.AgentManager1')
    manager.RegisterAgent(PATH, 'NoInputNoOutput')
    manager.RequestDefaultAgent(PATH)
    adapter = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/hci0'), 'org.freedesktop.DBus.Properties')
    adapter.Set('org.bluez.Adapter1', 'Pairable', dbus.Boolean(True))
    adapter.Set('org.bluez.Adapter1', 'PairableTimeout', dbus.UInt32(0))
    adapter.Set('org.bluez.Adapter1', 'DiscoverableTimeout', dbus.UInt32(0))
    adapter.Set('org.bluez.Adapter1', 'Discoverable', dbus.Boolean(True))
    loop = GLib.MainLoop()
    def stop(signum, frame):
        loop.quit()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    record('agent_ready', pid=os.getpid(), capability='NoInputNoOutput', scope='Identified Garmin and explicitly supplied phone; restricted audio services only')
    try:
        loop.run()
    finally:
        try:
            manager.UnregisterAgent(PATH)
        except dbus.DBusException:
            pass
        record('agent_stopped')
