#!/usr/bin/env python3
"""Own compiled Linux AA control + sender, bounded protobuf, real local TLS.

Peer and provider are test fixtures. No phone, USB, Garmin original instructions,
native guest, media decode/render/audio output or installation is performed.
"""
import ctypes as C
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import platform
import ssl
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/android-auto-control-host-v1'
PROOF = ROOT / 'evidence/android-auto-control-host-v1.json'
STARTUP = ROOT / 'evidence/android-auto-startup-host-v1.json'
PROTO = ROOT / 'evidence/android-auto-proto-host-v1.json'
REVIEW = ROOT / 'evidence/android-auto-control-source-review-v1.json'
TLSLIB = ROOT / 'staging/android-auto-tls-host-v1/libaa-tls-host-test.so'
RXLIB = ROOT / 'staging/android-auto-pipeline-host-v1/libaa-receiver-host.so'
BOOTLIB = ROOT / 'staging/android-auto-startup-host-v1/libaa-bootstrap-host.so'
CASES = []


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def pb(name, **fields):
    suffix = 'Message'
    cls = getattr(importlib.import_module(name + suffix + '_pb2'), name)
    return cls(**fields)


def parse(name, raw):
    m = pb(name)
    m.ParseFromString(raw)
    assert m.IsInitialized()
    return m


def profile():
    p = pb('ServiceDiscoveryResponse', head_unit_name='Linux fixture',
           headunit_manufacturer='test provider', headunit_model='bounded receiver')
    ch = p.channels.add(channel_id=1)
    ch.input_channel.supported_keycodes.extend([1, 2, 84])
    ch.input_channel.touch_screen_config.width = 800
    ch.input_channel.touch_screen_config.height = 480
    ch = p.channels.add(channel_id=3)
    ch.av_channel.stream_type = 3
    ch.av_channel.video_configs.add(video_resolution=1, video_fps=1, dpi=160)
    for channel, kind, rate, channels in [(4, 3, 48000, 2), (5, 1, 16000, 1), (6, 2, 16000, 1)]:
        ch = p.channels.add(channel_id=channel)
        ch.av_channel.stream_type = 1
        ch.av_channel.audio_type = kind
        ch.av_channel.audio_configs.add(sample_rate=rate, bit_depth=16, channel_count=channels)
    return p


PROVIDER = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint8, C.c_uint32,
                     C.c_int32, C.c_uint32, C.c_uint64, C.c_void_p, C.c_size_t)


def build():
    OUT.mkdir(exist_ok=True)
    shim = OUT / 'profile-init.c'
    shim.write_text('''/* Host test adapter; profiles decoded by real nanopb. */
#include "control.h"
int aa_test_control_init(void *ctx,uint32_t session,const unsigned char *p,
                         size_t n,aa_control_provider cb,void *arg){
    f1x_aasdk_proto_messages_ServiceDiscoveryResponse value={0};
    pb_istream_t in=pb_istream_from_buffer(p,n);
    if(!pb_decode(&in,f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,&value))
        return AA_CONTROL_E_PROTOBUF;
    return aa_control_init(ctx,session,&value,cb,arg);
}
''')
    generated = json.loads((ROOT / 'staging/android-auto-proto-host-v1/build.json').read_text())
    sources = [ROOT / 'native/aa-control/control.c', ROOT / 'native/aa-sender/sender.c', shim]
    sources += [ROOT / p for p in generated['c_sources']]
    includes = ['native/aa-control', 'native/aa-sender', 'native/aa-tls', 'native/aa-message',
                'native/aa-proto', 'native/aa-proto/generated', 'native/aa-proto/runtime']
    lib = OUT / 'libaa-control-host.so'
    args = ['cc', '-shared', '-fPIC', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
            '-DPB_VALIDATE_UTF8=1'] + ['-I' + str(ROOT / p) for p in includes]
    args += list(map(str, sources)) + [str(TLSLIB), '-o', str(lib)]
    result = subprocess.run(args, capture_output=True, cwd=ROOT)
    assert result.returncode == 0, result.stderr.decode()
    return lib, shim, {'argv': args, 'exit_code': result.returncode, 'stderr': result.stderr.decode()}


def bind(lib, view):
    lib.aa_control_context_bytes.restype = C.c_uint32
    lib.aa_test_control_init.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p,
                                       C.c_size_t, PROVIDER, C.c_void_p]
    lib.aa_control_receive.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(view)]
    lib.aa_control_channel_status.argtypes = [C.c_void_p, C.c_uint32, C.c_uint8]
    lib.aa_control_tx_peek.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(view), C.POINTER(C.c_uint32)]
    lib.aa_control_tx_commit.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_int]
    for n in ['pending', 'status', 'step', 'stop']:
        getattr(lib, 'aa_control_' + n).argtypes = [C.c_void_p, C.c_uint32]
    lib.aa_sender_context_bytes.restype = C.c_uint32
    lib.aa_sender_init.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32]
    lib.aa_sender_submit.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(view), C.c_uint32]
    lib.aa_sender_tx_peek.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t)]
    lib.aa_sender_tx_commit.argtypes = [C.c_void_p, C.c_uint32, C.c_size_t, C.c_int]
    lib.aa_sender_release.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32]
    for n in ['step', 'status', 'error_detail', 'stop']:
        getattr(lib, 'aa_sender_' + n).argtypes = [C.c_void_p, C.c_uint32]


def cold_start(bootlib, pair, boot, rx):
    b = boot.Bootstrap(bootlib, pair)
    assert b.initial == 0
    pending = bytearray()
    ids = []
    for _ in range(2000):
        if b.peek()[2]:
            wire = b.output(chunks=(1, 7, 31))
            mid, data = boot.payload(wire)
            ids.append(mid)
            if mid == 1:
                assert wire == boot.VERSION_REQUEST
                pending.extend(boot.VERSION_RESPONSE)
            elif mid == 3:
                pair.inbio.write(data)
                try:
                    pair.peer.do_handshake()
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                output = pair.outbio.read()
                if output:
                    pending.extend(rx.frame(0, 3, b'\x00\x03' + output))
            elif mid == 4:
                assert wire == boot.AUTH
                boot.proto_auth(data)
                assert b.call('status') == 5 and not pending
                b.stop()
                return ids
            else:
                raise AssertionError(mid)
        if pending:
            r, n = b.feed(bytes(pending))
            assert r in (0, 2, 3)
            del pending[:n]
        assert b.call('step', 1) in (1, 2, 3)
    raise AssertionError('startup failed to converge')


class Env:
    def __init__(self, lib, rxlib, tls, tlshelper, rxhelper, fixtures, bootlib, boothelper,
                 cold=False, offered=None):
        self.lib, self.tls, self.rxlib, self.rxhelper = lib, tls, rxlib, rxhelper
        self.pair = tlshelper.Pair(tls, fixtures)
        if cold:
            bootlib.aa_test_inject_final_output(0)
            self.startup_ids = cold_start(bootlib, self.pair, boothelper, rxhelper)
        else:
            assert self.pair.handshake(chunk=7) == 1
            self.startup_ids = []
        self.ctrl = C.create_string_buffer(lib.aa_control_context_bytes())
        self.sender = C.create_string_buffer(lib.aa_sender_context_bytes())
        self.events, self.attempts, self.outputs, self.errors = [], [], [], []
        self.pause_event, self.reject_event, self.reenter_event = 0, 0, 0
        self.reentry = []
        def provide(_, channel, event, sid, config, stamp, ptr, n):
            try:
                item = (channel, event, sid, config, stamp, C.string_at(ptr, n) if n else b'')
                self.attempts.append(item)
                if self.reenter_event == event:
                    self.reentry.append(lib.aa_control_step(self.ctrl, self.pair.sid))
                    self.reentry.append(lib.aa_control_stop(self.ctrl, self.pair.sid))
                if self.pause_event == event:
                    return 1
                if self.reject_event == event:
                    return -991
                self.events.append(item)  # Owned fixture copy, not physical output.
                return 0
            except Exception as e:
                self.errors.append(repr(e))
                return -992
        self.provider = PROVIDER(provide)
        p = offered if offered is not None else profile()
        raw = p.SerializeToString()
        self.initial = lib.aa_test_control_init(self.ctrl, self.pair.sid, raw, len(raw), self.provider, None)
        assert lib.aa_sender_init(self.sender, self.pair.storage, self.pair.sid) == 0
        self.receiver = C.create_string_buffer(rxlib.aa_receiver_context_bytes())
        self.wire, self.plain = C.create_string_buffer(32768), C.create_string_buffer(32768)
        self.message = C.create_string_buffer(262144)
        self.callback = rxhelper.CALLBACK(('aa_control_message_callback', lib))
        assert rxlib.aa_receiver_init(self.receiver, self.pair.storage, self.pair.sid,
            self.wire, len(self.wire), self.plain, len(self.plain), self.message, len(self.message),
            4096, self.callback, self.ctrl, 1) == 0

    def call(self, name, *args):
        return getattr(self.lib, 'aa_control_' + name)(self.ctrl, self.pair.sid, *args)

    def state(self, ch):
        return self.call('channel_status', ch)

    def peek(self):
        view, token = self.rxhelper.View(), C.c_uint32()
        assert self.call('tx_peek', C.byref(view), C.byref(token)) == 0
        return view, token.value

    def direct(self, ch, mid, obj=None, flags=None, raw=None):
        data = struct.pack('>H', mid) + (raw if raw is not None else obj.SerializeToString() if obj else b'')
        buf = C.create_string_buffer(data)
        view = self.rxhelper.View(ch, (8 | (4 if mid == 7 else 0)) if flags is None else flags,
                                  1, len(data), C.addressof(buf))
        return self.lib.aa_control_receive(self.ctrl, self.pair.sid, C.byref(view))

    def incoming(self, ch, mid, obj=None, flags=None, raw=None, fragments=False):
        flags = (8 | (4 if mid == 7 else 0)) if flags is None else flags
        data = struct.pack('>H', mid) + (raw if raw is not None else obj.SerializeToString() if obj else b'')
        parts = [data] if not fragments else [data[:15000], data[15000:30000], data[30000:]]
        kinds = [3] if not fragments else [1, 0, 2]
        return b''.join(self.rxhelper.frame(ch, flags | kind,
            self.rxhelper.encrypt(self.pair, part) if flags & 8 else part,
            len(data) if kind == 1 else 0) for part, kind in zip(parts, kinds))

    def feed(self, wire, chunks=(65535,), drain=False):
        storage = C.create_string_buffer(wire)
        at, turn, pending = 0, 0, False
        while at < len(wire) or pending:
            n = min(chunks[turn % len(chunks)], len(wire) - at)
            used = C.c_size_t()
            r = self.rxlib.aa_receiver_feed(self.receiver, self.pair.sid,
                C.addressof(storage) + at if n else None, n, C.byref(used))
            assert r in (0, 1), r
            assert used.value <= n
            C.memset(C.addressof(storage) + at, 0xCE, used.value)
            at += used.value
            pending = r == 1
            r = self.step()
            if r < 0:
                return r
            if drain:
                self.drain()
                r = self.step()
            if r == 1 and not drain:
                return r
            turn += 1
            assert turn < 50000
        return self.step()

    def step(self):
        for _ in range(1000):
            r = self.rxlib.aa_receiver_step(self.receiver, self.pair.sid)
            if r != 2:
                assert not self.errors, self.errors
                return r
        raise AssertionError('receiver did not yield')

    def drain(self, auto_focus=True):
        for _ in range(40):
            if auto_focus:
                r = self.call('step')
                assert r in (0, 1), r
            view, token = self.peek()
            if not token:
                return
            plain = C.string_at(view.payload, view.bytes)
            assert self.lib.aa_sender_submit(self.sender, self.pair.sid, C.byref(view), token) == 0
            for _ in range(100):
                r = self.lib.aa_sender_step(self.sender, self.pair.sid)
                if r == 2:
                    break
                assert r == 1, r
            else:
                raise AssertionError('sender did not yield wire')
            pointer, count = C.c_void_p(), C.c_size_t()
            assert self.lib.aa_sender_tx_peek(self.sender, self.pair.sid, C.byref(pointer), C.byref(count)) == 0
            wire = C.string_at(pointer, count.value)
            assert wire[0] == view.channel and wire[1] == view.flags | 3
            assert int.from_bytes(wire[2:4], 'big') == len(wire) - 4
            assert self.lib.aa_sender_tx_commit(self.sender, self.pair.sid, 0, 0) == 1
            assert self.lib.aa_sender_tx_commit(self.sender, self.pair.sid, len(wire) + 1, 0) == -400001
            # Borrowed view remains stable after zero/invalid commits.
            p2, n2 = C.c_void_p(), C.c_size_t()
            self.lib.aa_sender_tx_peek(self.sender, self.pair.sid, C.byref(p2), C.byref(n2))
            assert (p2.value, n2.value) == (pointer.value, count.value)
            old_state = self.state(view.channel) if view.channel else None
            assert self.lib.aa_sender_tx_commit(self.sender, self.pair.sid, 3, 0) == 1
            if view.channel:
                assert self.state(view.channel) == old_state
            assert self.lib.aa_sender_status(self.sender, self.pair.sid) == 1
            # Independent peer observes the actual complete wire output.
            if view.flags & 8:
                self.pair.inbio.write(wire[4:])
                actual = self.pair.peer.read(16384)
            else:
                actual = wire[4:]
            assert actual == plain
            assert self.lib.aa_sender_tx_commit(self.sender, self.pair.sid, len(wire)-3, 0) == 3
            assert self.call('tx_commit', token + 1, 0) == -500003
            assert self.call('tx_commit', token, 0) == 0
            assert self.lib.aa_sender_release(self.sender, self.pair.sid, token) == 0
            self.outputs.append((view.channel, view.flags, int.from_bytes(actual[:2], 'big'), actual[2:]))
            if actual[:2] == b'\x00\x10':
                return
        raise AssertionError('output did not quiesce')

    def discover(self):
        assert self.feed(self.incoming(0, 5, pb('ServiceDiscoveryRequest', device_name='fixture'))) == 0
        self.drain()
        assert self.outputs[-1][2] == 6

    def open(self, ch):
        assert self.feed(self.incoming(ch, 7, pb('ChannelOpenRequest', channel_id=ch))) == 0
        assert self.state(ch) == 1
        self.drain()
        assert self.state(ch) == 2

    def setup(self, ch):
        assert self.feed(self.incoming(ch, 0x8000, pb('AVChannelSetupRequest'))) == 0
        assert self.state(ch) == 3
        self.drain()
        assert self.state(ch) == 4

    def start(self, ch, sid=0):
        assert self.feed(self.incoming(ch, 0x8001, pb('AVChannelStartIndication', session=sid))) == 0
        assert self.state(ch) == 5

    def prepared(self, ch=3, sid=0):
        self.discover();self.open(ch);self.setup(ch);self.start(ch, sid)

    def close(self):
        assert self.rxlib.aa_receiver_stop(self.receiver, self.pair.sid) == 0
        if self.initial == 0:
            assert self.call('stop') == 0
        assert self.lib.aa_sender_stop(self.sender, self.pair.sid) == 0
        self.pair.free()


def tests(lib, rxlib, tls, tlshelper, rxhelper, bootlib, boothelper, fixtures):
    heap = C.create_string_buffer(2 * 1024 * 1024)
    assert tls.aa_tls_runtime_init(heap, len(heap), int(time.time())) == 0
    def new(**kwargs):
        e = Env(lib, rxlib, tls, tlshelper, rxhelper, fixtures, bootlib, boothelper, **kwargs)
        return e

    e = new(cold=True)
    assert e.initial == 0 and e.startup_ids[0] == 1 and e.startup_ids[-1] == 4
    e.discover()
    answer = parse('ServiceDiscoveryResponse', e.outputs[-1][3])
    assert [x.channel_id for x in answer.channels] == [1, 3, 4, 5, 6]
    assert answer == profile() and all(x.channel_id != 7 for x in answer.channels)
    e.prepared = None
    e.open(3);e.setup(3);e.start(3, -2147483648)
    assert e.outputs[-2][2] == 0x8003
    setup_answer = parse('AVChannelSetupResponse', e.outputs[-2][3])
    assert setup_answer.media_status == 2 and setup_answer.max_unacked == 1 and list(setup_answer.configs) == [0]
    assert e.outputs[-1][2] == 0x8008
    stamp = 0xFEDCBA9876543210
    media = b'\x00\x00\x00\x01\x67fixture-not-valid-H264' + bytes(range(256)) * 150
    assert e.feed(e.incoming(3, 0, raw=struct.pack('>Q', stamp)+media, fragments=True),
                  chunks=(1, 7, 4096), drain=True) == 0
    ev = [x for x in e.events if x[1] == 5]
    assert ev == [(3, 5, -2147483648, 0, stamp, media)]
    ack = parse('AVMediaAckIndication', e.outputs[-1][3])
    assert e.outputs[-1][:3] == (3, 8, 0x8004) and ack.session == -2147483648 and ack.value == 1
    assert len([x for x in e.outputs if x[2] == 0x8004]) == 1
    e.close()
    CASES.append('cold legacy startup -> real mutual TLS -> discovery/open/setup/focus/start -> 38KB fragmented timestamped media -> ONE encrypted ACK, same TLS session')

    e = new();e.discover();e.open(4);e.setup(4);e.start(4, -1)
    audio = struct.pack('<hhhh', 1000, -1000, 2000, -2000) * 600
    assert e.feed(e.incoming(4, 1, raw=audio), chunks=(13,)) == 0
    e.drain()
    assert [x for x in e.events if x[1] == 5] == [(4, 5, -1, 0, 0, audio)]
    assert parse('AVMediaAckIndication', e.outputs[-1][3]).session == -1
    assert e.feed(e.incoming(4, 0x8002, pb('AVChannelStopIndication'))) == 0 and e.state(4) == 4
    e.start(4, 2147483647)
    assert e.feed(e.incoming(4, 1, raw=b'new stream')) == 0;e.drain()
    assert parse('AVMediaAckIndication', e.outputs[-1][3]).session == 2147483647
    e.close();CASES.append('PCM media routing retains signed session, stop and restart without treating media as SBC/protobuf')

    e = new();e.discover();e.open(1)
    assert e.feed(e.incoming(1, 0x8002, pb('BindingRequest', scan_codes=[1, 84]))) == 0
    assert e.state(1) == 6;e.drain();assert e.state(1) == 7
    assert e.outputs[-1] == (1, 8, 0x8003, b'\x08\x00')
    e.close();CASES.append('input binding uses advertised keys and proto2 required success-zero')

    e = new();e.discover();e.open(1)
    assert e.feed(e.incoming(1, 0x8002, pb('BindingRequest', scan_codes=[999]))) == 0
    e.drain();assert e.state(1) == 2 and e.outputs[-1][3] == b'\x08\x01'
    assert not [x for x in e.events if x[1] == 8]
    e.close();CASES.append('unadvertised input key yields FAIL without starting provider')

    e = new()
    for timestamp in [-9223372036854775808, 0, 9223372036854775807]:
        assert e.feed(e.incoming(0, 11, pb('PingRequest', timestamp=timestamp), flags=0), chunks=(1,)) == 0
        e.drain()
        assert e.outputs[-1][:3] == (0, 0, 12)
        assert parse('PingResponse', e.outputs[-1][3]).timestamp == timestamp
    assert e.feed(e.incoming(0, 12, pb('PingResponse', timestamp=5), flags=0)) == 0
    assert e.call('pending') == 0
    e.close();CASES.append('explicit plaintext ping compatibility with full signed64 timestamp and parsed response')

    e = new();e.discover();e.open(3)
    assert e.feed(e.incoming(3, 0x8000, pb('AVChannelSetupRequest', config_index=4))) == 0
    e.drain();ans=parse('AVChannelSetupResponse', e.outputs[-1][3])
    assert ans.media_status == 1 and ans.max_unacked == 1 and not ans.configs and e.state(3) == 2
    e.close();CASES.append('unsupported setup index FAIL preserves OPEN and advertises no invalid config')

    for event, label in [(1, 'open'), (2, 'setup')]:
        e = new();e.discover();e.reject_event = event
        if event == 2:e.open(3)
        assert e.feed(e.incoming(3, 7 if event == 1 else 0x8000,
            pb('ChannelOpenRequest', channel_id=3) if event == 1 else pb('AVChannelSetupRequest'))) == 0
        e.drain();assert e.state(3) == (0 if event == 1 else 2)
        assert not [x for x in e.events if x[1] == event]
        e.close();CASES.append('real provider '+label+' refusal produces failed reply without advancing channel')

    e = new();e.prepared();e.pause_event = 5
    wire=e.incoming(3, 1, raw=b'held-media')
    assert e.feed(wire) == 1 and not e.call('pending')
    assert e.step() == 1 and not [x for x in e.events if x[1] == 5]
    e.pause_event=0;assert e.step() == 0;e.drain()
    assert [x for x in e.events if x[1] == 5] == [(3,5,0,0,0,b'held-media')]
    assert len([x for x in e.outputs if x[2] == 0x8004]) == 1
    e.close();CASES.append('provider PAUSED retains complete receiver message; retry accepts once with no premature ACK')

    e = new();e.prepared()
    assert e.feed(e.incoming(3, 1, raw=b'first')) == 0
    assert e.feed(e.incoming(3, 1, raw=b'second')) == 1
    assert len([x for x in e.events if x[1] == 5]) == 1
    e.drain();assert e.step() == 0;e.drain()
    assert [x[5] for x in e.events if x[1] == 5] == [b'first',b'second']
    e.close();CASES.append('max_unacked1 backpressure holds second whole media until first ACK transport completion')

    e = new();e.prepared()
    assert e.feed(e.incoming(3, 1, raw=b'last')) == 0
    assert e.feed(e.incoming(3, 0x8002, pb('AVChannelStopIndication'))) == 1
    assert e.state(3) == 5;e.drain();assert e.step() == 0 and e.state(3) == 4
    e.close();CASES.append('STOP waits for pending ACK completion before provider suspend/session clear')

    e = new();e.discover();e.open(3)
    assert e.feed(e.incoming(3, 0x8000, pb('AVChannelSetupRequest'))) == 0
    e.pause_event=6;e.drain(auto_focus=False)
    assert e.state(3) == 4 and e.call('step') == 1 and e.call('pending') == 0
    e.pause_event=0;e.drain()
    assert e.outputs[-1][2] == 0x8008 and len([x for x in e.events if x[1] == 6]) == 1
    e.close();CASES.append('deferred video focus after setup completion pauses/retries actual provider before publication')

    e = new();e.discover();e.open(3)
    assert e.feed(e.incoming(3, 0x8000, pb('AVChannelSetupRequest'))) == 0
    e.drain(auto_focus=False)
    assert e.feed(e.incoming(3, 0x8007, pb('VideoFocusRequest', focus_mode=2))) == 0
    e.drain()
    assert [x[3] for x in e.events if x[1] == 6] == [2]
    assert parse('VideoFocusIndication', e.outputs[-1][3]).focus_mode == 2
    assert e.call('step') == 0 and e.call('pending') == 0
    e.close();CASES.append('new explicit UNFOCUSED request supersedes pending automatic setup FOCUSED request')

    e = new();e.discover();e.open(3)
    assert e.feed(e.incoming(3, 0x8000, pb('AVChannelSetupRequest'))) == 0
    assert e.direct(3, 0x8001, pb('AVChannelStartIndication')) == -500003
    e.close();CASES.append('START before setup transport completion is refused')

    e = new()
    for i in range(4):assert e.direct(0, 11, pb('PingRequest', timestamp=i), flags=0) == 0
    assert e.call('pending') == 4
    assert e.direct(0, 11, pb('PingRequest', timestamp=4), flags=0) == 1
    e.drain();assert e.direct(0, 11, pb('PingRequest', timestamp=4), flags=0) == 0;e.drain()
    assert [parse('PingResponse',x[3]).timestamp for x in e.outputs] == list(range(5))
    e.close();CASES.append('four-slot reply queue full returns not-accepted PAUSED and stable ordered retry')

    for label, ch, mid, obj, flags, error in [
        ('plain discovery',0,5,pb('ServiceDiscoveryRequest'),0,-500004),
        ('discovery CONTROL bit',0,5,pb('ServiceDiscoveryRequest'),12,-500004),
        ('unknown message',0,0x7777,None,8,-500004),
        ('unadvertised microphone channel',7,7,pb('ChannelOpenRequest',channel_id=7),12,-500003),
        ('conflicting open channel',3,7,pb('ChannelOpenRequest',channel_id=4),12,-500004),
        ('media before start',3,1,None,8,-500003)]:
        e=new();e.discover()
        assert e.direct(ch,mid,obj,flags=flags) == error
        assert e.call('status') == error and e.call('pending') == error
        e.close();CASES.append('strict subset rejects '+label)

    e=new();e.discover()
    assert e.feed(e.incoming(3,7,pb('ChannelOpenRequest'))) == 0;e.drain();assert e.state(3)==2
    e.close();CASES.append('proto3 omitted open channel_id defaults0 accepted under documented legacy compatibility policy')

    for label, payload in [('truncated field',b'\x22\x05ab'),('invalid UTF8',b'\x22\x02\xff\xff'),
                           ('bounded name overflow',b'\x22\x40'+b'a'*64)]:
        e=new();assert e.direct(0,5,raw=payload) == -500005
        e.close();CASES.append('bounded real protobuf rejects '+label)

    e=new();assert e.direct(0,5,raw=b'\xa0\x06\x7b')==0;e.drain()
    assert e.outputs[-1][2]==6;e.close();CASES.append('unknown protobuf field skipped by pinned runtime without inventing capability')

    for label, ch, mid, raw, error in [('short BE64 timestamp',3,0,b'1234567',-500004),
                                      ('empty media',3,1,b'',-500004),
                                      ('wrong start config',3,0x8001,b'\x10\x01',-500003)]:
        e=new();e.prepared()
        assert e.direct(ch,mid,raw=raw)==error
        e.close();CASES.append('media lifecycle rejects '+label)

    e=new();e.prepared();e.reenter_event=5
    assert e.feed(e.incoming(3,1,raw=b'reentry'))==0
    assert e.reentry==[-500008,-500008];e.drain();e.close()
    CASES.append('provider cannot reenter control step or stop while borrowed media callback is active')

    e=new();e.discover()
    for typ,state in [(1,1),(2,2),(3,7),(4,3)]:
        assert e.feed(e.incoming(0,18,pb('AudioFocusRequest',audio_focus_type=typ)))==0;e.drain()
        assert parse('AudioFocusResponse',e.outputs[-1][3]).audio_focus_state==state
    e.close();CASES.append('audio focus responses require explicit provider acceptance; local gain/transient/guidance/loss mapping')

    e=new();e.discover();e.open(3);e.setup(3)
    assert e.feed(e.incoming(3,0x8007,pb('VideoFocusRequest',focus_mode=2)))==0;e.drain()
    assert parse('VideoFocusIndication',e.outputs[-1][3]).focus_mode==2
    e.close();CASES.append('video focus on actual video channel preserves requested focused/unfocused mode')

    e=new();assert e.feed(e.incoming(0,15,pb('ShutdownRequest')))==0
    assert e.direct(0,11,pb('PingRequest'),flags=0)==1
    e.drain();assert e.outputs[-1][:3]==(0,8,16) and e.call('status')==-500003
    e.close();CASES.append('shutdown response encrypted; subsequent input blocked until whole output commit closes control')

    e=new();assert e.direct(0,11,pb('PingRequest'),flags=0)==0
    v,t=e.peek();assert e.call('tx_commit',t,-5)==-500009
    e.close();CASES.append('failed whole-message transport completion invalidates control and discards queued plaintext')

    e=new();assert e.lib.aa_control_status(e.ctrl,e.pair.sid+1)==-500002
    assert e.lib.aa_sender_status(e.sender,e.pair.sid+1)==-400002
    e.close();CASES.append('stale bound session rejected by control and sender')

    for label, change in [('duplicate channel',lambda p:p.channels.add().CopyFrom(p.channels[0])),
                          ('microphone offer',lambda p:setattr(p.channels[0],'channel_id',7)),
                          ('zero touch width',lambda p:setattr(p.channels[0].input_channel.touch_screen_config,'width',0)),
                          ('unsupported media format',lambda p:setattr(p.channels[2].av_channel.audio_configs[0],'sample_rate',44100)),
                          ('multiple service kinds',lambda p:setattr(p.channels[0].av_channel,'stream_type',3))]:
        p=profile();change(p);e=new(offered=p);assert e.initial==-500001
        e.close();CASES.append('caller capability profile rejects '+label)

    e=new();assert e.direct(0,11,pb('PingRequest'),flags=0)==0
    v,t=e.peek();assert e.lib.aa_sender_submit(e.sender,e.pair.sid,C.byref(v),t)==0
    assert e.lib.aa_sender_step(e.sender,e.pair.sid)==2
    assert e.lib.aa_sender_tx_commit(e.sender,e.pair.sid,0,-9)==-400007
    assert e.lib.aa_sender_status(e.sender,e.pair.sid)==-400007
    e.close();CASES.append('sender failed partial transport is terminal and cannot publish DONE')

    e=new();assert e.direct(0,11,pb('PingRequest'),flags=0)==0
    v,t=e.peek();v.flags=8
    assert tls.aa_tls_write(e.pair.storage,e.pair.sid,b'foreign output',14)==14
    assert lib.aa_sender_submit(e.sender,e.pair.sid,C.byref(v),t)==-400004
    e.close();CASES.append('sender rejects stale TLS output rather than mislabelling it as current control response')

    e=new();assert e.direct(0,11,pb('PingRequest'),flags=0)==0
    v,t=e.peek();v.flags=8
    assert lib.aa_sender_submit(e.sender,e.pair.sid,C.byref(v),t)==0
    assert lib.aa_sender_step(e.sender,e.pair.sid)==2
    assert lib.aa_sender_tx_commit(e.sender,e.pair.sid,3,0)==1
    assert lib.aa_sender_stop(e.sender,e.pair.sid)==0
    # Generic TLS cannot enforce this sender-owner lifetime obligation: reinit
    # CAN succeed, but skipped ciphertext makes its next record unusable.
    replacement=C.create_string_buffer(lib.aa_sender_context_bytes())
    assert lib.aa_sender_init(replacement,e.pair.storage,e.pair.sid)==0
    assert lib.aa_sender_submit(replacement,e.pair.sid,C.byref(v),t)==0
    assert lib.aa_sender_step(replacement,e.pair.sid)==2
    ptr,n=C.c_void_p(),C.c_size_t()
    assert lib.aa_sender_tx_peek(replacement,e.pair.sid,C.byref(ptr),C.byref(n))==0
    wire=C.string_at(ptr,n.value);e.pair.inbio.write(wire[4:])
    try:
        e.pair.peer.read(16384)
    except ssl.SSLError:
        pass
    else:
        raise AssertionError('peer accepted next TLS record after discarded prior record')
    assert lib.aa_sender_stop(replacement,e.pair.sid)==0
    e.close();CASES.append('negative lifetime control: sender mid-output stop cannot preserve TLS sequence; whole TLS session MUST be discarded')

    assert tls.aa_tls_heap_used()==0 and tls.aa_tls_heap_verify()==0
    return {'allocator_peak_bytes':tls.aa_tls_heap_max(),'allocator_final_bytes':0,
            'control_context_bytes':lib.aa_control_context_bytes(),
            'sender_context_bytes':lib.aa_sender_context_bytes()}


def main():
    started=time.time()
    startup=json.loads(STARTUP.read_text())
    assert startup['pass'] and startup['case_count']==29 and not startup['device_IO']
    for name,pin in startup['source_sha256'].items():assert sha(ROOT/name)==pin,name
    assert sha(BOOTLIB)==startup['compiled_library_sha256']
    proto=json.loads(PROTO.read_text())
    assert proto['pass'] and not proto['device_IO'] and not proto['native_guest_executed']
    for name,pin in proto['source_sha256'].items():assert sha(ROOT/name)==pin,name
    review=json.loads(REVIEW.read_text())
    assert review['runtime_tests_run'] is False and review['phone_compatibility_verified'] is False
    for item in review['source_manifest']:
        assert sha(ROOT/item['path'])==item['sha256'],item['path']
    sys.path.insert(0,str(ROOT/'staging/android-auto-proto-host-v1/python'))
    tlshelper=module('aa_tls_control_fixture',ROOT/'scripts/test_aa_tls_host.py')
    rxhelper=module('aa_rx_control_fixture',ROOT/'scripts/test_aa_receiver_host.py')
    boothelper=module('aa_boot_control_fixture',ROOT/'scripts/test_aa_bootstrap_host.py')
    tls=C.CDLL(str(TLSLIB));tlshelper.bind(tls)
    rxlib=C.CDLL(str(RXLIB));rxhelper.bind(rxlib)
    bootlib=C.CDLL(str(BOOTLIB));boothelper.bind(bootlib)
    libpath,shim,buildinfo=build();lib=C.CDLL(str(libpath));bind(lib,rxhelper.View)
    tlshelper.OUT=OUT
    fixtures=tlshelper.certificates()
    stats=tests(lib,rxlib,tls,tlshelper,rxhelper,bootlib,boothelper,fixtures)
    pins=dict(startup['source_sha256']);pins.update(proto['source_sha256'])
    for p in [ROOT/'native/aa-control/control.c',ROOT/'native/aa-control/control.h',
              ROOT/'native/aa-sender/sender.c',ROOT/'native/aa-sender/sender.h',
              ROOT/'native/aa-control/README.md',ROOT/'native/aa-sender/README.md',
              ROOT/'scripts/test_aa_control_host.py',shim]:pins[str(p.relative_to(ROOT))]=sha(p)
    proof={'schema':'android-auto-control-host-v1','pass':True,'case_count':len(CASES),
           'cases':CASES,'device_IO':False,'native_guest_executed':False,
           'Garmin_code_executed':False,'current_Pixel_interoperability_verified':False,
           'Google_acceptance_verified':False,'install_candidate':False,
           'Garmin_Android_Auto_or_Google_Maps_running':False,
           'media_provider_is_owned_fixture_copy':True,'H264_decoding_or_display_verified':False,
           'PCM_hardware_speaker_or_touch_backend_verified':False,
           'real_local_TLS_legacy_startup_to_control_verified':True,
           'outgoing_control_encrypted_by_real_C_sender':True,
           'reply_state_changes_after_complete_transport_commit':True,
           'whole_media_ACK_after_provider_acceptance_verified':True,
           'fixture_ACK_is_not_render_or_sound_proof':True,
           'local_TLS_fixture_peer_is_Android_Auto':False,
           'control_and_sender_ASan_verified':False,
           'prerequisite':{'startup':{'path':str(STARTUP.relative_to(ROOT)),'sha256':sha(STARTUP)},
                           'proto':{'path':str(PROTO.relative_to(ROOT)),'sha256':sha(PROTO)}},
           'public_source_review':{'path':str(REVIEW.relative_to(ROOT)),'sha256':sha(REVIEW),
                                  'runtime_tests':0},
           'source_sha256':pins,'compiled_library_sha256':sha(libpath),
           'build':buildinfo,'runtime':stats,'host_arch':platform.machine(),
           'elapsed_host_seconds':round(time.time()-started,3),
           'next_required_work':['real USB host/VBUS/AOA and current-phone session',
             'H264 decoder/display scaling, bounded real media provider, touch send path',
             'native entropy/time/ABI/memory/performance, audio ownership/UI/install lifecycle'],
           'limitations':['Legacy pinned model and local explicit policies only; current phone/Google acceptance unknown.',
             'Strict supported subset: no sensor/navigation/Bluetooth descriptor or microphone, no general extension dispatch.',
             'ACK means the fixture copied complete media; no decoder, screen, sound, hardware transport or timing.',
             'All callers/provider/TLS operations serialized; no task/IRQ/cancellation/quiescence proof.',
             'Small outgoing control messages <=8192 bytes; no outgoing media fragmentation.',
             'The cold end-to-end case uses real TLS, but the independently written peer is a test fixture, not Android Auto.']}
    PROOF.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'pass':True,'cases':len(CASES),'proof':str(PROOF.relative_to(ROOT)),
                      'sha256':sha(PROOF),'runtime':stats,'device_IO':False,
                      'native_guest_executed':False},ensure_ascii=False))


if __name__=='__main__':main()
