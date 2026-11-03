#!/usr/bin/env python3
"""Real local TLS peer -> owned wire queue -> plaintext message assembly.

Linux host only. No Garmin/phone I/O, firmware instructions, guest, AA version
negotiation, protobuf dispatch, ACKs or hardware. Uses the previously verified
Mbed TLS adapter library; local test certificates are regenerated privately.
"""
import ctypes as C
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import ssl
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/android-auto-pipeline-host-v1'
PROOF = ROOT / 'evidence/android-auto-pipeline-host-v1.json'
PREREQ = {k: ROOT / ('evidence/android-auto-' + k + '-host-v1.json')
          for k in ['tls', 'wire', 'message']}
CASES = []


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_prerequisites():
    d = {k: json.loads(p.read_text()) for k, p in PREREQ.items()}
    for key in ['wire', 'message']:
        assert d[key]['success'], key
        for name, v in d[key]['source_files'].items():
            assert sha(ROOT / name) == v['sha256'], name
    assert d['tls']['pass'] and not d['tls']['device_IO']
    for name, pin in d['tls']['source_sha256'].items():
        assert sha(ROOT / name) == pin, name
    lib = ROOT / 'staging/android-auto-tls-host-v1/libaa-tls-host-test.so'
    assert sha(lib) == d['tls']['library_sha256']
    return d, lib


def build(tlslib):
    OUT.mkdir(exist_ok=True)
    lib = OUT / 'libaa-receiver-host.so'
    sources = [ROOT / ('native/' + p) for p in
               ['aa-receiver/receiver.c', 'aa-wire/wire.c', 'aa-message/message.c']]
    argv = ['cc', '-shared', '-fPIC', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror']
    argv += ['-I' + str(ROOT / 'native' / d) for d in
             ['aa-receiver', 'aa-wire', 'aa-message', 'aa-tls']]
    argv += list(map(str, sources)) + [str(tlslib), '-o', str(lib)]
    p = subprocess.run(argv, capture_output=True, cwd=ROOT)
    assert p.returncode == 0, p.stderr.decode()
    return lib, {'argv': argv, 'exit_code': p.returncode, 'stderr': p.stderr.decode()}


class View(C.Structure):
    _fields_ = [('channel', C.c_uint8), ('flags', C.c_uint8),
                ('fragments', C.c_uint32), ('bytes', C.c_size_t), ('payload', C.c_void_p)]


CALLBACK = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(View))


def bind(lib):
    lib.aa_receiver_context_bytes.argtypes = []
    lib.aa_receiver_context_bytes.restype = C.c_uint32
    lib.aa_receiver_init.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32,
        C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t,
        C.c_uint32, CALLBACK, C.c_void_p, C.c_int]
    lib.aa_receiver_init.restype = C.c_int
    for name in ['step', 'finish', 'stop', 'status', 'error_detail', 'queued']:
        f = getattr(lib, 'aa_receiver_' + name)
        f.argtypes, f.restype = [C.c_void_p, C.c_uint32], C.c_int
    lib.aa_receiver_feed.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p,
                                    C.c_size_t, C.POINTER(C.c_size_t)]
    lib.aa_receiver_feed.restype = C.c_int


class Receiver:
    def __init__(self, lib, pair, capacity=262144, allow_plaintext=0,
                 pause=0, callback_error=0, reenter=False, max_fragments=4096):
        self.lib, self.pair = lib, pair
        self.context = C.create_string_buffer(lib.aa_receiver_context_bytes())
        self.wire, self.plain = C.create_string_buffer(32768), C.create_string_buffer(32768)
        self.message = C.create_string_buffer(capacity) if capacity else None
        self.pause, self.callback_error, self.reenter = pause, callback_error, reenter
        self.views, self.attempts, self.errors, self.reentry = [], [], [], []
        def callback(_, pointer):
            try:
                v = pointer.contents
                snapshot = (v.channel, v.flags, v.fragments, C.string_at(v.payload, v.bytes))
                self.attempts.append(snapshot)
                if self.reenter:
                    consumed = C.c_size_t(123)
                    result = lib.aa_receiver_feed(self.context, pair.sid, None, 0, C.byref(consumed))
                    self.reentry.append((result, consumed.value,
                                         lib.aa_receiver_step(self.context, pair.sid)))
                if self.pause:
                    self.pause -= 1
                    return 1
                if self.callback_error:
                    return self.callback_error
                self.views.append(snapshot)
                return 0
            except Exception as e:
                self.errors.append(repr(e))
                return -777
        self.callback = CALLBACK(callback)
        self.initial = lib.aa_receiver_init(self.context, pair.storage, pair.sid,
            self.wire, len(self.wire), self.plain, len(self.plain), self.message, capacity,
            max_fragments, self.callback, None, allow_plaintext)
        assert self.initial == 0, self.initial

    def call(self, name):
        return getattr(self.lib, 'aa_receiver_' + name)(self.context, self.pair.sid)

    def feed(self, data):
        n = C.c_size_t(123)
        r = self.lib.aa_receiver_feed(self.context, self.pair.sid, data, len(data), C.byref(n))
        return r, n.value

    def step_all(self):
        for _ in range(100):
            r = self.call('step')
            if r != 2:
                assert not self.errors, self.errors
                return r
        raise AssertionError('worker failed to yield')

    def pump(self, data, chunks=(4096,), overwrite=True):
        storage = C.create_string_buffer(data)
        offset, turn, paused = 0, 0, False
        while offset < len(data) or paused:
            n = min(chunks[turn % len(chunks)], len(data) - offset)
            consumed = C.c_size_t(123)
            r = self.lib.aa_receiver_feed(self.context, self.pair.sid,
                C.addressof(storage) + offset if n else None, n, C.byref(consumed))
            assert r in (0, 1), (r, self.call('error_detail'))
            assert consumed.value <= n
            if overwrite and consumed.value:
                C.memset(C.addressof(storage) + offset, 0xCE, consumed.value)
            offset += consumed.value
            paused = r == 1
            result = self.step_all()
            assert result in (0, 1), (result, self.call('error_detail'))
            turn += 1
            assert turn < 100000
        while self.step_all() == 1:
            turn += 1
            assert turn < 100000
        assert self.call('queued') == 0 and not self.errors

    def close(self):
        assert self.call('stop') == 0
        assert not any(self.wire.raw) and not any(self.plain.raw)
        assert self.message is None or not any(self.message.raw)
        assert self.call('queued') == 0
        self.pair.free()


def frame(channel, flags, payload, total=0):
    assert len(payload) <= 65535
    return struct.pack('>BBH', channel, flags, len(payload)) + (
        struct.pack('>I', total) if flags & 3 == 1 else b'') + payload


def encrypt(pair, data):
    if not data:
        return b''
    for start in range(0, len(data), 16384):
        b = data[start:start + 16384]
        assert pair.peer.write(b) == len(b)
    return pair.outbio.read()


def tests(lib, tls, helper, fixtures):
    heap = C.create_string_buffer(2 * 1024 * 1024)
    assert tls.aa_tls_runtime_init(heap, len(heap), int(time.time())) == 0
    ciphers = set()
    def pair():
        p = helper.Pair(tls, fixtures)
        assert p.handshake(chunk=19) == 1
        ciphers.add(p.peer.cipher()[0])
        return p
    def new(**options):
        return Receiver(lib, pair(), **options)
    def bad(r, wire, error):
        result, consumed = r.feed(wire)
        assert result in (0, 1) and consumed == len(wire)
        assert r.step_all() == error, (error, r.call('status'), r.call('error_detail'))
        assert not r.views
        assert r.call('status') == error
        assert r.feed(b'')[0] == error
        assert not any(r.plain.raw)
        assert r.message is None or not any(r.message.raw)
        r.close()

    r = new()
    data = b'\x00\x05service-discovery-like-opaque-body' + bytes(range(256))
    r.pump(frame(0, 15, encrypt(r.pair, data)), chunks=(1,))
    assert r.views == [(0, 12, 1, data)] and r.call('finish') == 0
    assert r.call('finish') == 0 and r.feed(b'new')[0] == -200003
    r.close()
    CASES.append('real TLS record -> bytewise wire feed -> copied complete BULK message')

    r = new()
    data = bytes((i * 17) % 251 for i in range(40000))
    parts = [data[:16384], data[16384:32768], data[32768:]]
    wire = b''.join(frame(3, k | 8, encrypt(r.pair, b), len(data) if k == 1 else 0)
                    for k, b in zip([1, 0, 2], parts))
    r.pump(wire, chunks=(len(wire),))
    assert r.views == [(3, 8, 3, data)]
    r.close()
    CASES.append('40KB FIRST/MIDDLE/LAST through two-slot queue backpressure with consumed-source overwrite')

    r = new(pause=2)
    data = b'complete-but-delivery-paused' * 50
    wire = frame(6, 11, encrypt(r.pair, data))
    assert r.feed(wire) == (0, len(wire))
    assert r.call('step') == 1 and r.call('queued') == 0
    assert r.call('step') == 1 and not r.views
    assert r.call('step') == 2 and r.views == [(6, 8, 1, data)]
    assert r.attempts == [r.views[0]] * 3 and r.call('step') == 0
    r.close()
    CASES.append('message delivery pause retains exact plaintext and never repeats TLS ciphertext')

    r = new()
    data = bytes(i % 239 for i in range(16384))
    wire = frame(4, 9, encrypt(r.pair, data), len(data)) + frame(4, 10, b'')
    r.pump(wire, chunks=(4096, 3, 11, 97))
    assert r.views == [(4, 8, 2, data)]
    r.close()
    CASES.append('exact 16KB split message completed by zero-length LAST')

    r = new()
    data = bytes((i * 3) % 253 for i in range(25000))
    r.pump(frame(2, 11, encrypt(r.pair, data)), chunks=(37, 4096, 1, 211))
    assert r.views == [(2, 8, 1, data)]
    r.close()
    CASES.append('multiple complete TLS records in one AA frame, arbitrary wire splits')

    r = new()
    expected, wire = [], bytearray()
    for i in range(80):
        data = bytes([i]) * (i * 29 + 1)
        channel = i % 8
        flags = 12 if i % 2 else 8
        wire.extend(frame(channel, flags | 3, encrypt(r.pair, data)))
        expected.append((channel, flags, 1, data))
    r.pump(bytes(wire), chunks=(31, 7001, 4096, 17))
    assert r.views == expected
    r.close()
    CASES.append('80 sequential messages across eight channels retain order through repeated queue saturation')

    r = new()
    bad(r, frame(0, 7, b'plaintext'), -200008)
    CASES.append('plaintext disabled by default before message publication')
    r = new(allow_plaintext=1)
    r.pump(frame(0, 7, b'\x00\x01plain-control') + frame(0, 15, encrypt(r.pair, b'encrypted-next')))
    assert r.views == [(0, 4, 1, b'\x00\x01plain-control'), (0, 12, 1, b'encrypted-next')]
    r.close()
    CASES.append('explicit plaintext opt-in is retained as unauthenticated provenance separately from encrypted messages')

    r = new()
    cipher = encrypt(r.pair, b'hello')
    bad(r, frame(0, 9, cipher, len(cipher)) + frame(0, 10, b''), -200006)
    CASES.append('ciphertext-length substituted for FIRST plaintext total fails exact LAST validation')
    r = new()
    bad(r, frame(1, 9, encrypt(r.pair, b'first'), 10) +
        frame(2, 10, encrypt(r.pair, b'last!')), -200006)
    CASES.append('fragment channel change rejected without partial message publication')
    r = new(allow_plaintext=1)
    bad(r, frame(1, 9, encrypt(r.pair, b'first'), 10) + frame(1, 2, b'last!'), -200006)
    CASES.append('fragment encryption provenance change rejected')
    r = new()
    bad(r, frame(1, 13, encrypt(r.pair, b'first'), 10) +
        frame(1, 10, encrypt(r.pair, b'last!')), -200006)
    CASES.append('fragment control flag change rejected')

    r = new(capacity=32)
    bad(r, frame(1, 9, encrypt(r.pair, b'first'), 33), -200006)
    CASES.append('declared message capacity limit rejects publication and wipes partial plaintext')
    r = new()
    cipher = bytearray(encrypt(r.pair, b'authenticated-body'))
    cipher[-1] ^= 1
    bad(r, frame(1, 11, bytes(cipher)), -200005)
    CASES.append('real TLS ciphertext authentication failure is terminal and publishes no message')
    r = new()
    first, second = b'valid-prefix', b'tampered-tail'
    tail = bytearray(encrypt(r.pair, first))
    tail2 = bytearray(encrypt(r.pair, second))
    tail2[-1] ^= 1
    bad(r, frame(1, 11, bytes(tail + tail2)), -200005)
    CASES.append('later corrupt TLS record in a frame cannot publish its earlier valid plaintext prefix')
    r = new()
    head = encrypt(r.pair, b'valid-fragment')
    tail = bytearray(encrypt(r.pair, b'corrupt-fragment'))
    tail[-1] ^= 1
    bad(r, frame(1, 9, head, 30) + frame(1, 10, bytes(tail)), -200005)
    CASES.append('later corrupt message fragment clears already assembled prefix without publishing it')

    r = new()
    cipher = encrypt(r.pair, b'record-boundaries')
    bad(r, frame(1, 9, cipher[:8], 17), -200007)
    CASES.append('old-model policy rejects TLS record split across AA frames before feeding TLS')
    r = new()
    cipher = encrypt(r.pair, b'record-tail')
    bad(r, frame(1, 11, cipher[:-1]), -200007)
    CASES.append('truncated TLS record rejected before decryption')
    r = new(allow_plaintext=1)
    bad(r, frame(1, 0, b'no-first'), -200006)
    CASES.append('orphan MIDDLE cannot start a message')
    r = new(max_fragments=1)
    bad(r, frame(1, 9, encrypt(r.pair, b'first'), 5) + frame(1, 10, b''), -200006)
    CASES.append('bounded fragment count prevents unbounded empty continuation sequences')

    r = new(callback_error=-88)
    bad(r, frame(1, 11, encrypt(r.pair, b'callback-rejected')), -200006)
    CASES.append('negative complete-message callback fails terminally and clears owned buffers')
    r = new(reenter=True)
    r.pump(frame(1, 11, encrypt(r.pair, b'no-reentry')))
    assert r.reentry == [(-200010, 0, -200010)]
    assert len(r.views) == 1 and r.call('status') == 0
    r.close()
    CASES.append('callback cannot reenter receiver feed/worker and rejected reentry leaves stream valid')

    r = new()
    consumed = C.c_size_t(123)
    assert lib.aa_receiver_feed(r.context, r.pair.sid + 1, None, 0, C.byref(consumed)) == -200002
    assert consumed.value == 0 and r.call('queued') == 0 and r.call('status') == 0
    r.close()
    CASES.append('stale session rejected without mutating current receiver')
    r = new()
    assert r.feed(b'\x01\x09\x00') == (0, 3)
    assert r.call('finish') == -200004 and r.call('error_detail') == -5
    r.close()
    CASES.append('EOF inside wire header reports truncated transport')
    r = new()
    wire = frame(1, 9, encrypt(r.pair, b'first'), 9)
    assert r.feed(wire) == (0, len(wire)) and r.step_all() == 0
    assert r.call('finish') == -200006 and r.call('error_detail') == -10
    r.close()
    CASES.append('EOF inside assembled message reports truncated message')
    r = new()
    wire = frame(1, 11, encrypt(r.pair, b'stop-before-decode')) + b'\x01\x09'
    assert r.feed(wire) == (0, len(wire)) and r.call('queued') == 1
    assert r.call('finish') == 1
    r.close()
    assert not r.views and r.feed(b'new')[0] == -200003
    CASES.append('serialized stop discards queued and partial transport data, zeroes storage and rejects restart')

    assert tls.aa_tls_heap_verify() == 0 and tls.aa_tls_heap_used() == 0
    CASES.append('all real TLS peers/adapter contexts released; shared bounded allocator verifies with zero live bytes')
    return {'TLS_ciphers': sorted(ciphers), 'receiver_context_bytes': lib.aa_receiver_context_bytes(),
            'message_capacity_tested': 262144, 'TLS_heap_peak_bytes': tls.aa_tls_heap_max(),
            'TLS_heap_final_bytes': tls.aa_tls_heap_used()}


def main():
    started = time.time()
    prior, tlslib = read_prerequisites()
    library, compile_receipt = build(tlslib)
    spec = importlib.util.spec_from_file_location('aa_tls_host_fixture_helper', ROOT / 'scripts/test_aa_tls_host.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.OUT = OUT
    fixtures = helper.certificates()
    tls = C.CDLL(str(tlslib))
    helper.bind(tls)
    lib = C.CDLL(str(library))
    bind(lib)
    metrics = tests(lib, tls, helper, fixtures)
    sources = [ROOT / 'native/aa-receiver' / x for x in ['receiver.c', 'receiver.h']]
    for key in ['tls', 'wire', 'message']:
        items = prior[key].get('source_sha256', prior[key].get('source_files', {}))
        sources.extend(ROOT / p for p in items)
    sources += [Path(__file__).resolve()]
    proof = {'schema': 'android-auto-pipeline-host-v1', 'pass': True,
             'completed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'case_count': len(CASES), 'cases': CASES, 'metrics': metrics,
             'scope': 'Real local OpenSSL TLS1.2 peer -> our compiled C wire parser -> owned bounded frame queue -> Mbed TLS adapter -> plaintext assembler -> complete-message callback, Linux host only',
             'device_IO': False, 'native_guest_executed': False, 'Garmin_code_executed': False,
             'phone_session_verified': False, 'Android_Auto_receiver_running_on_Garmin': False,
             'Google_Maps_running_on_Garmin': False, 'install_candidate': False,
             'wire_TLS_plaintext_assembly_integrated': True,
             'post_handshake_only': True, 'production_record_authentication_tested': True,
             'callback_pause_does_not_refeed_ciphertext_verified': True,
             'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
             'prerequisites': {k: {'path': str(p.relative_to(ROOT)), 'sha256': sha(p)}
                              for k, p in PREREQ.items()},
             'compiled_library_sha256': sha(library), 'TLS_library_sha256': sha(tlslib),
             'compile_receipt': compile_receipt, 'host_arch': platform.machine(),
             'host_elapsed_seconds': round(time.time() - started, 3),
             'limitations': ['Old pinned-model whole TLS application records per AA frame; current Pixel unverified',
                'Stricter no-intertwined-fragments policy than old aasdk; header metadata not TLS-authenticated',
                'Post-handshake only; no AA version, SSL_HANDSHAKE envelope, AUTH_COMPLETE or protobuf dispatch',
                'No media ACK, USB host/VBUS/AOA backend, worker/IRQ/native ABI or hardware entropy provider',
                'No Garmin H264/display/touch/audio/UI, realtime performance, phone or installation validation',
                'Stop is serialized buffer discard, not asynchronous cancellation or hardware mute',
                'No pipeline ASan claim; component assembler/framer tests independently use ASan/UBSan']}
    PROOF.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'pass': True, 'case_count': len(CASES), 'proof': str(PROOF.relative_to(ROOT)),
                      'device_IO': False, 'native_guest_executed': False, **metrics}))


if __name__ == '__main__':
    main()
