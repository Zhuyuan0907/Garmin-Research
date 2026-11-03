#!/usr/bin/env python3
"""Legacy AA bootstrap envelopes with a real local TLS1.2 memory-BIO peer.

Our Linux C only: no phone, USB, Garmin guest/instructions or installation.
The peer is an independently written legacy-envelope fixture, not Android Auto.
One explicitly labelled API-output injection checks final-flight ordering.
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
OUT = ROOT / 'staging/android-auto-startup-host-v1'
PROOF = ROOT / 'evidence/android-auto-startup-host-v1.json'
PIPELINE = ROOT / 'evidence/android-auto-pipeline-host-v1.json'
REVIEW = ROOT / 'evidence/android-auto-startup-source-review-v1.json'
TLSLIB = ROOT / 'staging/android-auto-tls-host-v1/libaa-tls-host-test.so'
RXLIB = ROOT / 'staging/android-auto-pipeline-host-v1/libaa-receiver-host.so'
CASES = []
FAKE_FLIGHT = bytes.fromhex('1603030002a55a')
VERSION_REQUEST = bytes.fromhex('00030006000100010001')
VERSION_RESPONSE = bytes.fromhex('000300080002000100010000')
AUTH = bytes.fromhex('0003000400040800')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prerequisites():
    pipeline = json.loads(PIPELINE.read_text())
    assert pipeline['pass'] and not pipeline['device_IO'] and not pipeline['native_guest_executed']
    assert sha(TLSLIB) == pipeline['TLS_library_sha256']
    assert sha(RXLIB) == pipeline['compiled_library_sha256']
    for name, pin in pipeline['source_sha256'].items():
        assert sha(ROOT / name) == pin, name
    review = json.loads(REVIEW.read_text())
    assert review['success'] and review['scope']['runtime_protocol_tests'] == 0
    for name, v in review['selected_source_files'].items():
        assert sha(ROOT / name) == v['sha256'], name
    for item in review['source_snapshots']:
        assert sha(ROOT / item['archive']) == item['sha256']
    return pipeline, review


def build():
    OUT.mkdir(exist_ok=True)
    shim = OUT / 'test-final-output.c'
    shim.write_text(r'''/* Host-only API output control, not a real TLS flight. */
#include "tls.h"
#include <string.h>
static int armed;
static size_t offset=7;
static const unsigned char synthetic[7]={22,3,3,0,2,0xa5,0x5a};
int __real_aa_tls_handshake(void *,uint32_t,uint32_t);
int __real_aa_tls_take_out(void *,uint32_t,void *,uint32_t);
int __wrap_aa_tls_handshake(void *p,uint32_t s,uint32_t n){
    int r=__real_aa_tls_handshake(p,s,n);
    if(r==1 && armed){armed=0;offset=0;}return r;
}
int __wrap_aa_tls_take_out(void *p,uint32_t s,void *out,uint32_t cap){
    int r=__real_aa_tls_take_out(p,s,out,cap);
    size_t n;
    if(r || offset==sizeof(synthetic))return r;
    n=sizeof(synthetic)-offset;if(n>cap)n=cap;
    memcpy(out,synthetic+offset,n);offset+=n;return (int)n;
}
void aa_test_inject_final_output(int n){armed=n;offset=sizeof(synthetic);}
''')
    sources = [ROOT / ('native/' + p) for p in
               ['aa-bootstrap/bootstrap.c', 'aa-wire/wire.c', 'aa-message/message.c']]
    argv = ['cc', '-shared', '-fPIC', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror']
    argv += ['-I' + str(ROOT / 'native' / p) for p in ['aa-bootstrap', 'aa-wire', 'aa-message', 'aa-tls']]
    argv += list(map(str, sources)) + [str(shim), str(TLSLIB),
             '-Wl,--wrap=aa_tls_handshake', '-Wl,--wrap=aa_tls_take_out',
             '-o', str(OUT / 'libaa-bootstrap-host.so')]
    result = subprocess.run(argv, capture_output=True, cwd=ROOT)
    assert result.returncode == 0, result.stderr.decode()
    return OUT / 'libaa-bootstrap-host.so', shim, {'argv': argv, 'exit_code': 0, 'stderr': result.stderr.decode()}


def bind(lib):
    lib.aa_bootstrap_context_bytes.restype = C.c_uint32
    lib.aa_bootstrap_context_bytes.argtypes = []
    lib.aa_bootstrap_init.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32, C.c_uint16,
        C.c_uint16, C.c_uint32, C.c_uint32, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    lib.aa_bootstrap_feed.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    lib.aa_bootstrap_step.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32]
    lib.aa_bootstrap_tx_peek.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p), C.POINTER(C.c_size_t)]
    lib.aa_bootstrap_tx_commit.argtypes = [C.c_void_p, C.c_uint32, C.c_size_t, C.c_int]
    for name in ['status', 'error_detail', 'finish', 'stop']:
        getattr(lib, 'aa_bootstrap_' + name).argtypes = [C.c_void_p, C.c_uint32]
    lib.aa_test_inject_final_output.argtypes = [C.c_int]


class Bootstrap:
    def __init__(self, lib, pair, major=1, minor=1, now=0, timeout=60000):
        self.lib, self.pair = lib, pair
        self.context = C.create_string_buffer(lib.aa_bootstrap_context_bytes())
        self.wire, self.message = C.create_string_buffer(32768), C.create_string_buffer(32770)
        self.initial = lib.aa_bootstrap_init(self.context, pair.storage, pair.sid, major, minor,
                                             now, timeout, self.wire, len(self.wire), self.message, len(self.message))

    def call(self, name, *args):
        return getattr(self.lib, 'aa_bootstrap_' + name)(self.context, self.pair.sid, *args)

    def peek(self):
        pointer, n = C.c_void_p(), C.c_size_t()
        result = self.call('tx_peek', C.byref(pointer), C.byref(n))
        return result, pointer.value, C.string_at(pointer, n.value) if n.value else b''

    def feed(self, data):
        used = C.c_size_t(123)
        result = self.call('feed', data, len(data), C.byref(used))
        return result, used.value

    def output(self, chunks=(1, 3, 127)):
        result = bytearray()
        turn = 0
        while True:
            status, pointer, pending = self.peek()
            assert status == 0
            if not pending:
                return bytes(result)
            status2, pointer2, pending2 = self.peek()
            assert (status2, pointer2, pending2) == (status, pointer, pending)
            assert self.call('step', 1) == 2
            assert self.call('tx_commit', 0, 0) == 2
            assert self.peek()[1:] == (pointer, pending)
            n = min(chunks[turn % len(chunks)], len(pending))
            result.extend(pending[:n])
            committed = self.call('tx_commit', n, 0)
            assert committed in (0, 2, 3)
            if n < len(pending):
                assert committed == 2
            if pending[:2] == b'\x00\x03' and len(pending) == len(AUTH):
                assert self.call('status') == 4 if n < len(pending) else self.call('status') == 5
            turn += 1

    def stop(self):
        assert self.call('stop') == 0
        assert not any(self.wire.raw) and not any(self.message.raw)


def payload(frame):
    assert len(frame) >= 6 and frame[0] == 0 and frame[1] == 3
    assert struct.unpack('>H', frame[2:4])[0] == len(frame) - 4
    return struct.unpack('>H', frame[4:6])[0], frame[6:]


def proto_auth(body):
    # Independent protobuf runtime checks required field presence, not just bytes.
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    fd = descriptor_pb2.FileDescriptorProto(name='host_auth_fixture.proto', package='host', syntax='proto2')
    enum = fd.enum_type.add(name='Status')
    enum.value.add(name='OK', number=0)
    enum.value.add(name='FAIL', number=1)
    message = fd.message_type.add(name='Auth')
    message.field.add(name='status', number=1, type=14, label=2, type_name='.host.Status')
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fd)
    descriptor = pool.FindMessageTypeByName('host.Auth')
    cls = (message_factory.GetMessageClass(descriptor)
           if hasattr(message_factory, 'GetMessageClass')
           else message_factory.MessageFactory(pool).GetPrototype(descriptor))
    value = cls()
    value.ParseFromString(body)
    assert value.IsInitialized() and value.status == 0 and value.HasField('status')
    assert not cls().IsInitialized()


def tests(lib, tls, rxlib, tls_helper, rx_helper, fixtures):
    heap = C.create_string_buffer(2 * 1024 * 1024)
    assert tls.aa_tls_runtime_init(heap, len(heap), int(time.time())) == 0
    def new(**kwargs):
        pair = tls_helper.Pair(tls, fixtures, **kwargs.pop('tls_options', {}))
        assert pair.initial == 0
        lib.aa_test_inject_final_output(0)
        boot = Bootstrap(lib, pair, **kwargs)
        assert boot.initial == 0, boot.initial
        return boot, pair
    def run(raw_chunks=None, transport_chunks=(17, 4096, 1), fragmented=False,
            tail_mode=0, inject_output=False, tls_options=None):
        boot, pair = new(tls_options=tls_options or {})
        if inject_output:
            lib.aa_test_inject_final_output(1)
        pending = bytearray()
        events, frame_count, peer_ready, tail_wire = [], 0, False, b''
        tail_data = b'\x00\x05post-handshake-opaque-message' + bytes(range(256))
        for turn in range(20000):
            if boot.peek()[2]:
                output = boot.output()
                mid, body = payload(output)
                events.append((mid, body))
                frame_count += 1
                if mid == 1:
                    assert output == VERSION_REQUEST
                    pending.extend(VERSION_RESPONSE)
                elif mid == 3:
                    if inject_output and body == FAKE_FLIGHT:
                        assert peer_ready
                        # Explicit API-output ordering control, not fed to SSL.
                    else:
                        pair.inbio.write(body)
                        try:
                            pair.peer.do_handshake()
                            peer_ready = True
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            pass
                        except ssl.SSLError:
                            # Certificate-failure scenarios finish in the client.
                            pass
                        server = pair.outbio.read()
                        if server:
                            if fragmented:
                                message = b'\x00\x03' + server
                                pieces = [message[:2], message[2:7], message[7:]]
                                pending.extend(rx_helper.frame(0, 1, pieces[0], len(message)))
                                pending.extend(rx_helper.frame(0, 0, pieces[1]))
                                pending.extend(rx_helper.frame(0, 2, pieces[2]))
                            elif raw_chunks:
                                offset = 0
                                while offset < len(server):
                                    n = min(raw_chunks[offset % len(raw_chunks)], len(server) - offset)
                                    pending.extend(rx_helper.frame(0, 3, b'\x00\x03' + server[offset:offset+n]))
                                    offset += n
                            else:
                                pending.extend(rx_helper.frame(0, 3, b'\x00\x03' + server))
                        if peer_ready and tail_mode and not tail_wire:
                            assert pair.peer.write(tail_data) == len(tail_data)
                            tail_wire = rx_helper.frame(5, 11, pair.outbio.read())
                            pending.extend(tail_wire if tail_mode == 1 else tail_wire[:3])
                elif mid == 4:
                    assert output == AUTH and peer_ready
                    proto_auth(body)
                    assert boot.call('status') == 5
                    break
                else:
                    raise AssertionError(('unexpected ID', mid))
            if pending:
                n = min(transport_chunks[turn % len(transport_chunks)], len(pending))
                result, used = boot.feed(bytes(pending[:n]))
                assert result in (0, 2, 3), (result, boot.call('error_detail'))
                assert used <= n
                del pending[:used]
            r = boot.call('step', 1)
            if r < 0:
                return boot, pair, r, events, bytes(pending), tail_wire, tail_data
        else:
            raise AssertionError('bootstrap did not converge')
        assert events[0][0] == 1 and events[-1][0] == 4
        assert all(mid == 3 for mid, _ in events[1:-1])
        assert boot.call('step', 1) == 3 and tls.aa_tls_status(pair.storage, pair.sid) == 1
        assert tls.aa_tls_verify_flags(pair.storage, pair.sid) == 0
        assert pair.peer.getpeercert()['subject']
        return boot, pair, 3, events, bytes(pending), tail_wire, tail_data

    boot, pair = new()
    assert boot.peek()[2] == VERSION_REQUEST
    view = boot.peek()
    assert boot.call('tx_commit', len(view[2]) + 1, 0) == -300001 and boot.peek() == view
    assert boot.feed(VERSION_RESPONSE) == (2, 0)
    boot.stop();pair.free()
    CASES.append('literal legacy version request, stable peek, no-progress commit, oversize commit and RX gating')

    for label, options in [
        ('normal cold legacy startup and successful transport-completion gate', {}),
        ('every transport byte delivered separately during real TLS handshake', {'transport_chunks': (1,)}),
        ('TLS record headers/bodies split across multiple SSL_HANDSHAKE messages', {'raw_chunks': (1, 3, 11, 23)}),
        ('AA FIRST/MIDDLE/LAST envelope assembly before feeding real TLS', {'fragmented': True})]:
        boot, pair, result, events, tail, _, _ = run(**options)
        assert result == 3 and not tail
        assert all(body for mid, body in events if mid == 3)
        boot.stop();pair.free()
        CASES.append(label)

    boot, pair, result, events, tail, _, _ = run(inject_output=True)
    assert result == 3 and not tail
    assert events[-2] == (3, FAKE_FLIGHT) and events[-1] == (4, b'\x08\x00')
    boot.stop();pair.free()
    CASES.append('explicit API-output injection: drain pending output after real TLS success before AUTH')

    for mode, label in [(1, 'full encrypted frame'), (2, 'partial encrypted header')]:
        boot, pair, result, _, pending, wire, body = run(tail_mode=mode, transport_chunks=(65535,))
        assert result == 3 and pending == (wire if mode == 1 else wire[:3])
        assert boot.feed(pending) == (3, 0)
        # Stop bootstrap before the new owner drives the same active TLS session.
        boot.stop()
        receiver = rx_helper.Receiver(rxlib, pair)
        receiver.pump(pending)
        if mode == 2:
            assert not receiver.views
            receiver.pump(wire[3:])
        assert receiver.views == [(5, 8, 1, body)]
        receiver.close()
        CASES.append('same transport chunk handoff preserves ' + label + ' and SAME TLS context')

    boot, pair, result, _, _, _, _ = run()
    assert result == 3
    data = b'\x00\x06opaque-reply-not-a-discovery-negotiation'
    assert tls.aa_tls_write(pair.storage, pair.sid, data, len(data)) == len(data)
    encrypted = C.create_string_buffer(32768)
    n = tls.aa_tls_take_out(pair.storage, pair.sid, encrypted, len(encrypted))
    assert n > 0
    pair.inbio.write(encrypted.raw[:n])
    assert pair.peer.read(16384) == data
    boot.stop();pair.free()
    CASES.append('same verified TLS context encrypts outbound opaque reply after bootstrap, real peer decrypts it')

    for label, msg in [
        ('mismatched response major', bytes.fromhex('000300080002000200010000')),
        ('mismatched response minor', bytes.fromhex('000300080002000100020000')),
        ('explicit version mismatch status', bytes.fromhex('00030008000200010001ffff')),
        ('unknown nonzero version status', bytes.fromhex('000300080002000100010123'))]:
        boot, pair = new()
        boot.output()
        assert boot.feed(msg) == (2, len(msg))
        assert boot.call('step', 1) == -300007
        assert boot.call('status') == -300007 and boot.peek()[0] == -300007
        boot.stop();pair.free()
        CASES.append(label + ' rejected before TLS begins')

    for label, msg in [
        ('short version response', bytes.fromhex('00030006000200010001')),
        ('extra version response byte', VERSION_RESPONSE[:2] + b'\x00\x09' + VERSION_RESPONSE[4:] + b'X'),
        ('CONTROL instead of SPECIFIC flag', VERSION_RESPONSE[:1] + b'\x07' + VERSION_RESPONSE[2:]),
        ('wrong outer channel', b'\x01' + VERSION_RESPONSE[1:]),
        ('AUTH arrives before version/TLS', AUTH)]:
        boot, pair = new();boot.output()
        assert boot.feed(msg) == (2, len(msg))
        assert boot.call('step', 1) == -300006
        boot.stop();pair.free()
        CASES.append(label + ' rejected')

    for label, tls_options in [('wrong trusted server hostname', {'hostname': 'wrong.test'}),
                               ('untrusted server CA', {'ca': 'other-ca.pem'})]:
        boot, pair, result, events, _, _, _ = run(tls_options=tls_options)
        assert result == -300008 and all(mid != 4 for mid, _ in events)
        boot.stop();pair.free()
        CASES.append('real TLS verification rejects ' + label + ' without AUTH')

    boot, pair = new();boot.output()
    assert boot.call('step', 60000) == -300010
    assert boot.call('step', 1) == -300010
    boot.stop();pair.free()
    boot, pair = new(now=0xFFFFFFF0, timeout=32);boot.output()
    assert boot.call('step', 0xFFFFFFFF) == 2
    assert boot.call('step', 16) == -300010
    boot.stop();pair.free()
    CASES.append('whole bootstrap deadline and uint32 wrap, sticky timeout')

    boot, pair = new()
    assert boot.call('tx_commit', 0, -5) == -300009 and boot.call('error_detail') == -5
    assert boot.feed(b'') == (-300009, 0)
    boot.stop();pair.free()
    CASES.append('failed transport completion is terminal and never makes AUTH_READY')

    for label, raw in [('hidden application-data TLS record', bytes.fromhex('170303000141')),
                       ('zero-length handshake TLS record', bytes.fromhex('1603030000')),
                       ('oversize TLS record header', bytes.fromhex('160303ffff'))]:
        boot, pair = new();boot.output()
        assert boot.feed(VERSION_RESPONSE) == (2, len(VERSION_RESPONSE))
        assert boot.call('step', 1) == 1
        boot.output()
        msg = rx_helper.frame(0, 3, b'\x00\x03' + raw)
        assert boot.feed(msg) == (2, len(msg))
        assert boot.call('step', 1) == -300011
        boot.stop();pair.free()
        CASES.append(label + ' rejected before handing data to TLS')

    boot, pair = new();boot.output()
    used = C.c_size_t(123)
    assert lib.aa_bootstrap_feed(boot.context, pair.sid + 1, None, 0, C.byref(used)) == -300002
    assert used.value == 0 and boot.call('status') == 2
    boot.stop();pair.free()
    CASES.append('stale session rejected without consuming current transport')
    boot, pair = new();boot.output()
    assert boot.feed(b'\x00\x03\x00') == (0, 3)
    assert boot.call('finish') == -300012
    boot.stop();pair.free()
    CASES.append('transport EOF before authenticated completion is terminal truncation')
    boot, pair = new();boot.output()
    assert boot.feed(VERSION_RESPONSE[:5]) == (0, 5)
    boot.stop()
    assert boot.feed(VERSION_RESPONSE[5:]) == (-300003, 0)
    assert boot.peek()[0] == -300003
    pair.free()
    CASES.append('serialized stop clears partial transport/TX storage and rejects later input')

    assert tls.aa_tls_heap_verify() == 0 and tls.aa_tls_heap_used() == 0
    CASES.append('all cold/active/error TLS contexts freed and shared allocator integrity verified')
    return {'bootstrap_context_bytes': lib.aa_bootstrap_context_bytes(),
            'TLS_heap_peak_bytes': tls.aa_tls_heap_max(), 'TLS_heap_final_bytes': 0}


def main():
    started = time.time()
    pipeline, review = prerequisites()
    library, shim, compile_receipt = build()
    tls_helper = load_module('startup_tls_fixtures', ROOT / 'scripts/test_aa_tls_host.py')
    rx_helper = load_module('startup_receiver_fixtures', ROOT / 'scripts/test_aa_receiver_host.py')
    tls_helper.OUT = OUT
    fixtures = tls_helper.certificates()
    tls = C.CDLL(str(TLSLIB));tls_helper.bind(tls)
    rx = C.CDLL(str(RXLIB));rx_helper.bind(rx)
    lib = C.CDLL(str(library));bind(lib)
    metrics = tests(lib, tls, rx, tls_helper, rx_helper, fixtures)
    files = [ROOT / 'native/aa-bootstrap' / name for name in ['bootstrap.c', 'bootstrap.h']]
    files += [ROOT / p for p in pipeline['source_sha256']]
    files += [Path(__file__).resolve(), shim]
    proof = {'schema': 'android-auto-startup-host-v1', 'pass': True,
        'completed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'scope': 'our compiled Linux bootstrap: legacy AA version/SSL_HANDSHAKE/AUTH envelopes with real local OpenSSL mutual TLS1.2 and same-session handoff to the verified C receiver; one separately labelled synthetic pending-output API control',
        'case_count': len(CASES), 'cases': CASES, 'metrics': metrics,
        'device_IO': False, 'native_guest_executed': False, 'Garmin_code_executed': False,
        'current_Pixel_interoperability_verified': False, 'Google_acceptance_verified': False,
        'Garmin_Android_Auto_or_Google_Maps_running': False, 'install_candidate': False,
        'real_cold_TLS_handshake_enveloped': True, 'required_proto2_AUTH_status_verified': True,
        'AUTH_successful_transport_commit_gate_verified': True,
        'same_transport_chunk_tail_and_TLS_session_handoff_verified': True,
        'local_TLS_fixture_peer_is_Android_Auto': False,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'prerequisite': {'pipeline': {'path': str(PIPELINE.relative_to(ROOT)), 'sha256': sha(PIPELINE)}},
        'public_source_review': {'path': str(REVIEW.relative_to(ROOT)), 'sha256': sha(REVIEW),
                                'static_sources': len(review['selected_source_files']), 'runtime_tests': 0},
        'compile_receipt': compile_receipt, 'compiled_library_sha256': sha(library),
        'host_arch': platform.machine(), 'host_elapsed_seconds': round(time.time() - started, 3),
        'limitations': ['Legacy configurable exact version match, defaults1.1; no current Pixel or Google protocol validation',
            'No general protobuf dispatcher, ping, service discovery, channel open or media negotiation',
            'No actual transport; tx_commit correctness relies on serialized caller reporting successful completion',
            'Final-pending-output control is synthetic API output after real TLS success, not a real final TLS flight',
            'Bytewise startup feed and native ABI/performance unmeasured; no bootstrap ASan claim',
            'No USB host/VBUS/AOA, Garmin hardware entropy/time, decoder/display/touch/audio/UI or installation',
            'No async cancellation/IRQ/task quiescence; stop retains caller-owned TLS and cannot prove hardware mute']}
    PROOF.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'pass': True, 'case_count': len(CASES), 'proof': str(PROOF.relative_to(ROOT)),
                      'device_IO': False, 'native_guest_executed': False, **metrics}))


if __name__ == '__main__':
    main()
