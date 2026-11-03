#!/usr/bin/env python3
"""Build and test our TLS adapter on Linux; no Garmin/phone or native guest I/O.

Real peer: Python ssl (OpenSSL), memory BIOs, locally generated mutual-TLS
fixtures. Separate injected ssl_write returns exercise the actual adapter's
partial-positive / WANT / zero contract, not real-peer cryptography.
"""
import concurrent.futures
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/android-auto-tls-host-v1'
UPSTREAM = ROOT / 'sources/native-tls/mbedtls-3.6.7'
PROOF = ROOT / 'evidence/android-auto-tls-host-v1.json'
WANT_READ, WANT_WRITE = -0x6900, -0x6880
BAD_ARGUMENT, BAD_SESSION, BUSY = -100001, -100002, -100003
TIMED_OUT, BAD_STATE, CAPACITY = -100004, -100005, -100006
CASES = []


def checked(argv):
    p = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True)
    if p.returncode:
        raise RuntimeError(f'{argv[0]} failed ({p.returncode}): ' +
                           p.stderr.decode(errors='replace')[-4000:])
    return p


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    obj = OUT / 'objects'
    obj.mkdir(exist_ok=True)
    shim = OUT / 'host-test-shim.c'
    shim.write_text(r'''/* Test-only controls; includes exact production source. */
#include "tls.c"
static int inject, injected_result;
static unsigned char last[16384];
static size_t last_n;
static uintptr_t last_pointer;
int __real_mbedtls_ssl_write(mbedtls_ssl_context *, const unsigned char *, size_t);
int __wrap_mbedtls_ssl_write(mbedtls_ssl_context *s,const unsigned char *b,size_t n){
    if(!inject)return __real_mbedtls_ssl_write(s,b,n);
    inject=0;last_n=n;last_pointer=(uintptr_t)b;
    if(n<=sizeof(last))memcpy(last,b,n);
    return injected_result;
}
void aa_test_next_write(int n){inject=1;injected_result=n;}
size_t aa_test_last_write(void *p){memcpy(p,last,last_n);return last_n;}
uintptr_t aa_test_last_pointer(void){return last_pointer;}
int aa_test_reseed(void *p){struct context *c=p;return mbedtls_ctr_drbg_reseed(&c->rng,NULL,0);}
int aa_test_want_read(void){return MBEDTLS_ERR_SSL_WANT_READ;}
int aa_test_want_write(void){return MBEDTLS_ERR_SSL_WANT_WRITE;}
''')
    common = ['cc', '-std=c11', '-O1', '-fPIC', '-DAA_TLS_HOST',
              '-DMBEDTLS_CONFIG_FILE="' + str(ROOT / 'native/aa-tls/config.h') + '"',
              '-I' + str(UPSTREAM / 'include'), '-I' + str(UPSTREAM / 'library'),
              '-I' + str(ROOT / 'native/aa-tls')]
    source = list(sorted((UPSTREAM / 'library').glob('*.c')))
    source += [ROOT / 'native/aa-tls/port.c', shim]
    def compile_one(p):
        o = obj / (p.stem + '.o')
        checked(common + ['-c', p, '-o', o])
        return o
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        objects = list(pool.map(compile_one, source))
    lib = OUT / 'libaa-tls-host-test.so'
    checked(['cc', '-shared', '-Wl,-Bsymbolic', '-Wl,--wrap=mbedtls_ssl_write',
             *objects, '-o', lib])
    return lib, source


def certificates():
    d = OUT / 'private-fixtures'
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    for rootname in ['ca', 'other-ca']:
        checked(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', d / (rootname + '.key'), '-out', d / (rootname + '.pem'),
                 '-days', '2', '-subj', '/CN=AA Host Test ' + rootname])
    for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        checked(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', d / (name + '.key'), '-out', d / (name + '.csr'),
                 '-subj', '/CN=aa-host.test'])
        ext = d / (name + '.ext')
        ext.write_text('subjectAltName=DNS:aa-host.test\nextendedKeyUsage=' + usage +
                       '\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n')
        checked(['openssl', 'x509', '-req', '-in', d / (name + '.csr'),
                 '-CA', d / 'ca.pem', '-CAkey', d / 'ca.key', '-CAcreateserial',
                 '-out', d / (name + '.pem'), '-days', '1', '-extfile', ext])
    for p in d.glob('*.key'):
        os.chmod(p, 0o600)
    return d


ENTROPY = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)


class Params(C.Structure):
    _fields_ = [('session', C.c_uint32), ('hostname', C.c_void_p),
                ('hostname_bytes', C.c_uint32), ('ca', C.c_void_p),
                ('ca_bytes', C.c_uint32), ('cert', C.c_void_p),
                ('cert_bytes', C.c_uint32), ('key', C.c_void_p),
                ('key_bytes', C.c_uint32), ('entropy', ENTROPY),
                ('entropy_context', C.c_void_p), ('now_ms', C.c_uint32),
                ('timeout_ms', C.c_uint32)]


def bind(lib):
    for name in ['context_bytes', 'params_bytes', 'heap_used', 'heap_max']:
        f = getattr(lib, 'aa_tls_' + name)
        f.restype = C.c_uint32
        f.argtypes = []
    specs = {
        'runtime_init': [C.c_void_p, C.c_uint32, C.c_uint32],
        'runtime_set_time': [C.c_uint32], 'init': [C.c_void_p, C.POINTER(Params)],
        'feed': [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32],
        'take_out': [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32],
        'handshake': [C.c_void_p, C.c_uint32, C.c_uint32],
        'write': [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32],
        'read': [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32],
        'retry_write': [C.c_void_p, C.c_uint32],
        'pending_bytes': [C.c_void_p, C.c_uint32], 'close': [C.c_void_p, C.c_uint32],
        'status': [C.c_void_p, C.c_uint32], 'free': [C.c_void_p, C.c_uint32],
        'verify_flags': [C.c_void_p, C.c_uint32], 'heap_verify': []}
    for name, args in specs.items():
        f = getattr(lib, 'aa_tls_' + name)
        f.argtypes, f.restype = args, C.c_int
    lib.aa_test_next_write.argtypes = [C.c_int]
    lib.aa_test_last_write.argtypes = [C.c_void_p]
    lib.aa_test_last_write.restype = C.c_size_t
    lib.aa_test_last_pointer.restype = C.c_size_t
    lib.aa_test_reseed.argtypes = [C.c_void_p]


class Pair:
    def __init__(self, lib, fixtures, session=41, hostname='aa-host.test',
                 ca='ca.pem', fail_entropy=False, now_ms=0, timeout=60000):
        self.lib, self.sid = lib, session
        self.storage = C.create_string_buffer(lib.aa_tls_context_bytes())
        self.calls = []
        self.fail_entropy = fail_entropy
        def entropy(_, out, n):
            self.calls.append(n)
            if self.fail_entropy:
                return -1
            C.memmove(out, os.urandom(n), n)
            return 0
        self.callback = ENTROPY(entropy)
        self.buffers = [C.create_string_buffer(b) for b in [hostname.encode(),
                        (fixtures / ca).read_bytes(), (fixtures / 'client.pem').read_bytes(),
                        (fixtures / 'client.key').read_bytes()]]
        self.params = Params(session, C.addressof(self.buffers[0]), len(self.buffers[0]),
                             C.addressof(self.buffers[1]), len(self.buffers[1]),
                             C.addressof(self.buffers[2]), len(self.buffers[2]),
                             C.addressof(self.buffers[3]), len(self.buffers[3]),
                             self.callback, None, now_ms, timeout)
        self.initial = lib.aa_tls_init(self.storage, C.byref(self.params))
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sc.minimum_version = sc.maximum_version = ssl.TLSVersion.TLSv1_2
        sc.load_cert_chain(str(fixtures / 'server.pem'), str(fixtures / 'server.key'))
        sc.load_verify_locations(str(fixtures / 'ca.pem'))
        sc.verify_mode = ssl.CERT_REQUIRED
        self.inbio, self.outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.peer = sc.wrap_bio(self.inbio, self.outbio, server_side=True)
        self.peer_ready = False

    def call(self, name, *args):
        return getattr(self.lib, 'aa_tls_' + name)(self.storage, self.sid, *args)

    def drain_client(self, chunk=137):
        buf = C.create_string_buffer(chunk)
        total = 0
        while True:
            n = self.call('take_out', buf, chunk)
            assert n >= 0, n
            if n == 0:
                return total
            self.inbio.write(buf.raw[:n])
            total += n

    def drain_server(self, chunk=101):
        data = self.outbio.read()
        for start in range(0, len(data), chunk):
            b = data[start:start + chunk]
            assert self.call('feed', b, len(b)) == len(b)
        return len(data)

    def handshake(self, chunk=137):
        assert self.initial == 0, self.initial
        for _ in range(200):
            r = self.call('handshake', 1)
            self.drain_client(chunk)
            try:
                self.peer.do_handshake()
                self.peer_ready = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError:
                if r not in (1, WANT_READ, WANT_WRITE):
                    return r
                raise
            self.drain_server(chunk)
            if r == 1 and self.peer_ready:
                assert self.call('verify_flags') == 0
                assert self.peer.getpeercert()['subject']
                return 1
            if r not in (1, WANT_READ, WANT_WRITE):
                return r
        raise AssertionError('handshake failed to converge')

    def free(self):
        assert self.call('free') == 0
        assert not any(self.storage.raw)


def tests(lib, fixtures):
    assert lib.aa_test_want_read() == WANT_READ and lib.aa_test_want_write() == WANT_WRITE
    assert lib.aa_tls_params_bytes() == C.sizeof(Params)
    heap = C.create_string_buffer(2 * 1024 * 1024)
    now = int(time.time())
    assert lib.aa_tls_runtime_init(heap, len(heap), now) == 0
    assert lib.aa_tls_runtime_init(heap, len(heap), now) == BAD_STATE
    CASES.append('host-native-width params ABI and single global allocator initialization')
    p = Pair(lib, fixtures)
    assert p.handshake(chunk=1) == 1
    CASES.append('real TLS1.2 mutual certificate handshake, every transport byte separately fed')
    assert lib.aa_tls_status(p.storage, p.sid + 1) == BAD_SESSION
    assert p.call('write', b'x', 16385) == BAD_ARGUMENT
    assert p.call('feed', b'x', 32769) == CAPACITY
    CASES.append('wrong session, oversize plaintext and RX capacity guards')

    first = bytes(i % 251 for i in range(16384))
    second = bytes((i * 7) % 253 for i in range(16384))
    assert p.call('write', first, len(first)) == len(first)
    secondbuf = C.create_string_buffer(second)
    assert p.call('write', secondbuf, len(second)) == WANT_WRITE
    assert p.call('pending_bytes') == len(second)
    assert p.call('write', b'third', 5) == BUSY
    C.memset(secondbuf, 0xA7, len(second))
    p.drain_client(37)
    assert p.call('retry_write') == len(second)
    assert p.call('pending_bytes') == 0
    p.drain_client(23)
    data = bytearray()
    while True:
        try:
            data.extend(p.peer.read(97))
        except ssl.SSLWantReadError:
            break
    assert data == first + second
    CASES.append('real TX queue saturation, WANT_WRITE retry and owned plaintext unchanged after caller overwrite')

    response = bytes((i * 13) % 255 for i in range(30000))
    for start in range(0, len(response), 16384):
        b = response[start:start + 16384]
        assert p.peer.write(b) == len(b)
    p.drain_server(5)
    out = C.create_string_buffer(91)
    data = bytearray()
    while True:
        n = p.call('read', out, len(out))
        if n == WANT_READ:
            break
        assert n > 0, n
        data.extend(out.raw[:n])
    assert data == response
    CASES.append('real two-record server plaintext, five-byte ciphertext fragments and small plaintext reads')
    previous = len(p.calls)
    assert lib.aa_test_reseed(p.storage) == 0
    assert len(p.calls) > previous
    p.fail_entropy = True
    assert lib.aa_test_reseed(p.storage) < 0
    p.fail_entropy = False
    assert lib.aa_test_reseed(p.storage) == 0
    CASES.append('real DRBG explicit reseed requests fresh caller entropy and rejects provider failure')
    try:
        p.peer.unwrap()
    except ssl.SSLWantReadError:
        pass
    p.drain_server()
    assert p.call('read', out, len(out)) == -0x7880
    assert p.call('status') == 3
    p.free()
    CASES.append('real peer close_notify, terminal state and context zeroization')

    q = Pair(lib, fixtures, session=42)
    assert q.handshake() == 1
    original = C.create_string_buffer(b'abcdefghi')
    lib.aa_test_next_write(4)
    assert q.call('write', original, 9) == 4
    last = C.create_string_buffer(16384)
    assert lib.aa_test_last_write(last) == 9 and last.raw[:9] == b'abcdefghi'
    startptr = lib.aa_test_last_pointer()
    C.memset(original, 0xCC, 9)
    assert q.call('pending_bytes') == 5
    for result, expected_remaining, expected_data, offset in [
            (WANT_WRITE, 5, b'efghi', 4), (3, 2, b'efghi', 4),
            (0, 2, b'hi', 7), (2, 0, b'hi', 7)]:
        lib.aa_test_next_write(result)
        assert q.call('retry_write') == result
        assert lib.aa_test_last_write(last) == len(expected_data)
        assert last.raw[:len(expected_data)] == expected_data
        assert lib.aa_test_last_pointer() == startptr + offset
        assert q.call('pending_bytes') == expected_remaining
    CASES.append('injected API contract: positive partial write, identical WANT retry arguments, zero progress and exact remainder')
    lib.aa_test_next_write(-12345)
    assert q.call('write', b'fatal', 5) == -12345
    assert q.call('status') == -12345 and q.call('pending_bytes') == 0
    q.free()
    CASES.append('injected terminal write failure clears owned pending plaintext')

    for name, options in [('hostname mismatch', {'hostname': 'wrong.test'}),
                          ('untrusted server CA', {'ca': 'other-ca.pem'})]:
        q = Pair(lib, fixtures, **options)
        assert q.handshake() < 0
        assert q.call('verify_flags') != 0
        q.free()
        CASES.append('real required certificate verification rejects ' + name)
    q = Pair(lib, fixtures, fail_entropy=True)
    assert q.initial < 0 and q.calls
    q.free()
    CASES.append('initial caller entropy failure rejects TLS initialization')
    q = Pair(lib, fixtures)
    assert q.initial == 0
    assert q.call('handshake', 60000) == TIMED_OUT
    assert q.call('handshake', 1) == TIMED_OUT
    q.free()
    q = Pair(lib, fixtures, now_ms=0xFFFFFFF0, timeout=32)
    assert q.initial == 0
    assert q.call('handshake', 0xFFFFFFFF) == WANT_READ
    assert q.call('handshake', 16) == TIMED_OUT
    q.free()
    CASES.append('monotonic handshake deadline, terminal timeout and uint32 wrap')
    assert lib.aa_tls_runtime_set_time(now + 1) == 0
    assert lib.aa_tls_runtime_set_time(now) == BAD_ARGUMENT
    assert lib.aa_tls_runtime_set_time(now + 3 * 86400) == 0
    q = Pair(lib, fixtures)
    assert q.handshake() < 0 and q.call('verify_flags') != 0
    q.free()
    CASES.append('refreshed trusted time rejects expired server certificate and clock rollback')
    assert lib.aa_tls_heap_verify() == 0
    assert lib.aa_tls_heap_used() == 0
    CASES.append('all allocated Mbed TLS contexts freed and allocator integrity verified')
    return {'heap_peak_bytes': lib.aa_tls_heap_max(), 'heap_final_bytes': 0,
            'host_params_bytes': C.sizeof(Params), 'host_context_bytes': lib.aa_tls_context_bytes()}


def main():
    start = time.time()
    library, build_sources = build()
    fixtures = certificates()
    lib = C.CDLL(str(library))
    bind(lib)
    metrics = tests(lib, fixtures)
    source = [ROOT / 'native/aa-tls' / p for p in ['tls.c', 'tls.h', 'config.h', 'port.c']]
    source += [Path(__file__).resolve()]
    proof = {
        'schema': 'android-auto-tls-host-v1', 'pass': True,
        'completed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'scope': 'our Linux host adapter with real local TLS1.2 mutual certificate peer and separately identified injected API returns',
        'case_count': len(CASES), 'cases': CASES, 'metrics': metrics,
        'device_IO': False, 'native_guest_executed': False, 'Garmin_code_executed': False,
        'Android_Auto_phone_handshake_verified': False, 'Garmin_entropy_provider_verified': False,
        'Garmin_native_ABI_or_performance_verified': False, 'install_candidate': False,
        'TLS_verify_required': True, 'ciphertext_transport_split_verified': True,
        'caller_entropy_explicit_reseed_verified': True, 'production_partial_write_control_verified': True,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source},
        'upstream': {'version': '3.6.7', 'build_source_count': len(build_sources),
                     'sha256': {str(p.relative_to(ROOT)): sha(p) for p in build_sources}},
        'library_sha256': sha(library), 'host_arch': platform.machine(),
        'python_ssl': ssl.OPENSSL_VERSION, 'host_elapsed_seconds': round(time.time() - start, 3),
        'test_private_credentials_published': False,
        'limitations': ['No AOA/USB host backend or AA message envelope',
                        'No real Pixel AA credentials/certification interoperability',
                        'No thread safety or native hardware entropy/time provider',
                        'No ARM cross-compilation, firmware guest or on-device test',
                        'Partial-positive and zero-write scenarios are injected API results; real peer test covers WANT_WRITE']}
    PROOF.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'pass': True, 'case_count': len(CASES), 'proof': str(PROOF.relative_to(ROOT)),
                      'device_IO': False, 'native_guest_executed': False, **metrics}))


if __name__ == '__main__':
    main()
