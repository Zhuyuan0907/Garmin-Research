#!/usr/bin/env python3
"""Ordinary Linux host checks for public bounded AA protobuf schemas only."""
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import warnings

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'native/aa-proto'
STAGE = ROOT / 'staging/android-auto-proto-host-v1'
PROOF = ROOT / 'evidence/android-auto-proto-host-v1.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((STAGE / 'build.json').read_text())
    for name, pin in manifest['files'].items():
        assert sha(ROOT / name) == pin['sha256'], name
    sys.path.insert(0, str(STAGE / 'python'))
    import google.protobuf
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    from google.protobuf.message import DecodeError
    classes = {}
    for top in manifest['root_messages']:
        name = top.removesuffix('Message')
        classes[name] = getattr(importlib.import_module(top + '_pb2'), name)
    receipts = []
    cases = []
    observations = []
    env = dict(os.environ)
    env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1'
    env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    env['PYTHONDONTWRITEBYTECODE'] = '1'

    def run(argv, record=True):
        start = time.monotonic()
        r = subprocess.run([str(a) for a in argv], cwd=ROOT, env=env,
                           text=True, capture_output=True, timeout=90)
        receipt = {'argv': [str(a) for a in argv], 'exit_code': r.returncode,
                   'stdout': r.stdout, 'stderr': r.stderr,
                   'elapsed_seconds': time.monotonic() - start}
        if record or r.returncode:
            receipts.append(receipt)
        assert r.returncode == 0, receipt
        assert not r.stderr, receipt
        return r.stdout

    def fill_required(msg):
        for field in msg.DESCRIPTOR.fields:
            if field.label != field.LABEL_REQUIRED:
                continue
            if field.type == field.TYPE_MESSAGE:
                fill_required(getattr(msg, field.name))
            elif field.type == field.TYPE_ENUM:
                setattr(msg, field.name, field.enum_type.values[0].number)
            else:
                setattr(msg, field.name, field.default_value)
        return msg

    def call(binary, name, wire):
        return json.loads(run([binary, name, wire.hex()], record=False))

    def valid(binary, label, msg):
        wire = msg.SerializeToString(deterministic=True)
        result = call(binary, msg.DESCRIPTOR.name, wire)
        assert result['decoded'] and result['encoded'], (label, result)
        back = type(msg)()
        back.ParseFromString(bytes.fromhex(result['hex']))
        assert back.IsInitialized() and back == msg, (label, msg, back)
        cases.append({'build': binary.name, 'label': label, 'accepted': True,
                      'wire_bytes': len(wire), 'wire_sha256': hashlib.sha256(wire).hexdigest()})

    def reject(binary, label, name, wire, python_can_parse=None):
        result = call(binary, name, wire)
        assert not result['decoded'], (label, result)
        if python_can_parse is not None:
            py = classes[name]()
            try:
                with warnings.catch_warnings(record=True):
                    warnings.simplefilter('always')
                    py.ParseFromString(wire)
                parsed = py.IsInitialized()
            except DecodeError:
                parsed = False
            assert parsed == python_can_parse, (label, parsed)
        cases.append({'build': binary.name, 'label': label, 'accepted': False,
                      'error': result['error'], 'wire_sha256': hashlib.sha256(wire).hexdigest()})

    def service_bound(field, n):
        s = classes['ServiceDiscoveryResponse']()
        if field == 'channels':
            for i in range(n):
                s.channels.add(channel_id=i + 1)
        else:
            c = s.channels.add(channel_id=3)
            if field == 'audio_configs':
                for _ in range(n):
                    c.av_channel.audio_configs.add(sample_rate=48000, bit_depth=16, channel_count=2)
            elif field == 'video_configs':
                for _ in range(n):
                    c.av_channel.video_configs.add(video_resolution=1, video_fps=1)
            elif field == 'keycodes':
                c.input_channel.supported_keycodes.extend(range(n))
        return s

    with tempfile.TemporaryDirectory(prefix='run-', dir=STAGE) as tmp:
        tmp = Path(tmp)
        cc = run(['gcc', '--version']).splitlines()[0]
        builds = []
        for name, flags in [('ordinary', ['-O2']),
                            ('asan-ubsan', ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
            binary = tmp / name
            cmd = ['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-DPB_VALIDATE_UTF8=1'] + flags
            cmd += ['-I' + str(ROOT / d) for d in manifest['include_dirs']]
            cmd += [str(BASE / 'test_proto.c')] + [str(ROOT / n) for n in manifest['c_sources']]
            cmd += ['-o', str(binary)]
            run(cmd)
            output = run([binary, 'selftest'])
            summary = json.loads(next(l.removeprefix('RESULT ') for l in output.splitlines() if l.startswith('RESULT ')))
            builds.append({'name': name, 'selftest': summary, 'binary_sha256': sha(binary)})

            for message_name, cls in classes.items():
                valid(binary, 'all-required-defaults-' + message_name, fill_required(cls()))
            for value in [-1, -(1 << 31), (1 << 31) - 1]:
                valid(binary, 'int32-priority-' + str(value), classes['ChannelOpenRequest'](priority=value, channel_id=4))
                valid(binary, 'int32-session-' + str(value), classes['AVChannelStartIndication'](session=value, config=1))
            valid(binary, 'required-negative-session-uint32-max', classes['AVMediaAckIndication'](session=-1, value=(1 << 32) - 1))
            for kind in ['PingRequest', 'PingResponse']:
                for value in [-1, -(1 << 63), (1 << 63) - 1]:
                    valid(binary, kind + '-int64-' + str(value), classes[kind](timestamp=value))
            for text in ['a' * 63, '台' * 21, 'Pixel 7 Pro']:
                valid(binary, 'string-bound-' + str(len(text.encode())), classes['ServiceDiscoveryRequest'](device_name=text))
            reject(binary, 'string-64-over-capacity', 'ServiceDiscoveryRequest', classes['ServiceDiscoveryRequest'](device_name='a' * 64).SerializeToString(), True)
            reject(binary, 'UTF8-byte-limit-not-codepoints', 'ServiceDiscoveryRequest', classes['ServiceDiscoveryRequest'](device_name='台' * 22).SerializeToString(), True)
            for field, cap in [('channels', 8), ('audio_configs', 4), ('video_configs', 4), ('keycodes', 64)]:
                valid(binary, field + '-at-cap', service_bound(field, cap))
                reject(binary, field + '-over-cap', 'ServiceDiscoveryResponse', service_bound(field, cap + 1).SerializeToString(), True)
            valid(binary, 'binding-128-negative-and-positive', classes['BindingRequest'](scan_codes=[-1, -(1 << 31)] + list(range(126))))
            reject(binary, 'binding-129-over-cap', 'BindingRequest', classes['BindingRequest'](scan_codes=list(range(129))).SerializeToString(), True)
            valid(binary, 'setup-8-configs', classes['AVChannelSetupResponse'](media_status=2, max_unacked=1, configs=range(8)))
            reject(binary, 'setup-9-configs', 'AVChannelSetupResponse', classes['AVChannelSetupResponse'](media_status=2, max_unacked=1, configs=range(9)).SerializeToString(), True)

            for label, msgname, wire in [
                ('required-status-absent', 'ChannelOpenResponse', b''),
                ('required-ack-second-absent', 'AVMediaAckIndication', bytes.fromhex('0800')),
                ('required-setup-status-absent', 'AVChannelSetupResponse', bytes.fromhex('1001')),
                ('zero-tag', 'ChannelOpenResponse', bytes.fromhex('00')),
                ('invalid-wiretype', 'ChannelOpenResponse', bytes.fromhex('0e00')),
                ('truncated-varint', 'ChannelOpenResponse', bytes.fromhex('0880')),
                ('truncated-string-length', 'ServiceDiscoveryRequest', bytes.fromhex('2280')),
                ('truncated-string-payload', 'ServiceDiscoveryRequest', bytes.fromhex('220361')),
                ('invalid-UTF8', 'ServiceDiscoveryRequest', bytes.fromhex('2202c0af')),
            ]:
                reject(binary, label, msgname, wire, False)
            # A proto2 repeated primitive legally accepts packed and unpacked form.
            for wire in [bytes.fromhex('0a03010203'), bytes.fromhex('080108020803')]:
                r = call(binary, 'BindingRequest', wire)
                assert r['decoded'] and r['encoded']
                py = classes['BindingRequest'](); py.ParseFromString(bytes.fromhex(r['hex']))
                assert list(py.scan_codes) == [1, 2, 3]
                cases.append({'build': name, 'label': 'binding-packed-or-unpacked-' + wire.hex(), 'accepted': True})
            # Unknown fields are allowed but not retained by static nanopb structs.
            unknown = bytes.fromhex('0800a00601a9060000000000000000b20603616263bd0600000000')
            r = call(binary, 'ChannelOpenResponse', unknown)
            assert r['decoded'] and bytes.fromhex(r['hex']) == bytes.fromhex('0800')
            py = classes['ChannelOpenResponse'](); py.ParseFromString(unknown); py.DiscardUnknownFields()
            assert py.SerializeToString() == bytes.fromhex(r['hex'])
            cases.append({'build': name, 'label': 'skip-unknown-varint-fixed64-string-fixed32', 'accepted': True})
            r = call(binary, 'ChannelOpenRequest', bytes.fromhex('08010802'))
            py = classes['ChannelOpenRequest'](); py.ParseFromString(bytes.fromhex(r['hex']))
            assert r['decoded'] and py.priority == 2
            cases.append({'build': name, 'label': 'duplicate-scalar-last-wins', 'accepted': True})

            # Independently written C service-discovery payload validated in Python.
            r = json.loads(run([binary, 'emit-service']))
            s = classes['ServiceDiscoveryResponse'](); s.ParseFromString(bytes.fromhex(r['hex']))
            assert s.head_unit_name == 'Garmin research host' and s.sw_version == 'host-only'
            assert [c.channel_id for c in s.channels] == [1, 3, 4]
            assert s.channels[0].input_channel.touch_screen_config.width == 800
            assert list(s.channels[0].input_channel.supported_keycodes) == [4, 85]
            assert s.channels[1].av_channel.video_configs[0].video_resolution == 1
            assert s.channels[2].av_channel.audio_configs[0].sample_rate == 48000
            cases.append({'build': name, 'label': 'independent-C-service-discovery', 'accepted': True, 'encoded_bytes': r['bytes']})

            # Public nanopb stores enums numerically rather than applying enum-domain policy.
            r = call(binary, 'ChannelOpenResponse', bytes.fromhex('0802'))
            py = classes['ChannelOpenResponse'](); py.ParseFromString(bytes.fromhex('0802'))
            assert r['decoded'] and not py.IsInitialized()
            observations.append({'build': name, 'label': 'unknown-proto2-enum-domain',
                                 'nanopb_decoded': True, 'Python_initialized': False,
                                 'caller_requirement': 'Dispatcher must validate allowed enum values before using decoded object.'})
            # Static C strings do not preserve protobuf embedded-NUL strings on reencode.
            r = call(binary, 'ServiceDiscoveryRequest', bytes.fromhex('2203610062'))
            py = classes['ServiceDiscoveryRequest'](); py.ParseFromString(bytes.fromhex(r['hex']))
            assert r['decoded'] and py.device_name == 'a'
            observations.append({'build': name, 'label': 'embedded-NUL-static-C-string',
                                 'input': 'a\\u0000b', 'reencoded': 'a',
                                 'caller_requirement': 'Treat identity strings as C display labels; reject embedded NUL before decoding if exact protobuf-string fidelity is required.'})

        # No uint64 field exists in this AA schema closure; independently confirm
        # nanopb primitive's literal with a Python-runtime test-only uint64 message.
        fd = descriptor_pb2.FileDescriptorProto(name='test_uint64.proto', package='host_test', syntax='proto2')
        m = fd.message_type.add(name='UInt64'); f = m.field.add(name='value', number=1, type=4, label=2)
        pool = descriptor_pool.DescriptorPool(); pool.Add(fd)
        cls = message_factory.MessageFactory(pool).GetPrototype(pool.FindMessageTypeByName('host_test.UInt64'))
        assert cls(value=(1 << 64) - 1).SerializeToString() == bytes.fromhex('08ffffffffffffffffff01')
        cases.append({'build': 'independent-Python', 'label': 'uint64-max-literal-confirmation', 'accepted': True})
        # Link-symbol check demonstrates generated/runtime library has no malloc dependency.
        objects = tmp / 'objects'; objects.mkdir()
        for src in manifest['c_sources']:
            obj = objects / (Path(src).stem + '.o')
            run(['gcc', '-std=c11', '-O2', '-DPB_VALIDATE_UTF8=1'] +
                ['-I' + str(ROOT / d) for d in manifest['include_dirs']] +
                ['-c', str(ROOT / src), '-o', obj], record=False)
        symbols = run(['nm', '-u'] + sorted(objects.glob('*.o')))
        for prohibited in ['malloc', 'calloc', 'realloc', 'free']:
            assert not any(line.split()[-1:] == [prohibited] for line in symbols.splitlines()), prohibited
        runtime_symbols = {'no_malloc_calloc_realloc_free_undefined_symbols': True,
                           'objects': len(list(objects.glob('*.o'))), 'nm_output_sha256': hashlib.sha256(symbols.encode()).hexdigest()}

    source_paths = [p for p in BASE.rglob('*') if p.is_file()]
    source_paths += [ROOT / 'scripts/build_aa_proto_host.py', Path(__file__).resolve()]
    source_paths += sorted((STAGE / 'python').glob('*.py'))
    generator_dir = STAGE / 'tools/nanopb-0.4.9.1/generator'
    source_paths += sorted(generator_dir.glob('*.py'))
    source_paths += sorted((generator_dir / 'proto').glob('*.py'))
    source_paths += sorted((generator_dir / 'proto').glob('*.proto'))
    source_paths += [generator_dir / 'protoc-gen-nanopb']
    pins = {str(p.relative_to(ROOT)): sha(p) for p in sorted(source_paths)}
    proof = {'schema': 'android-auto-proto-host-v1', 'pass': True,
             'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'host': {'platform': platform.platform(), 'machine': platform.machine(), 'compiler': cc,
                      'python_protobuf': google.protobuf.__version__},
             'source_sha256': pins, 'build_manifest': str((STAGE / 'build.json').relative_to(ROOT)),
             'test_input_sha256': {'staging/android-auto-proto-host-v1/schema.desc': sha(STAGE / 'schema.desc'),
                                  'staging/android-auto-proto-host-v1/upstream-tools.json': sha(STAGE / 'upstream-tools.json')},
             'build_manifest_sha256': sha(STAGE / 'build.json'), 'schema_count': len(manifest['schema_source_pins']),
             'root_message_count': len(classes), 'c_source_count': len(manifest['c_sources']),
             'builds': builds, 'independent_runtime_case_count': len(cases), 'independent_runtime_cases': cases,
             'observed_semantic_limits': observations, 'runtime_link_symbols': runtime_symbols,
             'actual_subprocess_receipts': receipts, 'upstream_tools': manifest['nanopb_tools'],
             'device_IO': False, 'native_guest_executed': False, 'original_Garmin_code_executed': False,
             'ARM_crosscompile': False, 'Pixel_protocol_compatibility_confirmed': False,
             'installed_on_Garmin': False, 'wire_TLS_dispatcher_executed': False,
             'policy': {'malloc': False, 'generated_callbacks': False, 'UTF8_validation': True,
                        'unknown_fields': 'skip; not retained on encode',
                        'failed_decode': 'may partially modify destination; caller must discard',
                        'failed_encode': 'may partially write output; caller must not publish',
                        'required_proto2_zero': 'must remain explicitly present',
                        'max_service_schema_encoded': 8294, 'root_outgoing_slot_cap': 8192,
                        'service_encode_requires_actual_cap_check': True,
                        'uint64_scope': 'primitive only: schema Ping timestamp is int64'}}
    PROOF.write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'pass': True, 'ordinary_selftest': builds[0]['selftest'],
                      'asan_ubsan_selftest': builds[1]['selftest'],
                      'independent_runtime_case_count': len(cases), 'observed_semantic_limits': len(observations),
                      'proof': str(PROOF.relative_to(ROOT)), 'proof_sha256': sha(PROOF)}, indent=2))


if __name__ == '__main__':
    main()
