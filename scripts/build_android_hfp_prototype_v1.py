#!/usr/bin/env python3
"""Compile/sign an Android experiment. Never installs it or contacts any device."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'android/garmin-hfp-player'
TOOLS = ROOT / 'staging/android-hfp-typecheck-tools-v1'
OUT = ROOT / 'staging/android-hfp-prototype-apk-v1'
PRIVATE = ROOT / 'staging/android-hfp-signing-private-v1'
PACKAGE = 'org.garmin.hfpprototype'
ANDROID = 'http://schemas.android.com/apk/res/android'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    OUT.mkdir(mode=0o700, exist_ok=True)
    commands = []

    def run(argv):
        p = subprocess.run([str(a) for a in argv], text=True, capture_output=True, timeout=90, cwd=ROOT)
        commands.append({'argv': [str(a) for a in argv], 'returncode': p.returncode,
                         'stdout': p.stdout, 'stderr': p.stderr})
        (OUT / 'command-results.json').write_text(json.dumps(commands, ensure_ascii=False, indent=2) + '\n')
        if p.returncode:
            print(p.stdout[-4000:] + p.stderr[-4000:])
            raise RuntimeError('Android host build failed: ' + str(argv[0]))
        return p.stdout

    tool_manifest = json.loads((TOOLS / 'manifest.json').read_text())
    for entry in tool_manifest['files']:
        raw = (ROOT / entry['path']).read_bytes()
        assert len(raw) == entry['bytes'] and sha(raw) == entry['sha256']
    r8_receipt = json.loads((TOOLS / 'r8-fetch-receipt.json').read_text())
    assert sha((TOOLS / 'r8-8.7.18.jar').read_bytes()) == r8_receipt['sha256']
    lambda_receipt = json.loads((TOOLS / 'lambda-stubs-fetch-receipt.json').read_text())
    assert sha((TOOLS / 'core-lambda-stubs.jar').read_bytes()) == lambda_receipt['sha256']
    resource_receipt = json.loads((TOOLS / 'resource34-fetch-receipt.json').read_text())
    assert sha((TOOLS / 'android-34-resource.jar').read_bytes()) == resource_receipt['sha256']
    sources = sorted((PROJECT / 'app/src/main/java').rglob('*.java'))
    assert any(p.name == 'MainActivity.java' for p in sources)
    assert any(p.name == 'TestSession.java' for p in sources)
    source_pins = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    original_manifest = PROJECT / 'app/src/main/AndroidManifest.xml'
    source_pins[str(original_manifest.relative_to(ROOT))] = sha(original_manifest.read_bytes())
    ET.register_namespace('android', ANDROID)
    tree = ET.parse(original_manifest)
    root = tree.getroot()
    permissions = [p.get('{' + ANDROID + '}name') for p in root.findall('uses-permission')]
    assert not set(permissions).intersection({'android.permission.RECORD_AUDIO', 'android.permission.CALL_PHONE',
        'android.permission.INTERNET', 'android.permission.MODIFY_PHONE_STATE', 'android.permission.READ_CONTACTS'})
    root.set('package', PACKAGE)
    root.set('{' + ANDROID + '}versionCode', '1')
    root.set('{' + ANDROID + '}versionName', '0.1-experiment')
    sdk = ET.Element('uses-sdk', {'{' + ANDROID + '}minSdkVersion': '28', '{' + ANDROID + '}targetSdkVersion': '35'})
    root.insert(0, sdk)
    manifest = OUT / 'AndroidManifest.xml'
    tree.write(manifest, encoding='utf-8', xml_declaration=True)
    classes = OUT / 'classes'
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir()
    run(['java', '-jar', TOOLS / 'ecj-3.41.0.jar', '-source', '8', '-target', '8', '-proc:none',
         '-warn:none', '-encoding', 'UTF-8', '-bootclasspath',
         str(TOOLS / 'android-35.jar') + os.pathsep + str(TOOLS / 'core-lambda-stubs.jar'), '-d', classes, *sources])
    host_test = PROJECT / 'host-tests/PlaybackGateTest.java'
    source_pins[str(host_test.relative_to(ROOT))] = sha(host_test.read_bytes())
    host_classes = OUT / 'host-tests'
    host_classes.mkdir(exist_ok=True)
    run(['java', '-jar', TOOLS / 'ecj-3.41.0.jar', '-source', '8', '-target', '8', '-proc:none',
         '-encoding', 'UTF-8', '-classpath', classes, '-d', host_classes, host_test])
    gate_result = json.loads(run(['java', '-cp', str(classes) + os.pathsep + str(host_classes),
                                 PACKAGE + '.PlaybackGateTest']).strip())
    assert gate_result['all_passed'] and gate_result['host_cases'] == 18 and not gate_result['Android_runtime']
    jar = OUT / 'classes.jar'
    with zipfile.ZipFile(jar, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(classes.rglob('*.class')):
            z.write(p, p.relative_to(classes).as_posix())
    dex = OUT / 'dex'
    if dex.exists():
        shutil.rmtree(dex)
    dex.mkdir()
    run(['java', '-cp', TOOLS / 'r8-8.7.18.jar', 'com.android.tools.r8.D8', '--min-api', '28',
         '--lib', TOOLS / 'android-35.jar', '--output', dex, jar])
    unsigned = OUT / 'unsigned.apk'
    run(['aapt2', 'link', '--manifest', manifest, '-I', TOOLS / 'android-34-resource.jar', '-o', unsigned])
    with zipfile.ZipFile(unsigned, 'a', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(dex.glob('*.dex')):
            z.write(p, p.name)
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    PRIVATE.chmod(0o700)
    password_file = PRIVATE / 'store-password'
    key = PRIVATE / 'prototype.p12'
    if not key.exists():
        fd = os.open(password_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secrets.token_hex(24))
        run(['keytool', '-genkeypair', '-alias', 'garmin-hfp-prototype', '-keyalg', 'RSA', '-keysize', '2048',
             '-validity', '3650', '-dname', 'CN=Garmin HFP Local Prototype', '-keystore', key,
             '-storetype', 'PKCS12', '-storepass:file', password_file])
        key.chmod(0o600)
    apk = OUT / 'garmin-hfp-prototype.apk'
    signer = TOOLS / 'apksigner/usr/share/java/apksigner.jar'
    run(['java', '-jar', signer, 'sign', '--ks', key, '--ks-key-alias', 'garmin-hfp-prototype',
         '--ks-pass', 'file:' + str(password_file), '--v2-signing-enabled', 'true',
         '--v3-signing-enabled', 'true', '--out', apk, unsigned])
    verify = run(['java', '-jar', signer, 'verify', '--verbose', '--min-sdk-version', '28', apk])
    assert 'Verified using v3 scheme (APK Signature Scheme v3): true' in verify
    badging = run(['aapt2', 'dump', 'badging', apk])
    assert "package: name='" + PACKAGE + "'" in badging and "sdkVersion:'28'" in badging
    assert "targetSdkVersion:'35'" in badging
    assert 'android.permission.RECORD_AUDIO' not in badging and 'android.permission.CALL_PHONE' not in badging
    with zipfile.ZipFile(apk) as z:
        assert 'classes.dex' in z.namelist() and 'AndroidManifest.xml' in z.namelist()
        assert not any(n.startswith('lib/') for n in z.namelist())
    for p in sources + [host_test]:
        assert sha(p.read_bytes()) == source_pins[str(p.relative_to(ROOT))], 'Source changed during compilation'
    assert sha(original_manifest.read_bytes()) == source_pins[str(original_manifest.relative_to(ROOT))]
    proof = {'all_build_checks_passed': True, 'source_pins': source_pins, 'source_files': len(sources),
        'Android_API_stub': 35, 'manifest_framework_resource_API': 34,
        'manifest_only_uses_attributes_available_in_API34': True,
        'min_API': 28, 'target_API': 35, 'Java_source_target': 8,
        'typechecked_against_real_official_Android_stub_jar': True, 'DEX_generated': True,
        'APK_signature_v3_verified': True, 'APK_signature_verified_for_min_API28': True,
        'signature_verifier_range_min_API': 28, 'APK_badging_permissions_verified': True,
        'host_gate_cases': gate_result, 'permissions': permissions, 'apk': {'path': str(apk.relative_to(ROOT)), 'bytes': apk.stat().st_size,
            'sha256': sha(apk.read_bytes())},
        'no_full_SDK_or_device_tools_installed': True, 'temporary_platform_archive_removed': True,
        'Android_runtime_or_phone_install_or_call_or_route_or_sound_verified': False,
        'native_Garmin_A2DP_or_App_or_install_ready': False, 'device_IO': False, 'full_goal_complete': False,
        'host_tool_execution_is_not_Garmin_guest_execution': True}
    (OUT / 'proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_build_checks_passed': True, 'source_files': len(sources), 'apk': proof['apk'],
                      'device_IO': False, 'runtime_audio_verified': False}))


if __name__ == '__main__':
    main()
