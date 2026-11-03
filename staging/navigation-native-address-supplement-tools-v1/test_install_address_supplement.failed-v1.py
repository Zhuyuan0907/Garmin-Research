#!/usr/bin/env python3
"""Meaningful file-transaction and USB enumeration controls; no physical writes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installer', HERE / 'install_address_supplement.py')
i = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i)
PASSED = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(path, data):
    return {'device_path': path, 'bytes': len(data), 'sha256': sha(data)}


def rejected(call, reason):
    try:
        call()
    except i.Refusal as error:
        assert reason in str(error), str(error)
        return error
    raise AssertionError('Expected refusal: ' + reason)


def fixture(base):
    root = base / 'device'; root.mkdir()
    (root / '.System').mkdir(); (root / 'Garmin').mkdir(); (root / 'Map').mkdir()
    original = bytearray((n * 31 + 7) % 256 for n in range(8192))
    candidate = bytearray(original)
    candidate[512:523] = b'new_address'
    candidate[8128:8192] = bytes([83]) * 64
    original, candidate = bytes(original), bytes(candidate)
    source = base / 'candidate.img'; source.write_bytes(candidate)
    (root / i.TARGET).write_bytes(original)
    unit = 'fixture-unit-identity'
    xml = ('<Device xmlns="http://www.garmin.com/xmlschemas/GarminDevice/v2">'
           '<Model><PartNumber>006-B1352-00</PartNumber><SoftwareVersion>800</SoftwareVersion></Model>'
           '<Id>' + unit + '</Id></Device>').encode()
    (root / 'Garmin/GarminDevice.xml').write_bytes(xml)
    protected = [(p, data) for p, data in [('.System/firmware.bin', b'never change firmware'),
                  ('.System/stock.gma', b'never change licenses'), ('.System/old.db', b'never change DB'),
                  ('Map/other.img', b'never change other map')]]
    for p, data in protected:
        (root / p).write_bytes(data)
    road_path, road_data = 'Map/Taiwan_OSM_SearchRepair_v2.img', b'required installed road fixture'
    (root / road_path).write_bytes(road_data)
    m = {'target': {'device_path': i.TARGET, 'bytes': len(candidate), 'original_sha256': sha(original),
                    'candidate_sha256': sha(candidate)},
         'device': {'part_number': '006-B1352-00', 'software_version': '800', 'unit_id_sha256': i.private_hash(unit)},
         'preserved_stock_files': [record(p, data) for p, data in protected],
         'required_files': [record(road_path, road_data)]}
    rb = {'schema': i.ROLLBACK_SCHEMA, 'device_path': i.TARGET, 'bytes': len(candidate),
          'original_sha256': sha(original), 'candidate_sha256': sha(candidate), 'ranges': []}
    for offset, size in [(512, 11), (8128, 64)]:
        rb['ranges'].append({'offset': offset, 'length': size, 'before_hex': original[offset:offset + size].hex(),
                             'after_sha256': sha(candidate[offset:offset + size])})
    ranges = i.validate_ranges(rb, m['target'], source)
    return root, m, source, ranges, original, candidate, rb


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def run(name, call):
    call(); PASSED.append(name)


def transaction_controls():
    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        untouched = {p: data for p, data in snapshot(root).items() if p != i.TARGET}
        # A read-only preflight does not even create a device temporary file.
        baseline = snapshot(root)
        _, preflight = i.device_preflight(root, m, 'preflight')
        assert preflight['image_state'] == 'original' and snapshot(root) == baseline
        PASSED.append('readonly_preflight_has_no_device_changes')
        result = i.transaction(root, m, source, ranges, 'install')
        assert result['committed'] and (root / i.TARGET).read_bytes() == candidate
        assert {p: data for p, data in snapshot(root).items() if p != i.TARGET} == untouched
        assert not (root / i.PARTIAL).exists()
        PASSED.append('install_atomic_full_hash_and_only_target_change')
        before = (root / i.TARGET).stat()
        result = i.transaction(root, m, source, ranges, 'install')
        after = (root / i.TARGET).stat()
        assert not result['changed'] and before.st_ino == after.st_ino and before.st_mtime_ns == after.st_mtime_ns
        PASSED.append('already_installed_is_idempotent_without_temp')
        result = i.transaction(root, m, source, ranges, 'rollback')
        assert result['committed'] and (root / i.TARGET).read_bytes() == original
        assert {p: data for p, data in snapshot(root).items() if p != i.TARGET} == untouched
        PASSED.append('rollback_sparse_ranges_exact_original_only_target_change')
        assert not i.transaction(root, m, source, ranges, 'rollback')['changed']
        PASSED.append('already_original_rollback_is_idempotent')

    fault_stages = ['temporary_image_written_and_synced', 'temporary_image_readback_verified',
                    'precommit_identity_and_hashes_verified', 'atomic_target_replacement_committed',
                    'final_readback_preservation_and_identity_verified']
    for mode in ('install', 'rollback'):
        for stage in fault_stages:
            with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
                root, m, source, ranges, original, candidate, rb = fixture(Path(d))
                if mode == 'rollback':
                    (root / i.TARGET).write_bytes(candidate)
                old, new = (original, candidate) if mode == 'install' else (candidate, original)
                baseline = snapshot(root)

                def fail(event):
                    if event == stage:
                        raise RuntimeError('Injected IO interruption')

                error = rejected(lambda: i.transaction(root, m, source, ranges, mode, fault=fail), 'commit')
                committed = stage in fault_stages[3:]
                assert error.committed == committed
                assert (root / i.TARGET).read_bytes() == (new if committed else old)
                assert not (root / i.PARTIAL).exists()
                assert {p: data for p, data in snapshot(root).items() if p != i.TARGET} == {p: data for p, data in baseline.items() if p != i.TARGET}
                if committed:
                    i.transaction(root, m, source, ranges, 'rollback' if mode == 'install' else 'install')
                    assert (root / i.TARGET).read_bytes() == old
                PASSED.append(mode + '_fault_' + stage + '_safe_state_and_recovery')

    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        (root / i.TARGET).write_bytes(candidate[:-1] + b'X')
        baseline = snapshot(root)
        rejected(lambda: i.transaction(root, m, source, ranges, 'rollback'), 'external changes')
        assert snapshot(root) == baseline
        PASSED.append('rollback_external_target_change_refused_without_write')

    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        (root / i.PARTIAL).write_bytes(b'prior recovery data')
        baseline = snapshot(root)
        rejected(lambda: i.transaction(root, m, source, ranges, 'install'), 'Recovery/partial')
        assert snapshot(root) == baseline
        PASSED.append('existing_recovery_file_retained')

    for replacement in ('foreign_file', 'symlink'):
        with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
            root, m, source, ranges, original, candidate, rb = fixture(Path(d))

            def replace_partial(event):
                if event == 'temporary_image_written_and_synced':
                    p = root / i.PARTIAL
                    p.rename(root / '.System/owned-moved-by-test')
                    if replacement == 'foreign_file':
                        p.write_bytes(b'foreign data')
                    else:
                        p.symlink_to(root / '.System/old.db')
                    raise RuntimeError('Stop after hostile temporary replacement')

            error = rejected(lambda: i.transaction(root, m, source, ranges, 'install', fault=replace_partial), 'cleanup failed')
            assert error.cleanup_failed and not error.committed
            assert (root / i.TARGET).read_bytes() == original
            assert (root / i.PARTIAL).exists()
            assert (root / '.System/old.db').read_bytes() == b'never change DB'
            PASSED.append('cleanup_retains_replaced_' + replacement + '_and_other_files')

    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        external = original[:-1] + b'X'

        def change_target(event):
            if event == 'precommit_identity_and_hashes_verified':
                (root / i.TARGET).write_bytes(external)

        error = rejected(lambda: i.transaction(root, m, source, ranges, 'install', fault=change_target), 'Target at atomic replacement hash mismatch')
        assert not error.committed and (root / i.TARGET).read_bytes() == external
        assert not (root / i.PARTIAL).exists()
        PASSED.append('target_change_before_commit_refused_and_external_contents_retained')

    for path, reason in [('.System/old.db', 'Preserved original file hash mismatch'),
                         ('Map/Taiwan_OSM_SearchRepair_v2.img', 'Preserved original file hash mismatch')]:
        with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
            root, m, source, ranges, original, candidate, rb = fixture(Path(d))
            p = root / path; raw = p.read_bytes(); p.write_bytes(raw[:-1] + b'!')
            baseline = snapshot(root)
            rejected(lambda: i.transaction(root, m, source, ranges, 'install'), reason)
            assert snapshot(root) == baseline
            PASSED.append('required_or_protected_change_refused_' + path)

    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        road = root / 'Map/Taiwan_OSM_SearchRepair_v2.img'; road.unlink()
        rejected(lambda: i.transaction(root, m, source, ranges, 'install'), 'missing')
        assert (root / i.TARGET).read_bytes() == original and not (root / i.PARTIAL).exists()
        PASSED.append('missing_required_road_refused_before_write')

    with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
        root, m, source, ranges, original, candidate, rb = fixture(Path(d))
        with patch.object(i.os, 'statvfs', return_value=SimpleNamespace(f_bavail=len(candidate) + i.RESERVE_BYTES - 1, f_frsize=1)):
            rejected(lambda: i.transaction(root, m, source, ranges, 'install'), 'Insufficient free')
            assert (root / i.TARGET).read_bytes() == original and not (root / i.PARTIAL).exists()
            (root / i.TARGET).write_bytes(candidate)
            rejected(lambda: i.transaction(root, m, source, ranges, 'rollback'), 'Insufficient free')
            assert not i.transaction(root, m, source, ranges, 'install')['changed']
        PASSED.append('space_requires_full_temp_plus_reserve_in_both_directions')
        with patch.object(i.os, 'statvfs', return_value=SimpleNamespace(f_bavail=len(candidate) + i.RESERVE_BYTES, f_frsize=1)):
            i.transaction(root, m, source, ranges, 'rollback')
        PASSED.append('exact_space_threshold_accepted')

    for old, new, reason in [(b'1352', b'1371', 'model mismatch'), (b'>800<', b'>801<', 'software mismatch'),
                             (b'fixture-unit-identity', b'another-unit', 'unit identity mismatch')]:
        with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
            root, m, source, ranges, original, candidate, rb = fixture(Path(d))
            xml = root / 'Garmin/GarminDevice.xml'; xml.write_bytes(xml.read_bytes().replace(old, new))
            baseline = snapshot(root)
            rejected(lambda: i.transaction(root, m, source, ranges, 'install'), reason)
            assert snapshot(root) == baseline
            PASSED.append('actual_xml_' + reason.replace(' ', '_') + '_refused')

    for kind in ('overlap', 'out_of_bounds', 'wrong_before', 'wrong_after_sha', 'no_change'):
        with tempfile.TemporaryDirectory(prefix='address-installer-test-') as d:
            root, m, source, ranges, original, candidate, rb = fixture(Path(d))
            bad = copy.deepcopy(rb)
            if kind == 'overlap': bad['ranges'][1]['offset'] = 512
            if kind == 'out_of_bounds': bad['ranges'][1]['offset'] = len(candidate)
            if kind == 'wrong_before': bad['ranges'][0]['before_hex'] = '00' * 11
            if kind == 'wrong_after_sha': bad['ranges'][0]['after_sha256'] = '0' * 64
            if kind == 'no_change': bad['ranges'][0]['before_hex'] = candidate[512:523].hex()
            rejected(lambda: i.validate_ranges(bad, m['target'], source), 'Rollback' if kind in ('wrong_before', 'wrong_after_sha', 'no_change') else 'rollback range')
            PASSED.append('rollback_range_' + kind + '_refused')


def disk_controls():
    expected = {'disk_bytes': i.DISK_BYTES, 'usb': {'vendor': '091e', 'product': '2548', 'serial_sha256': i.USB_SERIAL_SHA}}

    def disk(name, size=i.DISK_BYTES):
        return {'name': '/dev/' + name, 'path': '/dev/' + name, 'kname': name, 'type': 'disk', 'tran': 'usb',
                'size': size, 'mountpoints': [None], 'maj:min': '8:' + ('0' if name == 'sdb' else '16')}

    def identity(name):
        return {'vendor': '091e', 'product': '2548', 'serial_sha256': i.USB_SERIAL_SHA,
                'disk_bytes': 0 if name == 'sdc' else i.DISK_BYTES, 'mass_storage_interface': True,
                'major_minor': '8:' + ('0' if name == 'sdb' else '16'), 'sysfs_path': '/fixture/usb/' + name}

    found = i.select_disk([disk('sdb'), disk('sdc', 0)], expected, identity, lambda _: None)
    assert found['name'] == 'sdb'; PASSED.append('exact_usb_and_independently_zero_empty_SD_LUN_selected')
    assert i.select_disk([disk('sdc', 0)], expected, identity, lambda _: None) is None
    PASSED.append('empty_SD_LUN_only_is_no_target')
    assert i.select_disk([disk('loop0'), {'type': 'loop', 'tran': 'usb', 'name': '/dev/loop1'}], expected,
                         lambda _: (_ for _ in ()).throw(AssertionError('must not read loop identity')), lambda _: None) is None
    PASSED.append('loop_backup_never_selected')
    assert i.select_disk([], expected, identity, lambda _: None) is None
    PASSED.append('no_usb_returns_no_target')
    for kind in ('mounted', 'partitioned', 'nonzero_SD_mismatch', 'lsblk_sysfs_zero_disagreement',
                 'serial_mismatch', 'no_mass_storage', 'major_minor_mismatch', 'path_mismatch',
                 'ambiguous', 'empty_mounted', 'empty_partitioned', 'mountinfo_mounted'):
        records, reader, checker = [disk('sdb')], identity, lambda _: None
        if kind == 'mounted': records[0]['mountpoints'] = ['/backup/GARMIN']
        if kind == 'partitioned': records[0]['children'] = [{'name': '/dev/sdb1'}]
        if kind == 'nonzero_SD_mismatch': records = [disk('sdc', 512)]
        if kind == 'lsblk_sysfs_zero_disagreement': records = [disk('sdb', 0)]
        if kind == 'serial_mismatch': reader = lambda n: {**identity(n), 'serial_sha256': '0' * 64}
        if kind == 'no_mass_storage': reader = lambda n: {**identity(n), 'mass_storage_interface': False}
        if kind == 'major_minor_mismatch': records[0]['maj:min'] = '8:99'
        if kind == 'path_mismatch': records[0]['path'] = '/dev/sda'
        if kind == 'ambiguous': records.append(disk('sdd'))
        if kind == 'empty_mounted': records = [disk('sdc', 0)]; records[0]['mountpoints'] = ['/mnt/sd']
        if kind == 'empty_partitioned': records = [disk('sdc', 0)]; records[0]['children'] = [{'name': '/dev/sdc1'}]
        if kind == 'mountinfo_mounted': checker = lambda _: i.need(False, 'Target disk is already mounted')
        rejected(lambda: i.select_disk(records, expected, reader, checker), '')
        PASSED.append('USB_' + kind + '_refused')
    for name in ('loop0', 'ram0', 'zram0', 'dm-0', '../sda'):
        rejected(lambda: i.usb_sysfs(name, Path('/does/not/exist')), 'Non-physical')
    PASSED.append('sysfs_rejects_nonphysical_and_path_traversal')


def actual_bundle_controls(bundle):
    m, source, ranges, manifest_sha = i.load_manifest(bundle)
    assert len(ranges) == 3 and i.reconstructed_sha(source, ranges, i.IMAGE_BYTES) == i.ORIGINAL_SHA
    PASSED.append('real_candidate_full_hash_and_sparse_original_reconstruction_verified')
    # These copies contain only small manifests plus hard links to the existing
    # candidate/archive, never another full image backup.
    for kind in ('target_path', 'original_hash', 'candidate_hash', 'image_size', 'unit', 'usb_serial',
                 'software', 'wrong_hwid', 'missing_preservation', 'required_target_collision'):
        with tempfile.TemporaryDirectory(prefix='address-installer-package-test-') as d:
            d = Path(d); (d / 'candidate').mkdir()
            (d / i.CANDIDATE).hardlink_to(source)
            (d / i.ROLLBACK).hardlink_to(bundle / i.ROLLBACK)
            bad = copy.deepcopy(m)
            if kind == 'target_path': bad['target']['device_path'] = '.System/gmapprom.img'
            if kind == 'original_hash': bad['target']['original_sha256'] = '0' * 64
            if kind == 'candidate_hash': bad['target']['candidate_sha256'] = '0' * 64
            if kind == 'image_size': bad['target']['bytes'] -= 1
            if kind == 'unit': bad['device']['unit_id_sha256'] = '0' * 64
            if kind == 'usb_serial': bad['device']['usb']['serial_sha256'] = '0' * 64
            if kind == 'software': bad['device']['software_version'] = '801'
            if kind == 'wrong_hwid': bad['device']['part_number'] = '006-B1371-00'
            if kind == 'missing_preservation': bad['preserved_stock_files'] = []
            if kind == 'required_target_collision': bad['required_files'] = [record(i.TARGET, b'x')]
            (d / 'manifest.json').write_text(json.dumps(bad))
            rejected(lambda: i.load_manifest(d), '')
            PASSED.append('manifest_' + kind + '_refused')
    return manifest_sha


def main():
    transaction_controls()
    disk_controls()
    bundle = HERE.parent / 'navigation-native-address-supplement-v1'
    manifest_sha = actual_bundle_controls(bundle)
    result = {'passed': True, 'checks': len(PASSED), 'controls': PASSED, 'physical_device_io': False,
              'candidate_device_verified': False, 'actual_bundle_manifest_sha256': manifest_sha,
              'installer_sha256': i.digest(HERE / 'install_address_supplement.py')}
    (HERE / 'installer-test-results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
