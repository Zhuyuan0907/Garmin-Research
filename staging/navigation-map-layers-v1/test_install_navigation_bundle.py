#!/usr/bin/env python3
"""File/identity/transaction tests; never discover, mount, or write a real USB."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('navigation_installer', HERE / 'install_navigation_bundle.py')
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image(seed):
    data = bytearray(bytes([seed]) * 102400)
    data[0] = 0
    data[16:23] = b'DSKIMG\0'
    data[65:72] = b'GARMIN\0'
    return bytes(data)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='navigation-installer-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'device'
        self.bundle = Path(self.temp.name) / 'bundle'
        self.root.mkdir()
        self.bundle.mkdir()
        self.old, self.new = image(1), image(2)
        self.device = {'part_number': '006-B1352-00', 'software_version': 800,
                       'unit_id_sha256': sha(b'SYNTHETIC-UNIT'), 'disk_bytes': I.DISK_BYTES,
                       'usb': {'vendor': '091e', 'product': '2548', 'serial_sha256': sha(b'SYNTHETIC-SERIAL')}}
        self.m = {'device': self.device,
                  'new_map': {'bundle_path': I.NEW_PATH, 'device_path': I.NEW_PATH, 'bytes': len(self.new), 'sha256': sha(self.new)},
                  'previous_project_map': {'device_path': I.OLD_PATH, 'disabled_path': I.OLD_PATH + '.disabled', 'bytes': len(self.old), 'sha256': sha(self.old)},
                  'preserved_stock_files': []}
        for n, rel in enumerate(sorted(I.CORE_STOCK)):
            content = ('SYNTHETIC-STOCK-' + str(n)).encode()
            self.write(self.root, rel, content)
            self.m['preserved_stock_files'].append({'device_path': rel, 'bytes': len(content), 'sha256': sha(content)})
        self.write(self.root, I.OLD_PATH, self.old)
        self.write(self.root, 'Garmin/GarminDevice.xml', self.xml())
        self.source = self.write(self.bundle, I.NEW_PATH, self.new)

    def write(self, root, rel, content):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def xml(self, unit='SYNTHETIC-UNIT', software='800', model='006-B1352-00', unicode=True):
        interface = '<DataType><Name>UnicodeMaps</Name><File><Location><Path>Map</Path></Location></File></DataType>' if unicode else ''
        return ('<Device xmlns="http://www.garmin.com/xmlschemas/GarminDevice/v2"><Model><PartNumber>' + model + '</PartNumber><SoftwareVersion>' + software + '</SoftwareVersion></Model><Id>' + unit + '</Id><MassStorageMode><DataType><Name>NMaps</Name><File><Location><Path>Map</Path></Location></File></DataType>' + interface + '</MassStorageMode></Device>').encode()

    def assert_original_state(self):
        self.assertEqual((self.root / I.OLD_PATH).read_bytes(), self.old)
        for suffix in ('.disabled',):
            self.assertFalse((self.root / (I.OLD_PATH + suffix)).exists())
        for suffix in ('', '.partial', '.rollback.partial'):
            self.assertFalse((self.root / (I.NEW_PATH + suffix)).exists())
        I.verify_stock(self.root, self.m)

    def assert_installed_state(self):
        self.assertEqual((self.root / I.NEW_PATH).read_bytes(), self.new)
        self.assertEqual((self.root / (I.OLD_PATH + '.disabled')).read_bytes(), self.old)
        self.assertFalse((self.root / I.OLD_PATH).exists())
        I.verify_stock(self.root, self.m)

    def valid_record(self, name='sda', major_minor='8:0'):
        return {'kname': name, 'name': '/dev/' + name, 'path': '/dev/' + name,
                'type': 'disk', 'tran': 'usb', 'size': I.DISK_BYTES, 'mountpoints': [None], 'maj:min': major_minor}

    def usb(self, name='sda'):
        return {'vendor': '091e', 'product': '2548', 'serial_sha256': self.device['usb']['serial_sha256'],
                'disk_bytes': I.DISK_BYTES, 'major_minor': '8:0' if name == 'sda' else '8:16',
                'sysfs_path': '/synthetic/' + name, 'mass_storage_interface': True}

    def test_manifest_contract_and_source_hash(self):
        contract = copy.deepcopy(self.m)
        # Production manifest must use the actual verified prior map identity;
        # pure file transactions use 100 KiB synthetic files instead.
        contract['previous_project_map'].update(bytes=I.OLD_BYTES, sha256=I.OLD_SHA)
        (self.bundle / 'manifest.json').write_text(json.dumps(contract))
        m, p, mh = I.load_manifest(self.bundle)
        self.assertEqual(m, contract)
        self.assertEqual(p, self.source)
        self.assertEqual(len(mh), 64)
        self.source.write_bytes(image(3))
        with self.assertRaises(I.Refusal):
            I.load_manifest(self.bundle)

    def test_manifest_protected_path_collision(self):
        contract = copy.deepcopy(self.m)
        contract['previous_project_map'].update(bytes=I.OLD_BYTES, sha256=I.OLD_SHA)
        contract['preserved_stock_files'].append({'device_path': I.NEW_PATH, 'bytes': len(self.new), 'sha256': sha(self.new)})
        (self.bundle / 'manifest.json').write_text(json.dumps(contract))
        with self.assertRaises(I.Refusal):
            I.load_manifest(self.bundle)

    def test_identity_and_interfaces(self):
        I.verify_xml(self.xml(), self.device)
        for data in (self.xml(unit='ANOTHER-SYNTHETIC-UNIT'), self.xml(software='801'), self.xml(model='006-B1371-00'), self.xml(unicode=False), b'<bad'):
            with self.subTest(case=sha(data)), self.assertRaises(I.Refusal):
                I.verify_xml(data, self.device)

    def test_waiting_and_loop_exclusion(self):
        self.assertIsNone(I.select_disk([], self.device, identity_reader=lambda n: self.fail('Unexpected identity read')))
        loop = self.valid_record('loop3')
        self.assertIsNone(I.select_disk([loop], self.device, identity_reader=lambda n: self.fail('Backup loop must be excluded')))
        other = self.usb()
        other.update(vendor='1234', product='5678', serial_sha256=None, mass_storage_interface=False)
        self.assertIsNone(I.select_disk([self.valid_record()], self.device, identity_reader=lambda n: other))

    def test_exact_usb_selection_and_negatives(self):
        good = I.select_disk([self.valid_record()], self.device, identity_reader=self.usb, mount_checker=lambda n: None)
        self.assertEqual(good['path'], '/dev/sda')
        for label, change_disk, change_usb in (
            ('serial', {}, {'serial_sha256': sha(b'OTHER')}), ('size', {'size': 999}, {}),
            ('sysfs_size', {}, {'disk_bytes': 999}), ('child', {'children': [{'type': 'part'}]}, {}),
            ('mounted', {'mountpoints': ['/synthetic-mount']}, {}), ('major', {'maj:min': '8:1'}, {}),
            ('interface', {}, {'mass_storage_interface': False}), ('path', {'path': '/tmp/fake-device'}, {})):
            d, u = self.valid_record(), self.usb()
            d.update(change_disk); u.update(change_usb)
            with self.subTest(case=label), self.assertRaises(I.Refusal):
                I.select_disk([d], self.device, identity_reader=lambda n: u, mount_checker=lambda n: None)
        with self.assertRaises(I.Refusal):
            I.select_disk([self.valid_record(), self.valid_record('sdb', '8:16')], self.device, identity_reader=self.usb, mount_checker=lambda n: None)
        with self.assertRaises(I.Refusal):
            I.select_disk([self.valid_record()], self.device, identity_reader=self.usb, mount_checker=lambda n: (_ for _ in ()).throw(I.Refusal('Already mounted')))

    def test_real_sysfs_reader_on_synthetic_tree(self):
        base = Path(self.temp.name) / 'synthetic-sysfs'
        usb = base / 'devices' / 'usb1' / '1-1'
        interface = usb / '1-1:1.0'
        node = interface / 'target' / 'block' / 'sda'
        (node / 'device').mkdir(parents=True)
        (node / 'size').write_text(str(I.DISK_BYTES // 512))
        (node / 'dev').write_text('8:0')
        (usb / 'idVendor').write_text('091e\n')
        (usb / 'idProduct').write_text('2548\n')
        (usb / 'serial').write_text('SYNTHETIC-SERIAL\n')
        (interface / 'bInterfaceClass').write_text('08\n')
        cls = base / 'class' / 'block'
        cls.mkdir(parents=True)
        (cls / 'sda').symlink_to(node, target_is_directory=True)
        identity = I.usb_sysfs('sda', sys_class=cls)
        self.assertEqual(identity['serial_sha256'], self.device['usb']['serial_sha256'])
        self.assertEqual(identity['disk_bytes'], I.DISK_BYTES)
        self.assertTrue(identity['mass_storage_interface'])
        read = lambda n: I.usb_sysfs(n, sys_class=cls)
        self.assertIsNotNone(I.select_disk([self.valid_record()], self.device, identity_reader=read, mount_checker=lambda n: None))
        (interface / 'bInterfaceClass').write_text('03\n')
        with self.assertRaises(I.Refusal):
            I.select_disk([self.valid_record()], self.device, identity_reader=read, mount_checker=lambda n: None)
        (interface / 'bInterfaceClass').write_text('08\n')
        (usb / 'serial').unlink()
        with self.assertRaises(I.Refusal):
            I.select_disk([self.valid_record()], self.device, identity_reader=read, mount_checker=lambda n: None)

    def test_mountinfo_existing_mount_rejected(self):
        with mock.patch.object(I.Path, 'read_text', return_value='42 33 8:0 / /synthetic ro,nosuid - vfat /dev/sda ro\n'):
            with self.assertRaises(I.Refusal):
                I.check_mountinfo('8:0')
            I.check_mountinfo('8:16')

    def test_readonly_preflight_rejects_low_space(self):
        with mock.patch.object(I.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
            with self.assertRaises(I.Refusal):
                I.device_preflight(self.root, self.m, 'install')
        self.assert_original_state()

    def test_install_idempotent_rollback_idempotent(self):
        xml, pf = I.device_preflight(self.root, self.m, 'install')
        self.assertTrue(pf['xml_unit_and_interfaces_verified'])
        first = I.transaction(self.root, self.m, self.source, 'install')
        self.assertTrue(first['previous_map_disabled'])
        self.assert_installed_state()
        again = I.transaction(self.root, self.m, self.source, 'install')
        self.assertNotIn('new_image_published', again['events'])
        self.assert_installed_state()
        rolled = I.transaction(self.root, self.m, self.source, 'rollback')
        self.assertFalse(rolled['new_map_present'])
        self.assert_original_state()
        I.transaction(self.root, self.m, self.source, 'rollback')
        self.assert_original_state()

    def test_install_undo_at_every_precommit_event(self):
        points = ('partial_written_and_synced', 'partial_readback_verified', 'new_image_published', 'previous_map_disabled', 'final_original_and_identity_checks_passed')
        for point in points:
            def fail(event):
                if event == point:
                    raise RuntimeError('Synthetic transaction fault')
            with self.subTest(point=point), self.assertRaises(RuntimeError):
                I.transaction(self.root, self.m, self.source, 'install', fault=fail)
            self.assert_original_state()

    def test_rollback_undo_at_every_precommit_event(self):
        I.transaction(self.root, self.m, self.source, 'install')
        points = ('new_map_quarantined', 'previous_map_restored', 'final_original_and_identity_checks_passed', 'before_own_new_map_removal')
        for point in points:
            def fail(event):
                if event == point:
                    raise RuntimeError('Synthetic rollback fault')
            with self.subTest(point=point), self.assertRaises(RuntimeError):
                I.transaction(self.root, self.m, self.source, 'rollback', fault=fail)
            self.assert_installed_state()

    def test_corrupt_readback_and_identity_failure_undo(self):
        def damage(event):
            if event == 'partial_written_and_synced':
                (self.root / (I.NEW_PATH + '.partial')).write_bytes(image(9))
        with self.assertRaises(I.Refusal):
            I.transaction(self.root, self.m, self.source, 'install', fault=damage)
        self.assert_original_state()
        with self.assertRaises(I.Refusal):
            I.transaction(self.root, self.m, self.source, 'install', final_check=lambda: (_ for _ in ()).throw(I.Refusal('Synthetic identity changed')))
        self.assert_original_state()

    def test_unknown_new_map_never_deleted_or_overwritten(self):
        unknown = b'UNRELATED-MAP'
        target = self.write(self.root, I.NEW_PATH, unknown)
        for mode in ('install', 'rollback'):
            with self.subTest(mode=mode), self.assertRaises(I.Refusal):
                I.transaction(self.root, self.m, self.source, mode)
            self.assertEqual(target.read_bytes(), unknown)
            self.assertEqual((self.root / I.OLD_PATH).read_bytes(), self.old)

    def test_unknown_old_or_recovery_file_refuses(self):
        old = self.root / I.OLD_PATH
        old.write_bytes(b'UNKNOWN-OLD')
        with self.assertRaises(I.Refusal):
            I.transaction(self.root, self.m, self.source, 'install')
        self.assertEqual(old.read_bytes(), b'UNKNOWN-OLD')
        old.write_bytes(self.old)
        recovery = self.write(self.root, I.NEW_PATH + '.partial', b'UNKNOWN-PARTIAL')
        with self.assertRaises(I.Refusal):
            I.transaction(self.root, self.m, self.source, 'install')
        self.assertEqual(recovery.read_bytes(), b'UNKNOWN-PARTIAL')

    def test_no_replace_race_preserves_unknown_destination(self):
        target = self.root / I.NEW_PATH
        def race(event):
            if event == 'partial_readback_verified':
                target.write_bytes(b'EXTERNAL-NEW-FILE')
        with self.assertRaises(FileExistsError):
            I.transaction(self.root, self.m, self.source, 'install', fault=race)
        self.assertEqual(target.read_bytes(), b'EXTERNAL-NEW-FILE')
        self.assertFalse((self.root / (I.NEW_PATH + '.partial')).exists())
        self.assertEqual((self.root / I.OLD_PATH).read_bytes(), self.old)

    def test_protected_stock_mismatch_blocks_writes(self):
        item = self.m['preserved_stock_files'][0]
        stock = self.root / item['device_path']
        stock.write_bytes(b'STOCK-CHANGED')
        with self.assertRaises(I.Refusal):
            I.transaction(self.root, self.m, self.source, 'install')
        self.assertEqual(stock.read_bytes(), b'STOCK-CHANGED')
        self.assertFalse((self.root / I.NEW_PATH).exists())
        self.assertEqual((self.root / I.OLD_PATH).read_bytes(), self.old)

    def test_symlink_and_path_escape_rejected(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (self.root / 'link').symlink_to(outside, target_is_directory=True)
        for relative in ('../outside/file', '/tmp/other', 'Map/../file', 'link/file', 'Map\\file'):
            with self.subTest(case=relative), self.assertRaises(I.Refusal):
                I.safe_path(self.root, relative)

    def test_full_flow_mock_ro_before_rw_and_final_unmount(self):
        commands = []
        mounted_root = Path(self.temp.name) / 'mock-mount'

        @contextlib.contextmanager
        def fake_lock():
            yield '/synthetic/operation.lock'

        def command(cmd):
            commands.append(cmd[:])
            if cmd[0] == 'mount' and '-t' in cmd:
                for p in self.root.iterdir():
                    if p.is_dir(): shutil.copytree(p, mounted_root / p.name)
                    else: shutil.copy2(p, mounted_root / p.name)
            elif cmd[0] == 'umount':
                for p in self.root.iterdir():
                    if p.is_dir(): shutil.rmtree(p)
                    else: p.unlink()
                for p in list(mounted_root.iterdir()):
                    shutil.move(str(p), self.root / p.name)
            return ''

        def make_mount(**kwargs):
            mounted_root.mkdir()
            return str(mounted_root)

        with mock.patch.object(I, 'load_manifest', return_value=(self.m, self.source, sha(b'MANIFEST'))), mock.patch.object(I, 'operation_lock', fake_lock), mock.patch.object(I, 'disk_records', return_value=[self.valid_record()]), mock.patch.object(I, 'select_disk', return_value={'name': 'sda', 'path': '/dev/sda', 'identity': self.usb()}), mock.patch.object(I, 'reconfirm_disk'), mock.patch.object(I, 'run_command', command), mock.patch.object(I.tempfile, 'mkdtemp', make_mount), mock.patch.object(I.os, 'sync'), mock.patch.object(I.os, 'geteuid', return_value=0):
            preflight = I.execute(self.bundle, 'preflight')
            self.assertEqual(preflight['state'], 'device_readonly_preflight_passed')
            self.assertTrue(preflight['unmounted'])
            self.assertFalse(any('remount,rw,nosuid,nodev,noexec' in c for c in commands))
            self.assert_original_state()
            commands.clear()
            installed = I.execute(self.bundle, 'install')
            self.assertEqual(installed['state'], 'installed_readback_verified')
            self.assertTrue(installed['unmounted'])
            self.assertIn('ro,nosuid,nodev,noexec', commands[0])
            self.assertIn('remount,rw,nosuid,nodev,noexec', commands[1])
            self.assertEqual(commands[-1][0], 'umount')
            self.assert_installed_state()

            # A physical preflight failure still unmounts and never remounts RW.
            commands.clear()
            (self.root / 'Garmin/GarminDevice.xml').write_bytes(self.xml(unit='ANOTHER-SYNTHETIC-UNIT'))
            failed = I.execute(self.bundle, 'preflight')
            self.assertEqual(failed['state'], 'failed')
            self.assertTrue(failed['unmounted'])
            self.assertFalse(any('remount,rw,nosuid,nodev,noexec' in c for c in commands))
            self.assertEqual(commands[-1][0], 'umount')
            self.assert_installed_state()

    def test_full_flow_waiting_no_mount_or_system_operation(self):
        @contextlib.contextmanager
        def fake_lock():
            yield '/synthetic/operation.lock'
        with mock.patch.object(I, 'load_manifest', return_value=(self.m, self.source, sha(b'MANIFEST'))), mock.patch.object(I, 'operation_lock', fake_lock), mock.patch.object(I, 'disk_records', return_value=[]), mock.patch.object(I, 'run_command', side_effect=AssertionError('No system command allowed')):
            result = I.execute(self.bundle, 'preflight')
        self.assertEqual(result['state'], 'waiting_for_usb')
        self.assertFalse(result['physical_device_present'])
        self.assertFalse(result['device_files_written'])
        self.assert_original_state()


if __name__ == '__main__':
    unittest.main(verbosity=2)
