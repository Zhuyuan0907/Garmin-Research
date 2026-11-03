#!/usr/bin/env python3
"""Record terminal pure-file/mock installer tests, with no real USB operations."""
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('navigation_installer_tests', HERE / 'test_install_navigation_bundle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.InstallerTests)
log = io.StringIO()
result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
scope = {
    'all_passed': result.wasSuccessful(),
    'checked_at': dt.datetime.now().astimezone().isoformat(),
    'tests_run': result.testsRun,
    'failures': len(result.failures), 'errors': len(result.errors),
    'actual_production_logic_executed': ['manifest/source validation', 'XML identity/interfaces',
        'USB candidate filtering', 'sysfs ancestor/interface/serial/size reader on synthetic tree',
        'mountinfo rejection on synthetic text', 'stock/old/new file hashing',
        'exclusive creation/copy/fsync/readback', 'Linux renameat2 NOREPLACE',
        'old image disable/restore', 'rollback own-hash deletion', 'precommit fault undo',
        'RO-before-RW and final sync/umount order with mocked system operations'],
    'synthetic_image_bytes': 102400,
    'actual_usb_discovery': False, 'actual_mount': False, 'actual_remount': False,
    'actual_garmin_file_write': False, 'raw_private_identity_in_results': False,
    'real_vfat_atomic_rename_verified': False,
    'physical_device_navigation_verified': False,
    'limitations': ['Tests use synthetic XML/USB IDs and 100 KiB images; original device identities are not exported.',
        'Transactions run on a temporary host filesystem, not the Garmin FAT mount.',
        'System mount/remount/umount and live reconfirm calls are mocked in the full-flow cases.',
        'Undo is tested before commit; after rollback commit, unmount failure is reported and cannot undo a deleted new image.',
        'No test proves physical map acceptance, Chinese address search, or navigation correctness.'],
    'source_files': {p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in (HERE / 'install_navigation_bundle.py', HERE / 'test_install_navigation_bundle.py', Path(__file__).resolve())},
    'test_output': log.getvalue(),
}
(HERE / 'installer-test-results.json').write_text(json.dumps(scope, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: scope[k] for k in ('all_passed', 'tests_run', 'failures', 'errors', 'actual_usb_discovery', 'actual_garmin_file_write')}, ensure_ascii=False))
raise SystemExit(0 if scope['all_passed'] else 1)
