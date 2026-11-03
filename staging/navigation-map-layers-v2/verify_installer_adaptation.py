#!/usr/bin/env python3
"""New v2 path adaptation checks; no USB discovery/mount/service operation."""
import ast
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import tempfile
from types import ModuleType

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'staging/navigation-map-layers-v1/install_navigation_bundle.py'
NEW = HERE / 'install_navigation_bundle.py'
PRIOR_PROOF = ROOT / 'staging/navigation-map-layers-v1/installer-test-results.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(path, name):
    obj = ModuleType(name)
    obj.__file__ = str(path)
    exec(compile(path.read_text(), str(path), 'exec'), obj.__dict__)
    return obj


def img(seed):
    data = bytearray([seed] * 102400)
    data[0] = 0
    data[16:23] = b'DSKIMG\0'
    data[65:72] = b'GARMIN\0'
    return bytes(data)


def xml(unit='MOCK-UNIT'):
    return ('<Device xmlns="http://www.garmin.com/xmlschemas/GarminDevice/v2">'
        '<Model><PartNumber>006-B1352-00</PartNumber><SoftwareVersion>800</SoftwareVersion></Model>'
        '<Id>' + unit + '</Id><MassStorageMode>'
        '<DataType><Name>NMaps</Name><File><Location><Path>Map</Path></Location></File></DataType>'
        '<DataType><Name>UnicodeMaps</Name><File><Location><Path>Map</Path></Location></File></DataType>'
        '</MassStorageMode></Device>').encode()


def write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def refused(installer, callback):
    try:
        callback()
    except installer.Refusal:
        return
    raise AssertionError('Expected safe refusal')


def main():
    before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in (OLD, PRIOR_PROOF)}
    prior = json.loads(PRIOR_PROOF.read_text())
    assert prior['all_passed'] and prior['tests_run'] == 19
    assert sha(OLD.read_bytes()) == prior['source_files']['install_navigation_bundle.py']['sha256']
    old_text, new_text = OLD.read_text(), NEW.read_text()
    assert old_text.count('Taiwan_OSM_SearchRepair_v1.img') == 1
    assert new_text == old_text.replace('Taiwan_OSM_SearchRepair_v1.img', 'Taiwan_OSM_SearchRepair_v2.img')
    assert ast.dump(ast.parse(old_text), include_attributes=False) == ast.dump(
        ast.parse(new_text.replace('Taiwan_OSM_SearchRepair_v2.img', 'Taiwan_OSM_SearchRepair_v1.img')),
        include_attributes=False)
    old, installer = module(OLD, 'sealed_v1_readonly'), module(NEW, 'v2_adapted')
    functions = [name for name, value in vars(old).items() if callable(value) and hasattr(value, '__code__')]
    assert functions
    for name in functions:
        assert vars(old)[name].__code__.co_code == vars(installer)[name].__code__.co_code
        assert vars(old)[name].__code__.co_consts == vars(installer)[name].__code__.co_consts

    def no_physical_call(*args, **kwargs):
        raise AssertionError('Physical discovery/system operation forbidden in adaptation test')

    installer.run_command = no_physical_call
    installer.disk_records = no_physical_call
    installer.usb_sysfs = no_physical_call
    cases = [{'name': 'Only NEW_PATH changes; normalized AST and all function code/consts equivalent',
              'passed': True, 'function_count': len(functions)}]
    with tempfile.TemporaryDirectory(prefix='navigation-v2-adaptation-') as temp:
        directory = Path(temp)
        device, bundle = directory / 'mock-device', directory / 'bundle'
        device.mkdir(); bundle.mkdir()
        previous, new = img(1), img(2)
        m = {'new_map': {'bundle_path': installer.NEW_PATH, 'device_path': installer.NEW_PATH,
                         'bytes': len(new), 'sha256': sha(new)},
             'previous_project_map': {'device_path': installer.OLD_PATH,
                         'disabled_path': installer.OLD_PATH + '.disabled',
                         'bytes': installer.OLD_BYTES, 'sha256': installer.OLD_SHA},
             'device': {'part_number': '006-B1352-00', 'software_version': '800',
                        'unit_id_sha256': sha(b'MOCK-UNIT'), 'disk_bytes': installer.DISK_BYTES,
                        'usb': {'vendor': '091e', 'product': '2548', 'serial_sha256': sha(b'MOCK-SERIAL')}},
             'preserved_stock_files': []}
        stock = {}
        for index, name in enumerate(sorted(installer.CORE_STOCK)):
            data = ('MOCK-STOCK-' + str(index)).encode()
            write(device, name, data)
            stock[name] = sha(data)
            m['preserved_stock_files'].append({'device_path': name, 'bytes': len(data), 'sha256': sha(data)})
        source = write(bundle, installer.NEW_PATH, new)
        write(bundle, 'manifest.json', json.dumps(m).encode())
        loaded, loaded_source, manifest_hash = installer.load_manifest(bundle)
        assert loaded == m and loaded_source == source and len(manifest_hash) == 64
        cases.append({'name': 'V2 production manifest contract and IMG hash/header load', 'passed': True})
        installer.verify_xml(xml(), m['device'])
        refused(installer, lambda: installer.verify_xml(xml('MOCK-OTHER-UNIT'), m['device']))
        cases.append({'name': 'Exact XML identity remains enforced', 'passed': True})
        bad = copy.deepcopy(m)
        bad['new_map']['bundle_path'] = 'Map/Taiwan_OSM_SearchRepair_v1.img'
        write(bundle, 'manifest.json', json.dumps(bad).encode())
        refused(installer, lambda: installer.load_manifest(bundle))
        bad = copy.deepcopy(m)
        bad['new_map'].update(bundle_path='.System/gmapprom.img', device_path='.System/gmapprom.img')
        write(bundle, 'manifest.json', json.dumps(bad).encode())
        refused(installer, lambda: installer.load_manifest(bundle))
        write(bundle, 'manifest.json', json.dumps(m).encode())
        cases.append({'name': 'V1 target or stock target rejected by V2 manifest', 'passed': True})

        # A 100 KiB mock old image is used only in pure-directory transaction;
        # production load_manifest above enforces the actual prior map identity.
        transaction_manifest = copy.deepcopy(m)
        transaction_manifest['previous_project_map'].update(bytes=len(previous), sha256=sha(previous))
        write(device, installer.OLD_PATH, previous)
        write(device, 'Garmin/GarminDevice.xml', xml())
        installer.device_preflight(device, transaction_manifest, 'install')
        first = installer.transaction(device, transaction_manifest, source, 'install')
        assert first['new_map_present'] and first['previous_map_disabled']
        second = installer.transaction(device, transaction_manifest, source, 'install')
        assert second['new_map_present'] and second['previous_map_disabled']
        back = installer.transaction(device, transaction_manifest, source, 'rollback')
        assert back['previous_map_active'] and not back['new_map_present']
        installer.transaction(device, transaction_manifest, source, 'rollback')
        assert (device / installer.OLD_PATH).read_bytes() == previous
        assert all(sha((device / name).read_bytes()) == value for name, value in stock.items())
        cases.append({'name': 'V2 install/idempotent install/rollback/idempotent rollback with stock hashes unchanged',
                      'passed': True, 'synthetic_IMG_bytes': 102400})
        installer.transaction(device, transaction_manifest, source, 'install')
        write(device, installer.NEW_PATH, img(3))
        unknown = (device / installer.NEW_PATH).read_bytes()
        refused(installer, lambda: installer.transaction(device, transaction_manifest, source, 'rollback'))
        assert (device / installer.NEW_PATH).read_bytes() == unknown
        assert all(sha((device / name).read_bytes()) == value for name, value in stock.items())
        cases.append({'name': 'Rollback refuses a changed V2 image without deleting it', 'passed': True})
    after = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in (OLD, PRIOR_PROOF)}
    assert before == after
    result = {'checked_at_local': datetime.now().astimezone().isoformat(), 'all_passed': True,
              'tests_run': len(cases), 'cases': cases, 'only_source_change': 'NEW_PATH v1 -> v2',
              'v1_prior_19_tests_inherited_not_rerun': True, 'prior_proof_sha256': before[str(PRIOR_PROOF.relative_to(ROOT))],
              'source_sha256': {'install_navigation_bundle.py': sha(NEW.read_bytes()),
                                'verify_installer_adaptation.py': sha(Path(__file__).read_bytes())},
              'frozen_v1_sha256_before': before, 'frozen_v1_sha256_after': after,
              'actual_usb_discovery': False, 'actual_mount': False, 'actual_Garmin_write': False,
              'raw_private_device_identity_in_results': False,
              'limitations': 'New constant adaptation, manifest load and true transaction roundtrip run on a host temporary directory. No real vfat atomic rename, USB/service operation or navigation search was tested.'}
    (HERE / 'installer-test-results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_passed': True, 'tests_run': len(cases), 'physical_device_io': False}))


if __name__ == '__main__':
    main()
