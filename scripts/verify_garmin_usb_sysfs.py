#!/usr/bin/env python3
"""Read current USB/sysfs identity without mounting or writing the Garmin disk."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC = 'evidence/device-diagnostic-observation-20261003T051812169056Z.json'
PRIOR = 'evidence/native-projection-live-usb-20261003T050946548244Z.json'


def digest(name):
    return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()


def main():
    diagnostic = json.loads((ROOT/DIAGNOSTIC).read_text())
    prior = json.loads((ROOT/PRIOR).read_text())
    devices = []
    for path in Path('/sys/bus/usb/devices').iterdir():
        if not (path/'idVendor').is_file():
            continue
        if ((path/'idVendor').read_text().strip(), (path/'idProduct').read_text().strip()) == ('091e','2548'):
            devices.append(path)
    assert len(devices) == 1, 'Expected one Garmin mass-storage USB device'
    path = devices[0]
    private_serial = (path/'serial').read_text().strip()
    # This unit exposes a zero-padded hexadecimal ID, while diagnostics/XML use decimal.
    assert int(private_serial,16) == int(diagnostic['private_unit_ESN']), 'Unit identity differs'
    assert diagnostic['private_unit_ESN_matches_backup_XML'], 'Diagnostic backup identity unverified'
    blob = (path/'descriptors').read_bytes()
    assert blob.hex() == prior['USB']['descriptors_hex'], 'USB presentation differs'
    block_paths = list(path.rglob('block/sda/size'))
    assert len(block_paths) == 1, 'Expected Garmin sda disk under this USB device'
    disk_bytes = int(block_paths[0].read_text().strip()) * 512
    assert disk_bytes == 3879731200, 'Logical disk size differs'
    now = datetime.now(timezone.utc)
    record = {
        'observed_utc':now.isoformat(), 'backup_USB_identity_including_serial_matched':True,
        'private_USB_hex_serial_matches_decimal_diagnostic_ESN':True,
        'exact_target':{'HWID':1352,'software':'8.00'}, 'disk_path_at_test':'/dev/sda',
        'logical_disk_bytes':disk_bytes, 'USB_VID_PID':['091e','2548'],
        'USB_speed_Mbps':float((path/'speed').read_text().strip()),
        'descriptor_sha256':hashlib.sha256(blob).hexdigest(),
        'matches_previous_live_and_original_builder':True, 'prior_live_evidence':PRIOR,
        'source_sha256':{name:digest(name) for name in
            (DIAGNOSTIC,PRIOR,str(Path(__file__).relative_to(ROOT)))},
        'device_files_written':False, 'USB_host_AOA_or_framebuffer_RAM_read':False,
        'scope':'Current kernel sysfs/block metadata only. Private USB hexadecimal serial '
            'compared to decimal diagnostic unit ID already matched to backup XML. '
            'No hardware command, mount, disk file write, Bluetooth, audio or host test.'}
    name = 'evidence/usb-mass-storage-reconnected-'+now.strftime('%Y%m%dT%H%M%S%fZ')+'.json'
    (ROOT/name).write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'evidence':name,'target_matched':True,'descriptor_matched':True,'disk_bytes':disk_bytes}))


if __name__ == '__main__':
    main()
