"""One disabled local map control and full exact stock reconstruction.

Runs pinned pure Python map-data helpers. No device, firmware, guest, audio,
service, archive, or second full backup operations are included.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-AP-coherent-expanded4K-actual-restore-v1'
CANDIDATE = OUT / 'coherent-expanded4K.img.disabled'
UTIL = 'scripts/verify_actual_coherent8k_map_restore_v1.py'
MAT = 'scripts/materialize_ap_header_control_v1.py'
PREP = 'staging/navigation-AP-coherent-expanded4K-restore-binding-preparation-v2/'
API = PREP + 'expanded_4k_stock_restore.py'
BINDING = PREP + 'expanded4K-stock-restore-binding.json'
RECIPE = 'staging/navigation-country-layout-restore-v2/restore-layout.json.gz'
PINS = {
    UTIL: '8ca8d42acacfb4e5680495949639c380ca7df9992bb0b0785c969478aa169f70',
    MAT: 'dfbf182f4d1b40fc4315c5568a7e92c521c35d1c764bc1946e53269f7f958142',
    API: 'b10b1c84a2328440653fa23cd355aa28fc74d5b702061e70a2cbe1a376c0118b',
    BINDING: '2d63bdac398468dd23d4ce6fff9179f3a13502fc8ec9f66445ccc3e1a6f10192',
    PREP + 'final-scope-summary.json': '8ecf29ed117c0a3a470cf35bbd4e4bd0faea920809f62934d3b672dd0465b292',
    PREP + 'sealed-files.json': '815389891d73160d6b8769f7e354e114b194a589dcddc4a7e1234da67e24c175',
    'staging/navigation-AP-header-control-materializer-independent-review-v1/proof.json':
        '9fa96cf0f4596b90a1c25c753347261fe74390a8721684268db71c948236b5c3',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snap(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, s.st_nlink, s.st_mode]


def save(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    require(len(raw) <= 65536, 'Small output cap')
    p = OUT / name
    with p.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    p.chmod(0o444)
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def load_inputs():
    values = {}
    receipts = []
    for name, pin in PINS.items():
        p = ROOT / name
        before = p.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 65536,
                'Small regular pinned input')
        with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
            require(snap(os.fstat(f.fileno())) == snap(before), 'Opened input stat')
            raw = f.read(65537)
            require(f.read(1) == b'', 'Small input EOF')
        require(len(raw) == before.st_size and sha(raw) == pin
                and snap(p.lstat()) == snap(before), 'Input hash and stable stat')
        values[name] = raw
        receipts.append({'path': name, 'bytes': len(raw), 'sha256': pin})
    return values, receipts


def module(name, path, raw):
    m = types.ModuleType(name)
    m.__file__ = str(ROOT / path)
    sys.modules[name] = m
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m


def main():
    require(not OUT.exists(), 'Single-use namespace must be absent')
    OUT.mkdir(mode=0o700)
    phase = 'preflight'
    state = {}
    counters = {'fresh_complete_hash_bytes': 0, 'bounded_candidate_read_bytes': 0,
                'bounded_candidate_reads': 0, 'fresh_complete_hash_events': 0}
    try:
        raw, receipts = load_inputs()
        util = module('_root_closed_map_utilities_expanded4k', UTIL, raw[UTIL])
        mat = module('_root_closed_materializer_expanded4k', MAT, raw[MAT])
        api = module('_root_closed_expanded4k_restore', API, raw[API])
        summary = json.loads(raw[PREP + 'final-scope-summary.json'])
        require(summary['finite_preparation_closed']
                and summary['final_API']['SHA256'] == PINS[API]
                and summary['binding']['SHA256'] == PINS[BINDING], 'Closed final API binding')
        controls, catalog_receipts = mat.load_catalog()
        control = controls['expanded_fourK_geometry']
        require(control.size == api.CANDIDATE_BYTES
                and control.virtual_sha256 == api.CANDIDATE_SHA, 'Exact fixed 4K control')
        small_bytes = sum(r['bytes'] for r in receipts + catalog_receipts)
        require(small_bytes + api.RECIPE_BYTES + len(raw[BINDING]) <= util.SMALL_INPUT_CAP,
                'Complete small input budget including recipe')
        free = os.statvfs(OUT)
        require(free.f_bavail * free.f_frsize > 3 * control.size, 'Local disk reserve')

        class Sink(util.ReceiptSink):
            def extend(self, values):
                for value in values:
                    self.append(value)

        check = Sink()
        check.extend([{'purpose': 'protocol_preflight', 'bytes': 0}])
        require(check.count == 1 and check.bytes == 0, 'append/extend protocol checked')
        save('execution-preflight.json', {
            'prerequisite_pins': PINS, 'small_input_bytes_before_recipe': small_bytes,
            'max_current_memory_KiB': util.MAX_CURRENT_MEMORY_KIB,
            'current_memory': util.memory(), 'restore_read_cap': util.RESTORE_ACTUAL_READ_CAP,
            'total_IMG_read_cap': util.TOTAL_IMG_READ_CAP, 'new_disabled_candidate_files': 1,
            'source_and_helper_guards_unchanged': True, 'device_IO': False,
            'native_guest': False, 'audio': False, 'service_changes': False})
        phase = 'materialization'
        print(json.dumps({'phase': phase, 'new_disabled_candidate_bytes': control.size}), flush=True)
        state = mat._materialize_control(control, CANDIDATE)
        require(state['all_handles_closed'] and state['published']
                and state['actual_saved_output_fullhash_verified'], 'Saved full readback complete')
        save('actual-materialization-receipt.json', state)
        before = CANDIDATE.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size == control.size
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o444,
                'One readonly exact candidate')
        descriptor = {'path': str(CANDIDATE.relative_to(ROOT)), 'bytes': control.size,
                      'sha256': control.virtual_sha256, 'final_stat': snap(before),
                      'changed_byte_offsets': list(control.changed_offsets),
                      'all_nonheader_bytes_unchanged': True, 'installed': False, 'installable': False}
        save('actual-control-output-descriptor.json', descriptor)

        # Observe completed read primitives in the unchanged final API. This
        # does not substitute a stream, alter the helper, or mint an input witness.
        def observer(frame, event, value):
            if event != 'return' or frame.f_globals is not api.__dict__:
                return
            if frame.f_code.co_name == '_hash_file_fresh' and type(value) is dict:
                counters['fresh_complete_hash_bytes'] += value['bytes']
                counters['fresh_complete_hash_events'] += 1
            elif frame.f_code.co_name == '_read' and type(value) is bytes:
                stream = frame.f_locals.get('stream')
                if getattr(stream, 'name', None) == str(CANDIDATE):
                    counters['bounded_candidate_read_bytes'] += len(value)
                    counters['bounded_candidate_reads'] += 1
            require(counters['fresh_complete_hash_bytes'] + counters['bounded_candidate_read_bytes']
                    <= util.RESTORE_ACTUAL_READ_CAP, 'Observed actual restore read bound')

        phase = 'fresh_full_candidate_hash_and_complete_stock_restore'
        print(json.dumps({'phase': phase, 'saved_candidate_SHA': state['actual_saved_output_sha256']}), flush=True)
        sink = Sink()
        h = hashlib.sha256()
        count = blocks = 0
        require(sys.getprofile() is None, 'No preexisting profiler')
        sys.setprofile(observer)
        try:
            for block in api.restored_stock_blocks(CANDIDATE, ROOT / RECIPE, ROOT / BINDING,
                                                  PINS[BINDING], sink):
                require(len(block) == 4096, 'Exact stock physical block')
                h.update(block)
                count += len(block)
                blocks += 1
                if blocks % 2048 == 0:
                    util.memory()
        finally:
            sys.setprofile(None)
        require(count == api.STOCK_BYTES and h.hexdigest() == api.STOCK_SHA, 'Full stock EOF SHA')
        require(counters['fresh_complete_hash_events'] == 1
                and counters['fresh_complete_hash_bytes'] == control.size, 'One fresh complete input witness')
        actual_reads = counters['fresh_complete_hash_bytes'] + counters['bounded_candidate_read_bytes']
        require(sink.bytes == actual_reads, 'Independent observer and returned logical receipts agree')
        require(snap(CANDIDATE.lstat()) == snap(before), 'Candidate stable through EOF')
        total = state['source_bytes_read'] + state['saved_output_bytes_read'] + actual_reads
        require(total <= util.TOTAL_IMG_READ_CAP, 'Complete measured IMG read budget')
        proof = {
            'schema': 'actual-coherent-expanded4K-materialization-and-stock-restore/v1',
            'all_assigned_checks_passed': True, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'prerequisite_pins': PINS, 'candidate': descriptor,
            'actual_saved_output_SHA_verified': state['actual_saved_output_sha256'],
            'fresh_second_complete_candidate_SHA_verified': api.CANDIDATE_SHA,
            'original_source_full_SHA_verified': state['source_actual_full_sha256'],
            'exact_stock_bytes': count, 'exact_stock_blocks': blocks, 'exact_stock_SHA256': h.hexdigest(),
            'production_final_API_executed_unchanged': True, 'actual_input_stat_tied_to_fresh_hash_through_EOF': True,
            'actual_read_counters': counters, 'actual_candidate_verify_restore_reads': actual_reads,
            'actual_total_IMG_reads': total, 'total_IMG_read_cap': util.TOTAL_IMG_READ_CAP,
            'stock_read_receipts': sink.summary(), 'current_memory': util.memory(),
            'source_unchanged': state['source_unchanged'], 'all_handles_closed': True,
            'new_full_candidate_files': 1, 'streamed_stock_image_saved': False,
            'second_full_backup_created': False, 'old_strict_helper_and_guards_unchanged': True,
            'device_IO': False, 'native_guest': False, 'firmware_execution': False,
            'audio': False, 'service_changes': False, 'installed': False, 'installable': False,
            'checksum_policy_verified': False, 'Garmin_UI_renderer_verified': False,
            'road_loss_rootcause_proven': False, 'full_Taiwan_update_complete': False, 'full_goal_complete': False}
        saved = save('proof.json', proof)
        print(json.dumps({'all_passed': True, 'proof': saved, 'candidate_SHA256': api.CANDIDATE_SHA,
                          'stock_SHA256': h.hexdigest(), 'actual_total_IMG_reads': total,
                          'device_IO': False}), flush=True)
    except BaseException as exc:
        sys.setprofile(None)
        save('failure.json', {'phase': phase, 'error_type': type(exc).__name__, 'error': str(exc),
                             'materializer_state': state if state else getattr(exc, 'receipt', {}),
                             'observed_read_counters': counters, 'no_automatic_retry': True,
                             'device_IO': False, 'old_sources_preserved': True})
        raise


if __name__ == '__main__':
    main()
