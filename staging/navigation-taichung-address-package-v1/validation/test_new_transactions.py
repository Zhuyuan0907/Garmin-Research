#!/usr/bin/env python3
"""New small synthetic transactions only; no CLI fake device or physical I/O."""
import ast
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import install_taichung_addresses as install
import device_support as support
import native_address_layout_restore_v1 as restore

RESULTS = []
NAMES = ['00004171.MD2', '00004171.MDR', '00004171.SRT', 'I053061A.GMP', 'I053061A.SRT', 'MAPSOURC.MPS']


def need(value, message):
    if not value:
        raise AssertionError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def fat(name, size, blocks, root=False):
    row = bytearray(512)
    row[0] = 1
    if root:
        row[1:12] = b' ' * 11
        row[16] = 3
    else:
        label, extension = name.split('.')
        row[1:12] = label.encode().ljust(8, b' ') + extension.encode().ljust(3, b' ')
    struct.pack_into('<I', row, 12, size)
    struct.pack_into('<240H', row, 32, *(blocks + [65535] * (240 - len(blocks))))
    return bytes(row)


def image(mdr):
    payloads = {'00004171.MDR': mdr}
    for index, name in enumerate(NAMES):
        payloads.setdefault(name, (name.encode() + bytes([70 + index])) * (11 + index))
    header = bytearray(4096)
    header[16:23] = b'DSKIMG\0'; header[65:72] = b'GARMIN\0'
    header[64] = 8; header[97:99] = bytes([9, 3]); header[510:512] = b'\x55\xaa'
    struct.pack_into('<H', header, 99, 32768); struct.pack_into('<I', header, 458, 262144)
    root_end = 8192
    directory = fat('', root_end, [0, 1], True)
    cursor = 2
    physical = []
    components, tails = {}, {}
    for name in NAMES:
        data = payloads[name]
        count = (len(data) + 4095) // 4096
        blocks = list(range(cursor, cursor + count)); cursor += count
        components[name] = dict(size=len(data), blocks=blocks, parts=1)
        pad = bytes([cursor % 251 + 1]) * ((-len(data)) % 4096)
        tails[name] = pad.hex()
        directory += fat(name, len(data), blocks)
        physical.append(data + pad)
    metadata = bytes(header) + directory.ljust(4096, b'\0')
    return metadata + b''.join(physical), components, tails, metadata


def fixtures():
    old_header = b'ORIGINAL-MDR-METADATA\x00'
    new_header = b'NEW-MDR-METADATA\x00'
    common = bytes(range(256)) * 40 + b'OLD-END'
    old_mdr = old_header + common
    new_mdr = new_header + common + b'APPENDED-INTEGER-HOUSES\x00' * 900
    old, old_components, tails, old_prefix = image(old_mdr)
    new, new_components, new_tails, new_prefix = image(new_mdr)
    previous = bytearray(old)
    previous_at = old_components['00004171.MDR']['blocks'][0] * 4096 + 64
    previous[previous_at:previous_at + 6] = b'NINEOK'
    recipe = dict(schema='garmin-native-layout-restore/v1', original_bytes=len(old), original_sha256=sha(old),
        candidate_bytes=len(new), candidate_sha256=sha(new), original_metadata_bytes=len(old_prefix),
        original_prefix_hex=old_prefix.hex(), original_components=old_components, candidate_components=new_components,
        MDR_ranges=[dict(length=len(old_header), original_hex=old_header.hex()),
                    dict(length=len(common), candidate_offset=len(new_header))], original_tail_hex=tails,
        original_unused_blocks_hex={})
    need(len(new) > len(old), 'Fixture has genuinely different destination size')
    xml = b'<Device xmlns="urn:garmin-test"><Model><PartNumber>006-B1352-00</PartNumber><SoftwareVersion>800</SoftwareVersion></Model><Id>synthetic-test-unit</Id></Device>'
    m = dict(target=dict(device_path=install.TARGET, bundle_path=install.CANDIDATE,
        bytes=len(new), candidate_sha256=sha(new), original_bytes=len(old), original_sha256=sha(old),
        accepted_predecessors=[dict(state='original', bytes=len(old), sha256=sha(old)),
                              dict(state='previous_verified_nine', bytes=len(old), sha256=sha(previous))]),
        device=dict(part_number='006-B1352-00', software_version='800', unit_id_sha256=support.private_hash('synthetic-test-unit')),
        preserved_stock_files=[dict(device_path='.System/protected-license.bin', bytes=len(b'LICENSE-UNCHANGED!'), sha256=sha(b'LICENSE-UNCHANGED!'))],
        required_files=[dict(device_path='Map/unchanged-road.img', bytes=14, sha256=sha(b'ROAD-UNCHANGED'))])
    # Explicit counts independent from the production byte sizes.
    m['required_files'][0]['bytes'] = len(b'ROAD-UNCHANGED')
    return dict(original=old, previous_verified_nine=bytes(previous), candidate=new, recipe=recipe, manifest=m, xml=xml)


class Case:
    def __init__(self, start='original'):
        self.tmp = tempfile.TemporaryDirectory(prefix='new-taichung-transaction-', dir=BASE / 'validation')
        self.root = Path(self.tmp.name)
        (self.root / '.System').mkdir(); (self.root / 'Garmin').mkdir(); (self.root / 'Map').mkdir()
        self.f = fixtures()
        self.target = self.root / install.TARGET
        self.target.write_bytes(self.f[start])
        os.utime(self.target, ns=(1650000000000000000, 1650000000000000000))
        (self.root / 'Garmin/GarminDevice.xml').write_bytes(self.f['xml'])
        (self.root / '.System/protected-license.bin').write_bytes(b'LICENSE-UNCHANGED!')
        (self.root / 'Map/unchanged-road.img').write_bytes(b'ROAD-UNCHANGED')
        self.source = self.root / 'bundled-candidate.img'
        self.source.write_bytes(self.f['candidate'])
        self.prior_mtime = self.target.stat().st_mtime_ns
        self.initial_names = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file())

    def run(self, mode='install', **kw):
        return install.transaction(self.root, self.f['manifest'], self.source, self.f['recipe'], mode, **kw)

    def original(self):
        need(self.target.read_bytes() == self.f['original'], 'Exact smaller original physical bytes')

    def candidate(self):
        need(self.target.read_bytes() == self.f['candidate'], 'Exact larger candidate physical bytes')

    def no_partial(self):
        need(not (self.root / install.PARTIAL).exists(), 'No owned partial remains')

    def preserved(self):
        need((self.root / '.System/protected-license.bin').read_bytes() == b'LICENSE-UNCHANGED!', 'License contents unchanged')
        need((self.root / 'Map/unchanged-road.img').read_bytes() == b'ROAD-UNCHANGED', 'Road contents unchanged')
        need(self.target.stat().st_mtime_ns == self.prior_mtime, 'Original target timestamp preserved')
        names = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file())
        need(names == self.initial_names, 'No complete duplicate backup/recovery copy created')

    def close(self):
        self.tmp.cleanup()


def check(name, callback, start='original'):
    c = Case(start)
    try:
        callback(c)
        RESULTS.append(dict(name=name, passed=True, actual_filesystem=True, synthetic_images=True,
                            fixture_original_bytes=len(c.f['original']), fixture_candidate_bytes=len(c.f['candidate'])))
    finally:
        c.close()


def expect_failure(c, call, committed=False, cleanup_failed=False):
    try:
        call()
    except install.TransactionFailure as error:
        need(error.committed is committed and error.cleanup_failed is cleanup_failed, 'Failure commit/cleanup facts accurate')
        return error
    except install.Refusal:
        need(not committed, 'Early refusal cannot hide a commit')
        return
    raise AssertionError('Unexpected operation acceptance')


def transition(c, mode, desired):
    before_inode = (c.target.stat().st_dev, c.target.stat().st_ino)
    r = c.run(mode)
    need(r['committed'] and r['changed'] and r['readback_verified'], 'Actual atomic transition completed')
    need(before_inode != (c.target.stat().st_dev, c.target.stat().st_ino), 'Live file replaced by different owned inode')
    getattr(c, desired)(); c.no_partial(); c.preserved()


def main():
    output = BASE / 'validation/new-transaction-results.json'
    need(not output.exists(), 'New scope results only')
    check('stock-to-larger-exact-new-image', lambda c: transition(c, 'install', 'candidate'))
    check('accepted-nine-to-larger-exact-new-image', lambda c: transition(c, 'install', 'candidate'), 'previous_verified_nine')
    check('larger-to-stock-different-size-exact-rollback', lambda c: transition(c, 'rollback', 'original'), 'candidate')
    check('accepted-nine-to-stock-compact-recipe-rollback', lambda c: transition(c, 'rollback', 'original'), 'previous_verified_nine')
    def double(c):
        transition(c, 'install', 'candidate'); transition(c, 'rollback', 'original')
        need(c.target.stat().st_size == len(c.f['original']), 'No larger image tail survives rollback')
    check('roundtrip-proves-smaller-file-no-surviving-tail', double)
    def noop(c, mode, expected):
        prior = c.target.stat().st_ino; r = c.run(mode)
        need(not r['changed'] and not r['committed'] and c.target.stat().st_ino == prior, 'No-op leaves target inode unchanged')
        getattr(c, expected)(); c.no_partial(); c.preserved()
    check('new-candidate-install-noop', lambda c: noop(c, 'install', 'candidate'), 'candidate')
    check('stock-rollback-noop', lambda c: noop(c, 'rollback', 'original'))
    def preflight(c):
        before = c.target.read_bytes(); _, r = install.device_preflight(c.root, c.f['manifest'], 'preflight')
        need(r['image_state'] == 'previous_verified_nine' and r['required_free_bytes'] == len(c.f['candidate']) + install.RESERVE_BYTES, 'Readonly uses larger destination free-space requirement')
        need(c.target.read_bytes() == before, 'Readonly preflight never writes target')
    check('readonly-preflight-recognizes-accepted-nine-and-new-size', preflight, 'previous_verified_nine')
    def bad_state(c, size=False):
        c.target.write_bytes(b'unknown' if size else c.f['previous_verified_nine'][:-1] + b'!')
        before = c.target.read_bytes(); expect_failure(c, c.run)
        need(c.target.read_bytes() == before, 'Unknown target bytes left untouched'); c.no_partial()
    check('reject-external-same-size-state', lambda c: bad_state(c))
    check('reject-external-different-size-state', lambda c: bad_state(c, True))
    def no_space(c, mode):
        fake = type('Space', (), {'f_bavail': 1, 'f_frsize': 4096})()
        before = c.target.read_bytes()
        with patch.object(install.os, 'statvfs', return_value=fake): expect_failure(c, lambda: c.run(mode))
        need(c.target.read_bytes() == before, 'Free space rejection before any mutation'); c.no_partial()
    check('install-free-space-measured-with-larger-size', lambda c: no_space(c, 'install'))
    check('rollback-free-space-measured-with-smaller-size', lambda c: no_space(c, 'rollback'), 'candidate')
    mutations = {
        'negative-candidate-offset': lambda r: r['MDR_ranges'].__setitem__(0, dict(length=r['MDR_ranges'][0]['length'], candidate_offset=-1)),
        'short-original-prefix': lambda r: r.__setitem__('original_prefix_hex', r['original_prefix_hex'][:-2]),
        'original-allocation-alias': lambda r: r['original_components']['00004171.SRT']['blocks'].__setitem__(0, r['original_components']['00004171.MDR']['blocks'][0]),
        'candidate-FAT-wrong': lambda r: r['candidate_components']['00004171.MDR'].__setitem__('size', 1),
        'short-component-tail': lambda r: r['original_tail_hex'].__setitem__('I053061A.GMP', ''),
        'recipe-original-sha-mismatch': lambda r: r.__setitem__('original_sha256', '0' * 64),
        'stored-MDR-content-corruption': lambda r: r['MDR_ranges'][0].__setitem__('original_hex', '00' + r['MDR_ranges'][0]['original_hex'][2:]),
        'dual-reconstruction-sources': lambda r: r['MDR_ranges'][0].__setitem__('candidate_offset', 0),
        'unlisted-unused-block': lambda r: r['original_unused_blocks_hex'].__setitem__('999', '00' * 4096),
    }
    for name, mutate in mutations.items():
        def corrupted(c, mutate=mutate):
            mutate(c.f['recipe']); expect_failure(c, c.run); c.original(); c.no_partial(); c.preserved()
        check('recipe-reject-' + name, corrupted)
    def bundled_bad(c):
        c.source.write_bytes(c.f['candidate'][:-1] + b'!')
        expect_failure(c, c.run); c.original(); c.no_partial()
    check('bundle-image-changed-before-transaction', bundled_bad)
    def fault_before(c, event, action):
        def fault(seen):
            if seen == event:action(c)
        expect_failure(c, lambda: c.run(fault=fault)); c.no_partial()
    def stop(c):raise OSError(errno.ENOSPC, 'Synthetic disk full')
    check('written-temp-ENOSPC-keeps-old-target', lambda c: (fault_before(c, 'temporary_image_written_and_synced', stop), c.original()))
    check('precommit-temp-content-change-is-fenced', lambda c: (fault_before(c, 'precommit_identity_and_hashes_verified', lambda c: (c.root / install.PARTIAL).write_bytes(c.f['candidate'][:-1] + b'!')), c.original()))
    check('precommit-XML-content-change-is-fenced', lambda c: (fault_before(c, 'precommit_identity_and_hashes_verified', lambda c: (c.root / 'Garmin/GarminDevice.xml').write_bytes(c.f['xml'] + b'\n')), c.original()))
    check('precommit-protected-license-change-is-fenced', lambda c: (fault_before(c, 'precommit_identity_and_hashes_verified', lambda c: (c.root / '.System/protected-license.bin').write_bytes(b'LICENSE-CHANGED!!')), c.original()))
    def replace_fail(c, after=False):
        real = os.replace
        def replacement(src, dst):
            if after:real(src, dst)
            raise OSError(errno.EIO, 'Synthetic rename response failure')
        with patch.object(install.os, 'replace', side_effect=replacement):expect_failure(c, c.run, committed=after)
        getattr(c, 'candidate' if after else 'original')(); c.no_partial(); c.preserved()
    check('rename-error-before-kernel-commit-cleans-only-owned-temp', lambda c: replace_fail(c))
    check('rename-committed-then-response-error-detects-owned-target', lambda c: replace_fail(c, True))
    def post_error(c):
        def fault(event):
            if event == 'atomic_target_replacement_committed':raise OSError(errno.EIO, 'Synthetic postcommit failure')
        expect_failure(c, lambda: c.run(fault=fault), committed=True)
        c.candidate(); c.no_partial(); c.preserved()
    check('postcommit-observer-error-retains-larger-candidate', post_error)
    def sync_error(c):
        with patch.object(install, 'fsync_directory', side_effect=OSError(errno.EIO, 'Synthetic dir fsync error')):
            expect_failure(c, c.run, committed=True)
        c.candidate(); c.no_partial(); c.preserved()
    check('postcommit-directory-fsync-error-retains-target', sync_error)
    def corrupt_committed(c):
        changed = c.f['candidate'][:-1] + b'!'
        def fault(event):
            if event == 'atomic_target_replacement_committed':c.target.write_bytes(changed)
        expect_failure(c, lambda: c.run(fault=fault), committed=True)
        need(c.target.read_bytes() == changed, 'Postcommit unknown target is retained for recovery, not deleted')
        c.no_partial()
        expect_failure(c, c.run)
        need(c.target.read_bytes() == changed, 'Subsequent operation refuses damaged committed state')
    check('postcommit-full-readback-detects-content-error-and-refuses-next-write', corrupt_committed)
    def streaming_error(c):
        def interrupted(source, recipe, mode):
            yield c.f['candidate'][:4096]
            raise OSError(errno.ENOSPC, 'Synthetic stream ENOSPC')
        with patch.object(install, 'image_blocks', side_effect=interrupted):expect_failure(c, c.run)
        need(c.target.read_bytes() == c.f['previous_verified_nine'], 'Incomplete copy never changes accepted nine target')
        c.no_partial(); c.preserved()
    check('midcopy-ENOSPC-keeps-accepted-nine-and-removes-only-owned-partial', streaming_error, 'previous_verified_nine')
    def rollback_error(c):
        def fault(event):
            if event == 'atomic_target_replacement_committed':raise OSError(errno.EIO, 'Synthetic rollback postcommit error')
        expect_failure(c, lambda: c.run('rollback', fault=fault), committed=True)
        c.original(); c.no_partial(); c.preserved()
    check('rollback-postcommit-error-retains-exact-smaller-stock', rollback_error, 'candidate')
    def partial(c, old=False):
        name = install.OLD_PARTIAL if old else install.PARTIAL
        p = c.root / name; p.write_bytes(b'other-owned-recovery')
        expect_failure(c, c.run); need(p.read_bytes() == b'other-owned-recovery', 'Unrelated recovery not removed'); c.original()
    check('new-recovery-partial-refused-and-retained', lambda c: partial(c))
    check('old-nine-recovery-partial-refused-and-retained', lambda c: partial(c, True))
    helper = (BASE / 'device_support.py').read_bytes()
    prior = (BASE.parents[1] / 'staging/navigation-native-address-supplement-v1/install_address_supplement.py').read_bytes()
    need(helper == prior, 'Unmodified old support exact-byte copy')
    def function_source(raw, name):
        text = raw.decode(); tree = ast.parse(text)
        n = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
        return '\n'.join(text.splitlines()[n.lineno - 1:n.end_lineno])
    need(function_source((BASE / 'install_taichung_addresses.py').read_bytes(), 'execute') == function_source(prior, 'execute'), 'Inherited execute wrapper source exactly unchanged')
    sources = [BASE / 'install_taichung_addresses.py', BASE / 'device_support.py', BASE / 'native_address_layout_restore_v1.py', Path(__file__)]
    result = dict(all_assigned_checks_passed=True, controls=RESULTS, controls_passed=len(RESULTS),
        inherited_helpers_byte_identical=True, inherited_execute_body_byte_identical=True,
        evidence_kind='Actual Python/file transactions on small constructed IMG fixtures; no emulated USB or physical device',
        source_bindings=[dict(path=p.name, bytes=p.stat().st_size, sha256=sha(p.read_bytes())) for p in sources],
        full_device_backup_created=False, physical_operations=False, device_IO=False,
        CLI_mocked_device_mode=False, old_61_suite_rerun=False,
        limits=['Fixture model/XML identity is synthetic and only passed to internal transaction API; no CLI bypass exists.',
                'Physical USB identity/mount/execute helpers inherited unchanged; no physical discovery or device installation done.',
                'Actual larger package loader is validated separately; small controls do not certify navigation UI or routes.'])
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_assigned_checks_passed=True, new_controls_passed=len(RESULTS), helper_copy_equal=True, execute_body_equal=True, device_IO=False)))


if __name__ == '__main__':
    main()
