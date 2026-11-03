"""One bounded capture of pinned ordinary source/preparation; no analyzer run."""
from pathlib import Path
import json
from bounded_review_io import Reader

OUT = Path(__file__).resolve().parent
V4 = 'staging/navigation-v3-reachable-suffix-compaction-current-mm-v4/'
V3 = 'staging/navigation-v3-reachable-suffix-compaction-root-observed-v3/'
INPUTS = [
    ('v4-prepared-files.json', V4+'prepared-files.json', 4825, 'c280de5f6888ea334a4527d5e03613dd86898db2752eb9ed80f220b0d72e94ef'),
    ('v4-observed-analyzer.py.txt', V4+'observed_analyzer.py', 22702, 'ad46dda03730cab4a73e39346fd597b13bc91604a811147840499a123baa3e04'),
    ('v3-observed-analyzer.py.txt', V3+'observed_analyzer.py', 20555, '6bf697390bf3440843cd33257c99e9c4de05d828b23122506cf4906d38fcd943'),
    ('core-analyze-reachable.py.txt', 'staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py', 27566, 'a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274'),
    ('mapper-prepare-control.py.txt', 'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py', 35380, 'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'),
    ('memory-measurement-evidence.json', V4+'memory-measurement-evidence.json', 3756, '697eb08139c25c23d656b1ed5e1721565be6d61b054b7b13425f72626f2d20d5'),
    ('producer-static-source-review.json', V4+'static-source-review.json', 1687, 'de7561f4ed9b4be3fb4d4b8285c3c94299fad179457f47fa73cbb8f7596cc90a'),
    ('v4-prepared-source.json', V4+'prepared-source.json', 3747, 'a94664848017d4b64171797569734dc284905ac5b411aadfb4a35a7ebcec603e'),
    ('HANDOFF-prepared.md', V4+'HANDOFF-prepared.md', 3586, None),
    ('v3-actual-failure.json', V3+'actual-failure.json', 2250, '9c2e22b5ccfe05c5b3667e621a3475a8e9f154a689878dabadfaa08fea62fbd4'),
]

def all_rows(obj):
    if isinstance(obj, dict):
        if 'path' in obj:
            yield obj
        for value in obj.values():
            yield from all_rows(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from all_rows(value)

def main():
    r = Reader()
    captured = OUT / 'captured-inputs'
    captured.mkdir(exist_ok=True)
    initial = json.loads((OUT / 'input-read-failure.json').read_text())
    assert initial['external_artifact_bytes'] == 4825
    assert len(initial['reads']) == 1
    sealraw = (captured / INPUTS[0][0]).read_bytes()
    import hashlib
    assert hashlib.sha256(sealraw).hexdigest() == INPUTS[0][3]
    seal = json.loads(sealraw)
    # Continue the partial ordinary capture; do not reread the first artifact.
    r.total = initial['external_artifact_bytes']
    try:
        for label, path, size, digest in INPUTS[1:]:
            expected_stat = None
            expected_mode = None
            if seal is not None:
                rows = [row for row in all_rows(seal) if row['path'] == path]
                if rows:
                    assert len(rows) == 1
                    row = rows[0]
                    digest = row.get('SHA256', row.get('sha256', digest))
                    assert digest
                    expected_stat = row.get('stat_at_seal', row.get('stat'))
                    expected_mode = row.get('mode')
            raw = r.read(path, digest, size, expected_stat, expected_mode)
            (captured / label).write_bytes(raw)
            if label == 'v4-prepared-files.json':
                seal = json.loads(raw)
        r.assert_unchanged()
        from bounded_review_io import ROOT, fingerprint
        for row in initial['reads']:
            assert fingerprint((ROOT / row['path']).stat()) == row['stat_after']
        result = {'all_pins_passed': True, 'read_limit_bytes': 131072,
                  'external_artifact_bytes': r.total,
                  'initial_partial_capture_bytes': initial['external_artifact_bytes'],
                  'corrected_continuation_bytes': sum(row['bytes'] for row in r.reads),
                  'reads': initial['reads'] + r.reads,
                  'all_handles_closed': True,
                  'scanner_IMG_MAIN_PBF_CPU_guest_audio_device': 0}
        (OUT / 'input-read-receipts.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'all_pins_passed': True, 'bytes': r.total,
                          'files': len(r.reads), 'no_analyzer_execution': True,
                          'all_handles_closed': True}))
    except BaseException as exc:
        (OUT / 'input-read-failure.json').write_text(json.dumps({
            'error': str(exc), 'external_artifact_bytes': r.total,
            'reads': r.reads, 'no_analyzer_execution': True}, indent=2)+'\n')
        raise

if __name__ == '__main__':
    main()
