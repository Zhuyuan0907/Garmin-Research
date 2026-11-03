#!/usr/bin/env python3
"""Share exact immutable audit/library/archive copies; preserve every read path."""
import importlib.util
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/garminos-media-compaction-v1'
spec = importlib.util.spec_from_file_location('helpers', ROOT / 'scripts/compact_frozen_traces_v1.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def main():
    output = BASE / 'exact-duplicate-result.json'
    assert not output.exists()
    groups = json.loads((BASE / 'remaining-exact-duplicates.json').read_text())
    before = shutil.disk_usage(ROOT).free
    selected, keys = [], set()
    for group in groups:
        paths = group['paths']
        originals = [p for p in paths if p.startswith('evidence/firmware-analysis/')]
        if len(originals) == 1 and all(p == originals[0] or p.endswith('/previous-audit.json') for p in paths):
            original = originals[0]
        elif all(p.endswith('.jar') and p.startswith('sources/maps/') for p in paths):
            original = next(p for p in paths if '/mkgmap-' in p)
        elif 'sources/deep-research/sbc-2.1.tar.xz' in paths and all(
                p == 'sources/deep-research/sbc-2.1.tar.xz' or '/source-snapshot/' in p for p in paths):
            original = 'sources/deep-research/sbc-2.1.tar.xz'
        else:
            continue
        reference = (ROOT / original).stat()
        for p in paths:
            s = (ROOT / p).stat()
            assert stat.S_IMODE(s.st_mode) == stat.S_IMODE(reference.st_mode), p
            assert helpers.digest(ROOT / p) == group['sha256'], p
            keys.add((s.st_dev, s.st_ino))
        selected.append(dict(original=original, paths=paths, sha256=group['sha256']))
    helpers.reject_open_writers(keys)
    for group in selected:
        original = ROOT / group['original']
        for p in group['paths']:
            source = ROOT / p
            if source == original:
                continue
            assert not source.is_symlink()
            assert helpers.digest(source) == helpers.digest(original) == group['sha256']
            temporary = source.with_name('.exact-duplicate-v1-' + source.name)
            assert not temporary.exists() and not temporary.is_symlink()
            os.symlink(os.path.relpath(original, source.parent), temporary)
            os.replace(temporary, source)
        assert all(helpers.digest(ROOT / p) == group['sha256'] for p in group['paths'])
    os.sync()
    result = dict(all_passed=True, groups=selected, all_read_paths_and_hashes_preserved=True,
                  editable_sources_and_live_executables_excluded=True, device_IO=False,
                  before_free_bytes=before, after_free_bytes=shutil.disk_usage(ROOT).free,
                  created_utc=datetime.now(timezone.utc).isoformat())
    result['freed_bytes'] = result['after_free_bytes'] - before
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
