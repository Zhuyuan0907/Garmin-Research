#!/usr/bin/env python3
"""Only additional exact-r4924 sources needed to identify prefix-bearing tables."""
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
URL = 'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip'
EXPECTED = '6738fb14e5a6f5ab85b99445d82e0d162f51844c50052c71fd29387b3021cdbb'
NAMES = ['Mdr6.java', 'Mdr8.java', 'Mdr12.java', 'Mdr17.java', 'Mdr18.java', 'Mdr19.java',
         'PlacesHeader.java', 'City.java']


def main():
    out = BASE / 'official-prefix-source-receipt-v3.json'
    assert not out.exists()
    data = urllib.request.urlopen(URL, timeout=30).read()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    rows = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in NAMES:
            matches = [n for n in archive.namelist() if n.endswith('/' + name)]
            assert len(matches) == 1, (name, matches)
            payload = archive.read(matches[0])
            target = BASE / 'reference' / name
            assert not target.exists(), name
            with target.open('xb') as stream:
                stream.write(payload)
            rows.append(dict(archive_member=matches[0], path=str(target.relative_to(BASE.parents[1])),
                             sha256=hashlib.sha256(payload).hexdigest()))
    result = dict(all_passed=True, source_url=URL, archive_sha256=EXPECTED,
        archive_bytes=len(data), archive_saved=False, selected_sources=rows,
        prior_MDR_query_or_candidate_hash_repeated=False, device_IO=False)
    with out.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=True, selected_source_count=len(rows), receipt=str(out))), flush=True)


if __name__ == '__main__':
    main()
