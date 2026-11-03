#!/usr/bin/env python3
"""Fetch only the exact official r4924 writer/layout sources, once."""
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
URL = 'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip'
EXPECTED = '6738fb14e5a6f5ab85b99445d82e0d162f51844c50052c71fd29387b3021cdbb'
NAMES = ['Mdr5.java', 'Mdr5Record.java', 'Mdr7.java', 'Mdr7Record.java', 'Mdr2x.java',
    'MdrMapSection.java', 'MdrSection.java', 'MDRFile.java', 'MDRHeader.java', 'Mdr1.java',
    'Mdr1Record.java', 'Mdr20.java', 'Mdr21.java', 'Mdr22.java', 'Mdr29.java', 'Mdr28.java',
    'Mdr25.java', 'Mdr23.java', 'Mdr24.java', 'Mdr13.java', 'Mdr14.java', 'Mdr15.java',
    'Section.java', 'Sort.java', 'LBLHeader.java', 'Label.java', 'SrtTextReader.java',
    'MdrBuilder.java', 'CodeFunctions.java', 'Utf8Decoder.java', 'Utils.java']


def main():
    out = BASE / 'official-source-receipt-v2.json'
    assert not out.exists()
    data = urllib.request.urlopen(URL, timeout=30).read()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    rows = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in NAMES:
            members = [n for n in archive.namelist() if n.endswith('/' + name)]
            # Utils has more than one package; the IMG pointer helper is exact.
            if name == 'Utils.java':
                members = [n for n in members if n.endswith('/imgfmt/Utils.java')]
            assert len(members) == 1, (name, members)
            payload = archive.read(members[0])
            target = BASE / 'reference' / name
            if target.exists():
                assert target.read_bytes() == payload
            else:
                with target.open('xb') as stream:
                    stream.write(payload)
            rows.append(dict(archive_member=members[0], path=str(target.relative_to(BASE.parents[1])),
                             sha256=hashlib.sha256(payload).hexdigest()))
    result = dict(all_passed=True, source_url=URL, archive_sha256=EXPECTED,
                  archive_bytes=len(data), archive_saved=False, selected_sources=rows,
                  PointerSizes_location='MdrSection.java nested static class',
                  old_suite_or_candidate_hashing=False, device_IO=False)
    with out.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=True, selected_source_count=len(rows), receipt=str(out))), flush=True)


if __name__ == '__main__':
    main()
