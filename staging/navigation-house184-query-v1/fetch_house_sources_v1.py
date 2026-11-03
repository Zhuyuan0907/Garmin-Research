#!/usr/bin/env python3
"""Extract selected exact official r4924 sources from an in-memory archive."""
import hashlib
import io
import json
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
URL = 'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip'
EXPECTED = '6738fb14e5a6f5ab85b99445d82e0d162f51844c50052c71fd29387b3021cdbb'
REQUESTED = {'HousenumberGenerator.java', 'HousenumberElem.java', 'HousenumberMatch.java',
    'HousenumberRoad.java', 'ExtNumbers.java', 'CityInfo.java', 'ZipCodeInfo.java',
    'Numbers.java', 'NumberPreparer.java', 'NumberReader.java', 'NETFileReader.java',
    'NETHeader.java', 'RoadDef.java', 'BitReader.java', 'BitWriter.java',
    'StyledConverter.java', 'MapRoad.java'}


def main():
    out = BASE / 'official-house-source-receipt-v1.json'
    assert not out.exists(), 'One-shot source extraction already completed'
    with urllib.request.urlopen(URL, timeout=30) as response:
        blob = response.read()
    assert len(blob) == 2527135 and hashlib.sha256(blob).hexdigest() == EXPECTED
    reference = BASE / 'reference'
    reference.mkdir(exist_ok=False)
    files, found = {}, set()
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for name in archive.namelist():
            basename = Path(name).name
            if basename in REQUESTED and '/src/' in name:
                assert basename not in found, 'Ambiguous source basename'
                found.add(basename)
                data = archive.read(name)
                with (reference / basename).open('xb') as stream:
                    stream.write(data)
                files[basename] = dict(archive_path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    result = dict(fetched_utc=datetime.now(timezone.utc).isoformat(), official_archive_url=URL,
        archive_sha256=EXPECTED, archive_bytes=len(blob), archive_saved_to_disk=False,
        selected_sources=files, missing_requested_sources=sorted(REQUESTED - found),
        whole_IMG_backup_or_firmware_read=False, candidate_or_canonical_modified=False)
    with out.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(receipt=str(out), selected_sources=len(files), missing=sorted(REQUESTED-found))), flush=True)


if __name__ == '__main__':
    main()
