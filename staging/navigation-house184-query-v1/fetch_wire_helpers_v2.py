#!/usr/bin/env python3
"""Select additional r4924 house wire helpers/tests, archive held in RAM only."""
from pathlib import Path
import hashlib, io, json, urllib.request, zipfile
from datetime import datetime, timezone
BASE = Path(__file__).resolve().parent
URL = 'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip'
EXPECTED = '6738fb14e5a6f5ab85b99445d82e0d162f51844c50052c71fd29387b3021cdbb'
WANTED = {'RoadSegmentIndex.java', 'NumberStyle.java', 'VarBitWriter.java'}
out = BASE / 'official-wire-helper-receipt-v2.json'
assert not out.exists()
with urllib.request.urlopen(URL, timeout=30) as response:
    blob = response.read()
assert hashlib.sha256(blob).hexdigest() == EXPECTED
files = {}
with zipfile.ZipFile(io.BytesIO(blob)) as archive:
    for name in archive.namelist():
        basename = Path(name).name
        if basename in WANTED or ('/test/' in name and 'Number' in basename and basename.endswith('.java')):
            assert basename not in files
            data = archive.read(name)
            with (BASE / 'reference' / basename).open('xb') as stream:
                stream.write(data)
            files[basename] = dict(archive_path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
result = dict(fetched_utc=datetime.now(timezone.utc).isoformat(), official_archive_url=URL,
    archive_sha256=EXPECTED, archive_saved=False, selected_sources=files,
    missing=sorted(WANTED-set(files)), number_related_archive_paths=[name for name in archive.namelist()
        if name.endswith('.java') and ('Number' in Path(name).name or 'BitReader' in Path(name).name)])
with out.open('x') as stream:
    stream.write(json.dumps(result, indent=2)+'\n')
print(json.dumps(dict(receipt=str(out), selected_sources=list(files), missing=result['missing'])), flush=True)
