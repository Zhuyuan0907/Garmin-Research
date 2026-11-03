#!/usr/bin/env python3
"""Lossless whitespace compaction of NEW unsealed JSON, never source files."""
import hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent
changes=[]
for f in sorted(p.glob('*.json')):
    b=f.read_bytes();x=json.loads(b)
    c=(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    if len(c)<len(b):
        assert json.loads(c)==x
        f.write_bytes(c)
        changes.append({'name':f.name,'old_bytes':len(b),'new_bytes':len(c),
           'old_SHA256':hashlib.sha256(b).hexdigest(),'new_SHA256':hashlib.sha256(c).hexdigest()})
receipt={'scope':'Only this NEW namespace, no old sealed sources modified','same_JSON_values':True,
 'operation':'Whitespace-only UTF8 JSON serialization; original field values/types retained, no stream or IMG reads.',
 'changed_files':changes,'total_scope_bytes_after_compaction':sum(f.stat().st_size for f in p.iterdir() if f.is_file())}
(p/'lossless-compaction-receipt.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps({'files_compacted':len(changes),'same_JSON_values':True,'scope_bytes_after':sum(f.stat().st_size for f in p.iterdir() if f.is_file())}))
