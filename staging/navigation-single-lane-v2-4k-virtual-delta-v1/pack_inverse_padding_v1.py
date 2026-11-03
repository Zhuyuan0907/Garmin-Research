#!/usr/bin/env python3
"""Losslessly compress only cached original inverse padding, no source reads."""
import gzip,hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent;f=p/'inverse-metadata.json'
before=f.read_bytes();x=json.loads(before);old=x.pop('old_component_padding_hex')
b=bytearray();index={}
for name,h in old.items():
    raw=bytes.fromhex(h);index[name]={'offset':len(b),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest()};b.extend(raw)
packed=gzip.compress(bytes(b),mtime=0);assert gzip.decompress(packed)==b
(p/'inverse-original-padding.bin.gz').write_bytes(packed)
x['original_component_padding']={'artifact':'inverse-original-padding.bin.gz','compression':'gzip',
  'artifact_SHA256':hashlib.sha256(packed).hexdigest(),'uncompressed_bytes':len(b),'components':index}
after=(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode();f.write_bytes(after)
reconstructed={name:b[r['offset']:r['offset']+r['bytes']].hex() for name,r in index.items()};assert reconstructed==old
receipt={'same_original_padding_bytes':True,'source_IMG_reads':0,'old_inverse_metadata_bytes':len(before),
 'new_inverse_metadata_bytes':len(after),'old_inverse_metadata_SHA256':hashlib.sha256(before).hexdigest(),
 'new_inverse_metadata_SHA256':hashlib.sha256(after).hexdigest(),'cached_original_padding_bytes':len(b),
 'gzip_artifact_bytes':len(packed),'scope':'Representation only after successful stream; inverse keep/masks/metadata byte runs unchanged.'}
(p/'inverse-padding-pack-receipt.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps(receipt))
