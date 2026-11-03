#!/usr/bin/env python3
import json,mmap,struct,hashlib
from pathlib import Path
p=Path('staging/maps/Taiwan_OSM_20261001_ZhuYuan/manifest.json')
m=json.loads(p.read_text());img=Path(m['image']);out=Path('staging/navigation-search-encoding-v1')
with img.open('rb') as f:
 d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ); bs=1<<(d[0x61]+d[0x62]);first=d[0x40]*512;end=struct.unpack_from('<I',d,first+12)[0];srt=None;name=None;blocks=[];size=None
 for off in range(first,end,512):
  e=d[off:off+512]
  if e[0]!=1 or e[0x10]==3 or e[9:12]!=b'SRT':continue
  name=e[1:9].decode().strip()+'.SRT'
  if struct.unpack_from('<H',e,0x11)[0]==0:size=struct.unpack_from('<I',e,12)[0]
  blocks += [b for b in struct.unpack_from('<240H',e,32) if b!=0xffff]
 assert size and blocks
 srt=b''.join(d[b*bs:(b+1)*bs] for b in blocks)[:size]
(out/'installed-map.SRT').write_bytes(srt)
hl=struct.unpack_from('<H',srt)[0];h2pos=struct.unpack_from('<I',srt,23)[0];descpos,descsize,subpos,subsize=struct.unpack_from('<4I',srt,h2pos)
print('size',len(srt),'headerlen',hl,'h2pos',h2pos,'desc',descpos,descsize,'sub',subpos,subsize)
print('desc',srt[descpos:descpos+descsize]);print('subheader',srt[subpos:subpos+92].hex(' '))
