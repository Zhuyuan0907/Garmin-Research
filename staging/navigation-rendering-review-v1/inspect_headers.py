#!/usr/bin/env python3
"""Read only directories/public headers, and unlocked OSM level tables. No full map copying."""
from pathlib import Path
import mmap,struct,json,datetime,re,hashlib
ROOT=Path('/root/garmin');OUT=ROOT/'staging/navigation-rendering-review-v1'

class Img:
 def __init__(self,p):
  self.p=p; self.f=p.open('rb');self.d=mmap.mmap(self.f.fileno(),0,access=mmap.ACCESS_READ)
  d=self.d;assert d[0]==0 and d[16:23]==b'DSKIMG\0' and d[65:72]==b'GARMIN\0'
  self.bs=1<<(d[97]+d[98]);first=d[64]*512;end=struct.unpack_from('<I',d,first+12)[0];assert first<end<=len(d)
  self.dirhash=hashlib.sha256(d[:end]).hexdigest();self.files={};self.readbytes=end
  for o in range(first,end,512):
   e=d[o:o+512]
   if e[0]==0 or e[16]==3:continue
   assert e[0]==1
   n=e[1:9].decode().strip()+'.'+e[9:12].decode().strip();part=struct.unpack_from('<H',e,17)[0]
   if part==0:self.files[n]={'bytes':struct.unpack_from('<I',e,12)[0],'blocks':[],'parts':0}
   f=self.files[n];assert f['parts']==part;f['parts']+=1;f['blocks'] += [v for v in struct.unpack_from('<240H',e,32) if v!=65535]
 def read(self,n,o,size):
  f=self.files[n];assert 0<=o<=o+size<=f['bytes'];self.readbytes+=size
  i,j=o//self.bs,(o+size+self.bs-1)//self.bs
  b=b''.join(self.d[v*self.bs:(v+1)*self.bs] for v in f['blocks'][i:j]);return b[o%self.bs:o%self.bs+size]
 def close(self):self.d.close();self.f.close()

def s24(d):
 x=int.from_bytes(d,'little');return x-(1<<24) if x&(1<<23) else x

def inspect(p):
 img=Img(p);res={'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'fresh_directory_sha256':img.dirhash,'components':{n:f['bytes'] for n,f in img.files.items()},'TRE_headers':[]}
 try:
  for n,f in img.files.items():
   ext=n.rsplit('.',1)[1]
   if ext=='TRE':heads=[(n,0)]
   elif ext=='GMP':
    h=img.read(n,0,57);assert h[2:12]==b'GARMIN GMP';off=struct.unpack_from('<I',h,25)[0];heads=[(n,off)] if off else []
   else:continue
   for n,off in heads:
    h=img.read(n,off,188);assert h[2:12]==b'GARMIN TRE'
    levelpos,levelsize,subdivpos,subdivsize=struct.unpack_from('<4I',h,33)
    b={'component':n,'component_offset':off,'header_length':struct.unpack_from('<H',h)[0],'flags_byte13':h[13],'level_table_offset':levelpos,'level_table_bytes':levelsize,'subdivision_table_bytes':subdivsize,'poi_flags':h[63],'display_priority':int.from_bytes(h[64:67],'little'),'bounds_deg':{'north':s24(h[21:24])*360/(1<<24),'east':s24(h[24:27])*360/(1<<24),'south':s24(h[27:30])*360/(1<<24),'west':s24(h[30:33])*360/(1<<24)}}
    if h[13]&128:b['levels']='not decoded: stock protected TRE'
    else:
     assert levelsize%4==0 and levelsize<512
     # GMP header section offsets are absolute within GMP, standalone offsets within TRE.
     raw=img.read(n,levelpos,levelsize)
     b['level_table_sha256']=hashlib.sha256(raw).hexdigest();b['levels']=[{'level':raw[x]&127,'inherited_bit':bool(raw[x]&128),'resolution':raw[x+1],'subdivisions':struct.unpack_from('<H',raw,x+2)[0]} for x in range(0,len(raw),4)]
    res['TRE_headers'].append(b)
  res['bounded_bytes_read']=img.readbytes
 finally:img.close()
 return res

if __name__=='__main__':
 paths=[ROOT/f'staging/navigation-repair-v2/compiled/{70530000+i}.img' for i in range(1,37)]
 paths += [ROOT/f'backups/20261002T154458Z/files/.System/{n}' for n in ['gmapprom.img','gmapprom1.img','gmapbmap.img']]
 results=[inspect(p) for p in paths]
 s=(ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/splitter.log').read_text()
 area_pattern=r'Area (\d+) covers \(([^,]+),([^\)]+)\) to \(([^,]+),([^\)]+)\) and contains (\d+) nodes'
 areas=[{'input_map':int(a),'v2_map':70530000+int(a)-70510000,'bounds':[float(b),float(c),float(d),float(e)],'source_node_count':int(f)} for a,b,c,d,e,f in re.findall(area_pattern,s)]
 assert len(areas)==36
 proof={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'fresh bounded IMG directory/header reads for 36 compiled OSM tiles and 3 stock backup images; unlocked level tables only. No device I/O; no protected stock rendering payload decoded','headers':results,'splitter_areas':areas,'total_bounded_bytes_read':sum(x['bounded_bytes_read'] for x in results)}
 (OUT/'header-inventory.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'images':len(results),'bounded_bytes_read':proof['total_bounded_bytes_read'],'tiles_bytes':{'min':min(x['bytes'] for x in results[:36]),'max':max(x['bytes'] for x in results[:36])}}))
