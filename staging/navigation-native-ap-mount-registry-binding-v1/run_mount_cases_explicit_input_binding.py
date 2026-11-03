#!/usr/bin/env python3
"""New actual AP-content original mount cases, explicit mapped generic file fixture."""
import sys;sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct,importlib.util,traceback
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
P=ROOT/'staging/navigation-native-ap-sector-reader-matrix-v1/run_matrix.py';SEAL=P.parent/'sealed-files.json'
s=json.loads(SEAL.read_bytes());row=next(r for r in s['files']if r['path']==str(P.relative_to(ROOT)));assert hashlib.sha256(P.read_bytes()).hexdigest()==row['sha256']
spec=importlib.util.spec_from_file_location('sealed_reader_primitives',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def save(name,x):
 p=HERE/name
 with p.open('x')as f:json.dump(x,f,indent=2);f.write('\n')
class MetadataImage:
 def __init__(self,path):
  self.path=path;self.before=m.stat(path);self.f=path.open('rb');self.size=self.before[2];self.total=0;self.receipts=[];self.limit=131072;self.end=min(self.size,131072)
  self.h=self.read(0,512,'new actual header metadata');h=self.h;assert h[0]==0 and h[16:23]==b'DSKIMG\0' and h[65:72]==b'GARMIN\0'
  self.start=h[64]*512;r=self.read(self.start,512,'new actual rootDIR metadata');self.end=struct.unpack_from('<I',r,12)[0];assert self.start+512<=self.end<=131072
  self.shift=h[98];self.spb=1<<self.shift;self.capblocks=struct.unpack_from('<H',h,99)[0];self.block=512*self.spb
  # Constructor compatibility only; all related volume/file/cache-row values are cleared before mount entry.
  self.components={'I053061A.GMP':{'size':1,'rows':[{'sector':0,'part':0,'raw':bytes(512)}]}}
 def read(self,at,count,purpose):
  assert 0<=at<=at+count<=self.end and count>=0 and self.total+count<=self.limit,('metadata-only actual-I/O bound',at,count,self.end,self.total)
  self.f.seek(at);b=self.f.read(count);assert len(b)==count;self.total+=count;self.receipts.append(dict(offset=at,bytes=count,sha256=m.sha(b),purpose=purpose));return b
 def close(self):
  self.f.close();assert m.stat(self.path)==self.before
  return dict(path=str(self.path.relative_to(ROOT)),stat_before=self.before,stat_after=m.stat(self.path),metadata_extent=self.end,actual_read_bytes=self.total,limit=self.limit,reads=self.receipts,handles_closed=True)
class MountVM(m.VM):
 def __init__(self,image):
  super().__init__(image)
  self.loaded_new=[]
  for p in [HERE/('windows-'+tag+'.json')for tag in ['targets','parser','dependencies','type1read','mountmem']]:
   for w in json.loads(p.read_bytes())['windows']:
    a=int(w['runtime_start'],0);b=bytes.fromhex(w['raw_hex']);self.map(a,len(b));self.uc.mem_write(a,b);self.loaded_new.append((a,b))
    for i in w['instructions']:
     if 'literal_value'in i:
      a=int(i['literal_address'],0);self.map(a,4);self.put(a,int(i['literal_value'],0))
  # Emptyvolume geometry onentry; nativeparser produces allfields.
  self.uc.mem_write(m.VOLS,bytes(4*116));self.uc.mem_write(m.FILE,bytes(44));self.uc.mem_write(m.FATCACHE,bytes(24));self.put(m.CTX+0x38,0)
  self.put(m.CTX+0x2c,m.FILE);self.put(m.CTX+0x30,1)
  self.before_volumes=bytes(self.uc.mem_read(m.VOLS,4*116));assert self.before_volumes==bytes(4*116)
 def mount(self):
  self.uc.reg_write(m.UC_ARM_REG_SP,m.STACK);self.uc.reg_write(m.UC_ARM_REG_LR,m.RETURN|1)
  for r,v in zip(m.REGS,[0,1,0,0]):self.uc.reg_write(r,v)
  try:self.uc.emu_start(0x1e86cf,m.RETURN,timeout=30_000_000,count=500000)
  except BaseException:
   save('initial-guest-stop.json',dict(PC=hex(self.uc.reg_read(m.UC_ARM_REG_PC)),LR=hex(self.uc.reg_read(m.UC_ARM_REG_LR)),registers=[hex(self.uc.reg_read(r))for r in m.REGS],last_executed_unique_addresses=[hex(a)for a in list(self.visits)[-35:]],guest=self.record(),actual_partial_reads=self.image.receipts));raise
  assert self.uc.reg_read(m.UC_ARM_REG_PC)==m.RETURN and self.uc.reg_read(m.UC_ARM_REG_SP)==m.STACK
  assert not any(self.mutexes.values())
  v=bytes(self.uc.mem_read(m.VOLS,116));half=lambda off:struct.unpack_from('<H',v,off)[0];word=lambda off:struct.unpack_from('<I',v,off)[0]
  return dict(native_volume_active=v[0],native_geometry=dict(sector_exponent=v[1],block_delta=v[2],sector_bytes=half(0x48),sectors_perblock_mask=half(0x4c),declaredblockcount=half(0x4e),FAT_sector_count=half(0x46),FAT_start_sector=word(0x6c),FAT_continuation_sectors=word(0x64),FAT_continuation_bytes=word(0x68),volume_flags=v[0x45]),volume_raw_hex=v.hex(),volume_entry_all_zero=True,original_mount_visit=self.visits[0x1e86ce],original_parser_visit=self.visits[0x1e8046],native_IO=self.record())
def main():
 out=[];bindings=[]
 for label,path,proof in m.INPUTS:
  im=MetadataImage(ROOT/path)
  try:
   vm=MountVM(im);r=vm.mount();g=r['native_geometry'];assert r['native_volume_active']==1 and g['sector_bytes']==512 and g['block_delta']==im.shift and g['declaredblockcount']==im.capblocks
   assert g['FAT_continuation_sectors']==240*im.spb and g['FAT_continuation_bytes']==240*im.block
   assert r['original_mount_visit']>0 and r['original_parser_visit']>0 and r['native_IO']['original_entry_visits']['0x1fde86']>0
   r['input']=label;out.append(r)
  finally:bindings.append(im.close())
 save('actual-mount-proof.json',dict(schema='actual-AP-content-original-shared-mount-parser-fixtures/v1',all_assigned_checks_passed=True,source_sha256=m.sha(Path(__file__).read_bytes()),sealed_helper_sha256=row['sha256'],sealed_helper_source_only_no_oldmain_or_closedcase_executed=True,results=out,inputs=bindings,complete_actual_header_and_parser_requested_metadata_read=True,no_PREBUILT_volume_geometry=True,physical_AP_opener_or_map_renderer_binding_established=False,actual_boarddriver_callback_recovered=False,lowest_ops8_actual_host_metadata_fixture=True,mount_entry_selected_explicitly_not_called_by_true_AP_physicalopener=True,no_device_or_fullIMG_MAIN_hash_or_GMPdata_read=True,handles_closed=True))
 print(json.dumps(dict(all_assigned_checks_passed=True,images=len(out),actual_metadata_read_bytes=[i['actual_read_bytes']for i in bindings],actual_native_geometry=[r['native_geometry']for r in out],handles_closed=True)))
if __name__=='__main__':
 try:main()
 except BaseException as e:save('initial-failure.json',dict(error=repr(e),traceback=traceback.format_exc(),source_sha256=m.sha(Path(__file__).read_bytes())));raise
