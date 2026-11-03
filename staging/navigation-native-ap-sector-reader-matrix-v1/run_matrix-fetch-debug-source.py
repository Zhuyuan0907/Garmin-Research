#!/usr/bin/env python3
"""New bounded actual IMG reader matrix; no mount/renderer/admission claim."""
from pathlib import Path
from collections import Counter
import hashlib,json,struct,time,traceback
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_1176,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
CTX=0xf7b3dc;VOLS=0x8000000;REGIONS=0x8001000;FILE=0x8002000;CACHE=0x8003000;BUCKETS=0x8004000;SECTOR=0x8005000;FATCACHE=0x8006000;OUTER=0x8007000;CHILD=0x8008000;DRIVE=0x8009000;OPS=0x800a000;TCB=0x800b000;OUT=0x800c000;STACK=0x800f000;RETURN=0x10000;BACKEND=0x10220
NAMES=('00004171.MD2','00004171.MDR','00004171.SRT','I053061A.GMP','I053061A.SRT','MAPSOURC.MPS')
INPUTS=[('country_v2_4K','staging/navigation-country-native-candidate-v2/gmapprom1.img','staging/navigation-country-native-candidate-v2/proof.json'),('lane_v3_8K','staging/navigation-country-native-lane-candidate-v3/gmapprom1.img','staging/navigation-country-native-lane-candidate-v3/proof.json'),('expanded_4K_disabled','staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled','staging/navigation-v3-expanded4k-offline-isolation-v1/proof.json')]
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
def need(x,msg):
 if not x:raise ValueError(msg)
def saved(name,obj):
 p=HERE/name
 with p.open('x')as f:json.dump(obj,f,ensure_ascii=False,indent=2);f.write('\n');f.flush()
 return dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))
class Image:
 def __init__(self,p):
  self.path=p;self.before=stat(p);self.f=p.open('rb');self.total=0;self.receipts=[];self.limit=262144;self.size=self.before[2]
  h=self.read(0,512,'actual header');self.h=h
  need(h[0]==0 and h[16:23]==b'DSKIMG\0' and h[65:72]==b'GARMIN\0' and h[510:512]==b'\x55\xaa','exact container signature')
  need(h[97]==9 and h[98] in(3,4),'actual512 sector/4K or8K block')
  self.shift=h[98];self.spb=1<<self.shift;self.block=512*self.spb;self.capblocks=struct.unpack_from('<H',h,99)[0]
  need(self.capblocks*self.spb==struct.unpack_from('<I',h,458)[0] and self.size<=self.capblocks*self.block and self.size%self.block==0,'capacity fields/EOF coherent')
  self.start=h[64]*512;root=self.read(self.start,512,'actual root DIR row');self.end=struct.unpack_from('<I',root,12)[0]
  need(root[0]==1 and root[1:12]==b' '*11 and root[16]==3 and struct.unpack_from('<H',root,17)[0]==0,'canonical root')
  need(self.start+512<=self.end<=131072 and self.end%self.block==0,'bounded root extent')
  meta=root+self.read(self.start+512,self.end-self.start-512,'actual all allocation metadata')
  owners=set(range(self.end//self.block));need(self.blocks(root)==list(range(self.end//self.block)),'root allocation exact')
  self.components={};order=[];last=None
  for off in range(512,len(meta),512):
   r=meta[off:off+512]
   if r[0]==0:need(r==bytes(512),'zero unused row');continue
   need(r[0]==1 and r[16]!=3,'allocated file row')
   name=r[1:9].decode().rstrip() +'.'+r[9:12].decode().rstrip();part=struct.unpack_from('<H',r,17)[0];size=struct.unpack_from('<I',r,12)[0]
   if part==0:
    need(name not in self.components and size>0,'unique nonempty component');self.components[name]=dict(size=size,blocks=[],rows=[]);order.append(name);last=name
   c=self.components[name];need(name==last and part==len(c['rows']) and (part==0 or size==0),'ordered FAT continuation')
   blocks=self.blocks(r)
   for b in blocks:need(b not in owners,'allocation unique');owners.add(b)
   c['blocks']+=blocks;c['rows'].append(dict(sector=(self.start+off)//512,raw=r,part=part))
  need(tuple(order)==NAMES and owners==set(range(self.size//self.block)),'six components complete allocation')
  for c in self.components.values():need(len(c['blocks'])==(c['size']+self.block-1)//self.block and len(c['rows'])==(len(c['blocks'])+239)//240,'component FAT count')
 def blocks(self,r):
  out=[];end=False
  for b in struct.unpack_from('<240H',r,32):
   if b==65535:end=True
   else:need(not end and b<self.size//self.block,'block bounds/sentinel');out.append(b)
  return out
 def read(self,off,count,purpose):
  need(0<=off<=off+count<=self.size and count>=0 and self.total+count<=self.limit,'physical range/read budget')
  self.f.seek(off);raw=self.f.read(count);need(len(raw)==count,'complete actual read');self.total+=count
  self.receipts.append(dict(offset=off,count=count,sha256=sha(raw),purpose=purpose));return raw
 def logical(self,off,count):
  c=self.components['I053061A.GMP'];need(0<=off<=off+count<=c['size'],'GMP logical range');out=bytearray()
  while count:
   ordinal,within=divmod(off,self.block);n=min(count,self.block-within);out+=self.read(c['blocks'][ordinal]*self.block+within,n,'independent actual GMP reference');off+=n;count-=n
  return bytes(out)
 def close(self):
  self.f.close();need(stat(self.path)==self.before,'IMG immutable while bounded handles open')
  return dict(path=str(self.path.relative_to(ROOT)),stat_before=self.before,stat_after=stat(self.path),header_hex=self.h.hex(),metadata_end=self.end,sector_bytes=512,block_shift=self.shift,block_bytes=self.block,declared_blocks=self.capblocks,declared_capacity=self.capblocks*self.block,total_actual_read_bytes=self.total,limit=self.limit,read_operations=len(self.receipts),actual_read_receipts=self.receipts,handle_closed=True)
class VM:
 def __init__(self,image,short=False):
  self.image=image;self.uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB);self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176);self.pages=set();self.visits=Counter();self.events=[];self.mutexes=Counter();self.instructions=0;self.short=short
  windows=[]
  for p in sorted(HERE.glob('windows-*.json')):windows+=json.load(p.open())['windows']
  for w in windows:
   addr=int(w['runtime_start'],0);raw=bytes.fromhex(w['raw_hex']);self.map(addr,len(raw));self.uc.mem_write(addr,raw)
   for i in w['instructions']:
    if 'literal_value'in i:
     a=int(i['literal_address'],0);self.map(a,4);self.put(a,int(i['literal_value'],0))
  for addr,n in [(CTX,104),(0xf00114,300),(0xf0019c,16),(0x105e424,512),(0x105e624,256),(VOLS,0x10000),(RETURN,4096)]:self.map(addr,n)
  for a in [0x3009a0,0x3008b0,0x21b6cc,0x21b6dc,0x358d24]:self.map(a,4)
  # Explicit RAM inventories. They are not live initialized driver objects.
  for o,v in [(0x18,REGIONS),(0x1c,VOLS),(0x20,1),(0x34,FATCACHE),(0x38,len(image.components['I053061A.GMP']['rows'])),(0x40,CACHE),(0x44,CACHE),(0x58,BUCKETS),(0x60,1)]:self.put(CTX+o,v)
  self.put(CACHE+12,0xffffffff);self.put(CACHE+20,SECTOR);self.uc.mem_write(0xf00114,b'\x63');self.uc.mem_write(0x105e424+99*2,b'\x01\x00');self.put(0x105e624+28,OUTER)
  self.put(0xf0019c,1);self.put(0xf001a0,OUTER)
  self.uc.mem_write(OUTER,b'\x01\x00\x01\x00');self.put(OUTER+12,CHILD)
  self.uc.mem_write(CHILD,b'\x01');self.put(CHILD+32,image.size);self.put(CHILD+44,DRIVE);self.put(DRIVE+24,OPS);self.put(OPS+8,BACKEND|1)
  self.uc.mem_write(VOLS,b'\x01\x09'+bytes([image.shift]));self.half(VOLS+0x46,(image.end-image.start)//512);self.half(VOLS+0x48,512);self.half(VOLS+0x4c,image.spb-1);self.half(VOLS+0x4e,image.capblocks);self.half(VOLS+0x5e,0);self.put(VOLS+0x64,240*image.spb);self.put(VOLS+0x6c,image.start//512)
  c=image.components['I053061A.GMP'];self.uc.mem_write(FILE,b'I053061AGMP'+b'\x40');self.put(FILE+12,c['size']);self.put(FILE+20,image.capblocks*image.spb);self.put(FILE+24,c['rows'][0]['sector']);self.half(FILE+38,0)
  for j,r in enumerate(c['rows']):
   a=FATCACHE+j*24;self.uc.mem_write(a,r['raw'][1:12]+b'\x40'+bytes([r['part'],0]));self.half(a+14,r['sector']);self.half(a+16,0)
  self.uc.hook_add(UC_HOOK_CODE,self.observe)
 def map(self,a,n):
  for p in range(a&~4095,(a+n+4095)&~4095,4096):
   if p not in self.pages:self.uc.mem_map(p,4096);self.pages.add(p)
 def put(self,a,v):self.uc.mem_write(a,struct.pack('<I',v&0xffffffff))
 def half(self,a,v):self.uc.mem_write(a,struct.pack('<H',v))
 def word(self,a):return struct.unpack('<I',self.uc.mem_read(a,4))[0]
 def ret(self,value):self.uc.reg_write(UC_ARM_REG_R0,value&0xffffffff);self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))
 def observe(self,uc,a,n,_):
  self.instructions+=1;self.visits[a]+=1
  if a==RETURN:uc.emu_stop();return
  args=[uc.reg_read(r)for r in REGS]
  if a in [0x3009a0,0x3008b0]:
   self.mutexes[args[0]]+=1 if a==0x3009a0 else -1;need(self.mutexes[args[0]]>=0,'balanced fixture mutex');self.ret(0)
  elif a in[0x21b6cc,0x21b6dc]:self.ret(0)
  elif a==0x358d24:self.ret(TCB)
  elif a==BACKEND:
   child,dest,lo,hi=args;count=self.word(uc.reg_read(UC_ARM_REG_SP));need(child==CHILD and hi==0 and 0<count<=512,'lowest driver callback ABI/range')
   need(VOLS<=dest<=dest+count<=STACK,'backend mapped fixture destination')
   actual=count-1 if self.short else count;raw=self.image.read(lo,actual,'actual IMG lowest ops+8 callback');uc.mem_write(dest,raw)
   self.events.append(dict(boundary='fixture physical storage callback ops+8',child=hex(child),destination=hex(dest),offset_low=lo,offset_high=hi,requested=count,returned=len(raw),sha256=sha(raw)))
   self.ret(len(raw))
 def read(self,off,count):
  self.put(FILE+16,off);self.uc.mem_write(OUT,b'\xa5'*(count+32));self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
  for r,v in zip(REGS,[FILE,OUT,count,0]):self.uc.reg_write(r,v)
  try:self.uc.emu_start(0x3324b9,RETURN,timeout=30_000_000,count=500000)
  except BaseException:
   saved('guest-fetch-debug.json',dict(PC=hex(self.uc.reg_read(UC_ARM_REG_PC)),SP=hex(self.uc.reg_read(UC_ARM_REG_SP)),LR=hex(self.uc.reg_read(UC_ARM_REG_LR)),registers=[hex(self.uc.reg_read(r))for r in REGS],last_visits=[hex(a)for a in list(self.visits)[-30:]],guest=self.record(),actual_partial_read_receipts=self.image.receipts));raise
  need(self.uc.reg_read(UC_ARM_REG_PC)==RETURN and self.uc.reg_read(UC_ARM_REG_SP)==STACK,'original return and stack')
  need(not any(self.mutexes.values()),'all fixture locks released');need(bytes(self.uc.mem_read(OUT+count,32))==b'\xa5'*32,'output tail canary')
  return self.uc.reg_read(UC_ARM_REG_R0),bytes(self.uc.mem_read(OUT,count)),self.word(FILE+16)
 def record(self):return dict(original_entry_visits={hex(a):self.visits[a]for a in[0x3324b8,0x123920,0x123f6c,0x11d5d0,0x11d678,0xfeb36,0x2d3380,0x31d2e0,0x31d1ce,0x31cf22,0x1fe010,0x1fdeb2,0x1fde12,0x6e0748,0x38c168,0x3732c8,0x1fde86]},instruction_count=self.instructions,backend_events=self.events,mapped_RAM_pages=len(self.pages),native_driver_control_arithmetic_executed=True,lowest_board_driver_callback_is_explicit_fixture=True)
def main():
 results=[];inputs=[];cases=[('GMP_header',0,57),('same_4K_boundary',4080,48),('same_8K_boundary',8176,48),('same_4K_FAT_part_boundary',983024,48),('same_8K_FAT_part_boundary',1966064,48)]
 for name,path,proofpath in INPUTS:
  p=ROOT/path;proof=json.loads((ROOT/proofpath).read_bytes());pin=proof.get('candidate_sha256',proof.get('output_sha256'));im=Image(p)
  try:
   vm=VM(im);rows=[]
   for label,off,n in cases:
    expected=im.logical(off,n);status,raw,pos=vm.read(off,n);need(status==0 and raw==expected and pos==off+n,'actual native GMP bytes/cursor '+name+' '+label)
    rows.append(dict(case=label,logical_offset=off,bytes=n,native_status=status,output_sha256=sha(raw),expected_actual_sha256=sha(expected),byte_identical=True,cursor=pos))
   positive=vm.record();need(all(positive['original_entry_visits'][hex(a)]>0 for a in[0x123f6c,0x2d3380,0x1fde86,0x38c168]),'real selected path must execute')
   # Separate meaningful guard: same actual profile, no image data read for component EOF.
   eof=VM(im);n=im.components['I053061A.GMP']['size'];status,raw,pos=eof.read(n-8,16);need(status==0xfffffffe and pos==n-8 and raw==b'\xa5'*16 and not eof.events,'original FREAD component EOF rejects before backend')
   # Lower callback returns actual511bytes; originalFEB36/FREAD must propagate failure.
   short=VM(im,short=True);status,raw,pos=short.read(0,57);need(status==0xffffffff and pos==0 and raw==b'\xa5'*57 and len(short.events)==1,'real lower shortread rejected')
   results.append(dict(input=name,inherited_full_IMG_sha256=pin,cases=rows,positive_guest=positive,guards=[dict(case='component EOF',status=eof.record(),native_status=0xfffffffe),dict(case='actual lowest callback shortread511',status=short.record(),native_status=0xffffffff)]))
  finally:inputs.append(im.close())
 need(all(len({r['cases'][i]['output_sha256']for r in results})==1 for i in range(len(cases))),'three input GMP logical windows exact')
 saved('matrix-proof.json',dict(schema='bounded-original-reader-actual-three-IMG-matrix/v1',all_assigned_checks_passed=True,source_sha256=sha(Path(__file__).read_bytes()),inputs=inputs,results=results,limits=dict(per_image_actual_read_bytes=262144,new_MAIN_code_limit=65536),geometry_volume_fields_are_explicit_actual_header_bound_fixtures=True,file_volume_cache_frame_and_driver_inventories_are_synthetic=True,driver_callback_replaces_only_actual_storage_IO=True,original_control_math_and_read_path_not_hooked=True,no_original_mount_or_AP_filename_open_or_renderer_or_admission_executed=True,no_live_storage_device_IO=True,no_whole_IMG_or_MAIN_hash=True,expanded4K_disabled_installable=False,AP_renderer_root_cause_established=False,hardware_driver_registration_unknown=True,handles_closed=True))
 print(json.dumps(dict(all_assigned_checks_passed=True,images=len(inputs),core_cases=len(cases)*len(inputs),guards=2*len(inputs),actual_read_bytes=[x['total_actual_read_bytes']for x in inputs],handles_closed=True)))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  saved('matrix-debug-failure.json',dict(error=repr(e),traceback=traceback.format_exc(),source_sha256=sha(Path(__file__).read_bytes()),no_success_claim=True));raise
