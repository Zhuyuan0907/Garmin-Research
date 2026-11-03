#!/usr/bin/env python3
"""Extract pinned saved windows/pages only; do not reopen MAIN or execute guest."""
from pathlib import Path
import hashlib,json,struct
import capstone
from capstone.arm import ARM_OP_MEM,ARM_REG_PC

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent

def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
 windows=[];inputs=[]
 old=ROOT/'staging/navigation-native-ap-map-registry-consumer-v1'
 seal=(old/'sealed-files.json').read_bytes()
 assert sha(seal)=='bedfbf5d3f6ec8ea1e988aa81b1cf0c7533d8e88ac872c50aae9f5e2b83fdce6'
 manifest={r['path']:r for r in json.loads(seal)['files']}
 source=old/'windows-seeds.json';b=source.read_bytes();assert sha(b)==manifest[str(source.relative_to(ROOT))]['sha256']
 d=json.loads(b);inputs.append(dict(path=str(source.relative_to(ROOT)),sha256=sha(b),sealed=True))
 rawwindows=d['windows']
 def original(a,n):
  hits=[bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'],16):a-int(w['runtime_start'],16)+n] for w in rawwindows if int(w['runtime_start'],16)<=a and a+n<=int(w['runtime_start'],16)+w['bytes']]
  assert hits and all(x==hits[0] for x in hits),(hex(a),n)
  return hits[0]
 new=json.loads((HERE/'windows-sources.json').read_bytes())
 def own(a,n):
  hits=[bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'],16):a-int(w['runtime_start'],16)+n] for w in new['windows'] if int(w['runtime_start'],16)<=a and a+n<=int(w['runtime_start'],16)+w['bytes']]
  assert hits;return hits[0]
 literal_values={int(i['literal_address'],16):int(i['literal_value'],16) for w in rawwindows for i in w['instructions'] if 'literal_value'in i}
 def add(name,a,b,mode,lookup):
  cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM if mode=='ARM' else capstone.CS_MODE_THUMB);cs.detail=True
  rows=[]
  for i in cs.disasm(b,a):
   r=dict(address=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
   if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
    lit=(i.address+8 if mode=='ARM'else (i.address+4)&~3)+i.operands[1].mem.disp
    r.update(literal_address=hex(lit),literal_value=hex(struct.unpack('<I',lookup(lit,4))[0]))
   rows.append(r)
  windows.append(dict(name=name,runtime_start=hex(a),bytes=len(b),mode=mode,raw_hex=b.hex(),sha256=sha(b),instructions=rows,linear_disasm_not_controlflow_proof=True))
 # Captured raw bytes include literal pools. Decode only these actual entry/ranges.
 for name,a,n in [('threshold_caller',0x1100aa,72),('registry_kind5_linker',0x10f170,170),('list_record_field6_writer',0x10ee80,34)]:
  def lookup(x,n):
   try:return original(x,n)
   except AssertionError:
    try:return own(x,n)
    except AssertionError:
     assert n==4 and x in literal_values
     return struct.pack('<I',literal_values[x])
  add(name,a,original(a,n),'Thumb',lookup)
 shared=ROOT/'staging/navigation-native-query-provider-full-getter-v1'
 peer_seal=(shared/'sealed-files.json').read_bytes()
 assert sha(peer_seal)=='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'
 peer_manifest={r['path']:r for r in json.loads(peer_seal)['files']}
 rp=shared/'additional-MAIN-capture-receipt.json';rb=rp.read_bytes();rd=json.loads(rb)
 assert sha(rb)==peer_manifest[str(rp.relative_to(ROOT))]['sha256']
 inputs.append(dict(path=str((shared/'sealed-files.json').relative_to(ROOT)),sha256=sha(peer_seal),sealed=True))
 inputs.append(dict(path=str(rp.relative_to(ROOT)),sha256=sha(rb),sealed_at_read=True))
 for page,start,n,mode,name in [(0x2bf000,0x2bf474,4,'ARM','real_ARM_div7_veneer'),(0x32b000,0x32be40,224,'Thumb','shared_registry_descriptor_consumer')]:
  row=next(r for r in rd['reads'] if r['runtime']==page)
  p=shared/f'MAIN-page-{page:08x}.bin';before=stat(p);b=p.read_bytes();assert stat(p)==before and len(b)==4096 and sha(b)==row['sha256']
  assert sha(b)==peer_manifest[str(p.relative_to(ROOT))]['sha256']
  inputs.append(dict(path=str(p.relative_to(ROOT)),sha256=sha(b),bytes=len(b),stat_at_read=before,stat_after_read=stat(p),sealed_at_read=True,content_pinned_to_actual_capture_receipt=True))
  def lookup(a,n):
   assert page<=a and a+n<=page+len(b),(hex(a),n)
   return b[a-page:a-page+n]
  add(name,start,b[start-page:start-page+n],mode,lookup)
 out=dict(schema='saved-code-window-reuse-without-MAIN-reread/v1',source_sha256=sha(Path(__file__).read_bytes()),inputs=inputs,windows=windows,new_MAIN_reads=0,new_IMG_reads=0,shared_pages_seal_pinned=True,shared_page_local_read_bytes=8192,own_sealed_windows_redecoded=True,handles_closed=True)
 (HERE/'reused-windows.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(dict(saved_window_views=len(windows),MAIN_reads=0,IMG_reads=0,shared_page_local_bytes=8192,handles_closed=True)))

if __name__=='__main__':main()
