#!/usr/bin/env python3
"""Only new original date-threshold arithmetic and status-state cases.

Fixtures are already-converted day ordinals and explicit runtime status values.
No live clock, metadata parser, registry mutation, rendering or device result is
invented. All loaded function calls execute their actual instructions.
"""
from pathlib import Path
import hashlib,json,struct,datetime
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
STACK=0x2008000;STOP=0x2108000
INPUTS=['reused-windows.json','windows-callees.json','windows-sources.json','windows-recordparse.json','windows-division.json']

def sha(b):return hashlib.sha256(b).hexdigest()
def word(x):return struct.pack('<I',x)

def main():
 ws=[];pins=[]
 for n in INPUTS:
  b=(HERE/n).read_bytes();d=json.loads(b);ws+=d['windows'];pins.append(dict(path=str((HERE/n).relative_to(ROOT)),sha256=sha(b)))
 def raw(a,n):
  hits=[bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'],16):a-int(w['runtime_start'],16)+n] for w in ws if int(w['runtime_start'],16)<=a and a+n<=int(w['runtime_start'],16)+w['bytes']]
  assert hits and all(x==hits[0]for x in hits),(hex(a),n)
  return hits[0]
 literals={int(i['literal_address'],16):int(i['literal_value'],16)for w in ws for i in w['instructions']if 'literal_value'in i}
 ranges=[(0x1100dc,22),(0x110414,4),(0x2bf474,4),(0x6e49bc,32),(0x10e328,70),(0x2caee2,16),(0x2cb204,4),(0x221644,20),(0x22457c,38),(0x224814,4)]
 def machine(stops):
  uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);uc.ctl_set_cpu_model(UC_CPU_ARM_1176);pages=set()
  for a,n in ranges:
   for p in range(a&~4095,(a+n+4095)&~4095,4096):
    if p not in pages:uc.mem_map(p,4096);pages.add(p)
  for a,n in ranges:
   b=word(literals[a]) if a in [0x2cb204,0x224814] else raw(a,n)
   uc.mem_write(a,b)
  for a,n in [(0xf06000,0x2000),(0x1278000,0x1000),(0x2000000,0x10000),(0x2100000,0x10000)]:uc.mem_map(a,n)
  uc.reg_write(UC_ARM_REG_SP,STACK);trace=[]
  def observer(u,a,n,user):
   trace.append(a)
   if a in stops:u.emu_stop()
  uc.hook_add(UC_HOOK_CODE,observer);return uc,trace
 cases=[]
 def progress():
  (HERE/'new-state-partial-results.json').write_text(json.dumps(dict(source_sha256=sha(Path(__file__).read_bytes()),completed_asserted_cases=cases,case_count=len(cases),all_scheduled_cases_completed=False),indent=2)+'\n')
 base=datetime.date(2001,1,1).toordinal();normal=datetime.date(2026,10,7).toordinal()
 for name,current in [('date_week_normal_fixture',normal),('date_week_base_fixture',base),('date_before_base_sentinel_fixture',base-1),('date_week_low16_truncation_fixture',base+65537*7+3)]:
  uc,tr=machine({0x1100f2});uc.reg_write(UC_ARM_REG_R0,current);uc.reg_write(UC_ARM_REG_R2,base)
  uc.mem_write(STACK+0x70,word(current));uc.mem_write(STACK+0x6c,word(0xa5a5a5a5));uc.emu_start(0x1100dd,0,count=1000)
  assert tr[-1]==0x1100f2
  expected=0xfffe if current<base else ((current-base)//7)&65535
  got=struct.unpack('<I',uc.mem_read(STACK+0x6c,4))[0];assert got==expected
  if current>=base:
   assert 0x2bf474 in tr and 0x6e49bc in tr
   assert uc.reg_read(UC_ARM_REG_R0)==expected and uc.reg_read(UC_ARM_REG_R1)==(current-base)//7
  else:assert 0x2bf474 not in tr and 0x6e49bc not in tr
  cases.append(dict(name=name,entry='0x1100dc',converted_day_ordinal_fixture=current,base_day_ordinal_fixture=base,actual_SP6C=got,expected_SP6C=expected,stop=hex(tr[-1]),instructions=len(tr)-1,trace=[hex(a)for a in tr],original_ARM_div7_executed=current>=base,live_clock_or_IMG_metadata=False))
  progress()
 for name,active,current,slots,expected in [('global_active_match',1,0x1234,[(0,0),(0,0)],1),('only_second_slot_match',0,0,[(0,0),(1,0x1234)],1),('all_active_values_different',1,0x2222,[(1,0x3333),(1,0x4444)],0)]:
  uc,tr=machine({STOP});uc.reg_write(UC_ARM_REG_R0,0x1234);uc.reg_write(UC_ARM_REG_LR,STOP|1)
  gb=0xf06ef4;tb=0x12787c0;uc.mem_write(gb,bytes(40));uc.mem_write(gb+3,bytes([active]));uc.mem_write(gb+0x20,word(current))
  for j,(flag,value)in enumerate(slots):uc.mem_write(tb+j*64+1,bytes([flag]));uc.mem_write(tb+j*64+0x10,word(value))
  before_global=bytes(uc.mem_read(gb,40));before_slots=bytes(uc.mem_read(tb,128))
  uc.emu_start(0x10e329,0,count=10000);assert tr[-1]==STOP and uc.reg_read(UC_ARM_REG_R0)==expected
  assert bytes(uc.mem_read(gb,40))==before_global and bytes(uc.mem_read(tb,128))==before_slots
  assert all(a not in tr for a in [0x1ee156,0x1af428,0x10cc8e,0x10df5a])
  cases.append(dict(name=name,entry='0x10e328',target_fixture='0x1234',global_active=active,global_value=current,two_slot_fixtures=slots,expected_return=expected,actual_return=uc.reg_read(UC_ARM_REG_R0),stop=hex(STOP),instructions=len(tr)-1,trace=[hex(a)for a in tr],status_RAM_preserved=True,unknown_calls_substituted=False))
  progress()
 out=dict(schema='new-original-date-threshold-and-runtime-status-cases/v1',source_sha256=sha(Path(__file__).read_bytes()),inputs=pins,case_count=len(cases),cases=cases,all_passed=True,semantic_hooks=[],observer_stops_only=True,original_ARM_target='0x6e49bc',code_ranges=[dict(start=hex(a),bytes=n)for a,n in ranges],IMG_reads=0,old_guard_mount_reader_cases_notrun=True,record_field6_actual_source_unproved=True,real_clock_or_live_registry_or_MDR_binding=False,AP_renderer_or_regression_rootcause_proved=False,handles_closed=True)
 (HERE/'new-state-cpu-proof.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(dict(all_passed=True,cases=len(cases),original_instructions=sum(c['instructions']for c in cases),IMG_reads=0,handles_closed=True)))

if __name__=='__main__':main()
