#!/usr/bin/env python3
"""Independent FILE ONLY replay; no import of runners, Unicorn or VM helpers.
Original bytes, ELF mapping symbols and complete saved case journals only.
"""
import hashlib,json,struct,sys
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from capstone.arm import (ARM_INS_STR,ARM_INS_STRB,ARM_INS_STRH,ARM_INS_STRD,
 ARM_INS_STM,ARM_INS_STMDA,ARM_INS_STMDB,ARM_INS_STMIB,ARM_INS_PUSH)
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[2]
MAIN_PATH=ROOT/'evidence/firmware-analysis/main_02bd.bin'
MAIN_SHA='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
CHANNELS=0x034e6f08;RECORD=CHANNELS+8*0x208;POOL=0x034e3cf4
MIXER=0x034e5378+8*0x130;DESCRIPTOR=0x09800020;BUFFER=0x09801020
SCRATCH=0x09803f00;INPUT=0x09804020;RESULT=0x08c00020;ACTOR=0x08820000;RETURN=0x08d00000
def sha(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def rel(path):return str(path.relative_to(ROOT))
def dump(path,obj):
 with path.open('x')as f:json.dump(obj,f,indent=2);f.write('\n')
def check(registry):
 for p,h in registry.items():assert sha(ROOT/p)==h,p

class ELF:
 def __init__(self,path):
  self.raw=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',self.raw)
  assert h[0][:7]==b'\x7fELF\x01\x01\x01'and h[1]==2 and h[2]==40 and h[11]==40
  keys=('name_index','type','flags','address','offset','size','link','info','alignment','entry_size')
  self.sections=[dict(zip(keys,struct.unpack_from('<10I',self.raw,h[6]+i*40)),index=i)for i in range(h[12])]
  names=self.data(self.sections[h[13]])
  for s in self.sections:s['name']=self.string(names,s['name_index'])
  table=next(s for s in self.sections if s['type']==2);assert table['entry_size']==16
  strings=self.data(self.sections[table['link']]);self.symbols=[]
  for p in range(table['offset'],table['offset']+table['size'],16):
   n,v,size,info,other,index=struct.unpack_from('<IIIBBH',self.raw,p)
   self.symbols.append(dict(name=self.string(strings,n),value=v,size=size,section=index,type=info&15))
  assert not [s for s in self.symbols if s['name']and s['section']==0]
  self.mapping=sorted((s['value'],s['name'][1],s['section'])for s in self.symbols if s['name'].startswith(('$a','$t','$d')))
 @staticmethod
 def string(raw,n):return raw[n:].split(b'\0',1)[0].decode('ascii')
 def data(self,s):
  assert s['type']!=8
  return self.raw[s['offset']:s['offset']+s['size']]
 def symbol(self,name):
  out=[s for s in self.symbols if s['name']==name];assert len(out)==1,name;return out[0]
 def at(self,address,n):
  out=[s for s in self.sections if s['flags']&2 and s['type']!=8 and s['address']<=address and address+n<=s['address']+s['size']]
  assert len(out)==1,(hex(address),n);s=out[0]
  return self.data(s)[address-s['address']:address-s['address']+n],s
 def mode(self,address):
  _,section=self.at(address,2)
  choices=[(a,m)for a,m,s in self.mapping if s==section['index']and a<=address]
  assert choices,hex(address);return max(choices)[1]

class Replay:
 def __init__(self,row,main,elf):
  self.row=row;self.main=main;self.elf=elf
  self.zones={int(a):bytearray.fromhex(b)for a,b in row['initial_whole_RW_zones'].items()}
  self.final={int(a):bytes.fromhex(b)for a,b in row['final_whole_RW_zones'].items()}
  assert set(self.zones)==set(self.final)and len(self.zones)==16
  self.ordinal=row['initial_ordinal'];self.mode_counts=Counter();self.opcodes={};self.snapshots={}
 def read(self,address,n):
  found=[a for a,b in self.zones.items()if a<=address and address+n<=a+len(b)]
  assert len(found)==1,(hex(address),n);a=found[0];return bytes(self.zones[a][address-a:address-a+n])
 def word(self,address):return struct.unpack('<I',self.read(address,4))[0]
 def write(self,address,b):
  found=[a for a,v in self.zones.items()if a<=address and address+len(b)<=a+len(v)]
  assert len(found)==1,(hex(address),len(b));a=found[0];self.zones[a][address-a:address-a+len(b)]=b
 def original(self,address,n):
  offset=address-0x50000;assert 0<=offset and offset+n<=len(self.main)
  return self.main[offset:offset+n]
 def validate_opcode(self,event):
  pc=int(event['PC'],16);raw=bytes.fromhex(event['opcode_hex']);thumb=event['Thumb']
  assert type(thumb)is bool and len(raw)in(2,4)and pc%2==0
  if 0x50000<=pc<0xc00000:
   assert self.original(pc,len(raw))==raw,(hex(pc),'MAIN bytes')
   expected_thumb=not any(a<=pc<b for a,b in ((0x35b4f4,0x35b548),(0x3732c8,0x37339c),(0x39129c,0x3912f0)))
   assert thumb==expected_thumb,(hex(pc),'original ARM admission range')
   source='MAIN'
  else:
   original,s=self.elf.at(pc,len(raw));assert s['flags']&4 and original==raw,(hex(pc),'ELF bytes')
   mode=self.elf.mode(pc);thunk=self.elf.symbol('mcs_original_pull_thunk')['value']&~1
   if pc in(thunk,thunk+2):
    # Frozen assembly uses .hword; assembler labels these four bytes $d.
    # Independent Thumb authority is function lowbit + exact MAIN prologue.
    assert self.elf.symbol('mcs_original_pull_thunk')['value']&1 and mode=='d'
    assert self.elf.at(thunk,4)[0]==self.original(0x2f9cca,4)==bytes.fromhex('f1b58ab0')
    expected_thumb=True
   else:
    assert mode in('a','t'),(hex(pc),mode);expected_thumb=mode=='t'
   assert thumb==expected_thumb,(hex(pc),'ELF mapping/function ISA')
   source='compiled_ELF'
  if not thumb:assert len(raw)==4 and pc%4==0
  md=Cs(CS_ARCH_ARM,CS_MODE_THUMB if thumb else CS_MODE_ARM);md.detail=True
  instructions=list(md.disasm(raw,pc));assert len(instructions)==1 and instructions[0].size==len(raw)
  i=instructions[0];widths={ARM_INS_STR:{4},ARM_INS_STRB:{1},ARM_INS_STRH:{2},ARM_INS_STRD:{4},
   ARM_INS_STM:{4},ARM_INS_STMDA:{4},ARM_INS_STMDB:{4},ARM_INS_STMIB:{4},ARM_INS_PUSH:{4}}
  assert i.id in widths and event['size']in widths[i.id],(hex(pc),i.mnemonic,event['size'])
  self.mode_counts[(source,'Thumb'if thumb else 'ARM')]+=1
  self.opcodes[(pc,thumb,raw.hex())]=dict(PC=hex(pc),source=source,Thumb=thumb,
    original_opcode_hex=raw.hex(),decoded_instruction=i.mnemonic+' '+i.op_str)
 def cold_initialization(self):
  expected={a:bytearray(len(b))for a,b in self.zones.items()}
  data=self.original(0xcb1980,0x7224c);expected[0xf00000][:len(data)]=data
  for s in self.elf.sections:
   if not s['flags']&2 or s['flags']&4 or not s['size']or s['type']==8:continue
   found=[a for a,b in expected.items()if a<=s['address']and s['address']+s['size']<=a+len(b)]
   assert len(found)==1,s['name'];a=found[0]
   expected[a][s['address']-a:s['address']-a+s['size']]=self.elf.data(s)
  before_events=[e for e in self.row['declared_fixture_mutations']if e['ordinal']<=self.ordinal]
  assert [e['ordinal']for e in before_events]==list(range(1,self.ordinal+1))
  for e in before_events:
   a=int(e['address'],16);before=bytes.fromhex(e['before_hex']);after=bytes.fromhex(e['after_hex']);assert len(before)==len(after)
   base=next(base for base,b in expected.items()if base<=a and a+len(before)<=base+len(b))
   off=a-base;assert bytes(expected[base][off:off+len(before)])==before
   expected[base][off:off+len(after)]=after
  for a,b in expected.items():assert bytes(b)==self.read(a,len(b)),('unrecorded initial mutation',hex(a))
 def run(self,checkpoints):
  events=sorted([e for e in self.row['CPU_store_journal']+self.row['declared_fixture_mutations']if e['ordinal']>self.ordinal],key=lambda e:e['ordinal'])
  assert [e['ordinal']for e in events]==list(range(self.ordinal+1,self.ordinal+len(events)+1))
  if self.ordinal in checkpoints:self.snapshots[self.ordinal]={a:bytes(b)for a,b in self.zones.items()}
  for e in events:
   a=int(e['address'],16);before=bytes.fromhex(e['before_hex']);n=len(before)
   assert self.read(a,n)==before,('before image',e['ordinal'],hex(a))
   assert not RETURN<=a<a+n<=RETURN+4096,'sentinel is actually RX; no writes permitted'
   if e['event_type']=='actual_CPU_store':
    assert n==e['size'];self.validate_opcode(e)
    after=(e['value']&((1<<(8*n))-1)).to_bytes(n,'little')
   else:assert e['event_type']=='declared_host_fixture';after=bytes.fromhex(e['after_hex']);assert len(after)==n
   self.write(a,after);self.ordinal=e['ordinal']
   if self.ordinal in checkpoints:self.snapshots[self.ordinal]={a:bytes(b)for a,b in self.zones.items()}
  assert set(checkpoints)<=set(self.snapshots)
  for a,b in self.final.items():assert bytes(self.zones[a])==b,('final whole zone',hex(a))
  assert self.read(RETURN,4096)==bytes(4096)
  return dict(whole_snapshot_zones=16,actual_RW_zones_excluding_RX_sentinel=15,
    joint_event_count=len(events),CPU_store_count=len(self.row['CPU_store_journal']),
    declared_after_baseline_fixture_count=sum(e['event_type']=='declared_host_fixture'for e in events),
    independently_decoded_CPU_stores=sum(self.mode_counts.values()),unique_store_opcode_sites=len(self.opcodes),
    ISA_source_counts={'/'.join(k):v for k,v in self.mode_counts.items()},whole_before_after_replay_passed=True,
    original_cold_initial_state_reconstructed=True,RX_sentinel_unchanged=True)

def get(snapshot,address,n):
 found=[a for a,b in snapshot.items()if a<=address and address+n<=a+len(b)]
 assert len(found)==1;a=found[0];return snapshot[a][address-a:address-a+n]
def word(snapshot,address):return struct.unpack('<I',get(snapshot,address,4))[0]
def groups_for_PC(journal,PC):
 groups=[]
 for e in journal:
  if int(e['PC'],16)!=PC:continue
  if not groups or e['ordinal']!=groups[-1][-1]['ordinal']+1:groups.append([])
  groups[-1].append(e)
 return groups

def verify_case(row,main,elf,symbols):
 assert row['passed']and row['ticket']==4
 J=row['CPU_store_journal'];F=row['declared_fixture_mutations'];flow=row['native_and_compiled_flow']
 g=symbols['aas_guard']['value'];c=symbols['aas_control']['value']
 profile_end=max(e['ordinal']for e in J if e['phase']=='original_profile')
 native_entries=[f for f in flow if f['PC']=='0x2f9cce']
 end_entries=[f for f in flow if int(f['PC'],16)==symbols['mcs_pull_end']['value']]
 reader_groups=groups_for_PC(J,symbols['memory_output_read']['value'])
 fifo_groups=groups_for_PC(J,symbols['continuous_media_read']['value'])
 checkpoints={profile_end}|{f['ordinal']for f in native_entries+end_entries}
 checkpoints|={a[0]['ordinal']-1 for a in reader_groups+fifo_groups}
 rp=Replay(row,main,elf);rp.cold_initialization();counts=rp.run(checkpoints)
 final=rp.final;profile=rp.snapshots[profile_end]
 for channel in range(18):
  if channel!=8:assert get(final,CHANNELS+channel*0x208,0x208)==get(profile,CHANNELS+channel*0x208,0x208)
 input_bytes=struct.pack('<256h',*[(i*181%60001)-30000 for i in range(256)])
 assert get(final,INPUT,512)==get(final,0x07700000,512)==input_bytes
 assert get(final,0x07700000+512,4096-512)==bytes(4096-512)
 for a,n in((DESCRIPTOR,36),(BUFFER,2048),(SCRATCH,256),(INPUT,512)):
  assert get(final,a-32,32)==get(final,a+n,32)==b'\xa5'*32
 allocations=[e for e in row['lower_opaque_mutex_fixtures']if e['entry']=='0x38853c']
 assert len(allocations)==2 and allocations[0]['args'][:2]==[0x421,3]and allocations[1]['args'][:2]==[524,2]
 for i,e in enumerate(allocations):
  ptr=0x09700000+i*4096+32;n=e['args'][0]
  assert get(final,ptr-32,32)==get(final,ptr+n,32)==b'\xa5'*32
 assert get(final,POOL-32,32)==b'\xa5'*32 and get(final,POOL+10*576,4)==b'\xa5'*4
 depth=Counter()
 for e in row['lower_opaque_mutex_fixtures']:
  if e['entry']=='0x3009a0':depth[e['args'][0]]+=1
  if e['entry']=='0x3008b0':depth[e['args'][0]]-=1;assert depth[e['args'][0]]>=0
 assert not any(depth.values())
 provider=row['selected_native_provider'];index=provider['index'];assert index==0 and provider['provider']==POOL
 assert word(final,RECORD+0xf0)==index and get(final,RECORD+2,1)==b'\x01'
 assert get(final,POOL+12,1)==get(final,POOL+28,1)==b'\x01'
 anchor=word(final,g+12);assert word(final,POOL+16)==anchor and word(final,POOL+20)==2
 assert word(final,RECORD+0x108)==symbols['memory_output_read']['value']and word(final,RECORD+0x10c)==0x48ee31
 assert struct.unpack('<HHII',get(final,RECORD+0x138,12))==(1,16,2,16000)
 assert word(final,g+40)==word(final,symbols['memory_output_control']['value']+12)==4
 assert word(final,g+44)==0 and word(final,g+16)==1 and word(final,g+108)==0
 slots=symbols['memory_output_slots']['value'];out=symbols['memory_output_control']['value']
 submit=[e for e in J if int(e['address'],16)==slots and e['value']==4]
 assert len(submit)==1 and symbols['memory_output_submit']['value']<=int(submit[0]['PC'],16)<symbols['memory_output_submit']['value']+symbols['memory_output_submit']['size']
 assert word(final,slots)==4 and word(final,out+8)==1
 native_index=[e for e in J if e['PC']=='0x48ee8e'and int(e['address'],16)==RECORD+0xf0]
 busy=[e for e in J if e['PC']=='0x48ee8c'and int(e['address'],16)==POOL+12]
 assert len(native_index)==len(busy)==1 and native_index[0]['value']==0 and busy[0]['value']==1
 assert row['native_visits'].get('0x48ee68')==1
 for e in F:
  if e['ordinal']<=row['initial_ordinal']:continue
  a=int(e['address'],16);n=len(bytes.fromhex(e['after_hex']))
  assert not(a<RECORD+0x138 and a+n>RECORD+0xf0),'fixture changed selected provider/methods'
  assert not(a<POOL+5*576 and a+n>POOL),'fixture changed native kind10 pool'
  assert not(a<0x07004000 and a+n>0x07003000),'fixture changed component private BSS/tickets'
 queues=row['original_queue_returns'];assert len(queues)==1 and queues[0]['actual_r0']==0 and queues[0]['actual_SP']==queues[0]['entry_SP']
 args=row['original_queue_seven_args'];assert len(args)==1 and args[0][:4]==[RECORD+0x1a8,0xffff,10,12]and args[0][5:]==[524,0]
 selectors=row['selector_opaque_fixture_calls'];assert len(selectors)==4
 assert [(e['entry'],e['LR']&~1)for e in selectors]==[
  ('0x38853c',0x277832),('0x388804',0x277838),('0x388b22',0x277848),('0x388804',0x2f9ff6)]
 copied=get(final,0x09701020,524);assert copied==get(final,0x09700032,524)
 assert struct.unpack('<5I',copied[:20])==(1,16000,16,anchor,2)
 for e in selectors[2:]:assert e['parameter_sha256']==digest(copied)
 release=[e for e in row['additional_declared_service_fixtures']if e['entry']=='0x3887a2']
 assert len(release)==1 and release[0]['LR']&~1==0x2fa018 and release[0]['handle']==0xd0000002
 assert word(final,0xf09090)==ACTOR and word(final,0xf09094)==0
 assert get(final,symbols['media_worker_state']['value'],32)==bytes(32),'worker unexpectedly booted'
 assert row['native_ownership_snapshot']==-200 and not row['native_STOP_DONE']
 for name in('actual_native_mixer_actor_2FA572_redirected','source_owner_to_mixer_handoff_verified',
             'native_heap_mutex_scheduler_hardware_or_App_verified','full_player_verified','device_io',
             'native_heap_allocator_or_pinning_verified'):assert row[name]is False
 assert not row['native_visits'].get('0x2fa572',0)and not row['native_visits'].get('0x2fa0dc',0)
 status=list(struct.unpack('<30I',get(final,RESULT,120)));assert status==row['status']
 assert status[2]==status[6]==status[7]==status[8]==status[12]==0
 if row['name']=='two_full_original_pulls':
  assert counts['CPU_store_count']==3336 and counts['joint_event_count']==3352 and row['instructions']==17343
  assert len(native_entries)==len(end_entries)==len(reader_groups)==len(fifo_groups)==2
  assert len(row['full_native_pull_returns'])==2 and len(row['reader_live_leases'])==4
  for j in range(2):
   ret=row['full_native_pull_returns'][j];entry=native_entries[j];end=end_entries[j]
   assert ret['entry_native_frame_SP']==entry['SP']and ret['returned_SP']==entry['SP']+64
   assert ret['return_PC']==ret['entry_LR']==symbols['mcs_pull_bridge']['value']+68
   assert ret['returned_r0']==row['pulls'][j]['full_native_r0']==0
   for checkpoint in(entry['ordinal'],end['ordinal'],reader_groups[j][0]['ordinal']-1,fifo_groups[j][0]['ordinal']-1):
    snap=rp.snapshots[checkpoint];borrow=word(snap,g+108)
    assert borrow==ret['entry_leases']['borrow']==entry['SP']+64
    assert word(snap,c+96)==word(snap,c+100)==1
    frame=struct.unpack('<18I',get(snap,borrow,72))
    assert frame==(1,1,1,1,0x1352,1,2,1,1,0x1352,ACTOR,1,1,4,0,8,1,0)
   assert end['args'][:2]==[ret['returned_SP'],0]
   readers=row['reader_live_leases'][2*j:2*j+2]
   assert readers[0]['args'][:3]==[0,SCRATCH,256]and readers[0]['LR']==0x2f9d1d
   assert readers[1]['args'][:2]==[SCRATCH,256]
   for v in(ret['entry_leases'],ret['return_leases'],*[a['leases']for a in readers]):
    assert v['media']==v['callback']==1 and v['current_TCB']==ACTOR and v['interrupt_marker']==0
   assert row['pulls'][j]['returned_leases']['borrow']==row['pulls'][j]['returned_leases']['media']==row['pulls'][j]['returned_leases']['callback']==0
  assert bytes.fromhex(''.join(p['PCM_hex']for p in row['pulls']))==input_bytes
  assert [p['committed_bytes']for p in row['pulls']]==[256,256]and [p['wrapped']for p in row['pulls']]==[True,False]
  assert get(final,BUFFER,448)==input_bytes[64:]and get(final,BUFFER+1984,64)==input_bytes[:64]
  assert get(final,BUFFER+448,1536)==b'\xa5'*1536 and get(final,SCRATCH,256)==input_bytes[256:]
  assert word(final,DESCRIPTOR+16)==BUFFER+448 and word(final,DESCRIPTOR+12)==BUFFER+1984
  assert status[3]==status[4]==2 and status[14]==512 and status[15]==0 and status[19]==0 and status[21]==1 and status[27]==1
  assert row['native_visits'].get('0x2f9d1a')==row['native_visits'].get('0x2f9e34')==2
 else:
  assert row['name']=='local_Stop_prevents_original_pull'
  assert counts['CPU_store_count']==2421 and counts['joint_event_count']==2437 and row['instructions']==11998
  assert not native_entries and not end_entries and not reader_groups and not fifo_groups
  assert not row['pulls']and not row['full_native_pull_returns']and not row['reader_live_leases']
  assert get(final,BUFFER,2048)==b'\xa5'*2048 and word(final,DESCRIPTOR+16)==word(final,DESCRIPTOR+12)==BUFFER+1984
  assert status[3]==status[4]==0 and status[5]==1 and status[9]==0 and status[15]==2 and status[19]==1
  assert not row['native_visits'].get('0x2f9cce',0)and not row['native_visits'].get('0x2f9d1a',0)
  assert word(final,c+52)==6 and word(final,c+72)==1 and word(final,c+76)==0,'Stop is pending, not completed'
 counts.update(name=row['name'],passed=True,actual_ticket=4,native_index_and_busy_stores_verified=True,
   actual_original_selector_param_copy524=True,original_full_pull_return_verified=row['name']=='two_full_original_pulls',
   native_anchor_and_provider_still_pinned=True,FIFO_slot_reusable_only_after_new_identity_design=True)
 return counts,list(rp.opcodes.values())

def main():
 proofpath=BASE/'audio-session-emulation-v2-proof.json';proof=json.loads(proofpath.read_text())
 assert proof['all_passed']and proof['case_count']==2;check(proof['source_sha256'])
 build=json.loads((BASE/'build-v3.json').read_text());check(build['source_sha256']);check(build['generated_sha256'])
 assert sha(MAIN_PATH)==MAIN_SHA and sha(ROOT/build['ELF'])==build['ELF_sha256']
 receiptpath=BASE/'guest-v2-terminal-tool-receipt.json';receipt=json.loads(receiptpath.read_text())
 assert receipt['tool_result']['exit_code']==0 and receipt['tool_result']['chunk_id']=='5fd653'
 assert json.loads((BASE/'guest-v2/inputs-at-run.json').read_text())==proof['source_sha256']
 assert sha(BASE/'guest-v2/runner-at-run.py')==proof['source_sha256'][rel(BASE/'emulate_audio_session_v2.py')]
 main=MAIN_PATH.read_bytes();elf=ELF(ROOT/build['ELF']);symbols=build['symbols']
 for name in('memory_output_submit','memory_output_read','continuous_media_read','mcs_pull_bridge','mcs_original_pull_thunk'):
  assert elf.symbol(name)['value']==symbols[name]['value']
 arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 for pc,target in((0x43776e,0x35b4f4),(0x27783e,0x3732c8)):
  i=next(thumb.disasm(main[pc-0x50000:pc-0x50000+4],pc));assert i.mnemonic=='blx'and i.op_str=='#'+hex(target)
 i=next(arm.disasm(main[0x373300-0x50000:0x373304-0x50000],0x373300));assert i.mnemonic=='beq'and i.op_str=='#0x39129c'
 rows=[];opcodes=[];outputs={rel(proofpath):sha(proofpath),rel(receiptpath):sha(receiptpath),
  rel(BASE/'guest-v2/inputs-at-run.json'):sha(BASE/'guest-v2/inputs-at-run.json'),
  rel(BASE/'guest-v2/runner-at-run.py'):sha(BASE/'guest-v2/runner-at-run.py')}
 for case in proof['cases']:
  p=ROOT/case['path'];assert sha(p)==case['sha256'];row=json.loads(p.read_text())
  outputs[case['path']]=case['sha256']
  for zone in row['zones']:
   if not zone['protection']&4:continue
   a,n=zone['start'],zone['size'];raw=bytearray(n)
   if a==0x50000:raw[:]=main[:n]
   else:
    for s in elf.sections:
     if s['flags']&2 and s['type']!=8 and a<=s['address']and s['address']+s['size']<=a+n:
      raw[s['address']-a:s['address']-a+s['size']]=elf.data(s)
   assert digest(raw)==row['unchanged_RX_sha256'][str(a)],('RX reconstructed input hash',hex(a))
  checks,sites=verify_case(row,main,elf,symbols);rows.append(checks);opcodes.extend(sites)
 sources=dict(proof['source_sha256']);sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
 for p in(ROOT/'scripts/emulate_native_mixer_creation.py',ROOT/'evidence/firmware-analysis/native-mixer-creation-emulation.json',
           ROOT/'scripts/emulate_native_audio_messages.py',ROOT/'evidence/firmware-analysis/native-audio-message-emulation.json'):
  sources[rel(p)]=sha(p)
 for pc,target in((0x2fa294,0x2f9f2e),(0x2fa536,0x2f9cca),(0x2fa572,0x2f9cca)):
  i=next(thumb.disasm(main[pc-0x50000:pc-0x50000+4],pc));assert i.mnemonic=='bl'and i.op_str=='#'+hex(target)
 handoff=dict(next_real_entry='original3B9B66(channel8,0)',
   actual_descriptor=dict(address='M+0x64',words=['2FA0DD','queue240pointer','stack8192top','0117140C','M+0x3C']),
   native_inputs=['native kind2 allocations8192 and240 use r2=0/R0 handle-return ABI; distinct from selector outcell fixture',
    'original388804 queries storage; native358BF8 constructs actualTCB and3B9C14 storesM+78;2FBBBE registersdescriptor',
    'original3B9C22 POST actualM+78,event10; originalkernelrestore determines running task/stack, no hostcurrent seed'],
   native_mixer_actor='2FA0DC on actualM+78 TCB/allocatedstack/message storage; not bounded aas_pull caller',
   message13=dict(selector_call='2FA294 BL2F9F2E',continuation='2FA298',argument='original message+4, stack+1C',
      owner_gap='mcs_capture_selected requires actor==sourceowner; actual different mixer actor requires a new validated handoff/admission design'),
   message18=dict(dispatch='2FA454->2FA53C',conditions='M+84 active !=0 and M+85 reset-pending==0',
      direct_native_fullpull='2FA572 BL2F9CCA'),
   alternate_direct_fullpull='2FA536 BL2F9CCA after M+84!=0 and M+85!=0 and2F9E84 reset path',
   outer_wrapper_gap='both direct native calls bypass mcs_pull_bridge; RAMreader+108 alone is rejected because g.borrow==0',
   required_new_source=['use actual original message-send/get37BCE4/37BC00 and WAIT2FD034/kernelrestore actor provenance',
    'validate selected provider at real2FA298 boundary in actual mixer domain without letting source-only capture impersonate mixer',
    'find authorized real RAM callback/import or original-callsite redirect covering both full pulls and repeated selection; currently not installed',
    'separate long-lived native anchor/session identity from recycleable FIFOslot tickets; next submit ticket8 currently invalidates selected ticket4 check',
    'retain native clock/timednode,wholeTCB/stack/ownedmutex/context guards across new actor,heap/msg/priority fixtures clearly stated'],
   different_helper='33F8FA/9BB7F4 builds33F94B PCMhelper, not2FA0DD mixer',
   legacy_evidence='mixer-creation control stopped before wake; older message controls supplied wait/get and Python context restore; neither proves new actual kernel handoff')
 result=dict(all_passed=True,assertion_scope='independent file-only verification of TWO bounded original-selector/full-pull cases',
  source_sha256=sources,output_sha256=outputs,cases=rows,case_count=2,independent_full_joint_RW_replay=True,
  every_recorded_CPUstore_original_MAIN_or_ELF_bytes_and_ISA_checked=True,
  exact_CPU_store_count=sum(r['CPU_store_count']for r in rows),joint_event_count=sum(r['joint_event_count']for r in rows),
  decoded_store_opcode_sites=list({(x['PC'],x['Thumb'],x['original_opcode_hex']):x for x in opcodes}.values()),
  source_hashes_ELF_RX_initial_cold_input_and_canaries_checked=True,actual_original_current_getter_IRQ_queue_selector_factory_copy=True,
  positive512byte_input_and_two256byte_full_native_returns=True,whole_reader_leases_then_full_return_release=True,
  Stop_new_body_denied_without_STOP_DONE=True,native_anchor_provider_and_registration_still_live=True,
  actual_source_owner_to_native_mixer_handoff_verified=False,original2FA572_or2FA536_outerwrapper_redirected=False,
  native_heap_pinning_mutex_scheduler_clock_IRQ_hardware_ownership_App_verified=False,
  complete_player_or_physical_audio_or_foreground_verified=False,device_io=False,guest_rerun=False,no_VM_import=True,
  limitations=[
   '16 whole tracked snapshots include RETURN08D00000 sentinel. Frozen parent changed its permission toRX after map while zones metadata retained3; independent verifier checks it separately zero/unchanged and rejects writes. Other15 areRW.',
   'ELF .hword copied prologue is mapped$d by assembler; exact originalThumb opcode and .thumb_func lowbit provide explicit four-byte exception, not blanket permission to execute data.',
   'Recorded store source/ISA/opcode/width/whole before-after values verified. Per-store complete GP/CPSR snapshots were not recorded; computed address/register payload execution cannot be reconstructed from machine state independently.',
   'single actor/current TCB,rawPCM/resident BSS,opaque heap/query/release,mutex,wake,priority,message and diagnostic services are explicit fixtures',
   'positive frees oneFIFOslot but leaves nativeanchor active,guardheld,providerbusy/prepared/methods/node live; Stop leavesreadyFIFO/native source pinned. No retirement,quiescence,STOP_DONE,unload or safe continuous slot reuse.',
   'compiled mediaworkerTCB remains0; no SBC/phone decoder worker or native mixer actor is booted; original ring consumer never advances'],
  next_native_handoff_contract=handoff)
 assert 'unicorn'not in sys.modules,'verifier imported VM library'
 check(sources);check(outputs)
 path=BASE/'audio-session-v2-independent-file-verification.json';dump(path,result)
 print(json.dumps(dict(all_passed=True,verification=rel(path),SHA256=sha(path),
  CPU_stores=result['exact_CPU_store_count'],joint_events=result['joint_event_count'],guest_rerun=False)))
if __name__=='__main__':main()
