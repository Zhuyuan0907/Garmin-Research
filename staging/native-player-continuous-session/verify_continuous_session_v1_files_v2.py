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
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
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
   if hasattr(self,'event_guard'):self.event_guard(self,e)
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

INHERITED=ROOT/'staging/native-player-native-allocation/audio-session-static/verify_audio_session_v2_files_v2.py'
INHERITED_SHA='53cb3c2326ec6ae93b948e33f668d9f5c2406a8ecec45f2cbf8036b441874b9b'
NAMES=('twelve_compiled_same_slot_generations_one_native_session',
 'underrun_silence_then_recycled_FIFO_resumes_same_session',
 'Stop_after_reuse_denies_new_pull_and_submit_keeps_anchor_pinned')
EXPECTED_COUNTS=((128966,21765,21816),(30822,5620,5637),(26424,4801,4818))

def production_payload(cycle):
 values=[(i*181)%60001-30000 for i in range(256)]if cycle==0 else [
  (i*313+cycle*1207)%60001-30000 for i in range(256)]
 return struct.pack('<256h',*values)

def first_push(elf,symbols,name,offset,opcode):
 start=symbols[name]['value'];raw,_=elf.at(start,offset+4)
 decoded=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(raw,start))
 assert len(decoded)==offset//4+1
 assert all(i.mnemonic in('ldr','sub','cmp','cmpne')for i in decoded[:-1])
 assert decoded[-1].address==start+offset and decoded[-1].id==ARM_INS_PUSH
 assert decoded[-1].bytes.hex()==opcode and elf.mode(start+offset)=='a'
 return start+offset

def verify_case(row,main,elf,symbols,case_number):
 assert row['passed']and row['name']==NAMES[case_number]
 assert row['session']==1 and row['bootstrap_registration_ticket']==4
 J=row['CPU_store_journal'];F=row['declared_fixture_mutations'];flow=row['native_and_compiled_flow']
 g=symbols['aas_guard']['value'];c=symbols['aas_control']['value']
 offsets=struct.unpack('<5I',elf.at(symbols['aas_offsets']['value'],20)[0])
 assert offsets==(96,40,44,96,100)and symbols['aas_guard']['size']==112
 borrow_field=g+offsets[0];media_field=c+offsets[3];callback_field=c+offsets[4]
 lease_fields=(borrow_field,media_field,callback_field)
 slots=symbols['memory_output_slots']['value'];out=symbols['memory_output_control']['value']
 owned=symbols['owned_media_control']['value'];cont=symbols['continuous_media_control']['value']
 tickets=symbols['tickets']['value'];queue=symbols['media_queue_control']['value']
 profile_end=max(e['ordinal']for e in J if e['phase']=='original_profile')
 entries=[f for f in flow if f['PC']=='0x2f9cce']
 ends=[f for f in flow if int(f['PC'],16)==symbols['mcs_pull_end']['value']]
 reader_groups=groups_for_PC(J,first_push(elf,symbols,'memory_output_read',4,'70402de9'))
 fifo_groups=groups_for_PC(J,first_push(elf,symbols,'continuous_media_read',12,'f04f2de9'))
 pulls_expected=(24,5,3)[case_number];productions_expected=(12,2,2)[case_number]
 assert len(entries)==len(ends)==len(reader_groups)==len(fifo_groups)==pulls_expected
 assert len(row['full_native_pull_returns'])==len(row['pulls'])==pulls_expected
 assert len(row['reader_live_leases'])==2*pulls_expected
 productions=row['productions'];assert len(productions)==productions_expected
 assert [p['ticket']for p in productions]==list(range(4,productions_expected*4+1,4))
 for cycle,p in enumerate(productions):
  assert p['slot']==0 and p['bytes']==512 and p['actual_compiled_submit']
  assert bytes.fromhex(p['input_hex'])==production_payload(cycle)
 publish_entries=[f for f in flow if int(f['PC'],16)==symbols['aas_pcm_publish']['value'] and not f['phase'].startswith('Stop_')]
 submit_entries=[f for f in flow if int(f['PC'],16)==symbols['memory_output_submit']['value']]
 assert len(publish_entries)==len(submit_entries)==productions_expected
 for f in publish_entries+submit_entries:assert f['args'][:2]==[INPUT,512]
 ticket_events=[e for e in J if int(e['address'],16)==slots and e['size']==4 and e['value']!=0]
 assert [e['value']for e in ticket_events]==[p['ticket']for p in productions]
 for e in ticket_events:
  pc=int(e['PC'],16);s=symbols['memory_output_submit'];assert s['value']<=pc<s['value']+s['size']
 ready_events=[e for e in J if int(e['address'],16)==slots+4 and e['size']==4 and e['value']==2]
 assert len(ready_events)==productions_expected
 consumers=row['explicit_output_consumer_fixtures']
 assert len(consumers)==(24 if case_number==0 else 0)
 stop_before=None
 if case_number==2:stop_before=min(e['ordinal']for e in J if e['phase']=='compiled_local_Stop_closes_controller_and_queue')-1
 checkpoints={profile_end}|{e['ordinal']for e in entries+ends+ready_events}
 checkpoints|={a[0]['ordinal']-1 for a in reader_groups+fifo_groups}
 checkpoints|={a['ordinal']-1 for a in consumers}
 if stop_before is not None:checkpoints.add(stop_before)
 rp=Replay(row,main,elf)
 # Before each actual PCM copy store, source/reader copy leases and private
 # FIFO in-flight ownership must still be live. No VM state is recreated.
 copy_checks=Counter()
 def event_guard(replay,e):
  if e['event_type']!='actual_CPU_store':return
  a=int(e['address'],16);n=e['size'];pc=int(e['PC'],16)
  if 0x07700000<=a and a+n<=0x07701000:
   assert replay.word(media_field)==replay.word(callback_field)==1
   assert replay.word(owned+4)==1 and replay.word(slots+4)==1
   assert replay.read(INPUT+a-0x07700000,n)==(e['value']&((1<<(8*n))-1)).to_bytes(n,'little')
   copy_checks['producer_FIFO_store_with_copy_leases']+=1
  if SCRATCH<=a and a+n<=SCRATCH+256:
   assert replay.word(borrow_field)and replay.word(media_field)==replay.word(callback_field)==1
   assert replay.word(out+24)==1
   memcpy=symbols['memcpy'];memset=symbols['memset']
   if memcpy['value']<=pc<memcpy['value']+memcpy['size']:
    read_index=replay.word(owned+8);ticket=replay.word(tickets+4*read_index)
    assert ticket==replay.word(slots)and replay.word(slots+4)==2 and replay.word(slots+20)==1
    assert replay.word(owned+16)>0
    copy_checks['reader_FIFO_store_with_inflight_and_full_return_leases']+=1
   else:
    assert memset['value']<=pc<memset['value']+memset['size']
    assert case_number==1 and replay.word(owned+16)==0 and replay.word(slots+20)==0
    assert e['value']==0;copy_checks['actual_underrun_zero_store']+=1
 rp.event_guard=event_guard;rp.cold_initialization();counts=rp.run(checkpoints)
 final=rp.final;profile=rp.snapshots[profile_end]
 assert (row['instructions'],counts['CPU_store_count'],counts['joint_event_count'])==EXPECTED_COUNTS[case_number]
 for channel in range(18):
  if channel!=8:assert get(final,CHANNELS+channel*0x208,0x208)==get(profile,CHANNELS+channel*0x208,0x208)
 assert get(final,INPUT,512)==get(final,0x07700000,512)==production_payload(productions_expected-1)
 assert get(final,0x07700000+512,4096-512)==bytes(4096-512)
 for p in(0x07701000,0x07702000,0x07703000):assert get(final,p,4096)==bytes(4096)
 for a,n in((DESCRIPTOR,36),(BUFFER,2048),(SCRATCH,256),(INPUT,512)):
  assert get(final,a-32,32)==get(final,a+n,32)==b'\xa5'*32
 allocations=[e for e in row['lower_opaque_mutex_fixtures']if e['entry']=='0x38853c']
 assert len(allocations)==2 and allocations[0]['args'][:2]==[0x421,3]and allocations[1]['args'][:2]==[524,2]
 for i,e in enumerate(allocations):
  p=0x09700020+i*4096;n=e['args'][0];assert get(final,p-32,32)==get(final,p+n,32)==b'\xa5'*32
 assert get(final,POOL-32,32)==b'\xa5'*32 and get(final,POOL+10*576,4)==b'\xa5'*4
 depth=Counter()
 for e in row['lower_opaque_mutex_fixtures']:
  if e['entry']=='0x3009a0':depth[e['args'][0]]+=1
  if e['entry']=='0x3008b0':depth[e['args'][0]]-=1;assert depth[e['args'][0]]>=0
 assert not any(depth.values())
 assert row['selected_native_provider']['index']==0 and row['selected_native_provider']['provider']==POOL
 anchor=word(final,g+12)
 assert word(final,RECORD+0xf0)==0 and get(final,RECORD+2,1)==b'\x01'
 assert get(final,POOL+12,1)==get(final,POOL+28,1)==b'\x01'
 assert word(final,POOL+16)==anchor and word(final,POOL+20)==2
 assert word(final,RECORD+0x108)==symbols['memory_output_read']['value']and word(final,RECORD+0x10c)==0x48ee31
 assert struct.unpack('<HHII',get(final,RECORD+0x138,12))==(1,16,2,16000)
 assert word(final,g+40)==word(final,g+4)==1 and word(final,g+44)==0
 assert word(final,g+72)==word(final,out+12)==4 and word(final,out+16)==word(final,g+16)==1
 assert word(final,borrow_field)==word(final,media_field)==word(final,callback_field)==0
 assert word(final,slots)==productions_expected*4 and word(final,out+8)==productions_expected
 index_events=[e for e in J if e['PC']=='0x48ee8e'and int(e['address'],16)==RECORD+0xf0]
 busy_events=[e for e in J if e['PC']=='0x48ee8c'and int(e['address'],16)==POOL+12]
 assert len(index_events)==len(busy_events)==1 and index_events[0]['value']==0 and busy_events[0]['value']==1
 for e in F:
  if e['ordinal']<=row['initial_ordinal']:continue
  a=int(e['address'],16);n=len(bytes.fromhex(e['after_hex']))
  assert not(a<RECORD+0x138 and a+n>RECORD+0xf0),'fixture seeded native selected provider'
  assert not(a<POOL+5*576 and a+n>POOL),'fixture seeded native kind10 provider'
  assert not(a<out+48 and a+n>g),'fixture seeded private session/tickets/FIFO controls'
  assert not(a<0x07704000 and a+n>0x07700000),'fixture seeded copied FIFO payload'
 queue_returns=row['original_queue_returns'];args=row['original_queue_seven_args']
 assert len(queue_returns)==len(args)==1 and queue_returns[0]['actual_r0']==0
 assert queue_returns[0]['actual_SP']==queue_returns[0]['entry_SP']
 assert args[0][:4]==[RECORD+0x1a8,0xffff,10,12]and args[0][5:]==[524,0]
 selectors=row['selector_opaque_fixture_calls'];assert len(selectors)==4
 assert [(e['entry'],e['LR']&~1)for e in selectors]==[
  ('0x38853c',0x277832),('0x388804',0x277838),('0x388b22',0x277848),('0x388804',0x2f9ff6)]
 copied=get(final,0x09701020,524);assert copied==get(final,0x09700032,524)
 assert struct.unpack('<5I',copied[:20])==(1,16000,16,anchor,2)
 for e in selectors[2:]:assert e['parameter_sha256']==digest(copied)
 release=[e for e in row['additional_declared_service_fixtures']if e['entry']=='0x3887a2']
 assert len(release)==1 and release[0]['LR']&~1==0x2fa018 and release[0]['handle']==0xd0000002
 assert word(final,0xf09090)==ACTOR and word(final,0xf09094)==0
 assert get(final,symbols['media_worker_state']['value'],32)==bytes(32)
 assert get(final,RESULT+256,128)==bytes(128),'uncertified ownership witness was changed'
 assert row['native_ownership_snapshot']==-200 and row['native_STOP_DONE']is False
 for flag in('actual_native_mixer_actor_redirected','source_owner_to_mixer_handoff_verified',
  'native_heap_mutex_scheduler_hardware_phone_UI_or_App_verified','complete_player_verified','device_io'):assert row[flag]is False
 for pc in('0x2fa0dc','0x2fa572','0x2fa536'):assert row['native_visits'].get(pc,0)==0
 for pc in('0x437764','0x48ee68','0x277c6a'):assert row['native_visits'].get(pc)==1
 status=list(struct.unpack('<30I',get(final,RESULT,120)));assert status==row['status']
 assert status[2]==status[6]==status[7]==status[8]==status[12]==0
 assert status[0]==1 and status[10]==4 and status[11]==1 and status[16]==productions_expected*4
 # Verify each genuine submit's READY state from reconstructed memory, never
 # from host-seeded selected/index or production metadata alone.
 for cycle,e in enumerate(ready_events):
  snap=rp.snapshots[e['ordinal']]
  assert word(snap,slots)==4*(cycle+1)and word(snap,slots+4)==2 and word(snap,slots+8)==512
  assert get(snap,0x07700000,512)==get(snap,INPUT,512)==production_payload(cycle)
  assert word(snap,media_field)==word(snap,callback_field)==1 and word(snap,owned+4)==1
  if cycle:assert word(snap,g+40)==word(snap,g+4)==1 and word(snap,g+72)==4
 if case_number==0:payload_stream=b''.join(production_payload(cycle)for cycle in range(12))
 elif case_number==1:payload_stream=production_payload(0)+bytes(256)+production_payload(1)
 else:payload_stream=production_payload(0)+production_payload(1)[:256]
 assert len(payload_stream)==256*pulls_expected
 assert bytes.fromhex(''.join(p['PCM_hex']for p in row['pulls']))==payload_stream
 expected_ring=bytearray(b'\xa5'*2048);write_offset=1984;read_offset=1984
 for j in range(pulls_expected):
  ret=row['full_native_pull_returns'][j];entry=entries[j];end=ends[j];pull=row['pulls'][j]
  pcm=payload_stream[256*j:256*(j+1)]
  assert ret['entry_native_frame_SP']==entry['SP']and ret['returned_SP']==entry['SP']+64
  assert ret['return_PC']==ret['entry_LR']==symbols['mcs_pull_bridge']['value']+68
  assert ret['returned_r0']==pull['full_native_r0']==0 and pull['committed_bytes']==256
  for checkpoint in(entry['ordinal'],end['ordinal'],reader_groups[j][0]['ordinal']-1,fifo_groups[j][0]['ordinal']-1):
   snap=rp.snapshots[checkpoint];borrow=word(snap,borrow_field)
   assert borrow==ret['entry_leases']['borrow']==entry['SP']+64
   assert word(snap,media_field)==word(snap,callback_field)==1
   assert struct.unpack('<18I',get(snap,borrow,72))==(1,1,1,1,0x1352,1,2,1,1,0x1352,ACTOR,1,1,1,0,8,1,0)
   assert word(snap,g+40)==word(snap,g+4)==1 and word(snap,g+72)==word(snap,out+12)==4
  assert end['args'][:2]==[ret['returned_SP'],0]
  readers=row['reader_live_leases'][2*j:2*j+2]
  for reader,group,nwords in((readers[0],reader_groups[j],4),(readers[1],fifo_groups[j],9)):
   assert len(group)==nwords and [int(e['address'],16)for e in group]==list(range(reader['SP']-4*nwords,reader['SP'],4))
   assert group[-1]['value']==reader['LR']
  assert readers[0]['args'][:3]==[0,SCRATCH,256]and readers[0]['LR']==0x2f9d1d
  assert readers[1]['args'][:2]==[SCRATCH,256]
  for view in(ret['entry_leases'],ret['return_leases'],*[a['leases']for a in readers]):
   assert view['media']==view['callback']==1 and view['selected_session']==1
   assert view['current_TCB']==ACTOR and view['interrupt_marker']==0
  for e in J+F:
   if not entry['ordinal']<e['ordinal']<=end['ordinal']:continue
   a=int(e['address'],16);n=len(bytes.fromhex(e['before_hex']))
   assert not any(a<t+4 and a+n>t for t in lease_fields),'lease altered before complete return'
  next_native=entries[j+1]['ordinal']if j+1<len(entries)else max(e['ordinal']for e in J+F)+1
  for t in lease_fields:
   releases=[e for e in J if end['ordinal']<e['ordinal']<next_native and int(e['address'],16)==t and e['size']==4 and e['value']==0]
   # A following producer can acquire/release its OWN event lease before
   # the next pull; first release must be the actual compiled pull epilogue.
   assert releases
   function='mcs_pull_end'if t==borrow_field else 'umc_media_release'if t==media_field else 'umc_callback_release'
   fn=symbols[function];pc=int(releases[0]['PC'],16);assert fn['value']<=pc<fn['value']+fn['size']
  returned=pull['returned_leases'];assert returned['borrow']==returned['media']==returned['callback']==0
  before_offset=write_offset
  for n,value in enumerate(pcm):expected_ring[(write_offset+n)%2048]=value
  write_offset=(write_offset+256)%2048
  snap=rp.snapshots[end['ordinal']]
  assert get(snap,SCRATCH,256)==pcm and get(snap,BUFFER,2048)==bytes(expected_ring)
  assert word(snap,DESCRIPTOR+16)==BUFFER+write_offset and word(snap,DESCRIPTOR+12)==BUFFER+read_offset
  assert pull['wrapped']==(before_offset+256>2048)
  if consumers:
   consumer=consumers[j];ordinal=consumer['ordinal'];snap=rp.snapshots[ordinal-1]
   assert end['ordinal']<ordinal<(entries[j+1]['ordinal']if j+1<len(entries)else max(e['ordinal']for e in J+F)+1)
   assert word(snap,borrow_field)==word(snap,media_field)==word(snap,callback_field)==0
   assert consumer['before']==BUFFER+read_offset and consumer['after']==BUFFER+write_offset
   assert consumer['after_full_native_return']and consumer['hardware']is False
   e=next(e for e in F if e['ordinal']==ordinal)
   assert int(e['address'],16)==DESCRIPTOR+12 and bytes.fromhex(e['before_hex'])==struct.pack('<I',consumer['before'])
   assert bytes.fromhex(e['after_hex'])==struct.pack('<I',consumer['after'])and 'test-only output mixer consumer' in e['reason']
   read_offset=write_offset
 assert get(final,BUFFER,2048)==bytes(expected_ring)and get(final,SCRATCH,256)==payload_stream[-256:]
 assert word(final,DESCRIPTOR+16)==BUFFER+write_offset and word(final,DESCRIPTOR+12)==BUFFER+read_offset
 for pc in('0x2f9cce','0x2f9d1a','0x2f9e34'):assert row['native_visits'].get(pc)==pulls_expected
 assert status[3]==status[4]==status[13]==status[24]==pulls_expected and status[14]==256*pulls_expected
 assert status[20]==productions_expected and status[22]==4*productions_expected
 if case_number==0:
  assert status[9]==status[28]==1 and status[15]==status[19]==status[23]==status[26]==0
  assert status[21]==status[27]==12 and status[25]==6144 and not row['denied_calls']
 elif case_number==1:
  assert status[9]==status[28]==1 and status[15]==status[19]==status[23]==0
  assert status[21]==status[27]==2 and status[25]==1024 and status[26]==256 and word(final,cont+20)==1
  assert not row['denied_calls']and copy_checks['actual_underrun_zero_store']>0
 else:
  assert row['denied_calls']==[dict(entry='aas_pull',result=0),dict(entry='aas_pcm_publish',result=(-201&0xffffffff)),dict(entry='memory_output_release_session',result=(-201&0xffffffff))]
  assert status[5]==1 and status[9]==status[28]==status[8]==0 and status[15]==2 and status[19]==1
  assert status[21]==status[27]==1 and status[25]==768 and status[23]==256 and status[26]==0 and status[29]==2
  assert word(final,c+52)==6 and word(final,c+72)==1 and word(final,c+76)==0
  snap=rp.snapshots[stop_before]
  assert word(snap,c+52)==4 and word(snap,c+68)==1
  assert get(snap,slots,96)==get(final,slots,96)and get(snap,BUFFER,2048)==get(final,BUFFER,2048)
  assert not any(int(f['PC'],16)==symbols['memory_output_submit']['value']and f['phase'].startswith('Stop_')for f in flow)
  assert not any(e['phase'].startswith('Stop_')and SCRATCH<=int(e['address'],16)<SCRATCH+256 for e in J)
 assert copy_checks['producer_FIFO_store_with_copy_leases']>0 and copy_checks['reader_FIFO_store_with_inflight_and_full_return_leases']>0
 counts.update(name=row['name'],passed=True,instructions=row['instructions'],session=1,
  bootstrap_registration_audit_seed=4,actual_FIFO_tickets=[p['ticket']for p in productions],
  native_registrations=1,native_factory_provider_constructions=1,complete_native_full_returns=pulls_expected,
  actual_PCM_bytes=256*pulls_expected,explicit_output_consumer_fixture_count=len(consumers),
  whole_mixer_ring_verified_at_every_full_return=True,full_native_frame64_and_borrow_frame72_checked=True,
  joint_history_preserves_full_native_return_leases=True,CPU_copy_inflight_lease_store_checks=dict(copy_checks),
  native_session_independent_of_recycled_FIFO_ticket=True,Stop_denied_without_fabricated_completion=case_number==2,
  actual_native_mixer_handoff=False,native_exclusive_ownership=False,native_STOP_DONE=False)
 return counts,list(rp.opcodes.values())

def main():
 assert sha(INHERITED)==INHERITED_SHA
 proofpath=BASE/'continuous-session-emulation-v1-proof.json';proof=json.loads(proofpath.read_text())
 assert proof['all_passed']and proof['case_count']==3;check(proof['source_sha256'])
 build=json.loads((BASE/'build-v1.json').read_text());check(build['source_sha256']);check(build['generated_sha256'])
 assert sha(MAIN_PATH)==MAIN_SHA and sha(ROOT/build['ELF'])==build['ELF_sha256']
 receiptpath=BASE/'guest-v1-terminal-tool-receipt.json';receipt=json.loads(receiptpath.read_text())
 assert receipt['tool_result']['exit_code']==0 and receipt['tool_result']['chunk_id']=='c99bc2'and receipt['observed_session_id']==2103
 assert json.loads((BASE/'guest-v1/inputs-at-run.json').read_text())==proof['source_sha256']
 assert sha(BASE/'guest-v1/runner-at-run.py')==proof['source_sha256'][rel(BASE/'emulate_continuous_session_v1.py')]
 main=MAIN_PATH.read_bytes();elf=ELF(ROOT/build['ELF']);symbols=build['symbols']
 for name in symbols:
  if symbols[name]['section_index']!=0 and symbols[name]['size']:
   # Manifest uses a name dictionary and keeps one of duplicate TU-local
   # names. Check the exact manifest tuple, not global name uniqueness.
   exact=[s for s in elf.symbols if s['name']==name and s['value']==symbols[name]['value']
    and s['size']==symbols[name]['size']and s['section']==symbols[name]['section_index']]
   assert len(exact)==1,(name,symbols[name])
 arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 for pc,target in((0x43776e,0x35b4f4),(0x27783e,0x3732c8)):
  i=next(thumb.disasm(main[pc-0x50000:pc-0x50000+4],pc));assert i.mnemonic=='blx'and i.op_str=='#'+hex(target)
 i=next(arm.disasm(main[0x373300-0x50000:0x373304-0x50000],0x373300));assert i.mnemonic=='beq'and i.op_str=='#0x39129c'
 rows=[];opcodes=[];outputs={rel(proofpath):sha(proofpath),rel(receiptpath):sha(receiptpath),
  rel(BASE/'guest-v1/inputs-at-run.json'):sha(BASE/'guest-v1/inputs-at-run.json'),
  rel(BASE/'guest-v1/runner-at-run.py'):sha(BASE/'guest-v1/runner-at-run.py')}
 for case_number,case in enumerate(proof['cases']):
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
   assert digest(raw)==row['unchanged_RX_sha256'][str(a)],('RX reconstructed input',hex(a))
  checks,sites=verify_case(row,main,elf,symbols,case_number);rows.append(checks);opcodes.extend(sites)
 sources=dict(proof['source_sha256']);sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve());sources[rel(INHERITED)]=INHERITED_SHA
 for p in(BASE/'verify_continuous_session_v1_files.py',BASE/'file-verifier-v1/verifier-at-run.py',BASE/'file-verifier-v1/inputs-at-run.json',BASE/'file-verifier-v1-terminal-tool-receipt.json'):
  sources[rel(p)]=sha(p)
 limits=[
  'Three bounded single-actor compiled/raw-PCM pipeline controls, not a complete music player or native mixer task/phone/UI/hardware suite.',
  'Long case read index advances24times only through explicit output-consumer HOST fixture AFTER actual full return and zero borrow/media/callback leases. Raw input updates are explicit fixtures. They are replayed alongside every CPU event; no DMA, mixer worker or timing claim.',
  'Sixteen whole tracked snapshots include15actualRW zones and one08D00000RXsentinel whose inherited metadata saysprotection3. All4096sentinelbytes checkedzero/unchanged; everywrite rejected.',
  'Every recorded store matches exact originalMAIN or compiledELF bytes/ISA/width and complete before-after history. Complete per-storeGP/CPSR was not recorded, so independent register-derived address/payload execution cannot be recreated.',
  'CurrentTCB/normal IRQmarker, initialmapping/ring/descriptor/storage, opaque allocation/query/release, mutex,wake,priority,message/diagnostic boundaries are explicit fixtures. No native heap pinning, whole kernel lifecycle, clock/IRQ, cross-actor exclusion or physical scheduling proof.',
  'Provider/node/methods/anchor and componentstorage remainresident. Stop leaves secondgenerationREADY and halfconsumed, rejects newpull/submit/release; noSTOP_DONE, cancel cleanup, native source retirement, quiescence or safeunload.',
  'Originalmixer2FA0DC/M+78 TCBhandoff and selector2FA294->2FA298 capture domain remainabsent; bothoriginal2FA572 and2FA536 directBL2F9CCA stillbypasscompiledfullreturnbridge. Consumerreaderpointer alone is insufficient.',
  'Onlyslot0 recycled12generations in longcase; no allslot/fullqueue/producer-consumer concurrency, decoder/SBC/mobileinput worker or navigationcoexistence. Legacy output.active_ticket4 is bootstrap audit identity, not a liveFIFOslot.']
 result=dict(all_passed=True,case_count=3,assertion_scope='FILE ONLY independent replay of frozen three bounded continuous-session cases',
  source_sha256=sources,output_sha256=outputs,cases=rows,
  exact_CPU_store_count=sum(r['CPU_store_count']for r in rows),joint_event_count=sum(r['joint_event_count']for r in rows),
  complete_native_full_returns=sum(r['complete_native_full_returns']for r in rows),
  independent_full_joint_RW_replay=True,every_recorded_CPUstore_MAIN_or_ELF_original_bytes_and_ISA_checked=True,
  cold_initialization_source_ELF_RX_and_canaries_checked=True,exact_FIFO_tickets_4_through_48_checked=True,
  payload_underrun_silence_Stop_and_every_full_return_leases_checked=True,
  explicit_output_consumer_fixture_preserved=True,per_store_complete_GP_CPSR_available=False,
  actual_source_owner_to_native_mixer_handoff_verified=False,original2FA572_or2FA536_outerwrapper_redirected=False,
  native_exclusive_ownership_or_STOP_DONE_or_hardware_or_App_verified=False,complete_player_verified=False,
  historical_file_verifier_failure=dict(receipt=rel(BASE/'file-verifier-v1-terminal-tool-receipt.json'),chunk_id='fe2945',guest_failure=False,correction='Exact manifest name/value/size/section tuple for duplicate TU-local symbols'),
  guest_rerun=False,no_VM_import=True,device_io=False,canonical_write=False,limitations=limits,
  decoded_store_opcode_sites=list({(x['PC'],x['Thumb'],x['original_opcode_hex']):x for x in opcodes}.values()))
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 check(sources);check(outputs)
 path=BASE/'continuous-session-v1-independent-file-verification.json';dump(path,result)
 print(json.dumps(dict(all_passed=True,verification=rel(path),SHA256=sha(path),cases=3,
  CPU_stores=result['exact_CPU_store_count'],joint_events=result['joint_event_count'],
  complete_native_full_returns=result['complete_native_full_returns'],guest_rerun=False)))

if __name__=='__main__':main()
