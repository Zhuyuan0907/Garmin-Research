#!/usr/bin/env python3
"""Actual warm single image + selected native gates + complete resident retirement.
Explicit startup/Timer/radio/heap/output fixtures remain. No device or unload.
"""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,struct,hashlib,traceback,ast,types,gc
from pathlib import Path
from datetime import datetime,timezone
import unicorn,gzip,io
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=load(ROOT/'staging/native-player-route-entries/emulate_route_entries_v5.py','warm_retirement_route_parent')
K=load(ROOT/'staging/native-player-sbc-retirement/kernel_retirement_monitor_v1.py','warm_retirement_Stop_sync_observer')
B,I=R.B,R.I
sha,rel,dump,require=R.sha,R.rel,R.dump,R.require
HEAD=0x034e68d8+8*4
# Same original observer except the declared initialize-vs-Stop sync branch.
# This only observes native instructions; no guest mutation/context restoration.
def comparable_observer(path):
 text=Path(path).read_text();tree=ast.parse(text)
 c=next(x for x in tree.body if isinstance(x,ast.ClassDef)and x.name=='Handoff')
 f=next(x for x in c.body if isinstance(x,ast.FunctionDef)and x.name=='code')
 f.body=[x for x in f.body if not(isinstance(x,ast.If)and '46CC7A'in ast.get_source_segment(text,x.test).upper())]
 return ast.dump(f,include_attributes=False)
require(comparable_observer(B.__file__)==comparable_observer(K.__file__),'unexpected observer change outside native sync contract')
B.Handoff.code=K.Handoff.code

class Retirement(R.RouteVM):

    def __init__(self, stock, elf, build, reference):
        self.native_stop_entries = []
        self.native_stop_returns = []
        self.pending_stops = {}
        self.ns_entries = []
        self.ns_returns = []
        self.pending_ns = None
        self.retirement_stores = []
        self.notice23 = []
        self.cleanup_release_calls = []
        self.playing_interference=None;self.other_controls=None;self.retirement_records=[];self.Stop_racer_checks=[]
        super().__init__(stock, elf, build, reference)

    def invoke_kernel(self, entry, args=(), phase=None):
        result = super().invoke_kernel(entry, args, phase)
        p = self.pending_ns
        if p and self.uc.reg_read(UC_ARM_REG_PC) == p['return_PC']:
            require(self.uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'controller retirement endpoint SP')
            require(self.word(B.READY_TASKS) == p['actor'], 'controller retirement endpoint actor')
            self.ns_returns.append(dict(p, returned=self.snapshot(), r0=result, native=self.retirement_native(), actual_emu_end_PC=True))
            self.pending_ns = None
        return result

    def retirement_native(self):
        s = self.build['symbols']
        g = s['aas_guard']['value']
        o = s['memory_output_control']['value']
        index = self.word(s['ns_instance']['value'])
        provider = list(bytes(self.uc.mem_read(B.POOL + index * 576, 32))) if index < 5 else None
        return dict(head=self.word(HEAD), node_count=struct.unpack('<H', self.uc.mem_read(B.RECORD + 448, 2))[0], prepared=self.uc.mem_read(B.RECORD + 2, 1)[0], methods_hex=bytes(self.uc.mem_read(B.RECORD + 244, 68)).hex(), selected_index=self.word(B.RECORD + 240), mixer_active=self.uc.mem_read(B.MIXER + 132, 1)[0], provider=provider, ns_stage=self.word(s['ns_stage']['value']), ns_hold=self.word(s['ns_hold']['value']), native_mutation=self.word(g + 48), guard_held=self.word(g + 16), native_calls=self.word(o + 20), active_ticket=self.word(o + 12), installed=self.word(o + 16), leases=self.leases())

    def ns_status(self):
        self.invoke_kernel('ns_status', (B.old.RESULT + 512,), phase='read-only compiled retirement status')
        return list(struct.unpack('<14I', self.uc.mem_read(B.old.RESULT + 512, 56)))

    def store(self, uc, access, address, size, value, data):
        super().store(uc, access, address, size, value, data)
        pc = self.last_instruction[0]
        if pc in (3122318, 3122322, 3122366, 6190516, 4779620, 4422320, 4422322, 2586060, 2586178):
            n = self.retirement_native()
            require(n['ns_stage'] == 3 and n['ns_hold'] == n['native_mutation'] == n['native_calls'] == 1, 'original retirement write outside retained Source cleanup hold')
            self.retirement_stores.append(dict(journal_ordinal=self.ordinal, PC=pc, address=address, size=size, value=value, state=self.snapshot(), native_before=n))

    def code(self, uc, address, size, data):
        super().code(uc, address, size, data)
        for entry, p in list(self.pending_stops.items()):
            if address == p['return_PC']:
                require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'original cleanup/removal full-return SP')
                require(self.word(B.READY_TASKS) == p['actor'], 'original cleanup/removal full-return actor')
                n = self.retirement_native()
                require(n['ns_hold'] == n['native_mutation'] == n['native_calls'] == 1, 'cleanup hold dropped before full original return')
                self.native_stop_returns.append(dict(p, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0), native=n))
                del self.pending_stops[entry]
        if self.pending_ns and address == self.pending_ns['return_PC']:
            p = self.pending_ns
            require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'compiled retirement full-return SP')
            require(self.word(B.READY_TASKS) == p['actor'], 'compiled retirement returned on another actor')
            self.ns_returns.append(dict(p, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0), native=self.retirement_native()))
            self.pending_ns = None
        s = self.build['symbols']
        if address == s['ns_retire_step']['value']:
            require(self.pending_ns is None, 'nested retirement source call')
            p = dict(entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1, actor=self.word(B.READY_TASKS), native=self.retirement_native())
            self.ns_entries.append(p)
            self.pending_ns = p
        actual_native_entry=address
        if address == (s['pg_stock_stop']['value'] & ~1): actual_native_entry=4779538
        if address == (s['pg_stock_free']['value'] & ~1): actual_native_entry=4779608
        if address in (4779538,4779608): actual_native_entry=-1 # now public gate patches, not native cleanup bodies
        if actual_native_entry in (4779538,4779608) and self.retirement_native()['ns_stage']!=3:actual_native_entry=-1
        if actual_native_entry in (3120924, 4422288, 4779538, 6190514, 4779608, 2586228):
            require(actual_native_entry not in self.pending_stops, 'nested same original retirement helper')
            n = self.retirement_native()
            require(n['ns_stage'] == 3 and n['ns_hold'] == n['native_mutation'] == n['native_calls'] == 1, 'original retirement entry lost cleanup hold')
            expected = self.source_tcb if actual_native_entry == 2586228 else self.mixer_tcb
            require(self.word(B.READY_TASKS) == expected, 'original retirement helper wrong Source/Mixer actor')
            if actual_native_entry == 2586228:
                require(self.regs()[:2] == [B.RECORD + 424, 0] and n['node_count'] == 1 and n['head'], 'original one-node removal input changed')
                require(len([p for p in self.sync_returns if p.get('barrier_kind') == 'Stop']) == 1, 'list removal before full original Stop sync return')
                require(n['prepared'] == 0 and (not any(bytes.fromhex(n['methods_hex']))) and (n['mixer_active'] == 0), 'list removal before native methods idle')
            p = dict(entry_PC=actual_native_entry,actual_entry_PC=address, entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1, actor=expected, args=self.regs(), native=n)
            self.native_stop_entries.append(p)
            self.pending_stops[actual_native_entry] = p
        if address == 4545670 and self.regs()[2] == 23:
            n = self.retirement_native()
            require(n['node_count'] == 1 and n['head'] == 0 and (n['ns_hold'] == n['native_calls'] == 1), 'notice23 misclassified as full removal/quiescence')
            require(self.regs()[1] == 0, 'unexpected notification metadata')
            self.notice23.append(dict(state=self.snapshot(), args=self.regs(), native=n))
        if address == 3704738 and 2586228 in self.pending_stops:
            self.cleanup_release_calls.append(dict(state=self.snapshot(), args=self.regs(), native=self.retirement_native()))

    def stop(self):
        require(self.invoke_kernel('mh_request_command', (5,), phase='controller requests actual Source Stop') == 0, 'Stop request failed')
        before = dict(native=self.retirement_native(), ns=self.ns_status(), sync_entries=len(self.sync_entries), sync_returns=len(self.sync_returns), actual_controller_snapshot=self.snapshot())
        self.attack_waiting_Stop()
        self.park()
        return dict(before_original_ACK=before, after_native_retirement=self.retirement_native(), status=self.ns_status(), source_status=self.status())

    def result(self, name, records):
        require(self.pending_ns is None and (not self.pending_stops), 'retirement frame still pending')
        terminal_native = self.retirement_native()
        terminal_status = self.ns_status()
        row = super().result(name)
        row.update(Stop_racer_checks=self.Stop_racer_checks,retirement_records=records,native_stop_entries=self.native_stop_entries, full_native_stop_returns=self.native_stop_returns, compiled_retirement_entries=self.ns_entries, full_compiled_retirement_returns=self.ns_returns, actual_retirement_stores=self.retirement_stores, notice23_before_count_commit=self.notice23, opaque_list_release_calls=self.cleanup_release_calls, retirement_terminal=terminal_native, retirement_status=terminal_status, Stop_ACK_orders_same_Mixer_only=True, original_heap_query_and_release_still_opaque_fixtures=True, native_control_remains_STOPPING=True, module_guard_and_original_TCBs_remain_resident=True, native_STOP_DONE_or_exclusive_hardware_drain_safe_unload_verified=False)
        return row

    def attack_waiting_Stop(self):
        before=self.retirement_native()
        if before['ns_stage']!=3:return
        require(before['ns_hold']==before['native_calls']==before['native_mutation']==1,'Stop waiting hold not retained')
        require(not any(p.get('barrier_kind')=='Stop'for p in self.sync_returns),'Stop ACK already returned before waiting racer')
        runs=self.claim()['racer_runs']
        require(self.invoke_kernel('rg_request_attack',phase='actual controller posts racer while Source waits native Stop ACK'),'Stop racer missing')
        self.check_racer('five foreign entries while Source waits original Stop ACK',runs+1)
        after=self.retirement_native();require(before==after,'racer mutated provider/list/cleanup hold while Source blocked')
        self.Stop_racer_checks.append(dict(before=before,after=after,racer=self.racer_checks[-1],state=self.snapshot()))


def complete(m,expected_fifo):
 n=m.retirement_native();s=m.ns_status();state=m.status()
 require(s[0]==4 and s[7]==s[8]==s[9]==1 and s[10]==expected_fifo and not s[12],'full native retirement did not complete')
 require(n['head']==n['node_count']==n['prepared']==n['mixer_active']==n['active_ticket']==n['installed']==0,'native source remains live')
 require(n['native_calls']==n['native_mutation']==0 and n['guard_held']==1 and state[8]==state[6]==state[7]==0,'hold leaked or fabricated STOP_DONE')
 require(m.producer()['owned'][4]==m.producer()['queue'][2]==0,'pending PCM or compressed input remains')
 require(len(m.notice23)==len(m.cleanup_release_calls)==1,'whole original list removal missing')
 ordered=[struct.unpack('<3I',bytes.fromhex(x['bytes_hex']))[0]&255 for x in m.message_receives]
 require(ordered[-3:]==[15,19,20],'original Stop order')
 cursor=len(m.codec_entries);m.media(m.packet(1));require(len(m.codec_entries)==cursor,'retired source decoded late input')
 for ch in(3,4):
  require(m.word(R.W.HEADS+4*ch)==0x01234000+ch*16 and struct.unpack('<H',m.uc.mem_read(R.W.ROWS+ch*R.W.STRIDE+0x1c0,2))[0]==ch,'Stop cleared another channel')
 require(m.claim()['active']==1 and m.claim()['owner']==m.source_tcb,'unexpected claim release')
 m.retirement_records.append(dict(kind='full resident retirement',native=n,status=s,source_status=state,original_FIFO_order=ordered,claim=m.claim()))
def run_case(m,name):
 m.load_native();m.install_tail_gate();m.install_route_gates()
 m.boot_kernel_only();m.construct_preexisting_audio();m.boot_both()
 m.ready();m.signal(7,b'\x04')
 if name=='warm_Stop_before_first_input':
  m.retirement_records.append(m.stop());m.media(m.packet(0))
  require(m.ns_status()[0]==6 and not m.native_stop_entries and not m.sync_entries and not m.codec_entries,'pre-input Stop invented native cleanup')
  return
 m.media(m.packet(0));m.complete_first_sync_and_attach_output()
 require(m.ns_status()[0]==2,'exact native registration/provider not captured')
 if name in('warm_full_PCM_pending_compressed_Stop','warm_Stop_during_actual_Mixer_borrow'):
  if name=='warm_Stop_during_actual_Mixer_borrow':m.command(10)
  for i in range(1,6):m.media(m.packet(i))
  require(m.producer()['owned'][4]==4 and m.producer()['queue'][2]==2,'four PCM/two compressed backpressure input absent')
  if name=='warm_Stop_during_actual_Mixer_borrow':
   m.park();require(m.ns_status()[6]>=1 and any(p['native']['leases']['borrow']for p in m.ns_entries),'Stop did not defer behind actual full Mixer borrow')
   complete(m,3);return
  m.retirement_records.append(m.stop());complete(m,4);return
 if name=='warm_foreign_head_change_keeps_anchor_pinned':
  m.fixture(HEAD,struct.pack('<I',0xd0ffffff),'explicit foreign native head mutation negative, not gated by all known APIs')
  m.retirement_records.append(m.stop());n=m.retirement_native()
  require(n['head']==0xd0ffffff and n['node_count']==1 and n['active_ticket']and n['installed']and not m.native_stop_entries and not m.notice23,'foreign native head removed or anchor released')
  cursor=len(m.codec_entries);m.media(m.packet(1));require(len(m.codec_entries)==cursor,'pinned error reached decoder')
  return
 if name=='native_Disconnect_while_paused_runs_warm_retirement':
  m.signal(9,b'\x04');m.park()
  require(m.source_pause()['mh_remote_paused']==1 and not m.remote_state()['admitting'],'Suspend did not pause')
  m.native('original Disconnect F2 requests resident native retirement',0x50be1c,(R.W.R.MEDIA_LCID,))
  m.attack_waiting_Stop();m.park();complete(m,1)
  require(m.remote_state()['retired']==1 and m.remote_state()['stop_requests']==1,'Disconnect did not retire remote session')
  return
 raw=m.cycle(True);m.compare(raw,m.expected(0));m.retirement_records.append(dict(kind='actual music before Stop',PCM_hex=raw.hex(),expected_PCM_hex=m.expected(0).hex()))
 m.challenge_playing();m.other_route_controls()
 before=m.retirement_native();ret=m.invoke_kernel('ns_retire_step',phase='foreign controller cannot perform warm native retirement');after=m.retirement_native()
 require(ret==0xfffffffb and before==after and not m.native_stop_entries,'foreign controller accepted Source retirement')
 m.retirement_records.append(dict(kind='wrong actor rejected',before=before,after=after,returned=ret))
 m.retirement_records.append(m.stop());complete(m,0)
 require(m.uc.mem_read(B.POOL+576+12,1)[0]==1,'Stop released an unrelated allocated provider')
def collect_modules(module,deps,seen):
 if id(module)in seen:return
 seen.add(id(module));p=getattr(module,'__file__',None)
 if not p or not Path(p).is_file()or not Path(p).is_relative_to(ROOT)or'site-packages'in Path(p).parts:return
 deps[rel(Path(p))]=sha(Path(p))
 for v in vars(module).values():
  if isinstance(v,types.ModuleType):collect_modules(v,deps,seen)
def dump_compressed(path,data):
 with path.open('xb')as raw:
  with gzip.GzipFile(fileobj=raw,mode='wb',compresslevel=1,mtime=0)as zipped:
   with io.TextIOWrapper(zipped,encoding='utf-8',newline='\n')as text:
    json.dump(data,text,indent=2);text.write('\n')
def decoded_sha(path):
 h=hashlib.sha256()
 with gzip.open(path,'rb')as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
PNAMES=('start','stop','free','config','reset','seek')
class ProviderVM(Retirement):
 def __init__(self,*args):
  self.pg_entries=[];self.pg_returns=[];self.pg_pending={};self.pg_checks=[];self.pg_posts=[];self.pg_native_actor_entries=[];self.pg_notes=[];self.pg_controls=[]
  super().__init__(*args)
 def finish_pg(self,pc,ordinary=False):
  for name,p in list(self.pg_pending.items()):
   if pc==p['return_PC'] and self.word(B.READY_TASKS)==p['entry']['current_TCB']:
    state=self.snapshot();require(state['GP16'][13]==p['entry_SP'] and state['GP16'][4:12]==p['entry']['GP16'][4:12],'provider gate full ABI '+name)
    self.pg_returns.append(dict(p,returned=state,r0=state['GP16'][0],actual_emu_end_PC=ordinary));del self.pg_pending[name]
 def invoke_kernel(self,*args,**kwargs):
  r=super().invoke_kernel(*args,**kwargs);self.finish_pg(self.uc.reg_read(UC_ARM_REG_PC),True);return r
 def pg_state(self):
  s=self.build['symbols'];return dict(pinned=self.word(s['pg_pinned']['value']),index=self.word(s['pg_index']['value']),epoch=self.word(s['pg_epoch']['value']),notes=self.word(s['pg_allocation_notes']['value']),masked_scans=self.word(s['pg_masked_scans']['value']),runs=self.word(s['pg_racer_runs']['value']),denied=list(struct.unpack('<6I',self.uc.mem_read(s['pg_denied']['value'],24))),forwarded=list(struct.unpack('<6I',self.uc.mem_read(s['pg_forwarded']['value'],24))))
 def code(self,uc,address,size,data):
  super().code(uc,address,size,data);self.finish_pg(address)
  s=self.build['symbols'];name=next((n for n in PNAMES if address==s['pg_'+n+'_gate']['value']),None)
  if name:
   require(name not in self.pg_pending,'nested provider gate '+name)
   p=dict(name=name,entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,args=self.regs(),reservation=self.pg_state());self.pg_entries.append(p);self.pg_pending[name]=p
  if address==s['pg_note_allocate']['value']:
   args=self.regs();index=self.word(args[0]);p=dict(state=self.snapshot(),args=args,index=index,busy=self.uc.mem_read(B.POOL+index*576+12,1)[0]if index<5 else None)
   if args[0]==B.RECORD+240 and args[1]==0:
    require(p['state']['CPSR']&128 and index<5 and p['busy']==1,'private allocation note outside IRQ exclusion/native busy claim')
   self.pg_notes.append(p)
  racer=self.word(s['pg_racer_tcb']['value'])
  if racer and address==B.POST and self.regs()[0]==racer:self.pg_posts.append(dict(state=self.snapshot(),reservation=self.pg_state(),racer_TCB=racer))
  if address==s['pg_racer_entry']['value']:
   require(racer and self.word(B.READY_TASKS)==racer,'provider racer not real native TCB');self.pg_native_actor_entries.append(self.snapshot())
 def install_provider_gates(self):
  for p in self.build['selected_native_provider_entry_barriers']:
   require(bytes(self.uc.mem_read(p['address'],p['patch_bytes'])).hex()==p['before_hex'],'provider native prefix changed')
   self.patch(p['address'],bytes.fromhex(p['after_hex']),'VM-only provider entry '+p['name']);self.uc.ctl_remove_cache(p['address'],p['address']+p['patch_bytes'])
  self.initial_ordinal=self.ordinal;self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if p&unicorn.UC_PROT_WRITE};self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}
 def pool_snapshot(self):return bytes(self.uc.mem_read(B.POOL,5*576)).hex()
 def reset_unclaimed(self):
  for i in range(5):self.fixture(B.POOL+i*576+12,b'\x01','explicit five busy slots before unclaimed original reset control')
  start=self.ordinal;self.invoke_kernel(0x48eed1,phase='unclaimed reset relocated whole original five-slot loop')
  stores=[x for x in self.journal if x['ordinal']>start and int(x['address'],16)in {B.POOL+i*576+12 for i in range(5)}]
  require(len(stores)==5 and all(x['value']==0 for x in stores),'unclaimed relocated reset did not clear five original busy bytes')
  self.pg_controls.append(dict(kind='unclaimed whole reset',stores=stores,reservation=self.pg_state()))
 def boot_pg_racer(self):
  s=self.build['symbols'];self.fixture(s['pg_racer_stack']['value'],b'\xa5'*8192,'explicit provider racer stack guards')
  require(self.invoke_kernel('pg_boot_racer',phase='native provider racer task creation'),'provider racer boot failed');self.park()
 def attack_pg(self,phase):
  before=dict(pool=self.pool_snapshot(),native=self.retirement_native());old=self.pg_state();racer=self.word(self.build['symbols']['pg_racer_tcb']['value'])
  require(self.invoke_kernel('pg_request_attack',phase=phase)==racer,'provider racer POST failed')
  after=dict(pool=self.pool_snapshot(),native=self.retirement_native());now=self.pg_state();results=list(struct.unpack('<6I',self.uc.mem_read(self.build['symbols']['pg_attack_results']['value'],24)))
  require(before==after and now['runs']==old['runs']+1 and results==[8,8,0xf0,8,0xf0,8],'foreign provider task changed reserved native audio')
  require(now['denied']==[n+1 for n in old['denied']],'six denial counters not advanced')
  self.pg_checks.append(dict(name=phase,before=before,after=after,prior=old,result=now,results=results,void_free_reset_results_are_markers_not_ABI_success=True))
 def attack_waiting_Stop(self):
  super().attack_waiting_Stop()
  if self.retirement_native()['ns_stage']==3:self.attack_pg('provider racer while Source waits original Stop ACK')
 def unclaimed_config_free(self):
  index=self.other_controls['other_provider'];private=self.pg_state()['index'];before=bytes(self.uc.mem_read(B.POOL+private*576,576)).hex();ptr=B.old.RESULT+1024
  self.fixture(ptr,struct.pack('<3I',3,22050,8)+bytes(548),'explicit other provider format input')
  result=self.invoke_kernel(0x48eea5,(index,ptr,2),phase='unclaimed provider original format forwarding')
  require(bytes(self.uc.mem_read(B.POOL+index*576,12))==struct.pack('<3I',3,22050,8),'unclaimed config did not execute original stores')
  self.invoke_kernel(0x48ee59,(index,),phase='unclaimed provider original free forwarding')
  require(self.uc.mem_read(B.POOL+index*576+12,1)[0]==0 and bytes(self.uc.mem_read(B.POOL+private*576,576)).hex()==before,'other free touched private provider')
  self.pg_controls.append(dict(kind='unclaimed config and void free',index=index,private=private,configuration_original_return=result,private_bytes_preserved=True))
 def allocate_after_Stop(self):
  p=B.old.RESULT+512;private=self.pg_state()['index'];before=bytes(self.uc.mem_read(B.POOL+private*576,576)).hex();self.fixture(p,struct.pack('<I',0xfffffffe),'ordinary allocator output after private retirement')
  require(self.invoke_kernel(0x48ee69,(p,),phase='original allocator skips pinned retired private slot')==0,'retired original allocation failed');index=self.word(p)
  require(index!=private and self.pg_state()['masked_scans']==1 and bytes(self.uc.mem_read(B.POOL+private*576,576)).hex()==before,'allocator reused or changed retired private slot')
  self.invoke_kernel(0x48ee59,(index,),phase='ordinary post-retirement provider free')
  self.pg_controls.append(dict(kind='retired reservation scanner exclusion',other_index=index,private_index=private,original_private_busy_restored=True,reservation=self.pg_state()))
 def result(self,name,records):
  require(not self.pg_pending,'provider gate still pending');row=super().result(name,records)
  row.update(provider_gate_entries=self.pg_entries,provider_gate_full_returns=self.pg_returns,provider_racer_native_POSTs=self.pg_posts,provider_racer_actor_entries=self.pg_native_actor_entries,provider_racer_checks=self.pg_checks,provider_allocation_note_entries=self.pg_notes,provider_controls=self.pg_controls,provider_reservation_final=self.pg_state(),six_provider_entry_gates_not_all_backend_aliases_or_writers=True);return row
def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn required');out=BASE/'guest-v2';out.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v3.json').read_text());reference=json.loads(I.REFERENCE.read_text());deps=dict(build['source_sha256']);deps.update(reference['source_sha256'])
 for p in(Path(__file__),BASE/'build-v3.json',ROOT/build['ELF'],ROOT/build['combined_binary'],I.REFERENCE):deps[rel(p)]=sha(p)
 collect_modules(R,deps,set());collect_modules(K,deps,set());require(all(sha(ROOT/p)==h for p,h in deps.items()),'dependency changed')
 dump(out/'inputs-at-run.json',deps);(out/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 elf=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','provider_elf').ELF32(ROOT/build['ELF']);m=None
 try:
  m=ProviderVM(R.R.NativeImage(),elf,build,reference);m.load_native();m.install_tail_gate();m.install_route_gates();m.install_provider_gates();m.boot_kernel_only();m.reset_unclaimed();m.construct_preexisting_audio();m.boot_both();m.ready();m.signal(7,b'\x04');m.media(m.packet(0));m.complete_first_sync_and_attach_output()
  require(m.pg_state()['pinned']==1 and m.pg_state()['notes']==1 and m.pg_state()['index']==m.word(B.RECORD+240),'actual selected provider not pinned')
  m.boot_pg_racer();m.attack_pg('provider racer after actual private binding');raw=m.cycle(True);m.compare(raw,m.expected(0));m.retirement_records.append(dict(kind='actual music before Stop',PCM_hex=raw.hex(),expected_PCM_hex=m.expected(0).hex()))
  m.challenge_playing();m.other_route_controls();m.unclaimed_config_free();m.retirement_records.append(m.stop());complete(m,0);m.attack_pg('provider racer after native retirement');m.allocate_after_Stop()
  row=m.result('six_provider_entries_actual_allocator_pin_music_Stop_and_other_callers');path=out/'provider-entry-integration.json.gz';dump_compressed(path,row)
  proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,cases=[dict(name=row['name'],path=rel(path),sha256=sha(path),encoding='gzip-json',decoded_sha256=decoded_sha(path),passed=True)],case_count=1,provider_gate_full_returns=len(m.pg_returns),provider_foreign_racer_runs=len(m.pg_checks),provider_foreign_rejections=18,original_native_retirement_full_returns=len(m.native_stop_returns),original_reset_loop_five_stores=True,unclaimed_config_free_and_retired_allocator_forward=True,actual_allocator_private_pin_under_IRQ=True,claim_guard_and_tasks_remain_pinned=True,backend_aliases_all_writers_STOP_DONE_yield_unload_App_phone_or_device=False,device_IO=False)
  dump(BASE/'provider-entry-v2-proof.json',proof);print(json.dumps(dict(all_passed=True,provider_gate_full_returns=len(m.pg_returns),provider_racer_runs=len(m.pg_checks),provider_rejections=18,native_Stop_returns=len(m.native_stop_returns),device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if m:fail.update(phase=m.phase,trace=m.trace,state=m.snapshot(),CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,provider_entries=m.pg_entries,provider_returns=m.pg_returns,provider_checks=m.pg_checks,retirement_entries=m.native_stop_entries,retirement_returns=m.native_stop_returns)
  dump_compressed(out/'terminal-failure.json.gz',fail);raise
if __name__=='__main__':main()
