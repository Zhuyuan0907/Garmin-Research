#!/usr/bin/env python3
"""Independent FILE ONLY review of frozen root mixer synchronization V3.

No guest module, Unicorn import, code execution or device access. Decode saved
CPU stores using exact MAIN/ELF bytes and GP16/CPSR, replay joint fixture/CPU
events, verify serialized native/outer returns and declared actor inputs.
"""
import ast, hashlib, json, re, struct, sys
from datetime import datetime, timezone
from collections import Counter, defaultdict
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'staging/native-player-mixer-sync'
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_REG, ARM_OP_MEM, ARM_INS_PUSH, ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH, ARM_INS_STRD, ARM_INS_STM, ARM_INS_STMDA, ARM_INS_STMDB, ARM_INS_STMIB
READY, ALL, IRQ = 0xF09090, 0xF0908C, 0xF09094
RECORD, POOL, MIXER = 0x034E7F48, 0x034E3CF4, 0x034E5CF8
DESC, BUFFER, SCRATCH, RESULT, RETURN = 0x09800020, 0x09801020, 0x09803F00, 0x08C00020, 0x08D00000
C, I, S, M = 0x09503F90, 0x09508F90, 0x07803F90, 0x09601F90
STACKS = {C:(0x09500000,16384), I:(0x09505000,16384), S:(0x07800000,16384), M:(0x09600000,8192)}
ARM_MAIN = [(0x2FCF44,0x2FCF6C),(0x2FCFB0,0x2FCFEC),(0x2FD01C,0x2FD028),
            (0x2FD03C,0x2FD050),(0x2FD06C,0x2FD0A8),(0x2FD0C4,0x2FD0D0),(0x300D40,0x300D98),(0x358E70,0x358EBA),(0x353B44,0x353B5C),
            (0x35B4F4,0x35B548),(0x3732C8,0x37339C),(0x39129C,0x3912F0)]
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()
def rel(p): return str(p.relative_to(ROOT))
def load(p): return json.loads(p.read_text())
def create(p,obj):
    with p.open('x') as f: json.dump(obj,f,indent=2);f.write('\n')
def require(x,msg):
    if not x: raise AssertionError(msg)
def get(z,address,n):
    out=[(a,b) for a,b in z.items() if a<=address and address+n<=a+len(b)]
    require(len(out)==1,'one whole zone '+hex(address)+' '+str(n));a,b=out[0]
    return bytes(b[address-a:address-a+n])
def put(z,address,raw):
    out=[a for a,b in z.items() if a<=address and address+len(raw)<=a+len(b)]
    require(len(out)==1,'write outside one whole zone '+hex(address));a=out[0]
    z[a][address-a:address-a+len(raw)]=raw
def word(z,address): return struct.unpack('<I',get(z,address,4))[0]
def bl(pc,target):
    delta=target-pc-4
    require(delta%2==0 and -(1<<22)<=delta<(1<<22),'Thumb BL range')
    return struct.pack('<HH',0xF000|((delta>>12)&0x7FF),0xF800|((delta>>1)&0x7FF))
class ELF:
    def __init__(self,p):
        self.raw=p.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',self.raw)
        require(h[0][:7]==b'\x7fELF\1\1\1' and h[1]==2 and h[2]==40 and h[11]==40,'ARM32 ET_EXEC')
        keys=('name_index','type','flags','address','offset','size','link','info','alignment','entry_size')
        self.sections=[dict(zip(keys,struct.unpack_from('<10I',self.raw,h[6]+i*40)),index=i) for i in range(h[12])]
        names=self.data(self.sections[h[13]])
        for s in self.sections:s['name']=self.string(names,s['name_index'])
        table=next(s for s in self.sections if s['type']==2);strings=self.data(self.sections[table['link']]);self.symbols=[]
        for p in range(table['offset'],table['offset']+table['size'],16):
            n,v,size,info,other,index=struct.unpack_from('<IIIBBH',self.raw,p)
            self.symbols.append(dict(name=self.string(strings,n),value=v,size=size,section=index,type=info&15))
        require(not [s for s in self.symbols if s['name'] and s['section']==0],'Undefined ELF symbol')
        self.mapping=sorted((s['value'],s['name'][1],s['section']) for s in self.symbols if s['name'].startswith(('$a','$t','$d')))
    @staticmethod
    def string(b,n):return b[n:].split(b'\0',1)[0].decode('ascii')
    def data(self,s):
        require(s['type']!=8,'NOBITS has no file data');return self.raw[s['offset']:s['offset']+s['size']]
    def at(self,address,n):
        out=[s for s in self.sections if s['flags']&2 and s['type']!=8 and s['address']<=address and address+n<=s['address']+s['size']]
        require(len(out)==1,'one ELF section '+hex(address));s=out[0]
        return self.data(s)[address-s['address']:address-s['address']+n],s
    def symbol(self,name):
        out=[s for s in self.symbols if s['name']==name];require(len(out)==1,name);return out[0]
    def mode(self,address):
        _,s=self.at(address,2);out=[(a,m) for a,m,index in self.mapping if index==s['index'] and a<=address]
        require(bool(out),'ELF mapping symbol '+hex(address));return max(out)[1]

MD={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
for m in MD.values():m.detail=True
def pred(cond,psr):
    n,z,c,v=[bool(psr&(1<<b)) for b in (31,30,29,28)]
    return [z,not z,c,not c,n,not n,v,not v,c and not z,not c or z,n==v,n!=v,not z and n==v,z or n!=v,True,False][cond]
def reg(i,r,gp):
    name=i.reg_name(r);aliases={'sb':9,'sl':10,'fp':11,'ip':12,'sp':13,'lr':14,'pc':15}
    k=int(name[1:]) if re.fullmatch(r'r\d+',name) else aliases[name]
    require(k<15,'PC source register store not reviewed');return gp[k]
def store_writes(i,gp,thumb,cpsr):
    if not thumb:require(pred(int.from_bytes(i.bytes,'little')>>28,cpsr),'Conditional store predicate false')
    ops=i.operands;writes={}
    if i.id in (ARM_INS_STR,ARM_INS_STRB,ARM_INS_STRH,ARM_INS_STRD):
        mem=next(o for o in ops if o.type==ARM_OP_MEM)
        base=reg(i,mem.mem.base,gp);index=0
        if mem.mem.index:
            index=reg(i,mem.mem.index,gp)
            if mem.shift.value:
                require(mem.shift.type==2,'Unreviewed memory shift');index=(index<<mem.shift.value)&0xffffffff
            if mem.subtracted:index=-index
        address=(base+mem.mem.disp+index)&0xffffffff
        source=[o.reg for o in ops if o.type==ARM_OP_REG]
        width={ARM_INS_STR:4,ARM_INS_STRB:1,ARM_INS_STRH:2,ARM_INS_STRD:8}[i.id]
        value=reg(i,source[0],gp)
        if i.id==ARM_INS_STRD:
            require(len(source)==2,'STRD two registers');value|=reg(i,source[1],gp)<<32
        for k,b in enumerate((value&((1<<(8*width))-1)).to_bytes(width,'little')):writes[address+k]=b
    elif i.id in (ARM_INS_PUSH,ARM_INS_STM,ARM_INS_STMDA,ARM_INS_STMDB,ARM_INS_STMIB):
        require('^' not in i.op_str,'User bank STM absent from scope')
        if i.id==ARM_INS_PUSH:base=gp[13];source=[o.reg for o in ops];start=base-4*len(source)
        else:
            require(ops[0].type==ARM_OP_REG and all(o.type==ARM_OP_REG for o in ops),'STM register operands')
            base=reg(i,ops[0].reg,gp);source=[o.reg for o in ops[1:]]
            start={ARM_INS_STM:base,ARM_INS_STMIB:base+4,ARM_INS_STMDB:base-4*len(source),ARM_INS_STMDA:base-4*(len(source)-1)}[i.id]
        for k,r in enumerate(source):
            for j,b in enumerate(reg(i,r,gp).to_bytes(4,'little')):writes[(start+4*k+j)&0xffffffff]=b
    else:raise AssertionError('Unreviewed store '+i.mnemonic+' '+i.op_str)
    return writes

class Replay:
    def __init__(self,row,n,elf,symbols):
        self.row=row;self.n=n;self.elf=elf;self.symbols=symbols
        self.z={int(a):bytearray.fromhex(b) for a,b in row['initial_whole_RW_zones'].items()}
        self.final={int(a):bytes.fromhex(b) for a,b in row['final_whole_RW_zones'].items()}
        self.counts=Counter();self.sites={};self.snapshots={};self.tcb_tags=[];self.contexts=[]
        self.checkpoints=set();self.callbacks=[]
        self.offsets=struct.unpack('<5I',elf.at(symbols['aas_offsets']['value'],20)[0])
        self.guard=symbols['aas_guard']['value'];self.control=symbols['aas_control']['value']
        self.eventchecks=defaultdict(list)
    def leases(self,z):
        g,c=self.guard,self.control;o=self.offsets
        return dict(borrow=word(z,g+o[0]),selected_session=word(z,g+o[1]),selected_instance=word(z,g+o[2]),
                    media=word(z,c+o[3]),callback=word(z,c+o[4]),current_TCB=word(z,READY))
    def state_check(self,state,z,label):
        gp=state['GP16'];require(len(gp)==16 and all(type(k)is int and 0<=k<=0xffffffff for k in gp),'GP16 '+label)
        require(state['current_TCB']==word(z,READY),'Current head readback '+label)
        require(word(z,IRQ)==0,'Declared normal current getter IRQmarker '+label)
    def check_at(self,ordinal,z):
        for label,state,view in self.eventchecks.get(ordinal,[]):
            self.state_check(state,z,label)
            if view is not None:require(self.leases(z)==view,'Live lease readback '+label)
        if ordinal in self.checkpoints:self.snapshots[ordinal]={a:bytes(b) for a,b in z.items()}
    def enqueue(self,label,state,view=None):self.eventchecks[state['ordinal']].append((label,state,view))
    def cold(self):
        require(set(self.z)==set(self.final) and len(self.z)==24,'24 tracked whole zones')
        specs={x['start']:x for x in self.row['zones']}
        require(len(specs)==27 and len([x for x in specs.values() if x['protection']&4])==3,'Zone recipe')
        require(set(self.z)=={a for a,x in specs.items() if not x['protection']&4},'Declared zone names')
        cold={a:bytearray(len(b)) for a,b in self.z.items()}
        put(cold,0xF00000,self.n.read(0xCB1980,0x7224c))
        for s in self.elf.sections:
            if s['flags']&2 and s['size'] and s['type']!=8 and any(a<=s['address'] and s['address']+s['size']<=a+len(b) for a,b in cold.items()):put(cold,s['address'],self.elf.data(s))
        early=[e for e in self.row['declared_fixture_mutations'] if e['ordinal']<=self.row['initial_ordinal']]
        require([e['ordinal'] for e in early]==list(range(1,self.row['initial_ordinal']+1)),'Cold fixture ordinal')
        for e in early:
            a=int(e['address'],16);b=bytes.fromhex(e['before_hex']);after=bytes.fromhex(e['after_hex'])
            require(get(cold,a,len(b))==b and len(after)==len(b),'Cold fixture exact preimage '+e['reason']);put(cold,a,after)
        require(cold==self.z,'Independent MAIN initialized copy/ELF/cold fixtures')
        require(word(self.z,READY)==word(self.z,ALL)==word(self.z,IRQ)==0,'Declared initial empty kernel inputs')
        require(get(self.z,RETURN,4096)==bytes(4096),'RX sentinel source declared zero')
        expected_patches=[]
        for pc,name,veneer in ((0x2fa294,'mh_selector_bridge',0x6e8000),(0x2fa536,'mcs_pull_bridge',0x6e8010),(0x2fa572,'mcs_pull_bridge',0x6e8020),(0x3b9c54,'ms_initializer_sync_bridge',0x6e8030)):
            target=self.symbols[name]['value'];oldtarget=0x2f9f2e if pc==0x2fa294 else (0x46cc7a if pc==0x3b9c54 else 0x2f9cca)
            require(self.n.read(pc,4)==bl(pc,oldtarget),'Stock direct BL')
            for a,b,why in ((pc,bl(pc,veneer),'guest call-site BL'),(veneer,b'\x00\x4b\x18\x47'+struct.pack('<I',target),'guest Thumb LDR/BX to ARM veneer')):
                expected_patches.append(dict(address=a,before_hex=self.n.read(a,len(b)).hex(),after_hex=b.hex(),reason=why,original_return_LR=pc+5,target_symbol=name,target_address=target))
        require(self.row['patches']==expected_patches,'Exact declared eight guest patches')
        rx={}
        for a,x in specs.items():
            if not x['protection']&4:continue
            b=bytearray(x['size'])
            if a==0x50000:
                b[:]=self.n.read(a,len(b))
                for p in expected_patches:b[p['address']-a:p['address']-a+len(bytes.fromhex(p['after_hex']))]=bytes.fromhex(p['after_hex'])
            elif a==0x9400000:b[:4]=bytes.fromhex('feffffea')
            else:
                for s in self.elf.sections:
                    if s['flags']&2 and s['type']!=8 and a<=s['address'] and s['address']+s['size']<=a+len(b):b[s['address']-a:s['address']-a+s['size']]=self.elf.data(s)
            rx[str(a)]=hashlib.sha256(b).hexdigest()
        require(rx==self.row['unchanged_after_declared_patches_RX_sha256'],'Independent exact declared-patches RX baseline')
        final_rx=self.row['actual_final_RX_zones']
        require(set(final_rx)==set(rx),'Actual finalRX dump completeness')
        for a,raw in final_rx.items():
            require(len(bytes.fromhex(raw))==specs[int(a)]['size'],'Actual finalRX wholezone size')
            require(hashlib.sha256(bytes.fromhex(raw)).hexdigest()==rx[a],'Actual finalRX equals independently reconstructed patchedbaseline '+a)
        self.final_RX_verified=len(final_rx)
    def opcode(self,e):
        pc=int(e['PC'],16);raw=bytes.fromhex(e['opcode_hex']);thumb=e['Thumb'];gp=e['GP16'];cpsr=e['CPSR']
        require(type(thumb)is bool and thumb==bool(cpsr&32) and gp[15]==pc,'Store GP PC/ISA '+hex(pc))
        require(len(raw) in (2,4),'Store opcode width')
        if 0x50000<=pc<0xC00000:
            require(raw==self.n.read(pc,len(raw)),'Exact original MAIN store bytes '+hex(pc))
            require(thumb==not_any_arm(pc),'Bounded original mixed-mode store range '+hex(pc));source='MAIN'
        else:
            data,s=self.elf.at(pc,len(raw));require(s['flags']&4 and data==raw,'Exact executable ELF store bytes '+hex(pc))
            thunk=self.symbols['mcs_original_pull_thunk']['value']&~1
            if pc==thunk:
                require(thumb and raw==self.n.read(0x2f9cca,2),'Original compatible Thumb thunk PUSH')
            else:require(self.elf.mode(pc)==('t' if thumb else 'a'),'ELF independent mapping ISA '+hex(pc))
            source='ELF'
        ins=next(MD[thumb].disasm(raw,pc,count=1));require(ins.size==len(raw),'Instruction complete')
        self.counts[(source,'Thumb' if thumb else 'ARM',ins.mnemonic,e['size'])]+=1
        self.sites[(pc,thumb)]={'PC':hex(pc),'Thumb':thumb,'opcode_hex':raw.hex(),'instruction':ins.mnemonic+' '+ins.op_str}
        return ins
    def run(self):
        events=sorted((e for e in self.row['CPU_store_journal']+self.row['declared_fixture_mutations'] if e['ordinal']>self.row['initial_ordinal']),key=lambda e:e['ordinal'])
        require([e['ordinal'] for e in events]==list(range(self.row['initial_ordinal']+1,self.row['initial_ordinal']+1+len(events))),'Contiguous joint ordinals')
        self.check_at(self.row['initial_ordinal'],self.z);pending=None;seen=set()
        for e in events:
            a=int(e['address'],16);before=bytes.fromhex(e['before_hex']);require(get(self.z,a,len(before))==before,'Joint exact preimage '+hex(a)+' '+str(e['ordinal']))
            if e['event_type']=='actual_CPU_store':
                n=e['size'];require(n==len(before) and n in (1,2,4,8),'CPU store width')
                self.state_check(e,self.z,'CPUstore '+str(e['ordinal']));ins=self.opcode(e)
                writes=store_writes(ins,e['GP16'],e['Thumb'],e['CPSR'])
                after=(e['value']&((1<<(n*8))-1)).to_bytes(n,'little')
                require(all(writes.get(a+k)==v for k,v in enumerate(after)),'GP16 effective address/value '+e['PC']+' '+str(e['ordinal']))
                sig=(int(e['PC'],16),tuple(e['GP16']),e['CPSR'])
                if pending is not None and sig!=pending:
                    require(seen==set(previous_writes),'Incomplete multiword instruction group');seen=set()
                pending=sig;previous_writes=writes
                require(not seen.intersection(range(a,a+n)),'Duplicate store lane within instruction');seen.update(range(a,a+n))
                if seen==set(writes):pending=None;seen=set()
                if a==RECORD+0x160:self.callbacks.append(dict(ordinal=e['ordinal'],PC=e['PC'],value=e['value'],actor=e['current_TCB']))
                if int(e['PC'],16) in (0x2fcfd0,0x2fd08c):self.contexts.append(dict(PC=e['PC'],ordinal=e['ordinal'],address=e['address'],value=e['value']))
                if a in (C+24,I+24,S+24,M+24):self.tcb_tags.append(dict(PC=e['PC'],ordinal=e['ordinal'],address=e['address'],value=e['value']))
            else:
                require(e['event_type']=='declared_host_fixture' and pending is None,'Declared fixture interrupts native multiword group')
                after=bytes.fromhex(e['after_hex']);require(len(after)==len(before),'Fixture length')
                # Allocator output/canaries, stack/input descriptors, outputring,
                # initialready membership are explicit. Selected/provider,
                # capabilities/tickets/currentactor afterinitial cannot be seeded.
                require(not (a<RECORD+0x13c and a+len(after)>RECORD+0xf0),'Fixture seeded selector/provider methods')
                require(not (a<POOL+10*576 and a+len(after)>POOL),'Fixture seeded provider pool')
                require(not (a<0x07005000 and a+len(after)>0x07004000),'Fixture seeded compiled capability/ticket state')
            put(self.z,a,after);self.check_at(e['ordinal'],self.z)
        require(pending is None,'Final incomplete store instruction')
        require(set(self.eventchecks)<=set(range(self.row['initial_ordinal'],self.row['initial_ordinal']+len(events)+1)),'Checkpoint ordinal outside event history')
        require(set(self.checkpoints)==set(self.snapshots),'Missing checkpoint snapshots')
        require({a:bytes(b) for a,b in self.z.items()}==self.final,'24 exact actual-after whole zones')
        require(get(self.z,RETURN,4096)==bytes(4096),'ReturnRXsentinel unchanged by guest')
        return dict(CPU_stores=len(self.row['CPU_store_journal']),joint_events=len(events),tracked_whole_zones=24,actual_RW_zones_from_frozen_parent_permission_recipe=23,unchanged_RX_return_sentinel_tracked_as_RW=1,unique_store_sites=len(self.sites),ISA_and_store_counts=[dict(source=k[0],ISA=k[1],instruction=k[2],hook_bytes=k[3],count=v) for k,v in sorted(self.counts.items())],whole_zone_after_sha256={hex(a):hashlib.sha256(b).hexdigest() for a,b in self.final.items()})

def not_any_arm(pc):return not any(a<=pc<b for a,b in ARM_MAIN)
def check_actor(state,tcb):
    gp=state['GP16'];require(state['current_TCB']==tcb,'Captured native actor');require((state['CPSR']&31) in (0x1f,0x13),'Normal privileged actor mode')
    base,size=STACKS[tcb];require(base<=gp[13]<=tcb,'Actor SP belongs to native stack')
def verify_case(d,n,elf,symbols):
    name=d['name'];rp=Replay(d,n,elf,symbols);rp.cold()
    require(d['source_TCB']==S and d['mixer_TCB']==M and d['controller_TCB']==C,'Built native actors')
    for entry in d['original_scheduled_actor_entries']:rp.enqueue('original actor/kernel '+hex(entry['PC']),entry['state'])
    for entry in d['selector_bridge_entries']:rp.enqueue('selector bridge',entry['state'],entry['leases'])
    for entry in d['compiled_reader_entries']:rp.enqueue('reader',entry['state'],entry['leases'])
    for entry in d['original_message_sends']+d['original_message_receives']:rp.enqueue('FIFO',entry['state']);rp.checkpoints.add(entry['state']['ordinal'])
    for entry in d['full_native_returns']:
        rp.enqueue('full entry',entry['entry'],entry['entry_leases']);rp.enqueue('full return',entry['returned'],entry['return_leases'])
        rp.checkpoints.update((entry['entry']['ordinal'],entry['returned']['ordinal']))
    for entry in d['original_mixer_call_site_returns']:
        rp.enqueue('outer entry',entry['entry']);rp.enqueue('outer return',entry['returned'],entry['return_leases'])
        rp.checkpoints.update((entry['entry']['ordinal'],entry['returned']['ordinal']))
    for entry in d['declared_service_calls']:
        rp.enqueue('fixture service before',entry['before']);rp.enqueue('fixture service after',entry['after'])
        rp.checkpoints.add(entry['before']['ordinal'])
    for entry in d['terminal_register_snapshots']:rp.enqueue('idle endpoint',entry)
    for entry in d['original_queue_returns']:rp.enqueue('full queue return',entry['returned'])
    prepare_sync_checkpoints(rp,d,symbols)
    counts=rp.run();z=rp.final;g=rp.guard;c=rp.control
    # Native cold task construction is real; ready membership and descriptors
    # for initial controller/idle remain declared cold inputs.
    builders=[e for e in d['original_scheduled_actor_entries'] if e['PC']==0x358bf8]
    require(len(builders)==5,'Five actual original context builders including unscheduledTimer')
    require([b['args'][0] for b in builders]==[0x09401800,0x09401820,0x02D226E0,symbols['source_descriptor']['value'],MIXER+0x64],'Exact builder descriptor pointers')
    require(struct.unpack('<5I',get(z,symbols['source_descriptor']['value'],20))==(symbols['mh_source_entry']['value'],0,0x07804000,12<<16,0),'Compiled source typed descriptor')
    require(struct.unpack('<5I',get(z,MIXER+0x64,20))==(0x2fa0dd,0x09604000,0x09602000,0x0117140c,MIXER+0x3c),'Original mixer typed descriptor')
    require(word(z,MIXER+0x78)==M and word(z,M+8)==0x09604000,'Original mixer TCB/messagequeue')
    require(word(z,M+28)==MIXER+0x3c,'Original mixer metadata pointer')
    require(word(z,READY)==C and word(z,C)==I and word(z,I)==0,'Final ready controller/idle')
    require(word(z,ALL)==M,'ALL head')
    for t,next_t,prev_link,prio,state,tag in [(M,S,ALL,23,2,0x1ed1a247),(S,0x02D227C8,M+40,12,2,0xed1a247),(C,I,0x02D227C8+40,16,1,0xed1a247),(I,0,C+40,240,1,0xed1a247)]:
        require(word(z,t+40)==next_t and word(z,t+44)==prev_link,'Original ALL intrusive linkage '+hex(t))
        require(get(z,t+16,2)==bytes([prio,prio]) and get(z,t+22,1)==bytes([state]),'Native priority/state '+hex(t))
        require(word(z,t+24)==tag and word(z,t+32)==word(z,t+36)==0,'Native tag/ownedhead/opaque state '+hex(t))
        sp=word(z,t+12);base,size=STACKS[t];require(base+64<=sp and sp+52<=t,'Resident saved52 frame '+hex(t))
        require(get(z,base,64)==b'\xa5'*64,'Native stack leading64 canary')
        if t in (S,M):
            require(word(z,t)==0xffffffff and word(z,sp+4)==0x2fd0ac,'Blocked original WAIT resident retry '+hex(t))
            require(word(z,sp)&0x3f==0x3f,'Saved WAIT Thumb CPSR/mode')
    constructor_tags=[r for r in rp.tcb_tags if r['PC'] in ('0x358c48','0x358ca0')]
    require(len(constructor_tags)==8 and Counter(r['PC'] for r in constructor_tags)=={'0x358c48':4,'0x358ca0':4},'Four runningactors nativebuilder clear/retag; Timer analyzed separately')
    condition_tags=[r for r in rp.tcb_tags if r['PC'] not in ('0x358c48','0x358ca0')]
    require(all(r['PC'] in ('0x3ec63a','0x3ec64c') and int(r['address'],16)==S+24 and r['value']==0xed1a247 for r in condition_tags),'Original conditionwait Source tag updates')
    require(len(condition_tags)==2*(2 if name.startswith('Stop') else 1),'Two actual tag updates per full conditionwait')
    require(get(z,0x09604000+240,4096-240)==b'\xa5'*(4096-240),'FIFO opaque240 trailing guard')
    for h in d['opaque_handles'].values():
        require(get(z,h['pointer']-32,32)==get(z,h['pointer']+h['size'],32)==b'\xa5'*32,'Opaque backing canaries')
    for a,size in ((DESC,36),(BUFFER,2048),(SCRATCH,256)):
        require(get(z,a-32,32)==get(z,a+size,32)==b'\xa5'*32,'Output/scratch actual canaries')
    require(get(z,POOL-32,32)==b'\xa5'*32 and get(z,POOL+10*576,4)==b'\xa5'*4,'Provider pool canaries')
    require(get(z,RESULT+256,128)==get({int(a):bytes.fromhex(v) for a,v in d['initial_whole_RW_zones'].items()},RESULT+256,128),'Uncertified ownership witness output remains unchanged')
    final_status=list(struct.unpack('<55I',get(z,RESULT,220)))
    require(final_status==d['status'],'Actual final serializedstatus bytes')
    require(final_status[30:37]==[S,1,1,0,0,S,M],'Source init/handoff actual status')
    require(final_status[40]==1 and final_status[51]==0,'Single handoff/selectoradmission')
    require(all(final_status[k]==0 for k in (2,6,7,8,12,46)),'Leases/completion/result endpoint')
    require(word(z,g+8)==S and word(z,g+19*4)==M and word(z,g+23*4)==0x09600000 and word(z,g+24*4)==0x09602000 and word(z,g+25*4)==0x09604000,'Actual compiled mixer capability')
    for e in d['selector_bridge_entries']:
        check_actor(e['state'],M);require(e['state']['GP16'][14]==0x2fa299,'Actual original selector LR')
    first_source=next(e for e in d['original_scheduled_actor_entries'] if e['PC']==symbols['mh_source_entry']['value'])
    first_mixer=next(e for e in d['original_scheduled_actor_entries'] if e['PC']==0x2fa0dc)
    check_actor(first_source['state'],S);check_actor(first_mixer['state'],M)
    require(first_source['state']['GP16'][13]==S and first_mixer['state']['GP16'][13]==M,'Original builder-to-restore initial native SP')
    handoff_stores=[e for e in d['CPU_store_journal'] if int(e['address'],16)==g+19*4 and e['value']==M]
    require(len(handoff_stores)==1 and handoff_stores[0]['current_TCB']==S and handoff_stores[0]['ordinal']<first_mixer['state']['ordinal'],'Actual source handoff before scheduled mixer')
    kernel=d['original_scheduled_actor_entries'];require(sum(e['PC']==0x358ec4 for e in kernel)>=9,'Original restore path actually observed')
    # Opaque allocation/audio policy/transport services remain fixtures.
    # Generic mutex and synchronous initialization run original instructions.
    reset_rows=[]
    allowed_names={'task construction bookkeeping','opaque mixer backing allocation','opaque node/selector allocation','opaque handle query','opaque release','opaque naming service','audio pull priority policy','audio diagnostic policy','external notice queue capture','explicit hardware reset request transport; backend queue uninitialized; no driver/ack'}
    for e in d['declared_service_calls']:
        require(e['name'] in allowed_names,'Unknown service fixture '+e['name']);before=e['before'];after=e['after'];gp=before['GP16'];ap=after['GP16']
        require(e['args']==gp[:4] and ap[1:15]==gp[1:15] and ap[15]==(gp[14]&~1),'Exact fixtureCPUreturn mutation')
        require((after['CPSR']&~32)==(before['CPSR']&~32) and bool(after['CPSR']&32)==bool(gp[14]&1),'Fixture mode/flags retained except native LR interworking')
        pc=gp[15]
        if e['name']=='opaque mixer backing allocation':require(gp[:3] in ([8192,2,0],[240,2,0]),'Mixer allocator shape')
        if e['name'].startswith('explicit hardware reset'):
            require(pc==0x37bce4 and gp[14]==0x1d8c8d and gp[0]==0 and gp[1]==gp[13]+4,'Exact hardwaretransport ABI')
            check_actor(before,M);packet=bytes.fromhex(e['original_request_hex'])
            require(packet==get(rp.snapshots[before['ordinal']],gp[1],56) and packet[:2]==b'\2\0' and packet[4]==8,'Actual original56bytes/kind/channel')
            require(ap[0]==0,'Explicit transportfixture result');reset_rows.append(e)
    # Real original queue publication/copy: source sends and actual mixer gets
    # exactly12 bytes. Validate the actual memory copy CPU/fixture history.
    sends=d['original_message_sends'];receives=d['original_message_receives']
    require([e['bytes_hex'] for e in sends]==[e['bytes_hex'] for e in receives],'Actual FIFO ordered12bytes')
    for send,receive in zip(sends,receives):
        sg,rg=send['state']['GP16'],receive['state']['GP16'];sz=rp.snapshots[send['state']['ordinal']];rz=rp.snapshots[receive['state']['ordinal']]
        require(sg[15]==0x37bce4 and sg[0]==M,'Original FIFO target')
        require(get(sz,sg[1],12).hex()==send['bytes_hex'],'Actual send input bytes')
        require(receive['state']['current_TCB']==M and rg[15]==0x37bc82 and rg[0]==1,'Actual getter successful prePOP result')
        require(send['state']['ordinal']<receive['state']['ordinal'],'Publication before consumption')
        require(bytes.fromhex(send['bytes_hex'])[1]==8,'Nativechannel8 message')
    require(d['original_queue_calls']==[d['original_queue_returns'][0]['args']] and len(d['original_queue_returns'])==1,'Single original registration writer')
    q=d['original_queue_returns'][0];require(q['args'][:4]==[RECORD+0x1a8,0xffff,10,12] and q['args'][5:]==[524,0],'Originalseven queueABI')
    require(q['r0']==0 and q['returned']['GP16'][13]==q['entry_SP'] and q['returned']['GP16'][15]==q['return_PC'],'Full queue writer returnSP/PC')
    check_actor(q['returned'],S)
    full=d['full_native_returns'];all_outer=d['original_mixer_call_site_returns']
    outer=[o for o in all_outer if o['full_native_return_count']==o['full_before']+1]
    denied=[o for o in all_outer if o['full_native_return_count']==o['full_before']]
    require(len(full)==len(outer) and len(all_outer)==len(outer)+len(denied),'Fullreturn association/admitted or denied wrapper')
    for o in denied:
        for st in (o['entry'],o['returned']):check_actor(st,M)
        require(o['call_site'] in (0x2fa536,0x2fa572) and o['return_PC']==o['call_site']+4,'Denied exact original caller')
        require(o['returned']['GP16'][15]==o['return_PC'] and o['returned']['GP16'][14]==o['return_PC']+1,'Denied original continuation/LR')
        require(o['returned']['GP16'][13]==o['entry_SP'] and o['entry']['GP16'][4:12]==o['returned']['GP16'][4:12],'Denied outerSP/GP preservation')
        require(o['bytes']==0 and o['PCM_hex']=='' and all(o['return_leases'][k]==0 for k in ('borrow','media','callback')),'Denied no bytes/leases')
        require(word(rp.snapshots[o['returned']['ordinal']],DESC+16)==o['ring_before'],'Denied no ringpublication')
        require(not any(o['entry']['ordinal']<f['entry']['ordinal']<o['returned']['ordinal'] for f in full),'Denied never enters original fullbody')
    require(len(denied)==final_status[5],'Exact serialized denial count')
    sites=Counter();total_PCM=[]
    for k,(f,o) in enumerate(zip(full,outer)):
        require(f['entry_PC']==0x2f9cce and f['entry']['GP16'][15]==0x2f9cce,'Originalfullentry after compatible native64prologue')
        require(o['call_site'] in (0x2fa536,0x2fa572) and o['return_PC']==o['call_site']+4,'Exact original two callsites')
        require(o['returned']['GP16'][15]==o['return_PC'] and o['returned']['GP16'][14]==o['return_PC']+1,'Actual Thumbouter continuation/LR')
        for st in (f['entry'],f['returned'],o['entry'],o['returned']):check_actor(st,M)
        require(f['returned']['GP16'][13]==f['entry_SP']+64 and o['returned']['GP16'][13]==o['entry_SP'],'Fullnative64andouter exactSPreturn')
        require(f['entry']['GP16'][14]==f['return_PC']==f['returned']['GP16'][15],'Actual ARMwrapper native-returnPC')
        require(f['entry']['GP16'][4:12]==f['returned']['GP16'][4:12] and o['entry']['GP16'][4:12]==o['returned']['GP16'][4:12],'Returnedcallee-savedGP4..11')
        require((f['entry']['CPSR']&~(0xf0000000|32))==(f['returned']['CPSR']&~(0xf0000000|32)),'Native mode/IRQmask preserved across interworking')
        require((o['entry']['CPSR']&0xff)==(o['returned']['CPSR']&0xff),'Outer mode/IRQ/Thumb preserved')
        require(o['full_before']==k and o['full_native_return_count']==k+1,'Exact fullreturn association')
        require(o['entry']['ordinal']<f['entry']['ordinal']<f['returned']['ordinal']<o['returned']['ordinal'],'Borrow fullreturn lifecycleorder')
        for view in (f['entry_leases'],f['return_leases']):require(view['borrow']==f['entry_SP']+64 and view['media']==view['callback']==1 and view['selected_session']==1,'Lease remains through entireoriginalfullbody')
        require(all(o['return_leases'][k]==0 for k in ('borrow','media','callback')),'Leasesreleased only after original fullreturn')
        fz=rp.snapshots[f['entry']['ordinal']];borrow=f['entry_leases']['borrow']
        require(word(fz,borrow+40)==M and word(fz,borrow+52)==1 and word(fz,borrow+60)==8 and word(fz,borrow+64)==1,'72byteborrowframe actor/session/channel/entered')
        oz=rp.snapshots[o['returned']['ordinal']];before=o['ring_before'];after=word(oz,DESC+16);count=(after-before)%2048
        require(count==o['bytes'] and count<=256,'Actual raw mixer ring count')
        raw=get(oz,before,min(count,BUFFER+2048-before))
        if len(raw)<count:raw+=get(oz,BUFFER,count-len(raw))
        require(raw.hex()==o['PCM_hex'],'Actual outputring PCM readback');total_PCM.append(raw);sites[hex(o['call_site'])]+=1
    for e in d['compiled_reader_entries']:
        check_actor(e['state'],M);require(e['leases']['media']==e['leases']['callback']==1 and e['leases']['borrow'],'Actual compiledreader leasedmixer')
    commands=d['commands'];expect_commands={'normal_reuse_reselection_reset':[1,2,3,4],'Stop_revokes_new_original_pulls':[1,5],'original_profile_rewrite_revokes_mixer':[1,6]}[name]
    require([x['command'] for x in commands]==expect_commands,'Command identities')
    audio=b'';cycle=0
    for cmd in commands:
        if cmd['command']<=4:
            expected=struct.pack('<256h',*[(j*181+cycle*1207)%60001-30000 for j in range(256)])+bytes(1280);cycle+=1
            require(bytes.fromhex(cmd['PCM_hex'])==expected and cmd['bytes']==1792 and cmd['source_PCM_bytes']==512 and cmd['original_self_posted_underrun_silence_bytes']==1280,'Independent deterministicmusic+underrun bytes')
            audio+=expected
        else:require(cmd['PCM_hex']=='' and cmd['bytes']==0,'Stopped/revoked no new ringpublication')
        require(all(cmd['state'][k]==0 for k in (2,6,7,8,12)),'Command lease/completion endpoints')
    require(b''.join(total_PCM)==audio,'Actualfullreturnchunks equalcommandPCM')
    require(final_status[3]==final_status[4]==len(full) and final_status[14]==len(audio),'Actual compiled pulls/fullreturns/bytes counters')
    expected_count=32 if name.startswith('normal') else 8;require(len(full)==expected_count,'Actual expectedfullreturns')
    selectors=2 if name.startswith(('normal','Stop')) else 1;require(len(d['selector_bridge_entries'])==selectors and final_status[42]==final_status[43]==selectors,'Actual reselection counts')
    if name.startswith('normal'):
        require(sites['0x2fa536']>0 and sites['0x2fa572']>0 and final_status[5]==0 and final_status[48]==16,'Both originalfullcallroutes and tickets4to16')
        require(word(z,RECORD+0x108)==symbols['memory_output_read']['value'],'Leased originalselector readerinstalled')
    else:
        require(final_status[41]==1 and word(z,g+20*4)==0,'Actual capability revoked')
        require(final_status[5]==(2 if name.startswith('Stop') else 1),'Actual localStop/profile denial counters')
    require(len(reset_rows)==(1 if name.startswith(('normal','Stop')) else 0),'Actual exactresettransport count')
    # Callback installs must be native or compiled CPU stores, never seeded.
    require(rp.callbacks[0]['PC']=='0x277dbc' and rp.callbacks[0]['value']==0x277c6b,'Originalinitialprofile callback')
    require(any(x['value']==symbols['mcs_queue_bridge']['value'] and x['actor']==S for x in rp.callbacks),'Compiledsource callbackinstallation')
    if name.startswith('original_profile'):
        writes=[x for x in rp.callbacks if x['PC']=='0x277dbc']
        require(len(writes)==3 and all(x['value']==0x277c6b and x['actor']==S for x in writes),'True originaltwo-profile callback CPUrewrites')
        require(word(z,RECORD+0x160)==0x277c6b and get(z,RECORD+0x15d,1)==b'\0','Originalprofile endpoint')
    # CPU-only native selector mutation evidence remains separate from fixture
    # allocation backing. Finalprovider index1 after reselection is legitimate.
    index_stores=[e for e in d['CPU_store_journal'] if e['PC']=='0x48ee8e' and int(e['address'],16)==RECORD+0xf0]
    require(len(index_stores)==selectors and all(e['current_TCB']==M for e in index_stores),'Native selector writes actual index')
    require([e['value'] for e in index_stores]==list(range(selectors)),'Original provider allocation index progression')
    for e in index_stores:
        busy=[x for x in d['CPU_store_journal'] if x['PC']=='0x48ee8c' and int(x['address'],16)==POOL+e['value']*576+12 and x['value']==1 and x['ordinal']<e['ordinal']]
        require(bool(busy),'Originalnative providerbusy publication')
    require(d['native_ownership_snapshot']==-200 and not d['native_STOP_DONE'] and not d['physical_speaker_phone_App_installation_or_complete_player_verified'] and not d['device_io'],'Limits preserved')
    endpoints=d['terminal_register_snapshots'];require(len(endpoints)>=25,'Actual controller and idle endofemu GP snapshots')
    idle=[e for e in endpoints if e['address']==0x9400000]
    require(bool(idle),'Actual serialized idle arrivals')
    for e in endpoints:
        require(e['GP16'][15]==e['address'] and e['address'] in (RETURN,0x9400000),'Actual endpoint PC')
        require((e['CPSR']&31)==0x1f and not e['CPSR']&32,'ARM systemmode controller/idle endpoint')
        if e['current_TCB'] in STACKS:check_actor(e,e['current_TCB'])
    sync=verify_sync(d,rp,symbols)
    counts.update(sync)
    counts.update(name=name,full_original_returns=len(full),original_callsite_counts=dict(sites),denied_outer_wrapper_returns=len(denied),selector_entries=selectors,music_bytes=512*cycle,underrun_silence_bytes=1280*cycle,total_output_bytes=len(audio),denials=final_status[5],mixer_revocations=final_status[41],actual_contextsave_store_count=len(rp.contexts),native_profile_callback_CPU_writes=rp.callbacks,
        original_priority_source12_mixer23_controller16=True,actual_source_before_mixer_handoff=True,actual_native_FULL_SP_LR_GP4_to11_IRQmode_returns_verified=True,GP_CPSR_store_semantics_and_joint_whole_replay_verified=True,
        controller_function_final_return_registers_serialized=True,all_per_instruction_nonstore_controlflow_or_scheduler_lifetime_verified=False,actual_hardware_reset_transport_requests=len(reset_rows))
    return counts

def prepare_sync_checkpoints(rp,d,symbols):
    prefix=d['sync_boot_no_ack_prefix']
    rp.enqueue('serialized noACK controller prefix',prefix['controller'])
    rp.checkpoints.add(prefix['controller']['ordinal'])
    for e in d['original_sync_entries']:
        rp.enqueue('original46CC7A entry',e['entry']);rp.checkpoints.add(e['entry']['ordinal'])
    for e in d['full_original_sync_returns']:
        rp.enqueue('full original46CC7A returned',e['returned']);rp.checkpoints.add(e['returned']['ordinal'])
    for e in d['actual_condition_entries']:
        rp.enqueue('original condition/wait',e['state']);rp.checkpoints.add(e['state']['ordinal'])
    for e in d['original_mixer_ACK8_entries']:
        rp.enqueue('original mixerACK8',e['state']);rp.checkpoints.add(e['state']['ordinal'])
    for e in d['original_kernel_events']:
        rp.enqueue('original kernelPOST',e['state']);rp.checkpoints.add(e['state']['ordinal'])
    for e in d['CPU_store_journal']:
        pc=int(e['PC'],16);a=int(e['address'],16)
        if pc in (0x300D64,0x358E9C) or a in (READY,RECORD+0x58+8,RECORD+0x70+12) or pc==0x3EC4CC:
            rp.checkpoints.add(e['ordinal'])

def verify_sync(d,rp,symbols):
    r,cnd,raw=RECORD,RECORD+0x70,RECORD+0x58
    backend=cnd+0x1c;timer=0x02D227C8
    z=rp.final;events=d['CPU_store_journal'];sync=d['full_original_sync_returns']
    expected=2 if d['name'].startswith('Stop') else 1
    require(len(sync)==len(d['original_sync_entries'])==len(d['original_mixer_ACK8_entries'])==expected,'One fullsync per nativeACK, existing path twice')
    require(word(z,0xF090A0)==timer and word(z,0xF09098)==0,'Native Timerpublication and unchanged clock tick')
    require(word(z,timer+40)==C and word(z,timer+44)==S+40 and word(z,timer+32)==cnd,'Native Timer ALL/retained conditiontoken ownership')
    require(word(z,cnd)==0 and word(z,cnd+4)==timer+32 and word(z,cnd+8)==timer,'Retained conditiontoken nativeintrusive linkage')
    require(word(z,cnd+0x18)==0xD4475B83 and word(z,raw+8)==word(z,backend+8)==0,'Constructedcondition magic and actuallyreleased raw/backend owners')
    require(not any(e['PC']==0x2FBBBE and e['args'][0]==0x02D226E0 for e in d['original_scheduled_actor_entries']),'Timer not registered')
    require(not any(e['args'][0]==timer for e in d['original_kernel_events']),'Timer not posted')
    require(not any(e['state']['current_TCB']==timer for e in d['original_scheduled_actor_entries']),'Timer did not execute as a scheduled actor')
    completed=symbols['ms_original_sync_completed']['value']
    prefix=d['sync_boot_no_ack_prefix'];pz=rp.snapshots[prefix['controller']['ordinal']]
    require(prefix['original_sync_entered'] and not prefix['original_sync_returned'] and not prefix['PLAY_open'] and prefix['actual_ack_count']==0,'Genuine noACK prefix facts')
    require(prefix['state']==list(struct.unpack('<55I',get(pz,RESULT,220))),'NoACKstatus actual joined memory')
    require(prefix['state'][32]==0 and word(pz,completed)==0 and word(pz,READY)==C,'PLAY completion remains closed while source blocked before ACK')
    for name,value in prefix['sync'].items():require(word(pz,symbols[name]['value'])==value,'NoACK compiledsync counter readback '+name)
    native_frames=[]
    for e in events:
        pc=int(e['PC'],16)
        if pc not in (0x300D64,0x358E9C):continue
        a=int(e['address'],16);t=a-12
        require(t in (S,M,C,I),'Original outgoing contention/context save TCBSPlocation')
        require(e['GP16'][6 if pc==0x300D64 else 0]==t,'Original saver r6/r0 actual outgoingTCB storebase')
        require((t==S and e['current_TCB'] in (C,M)) if pc==0x300D64 else (t==M and e['current_TCB']==S),'Native scheduler changed READY before outgoingSource/Mixer context save')
        frame=e['value'];sz=rp.snapshots[e['ordinal']];words=struct.unpack('<13I',get(sz,frame,52))
        require(words[1]==(0x300D98 if pc==0x300D64 else 0x358EBC),'Native52byte context exact resumePC')
        require(words[0]&0x3f==0x3f and words[2:11]==tuple(e['GP16'][4:13]),'Original saved CPSR/mode andr4-r12')
        require(words[11]==frame+52,'Original context saved oldSP exactframe52')
        format_store=[x for x in events if e['ordinal']<x['ordinal']<=e['ordinal']+4 and int(x['address'],16)==t+23 and x['value']==0]
        require(bool(format_store),'Original contextformat0, not17word alternate')
        native_frames.append(dict(ordinal=e['ordinal'],outgoing_saved_TCB=t,current_READY_TCB=e['current_TCB'],frame=frame,bytes=52,resume_PC=words[1],CPSR=words[0],old_SP=words[11],old_LR=words[12]))
    require(bool(native_frames),'Real nativecontention/context frames captured')
    results=[]
    for entry,returned,ack in zip(d['original_sync_entries'],sync,d['original_mixer_ACK8_entries']):
        lo,hi=entry['entry']['ordinal'],returned['returned']['ordinal'];ao=ack['state']['ordinal']
        ez,rz=rp.snapshots[lo],rp.snapshots[hi]
        require(word(ez,0xF0909C)==word(rz,0xF0909C),'Infinite ACK8 wait preserves its actual timedhead input')
        require(not any(lo<e['ordinal']<=hi and int(e['address'],16)==0xF0909C for e in events),'No timed-node-head mutation in infinite ACK8 sync window')
        require(returned['entry']==entry['entry'] and returned['entry_SP']==entry['entry_SP'],'Fullsync exact matched entry')
        for state in (entry['entry'],returned['returned']):check_actor(state,S)
        require(entry['entry']['GP16'][15]==0x46CC7A and entry['entry']['GP16'][14]==0x3B9C59 and entry['call_args'][:3]==[r,1,0],'Wrapper retains original threeargs/LR and nativeentry')
        require(entry['CONFIG_mixer_TCB']==M and word(ez,completed)==0,'CONFIG admitted, PLAY closed on native entry')
        require(returned['returned']['GP16'][15]==0x3B9C58 and returned['returned']['GP16'][13]==entry['entry_SP'] and returned['r0']==returned['returned']['GP16'][0]==0,'Complete originalsync exactPC/SP/R0 return')
        require(entry['entry']['GP16'][4:12]==returned['returned']['GP16'][4:12],'Originalsync full callee-savedGP4-r11')
        require((entry['entry']['CPSR']&0xff)==(returned['returned']['CPSR']&0xff),'Originalsync returned normalmode/IRQ/Thumb')
        require(lo<ao<hi and word(rz,raw+8)==0 and word(rz,S+32)==0,'Source fully unlocks originalmutex before whole sync returns')
        flag=ack['args'][0];az=rp.snapshots[ao]
        require(ack['args'][1]==8 and ack['state']['GP16'][15]==0x30ED24,'Actual originalACK8function')
        check_actor(ack['state'],M)
        require(get(az,flag,12).hex()==ack['flag_before_hex'] and get(az,flag,2)==b'\1\0' and word(az,flag+4)==raw and word(az,flag+8)==cnd,'ACK flags actual original initialized beforebytes')
        messages=[e for e in d['original_message_sends'] if lo<e['state']['ordinal']<ao and bytes.fromhex(e['bytes_hex'])[0]==20]
        require(len(messages)==1 and struct.unpack('<3I',bytes.fromhex(messages[0]['bytes_hex']))[2]==flag,'Originalmessage20 publishes exact nativeflag pointer')
        wait=[e for e in d['actual_condition_entries'] if lo<e['state']['ordinal']<ao and e['PC']==0x3EC6A2]
        require(len(wait)==1 and wait[0]['args'][:3]==[cnd,raw,0x7ffffff],'Original infiniteconditionwait ABI')
        nested=[e for e in d['actual_condition_entries'] if lo<e['state']['ordinal']<ao and e['PC']==0x3EC5C6]
        require(len(nested)==1 and nested[0]['args'][:3]==[cnd,raw,0xffffffff],'Infinite wait conversion, no timednode')
        posts=[e for e in d['original_kernel_events'] if ao<e['state']['ordinal']<hi and e['args'][:2]==[S,8]]
        require(len(posts)==1,'One originalPOST8 actualsource')
        post=posts[0];po=post['state']['ordinal'];mz=rp.snapshots[po]
        require(post['state']['current_TCB']==M and word(mz,raw+8)==word(mz,backend+8)==M,'ACK8 nativePOST occurs while mixer owns both raw/backend locks')
        flag_writes=[e for e in events if ao<e['ordinal']<po and int(e['address'],16)==flag and e['PC']=='0x30ed26']
        require(len(flag_writes)==1 and flag_writes[0]['size']==2 and flag_writes[0]['value']==8 and flag_writes[0]['current_TCB']==M,'OriginalACK8 CPUstores actual16bit flag')
        blocked=[e for e in events if lo<e['ordinal']<ao and e['PC']=='0x300d32' and int(e['address'],16)==cnd+12]
        require(len(blocked)==1,'Nativeconditionwaiter publication')
        waiter=blocked[0]['value']
        clear=[e for e in events if ao<e['ordinal']<=po and e['PC']=='0x3ec4cc' and int(e['address'],16)==waiter+4 and e['value']==0]
        require(len(clear)==1,'Originalcondition completion clears actualsourcewaiter field')
        switches=[e for e in events if lo<e['ordinal']<=hi and int(e['address'],16)==READY]
        require(any(e['ordinal']<ao and e['current_TCB']==S and e['value']==C for e in switches),'Source trueconditionwait restores controller before mixer')
        source_preempt=next(e for e in switches if po<e['ordinal'] and e['current_TCB']==M and e['value']==S)
        reblock=next(e for e in switches if source_preempt['ordinal']<e['ordinal'] and e['current_TCB']==S and e['value']==M)
        transfer=[e for e in events if reblock['ordinal']<e['ordinal']<=hi and e['PC']=='0x300bd6' and int(e['address'],16)==raw+8 and e['value']==S and e['current_TCB']==M]
        require(len(transfer)==1,'Originalmixer unlock transfers rawmutex ownership backtosource')
        transfer=transfer[0]
        donation=[e for e in events if source_preempt['ordinal']<e['ordinal']<transfer['ordinal'] and int(e['address'],16)==M+17 and e['size']==1 and e['PC']=='0x358f14' and e['value']==12]
        require(bool(donation),'Source contention natively donates priority12 tomixer')
        resume=next(e for e in switches if transfer['ordinal']<e['ordinal'] and e['current_TCB']==M and e['value']==S)
        require(po<source_preempt['ordinal']<reblock['ordinal']<transfer['ordinal']<resume['ordinal']<hi,'POSTpreemption,recontention,unlocktransfer,resumption fullreturn order')
        require(word(rp.snapshots[source_preempt['ordinal']],raw+8)==M,'Source preempts before mixer rawunlock')
        require(word(rp.snapshots[transfer['ordinal']],raw+8)==S,'Actual ownership transfer afterimage')
        require(word(rz,completed)==0,'Completion gate stillclosed at originalreturn, opens only in compiledaftervalidation')
        results.append(dict(entry_ordinal=lo,ACK_ordinal=ao,POST8_ordinal=po,source_preempt_ordinal=source_preempt['ordinal'],source_reblock_ordinal=reblock['ordinal'],raw_owner_transfer_ordinal=transfer['ordinal'],source_resume_ordinal=resume['ordinal'],full_return_ordinal=hi,flag=flag,waiter=waiter,priority_donation_CPU_stores=len(donation)))
    final=d['compiled_sync_status']
    require(final==dict(ms_sync_entries=expected,ms_sync_grants=1,ms_sync_reuses=expected-1,ms_sync_rejections=0,ms_before_result=0,ms_original_sync_completed=1),'Actualnew/existing compiledcompletion status')
    for name,value in final.items():require(word(z,symbols[name]['value'])==value,'Finalcompiledsync actualmemory '+name)
    for f in d['full_native_returns']:require(word(rp.snapshots[f['entry']['ordinal']],completed)==1,'Every actualaudio pull after complete originalsync validation')
    require(not any(e['name'] in ('generic mutex fixture','external audio timing hint') for e in d['declared_service_calls']),'Native rawmutex/condition no fixture service')
    visits=d['native_visits']
    for pc in ('0x300ada','0x3ec6a0','0x300bd6','0x30ed24','0x3ec6a2'):
        require(visits.get(pc,0)>=expected,'Original native epilog/ACK/wait visit '+pc)
    require(visits.get('0xf6e48')==visits.get('0x353d3c')==1,'Direct native Timer constructor visits')
    return dict(full_original_sync_returns=expected,actual_original_condition_waits=expected,actual_original_ACK8=expected,sync_lifecycle=results,native_saved_context_frames=native_frames,actual_final_RX_dump_zones=rp.final_RX_verified,serialized_controller_idle_endpoints=len(d['terminal_register_snapshots']),direct_native_constructor_boot_inputs=True,Timer_constructed_retainsconditiontoken_but_not_registered_posted_or_scheduled=True,original_raw_mutex_condition_wait_POST8_preemption_contended_reacquire_unlocktransfer_fullreturn_verified=True,ordinary_controller_endpoint_GP16_CPSR_SP_now_serialized_and_joined=True,independent_actual_final_RX_readback_verified=True,native_return_epilog_visit_counts={pc:visits.get(pc,0) for pc in ('0x300ada','0x3ec6a0')})

def verify_build(buildp,sources):
    build=load(buildp);elfp=ROOT/build['ELF']
    require(build['all_passed'] and sha(elfp)==build['ELF_sha256'],'Frozen compiled ELF '+rel(buildp))
    elf=ELF(elfp);symbols=build['symbols']
    for name,s in symbols.items():
        require(any(e['name']==name and e['value']==s['value'] and e['size']==s['size'] and e['section']==s['section_index'] for e in elf.symbols),'Actual manifest symbol identity '+name)
    for p,h in {**build['source_sha256'],**build['generated_sha256']}.items():
        require(sha(ROOT/p)==h,'Frozen build dependency '+p);sources[p]=h
    for p in (buildp,elfp):sources[rel(p)]=sha(p)
    return build,elf,symbols

def main():
    output=Path(__file__).resolve().parent/'mixer-sync-v3-independent-file-verification.json'
    require(not output.exists(),'New file verifier output already exists')
    proofp=BASE/'mixer-sync-v3-proof.json';proof=load(proofp)
    require(sha(proofp)=='1203ebadc01d44f4199aabcf6ea7f0dbfdd82134a328e86520b459896bc59554' and proof['all_passed'],'Frozen ROOT V3 proof')
    sources=dict(proof['source_sha256'])
    for p,h in sources.items():require(sha(ROOT/p)==h,'Frozen actual runtime input '+p)
    require(load(BASE/'guest-v3/inputs-at-run.json')==sources,'Exact actual V3 source registry')
    runnerp=BASE/'emulate_mixer_sync_v3.py'
    require(sources[rel(runnerp)]=='96c355a5460909a344ab9cfd106a372e55735d6a114074e309a14d6f9ee2d4f7','Frozen ROOT runner')
    require(sha(BASE/'guest-v3/runner-at-run.py')==sha(runnerp),'Exact actual V3 runner snapshot')
    source=runnerp.read_text();tree=ast.parse(source)
    require(not any(isinstance(t,ast.Call) and isinstance(t.func,ast.Attribute) and t.func.attr in ('host_return','context_restore') for t in ast.walk(tree)),'No Python actor restore method')
    require('self.uc.emu_start(entry, old.RETURN' in source and 'actual_emu_endpoint=True' in source and 'actual_final_RX_zones=' in source,'Actual terminal endpoint and RX serialization source')
    require('if address in (0xF5030, 0x2F9C52, 0x3B9674):' in source,'Narrow actual remaining audio policy fixtures')
    receiptp=BASE/'guest-v3-terminal-tool-receipt.json';receipt=load(receiptp)
    require(receipt['terminal'] and receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='925a2b' and receipt['started_session_id']==89948,'Actual ROOT V3 terminal success')
    build,elf,symbols=verify_build(BASE/'build-v2.json',sources)
    require(build['ELF_sha256']=='695d56bcc3299c1eaa494b7106fb7fa9af6aa034ce590c8446d556776005477c','Exact V3 compiled ELF')
    n=NativeImage();require(hashlib.sha256(n.data).hexdigest()==EXPECTED,'Exact Taiwan MAIN')
    rows=[]
    for item in proof['cases']:
        p=ROOT/item['path'];h=sha(p);require(h==item['sha256'],'Frozen actual V3 case '+item['name'])
        d=load(p);require(d['name']==item['name'] and d['passed'],'V3 case identity')
        row=verify_case(d,n,elf,symbols);row['case_sha256']=h;row['actual_original_and_ELF_instruction_visits']=d['instructions'];rows.append(row);sources[rel(p)]=h
        print(json.dumps(dict(case=row['name'],CPU_stores=row['CPU_stores'],fullpull_returns=row['full_original_returns'],fullsync_returns=row['full_original_sync_returns'],independent_file_only=True)),flush=True)
    totals=dict(CPU_stores=44931,joint_events=45065,full_original_returns=48,full_original_sync_returns=4,actual_original_condition_waits=4,actual_original_ACK8=4,actual_final_RX_dump_zones=9,serialized_controller_idle_endpoints=89,actual_original_and_ELF_instruction_visits=257336)
    require(len(rows)==proof['case_count']==3,'Three bounded V3 cases')
    for k,v in totals.items():require(sum(r[k] for r in rows)==v,'Exact V3 aggregate '+k)
    # V2 first case completed before the public request range rejected command7.
    # Replay that frozen successful case separately; its whole suite stays EXIT1.
    prior_receiptp=BASE/'guest-v2-terminal-tool-receipt.json';prior_receipt=load(prior_receiptp)
    require(prior_receipt['terminal'] and prior_receipt['actual_terminal_result']['exit_code']==1 and prior_receipt['actual_terminal_result']['chunk_id']=='d946b9' and prior_receipt['started_session_id']==17184,'Preserved actual V2 terminal failure')
    failurep=BASE/'guest-v2/terminal-failure.json';failure=load(failurep)
    require(not failure['all_passed'] and failure['error']=='existing source request rejected','V2 source guard failure preserved')
    require(sha(BASE/'guest-v2/runner-at-run.py')==sha(BASE/'emulate_mixer_sync_v2.py'),'Exact V2 actual runner snapshot')
    prior_inputs=load(BASE/'guest-v2/inputs-at-run.json')
    for p,h in prior_inputs.items():require(sha(ROOT/p)==h,'V2 frozen runtime input '+p);sources[p]=h
    prior_build,prior_elf,prior_symbols=verify_build(BASE/'build-v1.json',sources)
    priorp=BASE/'guest-v2/normal_reuse_reselection_reset.json'
    require(sha(priorp)=='270b1f1a2b52e06d3992971a43d8dfbe2b772197f6f6471f56e68b57a4b4c825','Exact V2 completed first case')
    prior=verify_case(load(priorp),n,prior_elf,prior_symbols);prior['case_sha256']=sha(priorp)
    require(prior['CPU_stores']==24567 and prior['full_original_returns']==32 and prior['full_original_sync_returns']==1,'V2 separately replayed first case counts')
    staticp=BASE/'static-review/original-mixer-sync-cold-initialization-contract.json'
    staticseal=BASE/'static-review/original-mixer-sync-static-seal.json';seal=load(staticseal)
    require(sha(staticp)=='ff64814f1b0ba943a0fac0b2a22d677884f53f8e559c2b39180f368c0943ed2d' and sha(staticseal)=='334cb95d7b1dcc1306324f2e355330a062f42a3c9d0e8b7483c89931b92e29de' and seal['all_passed'] and seal['static_analysis_only'],'Frozen independent static contract')
    for p,h in {**seal['source_sha256'],**seal['output_sha256']}.items():require(sha(ROOT/p)==h,'Independent static dependency '+p);sources[p]=h
    file_reviewer_failures=[]
    for p in sorted(Path(__file__).resolve().parent.glob('file-verifier-v*-terminal-failure-receipt.json')):
        f=load(p);require(f['tool_result']['exit_code']==1 and not f['guest_execution'],'Frozen file reviewer failure')
        for k,h in f['source_sha256'].items():require(sha(ROOT/k)==h,'Frozen failed file verifier');sources[k]=h
        sources[rel(p)]=sha(p);file_reviewer_failures.append(dict(receipt=rel(p),actual_terminal_chunk=f['tool_result']['chunk_id'],guest_failure=False))
    # Include all finished build files and source/receipt history, preserving
    # earlier failures. This namespace is terminal; no growing case is read.
    for p in sorted(BASE.rglob('*')):
        if p.is_file() and 'verification-v3' not in p.parts and '__pycache__' not in p.parts:sources[rel(p)]=sha(p)
    for p in (Path(__file__).resolve(),ROOT/'staging/native-player-mixer-handoff/verification-v5/verify_mixer_handoff_v5_files_v7.py',ROOT/'scripts/analyze_native_sections.py'):
        sources[rel(p)]=sha(p)
    require(not any(k=='unicorn' or k.startswith('unicorn.') for k in sys.modules),'VM imported')
    for p,h in sources.items():require(sha(ROOT/p)==h,'Final frozen dependency readback '+p)
    result=dict(all_passed=True,independent_FILE_ONLY=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=sources,case_count=3,cases=rows,
        actual_ROOT_terminal_session=89948,actual_ROOT_terminal_chunk='925a2b',actual_ROOT_guest_exit_code=0,
        CPU_stores=44931,joint_events=45065,full_original_native_returns=48,full_original_sync_returns=4,actual_original_condition_waits=4,actual_original_ACK8=4,
        tracked_whole_zone_case_replays=72,actual_RW_case_replays_from_frozen_permission_recipe=69,unchanged_RX_return_sentinel_case_replays=3,actual_final_RX_dump_case_zones=9,serialized_controller_idle_endpoint_GP16_CPSR_SP_snapshots=89,
        actual_original_and_ELF_instruction_visits=257336,
        exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,
        four_guest_only_BL_patches_and_four_interworking_veneers_verified=True,stock_MAIN_file_unchanged=True,independent_after_declared_patches_RX_baseline_and_actual_final_RX_dumps_verified=True,
        direct_original_Timer_rawmutex_condition_constructor_boot_inputs=True,complete_original_cold_audio_initialization=False,Timer_registered_posted_or_scheduled=False,later_original_mixer_timed_WAIT_nodes_may_be_linked=True,
        original_raw_mutex_condition_wait_ACK8_POST8_preemption_contended_reacquire_priority_donation_unlocktransfer_fullreturn_verified=True,
        actual_native_source_to_mixer_CONFIG_capability_and_PLAY_closed_until_complete_sync_verified=True,new_and_existing_M_plus78_initializer_paths_verified=True,
        source_and_mixer_native_POST_WAIT_contextsave_restore_and_52byte_format0_saved_frames_verified=True,
        full_mixer_native_and_outer_return_GP16_CPSR_SP_serialized=True,ordinary_controller_endpoint_GP16_CPSR_SP_serialized=True,complete_all_instruction_GP_or_controlflow_or_kernel_lifetime_proof=False,
        raw_compiled_PCM_source=True,SBC_decoder_in_this_sync_module=False,explicit_output_consumer_readindex_fixture=True,explicit_opaque_allocation_query_release_audio_policy_and_hardware_transport_fixtures=True,
        generic_mutex_or_46CC7A_syncwait_ACK_tail_bypassed=False,native_heap_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified=False,
        prior_V2_actual_suite_exit_code=1,prior_V2_actual_terminal_chunk='d946b9',prior_V2_actual_source_guard_failure=failure['error'],prior_V2_completed_first_case_independent_replay=prior,prior_V2_suite_all_passed=False,prior_V2_counts_added_to_V3_totals=False,
        device_io=False,canonical_write=False,VM_import_or_instantiation=False,guest_rerun=False,preserved_failed_file_verifier_receipts=file_reviewer_failures,file_verifier_v5_actual_failure='Original3EC4CC clear has same ordinal as subsequent POST-entry snapshot: eventordinal is last completed store, so before-POST clear includes equality.',file_verifier_v4_actual_failure='Actual original300D64 uses r6 and358E9C uses r0 as outgoingTCB store base; READY has already changed before both.',file_verifier_v3_actual_failure='READY has changed to Source before358E9C saves outgoing Mixer frame; frameowner is actual store address/r4, not currentREADY.',file_verifier_v2_actual_failure='Expected finaltimedheadzero incorrectly extended infinite ACK8 window scope to later mixer waits; later original353E94 legitimately links Mixer+0x88.',file_verifier_v1_actual_failure='Inherited V5 total TCB-tag-write count missed original3EC63A/3EC64C Source tag writes during native conditionwait; priority donation is separately verified at MixerTCB+17.',
        limits=['Three scoped ROOT V3 cases execute original source/mixer scheduling, FIFO, selector/fullpull and full46CC7A synchronization using four declared guest RAM callsite redirections. Stock firmware file stays unchanged; no installed App or original cold boot is claimed.',
          'Timer/rawmutex/condition are constructed by original bodies through direct declared boot inputs. Timer owns the retained condition token but is not registered, posted or scheduled. Infinite wait does not test timed wait, hardware timer, IRQ entry/exit or the second hardware synchronization branch.',
          'ACK8 can preempt Mixer23 while it owns external rawmutex/backend. Source12 contends and blocks, donating effective priority at MixerTCB+17; original unlock transfers ownership, and Source completes synchronization before Mixer unlock epilogue necessarily resumes. No native general heap, channel exclusivity or STOP_DONE is inferred.',
          'Opcode/GP/CPSR validation and whole-memory joint replay cover stores. Native/outer/fullsync and controller/idle endpoint registers are serialized; nonstore instruction/controlflow/lifetime semantics are not a complete independent CPU trace.',
          '72 tracked case zones comprise69 actual RW zones and3 RX return sentinels left labeled RW by the parent zone recipe. Nine additional whole actual finalRX dumps independently match reconstructed MAIN/ELF/idle baselines.',
          'Opaque allocator/query/release, bookkeeping, audio priority/diagnostics, output activation/readindex consumer, external notice and reset transport remain declared fixtures. Reset source message17 is not a real driver acknowledgement. Deterministic PCM does not integrate the previously verified SBC prototype or prove physical audio/phone/App.',
          'ROOT V2 first case is separately independently replayed. Its later compiled request-range failure and actual EXIT1 receipt remain unchanged and are not counted as a passing suite.'])
    create(output,result)
    print(json.dumps(dict(all_passed=True,proof=rel(output),proof_sha256=sha(output),CPU_stores=44931,joint_events=45065,full_original_native_returns=48,full_original_sync_returns=4,guest_execution=False)),flush=True)
if __name__=='__main__':main()
