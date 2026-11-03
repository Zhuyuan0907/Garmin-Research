#!/usr/bin/env python3
"""Independent FILE ONLY review of frozen root mixer handoff V5.

No guest module, Unicorn import, code execution or device access. Decode saved
CPU stores using exact MAIN/ELF bytes and GP16/CPSR, replay joint fixture/CPU
events, verify serialized native/outer returns and declared actor inputs.
"""
import ast, hashlib, json, re, struct, sys
from collections import Counter, defaultdict
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'staging/native-player-mixer-handoff'
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
            (0x2FD03C,0x2FD050),(0x2FD06C,0x2FD0A8),(0x2FD0C4,0x2FD0D0),(0x353B44,0x353B5C),
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
        for pc,name,veneer in ((0x2fa294,'mh_selector_bridge',0x6e8000),(0x2fa536,'mcs_pull_bridge',0x6e8010),(0x2fa572,'mcs_pull_bridge',0x6e8020)):
            target=self.symbols[name]['value'];oldtarget=0x2f9f2e if pc==0x2fa294 else 0x2f9cca
            require(self.n.read(pc,4)==bl(pc,oldtarget),'Stock direct BL')
            for a,b,why in ((pc,bl(pc,veneer),'guest call-site BL'),(veneer,b'\x00\x4b\x18\x47'+struct.pack('<I',target),'guest Thumb LDR/BX to ARM veneer')):
                expected_patches.append(dict(address=a,before_hex=self.n.read(a,len(b)).hex(),after_hex=b.hex(),reason=why,original_return_LR=pc+5,target_symbol=name,target_address=target))
        require(self.row['patches']==expected_patches,'Exact declared six guest patches')
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
    counts=rp.run();z=rp.final;g=rp.guard;c=rp.control
    # Native cold task construction is real; ready membership and descriptors
    # for initial controller/idle remain declared cold inputs.
    builders=[e for e in d['original_scheduled_actor_entries'] if e['PC']==0x358bf8]
    require(len(builders)==4,'Four actual original context builders')
    require([b['args'][0] for b in builders]==[0x09401800,0x09401820,symbols['source_descriptor']['value'],MIXER+0x64],'Exact builder descriptor pointers')
    require(struct.unpack('<5I',get(z,symbols['source_descriptor']['value'],20))==(symbols['mh_source_entry']['value'],0,0x07804000,12<<16,0),'Compiled source typed descriptor')
    require(struct.unpack('<5I',get(z,MIXER+0x64,20))==(0x2fa0dd,0x09604000,0x09602000,0x0117140c,MIXER+0x3c),'Original mixer typed descriptor')
    require(word(z,MIXER+0x78)==M and word(z,M+8)==0x09604000,'Original mixer TCB/messagequeue')
    require(word(z,M+28)==MIXER+0x3c,'Original mixer metadata pointer')
    require(word(z,READY)==C and word(z,C)==I and word(z,I)==0,'Final ready controller/idle')
    require(word(z,ALL)==M,'ALL head')
    for t,next_t,prev_link,prio,state,tag in [(M,S,ALL,23,2,0x1ed1a247),(S,C,M+40,12,2,0xed1a247),(C,I,S+40,16,1,0xed1a247),(I,0,C+40,240,1,0xed1a247)]:
        require(word(z,t+40)==next_t and word(z,t+44)==prev_link,'Original ALL intrusive linkage '+hex(t))
        require(get(z,t+16,2)==bytes([prio,prio]) and get(z,t+22,1)==bytes([state]),'Native priority/state '+hex(t))
        require(word(z,t+24)==tag and word(z,t+32)==word(z,t+36)==0,'Native tag/ownedhead/opaque state '+hex(t))
        sp=word(z,t+12);base,size=STACKS[t];require(base+64<=sp and sp+52<=t,'Resident saved52 frame '+hex(t))
        require(get(z,base,64)==b'\xa5'*64,'Native stack leading64 canary')
        if t in (S,M):
            require(word(z,t)==0xffffffff and word(z,sp+4)==0x2fd0ac,'Blocked original WAIT resident retry '+hex(t))
            require(word(z,sp)&0x3f==0x3f,'Saved WAIT Thumb CPSR/mode')
    require(len(rp.tcb_tags)==8 and Counter(r['PC'] for r in rp.tcb_tags)=={'0x358c48':4,'0x358ca0':4},'Original native builder clear and retag all four tags')
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
    # Exact opaque/mutex/sync/transport service inputs and returns are recorded
    # fixtures, not assertions of native heap or lock ownership.
    mutex=Counter();reset_rows=[]
    allowed_names={'task construction bookkeeping','generic mutex fixture','opaque mixer backing allocation','opaque node/selector allocation','opaque handle query','opaque release','opaque naming service','external audio timing hint','audio pull priority policy','audio diagnostic policy','external notice queue capture','explicit hardware reset request transport; backend queue uninitialized; no driver/ack'}
    for e in d['declared_service_calls']:
        require(e['name'] in allowed_names,'Unknown service fixture '+e['name']);before=e['before'];after=e['after'];gp=before['GP16'];ap=after['GP16']
        require(e['args']==gp[:4] and ap[1:15]==gp[1:15] and ap[15]==(gp[14]&~1),'Exact fixtureCPUreturn mutation')
        require((after['CPSR']&~32)==(before['CPSR']&~32) and bool(after['CPSR']&32)==bool(gp[14]&1),'Fixture mode/flags retained except native LR interworking')
        pc=gp[15]
        if e['name']=='generic mutex fixture':
            require(pc in (0x3009a0,0x3008b0),'Raw mutex boundary');mutex[gp[0]]+=1 if pc==0x3009a0 else -1;require(mutex[gp[0]]>=0,'Fixture mutex balanced prefix')
        if e['name']=='opaque mixer backing allocation':require(gp[:3] in ([8192,2,0],[240,2,0]),'Mixer allocator shape')
        if e['name']=='external audio timing hint':require(pc==0x46cc7a and gp[14]==0x3b9c59 and gp[:3]==[RECORD,1,0],'Declared original syncwait boundary')
        if e['name'].startswith('explicit hardware reset'):
            require(pc==0x37bce4 and gp[14]==0x1d8c8d and gp[0]==0 and gp[1]==gp[13]+4,'Exact hardwaretransport ABI')
            check_actor(before,M);packet=bytes.fromhex(e['original_request_hex'])
            require(packet==get(rp.snapshots[before['ordinal']],gp[1],56) and packet[:2]==b'\2\0' and packet[4]==8,'Actual original56bytes/kind/channel')
            require(ap[0]==0,'Explicit transportfixture result');reset_rows.append(e)
    require(not any(mutex.values()),'Generic fixturemutex terminal balanced')
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
    full=d['full_native_returns'];outer=d['original_mixer_call_site_returns'];require(len(full)==len(outer),'One fullreturn per admittedouter')
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
    selectors=2 if name.startswith('normal') else 1;require(len(d['selector_bridge_entries'])==selectors and final_status[42]==final_status[43]==selectors,'Actual reselection counts')
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
    idle=d['terminal_register_snapshots'];require(len(idle)==1 and idle[0]['address']==0x9400000 and idle[0]['GP16'][15]==0x9400000,'Actual serialized idle arrival')
    check_actor(idle[0],I)
    counts.update(name=name,full_original_returns=len(full),original_callsite_counts=dict(sites),selector_entries=selectors,music_bytes=512*cycle,underrun_silence_bytes=1280*cycle,total_output_bytes=len(audio),denials=final_status[5],mixer_revocations=final_status[41],actual_contextsave_store_count=len(rp.contexts),native_profile_callback_CPU_writes=rp.callbacks,
        original_priority_source12_mixer23_controller16=True,actual_source_before_mixer_handoff=True,actual_native_FULL_SP_LR_GP4_to11_IRQmode_returns_verified=True,GP_CPSR_store_semantics_and_joint_whole_replay_verified=True,
        controller_function_final_return_registers_serialized=False,all_per_instruction_nonstore_controlflow_or_scheduler_lifetime_verified=False,actual_hardware_reset_transport_requests=len(reset_rows))
    return counts

def main():
    proofp=BASE/'mixer-handoff-v5-proof.json';proof=load(proofp)
    require(sha(proofp)=='bbeece455499503f1eb8c26e257d6db427b649f914740150bcace782e306b954','Frozenv5 proof')
    sources=dict(proof['source_sha256'])
    for p,h in sources.items():require(sha(ROOT/p)==h,p)
    require(load(BASE/'guest-v5/inputs-at-run.json')==sources,'Actualsource registry')
    runnerp=BASE/'emulate_mixer_handoff_v5.py';require(sources[rel(runnerp)]=='657f190d1492d3bf9f6d278dcfeeb1be41bef8c330acd736864e9bf221bae345','Frozenrunner')
    require(sha(BASE/'guest-v5/runner-at-run.py')==sha(runnerp),'Exactactualrunnersnapshot')
    buildp=BASE/'build-v5.json';build=load(buildp);elfp=ROOT/build['ELF']
    require(sha(elfp)==build['ELF_sha256']=='13b3d11761e107c0481903e8786d8d8ef28f078ed248ac91ca014838a5ea11a1','ExactcompiledELF')
    elf=ELF(elfp);symbols=build['symbols']
    for name,s in symbols.items():
        require(any(e['name']==name and e['value']==s['value'] and e['size']==s['size'] and e['section']==s['section_index'] for e in elf.symbols),'Actual manifest symbol identity '+name)
    for p,h in {**build['source_sha256'],**build['generated_sha256']}.items():require(sha(ROOT/p)==h,'Buildregistry '+p)
    receiptp=BASE/'guest-v5-terminal-tool-receipt.json';receipt=load(receiptp)
    require(receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='317e2a' and receipt['started_session_id']==3366,'ActualROOTterminal')
    source=runnerp.read_text();tree=ast.parse(source)
    require('IDLE, DESCRIPTORS = 0x09400000, 0x09401800' in source and '(0x09401000, 4096)' in source,'DedicatedRW descriptorcorrection')
    require(not any(isinstance(t,ast.Call) and isinstance(t.func,ast.Attribute) and t.func.attr in ('host_return','context_restore') for t in ast.walk(tree)),'Pythonactor restore method')
    require('if target == 0 and uc.reg_read(UC_ARM_REG_LR) == 0x1D8C8D:' in source and '0x46CC7A' in source,'Explicitnarrowpolicy/transport fixtures')
    require('self.uc.emu_start(entry, old.RETURN' in source,'Ordinaryendaddress limits reviewed')
    n=NativeImage();require(hashlib.sha256(n.data).hexdigest()==EXPECTED,'ExactMAIN')
    rows=[]
    for item in proof['cases']:
        p=ROOT/item['path'];require(sha(p)==item['sha256'],'Frozenactualcase '+item['name'])
        d=load(p);require(d['name']==item['name'] and d['passed'],'Caseidentity')
        row=verify_case(d,n,elf,symbols);row['case_sha256']=sha(p);rows.append(row);sources[rel(p)]=sha(p)
    require(len(rows)==3 and sum(r['CPU_stores'] for r in rows)==42368 and sum(r['joint_events'] for r in rows)==42499 and sum(r['full_original_returns'] for r in rows)==48,'Actualaggregatecounts')
    failures=[]
    for version,chunk in ((1,'da7cf0'),(2,'7c4293'),(3,'5a13e1'),(4,'37dd23')):
        runtime=BASE/('guest-v'+str(version));rp=BASE/('guest-v'+str(version)+'-terminal-tool-receipt.json');r=load(rp)
        require(r['actual_terminal_result']['exit_code']==1 and r['actual_terminal_result']['chunk_id']==chunk,'Preservedactualfailureterminal '+str(version))
        fp=runtime/'terminal-failure.json';f=load(fp)
        require(not f['all_passed'],'Failure preserved')
        require(sha(runtime/'runner-at-run.py')==sha(BASE/('emulate_mixer_handoff_v'+str(version)+'.py')),'Failure exactsnapshot')
        failures.append(dict(version=version,actual_exit_code=1,actual_chunk=chunk,error=f['error'],original_frozen_failure_sha256=sha(fp),independent_replay_of_failed_attempt=False))
        for p in (rp,fp,runtime/'runner-at-run.py',runtime/'inputs-at-run.json',BASE/('emulate_mixer_handoff_v'+str(version)+'.py')):sources[rel(p)]=sha(p)
    for p in (Path(__file__).resolve(),proofp,receiptp,buildp,elfp,BASE/'guest-v5/inputs-at-run.json',BASE/'guest-v5/runner-at-run.py',ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_task_events.py',BASE/'static-review-v1/mixer-handoff-build-v4-static-review-seal.json',BASE/'static-review-v1/runner-v4-and-reset-transport-peer-review-seal.json'):sources[rel(p)]=sha(p)
    
    for p in sorted(Path(__file__).resolve().parent.glob('file-verifier-v*-terminal-failure-receipt.json')):
        r=load(p);require(r['tool_result']['exit_code']==1 and not r['guest_execution'],'Preserved file reviewer failure')
        for x,h in r['source_sha256'].items():require(sha(ROOT/x)==h,'Frozen failed reviewer');sources[x]=h
        sources[rel(p)]=sha(p)
    require(not any(k=='unicorn' or k.startswith('unicorn.') for k in sys.modules),'VM imported')
    for p,h in sources.items():require(sha(ROOT/p)==h,'Finaldependencycheck '+p)
    output=Path(__file__).resolve().parent/'mixer-handoff-v5-independent-file-verification.json'
    result=dict(all_passed=True,independent_FILE_ONLY=True,source_sha256=sources,case_count=3,cases=rows,actual_ROOT_terminal_session=3366,actual_ROOT_terminal_chunk='317e2a',actual_ROOT_guest_exit_code=0,
        CPU_stores=42368,joint_events=42499,tracked_whole_zone_case_replays=72,actual_RW_case_replays_from_frozen_permission_recipe=69,unchanged_RX_return_sentinel_case_replays=3,full_original_native_returns=48,
        exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,
        three_guest_only_BL_patches_and_three_interworking_veneers_verified=True,stock_MAIN_file_unchanged=True,independent_after_declared_patches_RX_baseline_verified=True,
        actual_original_cold_context_builders_source_mixer_tasks_POST_WAIT_restore_entries_and_resident_saved_frames_verified=True,actual_native_source_to_mixer_capability_and_original_FIFO_publication_consumption_verified=True,
        both_original_callsite_LR_SP_and_serialized_native_full_returns_leases_verified=True,returned_callee_saved_GP4_to11_and_CPSR_mode_IRQ_masks_verified=True,
        complete_all_instruction_GP_or_controlflow_or_kernel_lifetime_proof=False,ordinary_controller_function_return_GP16_CPSR_SP_serialized=False,full_mixer_native_and_outer_return_GP16_CPSR_SP_serialized=True,
        raw_compiled_PCM_source=True,explicit_output_consumer_readindex_fixture=True,explicit_opaque_allocation_query_release_and_generic_mutex_policy_fixtures=True,explicit_46CC7A_original_syncwait_ack_tail_bypassed=True,explicit_hardware_reset56_request_transport_and_source17_reset_complete_input=True,
        native_heap_mutex_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified=False,device_io=False,canonical_write=False,VM_import_or_instantiation=False,guest_rerun=False,
        preserved_actual_failed_attempts=failures,
        limits=['Three bounded rootguestcases use actual original source/mixer builder,POST/WAIT/restore,FIFO,selector/fullpull bodies and compiledresident source/reader. Guest-only three BL redirects/sixpatchledger are not an installed stockMAIN hook or a complete physicalApp.',
          'Original46CC7A synchronization lock/message20/waitbit8/ack tail is a declared service return; sourcepriority12 cannot alone rule out an originalblockingcalleeterm before handoff. Genericmutex calls, opaqueallocation/query/release, bookkeeping and audio priority remain fixtures, not native kernelownership/heap/MMU evidence.',
          'Hardware reset payload is actual original56bytes copied from mixer stack, including untouchedpadding/residualbytes. Target0/LR1D8C8D transport capture skips an uninitialized backendqueue. Message17 is a compiled source input, not driverACK/native STOP_DONE.',
          'PCM is deterministic compiledsource data. Outputactivation/descriptors/capacity/scratch and readindex advancement after actorsblock are explicitfixtures; no physicalDMA/speaker/decoderworker/phone/exclusivity evidence. Ownership witness staysminus200.',
          'PerCPUstore completeGP16/CPSR and actualfullnative/outerreturns are serialized and checked. Instructionvisit histogram is not a fullnonstoreGP/controlflow trace. emu endaddress08D00000 bypasses CODEsnapshot for ordinarycontrollerreturns: those returnedGP/SP/CPSR are sourceassertions only, not independently readback. Oneidlearrival is serialized.',
          '24 zones percase are tracked underRW flags, but parent calls mem_protect on08D00000 without updating flags. Independently verified72trackedwholezones consist of69source-declaredRWcasezones and3unchangedRXreturnsentinels. Other3RXzones have independent exactpatchedbaselinehashes; finalRXunchangedreadback is asserted by frozenrunner and stored as baselinehash only.',
          'ActualV1outputexpectation,V2hardwaretransport,V3RXdescriptorplacement andV4sameprofileearlyexit failures remain frozen with receipts. Their journals are preserved dependencies; only V5successcases undergo this independent complete jointreplay.'])
    create(output,result)
    print(json.dumps(dict(all_passed=True,proof=rel(output),proof_sha256=sha(output),CPU_stores=42368,joint_events=42499,full_original_native_returns=48,tracked_whole_zone_case_replays=72,guest_execution=False)))
if __name__=='__main__':main()
