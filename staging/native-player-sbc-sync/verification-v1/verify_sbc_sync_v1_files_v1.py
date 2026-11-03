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
BASE = ROOT / 'staging/native-player-sbc-sync'
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
        self.eventchecks=defaultdict(list);self.decode_cache={}
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
        require(set(self.z)==set(self.final) and len(self.z)==26,'26 tracked whole zones')
        specs={x['start']:x for x in self.row['zones']}
        require(len(specs)==29 and len([x for x in specs.values() if x['protection']&4])==3,'Zone recipe')
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
        key=(pc,thumb,raw);ins=self.decode_cache.get(key)
        if ins is None:ins=next(MD[thumb].disasm(raw,pc,count=1));self.decode_cache[key]=ins
        require(ins.size==len(raw),'Instruction complete')
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
                require(not any(sec['flags']&3==3 and a<sec['address']+sec['size'] and a+len(after)>sec['address'] for sec in self.elf.sections if sec['size']),'Fixture seeded compiled data/payload/capability state')
            put(self.z,a,after);self.check_at(e['ordinal'],self.z)
        require(pending is None,'Final incomplete store instruction')
        require(set(self.eventchecks)<=set(range(self.row['initial_ordinal'],self.row['initial_ordinal']+len(events)+1)),'Checkpoint ordinal outside event history')
        require(set(self.checkpoints)==set(self.snapshots),'Missing checkpoint snapshots')
        require({a:bytes(b) for a,b in self.z.items()}==self.final,'24 exact actual-after whole zones')
        require(get(self.z,RETURN,4096)==bytes(4096),'ReturnRXsentinel unchanged by guest')
        return dict(CPU_stores=len(self.row['CPU_store_journal']),joint_events=len(events),tracked_whole_zones=26,actual_RW_zones_from_frozen_parent_permission_recipe=25,unchanged_RX_return_sentinel_tracked_as_RW=1,unique_store_sites=len(self.sites),ISA_and_store_counts=[dict(source=k[0],ISA=k[1],instruction=k[2],hook_bytes=k[3],count=v) for k,v in sorted(self.counts.items())],whole_zone_after_sha256={hex(a):hashlib.sha256(b).hexdigest() for a,b in self.final.items()})

def not_any_arm(pc):return not any(a<=pc<b for a,b in ARM_MAIN)
def check_actor(state,tcb):
    gp=state['GP16'];require(state['current_TCB']==tcb,'Captured native actor');require((state['CPSR']&31) in (0x1f,0x13),'Normal privileged actor mode')
    base,size=STACKS[tcb];require(base<=gp[13]<=tcb,'Actor SP belongs to native stack')
def verify_case(d,n,elf,symbols):
    name=d['name'];normal_case=name.endswith('native_reuse_reselect_reset');crc_case='later_CRC' in name;stop_case='Stop' in name;profile_case='profile' in name;rp=Replay(d,n,elf,symbols);rp.cold()
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
    prepare_sbc_checkpoints(rp,d,symbols)
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
    require(len(condition_tags)==2*(2 if stop_case else 1),'Two actual tag updates per full conditionwait')
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
    commands=d['commands'];expected_commands={
        'mono16_native_reuse_reselect_reset':[1,2,3,4],
        'joint44_native_reuse_reselect_reset':[1,2,3,4],
        'stereo48_native_reuse_reselect_reset':[1,2,3,4],
        'joint44_Stop_rejects_compressed_input':[1,5,8],
        'joint44_later_CRC_reject_and_recover':[1,9,2],
        'stereo48_profile_rewrite_rejects_decode':[1,6,8]}[name]
    require([x['command'] for x in commands]==expected_commands,'Actual compressed-source commands')
    reference=load(BASE/'compressed_input_reference_v1.json')['streams'][d['stream_index']]
    audio=b'';cycle=0;music_bytes=0;silence_bytes=0;reset_pending=False;packet_index=0
    for cmd in commands:
        if cmd['command']<=4:
            key='expected_after_reset_PCM_hex' if reset_pending else 'expected_continuous_PCM_hex'
            pcm=bytes.fromhex(reference['packets'][packet_index][key]);reset_pending=False;packet_index+=1
            expected=pcm+bytes(1792-len(pcm));cycle+=1;music_bytes+=len(pcm);silence_bytes+=1792-len(pcm)
            require(bytes.fromhex(cmd['HOST_expected_PCM_hex'])==pcm,'Frozen expected PCM comparison identity')
            require(bytes.fromhex(cmd['PCM_hex'])==expected and cmd['bytes']==1792 and cmd['source_PCM_bytes']==len(pcm) and cmd['original_self_posted_underrun_silence_bytes']==1792-len(pcm),'Actual decoded/FIR PCM and underrun bytes')
            audio+=expected
        else:
            require(cmd['PCM_hex']=='' and cmd['bytes']==0 and cmd['source_PCM_bytes']==0,'Failed/stopped/revoked no new ring publication')
            if cmd['command']==9:reset_pending=True
        require(all(cmd['state'][k]==0 for k in (2,6,7,8,12)),'Command lease/completion endpoints')
    require(b''.join(total_PCM)==audio,'Actual native fullreturn chunks equal independently checked command PCM')
    require(final_status[3]==final_status[4]==len(full) and final_status[14]==len(audio),'Actual compiled pulls/fullreturns/byte counters')
    expected_count=32 if normal_case else (16 if crc_case else 8);require(len(full)==expected_count,'Actual expected native fullreturns')
    selectors=2 if (normal_case or stop_case) else 1;require(len(d['selector_bridge_entries'])==selectors and final_status[42]==final_status[43]==selectors,'Actual selector counts')
    if normal_case or crc_case:
        require(sites['0x2fa536']>0 and sites['0x2fa572']>0 and final_status[5]==0 and final_status[48]==(16 if normal_case else 8),'Both original fullcallroutes/current FIFO ticket')
        require(word(z,RECORD+0x108)==symbols['memory_output_read']['value'],'Leased original-selector reader installed')
    else:
        require(final_status[41]==1 and word(z,g+20*4)==0,'Actual capability revoked')
        require(final_status[5]==(2 if stop_case else 1),'Actual local Stop/profile denial counters')
    require(len(reset_rows)==(1 if (normal_case or stop_case) else 0),'Actual exact reset transport count')
    # Callback installs must be native or compiled CPU stores, never seeded.
    require(rp.callbacks[0]['PC']=='0x277dbc' and rp.callbacks[0]['value']==0x277c6b,'Originalinitialprofile callback')
    require(any(x['value']==symbols['mcs_queue_bridge']['value'] and x['actor']==S for x in rp.callbacks),'Compiledsource callbackinstallation')
    if profile_case:
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
    counts.update(name=name,full_original_returns=len(full),original_callsite_counts=dict(sites),denied_outer_wrapper_returns=len(denied),selector_entries=selectors,music_bytes=music_bytes,underrun_silence_bytes=silence_bytes,total_output_bytes=len(audio),denials=final_status[5],mixer_revocations=final_status[41],actual_contextsave_store_count=len(rp.contexts),native_profile_callback_CPU_writes=rp.callbacks,
        original_priority_source12_mixer23_controller16=True,actual_source_before_mixer_handoff=True,actual_native_FULL_SP_LR_GP4_to11_IRQmode_returns_verified=True,GP_CPSR_store_semantics_and_joint_whole_replay_verified=True,
        controller_function_final_return_registers_serialized=True,all_per_instruction_nonstore_controlflow_or_scheduler_lifetime_verified=False,actual_hardware_reset_transport_requests=len(reset_rows))
    counts.update(verify_sbc_pipeline(d,rp,symbols,reference))
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
    expected=2 if ('Stop' in d['name']) else 1
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

# NEW SBC-specific file-only extension appended to frozen verifier logic.
import gc

def prepare_sbc_checkpoints(rp,d,symbols):
    for e in d['compiled_producer_entries']:
        rp.enqueue('compiled producer '+e['symbol'],e['entry'],e['leases']);rp.checkpoints.add(e['entry']['ordinal'])
    for e in d['compiled_decoder_full_returns']:
        rp.enqueue('actual decoder full return',e['returned'],e['return_leases']);rp.checkpoints.add(e['returned']['ordinal'])
    # Capture after each actual ticket FIFO commit to compare copied payload.
    committed=symbols['owned_media_control']['value']+32
    for e in d['CPU_store_journal']:
        if int(e['address'],16)==committed:rp.checkpoints.add(e['ordinal'])

def producer_at(z,symbols):
    return dict(owned=list(struct.unpack('<13I',get(z,symbols['owned_media_control']['value'],52))),
        queue=list(struct.unpack('<9I',get(z,symbols['media_queue_control']['value'],36))),
        packet_index=word(z,symbols['mp_packet_index']['value']),
        last_decode_error=struct.unpack('<i',get(z,symbols['mp_last_decode_error']['value'],4))[0])

def verify_sbc_pipeline(d,rp,symbols,reference):
    entries=d['compiled_producer_entries'];codec=d['compressed_decoder_entries'];returns=d['compiled_decoder_full_returns']
    require(len(codec)==len(returns),'Every actual decoder entry has full native compiled return')
    declared={bytes.fromhex(p['packet_hex']):p for p in reference['packets']}
    bad=bytes.fromhex(reference['bad_later_frame_CRC_packet_hex'])
    frames=0;failed_frames=0
    for e in entries:
        st=e['entry'];z=rp.snapshots[st['ordinal']];check_actor(st,S)
        require(st['GP16'][15]==symbols[e['symbol']]['value'] and st['CPSR']&0xff==0x1f,'Exact compiled ARM normal Source function entry')
        require(e['args']==st['GP16'][:4] and producer_at(z,symbols)==e['producer'],'Actual producer control and argument readback')
        if e['symbol'] in ('owned_packet_parse','garmin_sbc_decode_frame','pcm_converter_process','memory_output_submit'):
            require(e['leases']['borrow']==0 and e['leases']['media']==e['leases']['callback']==1,'Typed Source producer whole callback/media leases')
            require(word(z,RECORD+0x160)==symbols['mcs_queue_bridge']['value'],'Actual profile callback coherent before decode/submit')
        if e['symbol']=='media_queue_callback':
            gp=st['GP16'];size=word(z,gp[13]);raw=get(z,gp[3],size)
            require(gp[:3]==[0xf1,0,0] and raw.hex()==e['packet_hex'] and size==e['packet_bytes'],'Exact callback r0..r3/stack length actual RAM bytes')
            require(raw in declared or raw==bad,'Declared compiled compressed input')
            rawelf,sec=rp.elf.at(gp[3],size);require(sec['flags']&4 and rawelf==raw,'Actual input came from compiled RX fixture bytes; no HOST PCM seed')
    for e,r in zip(codec,returns):
        require(all(r[k]==v for k,v in e.items()),'Decoder matched original entry metadata')
        check_actor(r['returned'],S);es=e['entry'];rs=r['returned'];ez=rp.snapshots[es['ordinal']];rz=rp.snapshots[rs['ordinal']]
        require(es['ordinal']<rs['ordinal'] and rs['GP16'][15]==e['return_PC']==(es['GP16'][14]&~1),'Actual decoder complete entry/return PC order')
        require(es['GP16'][13]==e['entry_SP']==rs['GP16'][13] and es['GP16'][4:12]==rs['GP16'][4:12],'Decoder full SP/callee saved GP preservation')
        require((es['CPSR']&0xff)==(rs['CPSR']&0xff)==0x1f and r['r0']==rs['GP16'][0],'Decoder return ISA/mode/IRQ and R0 snapshot')
        require(e['args'][3]==512 and e['result_pointer']==word(ez,es['GP16'][13]),'Decoder fifth ABI result pointer, source PCM capacity')
        require(get(ez,e['args'][0],e['args'][1]).hex()==e['frame_hex'],'Actual copied frame input bytes')
        result=list(struct.unpack('<9I',get(rz,e['result_pointer'],36)));require(result==r['decoder_result'],'Actual decoder result memory readback')
        for view in (e['leases'],r['return_leases']):require(view['media']==view['callback']==1 and view['borrow']==0,'Decoder lease retained through full return')
        if r['r0']==0:
            require(result[:5]==[e['args'][1],128*reference['channels']*2,reference['rate'],reference['channels'],128],'Decoder actual consumed/written/rate/channels/samples ABI')
            frames+=1
        else:require(r['r0']==0xfffffffa,'Only declared actual later-frame CRC error');failed_frames+=1
    parses=[e for e in entries if e['symbol']=='owned_packet_parse'];submits=[e for e in entries if e['symbol']=='memory_output_submit'];success=[];reset=False;crc_checks=[]
    for j,p in enumerate(parses):
        lo=p['entry']['ordinal'];hi=parses[j+1]['entry']['ordinal'] if j+1<len(parses) else max(e['ordinal'] for e in d['CPU_store_journal'])+1
        z=rp.snapshots[lo];gp=p['entry']['GP16'];raw=get(z,gp[3],word(z,gp[13]));cs=[r for r in returns if lo<r['entry']['ordinal']<hi];ss=[e for e in submits if lo<e['entry']['ordinal']<hi]
        require(raw in declared or raw==bad,'Actual queue copied whole original compressed input')
        require(0x07902000<=gp[3] and gp[3]+len(raw)<=0x07906000,'Parser consumes resident compressed queue payload')
        if raw==bad:
            require([r['r0'] for r in cs]==[0,0xfffffffa] and not ss,'Second frame CRC failure does not enter PCM submit')
            require(j+1<len(parses),'Declared CRC recovery parser snapshot exists')
            nz=rp.snapshots[hi]
            for i in range(4):require(get(z,0x07700000+i*4096,4096)==get(nz,0x07700000+i*4096,4096),'Bad packet does not change any PCM FIFO payload')
            require(get(z,symbols['memory_output_slots']['value'],96)==get(nz,symbols['memory_output_slots']['value'],96),'Bad packet does not mutate PCM slot generations/state/lease')
            a,b=producer_at(z,symbols),producer_at(nz,symbols)
            require([a['owned'][k] for k in (2,3,4,8,11,12)]==[b['owned'][k] for k in (2,3,4,8,11,12)] and a['packet_index']==b['packet_index'],'Bad packet leaves FIFO indices/count/committed/released/lastticket/input index unchanged')
            require(word(z,symbols['memory_output_control']['value']+8)==word(nz,symbols['memory_output_control']['value']+8),'Bad packet allocates no FIFO generation')
            crc_checks.append(dict(parser_entry_ordinal=lo,next_recovery_parser_ordinal=hi,decoder_returns=[0,-6],PCM_FIFO_4096x4_unchanged=True,PCM_slot96_unchanged=True,no_submit=True));reset=True
        else:
            require([r['r0'] for r in cs]==[0,0] and len(ss)==1,'Two decoded frames precede one whole-packet submit')
            expected=bytes.fromhex(declared[raw]['expected_after_reset_PCM_hex' if reset else 'expected_continuous_PCM_hex']);reset=False
            se=ss[0];sz=rp.snapshots[se['entry']['ordinal']];require(se['args'][0]==0x07900000 and se['args'][1]==len(expected),'Whole private gather exact pointer/length')
            require(get(sz,0x07900000,len(expected))==expected,'Actual CPU-written gather matches frozen HOST comparison only')
            commits=[e for e in d['CPU_store_journal'] if lo<e['ordinal']<hi and int(e['address'],16)==symbols['owned_media_control']['value']+32]
            require(len(commits)==1 and commits[0]['value']==len(success)+1 and commits[0]['current_TCB']==S,'Exactly one Source CPU FIFO commit after packet success')
            cz=rp.snapshots[commits[0]['ordinal']];owned=producer_at(cz,symbols)['owned'];ticket=word(cz,symbols['memory_output_slots']['value']+(len(success)%4)*24)
            # The sole FIFO consumer frees slot0 before each next submission in
            # this bounded runner; retain current generation independent of it.
            ready=[(i,struct.unpack('<6I',get(cz,symbols['memory_output_slots']['value']+i*24,24))) for i in range(4)]
            ready=[(i,v) for i,v in ready if v[1]==2 and v[0] and v[2]==len(expected)]
            require(len(ready)==1,'One privately READY whole-packet slot at actual commit');i,v=ready[0];ticket=v[0]
            require(ticket==4*(len(success)+1)+i and get(cz,0x07700000+i*4096,len(expected))==expected,'Actual copied PCM page complete before private FIFO publication')
            require(v[5]==0 and owned[4]==1,'No in-flight consumer at producer commit, one FIFO packet')
            success.append(dict(parser_entry_ordinal=lo,submit_entry_ordinal=se['entry']['ordinal'],commit_ordinal=commits[0]['ordinal'],ticket=ticket,PCM_bytes=len(expected),PCM_sha256=hashlib.sha256(expected).hexdigest()))
    z=rp.final;terminal=producer_at(z,symbols);require(terminal==d['producer_terminal'],'Actual final producer fields')
    require(terminal['owned'][8]==len(success) and terminal['owned'][9]==len(crc_checks) and terminal['packet_index']==len(success),'Actual whole-packet success/error counters')
    require(terminal['owned'][1]==terminal['owned'][4]==terminal['queue'][2]==terminal['queue'][5]==terminal['queue'][6]==0,'All actual queue producer/consumer/FIFO work returned, no unfinished decoder')
    require(len(submits)==len(success) and len(codec)==2*len(parses),'Exact parser/decoder/commit call cardinalities')
    stop='Stop' in d['name'];profile='profile' in d['name']
    if stop or profile:
        denied=[e for e in entries if e['entry']['phase']=='request compressed-source command 8'];require(denied,'Actual new compressed input rejection observed')
        require(not any(e['symbol'] in ('owned_packet_parse','garmin_sbc_decode_frame','pcm_converter_process','memory_output_submit') for e in denied),'Rejected input never enters decode/FIR/PCM commit')
        if stop:require([e['symbol'] for e in denied]==['media_queue_callback'] and terminal['last_decode_error']==-22 and terminal['queue'][4]==0,'Stop denies even queue step after callback admission')
        else:require(terminal['last_decode_error']==-201 and word(z,RECORD+0x160)==0x277c6b and any(e['symbol']=='owned_media_consume' for e in denied),'Original profile callback mismatch rejects before decode')
    # Compiled producer metadata and payload are CPU-only after baseline:
    # Replay denied all host fixtures touching any allocated writable ELF section.
    require(not d['phone_AVDTP_or_live_packet_receiver_verified'] and d['expected_PCM_was_never_written_to_guest'],'Declared offline-only input limits')
    return dict(actual_decoder_full_returns=len(returns),actual_successful_decoder_returns=frames,actual_failed_decoder_returns=failed_frames,
        whole_packet_successful_commits=len(success),whole_packet_commit_rows=success,second_frame_CRC_independent_checks=crc_checks,
        Source_typed_producer_lease_full_decoder_returns_verified=True,actual_compressed_copy_gather_FIFO_and_native_PCM_bytes_verified=True,
        actual_Stop_before_decode_rejection=stop,actual_original_profile_callback_before_decode_rejection=profile,
        compressed_input_is_compiled_fixture_not_phone=True,HOST_expected_PCM_only_compared=True)

def main():
    output=Path(__file__).resolve().parent/'sbc-sync-v1-independent-file-verification.json'
    require(not output.exists(),'NEW output already exists');proofp=BASE/'sbc-sync-v1-proof.json';proof=load(proofp)
    require(sha(proofp)=='a4e7d6400f5ad67277b537ff9407b8ac8c1e3524aa33bbb6e0edd026002f8ad0' and proof['all_passed'],'Exact actual ROOT SBC proof')
    sources=dict(proof['source_sha256'])
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'Frozen ROOT input '+path)
    require(load(BASE/'guest-v1/inputs-at-run.json')==sources,'Exact actual run registry')
    receiptp=BASE/'guest-v1-terminal-tool-receipt.json';receipt=load(receiptp)
    require(receipt['terminal'] and receipt['started_session_id']==35422 and receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='27fd35','Actual authoritative ROOT terminal')
    require(sha(BASE/'emulate_sbc_sync_v1.py')=='ac6be80e5c5a43b0abaa047bfabc4945646d1a3350d0bfdfc578aecc8b0c43cb' and sha(BASE/'guest-v1/runner-at-run.py')==sha(BASE/'emulate_sbc_sync_v1.py'),'Frozen actual runner snapshot')
    build,elf,symbols=verify_build(BASE/'build-v3.json',sources)
    require(build['ELF_sha256']=='c170e77c216abb44e6a6570034768ce00deb3226b20d1bd0349b70d1e564a4eb','Exact SBC ELF')
    n=NativeImage();require(hashlib.sha256(n.data).hexdigest()==EXPECTED,'Exact MAIN1352/8.00')
    rows=[]
    for item in proof['cases']:
        p=ROOT/item['path'];h=sha(p);require(h==item['sha256'],'Actual sealed ROOT case digest')
        d=load(p);require(d['name']==item['name'] and d['passed'],'Actual case identity')
        row=verify_case(d,n,elf,symbols);row['case_sha256']=h;row['actual_original_and_ELF_instruction_visits']=d['instructions'];rows.append(row);sources[rel(p)]=h
        print(json.dumps(dict(case=row['name'],CPU_stores=row['CPU_stores'],joint_events=row['joint_events'],decoder_full_returns=row['actual_decoder_full_returns'],native_full_returns=row['full_original_returns'],FILE_only=True)),flush=True)
        del d;gc.collect()
    expected=dict(CPU_stores=412189,joint_events=412491,tracked_whole_zones=156,actual_RW_zones_from_frozen_parent_permission_recipe=150,unchanged_RX_return_sentinel_tracked_as_RW=6,actual_final_RX_dump_zones=18,actual_decoder_full_returns=34,actual_successful_decoder_returns=33,actual_failed_decoder_returns=1,full_original_returns=128,full_original_sync_returns=7,actual_original_condition_waits=7,actual_original_ACK8=7,music_bytes=4206,underrun_silence_bytes=24466,total_output_bytes=28672,actual_original_and_ELF_instruction_visits=4671894)
    require(len(rows)==proof['case_count']==6,'Six bounded complete cases')
    for key,value in expected.items():require(sum(r[key] for r in rows)==value,'Exact independently replayed aggregate '+key)
    staticp=BASE/'static-review/sbc-pipeline-build-v3-peer-review.json';staticseal=BASE/'static-review/sbc-pipeline-build-v3-static-seal.json';seal=load(staticseal)
    require(sha(staticp)=='7705c4dfef585c508452cbce09a9a7c9099489823366881d5a61754e479e1700' and sha(staticseal)=='b12eef499499449ed3018205364f25326d9fe06505323868d3f333bc16dcfc5a','Frozen static contract')
    for path,h in {**seal['source_sha256'],**seal['output_sha256']}.items():require(sha(ROOT/path)==h,'Frozen static dependency');sources[path]=h
    # Hash only completed namespace files, excluding this new live verifier dir.
    for p in sorted(BASE.rglob('*')):
        if p.is_file() and 'verification-v1' not in p.parts and '__pycache__' not in p.parts:sources[rel(p)]=sha(p)
    for p in (Path(__file__).resolve(),ROOT/'staging/native-player-mixer-sync/verification-v3/verify_mixer_sync_v3_files_v6.py',Path(__file__).resolve().parent/'sbc_file_verifier_extension_v1.py',Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v1.py',Path(__file__).resolve().parent/'source-copy-provenance-v1.json',ROOT/'scripts/analyze_native_sections.py'):sources[rel(p)]=sha(p)
    require(not any(k=='unicorn' or k.startswith('unicorn.') for k in sys.modules),'VM imported')
    for path,h in sources.items():require(sha(ROOT/path)==h,'Final exact source readback '+path)
    result=dict(all_passed=True,independent_FILE_ONLY=True,source_sha256=sources,case_count=6,cases=rows,actual_ROOT_terminal_session=35422,actual_ROOT_terminal_chunk='27fd35',actual_ROOT_guest_exit_code=0,totals=expected,
        exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,
        actual_compressed_SBC_and_FIR_private_gather_whole_packet_FIFO_to_original_mixer_verified=True,actual_second_frame_CRC_no_PCM_prefix_verified=True,actual_first0_second_minus6_full_decoder_returns_and_reset_recovery_verified=True,
        Source_typed_media_callback_leases_and_actual_native_fullreturn_leases_verified=True,original_raw_mutex_condition_ACK8_preemption_contention_priority_donation_unlocktransfer_fullreturn_verified=True,
        actual_after_declared_patches_RX_baseline_and_final_RX_dumps_verified=True,final_controller_idle_GP16_CPSR_SP_and_full_native_outer_sync_registers_serialized=True,complete_all_instruction_controlflow_or_kernel_lifetime_proof=False,
        actual_phone_AVDTP_receiver_or_installed_App_or_hardware_speaker_verified=False,native_heap_exclusive_STOP_DONE_or_safe_unload_verified=False,
        device_io=False,canonical_write=False,VM_import_or_instantiation=False,guest_rerun=False,
        limits=['412189 captured CPU stores independently decode exact original MAIN/compiled ELF and GP16/CPSR effective address/value; whole150 trueRW case-zones plus6 unchanged RX return sentinels and18 actual finalRX dumps replay. This is not an independent trace of all4671894 nonstore/controlflow instructions.',
        'Compressed input is18 compiled offline packets; first fixture packet is decoded synchronously in Source bootstrap to create registration ticket before original native mixer initialization. Real phone bootstrap must first initialize typed guard/profile/queue, wait for external copied first packet, decode it on Source, then create native anchor/mixer/sync. POST alone does not make actual receiver integration.',
        'Current mh_source_entry ignores WAIT bits and serves mh_command. Future copy-only original AVDTP ingress must acquire typed callback/media input lifetime, POST actual Source event after queue publication, drain queued packets on Source, and wire freed FIFO capacity to Source retry. UMC_SOURCE_EVENT=0x80000 differs from current command bit1. Current separate media_worker_state.tcb is not constructed.',
        'Second CRC packet changes private gather and speculative parser counters; all four PCM page payloads/96-byte slot state and publication counters remain unchanged, and actual decoder fullreturns are0/-6. Recovery is compared with frozen after-reset SBC/FIR HOST reference, not continued stream history.',
        'Stop closes future queue/decode/commit but does not claim native15/19 cleanup/list removal, hardware flush, nativeSTOP_DONE, anchor retirement, exclusive channel ownership or safe storage unload. Profile transition is actual original277D26 rewrite and denied before decoder; input copy may already have occurred.',
        'Original kernel/context/mutex/condition/FIFO/selector/reader/fullpull bodies execute under four explicit guest BL redirects. Direct Timer/rawmutex/condition constructors are declared boot callers, controller/idle ready input is supplied, and no full physical cold boot is claimed.',
        'Opaque handles/allocation/query/release, mixer stack/FIFO backing, bounded16KiB codec arena/free no-op, task bookkeeping/audio policy, output activation/raw output mode, explicit output consumer read-index advance, reset transport and compiled synthetic message17 completion remain fixtures. HOST expected PCM is only compared and never seeds guest PCM.',
        'No actual SEP registration, live Pixel packet reception, physical speaker/DMA/MMU backing/native general allocator, App/UI or VPM/SIG install acceptance is verified.'])
    create(output,result);print(json.dumps(dict(all_passed=True,proof=rel(output),proof_sha256=sha(output),CPU_stores=expected['CPU_stores'],joint_events=expected['joint_events'],decoder_full_returns=34,full_original_returns=128,guest_execution=False)),flush=True)
if __name__=='__main__':main()
