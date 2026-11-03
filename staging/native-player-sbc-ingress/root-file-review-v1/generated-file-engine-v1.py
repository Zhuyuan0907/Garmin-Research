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

BASE = ROOT / 'staging/native-player-sbc-ingress'

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
        self.eventchecks=defaultdict(list);self.decode_cache={};self.copy_counts=Counter();self.PCM_copied=defaultdict(set);self.queue_copied=defaultdict(set)
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
        require(set(self.z)==set(self.final) and len(self.z)==27,'27 permission-declared RW zones including unchanged return sentinel')
        specs={x['start']:x for x in self.row['zones']}
        require(len(specs)==30 and len([x for x in specs.values() if x['protection']&4])==3,'Zone recipe')
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
        self.final_RX_verified=len(final_rx);self.actual_RX_bytes={int(a):bytes.fromhex(raw) for a,raw in final_rx.items()}
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
                verify_sbc_copy_state(self,e)
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
                require(not any(sec['flags']&3==3 and a<sec['address']+sec['size'] and a+len(after)>sec['address'] for sec in self.elf.sections if sec['size']) or supported_compiled_stack_fixture(self,e,a,after),'Fixture seeded compiled data/payload/capability state')
            put(self.z,a,after);self.check_at(e['ordinal'],self.z)
        require(pending is None,'Final incomplete store instruction')
        require(set(self.eventchecks)<=set(range(self.row['initial_ordinal'],self.row['initial_ordinal']+len(events)+1)),'Checkpoint ordinal outside event history')
        require(set(self.checkpoints)==set(self.snapshots),'Missing checkpoint snapshots')
        require({a:bytes(b) for a,b in self.z.items()}==self.final,'24 exact actual-after whole zones')
        require(get(self.z,RETURN,4096)==bytes(4096),'ReturnRXsentinel unchanged by guest')
        return dict(CPU_stores=len(self.row['CPU_store_journal']),joint_events=len(events),tracked_whole_zones=27,actual_RW_zones_from_frozen_parent_permission_recipe=27,unchanged_RX_return_sentinel_tracked_as_RW=1,unique_store_sites=len(self.sites),ISA_and_store_counts=[dict(source=k[0],ISA=k[1],instruction=k[2],hook_bytes=k[3],count=v) for k,v in sorted(self.counts.items())],whole_zone_after_sha256={hex(a):hashlib.sha256(b).hexdigest() for a,b in self.final.items()})

def not_any_arm(pc):return not any(a<=pc<b for a,b in ARM_MAIN)

def check_actor(state,tcb):
    gp=state['GP16'];require(state['current_TCB']==tcb,'Captured native actor');require((state['CPSR']&31) in (0x1f,0x13),'Normal privileged actor mode')
    base,size=STACKS[tcb];require(base<=gp[13]<=tcb,'Actor SP belongs to native stack')

def verify_sbc_copy_state(rp,e):
    a=int(e['address'],16);pc=int(e['PC'],16);n=e['size'];z=rp.z;sy=rp.symbols;gp=e['GP16'];value=e['value']&((1<<(n*8))-1)
    slots=sy['memory_output_slots']['value'];q=sy['media_queue_control']['value'];g=rp.guard;c=rp.control
    mm=sy['memcpy']['value']
    if pc==mm+16:
        require(n==1 and rp.elf.at(mm,28)[0]==bytes.fromhex('0030a0e3020053e11eff2f0103c0d1e703c0c0e7013083e2f9ffffea'),'Exact bounded compiled memcpy LDRB/STRB loop')
        require(a==gp[0]+gp[3] and value==get({**z,**rp.actual_RX_bytes},gp[1]+gp[3],1)[0],'Actual memcpy source-memory byte equals GP/CPU destination payload')
        rp.copy_counts['exact_compiled_memcpy_source_bytes']+=1
    if 0x07700000<=a<a+n<=0x07704000:
        i=(a-0x07700000)//4096;offset=a-(0x07700000+i*4096);s=struct.unpack('<6I',get(z,slots+i*24,24));view=rp.leases(z)
        require(e['current_TCB']==S and e['CPSR']&0xff==0x1f and pc==mm+16,'PCM copy only unlocked Source compiled memcpy')
        require(s[1]==1 and s[5]==0 and s[0] and offset+n<=s[2],'PCM COPYING lease and declared whole packet byte bound')
        require(view['media']==view['callback']==1+int(bool(view['borrow'])) and word(z,sy['owned_media_control']['value']+4)==1,'Typed producer lifetime held during complete PCM copy')
        require(gp[1]==0x07900000 and value==get(z,0x07900000+offset,n)[0],'Actual PCM page byte comes from private complete gather')
        rp.PCM_copied[i].update(range(offset,offset+n));rp.copy_counts['PCM_COPYING_bytes']+=n
    if 0x07902000<=a<a+n<=0x07906000:
        i=(a-0x07902000)//4096;offset=a-(0x07902000+i*4096)
        require(e['current_TCB']==C and e['CPSR']&0xff==0x1f and pc==mm+16,'Copied foreign packet on actual controller')
        view=rp.leases(z);require(view['media']==view['callback']==1 and not view['borrow'],'Foreign copied payload typed lifetime')
        require(word(z,q+20)==1 and word(z,q+16)==1 and word(z,q+4)==i,'Compressed producer_busy/running/write slot reservation')
        if offset==0:rp.queue_copied[i]=set()
        rp.queue_copied[i].update(range(offset,offset+n));rp.copy_counts['compressed_queue_copied_bytes']+=n
    if slots<=a<slots+96 and (a-slots)%24==4 and n==4:
        i=(a-slots)//24;old=word(z,a)
        if value==1:
            require(old==0 and e['current_TCB']==S,'Only Source reserves FREE FIFO slot for COPY');rp.PCM_copied[i]=set();rp.copy_counts['FIFO_COPYING_reservations']+=1
        if value==2:
            length=word(z,slots+i*24+8)
            require(old==1 and rp.PCM_copied[i]==set(range(length)) and e['current_TCB']==S,'Entire PCM payload copied before READY publication');rp.copy_counts['whole_FIFO_READY_publications']+=1
        if value==0 and old==2:
            view=rp.leases(z);require(e['current_TCB']==M and word(z,slots+i*24+20)==0 and view['borrow'] and view['media']==view['callback']==1,'Mixer frees FIFO only after copy in_flight returns0 under full native lease');rp.copy_counts['FIFO_free_after_inflight_zero']+=1
    if a==q+8 and n==4 and value==word(z,q+8)+1:
        i=(word(z,q+4)-1)%4;length=word(z,sy['lengths']['value']+4*i)
        require(rp.queue_copied[i]==set(range(length)) and word(z,q+20)==0 and e['current_TCB']==C,'Whole foreign compressed copy completes before queue count publication');rp.copy_counts['whole_compressed_queue_publications']+=1
    if SCRATCH<=a<a+n<=SCRATCH+256 and pc==mm+16:
        source=gp[1]+gp[3]
        if 0x07700000<=source<0x07704000:
            i=(source-0x07700000)//4096;view=rp.leases(z)
            require(e['current_TCB']==M and word(z,slots+i*24+4)==2 and word(z,slots+i*24+20)==1,'Actual mixer FIFO copy held exact slot in_flight1')
            require(view['borrow'] and view['media']==view['callback']==1,'Whole native reader lifetime extends through per-byte copy');rp.copy_counts['Mixer_copy_inflight_bytes']+=n

def supported_compiled_stack_fixture(rp,e,address,after):
    if len(after)!=4 or not 0x07800040<=address<0x07803f90:return False
    services=[x for x in rp.row['declared_service_calls'] if x['before']['ordinal']==e['ordinal'] and x['before']['current_TCB']==S]
    for x in services:
        gp=x['before']['GP16']
        if e['reason']=='opaque allocator output cell fixture' and x['name']=='opaque node/selector allocation':
            if gp[15]==0x38853c and gp[2]==address and 0<gp[0]<4000 and gp[1] in (2,3):
                h=struct.unpack('<I',after)[0]
                return str(h) in rp.row['opaque_handles'] and gp[13]<=address<gp[13]+524
        if e['reason']=='opaque release output fixture' and x['name']=='opaque release':
            return gp[15]==0x3887a2 and gp[0]==address and after==bytes(4) and gp[13]<=address<gp[13]+524
    return False
