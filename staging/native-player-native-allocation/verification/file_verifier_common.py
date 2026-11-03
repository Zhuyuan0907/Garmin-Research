"""File-only shared checks. No emulator/VM imported or guest execution."""
from functools import lru_cache
from pathlib import Path
import hashlib,json,re,sys
ROOT=Path(__file__).resolve().parents[3]
BASE='staging/native-player-native-allocation/'
RUNTIME=BASE+'runtime/'
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'scripts'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from analyze_native_sections import NativeImage

def require(value,message):
    if not value:raise AssertionError(message)
def read(path):return json.loads((ROOT/path).read_text())
@lru_cache(None)
def sha(path):
    h=hashlib.sha256()
    with (ROOT/path).open('rb')as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()
def dump(path,value):
    with(ROOT/path).open('x')as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def seal_inputs():
    meta=read(RUNTIME+'terminal-metadata.json');probe=read(meta['probe'])
    require(meta['authoritative_terminal_result_received_from_exec']is True,'Need sealed authoritative terminal metadata')
    for key in ('runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix','terminal_tool_receipt'):
        require(sha(meta[key])==meta[key+'_sha256'],'Sealed runtime artifact identity '+key)
    receipt=read(meta['terminal_tool_receipt']);actual=receipt['tool_result']
    require('session_id'not in actual and actual['exit_code']==meta['terminal_exit_code']
      and actual['chunk_id']==meta['actual_exec_chunk'] and receipt['observed_session_id']==meta['session_id'],
      'Actual final tool receipt differs from terminal metadata')
    require(meta['session_id']==87914 and meta['actual_exec_chunk']=='4ab59e'and meta['terminal_exit_code']==1,
      'This verifier is for immutable public-heap V1 session87914 only')
    require(meta['GUI_observer_sha256']=='f072a33b6505e21aa515a02d3e668f458d5842b6c4082debdd56ac60f1c181e8',
      'V1 observed helper identity')
    require(meta['completed']==probe['completed']==False and probe['body_full_guards_passed']==False,
      'V1 must retain failed/incomplete whole-body status')
    for p,h in meta['source_sha256'].items():require(sha(p)==h,'Immutable protected runtime source '+p)
    prefix=read(meta['cold_prefix']);require(prefix['cold_prefix_full_guards_passed']and probe['cold_prefix_full_guards_passed'],
      'Actual completed cold prefix is required')
    return meta,probe,prefix

class Replay:
    def __init__(self):
        self.stock=NativeImage();self.md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
        self.decoded={};self.counts={'original_MAIN':0,'frozen_ARM_companion':0,'declared_initial_ready':0}
        v=read('staging/controller-gir-prep-stock-v2/verification.json');self.companion_path=v['flat_binary']
        self.companion=(ROOT/self.companion_path).read_bytes()
    def store(self,e):
        opcode=bytes.fromhex(e.get('opcode_hex',e.get('original_opcode_hex','')));pc=int(e['PC'],16)
        require(opcode and isinstance(e['Thumb'],bool),'CPU writer opcode/mode absent')
        if e.get('writer_kind')=='frozen_ARM_companion':
            off=pc-0xEA10000;require(off>=0 and self.companion[off:off+len(opcode)]==opcode,'Frozen compiled original store bytes')
            self.counts['frozen_ARM_companion']+=1
        else:
            load=int(e['load_PC'],16)if 'load_PC'in e else self.stock.runtime_to_load(pc,len(opcode))if any(r['runtime_start']<=pc and pc+len(opcode)<=r['runtime_end']for r in self.stock.copies)else pc
            require(self.stock.read(load,len(opcode))==opcode,'Exact original MAIN store '+hex(pc));self.counts['original_MAIN']+=1
        key=pc,e['Thumb'],opcode
        if key not in self.decoded:
            ins=list(self.md[e['Thumb']].disasm(opcode,pc,count=1))
            require(len(ins)==1 and ins[0].size==len(opcode)and ins[0].mnemonic.startswith(('str','stm','swp','push','vstr','vstm')),
              'Original writer decode/family '+hex(pc))
            self.decoded[key]=ins[0].mnemonic+' '+ins[0].op_str
        text=e.get('original_instruction',e.get('instruction',''))
        require(re.sub(r'\s+','',self.decoded[key])==re.sub(r'\s+','',text),'Original writer text differs '+hex(pc))
    def replay(self,zone,before_hex=None,after_sha256=None,ready_fixture=False,require_actual=True):
        start=int(zone['start'],16);raw=bytearray.fromhex(before_hex if before_hex is not None else zone['before_hex'])
        require(len(raw)==zone['bytes'],'Whole-zone initial before length')
        if 'before_sha256'in zone:require(hashlib.sha256(raw).hexdigest()==zone['before_sha256'],'Whole-zone before SHA')
        for e in zone['stores']:
            n=e['size'];off=int(e['address'],16)-start
            require(n in (1,2,4,8)and 0<=off and off+n<=len(raw)and raw[off:off+n].hex()==e['before_hex'],
              'Chronological CPU beforeimage/span mismatch')
            if e.get('kind')=='declared_initial_ready_membership_input':
                require(ready_fixture and(int(e['address'],16),n,e['value'])in [(0x9503F90,4,0x9508F90),(0x9503FA6,1,1)],
                  'Unexpected explicit initial ready-membership input');self.counts['declared_initial_ready']+=1
            else:self.store(e)
            raw[off:off+n]=e['value'].to_bytes(n,'little')
        actual=after_sha256 if after_sha256 is not None else zone.get('after_sha256')
        digest=hashlib.sha256(raw).hexdigest()
        if require_actual:require(actual is not None and digest==actual,'No/mismatching actual final whole-zone SHA '+hex(start))
        elif actual is not None:require(actual==digest,'Recorded optional actual final SHA differs')
        return bytes(raw),dict(start=hex(start),bytes=len(raw),CPU_events=len(zone['stores']),replayed_sha256=digest,
          recorded_actual_after_SHA_available=actual is not None,equals_actual_after_SHA=actual is not None and digest==actual)

def sources(meta,*paths):
    paths=list(paths)+[BASE+'verification/file_verifier_common.py',RUNTIME+'terminal-metadata.json',meta['probe'],meta['cold_prefix'],
      meta['terminal_tool_receipt'],'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin']
    return {p:sha(p)for p in dict.fromkeys(paths)}

def fields(meta):
    return dict(actual_guest_session=meta['session_id'],actual_guest_terminal_chunk=meta['actual_exec_chunk'],
      actual_guest_terminal_exit_code=meta['terminal_exit_code'],actual_guest_terminal_error=meta['error'],
      guest_execution_by_verifier=False,VM_import_or_instantiation=False,device_io=False,sounds_emitted=False,
      full_Dispatcher_body_or_foreground_or_physical_App_verified=False)
