#!/usr/bin/env python3
"""FILE-only replay of the new bounded cold profile loop; no VM import/run."""
import sys, json, hashlib, struct
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
AUDIO=0x034e3000; SIZE=0x7000; RECORD=0x034e7f48; IMAGE=0x02d4bb74

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,d):
    with p.open('x') as f: json.dump(d,f,indent=2); f.write('\n')
def main():
    proof_path=BASE/'original-profile-bootstrap-v1-proof.json'
    proof=json.loads(proof_path.read_text()); assert proof['all_passed'] and proof['case_count']==1
    receipt=json.loads((BASE/'guest-v1-terminal-tool-receipt.json').read_text())
    assert receipt['terminal'] and receipt['actual_terminal_result']['exit_code']==0
    assert 'session_id' not in receipt['actual_terminal_result']
    for p,h in proof['source_sha256'].items(): assert sha(ROOT/p)==h,p
    native=NativeImage(); md={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    manifest=json.loads((ROOT/'staging/native-player-warm-probe/strict_marker/manifest.json').read_text())
    binary=(ROOT/manifest['combined_file']).read_bytes()
    def opcode(pc,code,cpsr,store=False):
        raw=bytes.fromhex(code)
        if IMAGE<=pc<IMAGE+len(binary): actual=binary[pc-IMAGE:pc-IMAGE+len(raw)]
        else:
            try: actual=native.read(pc,len(raw))
            except ValueError: actual=native.read(native.runtime_to_load(pc,len(raw)),len(raw))
        assert raw==actual,(hex(pc),code)
        i=next(md[bool(cpsr&32)].disasm(raw,pc,count=1),None)
        assert i is not None and i.size==len(raw)
        if store: assert i.mnemonic.startswith(('str','stm','vstr','vstm')),i.mnemonic
        return i
    bank=bytearray.fromhex(proof['startup_audio_before_hex']); assert bank==bytes(SIZE)
    for r in proof['original_setup_CPU_stores']:
        pc=r['PC']; opcode(pc,r['opcode_hex'],r['CPSR'],True)
        off=r['address']-AUDIO; n=r['size']; assert 0<=off and off+n<=len(bank)
        assert bank[off:off+n].hex()==r['before_hex']
        bank[off:off+n]=r['value'].to_bytes(n,'little')
    assert bank.hex()==proof['initialized_audio_after_hex']
    sentinels=[r for r in proof['original_setup_CPU_stores'] if r['PC']==0x269ed6]
    callbacks=[r for r in proof['original_setup_CPU_stores'] if r['PC']==0x277dbc]
    assert len(sentinels)==len(callbacks)==18
    for channel,(s,c) in enumerate(zip(sentinels,callbacks)):
        record=0x034e6f08+channel*0x208
        assert s['opcode_hex']=='0e54' and s['size']==1 and s['value']==2
        assert s['registers']['r0']==record and s['registers']['r1']==0x15d and s['registers']['r6']==2
        assert s['address']==record+0x15d
        assert c['size']==4 and c['value']==0x277c6b and c['address']==record+0x160
        assert c['registers']['r5']==record+0x140 and c['registers']['r0']==0x277c6b
    assert [r['channel'] for r in proof['full_original_profile_returns']]==list(range(18))
    assert all(r['before_profile']==2 and r['actual_return']==0 and r['actual_profile']==0 and
               r['callback']==0x277c6b and r['LR']==0x269ee9 for r in proof['full_original_profile_returns'])
    def read(a,n): return bytes(bank[a-AUDIO:a-AUDIO+n])
    def u32(a): return struct.unpack('<I',read(a,4))[0]
    m=0x034e5378+8*0x130; pool=0x034e3cf4
    samples=[u32(RECORD+0x88),read(RECORD+0x1f8,1)[0],u32(RECORD+0x160),read(RECORD+0x15d,1)[0],
             u32(RECORD+0x1ac),struct.unpack('<H',read(RECORD+0x1c0,2))[0],read(RECORD+2,1)[0],
             int(read(RECORD+0xf4,68)==bytes(68)),u32(0x034e68d8+8*4),read(m+0x84,1)[0],
             sum(read(pool+576*i+12,1)[0]==0 for i in range(5)),read(RECORD+0x1a8,1)[0]]
    assert samples==proof['actual_native_sample'] and samples[0]==0 and samples[2]==0x277c6b
    assert proof['tag']=='WFFE' and proof['actual_original_getter_UTF16_hex']=='WFFE\0'.encode('utf-16le').hex()
    reads=proof['actual_diagnostic_reads']; assert len(reads)==83
    expected_reads=Counter([(RECORD+0x88,4),(RECORD+0x1f8,1),(RECORD+0x160,4),(RECORD+0x15d,1),
                           (RECORD+0x1ac,4),(RECORD+0x1c0,2),(RECORD+2,1),(0x034e68d8+32,4),(m+0x84,1),
                           (RECORD+0x1a8,1)]+[(RECORD+0xf4+i,1) for i in range(68)]+[(pool+576*i+12,1) for i in range(5)])
    assert Counter((r['address'],r['size']) for r in reads)==expected_reads
    for r in reads:
        opcode(r['PC'],r['opcode_hex'],r['CPSR'])
        assert r['CPSR']&0x80 and r['value_hex']==read(r['address'],r['size']).hex()
    zones=proof['diagnostic_whole_zones']; replay={k:bytearray.fromhex(v['before_hex']) for k,v in zones.items()}
    for r in proof['diagnostic_CPU_write_journal']:
        opcode(r['pc'],r['opcode_hex'],r['cpsr'],True)
        z=zones[r['zone']]; off=r['address']-z['address']; n=r['size']
        assert 0<=off and off+n<=len(replay[r['zone']])
        assert replay[r['zone']][off:off+n].hex()==r['before_hex']
        replay[r['zone']][off:off+n]=r['value'].to_bytes(n,'little')
    assert all(replay[k].hex()==v['after_hex'] for k,v in zones.items())
    assert zones['native_audio_bank']['before_hex']==zones['native_audio_bank']['after_hex']==bank.hex()
    writes=proof['actual_diagnostic_version_stores']; assert len(writes)==5
    assert b''.join(r['value'].to_bytes(r['size'],'little') for r in writes)=='WFFE\0'.encode('utf-16le')
    sources=dict(proof['source_sha256'])
    for p in [Path(__file__),proof_path,BASE/'guest-v1-terminal-tool-receipt.json']:
        sources[str(p.relative_to(ROOT))]=sha(p)
    create(BASE/'ROOT-profile-bootstrap-file-proof-v1.json',dict(all_passed=True,case_count=1,source_sha256=sources,
           original_sentinel_CPU_writes=18,actual_sentinel_GP_address_value_verified=True,
           original_callback_CPU_writes=18,actual_callback_GP_address_value_verified=True,
           selected_original_setup_CPU_stores=len(proof['original_setup_CPU_stores']),
           diagnostic_CPU_stores=len(proof['diagnostic_CPU_write_journal']),native_reads=83,whole_diagnostic_zones=len(zones),
           native_audio_bank_bytes=SIZE,tag='WFFE',condition_constructed=False,
           scope='FILE-only ROOT opcode/preimage/whole-bank replay and two selected writers GP inputs. All other GP effective addresses and nonstore control flow are not reconstructed. Guest runtime full profile returns are preserved observations, not independent control-flow proof.',
           VM_import_or_execution=False,new_independent_agent_review=False,device_IO=False,
           physical_UI_App_music_or_warm_exclusivity=False,updated_utc=datetime.now(timezone.utc).isoformat()))
    print(json.dumps(dict(all_passed=True,case_count=1,original_sentinel_writes=18,original_callback_writes=18,
                         setup_stores=len(proof['original_setup_CPU_stores']),diagnostic_stores=len(proof['diagnostic_CPU_write_journal']),
                         native_reads=83,whole_zones=len(zones),tag='WFFE',VM=False,device_IO=False)))

if __name__=='__main__':main()
