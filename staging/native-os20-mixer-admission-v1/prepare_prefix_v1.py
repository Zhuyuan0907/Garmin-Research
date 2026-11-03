#!/usr/bin/env python3
"""FILE-only first msg13 caller prefix; original allocations are not rerun."""
import sys
sys.dont_write_bytecode=True
import gzip,json,hashlib,importlib.util
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OLD=ROOT/'staging/native-os20-mixer-allocator-v1';OUT=BASE/'prefix'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def reconstruct():
 seal=json.loads((OLD/'SEAL-v1.json').read_text());failpath=OLD/'guest-v1/terminal-failure.json.gz';buildpath=OLD/'build-v2/manifest.json'
 for p in(failpath,buildpath,OLD/'file-v1/FILE-proof.json',OLD/'prepare_prefix_v1.py'):assert sha(p)==seal['files'][rel(p)]
 spec=importlib.util.spec_from_file_location('sealed_FILE_prefix_only',OLD/'prepare_prefix_v1.py');pure=importlib.util.module_from_spec(spec);spec.loader.exec_module(pure)
 prefix=pure.reconstruct();fail=json.load(gzip.open(failpath,'rt'));build=json.loads(buildpath.read_text());regions=[dict(z)for z in fail['regions']]
 replay={int(a):bytearray.fromhex(v)for a,v in prefix['whole_ready'].items()}
 for a,fs,ms,fl,data in pure.segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;s=bytearray(b'\xa5'*(end-start));s[a-start:a-start+ms]=bytes(ms);s[a-start:a-start+fs]=data;replay[start]=s
 replay[0x183ff000]=bytearray(b'\xa5'*4096+b'\xcc'*65536+b'\xa5'*4096)
 entry=next(e for e in fail['entries']if e['name']=='original_mixer_message_send');assert entry['ordinal']==3947
 count=0
 for r in fail['CPU_store_journal']:
  if r['ordinal']>=entry['ordinal']:break
  a,n=r['address'],r['size'];z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size']);s=replay[z['start']];off=a-z['start']
  assert s[off:off+n].hex()==r['before_hex'];s[off:off+n]=r['value'].to_bytes(n,'little');count+=1
 state=dict(entry['state']);state['GP16']=list(state['GP16'])
 post=next(c for c in fail['native_returns']if c['name']=='original_POST'and c['return_PC']==0x3b9c26)
 assert post['after']['GP16'][14]==0x3b9c27 and state['GP16'][14]==0x3b9c4f and state['GP16'][15]==0x37bce4
 # One original Thumb BL changes only PC/LR. Recover pre-BL LR from the actual
 # last POST full return; no intervening call exists at3B9C26..3B9C4A.
 state['GP16'][15]=0x3b9c4a;state['GP16'][14]=post['after']['GP16'][14]
 for z in regions:z['after_SHA256']=hashlib.sha256(replay[z['start']]).hexdigest()
 inherited=[]
 for name in('NEW_allocator_supply_then_original_mixer','original_mixer_initializer'):
  row=next(c for c in fail['native_returns']if c['name']==name);row=dict(row);row.pop('after');row['full_ABI_return']=False
  row['inherited_actual_entry_before_new_boundary']=True;inherited.append(row)
 p=dict(all_passed=True,regions=regions,whole_ready={str(a):s.hex()for a,s in replay.items()},boundary=dict(state=state),worker_TCB=0x183140a0,
  inherited_guest_patches=prefix['inherited_guest_patches'],inherited_FIFO_publication=prefix['inherited_FIFO_publication'],
  inherited_open_returns=inherited,CPU_store_preimages_reconstructed=count,entry_ordinal=entry['ordinal'],
  inverse_original_BL=dict(callsite=0x3b9c4a,stock_opcode_hex='c2f74bf8',target=0x37bce4,actual_post_BL_state=entry['state'],
   LR_before_from_actual_original_POST_full_return=post['after']['GP16'][14],BL_only_changes_PC_LR=True),
  original_heap_append_allocations_mixer_creation_prefix_not_rerun=True)
 return p
def main():
 assert not OUT.exists();OUT.mkdir();p=reconstruct();meta={k:v for k,v in p.items()if k not in('whole_ready','inherited_FIFO_publication','inherited_open_returns')}
 meta.update(VM_import_or_creation=False,new_whole_MAIN_or_prefix_file_saved=False,device_IO=False,
  source_sha256={rel(p):sha(p)for p in(Path(__file__),OLD/'SEAL-v1.json',OLD/'guest-v1/terminal-failure.json.gz',OLD/'file-v1/FILE-proof.json',OLD/'prepare_prefix_v1.py')})
 (OUT/'FILE-prefix-proof.json').write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps(dict(all_passed=True,boundary_PC='0x3B9C4A',CPU_store_preimages_reconstructed=p['CPU_store_preimages_reconstructed'],append_allocations_creation_not_rerun=True,VM_import_or_creation=False)),flush=True)
if __name__=='__main__':main()
