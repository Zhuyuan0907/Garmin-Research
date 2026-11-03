import ast
import hashlib
import json
import os
from pathlib import Path

P=Path(__file__).resolve().parent
reads=[]

def get(name):
    q=P/name;s=q.stat();b=q.read_bytes();assert q.stat()==s
    reads.append({'name':name,'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest(),
                  'stat_before_after':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]})
    return b

def put(name,x):
    (P/name).write_text(json.dumps(x,indent=2)+'\n')

journal=json.loads(get('actual-normal-data-read-journal.json'))
old=get('expanded_4k_stock_restore.py')
assert hashlib.sha256(old).hexdigest()=='29f5f11c3f6eb1b0cc2de84840e78c7bd93dd73badac787aaeeede2e294b65bb'
part=get('expanded_restore_extension.py.part')
(P/'executed-preparation-API-source.py.txt').write_bytes(old)
needle="    current=_parse_candidate_prefix(coherent_prefix)\n"
canonical_guard="    require(digest((json.dumps(stock.data,ensure_ascii=False,separators=(',',':'))+'\\n').encode())\n            ==stock.uncompressed_sha256, 'Loaded pinned stock recipe data changed after verified decode')\n"
before_needle="        log.append({'purpose':'fresh_complete_supported_input_hash_before_first_yield',**witness})\n        yield from _restored_blocks(stream,stock,binding,log)\n"
after_text="        verified_stat=tuple(witness['stat_before_after'])\n        log.append({'purpose':'fresh_complete_supported_input_hash_before_first_yield',**witness})\n        require(tuple(identity(stream))==verified_stat, 'Input changed after fresh full SHA before restore')\n        yield from _restored_blocks(stream,stock,binding,log)\n        require(tuple(identity(stream))==verified_stat, 'Input stat differs from fresh full SHA witness at EOF')\n"
new=old.decode();extension=part.decode()
assert new.count(needle)==1 and extension.count(needle)==1
assert new.count(before_needle)==1 and extension.count(before_needle)==1
new=new.replace(needle,canonical_guard+needle).replace(before_needle,after_text)
extension=extension.replace(needle,canonical_guard+needle).replace(before_needle,after_text)
old_ast=ast.parse(old);new_ast=ast.parse(new)
old_funcs={n.name:ast.dump(n,include_attributes=False) for n in old_ast.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
new_funcs={n.name:ast.dump(n,include_attributes=False) for n in new_ast.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
changed=[name for name in old_funcs if old_funcs[name]!=new_funcs[name]]
assert changed==['prepare_restore_binding','restored_stock_blocks']
assert old_funcs.keys()==new_funcs.keys()
(P/'expanded_4k_stock_restore.py').write_text(new)
(P/'expanded_restore_extension.py.part').write_text(extension)
module={'__name__':'final_expanded4K_host_helper'}
exec(compile(new,str(P/'expanded_4k_stock_restore.py'),'exec'),module)
fixture=get('synthetic-host-helper-fixture.bin')
assert len(fixture)==12288
checks=[];helper_reads=0
with (P/'synthetic-host-helper-fixture.bin').open('rb') as f:
    actual=module['logical_read'](f,{'size':12288,'blocks':[2,0,1]},4096,4090,8192)
    assert actual==fixture[12282:12288]+fixture[:4096]+fixture[4096:8186]
    checks.append('unaligned non-monotonic three-block logical mapping');helper_reads+=8192
    for offset,length in ((12287,2),(0,65537),(-1,1)):
        try:module['logical_read'](f,{'size':12288,'blocks':[2,0,1]},4096,offset,length)
        except ValueError:checks.append('bounded/invalid logical request rejected')
        else:raise AssertionError('logical guard')
    module['_hash_file_fresh'](f,12288,hashlib.sha256(fixture).hexdigest());helper_reads+=12288
    checks.append('fresh complete helper hash/stat')
    try:module['_hash_file_fresh'](f,12288,'0'*64)
    except ValueError:checks.append('wrong whole helper hash rejected');helper_reads+=12288
    else:raise AssertionError('whole hash guard')
assert f.closed
fixture_path=P/'synthetic-host-helper-fixture.bin';before=fixture_path.stat()
class StatChange:
    def __init__(self,stream):self.stream=stream;self.changed=False
    def fileno(self):return self.stream.fileno()
    def seek(self,*args):return self.stream.seek(*args)
    def read(self,*args):
        raw=self.stream.read(*args)
        if raw and not self.changed:
            os.utime(fixture_path,ns=(before.st_atime_ns,before.st_mtime_ns+1))
            self.changed=True
        return raw
with fixture_path.open('rb') as f:
    try:module['_hash_file_fresh'](StatChange(f),12288,hashlib.sha256(fixture).hexdigest())
    except ValueError as e:
        assert str(e)=='Input changed during fresh complete SHA256';helper_reads+=12288
        checks.append('changed fixture fstat during fresh hash rejected')
    else:raise AssertionError('changed stat guard')
assert f.closed
# Negative host recipe immutability check, not a production/synthetic IMG.
fake=module['StockRecipe']({},module['RECIPE_SHA'],module['RECIPE_BYTES'],
                          '44ac0746da599dfd67f317bcba70fa891f315576cf0995f8a483ed9ba18401aa',False)
try:module['prepare_restore_binding'](fake,b'',b'',b'')
except ValueError as e:
    assert str(e)=='Loaded pinned stock recipe data changed after verified decode'
    checks.append('forged/changed recipe data cannot bind before metadata')
else:raise AssertionError('recipe data guard')
raw=journal['artifact_raw']+sum(x['bytes'] for x in reads)+helper_reads
decoded=journal['artifact_decoded']+sum(x['bytes'] for x in reads)+helper_reads
assert raw<=3145728 and decoded<=4194304
proof={'final_API_SHA256':hashlib.sha256(new.encode()).hexdigest(),'final_API_bytes':len(new.encode()),
       'executed_preparation_API_SHA256':hashlib.sha256(old).hexdigest(),
       'actual_original_preparation':'2b2f22 EXIT0 with preserved executed source',
       'AST_changed_functions_only':changed,'all_six_executed_fixture_core_functions_unchanged':True,
       'new_recipe_data_identity_guard':'Matches pinned old8K _binding canonical guard; negative fake data tested; no second production recipe decode',
       'new_production_stream_guard':'Fresh hash witness immutable tuple checked before and after entire generator',
       'positive_production_restore_or_recipe_rebind_with_final_source_run':False,
       'final_synthetic_host_checks':checks,'actual_fixture_helper_bytes_read':helper_reads,
       'actual_owned_artifact_reads':reads,'artifact_raw_before_seal':raw,'artifact_decoded_before_seal':decoded,
       'raw_cap':3145728,'decoded_cap':4194304,'new_IMGread':0,'new_recipe_or_original_source_read':0,
       'native_or_guest_run':False,'guards_loosened':False}
put('final-source-guard-review-and-controls.json',proof)
put('preseal-budget.json',{'raw':raw,'decoded':decoded,'raw_cap':3145728,'decoded_cap':4194304,
                         'new_IMGbytes':120,'prior_v1_IMGbytes':90884,'cumulative_IMGbytes':91004,'IMGcap':1048576})
print(json.dumps({'final_API_ready':True,'final_API_SHA256':proof['final_API_SHA256'],
                  'changed_functions':changed,'final_helper_checks':len(checks),
                  'artifact_raw':raw,'artifact_decoded':decoded,'IMGread':0,
                  'production_reconstruction_run':False}))
