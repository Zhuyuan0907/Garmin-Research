import ast
import builtins
import difflib
import hashlib
import json
from pathlib import Path

P=Path(__file__).resolve().parent
V1=P.parent/'navigation-AP-coherent-expanded4K-restore-binding-preparation-v1'
receipts=[]

def get(q):
    s=q.stat();raw=q.read_bytes();assert q.stat()==s
    receipts.append({'path':str(q.relative_to(Path.cwd())),'bytes':len(raw),
                     'SHA256':hashlib.sha256(raw).hexdigest(),
                     'stat_before_after':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
                     'mode':oct(s.st_mode&0o777),'handle_closed':True})
    return raw

seal=json.loads(get(V1/'sealed-files.json'))
oldraw=get(V1/'old-8K-helper-source-snapshot.py')
assert hashlib.sha256(oldraw).hexdigest()=='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
old=oldraw.decode();tree=ast.parse(old)
source_nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
constant_names={'BLOCK4','BLOCK8','MDR','NAMES','RECIPE_SHA','RECIPE_BYTES','RECIPE_PLAIN_BYTES',
                'STOCK_SHA','STOCK_BYTES','V2_SHA','V2_BYTES','LOWER_STRIDES','STOCK_COUNTS',
                'FUTURE_COUNTS','WIDTHS','FLAGS'}
parts=['#!/usr/bin/env python3\n"""Strict pure-host coherent expanded4K -> exact stock4K restore preparation.\nProduction reconstruction requires a fresh full actual input SHA before yielding.\nNo generic IMG profile, output writer, installer, device or native execution.\n"""\n',
       'from dataclasses import dataclass\nimport gzip\nimport hashlib\nimport io\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport struct\n']
for n in tree.body:
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in constant_names for t in n.targets):
        parts.append(ast.get_source_segment(old,n))
for name in ('require','integer','digest','digest_field','canonical','identity','_read','logical_read','StockRecipe'):
    text=ast.get_source_segment(old,source_nodes[name])
    if name=='StockRecipe':text='@dataclass(frozen=True)\n'+text
    parts.append(text)
text=ast.get_source_segment(old,source_nodes['parse_layout'])
text=text.replace('def parse_layout(', 'def _parse_stock_layout(',1)
text=text.replace("require(block_bytes in (BLOCK4,BLOCK8),'Unsupported allocation geometry')",
                  "require(block_bytes==BLOCK4,'Only original stock4K recipe metadata supported')",1)
parts.append(text)
text=ast.get_source_segment(old,source_nodes['_decode_recipe'])
text=text.replace('def _decode_recipe(raw, fixture):',
                  "def _decode_recipe(raw, fixture):\n    require(fixture is False, 'Production recipe only; no synthetic full-image API')",1)
text=text.replace('parsed=parse_layout(', 'parsed=_parse_stock_layout(',1)
parts.append(text)
parts.append(ast.get_source_segment(old,source_nodes['load_stock_recipe']))
extension=get(P/'expanded_restore_extension.py.part').decode()
parts.append(extension)
text=ast.get_source_segment(old,source_nodes['_restored_blocks'])
assert text.count('BLOCK8')==2
text=text.replace('BLOCK8','BLOCK4')
parts.append(text)
new='\n\n'.join(parts)+'\n'
ast.parse(new)
# Import/execute only NEW normal-data helper definitions, never old reviewed code.
module={'__name__':'expanded4k_preflight'}
exec(compile(new,str(P/'expanded_4k_stock_restore.py'),'exec'),module)
needed=('load_stock_recipe','prepare_restore_binding','load_restore_binding','logical_read',
        '_parse_candidate_prefix','_decode_directory','_hash_file_fresh','_restored_blocks',
        'restored_stock_blocks','reconstructed_stock_hash')
assert all(callable(module[n]) for n in needed)
assert module['EXPECTED_TABLES'][0][1]+module['EXPECTED_TABLES'][0][2]==module['DIRECTORY_START']
assert module['DIRECTORY_START']+120==module['MDR_BYTES']
assert module['CANDIDATE_BYTES']==37436*4096==299488*512
assert module['RANGE_OFFSETS']==[None,772,4195100,21728654,70204713,None,149214669,None]
(P/'expanded_4k_stock_restore.py').write_text(new)
diff=''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                               fromfile='frozen/native_8k_stock_restore.py',
                               tofile='NEW/expanded_4k_stock_restore.py'))
(P/'source-diff-against-old-8K.patch').write_text(diff)
proof={'scope':P.name,'old_helper_unchanged_SHA256':hashlib.sha256(oldraw).hexdigest(),
       'actual_source_reads':receipts,'artifact_raw':sum(x['bytes'] for x in receipts),
       'artifact_decoded':sum(x['bytes'] for x in receipts),
       'old_reviewed_module_import_or_execution':False,
       'new_pure_host_definition_preflight':True,'globals_prevalidated_before_IMGread':list(needed),
       'directory_descriptor_offset':600,'old_stock_parser_guard_not_relaxed':True,
       'copy_changes':{'parse_layout':'private original-stock-only _parse_stock_layout; 4K32768 limit retained',
                       '_decode_recipe':'production only; fixed old recipe identity retained',
                       '_restored_blocks':'two read geometry operands8K→4K in NEW copy only; stock block/EOF hash unchanged'},
       'new_API_bytes':len(new.encode()),'new_API_SHA256':hashlib.sha256(new.encode()).hexdigest(),
       'IMGbytes':0,'production_reconstruction_run':False}
(P/'source-assembly-and-preflight-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps({'new_host_API_assembled':True,'globals_prevalidated':True,'new_API_bytes':len(new.encode()),
                  'new_API_SHA256':hashlib.sha256(new.encode()).hexdigest(),'artifact_raw':proof['artifact_raw'],
                  'artifact_decoded':proof['artifact_decoded'],'IMGread':0}))
