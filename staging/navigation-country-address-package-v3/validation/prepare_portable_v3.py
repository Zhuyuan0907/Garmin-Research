#!/usr/bin/env python3
"""Prepare only small portablev3 files; never link/open/change any IMG."""
import ast
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parents[1]
V2=ROOT/'staging/navigation-country-address-package-v2'
API=ROOT/'staging/navigation-native-8k-layout-restore-api-v1'
ACTUAL=ROOT/'staging/navigation-country-native-lane-restore-v3'
PINS={'manifest.json':'71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7',
      'install_native_house_supplement.py':'663a40fb404e44598574035b0ea5d651342720864a41973459ef87f5affe5f5d',
      'device_support.py':'8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411'}
API_SHA='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
RECIPE_SHA='6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'
BINDING_SHA='0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89'
CANDIDATE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def need(ok,message):
    if not ok:raise ValueError(message)


def main():
    receipts=[]
    def read(path,digest,maxbytes):
        before=path.stat();need(before.st_size<=maxbytes,'Small source bound')
        raw=path.read_bytes();need(sha(raw)==digest and path.stat()==before,'Pinned source changed')
        receipts.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':digest,
                         'stat_before':[before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns],
                         'source_stat_unchanged':True})
        return raw
    need(not(OUT/'manifest.json').exists(),'Refuse overwrite newpackage manifest')
    m=json.loads(read(V2/'manifest.json',PINS['manifest.json'],65536))
    old=read(V2/'install_native_house_supplement.py',PINS['install_native_house_supplement.py'],65536).decode()
    support=read(V2/'device_support.py',PINS['device_support.py'],65536)
    api=read(API/'native_8k_stock_restore.py',API_SHA,65536)
    recipe=read(ROOT/'staging/navigation-country-layout-restore-v2/restore-layout.json.gz',RECIPE_SHA,1024*1024)
    binding=read(ACTUAL/'actual-stock-restore-binding.json',BINDING_SHA,1024*1024)
    rootproof_raw=read(ROOT/'staging/navigation-country-native-lane-candidate-v3/proof.json',
        'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0',2*1024*1024)
    rootproof=json.loads(rootproof_raw)
    need(rootproof['selected_L3_classification']=={'already_selected_v2':6366,'previously_stock_range':1284},
         'Actual sealed root street-union classification')
    need(len(recipe)==879499 and len(binding)==292144,'Exact compact production files')
    for name in ('candidate','roadmap','validation'):(OUT/name).mkdir(exist_ok=True)
    (OUT/'device_support.py').write_bytes(support)
    (OUT/'native_8k_stock_restore.py').write_bytes(api)
    (OUT/'restore-layout.json.gz').write_bytes(recipe)
    (OUT/'actual-stock-restore-binding.json').write_bytes(binding)
    (OUT/'validation/candidate-readback-v3.json').write_bytes(rootproof_raw)
    predecessors=m['target']['accepted_predecessors']+[{'state':'previous_country_v2_candidate','bytes':128356352,
                                                     'sha256':'925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'}]
    m['schema']='garmin-native-existing-street-house-supplement/v3'
    m['scope']='保留v2的130,637筆門牌，再依原巷弄階層新增58,233筆整數門牌，累計188,870筆；非全台完整更新'
    m['target'].update(bytes=153346048,candidate_sha256=CANDIDATE_SHA,accepted_predecessors=predecessors)
    m['rollback']={'schema':'garmin-native-8k-stock-layout-restore/v1',
        'stock_recipe':{'schema':'garmin-native-layout-restore/v1','bundle_path':'restore-layout.json.gz',
                        'bytes':879499,'sha256':RECIPE_SHA},
        'actual_binding':{'schema':'garmin-native-8k-stock-layout-restore/v1','bundle_path':'actual-stock-restore-binding.json',
                         'bytes':292144,'sha256':BINDING_SHA}}
    m['portable_helpers']={'native_8k_stock_restore.py':{'bytes':len(api),'sha256':API_SHA},
                           'device_support.py':{'bytes':len(support),'sha256':PINS['device_support.py']}}
    m['street_union_provenance']={'bundle_proof_path':'validation/candidate-readback-v3.json',
        'proof_sha256':sha(rootproof_raw),'original_v2_street_count':18823,'previously_stock_range':1284,
        'already_selected_v2':6366,'v3_changed_roots':7650,'cumulative_union':20107}
    m.update(new_houses=188870,new_lane_integer_houses=58233,prior_v2_new_integer_houses_retained=130637,
             updated_existing_streets=20107,updated_existing_streets_scope='cumulative_original_native_street_ID_union',
             prior_v2_updated_existing_streets=18823,v3_changed_existing_street_roots=7650,
             newly_affected_street_roots=1284,v3_roots_already_in_prior_v2=6366,v3_changed_lower_parents=22216,
             new_houses_by_leaf_level={'4':88094,'5':85088,'6':15688},
             allocation_block_bytes=8192,final_lower_table_counts={'4':4896236,'5':3077845,'6':2062771},
             header_checksum_rule_known=False,actual_8K_device_acceptance_verified=False,
             actual_stock_rollback_reconstruction_verified=True)
    m['limits']=[
        '只新增來源坐標與原索引路徑可精確核對的整數門牌；新街道、之號及未解／衝突來源仍未完成。',
        '累計20,107條既有街道：v2的18,823加本次新受影響1,284；其餘6,366個v3街道根已在v2範圍。',
        '原廠舊門牌坐標、巷弄語義及相對順序保留；不是所有2016地址都已刷新到2026。',
        '候選使用明確8K配置；checksum規則與實機接受性未知，有限原生CPU不等完整搜尋UI／路線結果。',
        'Search v2道路圖需已在此機安裝；包內提供相同版本，不更新道路、韌體或原JAI。',
        'rollback使用原廠compactrecipe加v3actualbinding；串流核對精確原廠4K雜湊，不建立第二份完整備份。']
    raw=(json.dumps(m,ensure_ascii=False,indent=2)+'\n').encode();(OUT/'manifest.json').write_bytes(raw)
    validate='''def validate_recipe(recipe, source, target):
    """Verify exact portable stock recipe/binding and complete original hash."""
    need(isinstance(recipe, dict) and set(recipe) == {'stock', 'binding'}, 'Unsupported portable8K restore objects')
    stock, binding = recipe['stock'], recipe['binding']
    need(type(stock) is restore.StockRecipe and stock.fixture is False and isinstance(binding, dict), 'Production restore requires the pinned stock recipe and actual binding')
    need(target.get('bytes') == CANDIDATE_BYTES and target.get('candidate_sha256') == CANDIDATE_SHA and
         target.get('original_bytes') == ORIGINAL_BYTES and target.get('original_sha256') == ORIGINAL_SHA,
         'Portable8K target image identity mismatch')
    try:
        layout = binding['candidate_layout']
        need(layout['candidate_bytes'] == target['bytes'] and layout['candidate_sha256'] == target['candidate_sha256'], 'Actual8K binding candidate identity mismatch')
        need(binding == restore.prepare_restore_binding(stock, layout), 'Portable8K restore binding changed')
        with open_regular(source) as stream:
            reconstructed = restore.reconstructed_stock_hash(stream, stock, binding)
    except (ValueError, KeyError, TypeError, OSError, OverflowError):
        raise Refusal('Portable8K binding cannot reconstruct the exact stock image') from None
    need(reconstructed == target['original_sha256'], 'Portable8K exact stock full hash mismatch')
    return recipe
'''
    tree=ast.parse(old);nodes={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
    old_load=old.splitlines(True)[nodes['load_manifest'].lineno-1:nodes['load_manifest'].end_lineno]
    load=''.join(old_load)
    load=load.replace("    need(rb == {'schema': 'garmin-native-layout-restore/v1', 'bundle_path': ROLLBACK, 'bytes': RECIPE_BYTES, 'sha256': RECIPE_SHA}, 'Unexpected compact rollback identity')", "    need(rb == EXPECTED_ROLLBACK, 'Unexpected compactstock recipe/actual8K binding identities')\n    need(m.get('portable_helpers') == EXPECTED_HELPERS, 'Unexpected portable helper identities')\n    need(Path(restore.__file__).resolve() == safe_path(bundle, RESTORE_HELPER).resolve() and Path(support.__file__).resolve() == safe_path(bundle, 'device_support.py').resolve(), 'Portable helper modules are outside this exact bundle')\n    verify_file(safe_path(bundle, RESTORE_HELPER), HELPER_BYTES, HELPER_SHA, 'Pinned portable8K stock restore helper')\n    verify_file(safe_path(bundle, 'device_support.py'), SUPPORT_BYTES, SUPPORT_SHA, 'Unchanged device protection helper')")
    old_tail=load[load.index('    source = safe_path(bundle, CANDIDATE)'):]
    new_tail='''    recipe_path = safe_path(bundle, ROLLBACK)
    binding_path = safe_path(bundle, RESTORE_BINDING)
    verify_file(recipe_path, RECIPE_BYTES, RECIPE_SHA, 'Pinned compactstock recipe')
    verify_file(binding_path, BINDING_BYTES, BINDING_SHA, 'Pinned actual8K stock restore binding')
    try:
        stock = restore.load_stock_recipe(recipe_path)
        binding = restore.load_restore_binding(binding_path, BINDING_SHA)
        need(binding == restore.prepare_restore_binding(stock, binding['candidate_layout']), 'Actual8K binding does not match portable pinned stock recipe')
        recipe = {'stock': stock, 'binding': binding}
    except (ValueError, KeyError, TypeError, OSError, UnicodeError):
        raise Refusal('Malformed portable compactstock recipe or actual8K binding') from None
    source = safe_path(bundle, CANDIDATE)
    verify_file(source, CANDIDATE_BYTES, CANDIDATE_SHA, 'Bundled country house supplement candidate')
    validate_recipe(recipe, source, t)
    return m, source, recipe, MANIFEST_SHA
'''
    load=load.replace(old_tail,new_tail)
    image='''def image_blocks(source, recipe, mode):
    with open_regular(source) as stream:
        if mode == 'rollback':
            yield from restore.restored_stock_blocks(stream, recipe['stock'], recipe['binding'])
        else:
            for block in iter(lambda: stream.read(CHUNK), b''):
                yield block
'''
    functions={'validate_recipe':validate,'load_manifest':load,'image_blocks':image}
    lines=old.splitlines(True)
    for name in sorted(functions,key=lambda name:nodes[name].lineno,reverse=True):
        node=nodes[name];lines[node.lineno-1:node.end_lineno]=[functions[name]]
    text=''.join(lines).replace('import native_address_layout_restore_v1 as restore','import native_8k_stock_restore as restore')
    constants={'SCHEMA':m['schema'],'CANDIDATE_BYTES':153346048,'CANDIDATE_SHA':CANDIDATE_SHA,
               'MANIFEST_BYTES':len(raw),'MANIFEST_SHA':sha(raw),'EXPECTED_PREDECESSORS':predecessors}
    for key,value in constants.items():
        text,count=re.subn('^'+key+r' = .*$',key+' = '+repr(value),text,flags=re.M);need(count==1,'One constant replacement '+key)
    extra={'RESTORE_BINDING':'actual-stock-restore-binding.json','BINDING_BYTES':len(binding),'BINDING_SHA':BINDING_SHA,
           'RESTORE_HELPER':'native_8k_stock_restore.py','HELPER_BYTES':len(api),'HELPER_SHA':API_SHA,
           'SUPPORT_BYTES':len(support),'SUPPORT_SHA':PINS['device_support.py'],
           'EXPECTED_ROLLBACK':m['rollback'],'EXPECTED_HELPERS':m['portable_helpers']}
    text=text.replace('\n\ndef validate_recipe','\n'+''.join(k+' = '+repr(v)+'\n' for k,v in extra.items())+'\n\ndef validate_recipe',1)
    new=ast.parse(text);newnodes={x.name:x for x in new.body if isinstance(x,ast.FunctionDef)}
    identical={name:ast.dump(node,include_attributes=False)==ast.dump(newnodes[name],include_attributes=False)
               for name,node in nodes.items() if name not in functions}
    need(all(identical.values()),'All unchanged function ASTs identical')
    (OUT/'install_native_house_supplement.py').write_text(text)
    result={'schema':'portable-v3-small-file-preparation/v1','created_utc':datetime.now(timezone.utc).isoformat(),
            'all_assigned_checks_passed':True,'input_pins':receipts,'manifest_bytes':len(raw),'manifest_sha256':sha(raw),
            'installer_sha256':sha(text.encode()),'unchanged_function_AST_identity':identical,
            'only_changed_functions':list(functions),'device_support_byte_exact':True,'restore_helper_byte_exact':True,
            'recipe_and_binding_exact_small_copies':True,'candidate_or_road_IMG_opened_linked_chmodded':False,
            'actual_production_load_manifest_tested':False,'device_IO':False}
    (OUT/'validation/binding-preparation-proof.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'manifest_bytes':len(raw),'manifest_sha256':sha(raw),
                      'installer_sha256':sha(text.encode()),'unchanged_function_count':len(identical),
                      'candidate_IMG_touched':False}))


if __name__=='__main__':main()
