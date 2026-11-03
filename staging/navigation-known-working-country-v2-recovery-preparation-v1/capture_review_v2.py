#!/usr/bin/env python3
"""Read only explicitly enumerated small artifacts, never any IMG or ZIP."""
from pathlib import Path
import ast
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
OLD = 'staging/navigation-country-address-package-v2/'
NEW = 'staging/navigation-AP-coherent8K-installer-integration-preparation-v1/'
PATHS = [OLD + n for n in ('install_native_house_supplement.py', 'device_support.py',
    'native_address_layout_restore_v1.py', 'manifest.json', 'SHA256SUMS.json',
    'restore-layout.json.gz')] + [NEW + n for n in ('install_native_house_supplement.py',
    'manifest.json', 'sealed-files.json')]

def need(ok, text):
    if not ok:
        raise ValueError(text)

def field(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
            s.st_mode & 0o777, s.st_nlink]

def main():
    data = {}
    rows = []
    for rel in PATHS:
        p = ROOT / rel
        s0 = p.lstat()
        need(stat.S_ISREG(s0.st_mode), 'Regular small file required')
        raw = p.read_bytes()
        s1 = p.lstat()
        need(field(s0) == field(s1), 'Small file stat changed')
        rows.append({'path': rel, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'stat_before': field(s0), 'stat_after': field(s1)})
        data[rel] = raw
    receipt = {'schema': 'corrected-bounded-small-read/v1', 'rows': rows,
        'raw_bytes': sum(r['bytes'] for r in rows), 'preceding_reads_bytes': 190665 + 985410,
        'aggregate_raw_bytes': 190665 + 985410 + sum(r['bytes'] for r in rows),
        'raw_budget': 3 * 1024 * 1024, 'decoded_recipe_bytes': 0,
        'recipe_gzip_hashed_without_decompression': True, 'IMG_operations': 0}
    need(receipt['aggregate_raw_bytes'] <= receipt['raw_budget'], 'Small input budget')
    (OUT / 'corrected-input-read-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    items = json.loads(data[OLD + 'SHA256SUMS.json'])
    need(type(items) is list, 'Pinned bundle catalog must be a list')
    catalog = {e['path']: e for e in items}
    need(len(catalog) == len(items), 'Duplicate catalog member')
    seal = json.loads(data[NEW + 'sealed-files.json'])
    for r in rows:
        if r['path'].startswith(OLD):
            entry = catalog[Path(r['path']).name]
        elif r['path'].endswith('/sealed-files.json'):
            need(r['sha256'] == 'dc59af5ef52cee72d7a7b936f276e895ceaf28c280428beef73b86b39a125008', 'Owner seal pin')
            continue
        else:
            matches = [e for e in seal['files'] if Path(e['path']).name == Path(r['path']).name]
            need(len(matches) == 1, 'Unique owner seal member')
            entry = matches[0]
        need(entry['bytes'] == r['bytes'] and entry['sha256'] == r['sha256'], 'Closed source/member pin')
    old = json.loads(data[OLD + 'manifest.json'])
    new = json.loads(data[NEW + 'manifest.json'])
    public = []
    for rel, raw in data.items():
        if not rel.endswith('.py'):
            continue
        src = raw.decode()
        tree = ast.parse(src)
        funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        imports = [a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names]
        imports += [n.module for n in tree.body if isinstance(n, ast.ImportFrom)]
        assignments = [ast.unparse(n) for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))]
        public.append({'path': rel, 'imports': imports,
            'workspace_ROOT_assignment': any(s.split('=', 1)[0].strip() == 'ROOT' for s in assignments),
            'main_source': ast.get_source_segment(src, funcs['main']) if 'main' in funcs else None,
            'function_lines': {k: [v.lineno, v.end_lineno] for k, v in funcs.items()
                if k in ('main', 'execute', 'load_manifest', 'image_state', 'device_preflight', 'transaction')},
            'load_manifest_first_statements': [ast.unparse(s) for s in funcs['load_manifest'].body[:9]]
                if 'load_manifest' in funcs else []})
    output = {'schema': 'recovery-static-interface-review/v1', 'sources': public,
        'old_runtime_checked_against_exact_bundle_catalog': True,
        'new_sources_checked_against_final_owner_seal': True,
        'new_integration_preparation_only': new['integration_preparation_only'],
        'old_stock_predecessor_present': any(e['state'] == 'original' and e['sha256'] == old['target']['original_sha256']
            for e in old['target']['accepted_predecessors']),
        'old_candidate_not_coherent8K': old['target']['candidate_sha256'] != new['target']['candidate_sha256'],
        'no_producer_import_or_execution': True}
    (OUT / 'static-source-interface-review.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'checks_passed': True, 'capture_bytes': receipt['raw_bytes'],
        'aggregate_bytes': receipt['aggregate_raw_bytes'], 'old_catalog_members': len(items),
        'interfaces': public}, ensure_ascii=False))

if __name__ == '__main__':
    main()
