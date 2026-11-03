#!/usr/bin/env python3
"""Pinned pure host-codec/stock-reader access. No old main or CPU execution."""
from pathlib import Path
import ast
import hashlib
import json
import struct

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
PINS={
 'staging/navigation-stock-address-schema-v1/analysis-file-seal.json':'c6c3ac34c15f2df3a4133b274300190c3bf217c444d29da2ddf4ea3ab84e0ad5',
 'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json':'8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d',
 'staging/navigation-stock-fts-codec-v1/stock-fts-codec-file-seal-v1.json':'1423e3d5067c09fef3d2bd96d71ca8c07418249d679df6ef0525bd9ffc0383fd',
 'staging/navigation-stock-fts-codec-v1/analyze_stock_fts_codec_v1.py':'1e77a8dd44103c366daa6f22a631d06e09e58ad0f19495a4e088c21b65b6a92e',
 'staging/navigation-stock-fts-native-codec-v1/native-fts-codec-file-seal-v1.json':'4b7a0c73521d40a4a271fac8e7fb9066d03da052edd2fd28bdb6be8e13c791c7',
 'staging/navigation-stock-fts-native-codec-v1/native-fts-token-codec-proof-v2.json':'a9318b8bdcbe1c7faf566159b6dcc4c54bf87f8c8be09d976b13ef55830a05da',
 'staging/navigation-firmware-address-v1/analysis-file-seal.json':'d37bd8c4abaf22c2e3afce09fc794907029512a71327fac7e48f0732e0c1d499',
 'staging/navigation-firmware-address-v1/address-dispatch-evidence.json':'ec01bf743cf465c3d6008542e143e5b07eb4208845b2fbf7a3c0f6242a55d92a',
 'staging/navigation-native-deeper-address-plan-v1/inspect_deeper_address_paths.py':'1348bcb2f0191bd1fa5b32ca446ee15b084e76dd7ed3ea33c31b5351b2d021ec',
}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def load(relative,inputs):
    path=ROOT/relative;before=stat(path);need(before[2]<=300000,'Small sealed local input');raw=path.read_bytes()
    need(sha(raw)==PINS[relative]and stat(path)==before,'Fixed source proof/hash/stat')
    inputs.append(dict(path=relative,bytes=len(raw),sha256=sha(raw),stat_before=before,stat_after=stat(path)))
    return raw


def codec(inputs):
    for name in ['staging/navigation-stock-fts-codec-v1/stock-fts-codec-file-seal-v1.json','staging/navigation-stock-fts-native-codec-v1/native-fts-codec-file-seal-v1.json']:load(name,inputs)
    relative='staging/navigation-stock-fts-codec-v1/analyze_stock_fts_codec_v1.py';tree=ast.parse(load(relative,inputs))
    names={'xor_swap','schedule','transform','encode_bytes','encode_text','decode_text'}
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names];need(len(functions)==6,'Only six sealed pure codec definitions')
    ns={'need':need};exec(compile(ast.Module(body=functions,type_ignores=[]),relative,'exec'),ns)
    proof=json.loads(load('staging/navigation-stock-fts-native-codec-v1/native-fts-token-codec-proof-v2.json',inputs));need(proof['all_passed'],'Sealed original instruction codec proof')
    context=bytes.fromhex(proof['final_context_hex']);need(len(context)==258 and context[-2:]==bytes(2)and sha(context)==proof['scheduled_context_sha256'],'Sealed native-generated shared context')
    scheduled=list(context[:256]);return(lambda text:ns['encode_text'](text,scheduled),lambda token:ns['decode_text'](token,scheduled)[0])


def stock_reader(inputs):
    relative='staging/navigation-native-deeper-address-plan-v1/inspect_deeper_address_paths.py';tree=ast.parse(load(relative,inputs))
    names={'need','sha','StockImage','derive_tables','read_record'}
    nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
    profiles=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='EXPECTED_PROFILES'for t in n.targets)]
    need(len(nodes)==5 and len(profiles)==1,'Only sealed original reader definitions')
    ns={'struct':struct,'hashlib':hashlib};exec(compile(ast.Module(body=profiles+nodes,type_ignores=[]),relative,'exec'),ns);return ns


def save(name,row):
    path=HERE/name
    with path.open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n')
    return dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=sha(path.read_bytes()))
