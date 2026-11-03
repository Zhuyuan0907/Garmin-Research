#!/usr/bin/env python3
"""NEW FILE-only sealer. Does not execute or import the terminal analyzer."""
import ast
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ledger_path=OUT/'native-receiver-static-source-output-ledger.json'
    seal_path=OUT/'native-receiver-static-seal.json'
    if ledger_path.exists() or seal_path.exists():
        raise RuntimeError('Immutable terminal outputs exist; use NEW source/version')
    proof_path=OUT/'native-receiver-to-compiled-ingress-contract.json'
    fragments_path=OUT/'native-receiver-exact-source-fragments.json'
    receipt_path=OUT/'native-receiver-static-terminal-tool-receipt.json'
    proof=json.loads(proof_path.read_text())
    fragments=json.loads(fragments_path.read_text())
    receipt=json.loads(receipt_path.read_text())
    analyzer=OUT/'analyze_native_receiver_ingress_contract_v1.py'
    assert sha(proof_path)=='d7fff2d5f3f75c570adad92976c12793831697108537ff31afe16de285b215a9'
    assert sha(fragments_path)=='2835751098165fff0934a33375b324805f4380ad3f8aa3956437bc74a3683a40'
    assert sha(analyzer)=='67deedee8f5e14487c8de0f22a74f97c2301cc642a3e7c92208e922593596523'
    assert receipt['terminal'] and receipt['exit_code']==0 and receipt['chunk_id']=='4f2edd'
    assert receipt['source_sha256']==sha(analyzer)
    actual=json.loads(receipt['output'])
    assert actual['source_sha256']==sha(analyzer) and actual['all_passed']
    for path,digest in actual['output_sha256'].items():
        assert sha(ROOT/path)==digest
    assert proof['all_passed'] and all(c['passed'] for c in proof['checks'])
    assert proof['HWID']==1352 and proof['software']=='8.00'
    assert proof['guest_executed'] is False and proof['device_IO'] is False
    assert proof['canonical_writes'] is False and proof['goal_complete'] is False
    assert proof['application_SEP_publication']['recovered_original_registration_API'] is False
    assert proof['application_SEP_publication']['host_function_pointer_seeding_is_registration'] is False
    assert proof['callback_lifetime']['clearing_SEP_callback_is_quiescence'] is False
    assert proof['generation_and_remoteStart']['state8_or_event17_alone_opens_remoteStart'] is False
    assert proof['cold_warm_and_channel8']['cold_inputs_are_warm_module_boot'] is False
    assert proof['native_phone_App_speaker_verified'] is False
    assert len(fragments['fragments'])==actual['bounded_functions']==15
    assert sum(f['reachable_instruction_count'] for f in fragments['fragments'])==actual['original_instructions']==1314
    for source in [analyzer,Path(__file__)]:
        tree=ast.parse(source.read_text())
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.extend(n.name for n in node.names)
            if isinstance(node,ast.ImportFrom):imports.append(node.module or '')
        assert not any(any(x in m.lower() for x in ['unicorn','emulate','probe_native','subprocess']) for m in imports)
    source_hashes=dict(proof['source_sha256'])
    for path,digest in source_hashes.items():
        assert sha(ROOT/path)==digest, path
    source_hashes[Path(__file__).relative_to(ROOT).as_posix()]=sha(Path(__file__))
    output_hashes={p.relative_to(ROOT).as_posix():sha(p) for p in [proof_path,fragments_path,receipt_path]}
    ledger={'schema':'native-receiver-static-source-output-ledger/v1',
      'created_utc':datetime.now(timezone.utc).isoformat(),'source_sha256':source_hashes,
      'output_sha256':output_hashes,'actual_analyzer_terminal':{'exit_code':0,'chunk_id':'4f2edd'},
      'read_only_inputs_preserved':True,'guest_executed':False}
    ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n')
    seal={'schema':'native-receiver-static-seal/v1','created_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope':'FILE-ONLY exact-source/static contract; no new VM/device/registration execution',
      'source_sha256':source_hashes,'output_sha256':output_hashes,
      'ledger_path':ledger_path.relative_to(ROOT).as_posix(),'ledger_sha256':sha(ledger_path),
      'bounded_functions':15,'original_reachable_instructions':1314,'checks':len(proof['checks']),
      'native_L2CAP_registration_static_identified':True,
      'original_SEP_registration_API_recovered':False,
      'historical_compiled_SEP_provider_observed':True,
      'new_Stage1_receiver_provider_integration_verified':False,
      'warm_system_channel8_ownership_verified':False,
      'callback_unload_quiescence_verified':False,
      'native_phone_App_speaker_or_installation_verified':False,'goal_complete':False}
    seal_path.write_text(json.dumps(seal,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'seal_sha256':sha(seal_path),
        'ledger_sha256':sha(ledger_path),'sealer_source_sha256':sha(Path(__file__)),
        'source_files':len(source_hashes),'sealed_output_files':len(output_hashes),'guest_executed':False}))

if __name__=='__main__':main()
