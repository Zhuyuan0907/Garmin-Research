python3 - '{"staging/native-player-mixer-handoff/audio_session_driver_v4.c":"013f91c366fb5e7fe5f838770ac43a98231a4408c02bc81f1c9072e0b4bec960","staging/native-player-remote-pause/mixer_source_pause_v1.c":"7a4de55660c627105a7727a73530e641ae30e2ca37d12bc02e9f9441a0bdd30c","native/ui-music-control-prototype/ui_music_control.c":"ec5907cb0543716539e375a3be24923ecf307ecf5c530a8000464a5ecdd6984f","native/ui-music-control-prototype/ui_music_control.h":"a10af2e7436530c263e0ba429442514300e3e8d3cd9f28d552905af8ab89136b","staging/native-player-mixer-handoff/music_session_guard_v4.h":"57b99cfc6f55a4be2a5c94997c977c9574ec5dfe32d5616efc5a10ffbb99b8e6","staging/native-player-mixer-handoff/music_session_guard_v4.c":"13563196ebb7b8c22bb8b1d4b50d2209849465b78e9b6ece5565ec4e79034706","staging/native-player-mixer-handoff/native_context_v4.c":"27df8d4a944b749267261ef49c1302be7d7d388c7f277b025b7c29b3723fc4c2","staging/native-player-loaded-single-image/build-v2/owned_media_loaded_v1.c":"58a665ddbc4f827acc72fd2723b5fda697a5091305a328d3ec78fc6e5579fbb5","staging/native-player-loaded-single-image/build-v2/sbc_fifo_loaded_v1.c":"d3a2982365b48b98883cb0e994877fb662ff64e77d4c7a1e7e95f46e50ab3fe0","native/sbc-prototype/memory_output.h":"26537024aab4dd0fa886a5b6d47c5c736177ffdd28e4f6083f8f92aba5ce51a9","native/sbc-prototype/media_queue.h":"a2280f75cffdc8e243f32a86342fa1d7ae11ecf8d12558686045db87b49edc63","native/sbc-prototype/decoder.h":"babf159dc179f502f6c89b2aa6c75ed5dec5b98b6feb345ee50814df413eebaf","staging/native-player-loaded-single-image/build-v2/remote_pause_binding_v1.c":"cb446dc80d83c8e6f3c88596f8b6f896b98c71cc9761ae89cf73a4be22c44405","staging/native-player-loaded-single-image/build-v2/reply_pause_binding_v1.c":"ba882c14da8383f3ccee66bfd96dc0eeba869b6b64dc9f9b31dbe72f18464910","staging/native-player-loaded-single-image/build-v2/remote_binding_v1.h":"47cabb1bbd60298e2dd11c67ba2af46915ca92e50d6b2cd727bcad5f15c73389","staging/native-player-loaded-single-image/build-v2/source_imports_v1.h":"68b1cc523c4310a583c8b91886a9be5f820cba0efb72b88d86efd76e454bdb76"}' <<'PY'
import sys,json,hashlib,os
from pathlib import Path
captured=json.loads(sys.argv[1]);assert len(captured)==16
out=Path('staging/native-music-lifecycle-pin-comparison-readonly-20261007-v1');assert not out.exists()
expected={'v2':'ee7d464e806cfc2d2f506989ffc7b2d7b30c6ce5e2d5f068b95f303cc6b76f75','v3':'9790e7d3951d9dd1210212fbb303c381eb8c9b6f64ebe7f80746ab074fe91677'}
rows={};inputs={}
for version,pin in expected.items():
 p=Path('staging/native-player-loaded-single-image/build-'+version+'.json');assert p.stat().st_size<=81920
 raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==pin
 d=json.loads(raw);rows[version]=[];inputs[str(p)]={'bytes':len(raw),'sha256':pin}
 for name,body_pin in captured.items():
  compare_name=name.replace('/build-v2/','/build-'+version+'/')
  declared=d['source_sha256'].get(compare_name)
  status='not_declared' if declared is None else 'matched_declared_pin' if declared==body_pin else 'different_declared_pin'
  rows[version].append({'captured_source':name,'captured_body_sha256_from_reviewer':body_pin,'manifest_source':compare_name,'manifest_sha256':declared,'comparison':status})
out.mkdir(mode=0o700)
value={'schema':'native-music-loaded-lifecycle-declared-pin-comparison/v1','FILE_check_complete':True,'STOP':True,'inputs':inputs,'metadata_bytes':sum(p['bytes'] for p in inputs.values()),'reviewer_captured_body_pins':captured,'rows':rows,'source_bodies_not_reread_by_root':True,'ELF_or_compiled_object_not_read':True,'not_declared_does_not_prove_not_compiled_or_not_included':True,'equal_source_pins_do_not_prove_equal_all_providers_or_runtime_ABI':True,'native_guest_compile_device_service_audio':False,'install_ready':False,'full_goal_complete':False}
raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
p=out/'comparison.json'
with p.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
p.chmod(0o444)
print(json.dumps({'FILE_check_complete':True,'metadata_bytes':value['metadata_bytes'],'comparison_bytes':len(raw),'comparison_sha256':hashlib.sha256(raw).hexdigest(),'counts':{v:{s:sum(r['comparison']==s for r in rs) for s in ['matched_declared_pin','different_declared_pin','not_declared']} for v,rs in rows.items()},'unmatched':{v:[{'source':r['manifest_source'],'status':r['comparison']} for r in rs if r['comparison']!='matched_declared_pin'] for v,rs in rows.items()}}))
PY