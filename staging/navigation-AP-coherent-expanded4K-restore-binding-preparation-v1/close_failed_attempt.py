"""Preserve and close the host-offset failure without another IMG read."""
import hashlib
import json
import os
from pathlib import Path
import struct

P = Path(__file__).resolve().parent
reads = []

def get(name):
    q=P/name; before=q.stat(); raw=q.read_bytes(); assert q.stat()==before
    reads.append({'name':name,'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest(),
                  'stat_before_after':[before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns]})
    return raw

def put(name,value):
    (P/name).write_text(json.dumps(value,indent=2)+'\n')

raw_budget=get('source-and-recipe-read-receipts.json'); budget=json.loads(raw_budget)
initial=json.loads(get('initial-artifact-read-receipts.json'))
metadata=get('metadata-actual.bin'); header=get('MDRheader-actual.bin')
assert len(metadata)==90112 and len(header)==772
assert struct.unpack_from('<I',header,0x2b2)[0]==0
correct_descriptor=list(struct.unpack_from('<4I',header,600))
assert correct_descriptor==[149220236,120,20,1]
source=Path('staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled')
s=source.stat(); source_stat=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
assert source_stat==[45826,538397,153337856,1791347653105259871,1791347659645611251]
# Failed command read this owned receipt and the already saved old helper once.
failed_artifact_delta=len(raw_budget)+26503
raw=budget['raw']+failed_artifact_delta+sum(x['bytes'] for x in reads)
decoded=budget['decoded']+failed_artifact_delta+sum(x['bytes'] for x in reads)
assert raw<3145728 and decoded<4194304
put('actual-failed-metadata-terminal-receipt.json',{
    'receipt_type':'recorded actual exec_command result', 'chunk_id':'0f1046','exit_code':1,
    'wall_time_seconds':0.000027185, 'execution':'python3 heredoc; exact body saved as failed-metadata-capture-v1.py',
    'terminal_tail':['DIRECTORYOFFSET 0','Traceback (most recent call last):',
                     '  File "<stdin>", line 13, in <module>','AssertionError'],
    'preceding_terminal_source_extracts':'Unchanged helper load_restore_binding and _layouts_and_header AST text; source snapshot retained.',
    'not_data_rejection_or_platform_review':True,
})
put('failure-proof.json',{
    'scope':P.name,'closed_failed_attempt':True,'API_or_restore_binding_prepared':False,
    'actual_failure':{'chunk_id':'0f1046','exit_code':1,'cause':'Own host reader used offset0x2B2 instead of unchanged helper decimal600/0x258'},
    'wrong_offset':{'offset':690,'actual_saved_header_u32':0},
    'correct_closed_helper_offset':{'offset':600,'actual_saved_header_4u32':correct_descriptor,'scope':'Read from already captured header only; no fresh DIR read'},
    'original_IMG_reads':[{'physical_offset':0,'bytes':90112,'saved_path':'metadata-actual.bin','saved_capture_SHA256':hashlib.sha256(metadata).hexdigest()},
                          {'physical_offset':94208,'bytes':772,'saved_path':'MDRheader-actual.bin','saved_capture_SHA256':hashlib.sha256(header).hexdigest()}],
    'actual_IMG_bytes':90884,'IMG_cap':1048576,'DIR_read':False,'source_stat_before_after_verified_at_failure_close':source_stat,
    'original_IMG_mode':oct(s.st_mode&0o777),'source_handle_close_scope':'Python with-context closes on AssertionError; failed command did not reach its final explicit handle/stat journal',
    'failure_journal_missing_at_throw':'bounded-metadata-read-receipts.json was not produced; closure reconstructs exact read counts from executed source and saved return-byte captures',
    'recovered_capture_digest_is_not_full_source_hash':True,
    'old_helper_SHA256':'43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f','old_helper_unchanged':True,
    'recipe_full_actual_hash_EOF_CRC_passed_in_prior_read':'4cba13 EXIT0; source-and-recipe-read-receipts.json',
    'coherent_expanded4K_future_target':{'bytes':153337856,'SHA256':'8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6','header_SHA256':'63ad71122370c5c5954520f34861c15cccac506ce0692f51856ec0cf4cc162c6','fresh_full_input_validation_and_generator_EOF':'not run'},
    'artifact_budget_before_seal':{'raw':raw,'decoded':decoded,'raw_cap':3145728,'decoded_cap':4194304,'failed_command_delta':failed_artifact_delta,'failure_close_own_reads':reads},
    'guards_adapted_or_relaxed':False,'new_IMG_read_after_failure':False,
    'falseflags':dict.fromkeys(['fullIMGhash','componenthash','restoreAPIprepared','production_reconstruction','fullIMGoutput','nativeCPU','guest','MAIN','device','audio','service','install','hardware_admission','checksum_verified','renderer_fix','App','fullgoal'],False),
    'next':'Parent separately authorized v2 with corrected decimal600; this v1 stops after failure seal.'
})
put('scope-summary.json',{'scope':P.name,'closed_result':'host reader offset bug, preserved EXIT1','actual':'0f1046','IMGbytes':90884,'DIRbytes':0,
    'API_prepared':False,'wrong_header_offset':690,'unchanged_helper_correct_offset':600,
    'saved_correct_descriptor':correct_descriptor,'source_stat_unchanged_at_close':True,
    'next_scope_authorized_separately':'navigation-AP-coherent-expanded4K-restore-binding-preparation-v2','no_install_or_hardware_claim':True})
(P/'HANDOFF.md').write_text('''# Preserved preparation failure

Actual metadata attempt `0f1046 EXIT1` read only90112 metadata bytes and772 MDR header bytes from the existing `.disabled` expanded4K image. It used an incorrect own host-reader offset0x2B2 (actual word0), then asserted the expected directory offset. The unchanged old helper uses decimal600/0x258; the saved header at that offset contains `[149220236,120,20,1]`. This is a preparation-reader bug, not IMG rejection, a platform review failure or a checksum finding.

`failed-metadata-capture-v1.py` preserves the executed heredoc body. The exception occurred before DIR120 and before the final journal write. `failure-proof.json` explicitly reconstructs the exact two reads from that body and the saved return-byte captures, hashes only owned captures, and verifies the original source stat without reopening IMG content. The with-context closed on exception; its planned final explicit closure assertion did not run. `actual-failed-metadata-terminal-receipt.json` preserves the actual exit and terminal tail.

Earlier ordinary small reads pinned the old helper, recipe and old binding; the recipe full compressed/decompressed digest and gzip EOF/CRC passed. No API/binding, synthetic fixture or production reconstruction was prepared or run, and no full/component IMG hash was repeated. Old sources/seals and all device/audio/guest/firmware state remain unchanged. This scope is closed at its first guard failure. Parent separately authorized v2 using decimal600 and saved captures; that permission does not rewrite this failure.
''')
put('preseal-budget.json',{'raw':raw,'decoded':decoded,'raw_cap':3145728,'decoded_cap':4194304,'IMGbytes':90884,'IMGcap':1048576})
print(json.dumps({'failure_closure_written':True,'IMGbytes':90884,'new_IMGreads':0,'correct_saved_descriptor':correct_descriptor,'artifact_raw_before_seal':raw,'artifact_decoded_before_seal':decoded}))
