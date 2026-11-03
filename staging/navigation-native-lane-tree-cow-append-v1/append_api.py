#!/usr/bin/env python3
"""Bind sealed prepared data to an explicitly supplied current-profile writer."""
from pathlib import Path
import hashlib
import json

HERE=Path(__file__).resolve().parent
PROOF_SHA='1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9'


def stat(path):
    s=path.stat();return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def small_json(path,pin):
    before=stat(path);raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=pin or stat(path)!=before:raise ValueError('Prepared metadata binding changed')
    return json.loads(raw)


def supplier(path,artifact):
    """Validate content hash, exact size and immutable source while streaming."""
    def chunks():
        before=stat(path)
        if before[2]!=artifact['bytes']:raise ValueError('Prepared append byte length differs')
        amount=0;hashed=hashlib.sha256()
        with path.open('rb')as stream:
            for raw in iter(lambda:stream.read(65536),b''):
                amount+=len(raw);hashed.update(raw);yield raw
        if amount!=artifact['bytes']or hashed.hexdigest()!=artifact['sha256']or stat(path)!=before:
            raise ValueError('Prepared append content changed/truncated')
    return chunks


def load_inputs(writer):
    """Return (PackedAppend dict, SelectedRange tuple, binding receipt).

    Writer must implement the agreed current-profile classes. This helper
    neither plans/writes an IMG nor treats data preparation as native readiness.
    """
    proof=small_json(HERE/'proof.json',PROOF_SHA)
    appends=small_json(HERE/'appends.json',proof['artifacts']['appends']['sha256'])
    selected=small_json(HERE/'selected-l3-range-changes.json',proof['artifacts']['selected_ranges']['sha256'])
    values={}
    for level in [4,5,6]:
        artifact=appends[str(level)];path=HERE/artifact['path']
        if path.parent!=HERE or artifact['record_bits']!={4:128,5:126,6:68}[level]or artifact!=proof['append_artifacts'][str(level)]:
            raise ValueError('Prepared level/path/profile binding differs')
        values[level]=writer.PackedAppend(level,artifact['record_count'],artifact['bit_length'],supplier(path,artifact))
    changes=tuple(writer.SelectedRange(r['one_based_street_ID'],r['first_child'],r['count'],r['next_level'],r['original_flags'])for r in selected)
    if len(changes)!=7650:raise ValueError('Incomplete current L3 closure')
    return values,changes,dict(proof_sha256=PROOF_SHA,source_candidate_sha256=proof['source_candidate_SHA'],
        native_write_ready=False,selected_L3_changes=7650,selected_L3_classification=proof['selected_L3_classification'],
        final_table_counts=proof['final_table_counts'],prepared_data_only=True)
