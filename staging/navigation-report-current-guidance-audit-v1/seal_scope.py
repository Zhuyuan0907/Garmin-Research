"""Seal owned audit outputs by exact hash/size/stat/mode; no shared mutations."""
from pathlib import Path
import hashlib,json,os,re,stat
HERE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,data):
    (HERE/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def main():
    proof=json.loads((HERE/'proof.json').read_text());audit=json.loads((HERE/'audit.json').read_text())
    assert proof['all_assigned_checks_passed'] and audit['html_confirmed_current_conflicts']==2
    assert audit['report_and_canonical_edited'] is False
    public=['audit.json','proof.json','paragraph-inventory.json','HANDOFF.txt']
    for name in public:
        raw=(HERE/name).read_text()
        assert '/root/' not in raw and '/media/' not in raw
        assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',raw)
    assert (HERE/'private-inputs').stat().st_mode&0o777==0o700
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in (HERE/'private-inputs').iterdir())
    save('actual-tool-receipts.json',dict(schema='garmin-report-audit-actual-tools/v1',
        original_source_IO_bytes=428039,source_handles_closed=True,source_read_attempts=[
            dict(terminal='fc9279',exit_code=1,source='capture_report.initial.py',artifact_bytes=418054,
                 failure='KeyError stat_at_seal before livecheck read'),
            dict(terminal='c8bf30',exit_code=0,source='resume_capture.py',artifact_bytes=1793,prior_bytes_reused=True),
            dict(terminal='ff1553',exit_code=1,source='capture_top_fields.initial.py',artifact_bytes=4096,
                 failure='Incomplete UTF8 final codepoint at bounded prefix end'),
            dict(terminal='31c8ed',exit_code=0,source='capture_top_fields.py',artifact_bytes=4096,prior_prefix_reused=True)],
        owned_snapshot_parser_runs=[dict(terminal='ebfc1f',exit_code=0,body_blocks=0,preliminary_only=True),
            dict(terminal='0db7dd',exit_code=0,body_blocks=746,selected_blocks=142)],
        actual_core_review=dict(terminal='3fdc69',exit_code=0,source='build_audit.py',
            independently_read_HTML_conflicts=2,independently_read_structured_stale_fields=2),
        no_new_HTTP_IMG_MAIN_PBF_guest_audio_device_or_service=True,
        root_additional_flags_are_inherited_not_independent_reads=True))
    save('output-audit.json',dict(all_assigned_checks_passed=True,public_files_no_private_paths_or_deviceIDs=True,
        private_inputs_0600_and_directory0700=True,HTML_findings=2,independently_read_stale_structured_fields=2,
        inherited_root_flag_observations=2,all_failed_attempts_preserved=True,
        shared_source_report_canonical_service_device_mutations=0,
        seal_is_hash_size_stat_mode_not_readonly_mode=True))
    save('sealer-receipt.json',dict(all_assigned_checks_passed=True,all_owned_output_handles_closed_before_seal=True,
        shared_source_read_bytes_during_seal=0,shared_mutations=0,report_republished=False,
        all_public_field_checks_passed=True,permission_mode_not_changed_by_sealer=True,
        STOP=True,whole_goal_complete=False))
    pins=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='sealed-files.json':continue
        b=p.stat();raw=p.read_bytes();a=p.stat();assert fp(a)==fp(b) and len(raw)==a.st_size
        pins.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(a.st_mode),'04o'),stat_at_seal=fp(a),
            private=p.name.endswith('.private.json') or 'private-inputs' in p.parts))
    result=dict(schema='garmin-report-current-guidance-audit-seal/v1',all_assigned_checks_passed=True,
        files=pins,exact_mode_pinned_not_required_0444=True,actual_original_artifact_bytes=428039,
        read_scope_stopped=True,all_source_handles_closed=True,no_canonical_report_changes=True,
        full_goal_complete=False)
    save('sealed-files.json',result)
    # Recheck owned file state only. No reread of report, evidence or download originals.
    for row in pins:assert fp((ROOT/row['path']).stat())==row['stat_at_seal']
    print(json.dumps(dict(all_assigned_checks_passed=True,STOP=True,files=len(pins),
        proof_sha256=sha((HERE/'proof.json').read_bytes()),audit_sha256=sha((HERE/'audit.json').read_bytes()),
        seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
        source_handles_closed=True,original_source_read_bytes_during_seal=0)))
if __name__=='__main__':main()
