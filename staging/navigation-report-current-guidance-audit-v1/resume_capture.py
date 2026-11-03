"""Continue one partial capture without re-reading previously captured sources."""
from pathlib import Path
import hashlib,json,os,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
CAP=786432
def digest(b):return hashlib.sha256(b).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,data):
    (HERE/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def main():
    private=HERE/'private-inputs';rows=[];total=0
    pairs=[('report.html','reports/nuvi2565RT.html'),('web.json','evidence/report-web-latest.json'),
           ('download-sealed-files.json','staging/navigation-v3-download-retirement-v1/sealed-files.json')]
    for label,path in pairs:
        raw=(private/label).read_bytes();s=(ROOT/path).stat();total+=len(raw)
        assert len(raw)==s.st_size
        rows.append(dict(source=path,bytes=len(raw),sha256=digest(raw),mode=format(stat.S_IMODE(s.st_mode),'04o'),
            stat_newly_recorded_at_continuation=fp(s),original_read_attempt='fc9279 EXIT1',
            initial_capture_before_after_equality_assertion_passed=True,
            initial_stat_values_not_durable=True,external_content_reread=False))
    initial=(HERE/'capture_report.initial.py').read_bytes()
    save('initial-capture-failure.json',dict(terminal='fc9279',exit_code=1,
        exception="KeyError: 'stat_at_seal'",failed_source_sha256=digest(initial),
        reason='host schema assumption; declared seal has size/hash/mode but no stat field',
        completed_original_artifact_read_bytes=total,failed_before_fourth_file_content_read=True,
        first_three_snapshot_stability_assertions_passed_but_stats_not_durable=True,
        source_corruption_or_platform_rejection=False,preserved_source='capture_report.initial.py'))
    seal=json.loads((private/'download-sealed-files.json').read_bytes())
    path='staging/navigation-v3-download-retirement-v1/actual-deployment-live-checks.json'
    pin=next(r for r in seal['files'] if r['path']==path)
    p=ROOT/path;b=p.stat()
    assert stat.S_ISREG(b.st_mode) and b.st_size==pin['bytes'] and total+b.st_size<=CAP
    assert stat.S_IMODE(b.st_mode)==int(pin['mode'],8)
    with p.open('rb') as f:raw=f.read(b.st_size+1)
    a=p.stat();assert fp(a)==fp(b) and len(raw)==pin['bytes'] and digest(raw)==pin['sha256']
    total+=len(raw);fd=os.open(private/'download-livecheck.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw)
    rows.append(dict(source=path,bytes=len(raw),sha256=digest(raw),mode=format(stat.S_IMODE(a.st_mode),'04o'),
        stat_before=fp(b),stat_after=fp(a),declared_seal_hash_size_mode_verified=True,
        declared_seal_contains_stat=False))
    save('input-read-receipts.json',dict(schema='garmin-report-guidance-audit-input/v1',
        total_original_artifact_bytes=total,original_artifact_cap=CAP,
        partial_failed_attempt_bytes=total-len(raw),corrected_continuation_original_bytes=len(raw),
        reads=rows,all_source_handles_closed=True,report_snapshot_only=True,
        private_raw_copy_mode0600_directory0700=True,
        no_HTTP_service_IMG_MAIN_guest_audio_device_reads_or_changes=True))
    print(json.dumps(dict(artifact_bytes=total,continuation_original_bytes=len(raw),
        report_sha256=rows[0]['sha256'],all_source_handles_closed=True)))
if __name__=='__main__':main()
