"""Small readonly report capture; no HTTP/services/map/firmware access."""
from pathlib import Path
import hashlib,json,os,stat

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
TOTAL_CAP=786432;HTML_CAP=524288
PATHS=[('report.html','reports/nuvi2565RT.html'),
       ('web.json','evidence/report-web-latest.json'),
       ('download-sealed-files.json','staging/navigation-v3-download-retirement-v1/sealed-files.json'),
       ('download-livecheck.json','staging/navigation-v3-download-retirement-v1/actual-deployment-live-checks.json')]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    private=HERE/'private-inputs';private.mkdir(mode=0o700,exist_ok=False)
    total=0;rows=[];seal=None
    for label,relative in PATHS:
        p=ROOT/relative;b=p.stat();needcap=HTML_CAP if label=='report.html' else TOTAL_CAP
        assert stat.S_ISREG(b.st_mode) and b.st_size<=needcap and total+b.st_size<=TOTAL_CAP
        pin=None
        if label=='download-livecheck.json':
            pin=next(r for r in seal['files'] if r['path']==relative)
            assert b.st_size==pin['bytes'] and fp(b)==pin['stat_at_seal']
            assert stat.S_IMODE(b.st_mode)==int(pin['mode'],8)
        with p.open('rb') as f:raw=f.read(b.st_size+1)
        a=p.stat();total+=len(raw)
        assert fp(b)==fp(a) and len(raw)==b.st_size
        digest=sha(raw)
        if pin:assert digest==pin['sha256']
        out=private/label
        fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw)
        rows.append(dict(source=relative,bytes=len(raw),sha256=digest,
            stat_before=fp(b),stat_after=fp(a),mode=format(stat.S_IMODE(a.st_mode),'04o'),
            original_snapshot_stable=True,official_digest_verified=bool(pin)))
        if label=='download-sealed-files.json':seal=json.loads(raw)
    for row in rows:assert fp((ROOT/row['source']).stat())==row['stat_after']
    receipt=dict(schema='garmin-report-guidance-audit-input/v1',total_artifact_bytes=total,
        total_cap=TOTAL_CAP,HTMLcap=HTML_CAP,reads=rows,all_source_handles_closed=True,
        snapshots_stable=True,no_HTTP_service_IMG_MAIN_guest_audio_device=0,
        private_raw_copies_mode0600_directory0700=True)
    (HERE/'input-read-receipts.json').write_text(json.dumps(receipt,indent=2)+'\n')
    web=json.loads((private/'web.json').read_text())
    print(json.dumps(dict(all_reads_stable=True,artifact_bytes=total,
        report_sha256=rows[0]['sha256'],web_top_keys=list(web),
        all_source_handles_closed=True,no_HTTP_or_service_changes=True)))

if __name__=='__main__':main()
