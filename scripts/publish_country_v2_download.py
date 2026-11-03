#!/usr/bin/env python3
"""Publish only a fully verified v2 ZIP on the existing LAN download service."""
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-country-v2-download-publication'
SERVER=ROOT/'scripts/serve_navigation_address_candidates.py'
INSTALLED=Path('/usr/local/lib/garmin-navigation-download/server.py')
OLD_SHA='0d674df9a5a2d7558a9f208efbcc5ca7c908513bd96af978eadfef8911bb8b94'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    raw=value if isinstance(value,bytes) else (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(0o444)
def live(name):
    p=subprocess.run(['systemctl','show',name,'--property=MainPID,ActiveState,SubState'],
      capture_output=True,text=True,check=True)
    result=dict(line.split('=',1) for line in p.stdout.splitlines())
    assert result['ActiveState']=='active' and result['SubState']=='running'
    os.kill(int(result['MainPID']),0)
    return result

def main():
    package=json.loads((ROOT/'staging/navigation-country-address-package-v2/package-result.json').read_text())
    assert package['all_passed'] and package['new_houses']==130637 and not package['device_installed']
    if sys.argv[1:]==['--finish-existing-publication']:
        assert OUT.exists() and not (OUT/'download-verification.json').exists()
        receipt=json.loads((OUT/'restart-receipt.json').read_text())
        assert receipt['returncode']==0
        new=SERVER.read_bytes()
        assert new==INSTALLED.read_bytes() and sha(new)==receipt['new_source_sha256']
        report_before=live('garmin-report-web.service')
        previous=json.loads((ROOT/'staging/navigation-source-extension-checkpoint-v1/fresh-readback.json').read_text())
        assert report_before==previous['service']
        verify_download(package,new,report_before)
        return
    assert not sys.argv[1:] and not OUT.exists()
    archive=ROOT/package['archive'];assert archive.stat().st_size==package['bytes']
    old=SERVER.read_bytes();assert old==INSTALLED.read_bytes() and sha(old)==OLD_SHA
    svc_before=live('garmin-navigation-download.service');report_before=live('garmin-report-web.service')
    source=old.decode();name=archive.name
    source=source.replace("COUNTRY_NAME = 'Garmin-2565RT-existing-street-address-test-v1.zip'",
      "COUNTRY_NAME = 'Garmin-2565RT-existing-street-address-test-v1.zip'\nCOUNTRY_V2_NAME = "+repr(name),1)
    source=source.replace('GarminNavigationDownload/5.0','GarminNavigationDownload/6.0',1)
    source=source.replace('(ROAD_NAME, ADDRESS_NAME, TAICHUNG_NAME, COUNTRY_NAME)',
      '(ROAD_NAME, ADDRESS_NAME, TAICHUNG_NAME, COUNTRY_NAME, COUNTRY_V2_NAME)',1)
    marker="                    '<h1>Garmin 2565RT 圖資測試包</h1>'\n"
    assert source.count(marker)==1
    paragraph=(f'                    \'<p>最新第二版補入{package["new_houses"]:,}筆整數門牌，更新{package["existing_streets"]:,}條既有街道，包含可驗證高雄區及四個原生無區層城市的補充。完整讀回、來源重排核對與原韌體有限讀取通過，尚未實機安裝；完整全台更新仍在進行。</p>\'\n'
      '                    f\'<p><a href="/{COUNTRY_V2_NAME}">下載最新跨縣市門牌測試包 v2</a></p>\'\n')
    source=source.replace(marker,marker+paragraph,1)
    source=source.replace("    assert (args.archive.parent / COUNTRY_NAME).is_file()",
      "    assert (args.archive.parent / COUNTRY_NAME).is_file()\n    assert (args.archive.parent / COUNTRY_V2_NAME).is_file()",1)
    ast.parse(source);new=source.encode();assert new!=old
    OUT.mkdir();save(OUT/'previous-server.py.gz',gzip.compress(old,mtime=0))
    for path in (SERVER,INSTALLED):
        temp=path.with_name('.country-v2-'+path.name)
        with temp.open('xb') as f:f.write(new);f.flush();os.fsync(f.fileno())
        temp.chmod(0o644);os.replace(temp,path)
    result=subprocess.run(['systemctl','restart','garmin-navigation-download.service'],capture_output=True,text=True)
    save(OUT/'restart-receipt.json',dict(returncode=result.returncode,stdout=result.stdout,stderr=result.stderr,
      before=svc_before,old_source_sha256=OLD_SHA,new_source_sha256=sha(new)))
    assert result.returncode==0
    verify_download(package,new,report_before)

def verify_download(package,new,report_before):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));failures=[]
    request=urllib.request.Request(package['download_url'],headers={'Cache-Control':'no-cache'})
    for attempt in range(5):
        try:response=opener.open(request,timeout=30);break
        except urllib.error.URLError as exc:
            failures.append(dict(attempt=attempt+1,error=repr(exc)))
            if attempt==4:raise
            time.sleep(.2)
    with response:
        assert response.status==200
        h=hashlib.sha256();count=0
        while raw:=response.read(1048576):h.update(raw);count+=len(raw)
        headers=dict(response.headers)
    assert count==package['bytes'] and h.hexdigest()==package['sha256']
    assert SERVER.read_bytes()==INSTALLED.read_bytes()==new and live('garmin-report-web.service')==report_before
    # Listener readiness and a successful full GET imply exec has completed;
    # active/running alone can be observed during systemd's fork/exec interval.
    svc=live('garmin-navigation-download.service')
    argv=Path('/proc')/svc['MainPID']/'cmdline'
    assert str(INSTALLED).encode() in argv.read_bytes().split(b'\0')
    proof=dict(all_passed=True,url=package['download_url'],HTTP_status=200,served_bytes=count,
      served_sha256=h.hexdigest(),headers=headers,service=svc,actual_PID_cmdline_verified=True,
      installed_source_sha256=sha(new),listener_readiness_transient_failures=failures,
      report_service_not_restarted=True,new_archive_readback_not_saved_as_duplicate=True)
    save(OUT/'download-verification.json',proof)
    print(json.dumps(dict(all_passed=True,served_bytes=count,url=package['download_url'],device_files_written=False)))

if __name__=='__main__':main()
