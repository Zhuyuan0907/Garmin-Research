#!/usr/bin/env python3
"""Exercise actual HTTP GET/HEAD and deny directory/private-file routes."""
import json
from pathlib import Path
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from serve_report import ReportHandler


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='garmin-apk-http-test-') as temp:
        report = Path(temp) / 'report.html'
        report.write_bytes(b'<p>test report</p>')
        apk = report.with_name('garmin-hfp-prototype.apk')
        apk.write_bytes(b'fake-test-payload-not-an-APK')
        with ThreadingHTTPServer(('127.0.0.1', 0), ReportHandler) as server:
            server.report_path = report
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = 'http://127.0.0.1:' + str(server.server_port)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                for path in ('/', '/report.html', '/nuvi2565RT.html'):
                    with opener.open(base + path, timeout=5) as r:
                        assert r.status == 200 and r.read() == report.read_bytes()
                    checks.append('report-' + path)
                for method in ('GET', 'HEAD'):
                    with opener.open(urllib.request.Request(base + '/garmin-hfp-prototype.apk', method=method), timeout=5) as r:
                        assert r.status == 200 and r.headers['Content-Type'] == 'application/vnd.android.package-archive'
                        assert r.headers['Content-Disposition'] == 'attachment; filename="garmin-hfp-prototype.apk"'
                        assert int(r.headers['Content-Length']) == apk.stat().st_size
                        assert r.headers['Cache-Control'] == 'no-store'
                        assert r.read() == (apk.read_bytes() if method == 'GET' else b'')
                    checks.append('apk-' + method)
                for path in ('/reports/', '/AGENTS.md', '/../AGENTS.md', '/%2e%2e/AGENTS.md',
                             '/prototype.p12', '/store-password', '/garmin-hfp-prototype.apk/other'):
                    try:
                        opener.open(base + path, timeout=5)
                        raise AssertionError('Unexpected accessible route: ' + path)
                    except urllib.error.HTTPError as e:
                        assert e.code == 404
                        e.close()
                    checks.append('denied-' + path)
                apk.unlink()
                try:
                    opener.open(base + '/garmin-hfp-prototype.apk', timeout=5)
                    raise AssertionError('Missing APK served')
                except urllib.error.HTTPError as e:
                    assert e.code == 404
                    e.close()
                checks.append('missing-apk-404')
            finally:
                server.shutdown()
                thread.join(timeout=5)
                assert not thread.is_alive()
    print(json.dumps({'all_passed': True, 'HTTP_cases': len(checks), 'cases': checks,
                      'test_payload_not_APK_validation': True, 'device_IO': False}))


if __name__ == '__main__':
    main()
