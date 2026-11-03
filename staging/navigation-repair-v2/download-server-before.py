#!/usr/bin/env python3
"""Serve only the sealed navigation candidate archive on the requested LAN."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

NAME = 'Garmin-2565RT-navigation-repair-v1.zip'


class Handler(BaseHTTPRequestHandler):
    server_version = 'GarminNavigationDownload/1.0'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def headers_for(self, code, size, mime, download=False):
        self.send_response(code)
        for k, v in [('Content-Type', mime), ('Content-Length', str(size)),
                     ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
                     ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")]:
            self.send_header(k, v)
        if download:
            self.send_header('Content-Disposition', f'attachment; filename="{NAME}"')
        self.end_headers()

    def respond(self, body):
        route = urlsplit(self.path).path
        if route == '/' + NAME:
            try:
                f = self.server.archive.open('rb')
            except OSError:
                self.send_error(503)
                return
            with f:
                self.headers_for(200, self.server.archive.stat().st_size, 'application/zip', True)
                if body:
                    try:
                        for chunk in iter(lambda: f.read(1024 * 1024), b''):
                            self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError, TimeoutError):
                        pass
            return
        if route == '/':
            data = ('<!doctype html><html lang="zh-Hant"><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width"><title>Garmin 導航修復包</title>'
                    '<style>body{font-family:system-ui;max-width:42em;margin:3em auto;padding:0 1em;line-height:1.7}</style>'
                    '<h1>Garmin 2565RT 導航修復候選</h1>'
                    '<p>已完成離線檢查；車機地址搜尋與路由尚待實測。</p>'
                    f'<p><a href="/{NAME}">下載完整候選包</a></p>'
                    '<p>包含新 OSM 地圖、圖層說明、安裝／還原工具與驗證紀錄。解壓縮後先讀 README.txt。</p>'
                    '<p><a href="http://172.16.60.187:8765/">查看研究報告</a></p></html>').encode()
            self.headers_for(200, len(data), 'text/html; charset=utf-8')
        else:
            data = b'Not found\n'
            self.headers_for(404, len(data), 'text/plain; charset=utf-8')
        if body:
            self.wfile.write(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=8767)
    a = p.parse_args()
    assert a.archive.name == NAME and a.archive.is_file()
    with ThreadingHTTPServer((a.host, a.port), Handler) as server:
        server.archive = a.archive
        server.serve_forever()


if __name__ == '__main__':
    main()
