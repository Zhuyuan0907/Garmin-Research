#!/usr/bin/env python3
"""Serve the two explicitly packaged Garmin candidates on the existing LAN port."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROAD_NAME = 'Garmin-2565RT-navigation-repair-v2.zip'
ADDRESS_NAME = 'Garmin-2565RT-address-test-v1.zip'


class Handler(BaseHTTPRequestHandler):
    server_version = 'GarminNavigationDownload/3.0'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def respond(self, body):
        route = urlsplit(self.path).path
        name = route.removeprefix('/')
        if route == '/' + name and name in (ROAD_NAME, ADDRESS_NAME):
            path = self.server.directory / name
            try:
                stream = path.open('rb')
            except OSError:
                self.send_error(503)
                return
            with stream:
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Length', str(path.stat().st_size))
                self.send_header('Content-Disposition', f'attachment; filename="{name}"')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                if body:
                    try:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError, TimeoutError):
                        pass
            return
        if route == '/':
            code = 200
            text = ('<!doctype html><html lang="zh-Hant"><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width"><title>Garmin 圖資測試包</title>'
                    '<style>body{font-family:system-ui;max-width:44em;margin:3em auto;padding:0 1em;line-height:1.7}</style>'
                    '<h1>Garmin 2565RT 圖資測試包</h1>'
                    '<p>民權路9筆門牌補充包已提供完整候選圖資、校驗與精確還原工具。尚待實機搜尋驗證，並非全台新版 Address Point。</p>'
                    f'<p><a href="/{ADDRESS_NAME}">下載地址補充測試包</a></p>'
                    '<p>包內附已安裝的 Search v2 道路圖；本次工具針對原廠門牌圖資。請先讀 README.txt。</p>'
                    f'<p><a href="/{ROAD_NAME}">既有 Search v2 研究包</a></p>'
                    '<p><a href="http://172.16.60.187:8765/">查看完整研究報告</a></p></html>')
            mime = 'text/html; charset=utf-8'
        elif route == '/Garmin-2565RT-navigation-repair-v1.zip':
            code, text, mime = 410, '舊版候選已由第二版取代。\n', 'text/plain; charset=utf-8'
        else:
            code, text, mime = 404, 'Not found\n', 'text/plain; charset=utf-8'
        data = text.encode()
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if body:
            self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=8767)
    args = parser.parse_args()
    assert args.archive.name == ROAD_NAME and args.archive.is_file()
    assert (args.archive.parent / ADDRESS_NAME).is_file()
    with ThreadingHTTPServer((args.host, args.port), Handler) as server:
        server.directory = args.archive.parent
        server.serve_forever()


if __name__ == '__main__':
    main()
