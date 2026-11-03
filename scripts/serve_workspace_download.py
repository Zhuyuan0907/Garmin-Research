#!/usr/bin/env python3
"""Serve one named research archive on the LAN; no directory exposure."""
import argparse,html
from pathlib import Path
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
NAME='GarminOS-2565RT-research-v1.zip'
class Handler(BaseHTTPRequestHandler):
 server_version='GarminResearchDownload/1.0';sys_version=''
 def setup(self):super().setup();self.connection.settimeout(30)
 def do_GET(self):self.respond(True)
 def do_HEAD(self):self.respond(False)
 def headers_for(self,status,size,mime,download=False):
  self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(size));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
  if download:self.send_header('Content-Disposition',f'attachment; filename="{NAME}"')
  self.end_headers()
 def respond(self,body):
  try:route=urlsplit(self.path).path
  except ValueError:route='invalid'
  if route=='/'+NAME:
   try:
    with self.server.archive.open('rb')as f:
     self.headers_for(200,self.server.archive.stat().st_size,'application/zip',True)
     if body:
      for block in iter(lambda:f.read(1<<20),b''):self.wfile.write(block)
   except (BrokenPipeError,ConnectionResetError,TimeoutError):return
   except OSError:
    # File-open failure occurs before successful headers; archive is immutable.
    if not self.server.archive.exists():self.send_error(503)
   return
  if route=='/':
   data=('<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>GarminOS 研究專案</title><style>body{font-family:system-ui;max-width:44em;margin:3em auto;padding:0 1em;line-height:1.7}a{font-size:1.2em}</style><h1>GarminOS 2565RT 研究專案</h1><p>包含原廠二進位、反組譯、研究用 C 程式及 VS Code 工作區。這是逆向研究專案，原廠完整原始碼未取得。</p><p><a href="/'+NAME+'">下載專案 ZIP（約 27.4 MiB）</a></p><p>解壓縮後開啟 GarminOS-research.code-workspace，先讀 README.md。</p></html>').encode('utf-8');self.headers_for(200,len(data),'text/html; charset=utf-8')
   if body:self.wfile.write(data)
  else:
   data=b'Not found\n';self.headers_for(404,len(data),'text/plain; charset=utf-8')
   if body:self.wfile.write(data)
def main():
 p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--host',required=True);p.add_argument('--port',type=int,default=8766);a=p.parse_args();assert a.archive.name==NAME and a.archive.is_file()
 with ThreadingHTTPServer((a.host,a.port),Handler)as s:s.archive=a.archive;print(f'Serving one archive on http://{a.host}:{a.port}/',flush=True);s.serve_forever()
if __name__=='__main__':main()
