#!/usr/bin/env python3
"""Serve the report and one explicitly named experiment APK, without directory access."""

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


REPORT_ROUTES = frozenset({"/", "/report.html", "/nuvi2565RT.html"})
APK_ROUTE = "/garmin-hfp-prototype.apk"
APK_FILENAME = "garmin-hfp-prototype.apk"


class ReportHandler(BaseHTTPRequestHandler):
    server_version = "GarminReport/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_GET(self):
        self.serve_report(send_body=True)

    def do_HEAD(self):
        self.serve_report(send_body=False)

    def respond(self, status, body, content_type, send_body, attachment=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if attachment:
            self.send_header("Content-Disposition", 'attachment; filename="' + APK_FILENAME + '"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def serve_report(self, send_body):
        try:
            route = urlsplit(self.path).path
        except ValueError:
            self.respond(
                HTTPStatus.BAD_REQUEST, b"Bad request\n",
                "text/plain; charset=utf-8", send_body,
            )
            return

        if route not in REPORT_ROUTES and route != APK_ROUTE:
            self.respond(
                HTTPStatus.NOT_FOUND, b"Not found\n",
                "text/plain; charset=utf-8", send_body,
            )
            return

        try:
            path = (self.server.report_path.with_name(APK_FILENAME)
                    if route == APK_ROUTE else self.server.report_path)
            body = path.read_bytes()
        except OSError:
            if route == APK_ROUTE:
                self.respond(HTTPStatus.NOT_FOUND, b"Not found\n",
                             "text/plain; charset=utf-8", send_body)
                return
            self.respond(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "報告暫時無法讀取，請稍後重新整理。\n".encode("utf-8"),
                "text/plain; charset=utf-8", send_body,
            )
            return

        self.respond(
            HTTPStatus.OK, body,
            "application/vnd.android.package-archive" if route == APK_ROUTE else "text/html; charset=utf-8",
            send_body, attachment=route == APK_ROUTE,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if not args.report.is_file():
        parser.error("the report file does not exist")

    with ThreadingHTTPServer((args.host, args.port), ReportHandler) as server:
        server.report_path = args.report
        print(f"Serving report on http://{args.host}:{args.port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
