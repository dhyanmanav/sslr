
import json
import os
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EVE_PATH = Path(r"C:\Program Files\Suricata\log\eve.json")
HOST = "0.0.0.0"
PORT = 8766
API_TOKEN = "hello"

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/synthetic-alert":
            return self.reply(404, {"ok": False})

        supplied = self.headers.get("X-API-Token", "")
        if not secrets.compare_digest(supplied, API_TOKEN):
            return self.reply(401, {
                "ok": False,
                "error": "Unauthorized"
            })

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z"),
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "dest_ip": "192.168.1.10",
            "proto": "TCP",
            "cyberforensics_test_tampered": True,
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 999999,
                "rev": 1,
                "signature": "TEST ONLY - Synthetic tampering test",
                "category": "Test Log Integrity Alert",
                "severity": 1
            }
        }

        try:
            # Append only the predefined synthetic event.
            # This does not make Suricata itself detect an attack.
            with open(EVE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())

            print("Synthetic test event appended.")
            self.reply(200, {
                "ok": True,
                "event_type": "alert",
                "synthetic": True,
                "signature": event["alert"]["signature"]
            })
        except OSError as exc:
            print("Could not append to EVE log:", exc)
            self.reply(500, {
                "ok": False,
                "error": "Log write failed; check Windows permissions."
            })

    def log_message(self, fmt, *args):
        print(fmt % args)

if __name__ == "__main__":
    if API_TOKEN == "REPLACE_WITH_A_LONG_RANDOM_SECRET":
        raise SystemExit("Set API_TOKEN before starting.")

    if not EVE_PATH.parent.is_dir():
        raise SystemExit(f"Log directory not found: {EVE_PATH.parent}")

    print(f"Appending labeled test events to: {EVE_PATH}")
    print(f"Listening on port {PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
