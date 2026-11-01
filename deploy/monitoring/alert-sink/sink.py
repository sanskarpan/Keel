"""Local alert sink for the Keel monitoring profile (development only).

Receives Alertmanager webhook notifications on ``/hooks/ops-alerts`` so the free
Prometheus/Alertmanager alternative delivers alerts without any paid paging service.
It stores only the fixed fields the alert rules carry (alert name, status, severity and
timestamps); tenant, endpoint, delivery, URL and error content never reach it because the
rules do not label alerts with those values.

Endpoints:
  POST /hooks/ops-alerts  Alertmanager webhook receiver
  GET  /alerts            Last 50 received alerts as JSON (for verification)
  GET  /healthz           Liveness
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1 << 20
KEEP = 50

_lock = threading.Lock()
_received = []


def _summarise(payload):
    alerts = payload.get("alerts") or []
    if not isinstance(alerts, list):
        return []
    rows = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        rows.append(
            {
                "alertname": str(labels.get("alertname", ""))[:64],
                "status": str(alert.get("status", ""))[:16],
                "severity": str(labels.get("severity", ""))[:16],
                "startsAt": str(alert.get("startsAt", ""))[:40],
                "endsAt": str(alert.get("endsAt", ""))[:40],
            }
        )
    return rows


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type="application/json"):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, '{"status":"ok"}')
            return
        if self.path == "/alerts":
            with _lock:
                self._send(200, json.dumps({"alerts": list(_received)}))
            return
        self._send(404, '{"error":"not_found"}')

    def do_POST(self):
        if self.path != "/hooks/ops-alerts":
            self._send(404, '{"error":"not_found"}')
            return
        length = self.headers.get("Content-Length")
        try:
            size = int(length) if length else 0
        except ValueError:
            self._send(400, '{"error":"invalid_length"}')
            return
        if size <= 0 or size > MAX_BODY:
            self._send(400, '{"error":"invalid_body_size"}')
            return
        try:
            payload = json.loads(self.rfile.read(size))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, '{"error":"invalid_json"}')
            return
        rows = _summarise(payload)
        with _lock:
            _received.extend(rows)
            del _received[:-KEEP]
        for row in rows:
            print(
                "alert_received alertname=%s status=%s severity=%s"
                % (row["alertname"], row["status"], row["severity"]),
                flush=True,
            )
        self._send(200, json.dumps({"accepted": len(rows)}))

    def log_message(self, *_args):
        # Suppress per-request access logs; only aggregate alert lines are emitted.
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 19095), Handler).serve_forever()
