"""The console's small web server (standard library only) and its command-line start-up.

    python "FAULT OR ATTACK.py" --admin [--realistic] [--speed 1] [--port 8800] [--password SECRET]
    python "FAULT OR ATTACK.py" --admin --replay-csv plant.csv [--columns sensor=LIT101,pump_cmd=P101]
    python "FAULT OR ATTACK.py" --admin --make-sample sample.csv [--attack spoof]

By default it listens on this computer only (127.0.0.1). To let other computers on the network see it, add
--host 0.0.0.0, and then always set --password too.
"""

from __future__ import annotations

import base64
import hmac
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..config import PROJECT_DIR, Config
from ..scenarios import KNOWN_SCENARIOS, MODES
from .demos import DEMOS
from .engine import Engine
from .incidents import OUTCOMES, IncidentLog
from .sources import LAB_GROUPS

PAGE = Path(__file__).with_name("console.html")
MAX_BODY = 16_000


def make_handler(engine: Engine, password: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FaultOrAttackConsole/1.0"

        # --- plumbing ------------------------------------------------------------
        def log_message(self, fmt, *args):   # keep the terminal quiet; the audit log is the record
            pass

        def _authorised(self) -> bool:
            if not password:
                return True
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                try:
                    _, _, given = base64.b64decode(header[6:]).decode("utf-8").partition(":")
                except (ValueError, UnicodeDecodeError):
                    return False
                if hmac.compare_digest(given.encode(), password.encode()):
                    return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Fault or Attack console"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code: int = 200) -> None:
            self._send(code, json.dumps(data).encode(), "application/json; charset=utf-8")

        def _error(self, message: str, code: int = 400) -> None:
            self._json({"error": message}, code)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ValueError("Request too large")
            raw = self.rfile.read(n) if n else b"{}"
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            return data

        @staticmethod
        def _who(data: dict) -> str:
            who = str(data.get("who", "")).strip()[:60]
            if not who:
                raise ValueError("Enter your name first (top right), so the log shows who did it")
            return who

        # --- GET -------------------------------------------------------------------
        def do_GET(self):
            if not self._authorised():
                return
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                if url.path in ("/", "/index.html"):
                    self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
                elif url.path == "/api/state":
                    since = q.get("since", [None])[0]
                    self._json(engine.state(int(since) if since not in (None, "") else None))
                elif url.path == "/api/incidents":
                    self._json({"version": engine.log.version, "items": engine.log.as_list(),
                                "outcomes": OUTCOMES})
                elif url.path == "/api/scenarios":
                    groups = [{"group": g, "items": [{"key": k, "name": KNOWN_SCENARIOS[k].name,
                                                      "kind": KNOWN_SCENARIOS[k].kind} for k in keys]}
                              for g, keys in LAB_GROUPS.items()]
                    self._json({"lab": engine.source.lab, "groups": groups, "modes": list(MODES)})
                elif url.path == "/api/demos":
                    self._json({"demos": [d.as_dict() for d in DEMOS] if engine.source.lab else []})
                elif url.path == "/api/export.csv":
                    self._send(200, engine.log.to_csv().encode("utf-8"), "text/csv; charset=utf-8",
                               {"Content-Disposition": 'attachment; filename="incidents.csv"'})
                else:
                    self._error("Not found", 404)
            except (ValueError, OSError) as e:
                self._error(str(e))

        # --- POST ------------------------------------------------------------------
        def do_POST(self):
            if not self._authorised():
                return
            path = urlparse(self.path).path
            try:
                data = self._body()
                m = re.fullmatch(r"/api/incidents/(\d+)/(ack|resolve|note)", path)
                if m:
                    inc_id, what = int(m.group(1)), m.group(2)
                    who, note = self._who(data), str(data.get("note", ""))[:2000]
                    if what == "ack":
                        inc = engine.log.acknowledge(inc_id, who, note)
                    elif what == "resolve":
                        inc = engine.log.resolve(inc_id, who, str(data.get("outcome", "")), note)
                    else:
                        inc = engine.log.add_note(inc_id, who, note)
                    self._json({"ok": True, "id": inc.id, "status": inc.status})
                elif path == "/api/control":
                    action = data.get("action")
                    if action == "pause":
                        engine.paused = True
                    elif action == "resume":
                        engine.paused = False
                    elif action == "speed":
                        engine.set_speed(float(data.get("speed", 1)))
                    elif action == "reset":
                        engine.reset_plant()
                    else:
                        raise ValueError(f"Unknown action {action!r}")
                    self._json({"ok": True})
                elif path == "/api/drill/start":
                    d = engine.start_drill(str(data.get("key", "")), str(data.get("mode", "permanent")),
                                           int(data.get("lead", 30)), bool(data.get("hidden", False)))
                    self._json({"ok": True, "starts_at": d["starts_at"], "hidden": d["hidden"]})
                elif path == "/api/demo/start":
                    d = engine.start_demo(str(data.get("id", "")))
                    self._json({"ok": True, "starts_at": d["starts_at"]})
                elif path == "/api/drill/end":
                    self._json({"ok": True, "result": engine.end_drill()})
                else:
                    self._error("Not found", 404)
            except KeyError as e:
                self._error(str(e).strip("'\""), 404)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                self._error(str(e))

    return Handler


def build(cfg: Config, replay_csv: str | None = None, columns: dict | None = None, speed: float = 1.0,
          backup: bool = True, seed: int = 1, log_dir: Path | None = None) -> Engine:
    from .sources import CsvSource, SimulatedSource
    source = CsvSource(replay_csv, cfg, columns) if replay_csv else SimulatedSource(cfg, backup=backup, seed=seed)
    engine = Engine(source, cfg, IncidentLog(log_dir), speed=speed)
    return engine


def parse_columns(text: str | None) -> dict[str, str] | None:
    """'sensor=LIT101,pump_cmd=P101' -> {'sensor': 'LIT101', 'pump_cmd': 'P101'}"""
    if not text:
        return None
    out = {}
    for part in text.split(","):
        ours, sep, theirs = part.partition("=")
        if not sep or not ours.strip() or not theirs.strip():
            raise ValueError(f"--columns wants ours=theirs pairs separated by commas, got {part!r}")
        out[ours.strip()] = theirs.strip()
    return out


def serve(engine: Engine, host: str = "127.0.0.1", port: int = 8800, password: str | None = None) -> None:
    if host not in ("127.0.0.1", "localhost", "::1") and not password:
        print("Refusing to listen on the network without a password. Add --password, or leave out --host.",
              file=sys.stderr)
        raise SystemExit(2)
    httpd = ThreadingHTTPServer((host, port), make_handler(engine, password))
    engine.start()
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"Fault or Attack console: http://{shown}:{port}")
    print(f"  data:   {engine.source.describe()['name']}")
    if engine.log.log_path:
        print(f"  audit log: {engine.log.log_path}")
    print("  Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        engine.stop()
        httpd.server_close()


DEFAULT_LOG_DIR = PROJECT_DIR / "admin_logs"
