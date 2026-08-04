#!/usr/bin/env python3
"""Home Assistant full-admin API client for the OpenClaw skill.

Exposes the full surface the long-lived access token allows, over HTTPS REST
and WebSocket. Everyday actions (service calls, reloads, notifications) run
freely. Only clearly destructive operations require --confirm.

API references (Home Assistant Core):
  https://developers.home-assistant.io/docs/api/rest/
  https://developers.home-assistant.io/docs/api/websocket/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_WRITE_BYTES = 256 * 1024
ENTITY_RE = re.compile(r"^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$")
NAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")
EVENT_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")
# Automation config ids, config-entry ids, flow ids (UUID hex or slug).
CONFIG_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")
WS_TYPE_RE = re.compile(r"^[a-z0-9_]+(?:/[a-z0-9_]+)*$")
API_PATH_RE = re.compile(r"^/api(?:/.*)?$")

# Domain/service pairs that always need --confirm (instance-level damage).
DESTRUCTIVE_SERVICES = frozenset({
    ("homeassistant", "stop"),
    ("homeassistant", "restart"),
})

# Service *names* treated as destructive across domains (delete/disable/remove).
DESTRUCTIVE_SERVICE_NAMES = frozenset({
    "remove",
    "delete",
    "disable",
    "purge",
    "remove_entity",
    "remove_device",
    "delete_account",
    "factory_reset",
})

# WebSocket types that are clearly destructive (registry/config removal, etc.).
WS_DESTRUCTIVE_TYPES = frozenset({
    "config/entity_registry/remove",
    "config/entity_registry/update",  # can disable / hide entities
    "config/device_registry/remove",
    "config/device_registry/update",
    "config/area_registry/delete",
    "config/area_registry/update",
    "config/floor_registry/delete",
    "config/label_registry/delete",
    "config_entries/disable",
    "config_entries/remove",
    "config_entries/update",
    "config_entries/flow/delete",
    "backup/remove",
    "person/delete",
    "todo/item/remove",
    "shopping_list/items/clear",
    "system_log/clear",
    "logger/set_level",
    "repairs/ignore_issue",
    "homeassistant/expose_entity",  # changes exposure config
})

# Path segments that mark a WS type as destructive when not otherwise listed.
_WS_DESTRUCTIVE_SEGMENTS = frozenset({
    "remove", "delete", "disable", "purge", "clear", "factory_reset",
})

ERROR_LOG_UNAVAILABLE = (
    "the Core file-log endpoint is unavailable on this installation. "
    "Home Assistant only registers /api/error_log when Core writes its own log "
    "file; Supervisor-managed installations normally disable that duplicate "
    "file. Use system-log (WebSocket) or Supervisor/host logging instead. "
    "The logbook is activity history, not an error-log fallback."
)

USER_AGENT = "openclaw-home-assistant/3"


# ── Security / shared helpers ─────────────────────────────────────────────────


class BlockRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(newurl, code, "redirect blocked", headers, fp)


def validate_base_url(base_url: str):
    """Require a strict HTTPS origin for REST and WebSocket."""
    parsed = urlsplit(base_url)
    if parsed.scheme != "https":
        raise ValueError("HOME_ASSISTANT_URL must use https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("HOME_ASSISTANT_URL is invalid")
    if parsed.query or parsed.fragment:
        raise ValueError("HOME_ASSISTANT_URL must not include a query or fragment")
    return parsed


def redact(text: str, token: str) -> str:
    if token and len(token) >= 8:
        text = text.replace(token, "[REDACTED]")
    patterns = (
        (r"(?i)(authorization\s*:\s*bearer\s+)\S+", r"\1[REDACTED]"),
        (r'(?i)(["\']?(?:access_)?token["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
        (
            r"(?i)([?&](?:access_token|token|api_key|apikey|password|secret)=)[^&#\s]+",
            r"\1[REDACTED]",
        ),
        (r"(?i)(https?://[^:/@\s]+:)[^@\s/]+(@)", r"\1[REDACTED]\2"),
        (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{10,})?\b", "[REDACTED]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def emit(value: Any, token: str) -> None:
    if isinstance(value, str):
        output = value
    else:
        output = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    print(redact(output, token))


def require_confirm(args: argparse.Namespace, what: str) -> None:
    if not getattr(args, "confirm", False):
        raise ValueError(
            f"destructive action blocked: {what}; "
            "obtain explicit user approval and pass --confirm"
        )


def is_destructive_service(domain: str, service: str) -> bool:
    """True for stop/restart and delete/disable/remove style services."""
    domain = domain.lower()
    service = service.lower()
    if (domain, service) in DESTRUCTIVE_SERVICES:
        return True
    if service in DESTRUCTIVE_SERVICE_NAMES:
        return True
    # e.g. permanent_delete, remove_entry
    if any(part in service for part in ("remove", "delete", "disable", "purge")):
        # Allow harmless names like "reload" / "turn_off" / "notify"
        if service in {"turn_off", "turn_on", "toggle", "reload", "reload_all",
                       "reload_core_config", "reload_custom_templates",
                       "reload_config_entry"}:
            return False
        if service.startswith("reload"):
            return False
        return True
    return False


def is_destructive_ws_type(ws_type: str) -> bool:
    if ws_type in WS_DESTRUCTIVE_TYPES:
        return True
    parts = ws_type.split("/")
    return any(part in _WS_DESTRUCTIVE_SEGMENTS for part in parts)


def is_destructive_rest(method: str, path: str) -> bool:
    method = method.upper()
    if method == "DELETE":
        return True
    # POST/PUT to services: inspect last two path segments as domain/service
    if method in {"POST", "PUT"}:
        clean = path.split("?", 1)[0].rstrip("/")
        if "/api/services/" in clean:
            tail = clean.split("/api/services/", 1)[1]
            bits = [b for b in tail.split("/") if b]
            if len(bits) >= 2:
                return is_destructive_service(bits[0], bits[1])
        if clean.endswith("/stop") or clean.endswith("/restart"):
            return True
    return False


def parse_json_object(raw: str | None, *, label: str = "JSON") -> dict[str, Any]:
    if raw is None or raw == "":
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_WRITE_BYTES:
        raise ValueError(f"{label} exceeds the 256 KiB limit")
    return value


def parse_json_payload(args: argparse.Namespace) -> dict[str, Any]:
    data = getattr(args, "data", None)
    data_file = getattr(args, "data_file", None)
    if data is not None and data_file is not None:
        raise ValueError("use either --data or --data-file, not both")
    if data_file is not None:
        path = Path(data_file)
        if path.stat().st_size > MAX_WRITE_BYTES:
            raise ValueError("request JSON file exceeds the 256 KiB limit")
        return parse_json_object(path.read_text(encoding="utf-8"), label="data file")
    return parse_json_object(data if data is not None else "{}", label="--data")


def validate_timestamp(value: str, option: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{option} must be an ISO 8601 timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError(f"{option} must include a timezone")
    return value


def validate_entity_id(entity_id: str) -> str:
    if not ENTITY_RE.fullmatch(entity_id):
        raise ValueError(f"invalid entity_id: {entity_id}")
    return entity_id


def validate_name(value: str, label: str = "name") -> str:
    if not NAME_RE.fullmatch(value):
        raise ValueError(f"invalid {label}: {value}")
    return value


def validate_config_id(value: str, label: str = "id") -> str:
    if not value or not CONFIG_ID_RE.fullmatch(value):
        raise ValueError(f"invalid {label}: {value}")
    return value


def split_entity_id(entity_id: str) -> tuple[str, str]:
    validate_entity_id(entity_id)
    domain, object_id = entity_id.split(".", 1)
    return domain, object_id


def describe_error_log_failure(exc: HTTPError) -> str:
    if exc.code == 404:
        return ERROR_LOG_UNAVAILABLE
    return f"Home Assistant API HTTP {exc.code}"


def clamp_limit(value: int, *, default: int, lo: int = 1, hi: int = 1000) -> int:
    if value is None:
        return default
    if value < lo or value > hi:
        raise ValueError(f"limit must be between {lo} and {hi}")
    return value


# ── REST client ───────────────────────────────────────────────────────────────


class HomeAssistant:
    def __init__(self, base_url: str, token: str, timeout: float):
        validate_base_url(base_url)
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = build_opener(BlockRedirects())

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        accept_text: bool = False,
        raw: bool = False,
    ) -> Any:
        method = method.upper()
        if not path.startswith("/"):
            path = "/" + path
        if not API_PATH_RE.fullmatch(path.split("?", 1)[0]):
            raise ValueError("only Home Assistant /api paths are allowed")

        body = None
        headers = {
            "Accept": "text/plain" if accept_text else "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": USER_AGENT,
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_WRITE_BYTES:
                raise ValueError("request JSON exceeds the 256 KiB limit")
            headers["Content-Type"] = "application/json"

        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Home Assistant response exceeded 4 MiB; narrow the query")
            if raw:
                return data
            text = data.decode(response.headers.get_content_charset() or "utf-8", "replace")
            if accept_text:
                return text
            if not text.strip():
                return None
            return json.loads(text)


# ── WebSocket client ──────────────────────────────────────────────────────────


class HomeAssistantWS:
    """RFC 6455 client for Home Assistant /api/websocket (stdlib only)."""

    def __init__(self, base_url: str, token: str, timeout: float = 15):
        parsed = validate_base_url(base_url)
        assert parsed.hostname is not None
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.token = token
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._msg_id = 0
        self._buf = bytearray()

    def connect(self) -> dict[str, Any]:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=self.host)
        sock.settimeout(self.timeout)

        key_bytes = os.urandom(16)
        key = base64.b64encode(key_bytes).decode()
        host_header = self.host if self.port == 443 else f"{self.host}:{self.port}"
        handshake = (
            f"GET /api/websocket HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(handshake.encode())

        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                raise RuntimeError("WebSocket handshake failed: connection closed")
            raw.extend(chunk)
            if len(raw) > 8192:
                sock.close()
                raise RuntimeError("WebSocket handshake failed: response too large")

        header_blob, _, remainder = bytes(raw).partition(b"\r\n\r\n")
        status_line = header_blob.split(b"\r\n", 1)[0]
        if b"101" not in status_line:
            sock.close()
            raise RuntimeError(
                f"WebSocket handshake failed: {header_blob[:200].decode(errors='replace')}"
            )
        accept_expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        headers = header_blob.decode("iso-8859-1", "replace").lower()
        if f"sec-websocket-accept: {accept_expected.lower()}" not in headers:
            sock.close()
            raise RuntimeError("WebSocket handshake failed: invalid Sec-WebSocket-Accept")

        self._sock = sock
        self._buf = bytearray(remainder)

        auth_required = self._recv()
        if auth_required.get("type") != "auth_required":
            raise RuntimeError(f"Expected auth_required, got {auth_required.get('type')}")

        self._send({"type": "auth", "access_token": self.token})
        auth_resp = self._recv()
        if auth_resp.get("type") != "auth_ok":
            raise RuntimeError(
                f"Auth failed: {auth_resp.get('type')} {auth_resp.get('message', '')}"
            )
        return auth_resp

    def _send(self, msg: dict[str, Any]) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode()
        if len(data) > MAX_WRITE_BYTES:
            raise ValueError("WebSocket message exceeds the 256 KiB limit")
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        frame = bytearray([0x81])  # FIN + text
        length = len(masked)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))
        frame.extend(mask)
        frame.extend(masked)
        if not self._sock:
            raise ConnectionError("WebSocket is not connected")
        self._sock.sendall(bytes(frame))

    def _read_more(self) -> None:
        assert self._sock is not None
        if len(self._buf) > MAX_RESPONSE_BYTES + 16:
            self.close()
            raise RuntimeError(
                "Home Assistant WebSocket frame exceeded 4 MiB; narrow the query"
            )
        chunk = self._sock.recv(65536)
        if not chunk:
            raise ConnectionError("WebSocket connection closed")
        self._buf.extend(chunk)

    def _recv(self) -> dict[str, Any]:
        if not self._sock:
            raise ConnectionError("WebSocket is not connected")
        while True:
            while len(self._buf) < 2:
                self._read_more()

            fin = bool(self._buf[0] & 0x80)
            opcode = self._buf[0] & 0x0F
            masked = bool(self._buf[1] & 0x80)
            plen = self._buf[1] & 0x7F
            header_len = 2

            if plen == 126:
                while len(self._buf) < 4:
                    self._read_more()
                plen = struct.unpack(">H", bytes(self._buf[2:4]))[0]
                header_len = 4
            elif plen == 127:
                while len(self._buf) < 10:
                    self._read_more()
                plen = struct.unpack(">Q", bytes(self._buf[2:10]))[0]
                header_len = 10

            if masked:
                header_len += 4

            if plen > MAX_RESPONSE_BYTES:
                self.close()
                raise RuntimeError(
                    "Home Assistant WebSocket frame exceeded 4 MiB; narrow the query"
                )

            total_len = header_len + plen
            while len(self._buf) < total_len:
                self._read_more()

            frame = bytes(self._buf[:total_len])
            del self._buf[:total_len]

            if opcode == 0x8:
                raise ConnectionError("WebSocket closed by server")
            if opcode in (0x9, 0xA):
                continue
            if opcode != 0x1:
                raise RuntimeError(f"Unexpected WebSocket opcode: {opcode}")
            if not fin:
                raise RuntimeError("Fragmented WebSocket frames are not supported")

            payload = frame[header_len:]
            if masked:
                mask = frame[header_len - 4 : header_len]
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            return json.loads(payload.decode())

    def call(self, msg: dict[str, Any]) -> dict[str, Any]:
        self._msg_id += 1
        outbound = dict(msg)
        outbound["id"] = self._msg_id
        self._send(outbound)
        # Skip unsolicited events until the matching result/pong arrives.
        while True:
            resp = self._recv()
            if resp.get("type") == "pong" and resp.get("id") == self._msg_id:
                return resp
            if resp.get("type") == "result" and resp.get("id") == self._msg_id:
                return resp
            if resp.get("id") == self._msg_id and resp.get("type") not in {"event"}:
                return resp

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        self._buf.clear()


def ws_connect(token: str, base_url: str, timeout: float) -> HomeAssistantWS:
    client = HomeAssistantWS(base_url, token, timeout)
    client.connect()
    return client


# ── Summaries / domain helpers ────────────────────────────────────────────────


def summarize_config(config: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "version",
        "state",
        "time_zone",
        "unit_system",
        "currency",
        "country",
        "language",
        "safe_mode",
        "recovery_mode",
        "location_name",
        "internal_url",
        "external_url",
    )
    result = {key: config.get(key) for key in keys if key in config}
    components = config.get("components")
    if isinstance(components, list):
        result["components_count"] = len(components)
    return result


def summarize_state(item: dict[str, Any]) -> dict[str, Any]:
    attributes = item.get("attributes") or {}
    return {
        "entity_id": item.get("entity_id"),
        "state": item.get("state"),
        "friendly_name": attributes.get("friendly_name"),
        "device_class": attributes.get("device_class"),
        "unit_of_measurement": attributes.get("unit_of_measurement"),
        "last_changed": item.get("last_changed"),
        "last_updated": item.get("last_updated"),
    }


def tail_lines(text: str, limit: int) -> dict[str, Any]:
    limit = clamp_limit(limit, default=200, lo=1, hi=2000)
    lines = text.splitlines()
    selected = lines[-limit:]
    return {
        "line_count": len(lines),
        "returned": len(selected),
        "lines": selected,
    }


def command_triage(client: HomeAssistant) -> dict[str, Any]:
    status = client.request("GET", "/api/")
    config = client.request("GET", "/api/config")
    states = client.request("GET", "/api/states")
    unavailable = [
        summarize_state(item)
        for item in states
        if isinstance(item, dict) and item.get("state") in {"unavailable", "unknown"}
    ]
    errors: dict[str, Any] | None
    errors_problem: str | None = None
    try:
        error_text = client.request("GET", "/api/error_log", accept_text=True)
        errors = tail_lines(error_text, 200)
    except HTTPError as exc:
        errors = None
        errors_problem = describe_error_log_failure(exc)
    return {
        "api": status,
        "config": summarize_config(config if isinstance(config, dict) else {}),
        "entity_count": len(states) if isinstance(states, list) else 0,
        "unavailable_count": len(unavailable),
        "unavailable": unavailable[:100],
        "errors": errors,
        "errors_problem": errors_problem,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def logbook_path(args: argparse.Namespace) -> str:
    if args.hours is not None and args.start is not None:
        raise ValueError("use either --hours or --start, not both")
    if args.hours is not None:
        if args.hours <= 0 or args.hours > 168:
            raise ValueError("--hours must be greater than 0 and no more than 168")
        start = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()
    elif args.start is not None:
        start = validate_timestamp(args.start, "--start")
    else:
        start = None

    path = "/api/logbook"
    if start is not None:
        path += f"/{quote(start, safe='')}"

    query: dict[str, str] = {}
    if args.end is not None:
        query["end_time"] = validate_timestamp(args.end, "--end")
    if args.entity is not None:
        query["entity"] = validate_entity_id(args.entity)
    if query:
        path += f"?{urlencode(query)}"
    return path


def history_path(args: argparse.Namespace) -> str:
    if not args.entity:
        raise ValueError("history requires --entity (comma-separated entity_ids)")
    entities = [validate_entity_id(e.strip()) for e in args.entity.split(",") if e.strip()]
    if not entities:
        raise ValueError("history requires at least one entity_id")

    if args.start:
        start = validate_timestamp(args.start, "--start")
        path = f"/api/history/period/{quote(start, safe='')}"
    else:
        path = "/api/history/period"

    query: dict[str, str] = {"filter_entity_id": ",".join(entities)}
    if args.end:
        query["end_time"] = validate_timestamp(args.end, "--end")
    if args.minimal:
        query["minimal_response"] = ""
    if args.no_attributes:
        query["no_attributes"] = ""
    if args.significant:
        query["significant_changes_only"] = ""
    path += f"?{urlencode(query)}"
    return path


# ── CLI ───────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Full-admin Home Assistant client (REST + WebSocket). "
            "Service calls and reloads run freely; only destructive actions "
            "(delete/disable/stop/restart) require --confirm."
        )
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    sub = parser.add_subparsers(dest="command", required=True)

    # Read-only REST
    for name in ("status", "config", "components", "events", "services", "unavailable", "triage"):
        sub.add_parser(name)

    p = sub.add_parser("errors", help="GET /api/error_log (plaintext core file log)")
    p.add_argument("--tail-lines", type=int, default=200)

    p = sub.add_parser("logbook", help="GET /api/logbook")
    p.add_argument("--hours", type=float)
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--entity")
    p.add_argument("--limit", type=int, default=200)

    p = sub.add_parser("history", help="GET /api/history/period")
    p.add_argument("--entity", required=True, help="Comma-separated entity_id list")
    p.add_argument("--start", help="ISO-8601 start (defaults to ~1 day ago on HA)")
    p.add_argument("--end")
    p.add_argument("--minimal", action="store_true")
    p.add_argument("--no-attributes", action="store_true")
    p.add_argument("--significant", action="store_true")

    p = sub.add_parser("state", help="GET /api/states/<entity_id>")
    p.add_argument("entity_id")
    p.add_argument("--full", action="store_true", help="Include full attributes")

    p = sub.add_parser("states", help="GET /api/states with filters")
    p.add_argument("--domain")
    p.add_argument("--state")
    p.add_argument("--search", help="Substring match on entity_id or friendly_name")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--full", action="store_true")

    p = sub.add_parser("template", help="POST /api/template (render)")
    p.add_argument("--template", help="Template string")
    p.add_argument("--template-file", help="Read template from file")

    sub.add_parser("check-config", help="POST /api/config/core/check_config")

    p = sub.add_parser("calendars", help="GET /api/calendars")
    p = sub.add_parser("calendar", help="GET /api/calendars/<entity_id>")
    p.add_argument("entity_id")
    p.add_argument("--start", required=True)
    p.add_argument("--end", required=True)

    # Mutating REST
    p = sub.add_parser("call-service", help="POST /api/services/<domain>/<service>")
    p.add_argument("domain")
    p.add_argument("service")
    p.add_argument("--data")
    p.add_argument("--data-file")
    p.add_argument("--return-response", action="store_true")
    p.add_argument(
        "--confirm",
        action="store_true",
        help="Required only for destructive services (stop/restart/remove/delete/disable)",
    )

    p = sub.add_parser("set-state", help="POST /api/states/<entity_id> (state machine only)")
    p.add_argument("entity_id")
    p.add_argument("--state", required=True)
    p.add_argument("--attributes", default="{}", help="JSON attributes object")

    p = sub.add_parser("delete-state", help="DELETE /api/states/<entity_id> (destructive)")
    p.add_argument("entity_id")
    p.add_argument("--confirm", action="store_true", required=False)
    # --confirm still optional flag but enforced in handler

    p = sub.add_parser("fire-event", help="POST /api/events/<event_type>")
    p.add_argument("event_type")
    p.add_argument("--data", default="{}")

    p = sub.add_parser("intent", help="POST /api/intent/handle")
    p.add_argument("name")
    p.add_argument("--data", default="{}")

    p = sub.add_parser("restart", help="homeassistant.restart (destructive — needs --confirm)")
    p.add_argument("--confirm", action="store_true")

    p = sub.add_parser("stop", help="homeassistant.stop (destructive — needs --confirm)")
    p.add_argument("--confirm", action="store_true")

    p = sub.add_parser("reload", help="Reload automations/scripts/core/etc. (no confirm)")
    p.add_argument(
        "what",
        help=(
            "One of: core, config, automations, scripts, scenes, groups, "
            "template, person, zones, input_*, or domain.service"
        ),
    )

    p = sub.add_parser("find-phone", help="Ring an Android companion device")
    p.add_argument("device")
    p.add_argument("--message", default="Your phone is here!")

    # Automation CRUD (admin config API — automations.yaml / UI storage)
    p = sub.add_parser(
        "automation-get",
        help="GET /api/config/automation/config/<id> (full editable config)",
    )
    p.add_argument(
        "automation_id",
        help="Automation config id (usually entity registry unique_id, not entity_id)",
    )

    p = sub.add_parser(
        "automation-set",
        help="POST /api/config/automation/config/<id> (create or replace; auto-reloads)",
    )
    p.add_argument("automation_id")
    p.add_argument("--data", help="Full automation config JSON object")
    p.add_argument("--data-file", help="Path to JSON file with automation config")

    p = sub.add_parser(
        "automation-delete",
        help="DELETE /api/config/automation/config/<id> (destructive)",
    )
    p.add_argument("automation_id")
    p.add_argument("--confirm", action="store_true")

    p = sub.add_parser(
        "automation-list",
        help="List automation entities with config ids (from states + entity registry)",
    )
    p.add_argument("--search")
    p.add_argument("--limit", type=int, default=200)

    # Config entries + config flows
    p = sub.add_parser(
        "config-entry-reload",
        help="POST /api/config/config_entries/entry/<entry_id>/reload",
    )
    p.add_argument("entry_id")

    p = sub.add_parser(
        "config-entry-delete",
        help="DELETE /api/config/config_entries/entry/<entry_id> (destructive)",
    )
    p.add_argument("entry_id")
    p.add_argument("--confirm", action="store_true")

    p = sub.add_parser(
        "config-flow-handlers",
        help="GET /api/config/config_entries/flow_handlers (installable integrations)",
    )
    p.add_argument(
        "--type",
        dest="flow_type",
        help="Optional type filter (e.g. integration, hardware, helper, ...)",
    )

    p = sub.add_parser(
        "config-flow-start",
        help="POST /api/config/config_entries/flow (start install or reconfigure)",
    )
    p.add_argument(
        "--handler",
        required=True,
        help="Integration domain / flow handler (e.g. mqtt, hue)",
    )
    p.add_argument(
        "--entry-id",
        help="Existing config entry id (reconfigure / show options context)",
    )
    p.add_argument(
        "--data",
        default="{}",
        help="Extra JSON fields merged into the start payload",
    )

    p = sub.add_parser(
        "config-flow-get",
        help="GET /api/config/config_entries/flow/<flow_id> (current step/schema)",
    )
    p.add_argument("flow_id")

    p = sub.add_parser(
        "config-flow-step",
        help="POST /api/config/config_entries/flow/<flow_id> (submit user_input)",
    )
    p.add_argument("flow_id")
    p.add_argument("--data", default="{}", help="JSON user_input for this step")
    p.add_argument("--data-file")

    p = sub.add_parser(
        "config-options-start",
        help="POST /api/config/config_entries/options/flow (edit integration options)",
    )
    p.add_argument("entry_id", help="Config entry id to configure")

    p = sub.add_parser(
        "config-options-get",
        help="GET /api/config/config_entries/options/flow/<flow_id>",
    )
    p.add_argument("flow_id")

    p = sub.add_parser(
        "config-options-step",
        help="POST /api/config/config_entries/options/flow/<flow_id>",
    )
    p.add_argument("flow_id")
    p.add_argument("--data", default="{}")
    p.add_argument("--data-file")

    # Generic REST escape hatch
    p = sub.add_parser(
        "rest",
        help="Raw REST under /api (DELETE and destructive services need --confirm)",
    )
    p.add_argument("method", choices=["GET", "POST", "PUT", "DELETE"])
    p.add_argument("path", help="Path starting with /api")
    p.add_argument("--data")
    p.add_argument("--data-file")
    p.add_argument("--text", action="store_true", help="Treat response as text")
    p.add_argument("--confirm", action="store_true")

    # WebSocket high-level
    p = sub.add_parser("automation-config", help="Entity registry + latest automation trace")
    p.add_argument("entity_id")

    p = sub.add_parser("automation-trace", help="List/detail automation traces")
    p.add_argument("entity_id")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--include-config", action="store_true")
    p.add_argument("--run-id", help="Fetch a single run_id")

    p = sub.add_parser("entity-registry", help="config/entity_registry/get")
    p.add_argument("entity_id")

    p = sub.add_parser("entity-registry-list", help="config/entity_registry/list_for_display")
    p.add_argument("--search")
    p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("device-registry", help="config/device_registry/list")
    p.add_argument("--search")
    p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("area-registry", help="config/area_registry/list")

    p = sub.add_parser("config-entries", help="config_entries/get (list integrations)")
    p.add_argument("--domain")
    p.add_argument("--search", help="Substring match on title/domain/entry_id")

    p = sub.add_parser("system-log", help="system_log/list via WebSocket")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("repairs", help="repairs/list_issues via WebSocket")

    p = sub.add_parser(
        "ws",
        help="Raw WebSocket command (destructive types / services need --confirm)",
    )
    p.add_argument("ws_type")
    p.add_argument("--data", default="{}")
    p.add_argument("--data-file")
    p.add_argument("--confirm", action="store_true")

    return parser


RELOAD_MAP = {
    "core": ("homeassistant", "reload_core_config"),
    "config": ("homeassistant", "reload_core_config"),
    "all": ("homeassistant", "reload_all"),
    "automations": ("automation", "reload"),
    "scripts": ("script", "reload"),
    "scenes": ("scene", "reload"),
    "groups": ("group", "reload"),
    "template": ("template", "reload"),
    "person": ("person", "reload"),
    "zones": ("zone", "reload"),
    "input_boolean": ("input_boolean", "reload"),
    "input_number": ("input_number", "reload"),
    "input_select": ("input_select", "reload"),
    "input_text": ("input_text", "reload"),
    "input_datetime": ("input_datetime", "reload"),
    "input_button": ("input_button", "reload"),
    "timers": ("timer", "reload"),
    "counters": ("counter", "reload"),
    "rest": ("rest", "reload"),
    "command_line": ("command_line", "reload"),
    "mqtt": ("mqtt", "reload"),
    "generic": ("generic", "reload"),
}


def run_ws(args: argparse.Namespace, token: str, base_url: str) -> Any:
    """Dispatch high-level WebSocket commands."""
    timeout = args.timeout

    if args.command == "ws":
        if not WS_TYPE_RE.fullmatch(args.ws_type):
            raise ValueError("invalid WebSocket command type")
        payload = parse_json_payload(args)
        if "type" in payload or "id" in payload:
            raise ValueError("WebSocket --data must not include 'type' or 'id'")
        # Gate only clearly destructive WS commands / services.
        if is_destructive_ws_type(args.ws_type):
            require_confirm(args, f"WebSocket type {args.ws_type!r} is destructive")
        if args.ws_type == "call_service":
            domain = str(payload.get("domain", ""))
            service = str(payload.get("service", ""))
            if domain and service and is_destructive_service(domain, service):
                require_confirm(
                    args,
                    f"WebSocket call_service {domain}.{service} is destructive",
                )
        client = ws_connect(token, base_url, timeout)
        try:
            return client.call({"type": args.ws_type, **payload})
        finally:
            client.close()

    client = ws_connect(token, base_url, timeout)
    try:
        if args.command == "entity-registry":
            entity_id = validate_entity_id(args.entity_id)
            return client.call({"type": "config/entity_registry/get", "entity_id": entity_id})

        if args.command == "entity-registry-list":
            resp = client.call({"type": "config/entity_registry/list_for_display"})
            result = resp.get("result") if isinstance(resp, dict) else resp
            entities = []
            if isinstance(result, dict):
                entities = result.get("entities") or []
            elif isinstance(result, list):
                entities = result
            if args.search:
                needle = args.search.lower()
                filtered = []
                for ent in entities:
                    if not isinstance(ent, dict):
                        continue
                    blob = " ".join(str(ent.get(k, "")) for k in ("ei", "en", "pl", "entity_id", "name")).lower()
                    if needle in blob:
                        filtered.append(ent)
                entities = filtered
            limit = clamp_limit(args.limit, default=100, lo=1, hi=5000)
            return {
                "count": len(entities),
                "returned": min(len(entities), limit),
                "entities": entities[:limit],
            }

        if args.command == "device-registry":
            resp = client.call({"type": "config/device_registry/list"})
            devices = resp.get("result") if isinstance(resp, dict) else resp
            if not isinstance(devices, list):
                devices = []
            if args.search:
                needle = args.search.lower()
                devices = [
                    d for d in devices
                    if isinstance(d, dict)
                    and needle in json.dumps(d, ensure_ascii=False).lower()
                ]
            limit = clamp_limit(args.limit, default=100, lo=1, hi=5000)
            return {
                "count": len(devices),
                "returned": min(len(devices), limit),
                "devices": devices[:limit],
            }

        if args.command == "area-registry":
            return client.call({"type": "config/area_registry/list"})

        if args.command == "config-entries":
            resp = client.call({"type": "config_entries/get"})
            entries = resp.get("result") if isinstance(resp, dict) else resp
            if not isinstance(entries, list):
                return resp
            if args.domain:
                domain = validate_name(args.domain, "domain")
                entries = [
                    e for e in entries
                    if isinstance(e, dict) and e.get("domain") == domain
                ]
            if getattr(args, "search", None):
                needle = args.search.lower()
                entries = [
                    e for e in entries
                    if isinstance(e, dict)
                    and needle
                    in " ".join(
                        str(e.get(k, ""))
                        for k in ("domain", "title", "entry_id", "unique_id", "source")
                    ).lower()
                ]
            return {"count": len(entries), "entries": entries}

        if args.command == "automation-list":
            # Prefer entity registry (has unique_id == automation config id).
            reg = client.call({"type": "config/entity_registry/list"})
            rows = reg.get("result") if isinstance(reg, dict) else reg
            if not isinstance(rows, list):
                # Fallback shape
                rows = []
            items = []
            for ent in rows:
                if not isinstance(ent, dict):
                    continue
                eid = str(ent.get("entity_id") or "")
                if not eid.startswith("automation."):
                    continue
                items.append({
                    "entity_id": eid,
                    "automation_id": ent.get("unique_id"),
                    "name": ent.get("name") or ent.get("original_name"),
                    "disabled_by": ent.get("disabled_by"),
                    "platform": ent.get("platform"),
                })
            if args.search:
                needle = args.search.lower()
                items = [
                    i for i in items
                    if needle in " ".join(str(v) for v in i.values()).lower()
                ]
            limit = clamp_limit(args.limit, default=200, lo=1, hi=5000)
            return {
                "count": len(items),
                "returned": min(len(items), limit),
                "automations": items[:limit],
                "_note": (
                    "automation_id is the config key for automation-get/set/delete. "
                    "YAML automations without an id may be missing unique_id."
                ),
            }

        if args.command == "system-log":
            resp = client.call({"type": "system_log/list"})
            records = resp.get("result") if isinstance(resp, dict) else resp
            if not isinstance(records, list):
                return resp
            limit = clamp_limit(args.limit, default=50, lo=1, hi=500)
            return {
                "count": len(records),
                "returned": min(len(records), limit),
                "records": records[-limit:],
            }

        if args.command == "repairs":
            return client.call({"type": "repairs/list_issues"})

        if args.command == "automation-config":
            entity_id = validate_entity_id(args.entity_id)
            entry = client.call({
                "type": "config/entity_registry/get",
                "entity_id": entity_id,
            })
            out: dict[str, Any] = {
                "entity_id": entity_id,
                "entity_registry": entry.get("result") if entry.get("success") else entry,
            }
            domain, item_id = split_entity_id(entity_id)
            traces = client.call({
                "type": "trace/list",
                "domain": domain,
                "item_id": item_id,
            })
            if traces.get("success") and isinstance(traces.get("result"), list):
                trace_list = traces["result"]
                out["traces_count"] = len(trace_list)
                if trace_list and isinstance(trace_list[0], dict) and "run_id" in trace_list[0]:
                    detail = client.call({
                        "type": "trace/get",
                        "domain": domain,
                        "item_id": item_id,
                        "run_id": trace_list[0]["run_id"],
                    })
                    if detail.get("success"):
                        td = detail.get("result") or {}
                        out["latest_run_id"] = trace_list[0]["run_id"]
                        if isinstance(td, dict):
                            if "config" in td:
                                out["config"] = td["config"]
                            if "trace" in td and isinstance(td["trace"], dict):
                                steps = []
                                for key, val in td["trace"].items():
                                    if isinstance(val, dict):
                                        step = {"path": val.get("path", key), "result": val.get("result")}
                                        if "error" in val:
                                            step["error"] = val["error"]
                                        steps.append(step)
                                out["latest_trace_steps"] = steps
            else:
                out["traces"] = traces
            out["_note"] = (
                "UI-created automations store YAML in .storage/automations; "
                "use automation-trace for execution path (triggers/conditions/actions)."
            )
            return out

        if args.command == "automation-trace":
            entity_id = validate_entity_id(args.entity_id)
            domain, item_id = split_entity_id(entity_id)
            limit = clamp_limit(args.limit, default=5, lo=1, hi=50)

            if args.run_id:
                detail = client.call({
                    "type": "trace/get",
                    "domain": domain,
                    "item_id": item_id,
                    "run_id": args.run_id,
                })
                return detail

            traces = client.call({
                "type": "trace/list",
                "domain": domain,
                "item_id": item_id,
            })
            if not traces.get("success"):
                return traces
            trace_list = traces.get("result") or []
            if not isinstance(trace_list, list):
                return traces

            result_traces = []
            for t in trace_list[:limit]:
                if not isinstance(t, dict) or "run_id" not in t:
                    continue
                entry: dict[str, Any] = {
                    "run_id": t["run_id"],
                    "timestamp": t.get("timestamp"),
                    "state": t.get("state"),
                    "script_execution": t.get("script_execution"),
                    "trigger": t.get("trigger"),
                }
                if args.include_config:
                    detail = client.call({
                        "type": "trace/get",
                        "domain": domain,
                        "item_id": item_id,
                        "run_id": t["run_id"],
                    })
                    if detail.get("success"):
                        td = detail.get("result") or {}
                        if isinstance(td, dict):
                            if "config" in td:
                                entry["config"] = td["config"]
                            if "trace" in td and isinstance(td["trace"], dict):
                                steps = {}
                                for k, v in td["trace"].items():
                                    if isinstance(v, dict):
                                        steps[k] = {
                                            "path": v.get("path", k),
                                            "result": (v.get("result") or {}).get("result")
                                            if isinstance(v.get("result"), dict)
                                            else v.get("result"),
                                        }
                                        if "error" in v:
                                            steps[k]["error"] = str(v["error"])
                                entry["steps"] = steps
                result_traces.append(entry)
            return {
                "entity_id": entity_id,
                "total_traces": len(trace_list),
                "returned": len(result_traces),
                "traces": result_traces,
            }

        raise RuntimeError(f"unsupported WebSocket command: {args.command}")
    finally:
        client.close()


def main() -> int:
    args = build_parser().parse_args()
    token = os.environ.get("HOME_ASSISTANT_TOKEN", "")
    base_url = os.environ.get("HOME_ASSISTANT_URL", "")
    if not token:
        print(
            "HOME_ASSISTANT_TOKEN is unavailable in this agent session. "
            "Do not resolve or reload it manually. Start a fresh skills snapshot "
            "with /reset soft or /new, then retry.",
            file=sys.stderr,
        )
        return 2
    if not base_url:
        print(
            "HOME_ASSISTANT_URL is unavailable in this agent session. "
            "Start a fresh skills snapshot with /reset soft or /new, then retry.",
            file=sys.stderr,
        )
        return 2

    try:
        ws_commands = {
            "ws",
            "automation-config",
            "automation-trace",
            "automation-list",
            "entity-registry",
            "entity-registry-list",
            "device-registry",
            "area-registry",
            "config-entries",
            "system-log",
            "repairs",
        }
        if args.command in ws_commands:
            result = run_ws(args, token, base_url)
            emit(result, token)
            return 0

        client = HomeAssistant(base_url, token, args.timeout)

        if args.command == "status":
            result = client.request("GET", "/api/")
        elif args.command == "config":
            raw = client.request("GET", "/api/config")
            result = summarize_config(raw if isinstance(raw, dict) else {})
        elif args.command == "components":
            result = client.request("GET", "/api/components")
        elif args.command == "events":
            result = client.request("GET", "/api/events")
        elif args.command == "services":
            result = client.request("GET", "/api/services")
        elif args.command == "errors":
            result = tail_lines(
                client.request("GET", "/api/error_log", accept_text=True),
                args.tail_lines,
            )
        elif args.command == "logbook":
            limit = clamp_limit(args.limit, default=200)
            entries = client.request("GET", logbook_path(args))
            if not isinstance(entries, list):
                raise RuntimeError("Home Assistant returned an invalid logbook response")
            selected = entries[-limit:]
            result = {
                "count": len(entries),
                "returned": len(selected),
                "entries": selected,
            }
        elif args.command == "history":
            result = client.request("GET", history_path(args))
        elif args.command in {"unavailable", "states"}:
            states = client.request("GET", "/api/states")
            if not isinstance(states, list):
                raise RuntimeError("invalid states response")
            if args.command == "unavailable":
                selected = [
                    item for item in states
                    if isinstance(item, dict) and item.get("state") in {"unavailable", "unknown"}
                ]
                limit = 200
                full = False
            else:
                selected = [item for item in states if isinstance(item, dict)]
                if args.domain:
                    domain = validate_name(args.domain, "domain")
                    selected = [
                        item for item in selected
                        if str(item.get("entity_id", "")).startswith(f"{domain}.")
                    ]
                if args.state:
                    selected = [item for item in selected if item.get("state") == args.state]
                if args.search:
                    needle = args.search.lower()
                    filtered = []
                    for item in selected:
                        eid = str(item.get("entity_id", "")).lower()
                        fname = str((item.get("attributes") or {}).get("friendly_name", "")).lower()
                        if needle in eid or needle in fname:
                            filtered.append(item)
                    selected = filtered
                limit = clamp_limit(args.limit, default=200)
                full = bool(args.full)
            if full:
                entities_out: list[Any] = selected[:limit]
            else:
                entities_out = [summarize_state(item) for item in selected[:limit]]
            result = {
                "count": len(selected),
                "returned": min(len(selected), limit),
                "entities": entities_out,
            }
        elif args.command == "state":
            entity_id = validate_entity_id(args.entity_id)
            raw = client.request("GET", f"/api/states/{quote(entity_id, safe='.')}")
            if args.full or not isinstance(raw, dict):
                result = raw
            else:
                result = summarize_state(raw)
                result["attributes"] = raw.get("attributes")
        elif args.command == "check-config":
            result = client.request("POST", "/api/config/core/check_config")
        elif args.command == "template":
            if args.template and args.template_file:
                raise ValueError("use either --template or --template-file")
            if args.template_file:
                path = Path(args.template_file)
                if path.stat().st_size > MAX_WRITE_BYTES:
                    raise ValueError("template file exceeds the 256 KiB limit")
                template = path.read_text(encoding="utf-8")
            elif args.template:
                template = args.template
            else:
                raise ValueError("provide --template or --template-file")
            result = client.request(
                "POST",
                "/api/template",
                {"template": template},
                accept_text=True,
            )
        elif args.command == "calendars":
            result = client.request("GET", "/api/calendars")
        elif args.command == "calendar":
            entity_id = validate_entity_id(args.entity_id)
            start = validate_timestamp(args.start, "--start")
            end = validate_timestamp(args.end, "--end")
            path = (
                f"/api/calendars/{quote(entity_id, safe='.')}"
                f"?{urlencode({'start': start, 'end': end})}"
            )
            result = client.request("GET", path)
        elif args.command == "triage":
            result = command_triage(client)
        elif args.command == "automation-get":
            auto_id = validate_config_id(args.automation_id, "automation_id")
            result = client.request(
                "GET",
                f"/api/config/automation/config/{quote(auto_id, safe='')}",
            )
        elif args.command == "automation-set":
            auto_id = validate_config_id(args.automation_id, "automation_id")
            if args.data is None and args.data_file is None:
                raise ValueError("automation-set requires --data or --data-file")
            payload = parse_json_payload(args)
            # HA stores id from the URL key; keep body consistent when possible.
            if "id" not in payload:
                payload = {**payload, "id": auto_id}
            result = client.request(
                "POST",
                f"/api/config/automation/config/{quote(auto_id, safe='')}",
                payload,
            )
        elif args.command == "automation-delete":
            require_confirm(
                args,
                f"automation-delete permanently removes automation {args.automation_id!r}",
            )
            auto_id = validate_config_id(args.automation_id, "automation_id")
            result = client.request(
                "DELETE",
                f"/api/config/automation/config/{quote(auto_id, safe='')}",
            )
        elif args.command == "config-entry-reload":
            entry_id = validate_config_id(args.entry_id, "entry_id")
            result = client.request(
                "POST",
                f"/api/config/config_entries/entry/{quote(entry_id, safe='')}/reload",
            )
        elif args.command == "config-entry-delete":
            require_confirm(
                args,
                f"config-entry-delete removes integration entry {args.entry_id!r}",
            )
            entry_id = validate_config_id(args.entry_id, "entry_id")
            result = client.request(
                "DELETE",
                f"/api/config/config_entries/entry/{quote(entry_id, safe='')}",
            )
        elif args.command == "config-flow-handlers":
            path = "/api/config/config_entries/flow_handlers"
            if args.flow_type:
                path += f"?{urlencode({'type': args.flow_type})}"
            result = client.request("GET", path)
        elif args.command == "config-flow-start":
            handler = args.handler
            if not handler or not re.fullmatch(r"[a-zA-Z0-9_.:-]+", handler):
                raise ValueError("invalid --handler")
            payload = parse_json_object(args.data, label="--data")
            body: dict[str, Any] = {"handler": handler, **payload}
            if args.entry_id:
                body["entry_id"] = validate_config_id(args.entry_id, "entry_id")
            result = client.request("POST", "/api/config/config_entries/flow", body)
        elif args.command == "config-flow-get":
            flow_id = validate_config_id(args.flow_id, "flow_id")
            result = client.request(
                "GET",
                f"/api/config/config_entries/flow/{quote(flow_id, safe='')}",
            )
        elif args.command == "config-flow-step":
            flow_id = validate_config_id(args.flow_id, "flow_id")
            payload = parse_json_payload(args)
            result = client.request(
                "POST",
                f"/api/config/config_entries/flow/{quote(flow_id, safe='')}",
                payload,
            )
        elif args.command == "config-options-start":
            entry_id = validate_config_id(args.entry_id, "entry_id")
            # Options flow: handler is the config entry id.
            result = client.request(
                "POST",
                "/api/config/config_entries/options/flow",
                {"handler": entry_id},
            )
        elif args.command == "config-options-get":
            flow_id = validate_config_id(args.flow_id, "flow_id")
            result = client.request(
                "GET",
                f"/api/config/config_entries/options/flow/{quote(flow_id, safe='')}",
            )
        elif args.command == "config-options-step":
            flow_id = validate_config_id(args.flow_id, "flow_id")
            payload = parse_json_payload(args)
            result = client.request(
                "POST",
                f"/api/config/config_entries/options/flow/{quote(flow_id, safe='')}",
                payload,
            )
        elif args.command == "call-service":
            domain = validate_name(args.domain, "domain")
            service = validate_name(args.service, "service")
            if is_destructive_service(domain, service):
                require_confirm(args, f"service {domain}.{service} is destructive")
            payload = parse_json_payload(args)
            path = f"/api/services/{quote(domain)}/{quote(service)}"
            if args.return_response:
                path += "?return_response"
            result = client.request("POST", path, payload)
        elif args.command == "set-state":
            entity_id = validate_entity_id(args.entity_id)
            attributes = parse_json_object(args.attributes, label="--attributes")
            result = client.request(
                "POST",
                f"/api/states/{quote(entity_id, safe='.')}",
                {"state": args.state, "attributes": attributes},
            )
        elif args.command == "delete-state":
            require_confirm(args, "delete-state permanently removes an entity from the state machine")
            entity_id = validate_entity_id(args.entity_id)
            result = client.request("DELETE", f"/api/states/{quote(entity_id, safe='.')}")
        elif args.command == "fire-event":
            if not EVENT_RE.fullmatch(args.event_type):
                raise ValueError("invalid event_type")
            payload = parse_json_object(args.data, label="--data")
            result = client.request(
                "POST",
                f"/api/events/{quote(args.event_type, safe='._-')}",
                payload,
            )
        elif args.command == "intent":
            payload = parse_json_object(args.data, label="--data")
            result = client.request(
                "POST",
                "/api/intent/handle",
                {"name": args.name, "data": payload},
            )
        elif args.command == "restart":
            require_confirm(args, "homeassistant.restart restarts the whole instance")
            result = client.request("POST", "/api/services/homeassistant/restart", {})
        elif args.command == "stop":
            require_confirm(args, "homeassistant.stop shuts down Home Assistant")
            result = client.request("POST", "/api/services/homeassistant/stop", {})
        elif args.command == "reload":
            what = args.what.lower()
            if what in RELOAD_MAP:
                domain, service = RELOAD_MAP[what]
            elif "." in what:
                domain, service = what.split(".", 1)
                domain = validate_name(domain, "domain")
                service = validate_name(service, "service")
            else:
                domain = validate_name(what, "domain")
                service = "reload"
            result = client.request(
                "POST",
                f"/api/services/{quote(domain)}/{quote(service)}",
                {},
            )
        elif args.command == "find-phone":
            device = validate_name(args.device, "device")
            service_name = f"mobile_app_{device}"
            svc_path = f"/api/services/notify/{quote(service_name)}"
            client.request("POST", svc_path, {
                "message": "command_ringer_mode",
                "title": "command_ringer_mode",
                "data": {
                    "command": "normal",
                    "channel": "alarm_stream",
                    "importance": "high",
                },
            })
            result = client.request("POST", svc_path, {
                "message": args.message,
                "title": "Find my phone",
                "data": {
                    "channel": "alarm_stream",
                    "media_stream": "alarm_stream_max",
                    "importance": "high",
                    "priority": "high",
                    "ttl": 0,
                    "tag": "Find",
                    "notification_icon": "mdi:cellphone-wireless",
                    "color": "#66baf0",
                },
            })
        elif args.command == "rest":
            method = args.method.upper()
            path = args.path
            if not path.startswith("/api"):
                raise ValueError("path must start with /api")
            if is_destructive_rest(method, path):
                require_confirm(args, f"REST {method} {path} is destructive")
            payload = None
            if method in {"POST", "PUT"}:
                payload = parse_json_payload(args)
            result = client.request(
                method,
                path,
                payload,
                accept_text=bool(args.text),
            )
        else:
            raise RuntimeError(f"unsupported command: {args.command}")

        emit(result, token)
        return 0

    except HTTPError as exc:
        body = exc.read(32_768).decode("utf-8", "replace") if exc.fp else ""
        error_log_unavailable = args.command == "errors" and exc.code == 404
        if error_log_unavailable:
            message = describe_error_log_failure(exc)
        else:
            message = f"Home Assistant API HTTP {exc.code}"
        if exc.code in {301, 302, 303, 307, 308}:
            message += ": redirect blocked"
        if body.strip() and not error_log_unavailable:
            message += f": {redact(body.strip(), token)}"
        print(message, file=sys.stderr)
        return 3
    except (ConnectionError, ConnectionRefusedError, ConnectionResetError) as exc:
        print(
            f"Home Assistant WebSocket connection error: {redact(str(exc), token)}",
            file=sys.stderr,
        )
        return 4
    except (URLError, ssl.SSLError, TimeoutError, socket.timeout) as exc:
        print(f"Home Assistant connection failed: {redact(str(exc), token)}", file=sys.stderr)
        return 4
    except (ValueError, RuntimeError, json.JSONDecodeError, OSError, KeyError) as exc:
        print(f"Home Assistant client error: {redact(str(exc), token)}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
