#!/usr/bin/env python3
"""Offline unit tests for ha_api.py (no real Home Assistant or token)."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ha_api", ROOT / "ha_api.py")
assert spec and spec.loader
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)


class UrlValidationTests(unittest.TestCase):
    def test_https_ok(self):
        p = ha.validate_base_url("https://ha.example:8123")
        self.assertEqual(p.hostname, "ha.example")
        self.assertEqual(p.port, 8123)

    def test_http_rejected_rest(self):
        with self.assertRaises(ValueError):
            ha.HomeAssistant("http://ha.example", "token-value-long", 5)

    def test_http_rejected_ws(self):
        with self.assertRaises(ValueError):
            ha.HomeAssistantWS("http://ha.example", "token-value-long", 5)


class DestructiveClassifierTests(unittest.TestCase):
    def test_normal_services_free(self):
        for domain, service in (
            ("light", "turn_on"),
            ("automation", "trigger"),
            ("script", "my_script"),
            ("homeassistant", "reload_all"),
            ("homeassistant", "reload_core_config"),
            ("automation", "reload"),
            ("switch", "turn_off"),
            ("notify", "mobile_app_phone"),
        ):
            self.assertFalse(
                ha.is_destructive_service(domain, service),
                f"{domain}.{service}",
            )

    def test_destructive_services(self):
        for domain, service in (
            ("homeassistant", "stop"),
            ("homeassistant", "restart"),
            ("backup", "remove"),
            ("person", "delete"),
            ("foo", "disable"),
            ("foo", "purge"),
        ):
            self.assertTrue(
                ha.is_destructive_service(domain, service),
                f"{domain}.{service}",
            )

    def test_ws_types(self):
        self.assertFalse(ha.is_destructive_ws_type("call_service"))
        self.assertFalse(ha.is_destructive_ws_type("trace/list"))
        self.assertTrue(ha.is_destructive_ws_type("config/entity_registry/remove"))
        self.assertTrue(ha.is_destructive_ws_type("config_entries/disable"))


class FrameTests(unittest.TestCase):
    def test_client_frames_masked(self):
        class Rec:
            def __init__(self):
                self.sent = bytearray()

            def sendall(self, b):
                self.sent.extend(b)

        ws = ha.HomeAssistantWS("https://ha.example:8123", "token-value-long", 5)
        ws._sock = Rec()
        ws._send({"type": "ping", "id": 1})
        frame = bytes(ws._sock.sent)
        self.assertEqual(frame[0], 0x81)
        self.assertTrue(frame[1] & 0x80)
        plen = frame[1] & 0x7F
        mask = frame[2:6]
        masked = frame[6 : 6 + plen]
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(masked))
        self.assertEqual(json.loads(payload)["type"], "ping")

    def test_oversized_frame_rejected(self):
        class Peer:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def recv(self, n):
                return self.chunks.pop(0) if self.chunks else b""

            def close(self):
                pass

        header = bytes([0x81, 127]) + struct.pack(">Q", ha.MAX_RESPONSE_BYTES + 1)
        ws = ha.HomeAssistantWS("https://ha.example:8123", "token-value-long", 5)
        ws._sock = Peer([header])
        with self.assertRaises(RuntimeError):
            ws._recv()


class CliGateTests(unittest.TestCase):
    def _run(self, argv, env=None, stub_ws=True, stub_rest=False):
        env = env or {
            "HOME_ASSISTANT_TOKEN": "token-value-long",
            "HOME_ASSISTANT_URL": "https://ha.example:8123",
        }
        calls: list[dict] = []

        class StubWS:
            def call(self, msg):
                calls.append(msg)
                return {"success": True, "result": {}, "id": msg.get("id"), "type": "result"}

            def close(self):
                pass

        rest_calls: list[tuple] = []

        class StubREST:
            def request(self, method, path, payload=None, **kwargs):
                rest_calls.append((method, path, payload))
                return {"ok": True}

        err, out = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch.object(sys, "argv", ["ha_api.py", *argv]):
                with mock.patch.object(sys, "stderr", err), mock.patch.object(sys, "stdout", out):
                    if stub_ws:
                        with mock.patch.object(ha, "ws_connect", return_value=StubWS()):
                            if stub_rest:
                                with mock.patch.object(ha, "HomeAssistant", return_value=StubREST()):
                                    code = ha.main()
                            else:
                                code = ha.main()
                    else:
                        code = ha.main()
        return code, out.getvalue(), err.getvalue(), calls, rest_calls

    def test_call_service_free(self):
        code, _, err, _, rest = self._run(
            ["call-service", "light", "turn_on", "--data", '{"entity_id":"light.x"}'],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "POST")
        self.assertIn("/api/services/light/turn_on", rest[0][1])

    def test_reload_free(self):
        code, _, err, _, rest = self._run(["reload", "automations"], stub_rest=True)
        self.assertEqual(code, 0, err)
        self.assertIn("/api/services/automation/reload", rest[0][1])

    def test_restart_requires_confirm(self):
        code, _, err, _, rest = self._run(["restart"], stub_rest=True)
        self.assertEqual(code, 5)
        self.assertIn("confirm", err.lower())
        self.assertEqual(rest, [])

    def test_call_service_restart_requires_confirm(self):
        code, _, err, _, rest = self._run(
            ["call-service", "homeassistant", "restart", "--data", "{}"],
            stub_rest=True,
        )
        self.assertEqual(code, 5)
        self.assertIn("confirm", err.lower())
        self.assertEqual(rest, [])

    def test_delete_state_requires_confirm(self):
        code, _, err, _, rest = self._run(
            ["delete-state", "sensor.x"],
            stub_rest=True,
        )
        self.assertEqual(code, 5)
        self.assertIn("confirm", err.lower())
        self.assertEqual(rest, [])

    def test_ws_call_service_free(self):
        code, _, err, calls, _ = self._run(
            [
                "ws",
                "call_service",
                "--data",
                '{"domain":"light","service":"turn_on","target":{"entity_id":"light.x"}}',
            ]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(calls[0]["type"], "call_service")

    def test_ws_remove_requires_confirm(self):
        code, _, err, calls, _ = self._run(
            [
                "ws",
                "config/entity_registry/remove",
                "--data",
                '{"entity_id":"sensor.x"}',
            ]
        )
        self.assertEqual(code, 5)
        self.assertIn("confirm", err.lower())
        self.assertEqual(calls, [])

    def test_ws_type_override_blocked(self):
        code, _, err, calls, _ = self._run(
            ["ws", "trace/list", "--data", '{"type":"fire_event","event_type":"x"}']
        )
        self.assertEqual(code, 5)
        self.assertIn("type", err.lower())
        self.assertEqual(calls, [])

    def test_http_url_rejected_in_main(self):
        code, _, err, _, _ = self._run(
            ["status"],
            env={
                "HOME_ASSISTANT_TOKEN": "token-value-long",
                "HOME_ASSISTANT_URL": "http://127.0.0.1:9",
            },
            stub_ws=False,
        )
        self.assertEqual(code, 5)
        self.assertIn("https", err.lower())

    def test_automation_get_set_delete(self):
        code, _, err, _, rest = self._run(
            ["automation-get", "abc123"],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "GET")
        self.assertIn("/api/config/automation/config/abc123", rest[0][1])

        code, _, err, _, rest = self._run(
            [
                "automation-set",
                "abc123",
                "--data",
                '{"alias":"Test","triggers":[],"actions":[]}',
            ],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "POST")
        self.assertEqual(rest[0][2].get("id"), "abc123")

        code, _, err, _, rest = self._run(
            ["automation-delete", "abc123"],
            stub_rest=True,
        )
        self.assertEqual(code, 5)
        self.assertIn("confirm", err.lower())
        self.assertEqual(rest, [])

        code, _, err, _, rest = self._run(
            ["automation-delete", "abc123", "--confirm"],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "DELETE")

    def test_config_entry_reload_and_flow(self):
        code, _, err, _, rest = self._run(
            ["config-entry-reload", "entry_xyz"],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "POST")
        self.assertIn("/entry/entry_xyz/reload", rest[0][1])

        code, _, err, _, rest = self._run(
            ["config-flow-start", "--handler", "mqtt"],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "POST")
        self.assertEqual(rest[0][1], "/api/config/config_entries/flow")
        self.assertEqual(rest[0][2]["handler"], "mqtt")

        code, _, err, _, rest = self._run(
            ["config-flow-step", "flow99", "--data", '{"host":"192.0.2.1"}'],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][0], "POST")
        self.assertIn("/flow/flow99", rest[0][1])
        self.assertEqual(rest[0][2]["host"], "192.0.2.1")

        code, _, err, _, rest = self._run(
            ["config-options-start", "entry_xyz"],
            stub_rest=True,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rest[0][2]["handler"], "entry_xyz")


if __name__ == "__main__":
    unittest.main()
