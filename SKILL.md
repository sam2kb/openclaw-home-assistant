---
name: home-assistant
description: Full-admin operate, diagnose, and repair the user's Home Assistant instance through its HTTPS REST and WebSocket APIs. Use for health checks, logs, history, entity/device/area registry, automation traces, service calls, reloads, restarts, notifications, repairs, config validation, and any other action the long-lived access token allows.
metadata: {"openclaw":{"requires":{"bins":["python3"],"env":["HOME_ASSISTANT_URL","HOME_ASSISTANT_TOKEN"]},"primaryEnv":"HOME_ASSISTANT_TOKEN"}}
---

# Home Assistant

Full-admin skill for the user's Home Assistant. Scope is whatever the injected
long-lived access token permits (ideally an admin user). Prefer the bundled
client over ad-hoc `curl`.

```bash
python3 {baseDir}/scripts/ha_api.py <command> [options]
```

## Credentials and transport

- `HOME_ASSISTANT_TOKEN` and `HOME_ASSISTANT_URL` are injected by OpenClaw.
- Never print, inspect, resolve, or pass the token manually.
- `HOME_ASSISTANT_URL` **must** be `https://…` (no embedded credentials, query, or fragment). REST and WebSocket share this rule; the bearer token is never sent in cleartext.
- If either env var is missing, stop. Tell the user to send `/reset soft` or `/new` as a standalone chat message so OpenClaw rebuilds the skills snapshot, then retry.

References:

- REST: <https://developers.home-assistant.io/docs/api/rest/>
- WebSocket: <https://developers.home-assistant.io/docs/api/websocket/>

## Safety model

Everyday operation is the point of this skill. **Do not** ask for confirmation
before normal service calls, automation triggers, reloads, notifications, or
state updates.

| Class | Examples | Rule |
|---|---|---|
| **Operate freely** | `call-service` (lights, covers, `automation.trigger`, scripts…), `reload`, `set-state`, `fire-event`, `intent`, `find-phone`, templates, all reads | Run when the user asked for that outcome. Prefer a quick state check first when useful; no `--confirm`. |
| **Destructive — need `--confirm`** | `restart`, `stop`, `delete-state`, services named remove/delete/disable/purge, registry/config-entry removal or disable, raw REST `DELETE` | Explain the irreversible or instance-wide effect, get explicit approval, then pass `--confirm`. |

Protected examples:

- `homeassistant.restart` / `homeassistant.stop` (and the `restart` / `stop` commands)
- Deleting entities (`delete-state`, `*.remove`, `*.delete`)
- Disabling integrations / entities / config entries
- Clearing system log, removing backups, permanent registry edits

**Not** protected (run freely): turning devices on/off, triggering automations,
running scripts, reloading automations/core/scripts, rendering templates,
checking config, ringing a phone.

Still: never claim a fix succeeded without a follow-up read. Bound chat output.
Supervisor/host/OS work outside the token is out of scope—say so.

---

## Start here

```bash
python3 {baseDir}/scripts/ha_api.py triage
python3 {baseDir}/scripts/ha_api.py status
python3 {baseDir}/scripts/ha_api.py config
python3 {baseDir}/scripts/ha_api.py check-config
```

`triage` returns API health, summarized config, unavailable/unknown entities,
and a bounded error-log tail (or an explanation when `/api/error_log` is 404
on Supervisor-managed installs).

---

## Read: entities, services, components

```bash
python3 {baseDir}/scripts/ha_api.py states --domain light --limit 100
python3 {baseDir}/scripts/ha_api.py states --search kitchen --full
python3 {baseDir}/scripts/ha_api.py state light.kitchen --full
python3 {baseDir}/scripts/ha_api.py unavailable
python3 {baseDir}/scripts/ha_api.py services
python3 {baseDir}/scripts/ha_api.py components
python3 {baseDir}/scripts/ha_api.py events
```

---

## Read: logs, history, templates

```bash
python3 {baseDir}/scripts/ha_api.py errors --tail-lines 200
python3 {baseDir}/scripts/ha_api.py system-log --limit 50
python3 {baseDir}/scripts/ha_api.py logbook --hours 6 --limit 100
python3 {baseDir}/scripts/ha_api.py logbook --entity light.kitchen --hours 24
python3 {baseDir}/scripts/ha_api.py history --entity sensor.temp,sensor.humidity --minimal
python3 {baseDir}/scripts/ha_api.py template --template "{{ states('sensor.temp') }}"
```

Semantics:

- `errors` → `GET /api/error_log` (plaintext Core file log for this session). Often **404** on Supervisor installs; that is normal, not a bad token.
- `system-log` → WebSocket `system_log/list` (structured logger buffer; prefer when file log is missing).
- `logbook` → activity history, **not** an error log.
- `history` requires `--entity` (HA REST requirement).

---

## Read: registries, config entries, repairs, calendars

```bash
python3 {baseDir}/scripts/ha_api.py entity-registry light.kitchen
python3 {baseDir}/scripts/ha_api.py entity-registry-list --search kitchen --limit 50
python3 {baseDir}/scripts/ha_api.py device-registry --search hue --limit 50
python3 {baseDir}/scripts/ha_api.py area-registry
python3 {baseDir}/scripts/ha_api.py config-entries --domain mqtt
python3 {baseDir}/scripts/ha_api.py repairs
python3 {baseDir}/scripts/ha_api.py calendars
python3 {baseDir}/scripts/ha_api.py calendar calendar.holidays \
  --start 2026-01-01T00:00:00+00:00 --end 2026-02-01T00:00:00+00:00
```

---

## Read: automation debugging (WebSocket)

Use traces for the real execution path (trigger → condition → action).

```bash
python3 {baseDir}/scripts/ha_api.py automation-config automation.example
python3 {baseDir}/scripts/ha_api.py automation-trace automation.example \
  --include-config --limit 3
python3 {baseDir}/scripts/ha_api.py automation-trace automation.example \
  --run-id RUN_ID
```

---

## Automations: list / get / set / delete (config API)

UI and id-based automations are stored under config keys (often the entity
registry `unique_id`). Discover ids, pull full config, edit, test, reload.

```bash
# Find automations and their config ids
python3 {baseDir}/scripts/ha_api.py automation-list --search shade --limit 50

# Full editable config for one automation
python3 {baseDir}/scripts/ha_api.py automation-get AUTOMATION_ID

# Create or replace (HA validates + reloads that automation)
python3 {baseDir}/scripts/ha_api.py automation-set AUTOMATION_ID \
  --data-file /tmp/automation.json

# Or inline JSON
python3 {baseDir}/scripts/ha_api.py automation-set AUTOMATION_ID \
  --data '{"alias":"Example","triggers":[...],"actions":[...]}'

# Remove permanently
python3 {baseDir}/scripts/ha_api.py automation-delete AUTOMATION_ID --confirm

# After broader YAML/core changes
python3 {baseDir}/scripts/ha_api.py reload automations
```

Typical loop: `automation-list` → `automation-get` → edit → `automation-set` →
`automation-trace` / `state automation.…` to verify. Prefer `automation-set`
over hand-editing host files. Automations without an `id` may not appear with
a usable `automation_id`.

---

## Integrations: list, reload, config flows, options

```bash
# List installed integrations (config entries)
python3 {baseDir}/scripts/ha_api.py config-entries
python3 {baseDir}/scripts/ha_api.py config-entries --domain mqtt
python3 {baseDir}/scripts/ha_api.py config-entries --search hue

# Reload one integration after a fix (no full restart)
python3 {baseDir}/scripts/ha_api.py config-entry-reload ENTRY_ID

# Remove an integration (destructive)
python3 {baseDir}/scripts/ha_api.py config-entry-delete ENTRY_ID --confirm
```

### Install or reconfigure (config flow)

Flows are multi-step. Start → inspect `data_schema` / `type` → submit
`user_input` until `type` is `create_entry` or `abort`.

```bash
# What can be installed
python3 {baseDir}/scripts/ha_api.py config-flow-handlers
python3 {baseDir}/scripts/ha_api.py config-flow-handlers --type integration

# Start install (handler = domain, e.g. mqtt)
python3 {baseDir}/scripts/ha_api.py config-flow-start --handler mqtt

# Reconfigure an existing entry
python3 {baseDir}/scripts/ha_api.py config-flow-start --handler mqtt --entry-id ENTRY_ID

# Inspect current step (fields to fill)
python3 {baseDir}/scripts/ha_api.py config-flow-get FLOW_ID

# Submit answers for this step (prefill params here)
python3 {baseDir}/scripts/ha_api.py config-flow-step FLOW_ID \
  --data '{"host":"192.0.2.10","port":1883}'
```

### Edit integration options (options flow)

```bash
python3 {baseDir}/scripts/ha_api.py config-options-start ENTRY_ID
python3 {baseDir}/scripts/ha_api.py config-options-get FLOW_ID
python3 {baseDir}/scripts/ha_api.py config-options-step FLOW_ID \
  --data '{"some_option":true}'
python3 {baseDir}/scripts/ha_api.py config-entry-reload ENTRY_ID
```

Typical repair loop: `system-log` / `repairs` / `config-entries` →
`config-options-start` or `config-flow-start --entry-id` → fill steps →
`config-entry-reload` (or `reload` / `restart --confirm` if required).

---

## Operate: services, state, events, intents

When the user asks to do something with HA, just do it (within the token).

```bash
python3 {baseDir}/scripts/ha_api.py call-service light turn_on \
  --data '{"entity_id":"light.kitchen","brightness":128}'

python3 {baseDir}/scripts/ha_api.py call-service automation trigger \
  --data '{"entity_id":"automation.example"}'

python3 {baseDir}/scripts/ha_api.py call-service script my_script --data '{}'

python3 {baseDir}/scripts/ha_api.py call-service weather get_forecasts \
  --data '{"entity_id":"weather.home","type":"daily"}' \
  --return-response

python3 {baseDir}/scripts/ha_api.py set-state sensor.custom --state "42" \
  --attributes '{"unit_of_measurement":"°C"}'

python3 {baseDir}/scripts/ha_api.py fire-event my_custom_event \
  --data '{"source":"openclaw"}'

python3 {baseDir}/scripts/ha_api.py intent SetTimer \
  --data '{"seconds":"30"}'
```

Destructive services still need approval + `--confirm`:

```bash
python3 {baseDir}/scripts/ha_api.py delete-state sensor.custom --confirm
python3 {baseDir}/scripts/ha_api.py call-service homeassistant restart --data '{}' --confirm
```

Notes:

- `set-state` updates HA's **state machine only**; it does not talk to the physical device. Prefer `call-service` for real devices.
- Prefer `--data-file` for large JSON.
- Use `--return-response` only for services that support/require response data.

---

## Operate: reload (free) / restart & stop (confirm)

```bash
python3 {baseDir}/scripts/ha_api.py check-config
python3 {baseDir}/scripts/ha_api.py reload automations
python3 {baseDir}/scripts/ha_api.py reload scripts
python3 {baseDir}/scripts/ha_api.py reload core

# Instance-wide — ask first, then:
python3 {baseDir}/scripts/ha_api.py restart --confirm
python3 {baseDir}/scripts/ha_api.py stop --confirm
```

`reload` accepts shortcuts (`automations`, `scripts`, `scenes`, `groups`,
`template`, `person`, `zones`, `input_*`, `mqtt`, …) or `domain.service`.

---

## Operate: find phone

```bash
python3 {baseDir}/scripts/ha_api.py find-phone DEVICE
python3 {baseDir}/scripts/ha_api.py find-phone DEVICE --message "Where are you?"
```

Forces companion ringer mode to normal, then sends an `alarm_stream_max`
notification. Device is the short `mobile_app` name (`DEVICE` →
`notify.mobile_app_DEVICE`).

---

## Escape hatches

```bash
# Any GET under /api
python3 {baseDir}/scripts/ha_api.py rest GET /api/config

# Normal service POST — no confirm
python3 {baseDir}/scripts/ha_api.py rest POST /api/services/homeassistant/reload_all \
  --data '{}'

# Destructive REST — confirm
python3 {baseDir}/scripts/ha_api.py rest DELETE /api/states/sensor.custom --confirm

# WebSocket — free for normal types; confirm for remove/disable/delete/stop/restart
python3 {baseDir}/scripts/ha_api.py ws get_states
python3 {baseDir}/scripts/ha_api.py ws call_service \
  --data '{"domain":"light","service":"turn_on","target":{"entity_id":"light.kitchen"}}'
python3 {baseDir}/scripts/ha_api.py ws config/entity_registry/remove \
  --data '{"entity_id":"sensor.custom"}' --confirm
```

Rules for `ws`:

- Do **not** put `type` or `id` inside `--data`; the positional type is authoritative.
- Destructive types (path contains remove/delete/disable/… or listed registry mutations) and destructive `call_service` targets need `--confirm`.

---

## Handle failures

- Missing env: `/reset soft` or `/new`, then retry. Do not probe secrets.
- `401`: token rejected — rotate via the user's secret workflow; do not inspect it.
- `403`: token user lacks permission for that operation.
- `404` on `errors`: Core file log disabled (common on HA OS/Supervisor). Use `system-log` or Supervisor.
- Redirect blocked: fix `HOME_ASSISTANT_URL`; authenticated redirects are refused.
- Network/TLS: report without weakening TLS or switching to HTTP.
- Huge output: narrow filters (`--domain`, `--entity`, `--limit`, `--search`, `--minimal`).

---

## Operating style

1. When the user wants HA to do something ordinary (toggle, trigger, reload, notify), execute it.
2. Reserve confirmation for destructive / instance-wide actions only.
3. After important changes, re-read state and report evidence.
4. Distinguish Core API issues from host, Supervisor, add-on, storage, or kernel issues.
