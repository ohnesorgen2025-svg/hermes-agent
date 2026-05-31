"""Home Assistant tool for controlling smart home devices via REST API.

Registers LLM-callable tools:
- ``ha_list_entities`` -- list/filter entities by domain or area
- ``ha_get_state`` -- get detailed state of a single entity
- ``ha_detect_capabilities`` -- detect configured HA integrations for onboarding
- ``ha_observe_changes`` -- briefly listen for Home Assistant state changes
- ``ha_list_areas`` -- list Home Assistant areas via the area registry
- ``ha_create_area`` -- create a Home Assistant area via the area registry
- ``ha_assign_area`` -- assign an entity to an existing Home Assistant area
- ``ha_list_services`` -- list available services (actions) per domain
- ``ha_call_service`` -- call a HA service (turn_on, turn_off, set_temperature, etc.)
- ``ha_automation_manage`` -- list, read, create, update, and delete automations
- ``ha_dashboard_manage`` -- create, read, save, and manage Lovelace dashboards
- ``ha_supervisor_manage`` -- manage HA Supervisor, add-ons, updates, logs, and backups
- ``ha_update_manage`` -- inspect and install Home Assistant update entities, including HACS updates
- ``ha_admin_diagnose`` -- diagnose HA admin API capabilities and likely fallback paths
- ``ha_config_read`` -- read Home Assistant Core config files from the mounted config directory
- ``ha_config_write`` -- write Home Assistant Core config files with backups and path safety checks
- ``ha_config_reload`` -- reload Home Assistant Core config through the Home Assistant service API
- ``ha_integration_manage`` -- inspect integrations, repairs, and reload config entries
- ``ha_entity_rename`` -- rename an entity and optionally set its icon
- ``ha_zigbee_manage`` -- manage Zigbee2MQTT devices over MQTT
- ``ha_matter_manage`` -- expose/unexpose entities to Matter Hub via labels

Authentication uses a Long-Lived Access Token via ``HASS_TOKEN`` env var.
The HA instance URL is read from ``HASS_URL`` (default: http://homeassistant.local:8123).
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover - optional dependency
    mqtt = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Kept for backward compatibility (e.g. test monkeypatching); prefer _get_config().
_HASS_URL: str = ""
_HASS_TOKEN: str = ""


def _get_config():
    """Return (hass_url, hass_token) from env vars at call time."""
    return (
        (_HASS_URL or os.getenv("HASS_URL", "http://homeassistant.local:8123")).rstrip("/"),
        _HASS_TOKEN or os.getenv("HASS_TOKEN", ""),
    )

# Regex for valid HA entity_id format (e.g. "light.living_room", "sensor.temperature_1")
_ENTITY_ID_RE = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z0-9_]+$")

# Regex for HA automation IDs accepted by config endpoints. Allows plain config
# IDs ("morning_lights") and entity-style IDs ("automation.morning_lights").
_AUTOMATION_ID_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)?$")

# Regex for valid HA service/domain names (e.g. "light", "turn_on", "shell_command").
# Only lowercase ASCII letters, digits, and underscores — no slashes, dots, or
# other characters that could allow path traversal in URL construction.
# The domain and service are interpolated into /api/services/{domain}/{service},
# so allowing arbitrary strings would enable SSRF via path traversal
# (e.g. domain="../../api/config") or blocked-domain bypass
# (e.g. domain="shell_command/../light").
_SERVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Service domains blocked for security -- these allow arbitrary code/command
# execution on the HA host or enable SSRF attacks on the local network.
# HA provides zero service-level access control; all safety must be in our layer.
_BLOCKED_DOMAINS = frozenset({
    "shell_command",    # arbitrary shell commands as root in HA container
    "command_line",     # sensors/switches that execute shell commands
    "python_script",    # sandboxed but can escalate via hass.services.call()
    "pyscript",         # scripting integration with broader access
    "hassio",           # addon control, host shutdown/reboot, stdin to containers
    "rest_command",     # HTTP requests from HA server (SSRF vector)
})

_HA_APPROVAL_SUPERVISOR_ACTIONS = frozenset({
    "uninstall", "restart", "stop",
    "uninstall_addon", "restart_addon", "stop_addon",
})
_HA_APPROVAL_INTEGRATION_ACTIONS = frozenset({"remove_entry", "remove", "delete"})
_HA_APPROVAL_ZIGBEE_ACTIONS = frozenset({"remove_device", "remove"})


def _format_ha_approval_target(target: Any) -> str:
    """Return a compact target string for approval prompts."""
    if target is None:
        return "unspecified"
    if isinstance(target, str):
        return target.strip() or "unspecified"
    try:
        rendered = json.dumps(target, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(target)
    return rendered[:500] or "unspecified"


def _ha_approval_command(tool_name: str, action: str, target: Any) -> str:
    """Build the command-like text shown in approval UIs."""
    return (
        f"{tool_name} action={action or 'unspecified'} "
        f"target={_format_ha_approval_target(target)}"
    )


def _check_ha_tool_approval(
    tool_name: str,
    action: str,
    target: Any,
    risk_description: str,
) -> Optional[str]:
    """Require approval for destructive Home Assistant tool actions.

    Mirrors the terminal approval flow for manual, smart, gateway, CLI, yolo,
    and approvals.mode=off behavior without changing tools.approval.
    """
    from tools.approval import (  # imported lazily to keep module import light
        _ApprovalEntry,
        _fire_approval_hook,
        _gateway_notify_cbs,
        _gateway_queues,
        _get_approval_config,
        _get_approval_mode,
        _is_gateway_approval_context,
        _lock,
        _permanent_approved,
        _smart_approve,
        approve_permanent,
        approve_session,
        get_current_session_key,
        is_approved,
        is_current_session_yolo_enabled,
        prompt_dangerous_approval,
        save_permanent_allowlist,
        submit_pending,
    )
    from tools.terminal_tool import _get_approval_callback
    from utils import is_truthy_value

    command = _ha_approval_command(tool_name, action, target)
    pattern_key = f"ha_tool:{tool_name}:{action or 'unspecified'}"
    description = (
        f"Home Assistant approval required: tool={tool_name}, "
        f"action={action or 'unspecified'}, "
        f"target={_format_ha_approval_target(target)}. {risk_description}"
    )

    approval_mode = _get_approval_mode()
    if (
        is_truthy_value(os.getenv("HERMES_YOLO_MODE"))
        or is_current_session_yolo_enabled()
        or approval_mode == "off"
    ):
        return None

    session_key = get_current_session_key()
    if is_approved(session_key, pattern_key):
        return None

    is_cli = os.getenv("HERMES_INTERACTIVE")
    is_gateway = _is_gateway_approval_context()
    is_ask = os.getenv("HERMES_EXEC_ASK")
    if not is_cli and not is_gateway and not is_ask:
        return None

    if approval_mode == "smart":
        verdict = _smart_approve(command, description)
        if verdict == "approve":
            approve_session(session_key, pattern_key)
            logger.debug("Smart approval: auto-approved HA action '%s'", command)
            return None
        if verdict == "deny":
            return (
                f"BLOCKED by smart approval: {description}. "
                "The Home Assistant action was assessed as genuinely dangerous. Do NOT retry."
            )

    if is_gateway or is_ask:
        with _lock:
            notify_cb = _gateway_notify_cbs.get(session_key)

        approval_data = {
            "command": command,
            "pattern_key": pattern_key,
            "pattern_keys": [pattern_key],
            "description": description,
        }

        if notify_cb is None:
            submit_pending(session_key, approval_data)
            return (
                f"Approval required for Home Assistant action. Tool: {tool_name}; "
                f"action: {action}; target: {_format_ha_approval_target(target)}."
            )

        entry = _ApprovalEntry(approval_data)
        with _lock:
            _gateway_queues.setdefault(session_key, []).append(entry)

        _fire_approval_hook(
            "pre_approval_request",
            command=command,
            description=description,
            pattern_key=pattern_key,
            pattern_keys=[pattern_key],
            session_key=session_key,
            surface="gateway",
        )

        try:
            notify_cb(approval_data)
        except Exception as exc:
            logger.warning("Gateway HA approval notify failed: %s", exc)
            with _lock:
                queue = _gateway_queues.get(session_key, [])
                if entry in queue:
                    queue.remove(entry)
                if not queue:
                    _gateway_queues.pop(session_key, None)
            return "BLOCKED: Failed to send Home Assistant approval request to user. Do NOT retry."

        try:
            timeout = int(_get_approval_config().get("gateway_timeout", 300))
        except (TypeError, ValueError):
            timeout = 300

        try:
            from tools.environments.base import touch_activity_if_due
        except Exception:  # pragma: no cover
            touch_activity_if_due = None

        now = time.monotonic()
        deadline = now + max(timeout, 0)
        activity_state = {"last_touch": now, "start": now}
        resolved = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if entry.event.wait(timeout=min(1.0, remaining)):
                resolved = True
                break
            if touch_activity_if_due is not None:
                touch_activity_if_due(activity_state, "waiting for Home Assistant approval")

        with _lock:
            queue = _gateway_queues.get(session_key, [])
            if entry in queue:
                queue.remove(entry)
            if not queue:
                _gateway_queues.pop(session_key, None)

        choice = entry.result
        outcome = "timeout" if not resolved else (choice if choice else "timeout")
        _fire_approval_hook(
            "post_approval_response",
            command=command,
            description=description,
            pattern_key=pattern_key,
            pattern_keys=[pattern_key],
            session_key=session_key,
            surface="gateway",
            choice=outcome,
        )

        if not resolved or choice is None or choice == "deny":
            reason = "timed out" if not resolved else "denied by user"
            return f"BLOCKED: Home Assistant action {reason}. Do NOT retry this action."

        if choice in {"session", "always"}:
            approve_session(session_key, pattern_key)
        if choice == "always":
            approve_permanent(pattern_key)
            save_permanent_allowlist(_permanent_approved)
        return None

    _fire_approval_hook(
        "pre_approval_request",
        command=command,
        description=description,
        pattern_key=pattern_key,
        pattern_keys=[pattern_key],
        session_key=session_key,
        surface="cli",
    )
    choice = prompt_dangerous_approval(
        command,
        description,
        approval_callback=_get_approval_callback(),
    )
    _fire_approval_hook(
        "post_approval_response",
        command=command,
        description=description,
        pattern_key=pattern_key,
        pattern_keys=[pattern_key],
        session_key=session_key,
        surface="cli",
        choice=choice,
    )

    if choice == "deny":
        return "BLOCKED: User denied this Home Assistant action. Do NOT retry."
    if choice in {"session", "always"}:
        approve_session(session_key, pattern_key)
    if choice == "always":
        approve_permanent(pattern_key)
        save_permanent_allowlist(_permanent_approved)
    return None


def _get_headers(token: str = "") -> Dict[str, str]:
    """Return authorization headers for HA REST API."""
    if not token:
        _, token = _get_config()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _get_mqtt_config() -> tuple[str, int, Optional[str], Optional[str]]:
    """Return MQTT broker config from env vars."""
    port_value = os.getenv("MQTT_PORT", "1883")
    try:
        port = int(port_value)
    except ValueError as e:
        raise ValueError(f"Invalid MQTT_PORT value: {port_value}") from e
    return (
        os.getenv("MQTT_HOST", "localhost"),
        port,
        os.getenv("MQTT_USER"),
        os.getenv("MQTT_PASSWORD"),
    )


def _get_supervisor_config() -> tuple[str, str]:
    """Return (supervisor_url, token) for Home Assistant Supervisor API calls."""
    _, hass_token = _get_config()
    return os.getenv("SUPERVISOR_URL", "http://supervisor").rstrip("/"), os.getenv("SUPERVISOR_TOKEN", hass_token)


def _get_hermes_home() -> Path:
    """Return Hermes home for local add-on managed backups."""
    return Path(os.getenv("HERMES_HOME", os.path.expanduser("~/.hermes")))


def _get_ha_config_dir() -> Path:
    """Return the mounted Home Assistant Core config directory."""
    return Path(os.getenv("HA_CONFIG_DIR") or os.getenv("HOMEASSISTANT_CONFIG_DIR") or "/homeassistant_config")


def _backup_json(category: str, name: str, payload: Any) -> str:
    """Write a JSON backup below HERMES_HOME and return the path."""
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("_") or "backup"
    backup_dir = _get_hermes_home() / f"{category}-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"{safe_name}-{timestamp}.json"
    backup_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return str(backup_path)


def _backup_text(category: str, name: str, content: str) -> str:
    """Write a text backup below HERMES_HOME and return the path."""
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("_") or "backup"
    backup_dir = _get_hermes_home() / f"{category}-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"{safe_name}-{timestamp}"
    backup_path.write_text(content, encoding="utf-8")
    return str(backup_path)


def _resolve_ha_config_path(path_value: str) -> tuple[Path, str]:
    """Resolve a user path safely below the mounted Home Assistant config root."""
    raw_path = str(path_value or "").strip()
    if not raw_path:
        raise ValueError("Missing config path")

    config_dir = _get_ha_config_dir().resolve(strict=False)
    normalized = raw_path.replace("\\", "/")
    for prefix in ("/config/", "/homeassistant_config/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    if normalized in {"/config", "/homeassistant_config"}:
        normalized = ""
    if normalized.startswith("/"):
        raise ValueError("Config path must be relative to /config")

    relative = Path(normalized)
    if not relative.parts:
        raise ValueError("Config path must point to a file")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Config path must not contain empty, current, or parent-directory segments")

    target = (config_dir / relative).resolve(strict=False)
    try:
        target.relative_to(config_dir)
    except ValueError as e:
        raise ValueError("Config path escapes the Home Assistant config directory") from e
    return target, relative.as_posix()


def _validate_yaml_if_needed(path: str, content: str) -> Dict[str, Any]:
    """Validate YAML files when PyYAML is available."""
    if not path.lower().endswith((".yaml", ".yml")):
        return {"checked": False, "reason": "not_yaml"}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {"checked": False, "reason": "pyyaml_unavailable"}
    yaml.safe_load(content or "")
    return {"checked": True, "valid": True}


# ---------------------------------------------------------------------------
# Async helpers (called from sync handlers via run_until_complete)
# ---------------------------------------------------------------------------

def _filter_and_summarize(
    states: list,
    domain: Optional[str] = None,
    area: Optional[str] = None,
) -> Dict[str, Any]:
    """Filter raw HA states by domain/area and return a compact summary."""
    if domain:
        states = [s for s in states if s.get("entity_id", "").startswith(f"{domain}.")]

    if area:
        area_lower = area.lower()
        states = [
            s for s in states
            if area_lower in (s.get("attributes", {}).get("friendly_name", "") or "").lower()
            or area_lower in (s.get("attributes", {}).get("area", "") or "").lower()
        ]

    entities = []
    for s in states:
        entities.append({
            "entity_id": s["entity_id"],
            "state": s["state"],
            "friendly_name": s.get("attributes", {}).get("friendly_name", ""),
        })

    return {"count": len(entities), "entities": entities}


async def _async_list_entities(
    domain: Optional[str] = None,
    area: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch entity states from HA and optionally filter by domain/area."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/states"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
            resp.raise_for_status()
            states = await resp.json()

    return _filter_and_summarize(states, domain, area)


async def _async_get_state(entity_id: str) -> Dict[str, Any]:
    """Fetch detailed state of a single entity."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/states/{entity_id}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=10)) as resp:
            resp.raise_for_status()
            data = await resp.json()

    return {
        "entity_id": data["entity_id"],
        "state": data["state"],
        "attributes": data.get("attributes", {}),
        "last_changed": data.get("last_changed"),
        "last_updated": data.get("last_updated"),
    }


async def _async_detect_capabilities() -> Dict[str, Any]:
    """Detect relevant Home Assistant integration capabilities for onboarding."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/config/config_entries/entry"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
            resp.raise_for_status()
            entries = await resp.json()

    domains: set[str] = set()
    homematic_entries = []
    mqtt_entries = []
    matter_entries = []

    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        domain = str(entry.get("domain") or "").strip().lower()
        state = str(entry.get("state") or "").strip().lower()
        title = str(entry.get("title") or "").strip()
        if not domain:
            continue
        domains.add(domain)

        info = {
            "domain": domain,
            "title": title,
            "state": state,
        }

        if domain == "mqtt":
            mqtt_entries.append(info)
        if domain == "matter":
            matter_entries.append(info)
        if domain.startswith("homematic"):
            homematic_entries.append(info)

    def _is_configured(integration_entries: list[dict[str, str]]) -> bool:
        return any(item.get("state") not in {"failed_setup", "setup_error", "not_loaded"} for item in integration_entries)

    return {
        "success": True,
        "integrations": sorted(domains),
        "mqtt_configured": _is_configured(mqtt_entries),
        "matter_configured": _is_configured(matter_entries),
        "homematic_configured": _is_configured(homematic_entries),
        "details": {
            "mqtt": mqtt_entries,
            "matter": matter_entries,
            "homematic": homematic_entries,
        },
    }


def _is_controller_like_change(entity_id: str, domain: str, new_state: str, attributes: Dict[str, Any]) -> bool:
    """Return true for entities that look like physical controls or action sensors."""
    _, _, object_id = entity_id.partition(".")
    lowered = f"{entity_id} {attributes.get('friendly_name', '')} {new_state}".lower()
    controller_terms = (
        "action", "click", "button", "remote", "dimmer", "schalter", "taster",
        "single", "double", "triple", "hold", "release", "rotate", "brightness_move",
        "brightness_stop", "arrow_left", "arrow_right",
    )
    if domain in {"button", "input_button", "event"}:
        return True
    if object_id.endswith(("_action", "_click", "_button", "_scene")):
        return True
    return any(term in lowered for term in controller_terms)


def _score_state_change(entity_id: str, old_state: str, new_state: str, attributes: Dict[str, Any]) -> tuple[int, list[str]]:
    """Score how likely a state change was caused by an intentional device action."""
    domain, _, object_id = entity_id.partition(".")
    lowered = f"{entity_id} {attributes.get('friendly_name', '')}".lower()
    reasons: list[str] = []
    score = 10

    noisy_terms = (
        "battery", "batterie", "linkquality", "rssi", "signal", "lqi", "uptime",
        "last_seen", "last seen", "update", "diagnostic", "diagnose", "illuminance",
        "temperature", "temperatur", "humidity", "feuchtigkeit", "power", "energy",
        "voltage", "current", "leistung", "energie",
    )
    if any(term in lowered for term in noisy_terms):
        score -= 25
        reasons.append("diagnostic_or_periodic_sensor")

    controller_like = _is_controller_like_change(entity_id, domain, new_state, attributes)

    if domain in {"button", "input_button", "event"}:
        score += 65
        reasons.append("button_or_event")
    elif controller_like:
        score += 60
        reasons.append("controller_action_entity")
    elif domain in {"binary_sensor", "cover", "lock"}:
        score += 35
        reasons.append("interactive_domain")
    elif domain in {"switch", "light", "fan"}:
        score += 20
        reasons.append("possibly_downstream_actuator")
    elif domain == "sensor":
        score += 5
        reasons.append("sensor_change")

    transition = f"{old_state}->{new_state}"
    strong_transitions = {
        "off->on", "on->off", "closed->open", "open->closed", "locked->unlocked",
        "unlocked->locked", "idle->press", "idle->pressed", "standby->press",
    }
    if transition in strong_transitions:
        score += 45
        reasons.append("strong_state_transition")
    elif old_state != new_state:
        score += 15
        reasons.append("state_changed")

    if object_id.endswith(("_action", "_click", "_button", "_contact", "_occupancy", "_motion")):
        score += 25
        reasons.append("interactive_entity_name")

    if new_state in {"unknown", "unavailable"}:
        score -= 45
        reasons.append("unavailable_state")

    return max(score, 0), reasons


def _apply_cascade_context(events: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Demote likely downstream actuator events when a controller caused a cascade."""
    downstream_domains = {"light", "switch", "fan", "cover"}
    downstream_events = [event for event in events if event.get("domain") in downstream_domains]
    controller_events = [
        event for event in events
        if _is_controller_like_change(
            str(event.get("entity_id") or ""),
            str(event.get("domain") or ""),
            str(event.get("new_state") or ""),
            {"friendly_name": event.get("friendly_name", "")},
        )
    ]

    cascade_detected = len(downstream_events) >= 3 and bool(controller_events)
    if cascade_detected:
        for event in downstream_events:
            event["score"] = max(int(event.get("score", 0)) - 35, 0)
            reasons = event.setdefault("reasons", [])
            if "likely_downstream_cascade" not in reasons:
                reasons.append("likely_downstream_cascade")
        for event in controller_events:
            event["score"] = int(event.get("score", 0)) + 25
            reasons = event.setdefault("reasons", [])
            if "likely_controller_for_cascade" not in reasons:
                reasons.append("likely_controller_for_cascade")

    return {
        "cascade_detected": cascade_detected,
        "downstream_event_count": len(downstream_events),
        "controller_event_count": len(controller_events),
    }


async def _async_observe_changes(
    duration_seconds: int = 10,
    include_domains: Optional[list[str]] = None,
    ignore_domains: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """Listen to Home Assistant state_changed events for a short window."""
    import aiohttp

    _, hass_token = _get_config()
    duration_seconds = max(3, min(int(duration_seconds or 10), 20))
    include = {item.strip().lower() for item in include_domains or [] if isinstance(item, str) and item.strip()}
    ignored = {item.strip().lower() for item in ignore_domains or [] if isinstance(item, str) and item.strip()}
    ignored.update({"sun", "weather", "zone", "person", "device_tracker", "update", "calendar"})

    events: list[Dict[str, Any]] = []
    command_id = 1

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(_get_ws_url(), heartbeat=20) as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": hass_token})
            msg = await ws.receive_json()
            if msg.get("type") != "auth_ok":
                raise Exception("WebSocket auth failed")

            command_id += 1
            await ws.send_json({"id": command_id, "type": "subscribe_events", "event_type": "state_changed"})
            msg = await ws.receive_json()
            if not msg.get("success"):
                raise Exception(msg.get("error", {}).get("message", "Failed to subscribe to state_changed events"))

            loop = asyncio.get_running_loop()
            end_at = loop.time() + duration_seconds
            while True:
                remaining = end_at - loop.time()
                if remaining <= 0:
                    break
                try:
                    msg = await asyncio.wait_for(ws.receive_json(), timeout=remaining)
                except asyncio.TimeoutError:
                    break

                if msg.get("type") != "event":
                    continue
                event = msg.get("event", {})
                data = event.get("data", {}) if isinstance(event, dict) else {}
                entity_id = str(data.get("entity_id") or "")
                if not entity_id or "." not in entity_id:
                    continue
                domain = entity_id.split(".", 1)[0]
                if include and domain not in include:
                    continue
                if domain in ignored:
                    continue

                old = data.get("old_state") or {}
                new = data.get("new_state") or {}
                if not isinstance(old, dict) or not isinstance(new, dict):
                    continue
                old_state = str(old.get("state") or "")
                new_state = str(new.get("state") or "")
                attributes = new.get("attributes") if isinstance(new.get("attributes"), dict) else {}
                score, reasons = _score_state_change(entity_id, old_state, new_state, attributes)
                events.append(
                    {
                        "entity_id": entity_id,
                        "domain": domain,
                        "friendly_name": attributes.get("friendly_name", ""),
                        "old_state": old_state,
                        "new_state": new_state,
                        "last_changed": new.get("last_changed"),
                        "last_updated": new.get("last_updated"),
                        "score": score,
                        "reasons": reasons,
                    }
                )

    cascade = _apply_cascade_context(events)
    events.sort(key=lambda item: item.get("score", 0), reverse=True)
    strong = [item for item in events if item.get("score", 0) >= 60]
    return {
        "success": True,
        "duration_seconds": duration_seconds,
        "event_count": len(events),
        "strong_count": len(strong),
        "cascade": cascade,
        "candidates": events[:10],
        "best_candidate": events[0] if events else None,
        "message": "Keine passenden Aenderungen erkannt." if not events else f"{len(events)} Aenderungen erkannt, {len(strong)} starke Kandidaten.",
    }


async def _async_entity_rename(
    entity_id: str,
    name: Optional[str] = None,
    icon: Optional[str] = None,
    new_entity_id: Optional[str] = None,
    area_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a Home Assistant entity via the entity registry WebSocket API."""
    payload: Dict[str, Any] = {
        "type": "config/entity_registry/update",
        "entity_id": entity_id,
    }
    if name is not None:
        payload["name"] = name
    if icon:
        payload["icon"] = icon
    if new_entity_id is not None:
        payload["new_entity_id"] = new_entity_id
    if area_id is not None:
        payload["area_id"] = area_id

    result = await _ws_command(payload)
    response = {"success": True, "entity_id": entity_id, "entity": result}
    if name is not None:
        response["name"] = name
    if new_entity_id is not None:
        response["new_entity_id"] = new_entity_id
    if area_id is not None:
        response["area_id"] = area_id
    return response


def _get_ws_url() -> str:
    """Return the Home Assistant WebSocket endpoint for the current HASS_URL."""
    hass_url, _ = _get_config()
    base_url = hass_url.rstrip("/")
    if base_url.endswith("/api"):
        ws_url = f"{base_url}/websocket"
    else:
        ws_url = f"{base_url}/api/websocket"
    return ws_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)


async def _ws_command(message: Dict[str, Any]) -> Any:
    """Send a Home Assistant WebSocket command and return the result payload."""
    import aiohttp

    _, hass_token = _get_config()
    payload = dict(message)
    payload.setdefault("id", 1)

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(_get_ws_url()) as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": hass_token})
            msg = await ws.receive_json()
            if msg.get("type") != "auth_ok":
                raise Exception("WebSocket auth failed")

            await ws.send_json(payload)
            msg = await ws.receive_json()
            if not msg.get("success"):
                raise Exception(msg.get("error", {}).get("message", "Unknown error"))
            return msg.get("result")


async def _ws_get_entity(entity_id) -> dict:
    """Get an entity registry entry via the Home Assistant WebSocket API."""
    result = await _ws_command({"type": "config/entity_registry/get", "entity_id": entity_id})
    return result or {}


async def _ws_update_entity_labels(entity_id, labels) -> dict:
    """Update an entity registry entry's labels via the Home Assistant WebSocket API."""
    result = await _ws_command(
        {
            "type": "config/entity_registry/update",
            "entity_id": entity_id,
            "labels": labels,
        }
    )
    return result or {}


async def _async_list_areas() -> Dict[str, Any]:
    """List Home Assistant areas via the area registry WebSocket API."""
    areas = await _ws_command({"type": "config/area_registry/list"})
    normalized = []
    for area in areas or []:
        normalized.append(
            {
                "area_id": area.get("area_id", ""),
                "name": area.get("name", ""),
                "aliases": area.get("aliases", []),
                "floor_id": area.get("floor_id"),
            }
        )
    normalized.sort(key=lambda item: (item["name"] or "").lower())
    return {"count": len(normalized), "areas": normalized}


async def _async_create_area(name: str) -> Dict[str, Any]:
    """Create a Home Assistant area via the area registry WebSocket API."""
    result = await _ws_command({"type": "config/area_registry/create", "name": name})
    return {
        "success": True,
        "area_id": result.get("area_id", ""),
        "name": result.get("name", name),
        "area": result,
    }


async def _async_assign_area(entity_id: str, area_id: str) -> Dict[str, Any]:
    """Assign an entity to a Home Assistant area via the entity registry WebSocket API."""
    result = await _ws_command(
        {
            "type": "config/entity_registry/update",
            "entity_id": entity_id,
            "area_id": area_id,
        }
    )
    return {
        "success": True,
        "entity_id": entity_id,
        "area_id": area_id,
        "entity": result,
        "message": f"{entity_id} wurde dem Bereich {area_id} zugeordnet.",
    }


async def _async_matter_manage(action: str, entity_id: Optional[str] = None) -> Dict[str, Any]:
    """Manage the 'matter' entity label used by Home Assistant Matter Hub."""
    import aiohttp

    hass_url, hass_token = _get_config()

    async with aiohttp.ClientSession() as session:
        if action == "list_exposed":
            url = f"{hass_url}/api/template"
            payload = {"template": "{{ label_entities('matter') | join(',') }}"}
            async with session.post(
                url,
                headers=_get_headers(hass_token),
                json=payload,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                resp.raise_for_status()
                rendered = (await resp.text()).strip()
            entities = [item.strip() for item in rendered.split(",") if item.strip()]
            message = "Keine Entities freigegeben." if not entities else f"{len(entities)} Entities fuer Alexa freigegeben."
            return {"success": True, "action": action, "count": len(entities), "entities": entities, "message": message}

        entry = await _ws_get_entity(entity_id)
        current = entry.get("labels", [])
        if not isinstance(current, list):
            current = []

        if action == "expose":
            if "matter" in current:
                return {
                    "success": True,
                    "action": action,
                    "entity_id": entity_id,
                    "labels": current,
                    "message": f"{entity_id} ist bereits fuer Alexa freigegeben.",
                }
            updated_labels = [*current, "matter"]
            message = f"{entity_id} wurde fuer Alexa freigegeben."
        elif action == "unexpose":
            if "matter" not in current:
                return {
                    "success": True,
                    "action": action,
                    "entity_id": entity_id,
                    "labels": current,
                    "message": f"{entity_id} ist nicht fuer Alexa freigegeben.",
                }
            updated_labels = [label for label in current if label != "matter"]
            message = f"{entity_id} ist nicht mehr fuer Alexa freigegeben."
        else:
            raise ValueError(f"Unsupported action: {action}")

        result = await _ws_update_entity_labels(entity_id, updated_labels)

    return {
        "success": True,
        "action": action,
        "entity_id": entity_id,
        "labels": updated_labels,
        "entity": result,
        "message": message,
    }


async def _supervisor_request(method: str, path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Call the Home Assistant Supervisor API."""
    import aiohttp

    supervisor_url, token = _get_supervisor_config()
    clean_path = path if path.startswith("/") else f"/{path}"
    url = f"{supervisor_url}{clean_path}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    method = method.upper()

    async with aiohttp.ClientSession() as session:
        async with session.request(method, url, headers=headers, json=data if data is not None else None, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            text = await resp.text()
            if resp.status >= 400:
                hint = ""
                if resp.status == 403:
                    hint = " Add-on needs Supervisor API permission (`hassio_api: true`) and must be updated/restarted."
                raise RuntimeError(f"Supervisor API {method} {clean_path} failed with {resp.status}: {text[:500]}{hint}")
            if not text:
                return {"success": True, "status": resp.status}
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text
            return {"success": True, "status": resp.status, "response": parsed}


async def _ha_request(method: str, path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Call the Home Assistant REST API and return a parsed response."""
    import aiohttp

    hass_url, hass_token = _get_config()
    clean_path = path if path.startswith("/") else f"/{path}"
    url = f"{hass_url}{clean_path}"
    method = method.upper()

    async with aiohttp.ClientSession() as session:
        async with session.request(
            method,
            url,
            headers=_get_headers(hass_token),
            json=data if data is not None else None,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise RuntimeError(f"Home Assistant API {method} {clean_path} failed with {resp.status}: {text[:500]}")
            if not text:
                return {"success": True, "status": resp.status}
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text
            return {"success": True, "status": resp.status, "response": parsed}


async def _async_supervisor_manage(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Manage Home Assistant Supervisor, add-ons, updates, logs, and backups."""
    addon = str(args.get("addon") or args.get("slug") or "").strip()
    data = args.get("data") if isinstance(args.get("data"), dict) else None

    if action == "info":
        return await _supervisor_request("GET", "/info")
    if action == "list_addons":
        return await _supervisor_request("GET", "/addons")
    if action == "addon_info":
        if not addon:
            raise ValueError("Missing addon slug")
        return await _supervisor_request("GET", f"/addons/{addon}/info")
    if action in {"install_addon", "uninstall_addon", "start_addon", "stop_addon", "restart_addon", "update_addon"}:
        if not addon:
            raise ValueError("Missing addon slug")
        endpoint = {
            "install_addon": "install",
            "uninstall_addon": "uninstall",
            "start_addon": "start",
            "stop_addon": "stop",
            "restart_addon": "restart",
            "update_addon": "update",
        }[action]
        return await _supervisor_request("POST", f"/addons/{addon}/{endpoint}", data or {})
    if action == "addon_logs":
        if not addon:
            raise ValueError("Missing addon slug")
        return await _supervisor_request("GET", f"/addons/{addon}/logs")
    if action == "core_info":
        return await _supervisor_request("GET", "/core/info")
    if action == "supervisor_info":
        return await _supervisor_request("GET", "/supervisor/info")
    if action == "os_info":
        return await _supervisor_request("GET", "/os/info")
    if action in {"update_core", "update_supervisor", "update_os"}:
        path = {"update_core": "/core/update", "update_supervisor": "/supervisor/update", "update_os": "/os/update"}[action]
        return await _supervisor_request("POST", path, data or {})
    if action == "create_backup":
        backup_type = str(args.get("backup_type") or "full").strip().lower()
        if backup_type not in {"full", "partial"}:
            raise ValueError("backup_type must be full or partial")
        return await _supervisor_request("POST", f"/backups/new/{backup_type}", data or {})
    if action == "list_backups":
        return await _supervisor_request("GET", "/backups")
    if action == "raw_request":
        method = str(args.get("method") or "GET")
        path = str(args.get("path") or "").strip()
        if not path.startswith("/"):
            raise ValueError("raw_request path must start with /")
        return await _supervisor_request(method, path, data)
    raise ValueError(f"Unsupported supervisor action: {action}")


def _supervisor_payload_data(payload: Dict[str, Any]) -> Any:
    """Return Supervisor response data when wrapped in the usual success/data envelope."""
    response = payload.get("response") if isinstance(payload, dict) else None
    if isinstance(response, dict) and "data" in response:
        return response["data"]
    return response


def _classify_admin_error(error: Exception) -> Dict[str, str]:
    """Classify Home Assistant API failures into actionable admin categories."""
    message = str(error)
    lowered = message.lower()
    if "403" in lowered or "forbidden" in lowered:
        return {
            "category": "permission",
            "meaning": "The API path exists, but the token or add-on role lacks permission.",
            "next_step": "Check add-on permissions such as hassio_api, hassio_role, or the Home Assistant token scope.",
        }
    if "404" in lowered or "not found" in lowered:
        return {
            "category": "missing_endpoint",
            "meaning": "This Home Assistant version or proxy path does not expose that endpoint.",
            "next_step": "Try the matching WebSocket command, REST endpoint, service/entity path, or Supervisor path before giving up.",
        }
    if "unknown command" in lowered or "unknown_command" in lowered:
        return {
            "category": "unsupported_websocket_command",
            "meaning": "This Home Assistant version rejected that WebSocket command.",
            "next_step": "Try a REST endpoint, service/entity path, or version-specific command variant.",
        }
    if "cannot connect" in lowered or "connection" in lowered or "timeout" in lowered:
        return {
            "category": "connectivity",
            "meaning": "Hermes could not reach Home Assistant or the Supervisor API reliably.",
            "next_step": "Check HASS_URL, SUPERVISOR_URL, add-on networking, and whether Home Assistant is still restarting.",
        }
    return {
        "category": "api_error",
        "meaning": "The API returned an unexpected error.",
        "next_step": "Keep the exact error and try the next available adapter path before asking the user for manual work.",
    }


def _probe_summary(value: Any) -> Dict[str, Any]:
    """Return a compact, non-secret summary for diagnostic probe output."""
    if isinstance(value, list):
        sample = value[:3]
        return {"type": "list", "count": len(value), "sample": sample}
    if isinstance(value, dict):
        summary: Dict[str, Any] = {"type": "object", "keys": sorted(str(key) for key in value.keys())[:20]}
        if "count" in value:
            summary["count"] = value.get("count")
        if "available_count" in value:
            summary["available_count"] = value.get("available_count")
        if "status" in value:
            summary["status"] = value.get("status")
        return summary
    return {"type": type(value).__name__, "value": str(value)[:200]}


async def _run_admin_probe(name: str, category: str, call) -> Dict[str, Any]:
    """Run one admin diagnostic probe and return a classified result."""
    try:
        result = await call()
        return {
            "name": name,
            "category": category,
            "ok": True,
            "summary": _probe_summary(result),
        }
    except Exception as error:
        return {
            "name": name,
            "category": category,
            "ok": False,
            "error": str(error),
            "classification": _classify_admin_error(error),
        }


async def _async_admin_diagnose(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Diagnose Home Assistant admin API capabilities and fallback paths."""
    if action not in {"run", "quick"}:
        raise ValueError("Unsupported admin diagnose action")

    hass_url, hass_token = _get_config()
    supervisor_url, supervisor_token = _get_supervisor_config()
    checks = {
        "hass_url": hass_url,
        "hass_token_present": bool(hass_token),
        "supervisor_url": supervisor_url,
        "supervisor_token_present": bool(supervisor_token),
        "ha_config_dir": str(_get_ha_config_dir()),
        "ha_config_dir_exists": _get_ha_config_dir().exists(),
        "hassio_api_expected": supervisor_url == "http://supervisor" or bool(os.getenv("SUPERVISOR_URL")),
    }

    probes = [
        ("ha_rest_config", "homeassistant_rest", lambda: _ha_request("GET", "/api/config")),
        ("supervisor_info", "supervisor", lambda: _supervisor_request("GET", "/info")),
        ("supervisor_backups_list", "supervisor", lambda: _supervisor_request("GET", "/backups")),
        ("automation_ws_list", "automation", lambda: _ws_command({"type": "automation/config/list"})),
        ("automation_rest_list", "automation", lambda: _ha_request("GET", "/api/config/automation/config")),
        ("dashboard_ws_list", "dashboard", lambda: _ws_command({"type": "lovelace/dashboards/list"})),
        ("dashboard_rest_metadata_list", "dashboard", lambda: _ha_request("GET", "/api/lovelace/dashboards")),
        ("config_filesystem_configuration", "config_filesystem", lambda: _async_config_read("configuration.yaml", max_bytes=256_000)),
        ("integration_entries", "integration", lambda: _ws_command({"type": "config_entries/get"})),
        ("repairs_list", "integration", lambda: _ws_command({"type": "repairs/list_issues"})),
        ("update_entities", "updates", _async_list_update_entities),
        ("update_services", "updates", lambda: _async_list_services("update")),
    ]
    if action == "quick":
        probes = probes[:6]

    results = [await _run_admin_probe(name, category, call) for name, category, call in probes]
    categories: Dict[str, Dict[str, int]] = {}
    for result in results:
        category = result["category"]
        category_summary = categories.setdefault(category, {"ok": 0, "failed": 0})
        if result.get("ok"):
            category_summary["ok"] += 1
        else:
            category_summary["failed"] += 1

    recommendations = []
    failed_categories = {result.get("classification", {}).get("category") for result in results if not result.get("ok")}
    if "permission" in failed_categories:
        recommendations.append("A 403 means Hermes reached the API but lacks permission; update/restart the add-on and verify hassio_api/hassio_role or token scope.")
    if "missing_endpoint" in failed_categories or "unsupported_websocket_command" in failed_categories:
        recommendations.append("A 404 or unknown WebSocket command is an adapter-path problem; try the alternate WebSocket, REST, service/entity, or Supervisor path before asking for manual UI work.")
    if not recommendations:
        recommendations.append("Use the successful probes as the preferred admin adapter paths for this Home Assistant instance.")

    return {
        "success": True,
        "action": action,
        "checks": checks,
        "categories": categories,
        "probes": results,
        "recommendations": recommendations,
    }


async def _async_list_update_entities() -> list[Dict[str, Any]]:
    """Return Home Assistant update.* entities with their useful attributes."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/states"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
            resp.raise_for_status()
            states = await resp.json()

    updates = []
    for state in states if isinstance(states, list) else []:
        entity_id = str(state.get("entity_id") or "")
        if not entity_id.startswith("update."):
            continue
        attrs = state.get("attributes") if isinstance(state.get("attributes"), dict) else {}
        updates.append({
            "entity_id": entity_id,
            "state": state.get("state"),
            "available": state.get("state") == "on",
            "title": attrs.get("title") or attrs.get("friendly_name") or entity_id,
            "installed_version": attrs.get("installed_version"),
            "latest_version": attrs.get("latest_version"),
            "release_url": attrs.get("release_url"),
            "skipped_version": attrs.get("skipped_version"),
            "auto_update": attrs.get("auto_update"),
            "device_class": attrs.get("device_class"),
            "entity_picture": attrs.get("entity_picture"),
        })
    return updates


def _filter_update_entities(updates: list[Dict[str, Any]], args: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Filter update entities for bulk installation."""
    only_available = bool(args.get("only_available", True))
    include_hacs = bool(args.get("include_hacs", True))
    include_core = bool(args.get("include_core", True))
    raw_entity_ids = args.get("entity_ids") or args.get("entity_id")
    if isinstance(raw_entity_ids, str):
        entity_ids = {item.strip() for item in raw_entity_ids.split(",") if item.strip()}
    elif isinstance(raw_entity_ids, list):
        entity_ids = {str(item).strip() for item in raw_entity_ids if str(item).strip()}
    else:
        entity_ids = set()
    include_text = str(args.get("include") or "").strip().lower()
    exclude_text = str(args.get("exclude") or "").strip().lower()

    selected = []
    for update in updates:
        entity_id = update["entity_id"]
        searchable = f"{entity_id} {update.get('title') or ''}".lower()
        if only_available and not update.get("available"):
            continue
        if entity_ids and entity_id not in entity_ids:
            continue
        if not include_hacs and "hacs" in searchable:
            continue
        if not include_core and any(token in searchable for token in ("home_assistant_core", "home assistant core", "supervisor", "operating_system", "operating system")):
            continue
        if include_text and include_text not in searchable:
            continue
        if exclude_text and exclude_text in searchable:
            continue
        selected.append(update)
    return selected


async def _async_install_update_entity(entity_id: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Install one Home Assistant update entity via update.install."""
    if not _ENTITY_ID_RE.match(entity_id) or not entity_id.startswith("update."):
        raise ValueError(f"Invalid update entity_id: {entity_id}")
    service_data: Dict[str, Any] = {}
    if "version" in args and args.get("version"):
        service_data["version"] = args["version"]
    if "backup" in args:
        service_data["backup"] = bool(args.get("backup"))
    return await _async_call_service("update", "install", entity_id, service_data)


async def _async_update_manage(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Manage Home Assistant updates across Supervisor and update.* entities."""
    if action in {"list_updates", "status"}:
        updates = await _async_list_update_entities()
        result: Dict[str, Any] = {
            "success": True,
            "updates": updates,
            "available": [item for item in updates if item.get("available")],
            "count": len(updates),
            "available_count": sum(1 for item in updates if item.get("available")),
        }
        if action == "status":
            for key, supervisor_action in (("core", "core_info"), ("supervisor", "supervisor_info"), ("os", "os_info"), ("addons", "list_addons")):
                try:
                    result[key] = await _async_supervisor_manage(supervisor_action, {})
                except Exception as e:
                    result[key] = {"error": str(e)}
        return result

    if action == "install_update":
        entity_id = str(args.get("entity_id") or "").strip()
        if not entity_id:
            raise ValueError("Missing update entity_id")
        return {"success": True, "entity_id": entity_id, "result": await _async_install_update_entity(entity_id, args)}

    if action == "install_updates":
        updates = await _async_list_update_entities()
        selected = _filter_update_entities(updates, args)
        results = []
        for update in selected:
            entity_id = update["entity_id"]
            try:
                results.append({"entity_id": entity_id, "success": True, "result": await _async_install_update_entity(entity_id, args)})
            except Exception as e:
                results.append({"entity_id": entity_id, "success": False, "error": str(e)})
        return {"success": all(item.get("success") for item in results), "selected_count": len(selected), "results": results}

    if action == "update_everything":
        backup = bool(args.get("backup", True))
        force_without_backup = bool(args.get("force_without_backup", False))
        backup_result: Optional[Dict[str, Any]] = None
        if backup:
            try:
                backup_result = await _async_supervisor_manage("create_backup", {"backup_type": args.get("backup_type") or "full"})
            except Exception as e:
                if not force_without_backup:
                    return {
                        "success": False,
                        "blocked": True,
                        "stage": "backup",
                        "error": str(e),
                        "message": "Backup failed; update_everything stopped. Confirm force_without_backup=true to proceed anyway.",
                    }
                backup_result = {"success": False, "error": str(e), "forced_continue": True}

        supervisor_results: Dict[str, Any] = {}
        for supervisor_action in ("update_core", "update_supervisor", "update_os"):
            if bool(args.get(supervisor_action, True)):
                try:
                    supervisor_results[supervisor_action] = await _async_supervisor_manage(supervisor_action, {})
                except Exception as e:
                    supervisor_results[supervisor_action] = {"success": False, "error": str(e)}

        addon_results = []
        if bool(args.get("addons", True)):
            try:
                addon_payload = await _async_supervisor_manage("list_addons", {})
                addon_data = _supervisor_payload_data(addon_payload)
                addons = addon_data.get("addons", []) if isinstance(addon_data, dict) else []
                for addon in addons if isinstance(addons, list) else []:
                    if not isinstance(addon, dict) or not addon.get("update_available"):
                        continue
                    slug = str(addon.get("slug") or addon.get("name") or "").strip()
                    if not slug:
                        continue
                    try:
                        addon_results.append({"addon": slug, "success": True, "result": await _async_supervisor_manage("update_addon", {"addon": slug})})
                    except Exception as e:
                        addon_results.append({"addon": slug, "success": False, "error": str(e)})
            except Exception as e:
                addon_results.append({"success": False, "error": str(e)})

        entity_result = None
        if bool(args.get("update_entities", True)):
            entity_args = dict(args)
            entity_args.setdefault("backup", False)
            entity_result = await _async_update_manage("install_updates", entity_args)

        failures = [value for value in supervisor_results.values() if isinstance(value, dict) and value.get("success") is False]
        failures.extend(item for item in addon_results if isinstance(item, dict) and item.get("success") is False)
        if isinstance(entity_result, dict):
            failures.extend(item for item in entity_result.get("results", []) if isinstance(item, dict) and item.get("success") is False)
        return {
            "success": not failures,
            "backup": backup_result,
            "supervisor": supervisor_results,
            "addons": addon_results,
            "update_entities": entity_result,
        }

    raise ValueError(f"Unsupported update action: {action}")


async def _async_config_read(path: str, max_bytes: int = 512_000) -> Dict[str, Any]:
    """Read a Home Assistant Core config file from the mounted config directory."""
    target, relative_path = _resolve_ha_config_path(path)
    config_dir = _get_ha_config_dir().resolve(strict=False)
    if not config_dir.exists():
        raise FileNotFoundError(f"Home Assistant config mount not found: {config_dir}")
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Config file not found: /config/{relative_path}")
    size = target.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Config file /config/{relative_path} is {size} bytes; increase max_bytes to read it")
    content = target.read_text(encoding="utf-8")
    return {
        "success": True,
        "path": f"/config/{relative_path}",
        "mount_path": str(target),
        "size": size,
        "content": content,
    }


async def _async_config_write(path: str, content: str, backup: bool = True, validate_yaml: bool = True, create_parent_dirs: bool = False) -> Dict[str, Any]:
    """Write a Home Assistant Core config file with path safety and backups."""
    if not isinstance(content, str):
        raise ValueError("Config content must be a string")
    target, relative_path = _resolve_ha_config_path(path)
    config_dir = _get_ha_config_dir().resolve(strict=False)
    if not config_dir.exists():
        raise FileNotFoundError(f"Home Assistant config mount not found: {config_dir}")
    if target.exists() and not target.is_file():
        raise ValueError(f"Config path is not a file: /config/{relative_path}")
    if not target.parent.exists():
        if create_parent_dirs:
            target.parent.mkdir(parents=True, exist_ok=True)
        else:
            raise FileNotFoundError(f"Parent directory does not exist for /config/{relative_path}")

    validation = _validate_yaml_if_needed(relative_path, content) if validate_yaml else {"checked": False, "reason": "disabled"}
    backup_path = None
    if backup:
        if target.exists():
            backup_path = _backup_text("config", relative_path, target.read_text(encoding="utf-8"))
        else:
            backup_path = _backup_json("config", f"{relative_path}.create", {"path": f"/config/{relative_path}", "existed": False})

    temp_path = target.with_name(f".{target.name}.hermes-tmp")
    temp_path.write_text(content, encoding="utf-8")
    if target.exists():
        try:
            temp_path.chmod(target.stat().st_mode & 0o777)
        except OSError:
            pass
    os.replace(temp_path, target)
    return {
        "success": True,
        "path": f"/config/{relative_path}",
        "mount_path": str(target),
        "backup_path": backup_path,
        "validation": validation,
        "bytes_written": len(content.encode("utf-8")),
    }


async def _async_config_reload() -> Dict[str, Any]:
    """Reload Home Assistant Core config through the Home Assistant service API."""
    result = await _async_call_service("homeassistant", "reload_core_config")
    return {"success": True, "service": "homeassistant.reload_core_config", "result": result}


async def _async_dashboard_manage(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Manage Lovelace dashboards via Home Assistant WebSocket commands."""
    url_path = str(args.get("url_path") or args.get("dashboard") or "").strip().strip("/")
    dashboard_id = str(args.get("dashboard_id") or args.get("id") or url_path).strip().strip("/")
    config = args.get("config")
    metadata_keys = ("title", "icon", "show_in_sidebar", "require_admin")

    def dashboard_api_path() -> str:
        from urllib.parse import quote

        if not dashboard_id:
            raise ValueError("Missing dashboard_id or url_path")
        return f"/api/lovelace/dashboards/{quote(dashboard_id, safe='')}"

    def config_url_path() -> str:
        if url_path:
            return url_path
        if dashboard_id and dashboard_id != "lovelace":
            return dashboard_id
        return ""

    def metadata_patch() -> Dict[str, Any]:
        return {key: args[key] for key in metadata_keys if key in args}

    async def get_config() -> Any:
        payload: Dict[str, Any] = {"type": "lovelace/config"}
        target = config_url_path()
        if target:
            payload["url_path"] = target
        return await _ws_command(payload)

    if action == "list_dashboards":
        return {"success": True, "dashboards": await _ws_command({"type": "lovelace/dashboards/list"})}
    if action == "get_dashboard":
        return {"success": True, "url_path": url_path or None, "config": await get_config()}
    if action == "backup_dashboard":
        current = await get_config()
        return {"success": True, "url_path": url_path or None, "backup_path": _backup_json("dashboard", url_path or "default", current)}
    if action == "create_dashboard":
        title = str(args.get("title") or "").strip()
        if not title:
            raise ValueError("Missing dashboard title")
        if not url_path:
            url_path = re.sub(r"[^a-z0-9_]+", "-", title.lower()).strip("-") or "hermes-dashboard"
        backup_path = _backup_json("dashboard", "dashboards-list", await _ws_command({"type": "lovelace/dashboards/list"}))
        payload = {
            "type": "lovelace/dashboards/create",
            "url_path": url_path,
            "title": title,
            "mode": str(args.get("mode") or "storage"),
            "show_in_sidebar": bool(args.get("show_in_sidebar", True)),
        }
        icon = args.get("icon")
        if icon:
            payload["icon"] = icon
        return {"success": True, "backup_path": backup_path, "dashboard": await _ws_command(payload), "url_path": url_path}
    if action == "update_dashboard":
        patch = metadata_patch()
        if isinstance(config, str):
            config = json.loads(config)
        if config is not None and not isinstance(config, dict):
            raise ValueError("Dashboard config must be an object")
        if not patch and config is None:
            raise ValueError("Missing dashboard metadata fields or config")
        if patch:
            dashboard_api_path()
        backup_path = _backup_json("dashboard", url_path or dashboard_id or "default", await get_config())
        result: Dict[str, Any] = {}
        if config is not None:
            payload = {"type": "lovelace/config/save", "config": config}
            target = config_url_path()
            if target:
                payload["url_path"] = target
            result["config_save"] = await _ws_command(payload)
        if patch:
            result["metadata_update"] = await _ha_request("PUT", dashboard_api_path(), patch)
        return {"success": True, "backup_path": backup_path, "result": result}
    if action == "delete_dashboard":
        dashboard_api_path()
        current = await get_config()
        backup_path = _backup_json("dashboard", url_path or dashboard_id, current)
        return {"success": True, "backup_path": backup_path, "result": await _ha_request("DELETE", dashboard_api_path())}
    if action == "save_dashboard":
        if isinstance(config, str):
            config = json.loads(config)
        if not isinstance(config, dict):
            raise ValueError("Missing dashboard config object")
        patch = metadata_patch()
        if patch:
            dashboard_api_path()
        backup_path = _backup_json("dashboard", url_path or dashboard_id or "default", await get_config())
        payload = {"type": "lovelace/config/save", "config": config}
        target = config_url_path()
        if target:
            payload["url_path"] = target
        result = {"config_save": await _ws_command(payload)}
        if patch:
            result["metadata_update"] = await _ha_request("PUT", dashboard_api_path(), patch)
        return {"success": True, "backup_path": backup_path, "result": result}
    if action in {"add_view", "update_view", "delete_view", "add_card", "update_card", "delete_card"}:
        current = await get_config()
        if not isinstance(current, dict):
            raise ValueError("Dashboard config is not an object")
        views = current.setdefault("views", [])
        if not isinstance(views, list):
            raise ValueError("Dashboard views is not a list")
        view_index = int(args.get("view_index", 0))
        if action == "add_view":
            view = args.get("view")
            if isinstance(view, str):
                view = json.loads(view)
            if not isinstance(view, dict):
                raise ValueError("Missing view object")
            views.append(view)
        else:
            if view_index < 0 or view_index >= len(views):
                raise ValueError("view_index out of range")
            if action == "update_view":
                patch = args.get("view") or args.get("patch")
                if isinstance(patch, str):
                    patch = json.loads(patch)
                if not isinstance(patch, dict):
                    raise ValueError("Missing view patch object")
                views[view_index].update(patch)
            elif action == "delete_view":
                views.pop(view_index)
            else:
                cards = views[view_index].setdefault("cards", [])
                if not isinstance(cards, list):
                    raise ValueError("View cards is not a list")
                card_index = args.get("card_index")
                if action == "add_card":
                    card = args.get("card")
                    if isinstance(card, str):
                        card = json.loads(card)
                    if not isinstance(card, dict):
                        raise ValueError("Missing card object")
                    cards.append(card)
                else:
                    card_index = int(card_index)
                    if card_index < 0 or card_index >= len(cards):
                        raise ValueError("card_index out of range")
                    if action == "update_card":
                        patch = args.get("card") or args.get("patch")
                        if isinstance(patch, str):
                            patch = json.loads(patch)
                        if not isinstance(patch, dict):
                            raise ValueError("Missing card patch object")
                        cards[card_index].update(patch)
                    elif action == "delete_card":
                        cards.pop(card_index)
        backup_path = _backup_json("dashboard", url_path or "default", await get_config())
        payload = {"type": "lovelace/config/save", "config": current}
        if url_path:
            payload["url_path"] = url_path
        return {"success": True, "backup_path": backup_path, "config": current, "result": await _ws_command(payload)}
    if action == "raw_ws":
        message = args.get("message")
        if isinstance(message, str):
            message = json.loads(message)
        if not isinstance(message, dict):
            raise ValueError("Missing raw WebSocket message object")
        return {"success": True, "result": await _ws_command(message)}
    raise ValueError(f"Unsupported dashboard action: {action}")


async def _async_integration_manage(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect and manage Home Assistant integrations where HA exposes APIs."""
    if action == "list_entries":
        return {"success": True, "entries": await _ws_command({"type": "config_entries/get"})}
    if action == "reload_entry":
        entry_id = str(args.get("entry_id") or "").strip()
        if not entry_id:
            raise ValueError("Missing entry_id")
        return {"success": True, "result": await _ws_command({"type": "config_entries/reload", "entry_id": entry_id})}
    if action == "remove_entry":
        entry_id = str(args.get("entry_id") or "").strip()
        if not entry_id:
            raise ValueError("Missing entry_id")
        return {"success": True, "result": await _ws_command({"type": "config_entries/remove", "entry_id": entry_id})}
    if action == "list_repairs":
        return {"success": True, "issues": await _ws_command({"type": "repairs/list_issues"})}
    if action == "ignore_repair":
        issue_id = str(args.get("issue_id") or "").strip()
        domain = str(args.get("domain") or "").strip()
        if not issue_id or not domain:
            raise ValueError("Missing domain or issue_id")
        return {"success": True, "result": await _ws_command({"type": "repairs/ignore_issue", "domain": domain, "issue_id": issue_id})}
    if action == "raw_ws":
        message = args.get("message")
        if isinstance(message, str):
            message = json.loads(message)
        if not isinstance(message, dict):
            raise ValueError("Missing raw WebSocket message object")
        return {"success": True, "result": await _ws_command(message)}
    raise ValueError(f"Unsupported integration action: {action}")


def _build_service_payload(
    entity_id: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the JSON payload for a HA service call."""
    payload: Dict[str, Any] = {}
    if data:
        payload.update(data)
    # entity_id parameter takes precedence over data["entity_id"]
    if entity_id:
        payload["entity_id"] = entity_id
    return payload


def _parse_service_response(
    domain: str,
    service: str,
    result: Any,
) -> Dict[str, Any]:
    """Parse HA service call response into a structured result."""
    affected = []
    if isinstance(result, list):
        for s in result:
            affected.append({
                "entity_id": s.get("entity_id", ""),
                "state": s.get("state", ""),
            })

    return {
        "success": True,
        "service": f"{domain}.{service}",
        "affected_entities": affected,
    }


def _slugify_automation_id(alias: str) -> str:
    """Derive a stable automation_id from an automation alias."""
    slug = re.sub(r"[^a-z0-9_]+", "_", alias.strip().lower())
    slug = re.sub(r"_+", "_", slug).strip("_")
    if not slug or not slug[0].isalpha():
        slug = f"automation_{slug}" if slug else "automation"
    return slug


def _normalize_automation_id(automation_id: str) -> str:
    """Validate and normalize an automation config ID."""
    if not automation_id:
        raise ValueError("Missing required parameter: automation_id")
    if not _AUTOMATION_ID_RE.match(automation_id):
        raise ValueError(f"Invalid automation_id format: {automation_id}")
    return automation_id.split(".", 1)[1] if automation_id.startswith("automation.") else automation_id


def _parse_automation_config(config: Any) -> Dict[str, Any]:
    """Parse and validate an automation config payload."""
    if isinstance(config, str):
        try:
            config = json.loads(config) if config.strip() else None
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string in 'config' parameter: {e}") from e
    if not isinstance(config, dict):
        raise ValueError("Missing or invalid required parameter: config")

    missing = [field for field in ("alias", "trigger", "action") if field not in config or config[field] in (None, "")]
    if missing:
        raise ValueError(f"Automation config missing required field(s): {', '.join(missing)}")

    _validate_safe_automation_actions(config.get("action"))
    return config


def _blocked_service_domain(service_name: str) -> Optional[str]:
    """Return blocked service domain if service_name references one."""
    if "." not in service_name:
        return None
    domain = service_name.split(".", 1)[0]
    return domain if domain in _BLOCKED_DOMAINS else None


def _validate_safe_automation_actions(node: Any) -> None:
    """Reject automation actions that call dangerous HA service domains."""
    if isinstance(node, dict):
        for service_key in ("service", "action"):
            service_value = node.get(service_key)
            if isinstance(service_value, str):
                blocked_domain = _blocked_service_domain(service_value)
                if blocked_domain:
                    raise ValueError(
                        f"Automation action service '{service_value}' is blocked for security. "
                        f"Blocked domains: {', '.join(sorted(_BLOCKED_DOMAINS))}."
                    )
        domain = node.get("domain")
        if isinstance(domain, str) and domain in _BLOCKED_DOMAINS:
            raise ValueError(
                f"Automation action domain '{domain}' is blocked for security. "
                f"Blocked domains: {', '.join(sorted(_BLOCKED_DOMAINS))}."
            )
        for value in node.values():
            _validate_safe_automation_actions(value)
    elif isinstance(node, list):
        for item in node:
            _validate_safe_automation_actions(item)


async def _async_call_service(
    domain: str,
    service: str,
    entity_id: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Call a Home Assistant service."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/services/{domain}/{service}"
    payload = _build_service_payload(entity_id, data)

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            headers=_get_headers(hass_token),
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            resp.raise_for_status()
            result = await resp.json()

    return _parse_service_response(domain, service, result)


async def _async_automation_manage(
    action: str,
    automation_id: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Manage Home Assistant automations through WebSocket config commands."""
    import aiohttp

    hass_url, hass_token = _get_config()
    base_url = f"{hass_url}/api/config/automation/config"

    async def rest_fallback() -> Dict[str, Any]:
        async with aiohttp.ClientSession() as session:
            if action == "list":
                async with session.get(base_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    resp.raise_for_status()
                    result = await resp.json()
                return {"success": True, "action": action, "source": "rest", "automations": result, "count": len(result) if isinstance(result, list) else None}

            normalized_id = _normalize_automation_id(automation_id or "")
            automation_url = f"{base_url}/{normalized_id}"

            if action == "get":
                async with session.get(automation_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    resp.raise_for_status()
                    result = await resp.json()
                return {"success": True, "action": action, "source": "rest", "automation_id": normalized_id, "automation": result}

            if action in {"create", "update"}:
                async with session.post(
                    automation_url,
                    headers=_get_headers(hass_token),
                    json=config,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    resp.raise_for_status()
                    result = await resp.json()
                await _async_reload_automations(session, hass_url, hass_token)
                return {"success": True, "action": action, "source": "rest", "automation_id": normalized_id, "automation": result, "reloaded": True}

            if action == "delete":
                async with session.delete(automation_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    resp.raise_for_status()
                    try:
                        result = await resp.json()
                    except aiohttp.ContentTypeError:
                        result = None
                await _async_reload_automations(session, hass_url, hass_token)
                return {"success": True, "action": action, "source": "rest", "automation_id": normalized_id, "result": result, "reloaded": True}

        raise ValueError(f"Unsupported action: {action}")

    try:
        if action == "list":
            result = await _ws_command({"type": "automation/config/list"})
            return {"success": True, "action": action, "source": "websocket", "automations": result, "count": len(result) if isinstance(result, list) else None}

        normalized_id = _normalize_automation_id(automation_id or "")

        if action == "get":
            result = await _ws_command({"type": "automation/config/item", "id": normalized_id})
            return {"success": True, "action": action, "source": "websocket", "automation_id": normalized_id, "automation": result}

        if action in {"create", "update"}:
            if not isinstance(config, dict):
                raise ValueError("Missing or invalid required parameter: config")
            payload = {"type": "automation/config/save", "id": normalized_id, "config": config}
            result = await _ws_command(payload)
            return {"success": True, "action": action, "source": "websocket", "automation_id": normalized_id, "automation": result, "reloaded": True}

        if action == "delete":
            result = await _ws_command({"type": "automation/config/delete", "id": normalized_id})
            return {"success": True, "action": action, "source": "websocket", "automation_id": normalized_id, "result": result, "reloaded": True}

    except ValueError:
        raise
    except Exception as ws_error:
        logger.warning("Automation WebSocket config API failed; trying REST fallback: %s", ws_error)
        try:
            result = await rest_fallback()
            result["websocket_error"] = str(ws_error)
            return result
        except Exception as rest_error:
            raise RuntimeError(
                f"Automation config read/write failed via WebSocket and REST. "
                f"WebSocket error: {ws_error}. REST error: {rest_error}"
            ) from rest_error

    raise ValueError(f"Unsupported action: {action}")


def _build_zigbee_request(action: str, args: Dict[str, Any]) -> tuple[str, str, Dict[str, Any], float]:
    """Validate Zigbee2MQTT args and build topic/payload/timeout."""
    if action == "permit_join":
        duration = args.get("duration", 60)
        try:
            duration = int(duration)
        except (TypeError, ValueError) as e:
            raise ValueError("duration must be an integer") from e
        if duration < 0 or duration > 254:
            raise ValueError("duration must be between 0 and 254 seconds")
        return "permit_join", "permit_join", {"value": True, "time": duration}, duration + 10

    if action == "rename_device":
        friendly_name = args.get("friendly_name", "")
        new_name = args.get("new_name", "")
        if not isinstance(friendly_name, str) or not friendly_name.strip():
            raise ValueError("Missing required parameter: friendly_name")
        if not isinstance(new_name, str) or not new_name.strip():
            raise ValueError("Missing required parameter: new_name")
        return "device/rename", "device/rename", {"from": friendly_name.strip(), "to": new_name.strip()}, 30

    if action == "remove_device":
        ieee_address = args.get("ieee_address", "")
        if not isinstance(ieee_address, str) or not ieee_address.strip():
            raise ValueError("remove_device requires explicit ieee_address")
        return "device/remove", "device/remove", {"id": ieee_address.strip()}, 30

    raise ValueError("Invalid action. Expected one of: permit_join, rename_device, list_devices, remove_device")


def _decode_mqtt_payload(payload: bytes) -> Any:
    """Decode a Zigbee2MQTT payload as JSON when possible."""
    text = payload.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _make_mqtt_client():
    """Create a paho MQTT client compatible with paho-mqtt 1.x and 2.x."""
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed; install hermes-agent[homeassistant]")
    if hasattr(mqtt, "CallbackAPIVersion"):
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    return mqtt.Client()


def _mqtt_request(response_topic: str, request_topic: Optional[str] = None, payload: Optional[Dict[str, Any]] = None, timeout: float = 30) -> Dict[str, Any]:
    """Subscribe, optionally publish, and wait for one Zigbee2MQTT response."""
    host, port, username, password = _get_mqtt_config()
    connected = threading.Event()
    subscribed = threading.Event()
    received = threading.Event()
    response: Dict[str, Any] = {}
    client = _make_mqtt_client()

    if username:
        client.username_pw_set(username, password)

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            client.subscribe(response_topic)
            connected.set()
        else:
            response["error"] = f"MQTT connection failed with code {reason_code}"
            connected.set()

    def on_subscribe(client, userdata, mid, reason_codes=None, properties=None):
        subscribed.set()

    def on_message(client, userdata, message):
        if message.topic == response_topic:
            response["topic"] = message.topic
            response["payload"] = _decode_mqtt_payload(message.payload)
            received.set()

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message

    try:
        client.connect_async(host, port, keepalive=30)
        client.loop_start()
        if not connected.wait(5):
            raise TimeoutError(f"Timed out connecting to MQTT broker {host}:{port}")
        if response.get("error"):
            raise RuntimeError(response["error"])
        if not subscribed.wait(5):
            raise TimeoutError(f"Timed out subscribing to MQTT topic {response_topic}")
        if request_topic:
            info = client.publish(request_topic, json.dumps(payload or {}), qos=0)
            info.wait_for_publish(timeout=5)
        if not received.wait(timeout):
            raise TimeoutError(f"Timed out waiting for MQTT response on {response_topic}")
        return {"success": True, "response": response}
    finally:
        client.loop_stop()
        client.disconnect()


def _zigbee_manage(action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Manage Zigbee2MQTT bridge actions over MQTT."""
    base_topic = "zigbee2mqtt/bridge"
    if action == "list_devices":
        result = _mqtt_request(f"{base_topic}/devices", timeout=30)
        return {"success": True, "action": action, "devices": result["response"].get("payload")}

    request_path, response_path, payload, timeout = _build_zigbee_request(action, args)
    result = _mqtt_request(
        response_topic=f"{base_topic}/response/{response_path}",
        request_topic=f"{base_topic}/request/{request_path}",
        payload=payload,
        timeout=timeout,
    )
    return {"success": True, "action": action, "request": payload, "response": result["response"]}


async def _async_reload_automations(session, hass_url: str, hass_token: str) -> None:
    """Reload Home Assistant automations after config changes."""
    import aiohttp

    url = f"{hass_url}/api/services/automation/reload"
    async with session.post(url, headers=_get_headers(hass_token), json={}, timeout=aiohttp.ClientTimeout(total=15)) as resp:
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Sync wrappers (handler signature: (args, **kw) -> str)
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async coroutine from a sync handler."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop -- create a new thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=30)
    else:
        return asyncio.run(coro)


def _handle_list_entities(args: dict, **kw) -> str:
    """Handler for ha_list_entities tool."""
    domain = args.get("domain")
    area = args.get("area")
    try:
        result = _run_async(_async_list_entities(domain=domain, area=area))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_list_entities error: %s", e)
        return tool_error(f"Failed to list entities: {e}")


def _handle_get_state(args: dict, **kw) -> str:
    """Handler for ha_get_state tool."""
    entity_id = args.get("entity_id", "")
    if not entity_id:
        return tool_error("Missing required parameter: entity_id")
    if not _ENTITY_ID_RE.match(entity_id):
        return tool_error(f"Invalid entity_id format: {entity_id}")
    try:
        result = _run_async(_async_get_state(entity_id))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_get_state error: %s", e)
        return tool_error(f"Failed to get state for {entity_id}: {e}")


def _handle_detect_capabilities(args: dict, **kw) -> str:
    """Handler for ha_detect_capabilities tool."""
    try:
        result = _run_async(_async_detect_capabilities())
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_detect_capabilities error: %s", e)
        return tool_error(f"Failed to detect Home Assistant capabilities: {e}")


def _handle_observe_changes(args: dict, **kw) -> str:
    """Handler for ha_observe_changes tool."""
    duration = args.get("duration_seconds", 10)
    include_domains = args.get("include_domains") or []
    ignore_domains = args.get("ignore_domains") or []
    try:
        duration = int(duration)
    except (TypeError, ValueError):
        return tool_error("duration_seconds must be an integer")
    if duration < 3 or duration > 20:
        return tool_error("duration_seconds must be between 3 and 20")
    if not isinstance(include_domains, list):
        return tool_error("include_domains must be a list of domain strings")
    if not isinstance(ignore_domains, list):
        return tool_error("ignore_domains must be a list of domain strings")
    try:
        result = _run_async(
            _async_observe_changes(
                duration_seconds=duration,
                include_domains=include_domains,
                ignore_domains=ignore_domains,
            )
        )
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_observe_changes error: %s", e)
        return tool_error(f"Failed to observe Home Assistant changes: {e}")


def _handle_list_areas(args: dict, **kw) -> str:
    """Handler for ha_list_areas tool."""
    try:
        result = _run_async(_async_list_areas())
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_list_areas error: %s", e)
        return tool_error(f"Failed to list areas: {e}")


def _handle_create_area(args: dict, **kw) -> str:
    """Handler for ha_create_area tool."""
    name = args.get("name", "")
    if not isinstance(name, str) or not name.strip():
        return tool_error("Missing required parameter: name")

    try:
        result = _run_async(_async_create_area(name.strip()))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_create_area error: %s", e)
        return tool_error(f"Failed to create area: {e}")


def _handle_assign_area(args: dict, **kw) -> str:
    """Handler for ha_assign_area tool."""
    entity_id = args.get("entity_id", "")
    area_id = args.get("area_id", "")
    if not entity_id:
        return tool_error("Missing required parameter: entity_id")
    if not _ENTITY_ID_RE.match(entity_id):
        return tool_error(f"Invalid entity_id format: {entity_id}")
    if not isinstance(area_id, str) or not area_id.strip():
        return tool_error("Missing required parameter: area_id")

    try:
        result = _run_async(_async_assign_area(entity_id, area_id.strip()))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_assign_area error: %s", e)
        return tool_error(f"Failed to assign area for {entity_id}: {e}")


def _handle_entity_rename(args: dict, **kw) -> str:
    """Handler for ha_entity_rename tool."""
    entity_id = args.get("entity_id", "")
    name = args.get("name")
    icon = args.get("icon")
    new_entity_id = args.get("new_entity_id")
    area_id = args.get("area_id")
    if not entity_id:
        return tool_error("Missing required parameter: entity_id")
    if not _ENTITY_ID_RE.match(entity_id):
        return tool_error(f"Invalid entity_id format: {entity_id}")
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return tool_error("Invalid name parameter")
        name = name.strip()
    if icon is not None and (not isinstance(icon, str) or not icon.strip()):
        return tool_error("Invalid icon parameter")
    if new_entity_id is not None:
        if not isinstance(new_entity_id, str) or not _ENTITY_ID_RE.match(new_entity_id):
            return tool_error(f"Invalid new_entity_id format: {new_entity_id}")
    if area_id is not None:
        if not isinstance(area_id, str) or not area_id.strip():
            return tool_error("Invalid area_id parameter")
        area_id = area_id.strip()
    if name is None and icon is None and new_entity_id is None and area_id is None:
        return tool_error("At least one of name, icon, new_entity_id, or area_id is required")

    approval_error = _check_ha_tool_approval(
        "ha_entity_rename",
        "update_registry",
        {
            "entity_id": entity_id,
            "new_entity_id": new_entity_id,
            "name": name,
            "area_id": area_id,
        },
        "This changes the Home Assistant entity registry.",
    )
    if approval_error:
        return tool_error(approval_error)

    try:
        result = _run_async(
            _async_entity_rename(
                entity_id,
                name=name,
                icon=icon.strip() if icon else None,
                new_entity_id=new_entity_id,
                area_id=area_id,
            )
        )
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_entity_rename error: %s", e)
        return tool_error(f"Failed to update entity {entity_id}: {e}")


def _handle_call_service(args: dict, **kw) -> str:
    """Handler for ha_call_service tool."""
    domain = args.get("domain", "")
    service = args.get("service", "")
    if not domain or not service:
        return tool_error("Missing required parameters: domain and service")

    # Validate domain/service format BEFORE the blocklist check — prevents
    # path traversal in /api/services/{domain}/{service} and blocklist bypass
    # via payloads like "shell_command/../light".
    if not _SERVICE_NAME_RE.match(domain):
        return tool_error(f"Invalid domain format: {domain!r}")
    if not _SERVICE_NAME_RE.match(service):
        return tool_error(f"Invalid service format: {service!r}")

    if domain in _BLOCKED_DOMAINS:
        return json.dumps({
            "error": f"Service domain '{domain}' is blocked for security. "
            f"Blocked domains: {', '.join(sorted(_BLOCKED_DOMAINS))}"
        })

    entity_id = args.get("entity_id")
    if entity_id and not _ENTITY_ID_RE.match(entity_id):
        return tool_error(f"Invalid entity_id format: {entity_id}")

    data = args.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data) if data.strip() else None
        except json.JSONDecodeError as e:
            return tool_error(f"Invalid JSON string in 'data' parameter: {e}")

    try:
        result = _run_async(_async_call_service(domain, service, entity_id, data))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_call_service error: %s", e)
        return tool_error(f"Failed to call {domain}.{service}: {e}")


# ---------------------------------------------------------------------------
# List services
# ---------------------------------------------------------------------------

async def _async_list_services(domain: Optional[str] = None) -> Dict[str, Any]:
    """Fetch available services from HA and optionally filter by domain."""
    import aiohttp

    hass_url, hass_token = _get_config()
    url = f"{hass_url}/api/services"
    headers = {"Authorization": f"Bearer {hass_token}", "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            resp.raise_for_status()
            services = await resp.json()

    if domain:
        services = [s for s in services if s.get("domain") == domain]

    # Compact the output for context efficiency
    result = []
    for svc_domain in services:
        d = svc_domain.get("domain", "")
        domain_services = {}
        for svc_name, svc_info in svc_domain.get("services", {}).items():
            svc_entry: Dict[str, Any] = {"description": svc_info.get("description", "")}
            fields = svc_info.get("fields", {})
            if fields:
                svc_entry["fields"] = {
                    k: v.get("description", "") for k, v in fields.items()
                    if isinstance(v, dict)
                }
            domain_services[svc_name] = svc_entry
        result.append({"domain": d, "services": domain_services})

    return {"count": len(result), "domains": result}


def _handle_list_services(args: dict, **kw) -> str:
    """Handler for ha_list_services tool."""
    domain = args.get("domain")
    try:
        result = _run_async(_async_list_services(domain=domain))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_list_services error: %s", e)
        return tool_error(f"Failed to list services: {e}")


def _handle_automation_manage(args: dict, **kw) -> str:
    """Handler for ha_automation_manage tool."""
    action = args.get("action", "")
    if action not in {"list", "get", "create", "update", "delete"}:
        return tool_error("Invalid action. Expected one of: list, get, create, update, delete")

    automation_id = args.get("automation_id")
    config = args.get("config")
    try:
        parsed_config = None
        if action in {"create", "update"}:
            parsed_config = _parse_automation_config(config)
            if not automation_id and action == "create":
                automation_id = _slugify_automation_id(str(parsed_config["alias"]))
        if action == "delete":
            normalized_id = _normalize_automation_id(str(automation_id or ""))
            approval_error = _check_ha_tool_approval(
                "ha_automation_manage",
                action,
                normalized_id,
                "This deletes a Home Assistant automation configuration.",
            )
            if approval_error:
                return tool_error(approval_error)
        result = _run_async(_async_automation_manage(action, automation_id, parsed_config))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_automation_manage error: %s", e)
        return tool_error(f"Failed to manage automation: {e}")


def _handle_matter_manage(args: dict, **kw) -> str:
    """Handler for ha_matter_manage tool."""
    action = args.get("action", "")
    if action not in {"expose", "unexpose", "list_exposed"}:
        return tool_error("Invalid action. Expected one of: expose, unexpose, list_exposed")

    entity_id = args.get("entity_id", "")
    if action in {"expose", "unexpose"}:
        if not entity_id:
            return tool_error("Missing required parameter: entity_id")
        if not _ENTITY_ID_RE.match(entity_id):
            return tool_error(f"Invalid entity_id format: {entity_id}")

    try:
        result = _run_async(_async_matter_manage(action, entity_id or None))
        return json.dumps({"result": result})
    except ValueError as e:
        logger.error("ha_matter_manage validation error: %s", e)
        return tool_error(str(e))
    except Exception as e:
        logger.error("ha_matter_manage error: %s", e)
        return tool_error(str(e) or "Failed to manage Matter exposure")


def _handle_zigbee_manage(args: dict, **kw) -> str:
    """Handler for ha_zigbee_manage tool."""
    action = args.get("action", "")
    if action in _HA_APPROVAL_ZIGBEE_ACTIONS:
        approval_error = _check_ha_tool_approval(
            "ha_zigbee_manage",
            action,
            args.get("ieee_address") or args.get("friendly_name"),
            "This removes a Zigbee2MQTT device from the network registry.",
        )
        if approval_error:
            return tool_error(approval_error)
    try:
        result = _zigbee_manage(action, args)
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_zigbee_manage error: %s", e)
        return tool_error(f"Failed to manage Zigbee2MQTT: {e}")


def _handle_supervisor_manage(args: dict, **kw) -> str:
    """Handler for ha_supervisor_manage tool."""
    action = args.get("action", "")
    if action in _HA_APPROVAL_SUPERVISOR_ACTIONS:
        approval_error = _check_ha_tool_approval(
            "ha_supervisor_manage",
            action,
            args.get("addon") or args.get("slug") or args.get("path"),
            "This is a destructive or disruptive Supervisor action.",
        )
        if approval_error:
            return tool_error(approval_error)
    try:
        result = _run_async(_async_supervisor_manage(action, args))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_supervisor_manage error: %s", e)
        return tool_error(f"Failed to manage Home Assistant Supervisor: {e}")


def _handle_update_manage(args: dict, **kw) -> str:
    """Handler for ha_update_manage tool."""
    action = args.get("action", "")
    try:
        result = _run_async(_async_update_manage(action, args))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_update_manage error: %s", e)
        return tool_error(f"Failed to manage Home Assistant updates: {e}")


def _handle_admin_diagnose(args: dict, **kw) -> str:
    """Handler for ha_admin_diagnose tool."""
    action = args.get("action", "run")
    try:
        result = _run_async(_async_admin_diagnose(action, args))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_admin_diagnose error: %s", e)
        return tool_error(f"Failed to diagnose Home Assistant admin capabilities: {e}")


def _handle_config_read(args: dict, **kw) -> str:
    """Handler for ha_config_read tool."""
    try:
        max_bytes = int(args.get("max_bytes", 512_000))
        result = _run_async(_async_config_read(str(args.get("path") or ""), max_bytes=max_bytes))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_config_read error: %s", e)
        return tool_error(f"Failed to read Home Assistant config file: {e}")


def _handle_config_write(args: dict, **kw) -> str:
    """Handler for ha_config_write tool."""
    path_value = str(args.get("path") or "")
    content = args.get("content")
    if not isinstance(content, str):
        return tool_error("Config content must be a string")
    try:
        _, relative_path = _resolve_ha_config_path(path_value)
    except Exception as e:
        return tool_error(str(e))

    approval_error = _check_ha_tool_approval(
        "ha_config_write",
        "write",
        f"/config/{relative_path}",
        "This writes a Home Assistant Core config file.",
    )
    if approval_error:
        return tool_error(approval_error)

    try:
        result = _run_async(_async_config_write(
            path_value,
            content,
            backup=bool(args.get("backup", True)),
            validate_yaml=bool(args.get("validate_yaml", True)),
            create_parent_dirs=bool(args.get("create_parent_dirs", False)),
        ))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_config_write error: %s", e)
        return tool_error(f"Failed to write Home Assistant config file: {e}")


def _handle_config_reload(args: dict, **kw) -> str:
    """Handler for ha_config_reload tool."""
    try:
        result = _run_async(_async_config_reload())
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_config_reload error: %s", e)
        return tool_error(f"Failed to reload Home Assistant core config: {e}")


def _handle_dashboard_manage(args: dict, **kw) -> str:
    """Handler for ha_dashboard_manage tool."""
    action = args.get("action", "")
    try:
        result = _run_async(_async_dashboard_manage(action, args))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_dashboard_manage error: %s", e)
        return tool_error(f"Failed to manage Home Assistant dashboard: {e}")


def _handle_integration_manage(args: dict, **kw) -> str:
    """Handler for ha_integration_manage tool."""
    action = args.get("action", "")
    if action in _HA_APPROVAL_INTEGRATION_ACTIONS:
        approval_error = _check_ha_tool_approval(
            "ha_integration_manage",
            action,
            args.get("entry_id") or args.get("domain") or args.get("issue_id"),
            "This removes a Home Assistant integration/config entry.",
        )
        if approval_error:
            return tool_error(approval_error)
    try:
        result = _run_async(_async_integration_manage(action, args))
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_integration_manage error: %s", e)
        return tool_error(f"Failed to manage Home Assistant integrations: {e}")


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _check_ha_available() -> bool:
    """Tool is only available when HASS_TOKEN is set."""
    return bool(os.getenv("HASS_TOKEN"))


def _check_mqtt_available() -> bool:
    """Tool is only available when paho-mqtt can be imported."""
    return mqtt is not None


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

HA_LIST_ENTITIES_SCHEMA = {
    "name": "ha_list_entities",
    "description": (
        "List Home Assistant entities. Optionally filter by domain "
        "(light, switch, climate, sensor, binary_sensor, cover, fan, etc.) "
        "or by area name (living room, kitchen, bedroom, etc.)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": (
                    "Entity domain to filter by (e.g. 'light', 'switch', 'climate', "
                    "'sensor', 'binary_sensor', 'cover', 'fan', 'media_player'). "
                    "Omit to list all entities."
                ),
            },
            "area": {
                "type": "string",
                "description": (
                    "Area/room name to filter by (e.g. 'living room', 'kitchen'). "
                    "Matches against entity friendly names. Omit to list all."
                ),
            },
        },
        "required": [],
    },
}

HA_GET_STATE_SCHEMA = {
    "name": "ha_get_state",
    "description": (
        "Get the detailed state of a single Home Assistant entity, including all "
        "attributes (brightness, color, temperature setpoint, sensor readings, etc.)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "entity_id": {
                "type": "string",
                "description": (
                    "The entity ID to query (e.g. 'light.living_room', "
                    "'climate.thermostat', 'sensor.temperature')."
                ),
            },
        },
        "required": ["entity_id"],
    },
}

HA_DETECT_CAPABILITIES_SCHEMA = {
    "name": "ha_detect_capabilities",
    "description": (
        "Detect configured Home Assistant integrations relevant for onboarding, "
        "including MQTT, Matter, and Homematic."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

HA_OBSERVE_CHANGES_SCHEMA = {
    "name": "ha_observe_changes",
    "description": (
        "Briefly listen to Home Assistant state_changed events to identify which "
        "device or entity the user just touched. Best used after telling the user "
        "to press a button, open a contact sensor, move a motion sensor, or switch a device."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "duration_seconds": {
                "type": "integer",
                "minimum": 3,
                "maximum": 20,
                "description": "Listening window in seconds. Use 10 by default; maximum 20.",
            },
            "include_domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional HA domains to include, e.g. ['binary_sensor', 'switch', 'button'].",
            },
            "ignore_domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional extra HA domains to ignore.",
            },
        },
        "required": [],
    },
}

HA_LIST_AREAS_SCHEMA = {
    "name": "ha_list_areas",
    "description": "List Home Assistant areas via the area registry WebSocket API.",
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

HA_CREATE_AREA_SCHEMA = {
    "name": "ha_create_area",
    "description": "Create a new Home Assistant area via the area registry WebSocket API.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Display name for the new area, e.g. 'Büro' or 'Wohnzimmer'.",
            },
        },
        "required": ["name"],
    },
}

HA_SUPERVISOR_MANAGE_SCHEMA = {
    "name": "ha_supervisor_manage",
    "description": (
        "Full Home Assistant Supervisor administration: inspect system status, list and manage add-ons, "
        "run Core/Supervisor/OS updates, create/list backups, read logs, and call raw Supervisor API endpoints. "
        "Ask for user confirmation before destructive or disruptive actions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "info", "list_addons", "addon_info", "install_addon", "uninstall_addon",
                    "start_addon", "stop_addon", "restart_addon", "update_addon", "addon_logs",
                    "core_info", "supervisor_info", "os_info", "update_core", "update_supervisor",
                    "update_os", "create_backup", "list_backups", "raw_request",
                ],
            },
            "addon": {"type": "string", "description": "Add-on slug, e.g. core_mosquitto."},
            "slug": {"type": "string", "description": "Alias for addon slug."},
            "backup_type": {"type": "string", "enum": ["full", "partial"]},
            "method": {"type": "string", "description": "HTTP method for raw_request."},
            "path": {"type": "string", "description": "Supervisor API path for raw_request, starting with /."},
            "data": {"type": "object", "description": "Optional request body."},
        },
        "required": ["action"],
    },
}

HA_UPDATE_MANAGE_SCHEMA = {
    "name": "ha_update_manage",
    "description": (
        "Inspect and install Home Assistant updates. Handles update.* entities, including HACS updates, "
        "and can coordinate Supervisor/Core/OS/add-on updates with a backup-first workflow. "
        "Ask for user confirmation before installing updates."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["status", "list_updates", "install_update", "install_updates", "update_everything"],
            },
            "entity_id": {"type": "string", "description": "Single update.* entity to install."},
            "entity_ids": {"type": ["array", "string"], "description": "Comma-separated string or array of update.* entities to install."},
            "include": {"type": "string", "description": "Optional text filter for bulk update entity installs."},
            "exclude": {"type": "string", "description": "Optional text filter to exclude update entities."},
            "only_available": {"type": "boolean", "description": "Only install entities whose state is on. Default true."},
            "include_hacs": {"type": "boolean", "description": "Include HACS update entities in bulk installs. Default true."},
            "include_core": {"type": "boolean", "description": "Include core/supervisor/os update entities in bulk installs. Default true."},
            "version": {"type": "string", "description": "Optional version passed to update.install."},
            "backup": {"type": "boolean", "description": "Create a Supervisor backup before update_everything; default true. Passed to update.install when explicitly set."},
            "backup_type": {"type": "string", "enum": ["full", "partial"], "description": "Backup type for update_everything. Default full."},
            "force_without_backup": {"type": "boolean", "description": "Proceed with update_everything if backup creation fails."},
            "update_core": {"type": "boolean", "description": "Include Supervisor Core update in update_everything. Default true."},
            "update_supervisor": {"type": "boolean", "description": "Include Supervisor update in update_everything. Default true."},
            "update_os": {"type": "boolean", "description": "Include OS update in update_everything. Default true."},
            "addons": {"type": "boolean", "description": "Include Supervisor add-on updates in update_everything. Default true."},
            "update_entities": {"type": "boolean", "description": "Include update.* entities such as HACS in update_everything. Default true."},
        },
        "required": ["action"],
    },
}

HA_ADMIN_DIAGNOSE_SCHEMA = {
    "name": "ha_admin_diagnose",
    "description": (
        "Read-only diagnostic tool for Home Assistant admin capabilities. Probes critical REST, WebSocket, "
        "Supervisor, dashboard, automation, integration, and update paths and classifies failures such as "
        "403 permissions, 404 missing endpoints, and unsupported WebSocket commands. Use after admin tool failures "
        "before telling the user manual UI work is required."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["run", "quick"],
                "description": "Run the full read-only probe set or a shorter critical-path probe set. Default run.",
            },
        },
        "required": [],
    },
}

HA_CONFIG_READ_SCHEMA = {
    "name": "ha_config_read",
    "description": "Read a Home Assistant Core config file from the mounted /config directory, such as configuration.yaml, scripts.yaml, scenes.yaml, or templates.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Relative path below /config, or /config/... for user-facing paths."},
            "max_bytes": {"type": "integer", "description": "Maximum file size to return. Default 512000."},
        },
        "required": ["path"],
    },
}

HA_CONFIG_WRITE_SCHEMA = {
    "name": "ha_config_write",
    "description": "Write a Home Assistant Core config file below /config with sandboxed paths, backup before write, and optional YAML validation. Ask for confirmation before use.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Relative path below /config, or /config/... for user-facing paths."},
            "content": {"type": "string", "description": "Full new file content to write."},
            "backup": {"type": "boolean", "description": "Create a backup before writing. Default true."},
            "validate_yaml": {"type": "boolean", "description": "Validate .yaml/.yml syntax when PyYAML is available. Default true."},
            "create_parent_dirs": {"type": "boolean", "description": "Create missing parent directories. Default false."},
        },
        "required": ["path", "content"],
    },
}

HA_CONFIG_RELOAD_SCHEMA = {
    "name": "ha_config_reload",
    "description": "Reload Home Assistant Core config by calling homeassistant.reload_core_config. Ask for confirmation before use after writes.",
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

HA_DASHBOARD_MANAGE_SCHEMA = {
    "name": "ha_dashboard_manage",
    "description": (
        "Create, read, update, delete, and fully save Home Assistant Lovelace dashboards. "
        "Backs up dashboard JSON before writes where possible. Ask for user confirmation before writes."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list_dashboards", "create_dashboard", "update_dashboard", "delete_dashboard",
                    "get_dashboard", "save_dashboard", "backup_dashboard", "add_view", "update_view",
                    "delete_view", "add_card", "update_card", "delete_card", "raw_ws",
                ],
            },
            "url_path": {"type": "string", "description": "Dashboard URL path/slug. Omit for the default dashboard."},
            "dashboard": {"type": "string", "description": "Alias for url_path."},
            "dashboard_id": {"type": "string", "description": "Dashboard storage ID for REST metadata operations. Defaults to url_path."},
            "id": {"type": "string", "description": "Alias for dashboard_id."},
            "title": {"type": "string"},
            "icon": {"type": "string"},
            "mode": {"type": "string", "description": "Dashboard mode, usually storage or yaml."},
            "show_in_sidebar": {"type": "boolean"},
            "require_admin": {"type": "boolean"},
            "config": {"type": ["object", "string"], "description": "Full Lovelace config for save_dashboard."},
            "view_index": {"type": "integer"},
            "view": {"type": ["object", "string"], "description": "View object or patch."},
            "card_index": {"type": "integer"},
            "card": {"type": ["object", "string"], "description": "Card object or patch."},
            "patch": {"type": ["object", "string"], "description": "Patch object for update actions."},
            "message": {"type": ["object", "string"], "description": "Raw Home Assistant WebSocket message for raw_ws."},
        },
        "required": ["action"],
    },
}

HA_INTEGRATION_MANAGE_SCHEMA = {
    "name": "ha_integration_manage",
    "description": (
        "Inspect and manage Home Assistant integrations/config entries and repairs. "
        "Some integrations require interactive config flows or OAuth and cannot be fully installed without user participation."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list_entries", "reload_entry", "remove_entry", "list_repairs", "ignore_repair", "raw_ws"],
            },
            "entry_id": {"type": "string"},
            "domain": {"type": "string"},
            "issue_id": {"type": "string"},
            "message": {"type": ["object", "string"], "description": "Raw Home Assistant WebSocket message for raw_ws."},
        },
        "required": ["action"],
    },
}

HA_ASSIGN_AREA_SCHEMA = {
    "name": "ha_assign_area",
    "description": "Assign an existing Home Assistant entity to an area via the entity registry WebSocket API.",
    "parameters": {
        "type": "object",
        "properties": {
            "entity_id": {
                "type": "string",
                "description": "Entity ID to assign, e.g. 'sensor.klima_buero_temperature'.",
            },
            "area_id": {
                "type": "string",
                "description": "Existing Home Assistant area_id, e.g. 'buero' or 'wohnzimmer'.",
            },
        },
        "required": ["entity_id", "area_id"],
    },
}

HA_ENTITY_RENAME_SCHEMA = {
    "name": "ha_entity_rename",
    "description": "Update a Home Assistant entity via the entity registry WebSocket API. Can set friendly name, icon, area, and a new entity_id in one call.",
    "parameters": {
        "type": "object",
        "properties": {
            "entity_id": {
                "type": "string",
                "description": "Existing entity ID to update, e.g. 'light.living_room'.",
            },
            "name": {
                "type": "string",
                "description": "Optional new friendly name for the entity.",
            },
            "icon": {
                "type": "string",
                "description": "Optional Material Design icon, e.g. 'mdi:lamp'.",
            },
            "new_entity_id": {
                "type": "string",
                "description": "Optional new entity_id, e.g. 'sensor.klima_buero_temperature'.",
            },
            "area_id": {
                "type": "string",
                "description": "Optional existing Home Assistant area_id, e.g. 'buero'.",
            },
        },
        "required": ["entity_id"],
    },
}

HA_LIST_SERVICES_SCHEMA = {
    "name": "ha_list_services",
    "description": (
        "List available Home Assistant services (actions) for device control. "
        "Shows what actions can be performed on each device type and what "
        "parameters they accept. Use this to discover how to control devices "
        "found via ha_list_entities."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": (
                    "Filter by domain (e.g. 'light', 'climate', 'switch'). "
                    "Omit to list services for all domains."
                ),
            },
        },
        "required": [],
    },
}

HA_CALL_SERVICE_SCHEMA = {
    "name": "ha_call_service",
    "description": (
        "Call a Home Assistant service to control a device. Use ha_list_services "
        "to discover available services and their parameters for each domain."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": (
                    "Service domain (e.g. 'light', 'switch', 'climate', "
                    "'cover', 'media_player', 'fan', 'scene', 'script')."
                ),
            },
            "service": {
                "type": "string",
                "description": (
                    "Service name (e.g. 'turn_on', 'turn_off', 'toggle', "
                    "'set_temperature', 'set_hvac_mode', 'open_cover', "
                    "'close_cover', 'set_volume_level')."
                ),
            },
            "entity_id": {
                "type": "string",
                "description": (
                    "Target entity ID (e.g. 'light.living_room'). "
                    "Some services (like scene.turn_on) may not need this."
                ),
            },
            "data": {
                "type": "string",
                "description": (
                    "Additional service data as a JSON string. Examples: "
                    '{"brightness": 255, "color_name": "blue"} for lights, '
                    '{"temperature": 22, "hvac_mode": "heat"} for climate, '
                    '{"volume_level": 0.5} for media players.'
                ),
            },
        },
        "required": ["domain", "service"],
    },
}

HA_AUTOMATION_MANAGE_SCHEMA = {
    "name": "ha_automation_manage",
    "description": (
        "Manage Home Assistant automations. List, get, create, update, or delete "
        "full automation configs, including triggers, conditions, and actions, through "
        "Home Assistant's automation WebSocket config API with REST fallback. For safety, "
        "shell_command, command_line, and python_script services are blocked in automation actions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list", "get", "create", "update", "delete"],
                "description": "Automation management action to perform.",
            },
            "automation_id": {
                "type": "string",
                "description": (
                    "Automation config ID, e.g. 'morning_lights' or "
                    "'automation.morning_lights'. Required for get, update, and delete. "
                    "For create, omitted IDs are derived from config.alias."
                ),
            },
            "config": {
                "type": "object",
                "description": (
                    "Automation config for create/update. Required fields: alias, trigger, action. "
                    "Optional fields include condition and mode."
                ),
            },
        },
        "required": ["action"],
    },
}

HA_ZIGBEE_MANAGE_SCHEMA = {
    "name": "ha_zigbee_manage",
    "description": "Manage Zigbee2MQTT devices over MQTT: permit joining, list devices, rename devices, or remove devices.",
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["permit_join", "rename_device", "list_devices", "remove_device"],
                "description": "Zigbee2MQTT management action to perform.",
            },
            "duration": {
                "type": "integer",
                "description": "Permit-join duration in seconds. Defaults to 60, maximum 254.",
            },
            "friendly_name": {
                "type": "string",
                "description": "Current Zigbee2MQTT friendly name for rename_device.",
            },
            "new_name": {
                "type": "string",
                "description": "New Zigbee2MQTT friendly name for rename_device.",
            },
            "ieee_address": {
                "type": "string",
                "description": "Explicit IEEE address for remove_device. Wildcards are not allowed.",
            },
        },
        "required": ["action"],
    },
}

SCHEMA_MATTER_MANAGE = {
    "name": "ha_matter_manage",
    "description": (
        "Manage which Home Assistant entities are exposed to Alexa via Matter Hub. "
        "Adds or removes the entity label 'matter' which Matter Hub uses to filter exposed devices."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["expose", "unexpose", "list_exposed"],
                "description": (
                    "expose adds the matter label, unexpose removes it, "
                    "list_exposed shows all labeled entities"
                ),
            },
            "entity_id": {
                "type": "string",
                "description": "Home Assistant entity ID (required for expose and unexpose)",
            },
        },
        "required": ["action"],
    },
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

from tools.registry import registry, tool_error

registry.register(
    name="ha_list_entities",
    toolset="homeassistant",
    schema=HA_LIST_ENTITIES_SCHEMA,
    handler=_handle_list_entities,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_get_state",
    toolset="homeassistant",
    schema=HA_GET_STATE_SCHEMA,
    handler=_handle_get_state,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_detect_capabilities",
    toolset="homeassistant",
    schema=HA_DETECT_CAPABILITIES_SCHEMA,
    handler=_handle_detect_capabilities,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_observe_changes",
    toolset="homeassistant",
    schema=HA_OBSERVE_CHANGES_SCHEMA,
    handler=_handle_observe_changes,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_list_areas",
    toolset="homeassistant",
    schema=HA_LIST_AREAS_SCHEMA,
    handler=_handle_list_areas,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_create_area",
    toolset="homeassistant",
    schema=HA_CREATE_AREA_SCHEMA,
    handler=_handle_create_area,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_assign_area",
    toolset="homeassistant",
    schema=HA_ASSIGN_AREA_SCHEMA,
    handler=_handle_assign_area,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_supervisor_manage",
    toolset="homeassistant",
    schema=HA_SUPERVISOR_MANAGE_SCHEMA,
    handler=_handle_supervisor_manage,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_update_manage",
    toolset="homeassistant",
    schema=HA_UPDATE_MANAGE_SCHEMA,
    handler=_handle_update_manage,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_admin_diagnose",
    toolset="homeassistant",
    schema=HA_ADMIN_DIAGNOSE_SCHEMA,
    handler=_handle_admin_diagnose,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_config_read",
    toolset="homeassistant",
    schema=HA_CONFIG_READ_SCHEMA,
    handler=_handle_config_read,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_config_write",
    toolset="homeassistant",
    schema=HA_CONFIG_WRITE_SCHEMA,
    handler=_handle_config_write,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_config_reload",
    toolset="homeassistant",
    schema=HA_CONFIG_RELOAD_SCHEMA,
    handler=_handle_config_reload,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_dashboard_manage",
    toolset="homeassistant",
    schema=HA_DASHBOARD_MANAGE_SCHEMA,
    handler=_handle_dashboard_manage,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_integration_manage",
    toolset="homeassistant",
    schema=HA_INTEGRATION_MANAGE_SCHEMA,
    handler=_handle_integration_manage,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_entity_rename",
    toolset="homeassistant",
    schema=HA_ENTITY_RENAME_SCHEMA,
    handler=_handle_entity_rename,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_list_services",
    toolset="homeassistant",
    schema=HA_LIST_SERVICES_SCHEMA,
    handler=_handle_list_services,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_call_service",
    toolset="homeassistant",
    schema=HA_CALL_SERVICE_SCHEMA,
    handler=_handle_call_service,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_automation_manage",
    toolset="homeassistant",
    schema=HA_AUTOMATION_MANAGE_SCHEMA,
    handler=_handle_automation_manage,
    check_fn=_check_ha_available,
    emoji="🏠",
)

registry.register(
    name="ha_zigbee_manage",
    toolset="homeassistant",
    schema=HA_ZIGBEE_MANAGE_SCHEMA,
    handler=_handle_zigbee_manage,
    check_fn=_check_mqtt_available,
    emoji="🏠",
)

registry.register(
    name="ha_matter_manage",
    toolset="homeassistant",
    schema=SCHEMA_MATTER_MANAGE,
    handler=_handle_matter_manage,
    check_fn=_check_ha_available,
    emoji="📡",
)
