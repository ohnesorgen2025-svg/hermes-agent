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

    if domain in {"button", "input_button", "event"}:
        score += 55
        reasons.append("button_or_event")
    elif domain in {"binary_sensor", "switch", "light", "cover", "lock", "fan"}:
        score += 35
        reasons.append("interactive_domain")
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

    events.sort(key=lambda item: item.get("score", 0), reverse=True)
    strong = [item for item in events if item.get("score", 0) >= 60]
    return {
        "success": True,
        "duration_seconds": duration_seconds,
        "event_count": len(events),
        "strong_count": len(strong),
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
    """Manage Home Assistant automations through config REST endpoints."""
    import aiohttp

    hass_url, hass_token = _get_config()
    base_url = f"{hass_url}/api/config/automation/config"

    async with aiohttp.ClientSession() as session:
        if action == "list":
            async with session.get(base_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
                resp.raise_for_status()
                result = await resp.json()
            return {"success": True, "action": action, "automations": result, "count": len(result) if isinstance(result, list) else None}

        normalized_id = _normalize_automation_id(automation_id or "")
        automation_url = f"{base_url}/{normalized_id}"

        if action == "get":
            async with session.get(automation_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=10)) as resp:
                resp.raise_for_status()
                result = await resp.json()
            return {"success": True, "action": action, "automation_id": normalized_id, "automation": result}

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
            return {"success": True, "action": action, "automation_id": normalized_id, "automation": result, "reloaded": True}

        if action == "delete":
            async with session.delete(automation_url, headers=_get_headers(hass_token), timeout=aiohttp.ClientTimeout(total=15)) as resp:
                resp.raise_for_status()
                try:
                    result = await resp.json()
                except aiohttp.ContentTypeError:
                    result = None
            await _async_reload_automations(session, hass_url, hass_token)
            return {"success": True, "action": action, "automation_id": normalized_id, "result": result, "reloaded": True}

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
    try:
        result = _zigbee_manage(action, args)
        return json.dumps({"result": result})
    except Exception as e:
        logger.error("ha_zigbee_manage error: %s", e)
        return tool_error(f"Failed to manage Zigbee2MQTT: {e}")


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
        "automation configs via the Home Assistant config API. Create and update "
        "reload automations automatically. For safety, shell_command, command_line, "
        "and python_script services are blocked in automation actions."
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
