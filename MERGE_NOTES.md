# Merge Verification Notes

Stand: Branch `merge/upstream-sync-20260609`

## Kurzfazit

- Upstream-Merge steht auf dem Branch; lokale HA-/Approval-Sicherheitssemantik blieb erhalten.
- Drei zunaechst divergente Gateway-Dateien wurden nach Angleichung der Vergleichsumgebung erneut auf Merge und `upstream/main` ausgefuehrt und liefen beidseitig gruen.
- Zwei branch-lokale Nacharbeiten wurden bewusst vorgenommen: Test-Erwartung an lokale `execute_code`-Policy angepasst und leeres lokales Plugin-Verzeichnis entfernt.

## Policy-Konflikt: `test_tools_config`

- Betroffener Test: `tests/hermes_cli/test_tools_config.py::test_get_platform_tools_expands_composite_when_mixed_with_configurable`
- Konflikt: Upstream-Test erwartete, dass `hermes-cli` implizit auch `code_execution` wieder aktiviert.
- Lokale Entscheidung: `execute_code` ist absichtlich **nicht** Teil der Default-/Core-Toolsets; Aktivierung nur via explizitem `code_execution`-Opt-in.
- Umsetzung auf diesem Branch: Test auf lokale Policy ausgerichtet, statt die lokale Sicherheitsentscheidung zu lockern.

## Stray-Artefakt: `ai-gateway`

- `plugins/model-providers/ai-gateway/` war ein leeres lokales Verzeichnis ohne `__init__.py` und ohne `plugin.yaml`.
- Es existiert nicht auf `upstream/main` und war kein getrackter Merge-Inhalt.
- Wirkung: `tests/providers/test_plugin_discovery.py` lief rot, obwohl keine Discovery-Logik defekt war.
- Umsetzung auf diesem Branch: leeres Verzeichnis entfernt.

## Equalized Divergent Comparisons

- Vergleichsproblem: Die Upstream-venv hatte `aiohttp` zunaechst nicht installiert; die Merge-venv hatte zudem eine abweichende `aiohttp`-Version.
- Angleichen: beide venvs auf `aiohttp==3.13.4` gebracht.
- Danach liefen die zuvor divergenten Dateien auf Merge und Upstream gruen:
  - `tests/gateway/test_webhook_integration.py`
  - `tests/gateway/test_weixin.py`
  - `tests/gateway/test_wecom.py`

## Known Upstream Failures

- `tests/agent/test_anthropic_adapter.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/gateway/test_background_command.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/gateway/test_gateway_shutdown.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/gateway/test_shutdown_forensics.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/gateway/test_wecom_callback.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/hermes_cli/test_gateway_wsl.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/hermes_cli/test_gateway_service.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/hermes_cli/test_service_manager.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/hermes_cli/test_signal_handler_kanban_worker.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/test_live_system_guard_self_test.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/test_tui_gateway_server.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/tools/test_file_tools.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.
- `tests/tools/test_file_sync_back.py`: upstream-reproduzierbar; kein merge-spezifischer Befund.