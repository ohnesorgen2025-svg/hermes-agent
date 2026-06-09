from toolsets import resolve_toolset


class TestCoreToolsets:
    def test_hermes_cli_excludes_execute_code(self):
        tools = resolve_toolset("hermes-cli")
        assert "execute_code" not in tools

    def test_hermes_cron_excludes_execute_code(self):
        tools = resolve_toolset("hermes-cron")
        assert "execute_code" not in tools

    def test_telegram_excludes_execute_code(self):
        tools = resolve_toolset("telegram")
        assert "execute_code" not in tools

    def test_code_execution_toolset_keeps_execute_code(self):
        tools = resolve_toolset("code_execution")
        assert "execute_code" in tools