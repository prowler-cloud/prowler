from unittest.mock import MagicMock, patch

from prowler.providers.llm.llm_provider import LlmProvider


class TestLlmProvider:
    @staticmethod
    def _create_minimal_config(tmp_path):
        config_path = tmp_path / "llm_test_config.yaml"
        config_path.write_text(
            "targets:\n"
            "  - id: openai:gpt-5\n"
            "redteam:\n"
            "  plugins: []\n",
            encoding="utf-8",
        )
        return str(config_path)

    @patch.object(LlmProvider, "run_scan")
    def test_run_calls_run_scan_with_default_callback(self, mock_run_scan, tmp_path):
        mock_run_scan.return_value = []
        provider = LlmProvider(config_path=self._create_minimal_config(tmp_path))

        result = provider.run()

        mock_run_scan.assert_called_once_with(streaming_callback=None)
        assert result == []

    @patch("subprocess.Popen")
    def test_run_scan_allows_missing_streaming_callback(self, mock_popen, tmp_path):
        provider = LlmProvider(config_path=self._create_minimal_config(tmp_path))
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        with patch.object(provider, "_stream_findings", return_value=[]) as mock_stream:
            result = provider.run_scan()

        assert result == []
        mock_stream.assert_called_once_with(
            mock_process,
            "/tmp/prowler_promptfoo_results.jsonl",
            None,
        )

    def test_default_fixer_config_is_not_shared_between_instances(self, tmp_path):
        config_path = self._create_minimal_config(tmp_path)
        first_provider = LlmProvider(config_path=config_path)
        second_provider = LlmProvider(config_path=config_path)

        first_provider.fixer_config["shared_state"] = True

        assert first_provider.fixer_config is not second_provider.fixer_config
        assert "shared_state" not in second_provider.fixer_config
