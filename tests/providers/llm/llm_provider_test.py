import os
import stat
import tempfile
from unittest.mock import MagicMock, patch

from prowler.providers.llm.llm_provider import LlmProvider

LEGACY_REPORT_PATH = "/tmp/prowler_promptfoo_results.jsonl"


def _provider():
    provider = object.__new__(LlmProvider)
    provider.max_concurrency = 1
    provider.config_path = __file__
    return provider


def _run_scan_capturing_report_path():
    provider = _provider()
    seen = {}

    def fake_stream(process, report_path, streaming_callback):
        seen["path"] = report_path
        seen["existed"] = os.path.exists(report_path)
        seen["mode"] = os.stat(report_path).st_mode
        return []

    with (
        patch(
            "prowler.providers.llm.llm_provider.subprocess.Popen",
            return_value=MagicMock(),
        ) as popen,
        patch.object(provider, "_stream_findings", side_effect=fake_stream),
    ):
        provider.run_scan(streaming_callback=None)
    seen["command"] = popen.call_args.args[0]
    return seen


class Test_LlmProvider_run_scan_report_path:
    def test_report_path_is_not_the_fixed_tmp_path(self):
        seen = _run_scan_capturing_report_path()

        assert seen["path"] != LEGACY_REPORT_PATH
        assert (
            os.path.dirname(seen["path"]) == os.path.realpath(tempfile.gettempdir())
            or os.path.dirname(seen["path"]) == tempfile.gettempdir()
        )
        assert os.path.basename(seen["path"]).startswith("prowler_promptfoo_results_")
        assert seen["command"][seen["command"].index("--output") + 1] == seen["path"]

    def test_report_path_is_unique_per_scan(self):
        first = _run_scan_capturing_report_path()
        second = _run_scan_capturing_report_path()

        assert first["path"] != second["path"]

    def test_report_file_is_created_private_and_removed_after_scan(self):
        seen = _run_scan_capturing_report_path()

        assert seen["existed"]
        if os.name == "posix":
            assert stat.S_IMODE(seen["mode"]) == 0o600
        assert not os.path.exists(seen["path"])
