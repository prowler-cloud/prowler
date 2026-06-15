from unittest.mock import MagicMock, patch

import pytest

from config import ecs_task_protection as tp


class _Req:
    def __init__(self, name):
        self.name = name


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for var in (
        "ECS_AGENT_URI",
        "DJANGO_ECS_TASK_PROTECTION",
        "DJANGO_ECS_TASK_PROTECTION_POLL_SECONDS",
        "DJANGO_ECS_TASK_PROTECTION_EXPIRES_MINUTES",
    ):
        monkeypatch.delenv(var, raising=False)


class TestIsEnabled:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        assert tp.is_enabled() is False

    def test_requires_agent_uri(self, monkeypatch):
        monkeypatch.setenv("DJANGO_ECS_TASK_PROTECTION", "True")
        assert tp.is_enabled() is False

    def test_enabled_when_flag_and_agent_present(self, monkeypatch):
        monkeypatch.setenv("DJANGO_ECS_TASK_PROTECTION", "true")
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        assert tp.is_enabled() is True


class TestSetTaskProtection:
    def test_noop_without_agent(self):
        assert tp.set_task_protection(True, 120) is False

    def test_enable_puts_expected_payload(self, monkeypatch):
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(tp.urllib_request, "urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
            assert tp.set_task_protection(True, 90) is True
            request = urlopen.call_args.args[0]
            assert request.full_url == "http://agent/task-protection/v1/state"
            assert request.get_method() == "PUT"
            assert request.data == (
                b'{"ProtectionEnabled": true, "ExpiresInMinutes": 90}'
            )

    def test_disable_omits_expiry(self, monkeypatch):
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(tp.urllib_request, "urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
            assert tp.set_task_protection(False, 90) is True
            assert urlopen.call_args.args[0].data == b'{"ProtectionEnabled": false}'

    def test_failure_is_swallowed(self, monkeypatch):
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(
            tp.urllib_request, "urlopen", side_effect=OSError("boom")
        ):
            assert tp.set_task_protection(True, 120) is False


class TestECSTaskProtectionStep:
    def _step(self):
        return tp.ECSTaskProtectionStep(parent=MagicMock())

    def test_start_is_noop_when_disabled(self):
        step = self._step()
        with patch.object(tp, "set_task_protection") as setter:
            step.start(MagicMock())
            setter.assert_not_called()
        assert step._timer is None

    def test_tick_acquires_then_releases(self, monkeypatch):
        monkeypatch.setenv("DJANGO_ECS_TASK_PROTECTION", "true")
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        step = self._step()

        # Patch Timer so the reschedule in the `finally` block does not spawn a
        # real thread, but the tick body still runs.
        with patch.object(tp, "set_task_protection", return_value=True) as setter, \
                patch.object(tp.threading, "Timer", return_value=MagicMock()), \
                patch.object(
                    tp.ECSTaskProtectionStep, "_protected_task_in_flight"
                ) as in_flight:
            in_flight.return_value = True
            step._tick()
            assert step._protected is True
            assert setter.call_args.args == (True, step._expires_minutes)

            in_flight.return_value = False
            step._tick()
            assert step._protected is False
            assert setter.call_args.args == (False, step._expires_minutes)

        step._stop.set()

    def test_protected_task_detection_matches_only_protected_names(self):
        from celery.worker import state

        with patch.object(
            state, "active_requests", [_Req("scan-summary"), _Req("scan-perform")]
        ):
            assert tp.ECSTaskProtectionStep._protected_task_in_flight() is True

        with patch.object(
            state, "active_requests", [_Req("scan-summary"), _Req("overview")]
        ):
            assert tp.ECSTaskProtectionStep._protected_task_in_flight() is False
