"""Tests for the ECS task scale-in protection worker bootstep."""

import json
from unittest.mock import MagicMock, patch

import pytest

from config import ecs_task_protection as tp


class _Req:
    """Minimal stand-in for a Celery request exposing a task ``name``."""

    def __init__(self, name):
        """Store the task name used for protected-task matching."""
        self.name = name


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure each test starts with the protection env vars unset."""
    for var in (
        "ECS_AGENT_URI",
        "DJANGO_ECS_TASK_PROTECTION",
        "DJANGO_ECS_TASK_PROTECTION_POLL_SECONDS",
        "DJANGO_ECS_TASK_PROTECTION_EXPIRES_MINUTES",
    ):
        monkeypatch.delenv(var, raising=False)


class TestIsEnabled:
    """`is_enabled` requires both the flag and the ECS agent endpoint."""

    def test_disabled_by_default(self, monkeypatch):
        """On ECS but without the flag, protection stays disabled."""
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        assert tp.is_enabled() is False

    def test_requires_agent_uri(self, monkeypatch):
        """The flag alone is not enough when not running on ECS."""
        monkeypatch.setenv("DJANGO_ECS_TASK_PROTECTION", "True")
        assert tp.is_enabled() is False

    def test_enabled_when_flag_and_agent_present(self, monkeypatch):
        """Both the flag and the agent endpoint enable protection."""
        monkeypatch.setenv("DJANGO_ECS_TASK_PROTECTION", "true")
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        assert tp.is_enabled() is True


class TestEnvInt:
    """`_env_int` tolerates missing and malformed environment values."""

    _VAR = "DJANGO_ECS_TASK_PROTECTION_POLL_SECONDS"

    def test_uses_default_when_unset(self):
        """An unset variable yields the default."""
        assert tp._env_int(self._VAR, default=60, minimum=5) == 60

    def test_parses_valid_value(self, monkeypatch):
        """A valid integer string is parsed."""
        monkeypatch.setenv(self._VAR, "90")
        assert tp._env_int(self._VAR, default=60, minimum=5) == 90

    def test_clamps_to_minimum(self, monkeypatch):
        """Values below the minimum are clamped up."""
        monkeypatch.setenv(self._VAR, "1")
        assert tp._env_int(self._VAR, default=60, minimum=5) == 5

    def test_falls_back_on_malformed_value(self, monkeypatch):
        """A non-numeric value falls back to the default instead of raising."""
        monkeypatch.setenv(self._VAR, "sixty")
        assert tp._env_int(self._VAR, default=60, minimum=5) == 60


class TestSetTaskProtection:
    """`set_task_protection` builds the correct request and never raises."""

    def test_noop_without_agent(self):
        """Without the agent endpoint the call is a no-op returning False."""
        assert tp.set_task_protection(True, 120) is False

    def test_enable_puts_expected_payload(self, monkeypatch):
        """Enabling sends a PUT with ProtectionEnabled and the expiry."""
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(tp.urllib_request, "urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
            assert tp.set_task_protection(True, 90) is True
            request = urlopen.call_args.args[0]
            assert request.full_url == "http://agent/task-protection/v1/state"
            assert request.get_method() == "PUT"
            assert json.loads(request.data.decode("utf-8")) == {
                "ProtectionEnabled": True,
                "ExpiresInMinutes": 90,
            }

    def test_disable_omits_expiry(self, monkeypatch):
        """Disabling sends ProtectionEnabled=false without an expiry."""
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(tp.urllib_request, "urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
            assert tp.set_task_protection(False, 90) is True
            assert json.loads(
                urlopen.call_args.args[0].data.decode("utf-8")
            ) == {"ProtectionEnabled": False}

    def test_failure_is_swallowed(self, monkeypatch):
        """A transport error is logged and returns False, never raised."""
        monkeypatch.setenv("ECS_AGENT_URI", "http://agent")
        with patch.object(
            tp.urllib_request, "urlopen", side_effect=OSError("boom")
        ):
            assert tp.set_task_protection(True, 120) is False


class TestECSTaskProtectionStep:
    """The bootstep toggles protection based on in-flight protected tasks."""

    def _step(self):
        """Build a step instance with a dummy parent."""
        return tp.ECSTaskProtectionStep(parent=MagicMock())

    def test_start_is_noop_when_disabled(self):
        """`start` does nothing when protection is not enabled."""
        step = self._step()
        with patch.object(tp, "set_task_protection") as setter:
            step.start(MagicMock())
            setter.assert_not_called()
        assert step._timer is None

    def test_tick_acquires_then_releases(self, monkeypatch):
        """A tick acquires protection while busy and releases it when idle."""
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
        """Only the protected task names count as in-flight protected work."""
        from celery.worker import state

        with patch.object(
            state, "active_requests", [_Req("scan-summary"), _Req("scan-perform")]
        ):
            assert tp.ECSTaskProtectionStep._protected_task_in_flight() is True

        with patch.object(
            state, "active_requests", [_Req("scan-summary"), _Req("overview")]
        ):
            assert tp.ECSTaskProtectionStep._protected_task_in_flight() is False
