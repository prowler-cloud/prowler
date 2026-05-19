from types import SimpleNamespace

from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings


def _report(status):
    return SimpleNamespace(status=status)


def _evaluate(resource):
    # resource is the (status, _id) tuple; emulates a check's per-resource logic
    status, _ = resource
    return _report(status)


class Test_limited_findings:
    def test_no_limit_returns_all_in_order(self):
        resources = [("PASS", 1), ("FAIL", 2), ("PASS", 3)]

        result = limited_findings(iter(resources), _evaluate, None)

        assert [r.status for r in result] == ["PASS", "FAIL", "PASS"]

    def test_limit_zero_or_negative_is_unlimited(self):
        resources = [("FAIL", i) for i in range(5)]

        assert len(limited_findings(iter(resources), _evaluate, 0)) == 5
        assert len(limited_findings(iter(resources), _evaluate, -3)) == 5

    def test_fail_quota_full_returns_only_fails_and_stops_early(self):
        pulled = []

        def gen():
            for i in range(1000):
                pulled.append(i)
                yield ("FAIL", i)

        result = limited_findings(gen(), _evaluate, 100)

        assert len(result) == 100
        assert all(r.status == "FAIL" for r in result)
        # Lazy: generator must stop being pulled once the FAIL quota is met
        assert len(pulled) == 100

    def test_mixed_under_limit_sums_fails_first(self):
        resources = [("PASS", 1), ("FAIL", 2), ("PASS", 3), ("FAIL", 4)]

        result = limited_findings(iter(resources), _evaluate, 100)

        assert [r.status for r in result] == ["FAIL", "FAIL", "PASS", "PASS"]

    def test_passes_truncated_to_remaining_quota_after_fails(self):
        resources = [("FAIL", 1), ("FAIL", 2)] + [("PASS", i) for i in range(50)]

        result = limited_findings(iter(resources), _evaluate, 10)

        assert len(result) == 10
        assert [r.status for r in result[:2]] == ["FAIL", "FAIL"]
        assert all(r.status == "PASS" for r in result[2:])

    def test_no_fails_returns_passes_capped(self):
        resources = [("PASS", i) for i in range(500)]

        result = limited_findings(iter(resources), _evaluate, 100)

        assert len(result) == 100
        assert all(r.status == "PASS" for r in result)

    def test_evaluate_returning_none_is_skipped(self):
        resources = [("FAIL", 1), ("SKIP", 2), ("PASS", 3)]

        def evaluate(resource):
            status, _ = resource
            return None if status == "SKIP" else _report(status)

        result = limited_findings(iter(resources), evaluate, 100)

        assert [r.status for r in result] == ["FAIL", "PASS"]


class Test_get_resource_scan_limit:
    def test_per_service_override_wins(self):
        config = {
            "max_scanned_resources_per_service": 100,
            "max_ecs_task_definitions": 25,
        }
        assert get_resource_scan_limit(config, "max_ecs_task_definitions") == 25

    def test_falls_back_to_global_default(self):
        config = {"max_scanned_resources_per_service": 50}
        assert get_resource_scan_limit(config, "max_ecs_task_definitions") == 50

    def test_default_is_100_when_unset(self):
        assert get_resource_scan_limit({}, "max_ecs_task_definitions") == 100

    def test_non_positive_means_unlimited(self):
        assert (
            get_resource_scan_limit(
                {"max_scanned_resources_per_service": 0}, "max_lambda_functions"
            )
            is None
        )
        assert (
            get_resource_scan_limit(
                {"max_lambda_functions": -1}, "max_lambda_functions"
            )
            is None
        )
