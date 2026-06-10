from prowler.lib.check.resource_limit import get_resource_scan_limit, limit_resources


class Test_limit_resources:
    def test_no_limit_returns_all_in_order(self):
        resources = ["PASS", "FAIL", "PASS"]

        result = list(limit_resources(iter(resources), None))

        assert result == ["PASS", "FAIL", "PASS"]

    def test_limit_zero_or_negative_is_unlimited(self):
        resources = list(range(5))

        assert list(limit_resources(iter(resources), 0)) == resources
        assert list(limit_resources(iter(resources), -3)) == resources

    def test_positive_limit_stops_after_selected_resources(self):
        pulled = []

        def gen():
            for i in range(1000):
                pulled.append(i)
                yield i

        result = list(limit_resources(gen(), 100))

        assert result == list(range(100))
        assert len(pulled) == 100

    def test_does_not_reorder_or_inspect_resource_status(self):
        resources = ["PASS", "FAIL", "PASS", "FAIL"]

        result = list(limit_resources(iter(resources), 3))

        assert result == ["PASS", "FAIL", "PASS"]


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

    def test_default_is_unlimited_when_unset(self):
        assert get_resource_scan_limit({}, "max_ecs_task_definitions") is None

    def test_null_per_service_override_falls_back_to_unlimited_global_default(self):
        config = {"max_ecs_task_definitions": None}

        assert get_resource_scan_limit(config, "max_ecs_task_definitions") is None

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
