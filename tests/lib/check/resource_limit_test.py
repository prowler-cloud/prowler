from prowler.lib.check.resource_limit import (
    get_resource_scan_limit,
    iter_limited_paginator_items,
    limit_resources,
)


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages
        self.paginate_calls = []
        self.pages_requested = 0

    def paginate(self, **kwargs):
        self.paginate_calls.append(kwargs)
        for page in self.pages:
            self.pages_requested += 1
            yield page


class Test_limit_resources:
    def test_no_limit_returns_all_in_order(self):
        resources = ["PASS", "FAIL", "PASS"]

        result = list(limit_resources(iter(resources), None))

        assert result == ["PASS", "FAIL", "PASS"]


class Test_iter_limited_paginator_items:
    def test_positive_limit_stops_without_page_size(self):
        paginator = FakePaginator(
            [
                {"Items": [1, 2]},
                {"Items": [3, 4]},
                {"Items": [5]},
            ]
        )

        result = list(iter_limited_paginator_items(paginator, "Items", 3))

        assert result == [1, 2, 3]
        assert paginator.paginate_calls == [{}]
        assert paginator.pages_requested == 2

    def test_absurd_limit_is_not_sent_as_page_size(self):
        paginator = FakePaginator([{"Items": [1, 2]}])

        result = list(iter_limited_paginator_items(paginator, "Items", 200000))

        assert result == [1, 2]
        assert paginator.paginate_calls == [{}]

    def test_operation_parameters_are_forwarded_unchanged(self):
        paginator = FakePaginator([{"Snapshots": ["snapshot"]}])

        result = list(
            iter_limited_paginator_items(
                paginator,
                "Snapshots",
                1,
                OwnerIds=["self"],
            )
        )

        assert result == ["snapshot"]
        assert paginator.paginate_calls == [{"OwnerIds": ["self"]}]

    def test_item_filter_limits_selected_items_only(self):
        paginator = FakePaginator(
            [
                {"Items": [{"arn": "skip"}, {"arn": "first"}]},
                {"Items": [{"arn": "second"}, {"arn": "third"}]},
            ]
        )

        result = list(
            iter_limited_paginator_items(
                paginator,
                "Items",
                2,
                item_filter=lambda item: item["arn"] != "skip",
            )
        )

        assert result == [{"arn": "first"}, {"arn": "second"}]
        assert paginator.pages_requested == 2

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

    def test_null_per_service_override_falls_back_to_global_default(self):
        config = {
            "max_scanned_resources_per_service": 50,
            "max_ecs_task_definitions": None,
        }

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
