from datetime import datetime, timezone
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.ecs.ecs_service import ECS
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListTaskDefinitions":
        return {
            "taskDefinitionArns": [
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"
            ]
        }
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "test-image",
                        "logConfiguration": {
                            "logDriver": "awslogs",
                            "options": {
                                "mode": "non-blocking",
                                "max-buffer-size": "25m",
                            },
                        },
                        "environment": [
                            {"name": "DB_PASSWORD", "value": "pass-12343"},
                        ],
                    }
                ],
                "networkMode": "host",
                "pidMode": "host",
                "tags": [],
            }
        }
    if operation_name == "ListServices":
        return {
            "serviceArns": [
                "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service"
            ]
        }
    if operation_name == "DescribeServices":
        return {
            "services": [
                {
                    "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service",
                    "serviceName": "test_ecs_service",
                    "networkConfiguration": {
                        "awsvpcConfiguration": {
                            "subnets": ["subnet-12345678"],
                            "securityGroups": ["sg-12345678"],
                            "assignPublicIp": "ENABLED",
                        }
                    },
                    "launchType": "FARGATE",
                    "platformVersion": "1.4.0",
                    "platformFamily": "Linux",
                    "taskSets": [
                        {
                            "id": "ecs-svc/task-set",
                            "taskSetArn": "arn:aws:ecs:eu-west-1:123456789012:task-set/test_cluster_1/test_ecs_service/ecs-svc/task-set",
                            "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
                            "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service",
                            "networkConfiguration": {
                                "awsvpcConfiguration": {
                                    "subnets": ["subnet-12345678"],
                                    "securityGroups": ["sg-12345678"],
                                    "assignPublicIp": "DISABLED",
                                },
                            },
                            "tags": [],
                        }
                    ],
                }
            ]
        }
    if operation_name == "ListClusters":
        return {
            "clusterArns": [
                "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
            ]
        }
    if operation_name == "DescribeClusters":
        return {
            "clusters": [
                {
                    "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
                    "clusterName": "test_cluster_1",
                    "status": "ACTIVE",
                    "tags": [{"key": "Name", "value": "test_cluster_1"}],
                    "settings": [
                        {"name": "containerInsights", "value": "enabled"},
                    ],
                    "registeredContainerInstancesCount": 5,
                    "runningTasksCount": 10,
                    "pendingTasksCount": 1,
                    "activeServicesCount": 2,
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def mock_generate_multi_region_clients(provider, service):
    eu_west_1_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    eu_west_1_client.region = AWS_REGION_EU_WEST_1

    us_east_1_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    us_east_1_client.region = AWS_REGION_US_EAST_1

    return {
        AWS_REGION_EU_WEST_1: eu_west_1_client,
        AWS_REGION_US_EAST_1: us_east_1_client,
    }


def mock_make_api_call_task_definitions_by_registration_date(
    self, operation_name, kwarg
):
    task_definition_dates = {
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/eu-old:1": datetime(
            2024, 1, 1, tzinfo=timezone.utc
        ),
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/eu-second-newest:1": datetime(
            2024, 5, 1, tzinfo=timezone.utc
        ),
        f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:123456789012:task-definition/us-newest:1": datetime(
            2024, 6, 1, tzinfo=timezone.utc
        ),
        f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:123456789012:task-definition/us-old:1": datetime(
            2024, 2, 1, tzinfo=timezone.utc
        ),
    }
    task_definitions_by_region = {
        AWS_REGION_EU_WEST_1: [
            task_definition
            for task_definition in task_definition_dates
            if f":{AWS_REGION_EU_WEST_1}:" in task_definition
        ],
        AWS_REGION_US_EAST_1: [
            task_definition
            for task_definition in task_definition_dates
            if f":{AWS_REGION_US_EAST_1}:" in task_definition
        ],
    }

    if operation_name == "ListTaskDefinitions":
        return {"taskDefinitionArns": task_definitions_by_region[self.region]}
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [],
                "registeredAt": task_definition_dates[kwarg["taskDefinition"]],
            },
            "tags": [],
        }
    if operation_name == "ListClusters":
        return {"clusterArns": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_task_definitions_with_equal_registration_dates(
    self, operation_name, kwarg
):
    registered_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    task_definition_dates = {
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/zzz-task:1": registered_at,
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/aaa-task:1": registered_at,
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/mmm-task:1": registered_at,
    }

    if operation_name == "ListTaskDefinitions":
        return {"taskDefinitionArns": list(task_definition_dates)}
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [],
                "registeredAt": task_definition_dates[kwarg["taskDefinition"]],
            },
            "tags": [],
        }
    if operation_name == "ListClusters":
        return {"clusterArns": []}
    return make_api_call(self, operation_name, kwarg)


DESCRIBED_TASK_DEFINITIONS = []


def mock_make_api_call_task_definitions_with_audit_resources(
    self, operation_name, kwarg
):
    task_definition_dates = {
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/audited-older:1": datetime(
            2024, 1, 1, tzinfo=timezone.utc
        ),
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/audited-newer:1": datetime(
            2024, 2, 1, tzinfo=timezone.utc
        ),
        f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/unaudited-newest:1": datetime(
            2024, 3, 1, tzinfo=timezone.utc
        ),
    }

    if operation_name == "ListTaskDefinitions":
        return {"taskDefinitionArns": list(task_definition_dates)}
    if operation_name == "DescribeTaskDefinition":
        DESCRIBED_TASK_DEFINITIONS.append(kwarg["taskDefinition"])
        return {
            "taskDefinition": {
                "containerDefinitions": [],
                "registeredAt": task_definition_dates[kwarg["taskDefinition"]],
            },
            "tags": [],
        }
    if operation_name == "ListClusters":
        return {"clusterArns": []}
    return make_api_call(self, operation_name, kwarg)


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ECS_Service:
    # Test ECS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)
        assert ecs.service == "ecs"

    # Test ECS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)
        for reg_client in ecs.regional_clients.values():
            assert reg_client.__class__.__name__ == "ECS"

    # Test ECS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)
        assert ecs.session.__class__.__name__ == "Session"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_task_definitions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"

        assert len(ecs.task_definitions) == 1
        assert ecs.task_definitions[task_arn].name == "test_ecs_task"
        assert ecs.task_definitions[task_arn].arn == task_arn
        assert ecs.task_definitions[task_arn].revision == "1"
        assert ecs.task_definitions[task_arn].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS task definitions
    def test_describe_task_definitions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"

        assert len(ecs.task_definitions) == 1
        assert ecs.task_definitions[task_arn].name == "test_ecs_task"
        assert ecs.task_definitions[task_arn].arn == task_arn
        assert ecs.task_definitions[task_arn].revision == "1"
        assert ecs.task_definitions[task_arn].region == AWS_REGION_EU_WEST_1
        assert len(ecs.task_definitions[task_arn].container_definitions) == 1
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].name
            == "test-container"
        )
        assert (
            len(ecs.task_definitions[task_arn].container_definitions[0].environment)
            == 1
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].environment[0].name
            == "DB_PASSWORD"
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].environment[0].value
            == "pass-12343"
        )
        assert ecs.task_definitions[task_arn].network_mode == "host"
        assert not ecs.task_definitions[task_arn].container_definitions[0].privileged
        assert ecs.task_definitions[task_arn].container_definitions[0].user == ""
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].log_driver
            == "awslogs"
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].log_option
            == "non-blocking"
        )
        assert ecs.task_definitions[task_arn].pid_mode == "host"
        assert (
            not ecs.task_definitions[task_arn]
            .container_definitions[0]
            .readonly_rootfilesystem
        )

    def test_task_definitions_are_loaded_once_for_analysis(self):
        describe_calls = []
        list_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListTaskDefinitions":
                list_calls.append(kwarg)
                return {
                    "taskDefinitionArns": [
                        f"arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:{i}"
                        for i in (3, 2, 1)
                    ]
                }
            if operation_name == "DescribeTaskDefinition":
                describe_calls.append(kwarg["taskDefinition"])
                return {
                    "taskDefinition": {
                        "containerDefinitions": [],
                        "networkMode": "bridge",
                        "pidMode": "",
                        "tags": [],
                    }
                }
            return make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            ecs = ECS(aws_provider)

            assert [td.revision for td in ecs.task_definitions.values()] == [
                "3",
                "2",
                "1",
            ]
            assert list_calls == [{"sort": "DESC"}]
            assert len(describe_calls) == 3

    def test_task_definition_limit_exposes_only_selected_resources(self):
        describe_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListTaskDefinitions":
                return {
                    "taskDefinitionArns": [
                        f"arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:{i}"
                        for i in (3, 2, 1)
                    ]
                }
            if operation_name == "DescribeTaskDefinition":
                describe_calls.append(kwarg["taskDefinition"])
                return {
                    "taskDefinition": {
                        "containerDefinitions": [],
                        "networkMode": "bridge",
                        "pidMode": "",
                        "tags": [],
                    }
                }
            return make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1], audit_config={"max_ecs_task_definitions": 2}
            )
            ecs = ECS(aws_provider)

            assert [td.revision for td in ecs.task_definitions.values()] == ["3", "2"]
            assert len(describe_calls) == 3

    def test_task_definition_limit_describes_candidates_before_exposing_limit(self):
        describe_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListTaskDefinitions":
                return {
                    "taskDefinitionArns": [
                        f"arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:{i}"
                        for i in (3, 2, 1)
                    ]
                }
            if operation_name == "DescribeTaskDefinition":
                describe_calls.append(kwarg["taskDefinition"])
                return {
                    "taskDefinition": {
                        "containerDefinitions": [],
                        "networkMode": "bridge",
                        "pidMode": "",
                        "tags": [],
                    }
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1], audit_config={"max_ecs_task_definitions": 1}
            )
            ecs = ECS(aws_provider)

            assert [td.revision for td in ecs.task_definitions.values()] == ["3"]
            assert sorted(describe_calls) == sorted(
                [
                    "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:3",
                    "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:2",
                    "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:1",
                ]
            )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_task_definitions_by_registration_date,
    )
    def test_task_definition_limit_uses_global_latest_registration_dates(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            audit_config={"max_ecs_task_definitions": 2},
        )
        with patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            new=mock_generate_multi_region_clients,
        ):
            ecs = ECS(aws_provider)

        assert list(ecs.task_definitions) == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:123456789012:task-definition/us-newest:1",
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/eu-second-newest:1",
        ]

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_task_definitions_with_equal_registration_dates,
    )
    def test_task_definition_limit_uses_arn_order_for_equal_registration_dates(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], audit_config={"max_ecs_task_definitions": 2}
        )
        ecs = ECS(aws_provider)

        assert list(ecs.task_definitions) == [
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/aaa-task:1",
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/mmm-task:1",
        ]

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_task_definitions_with_audit_resources,
    )
    def test_task_definition_limit_applies_after_audit_resources_filter(self):
        DESCRIBED_TASK_DEFINITIONS.clear()
        audited_older_task_definition = (
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:"
            "task-definition/audited-older:1"
        )
        audited_newer_task_definition = (
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:"
            "task-definition/audited-newer:1"
        )
        unaudited_newest_task_definition = (
            f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:"
            "task-definition/unaudited-newest:1"
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], audit_config={"max_ecs_task_definitions": 1}
        )
        aws_provider._audit_resources = [
            audited_older_task_definition,
            audited_newer_task_definition,
        ]

        ecs = ECS(aws_provider)

        assert sorted(DESCRIBED_TASK_DEFINITIONS) == sorted(
            [audited_older_task_definition, audited_newer_task_definition]
        )
        assert list(ecs.task_definitions) == [audited_newer_task_definition]
        assert unaudited_newest_task_definition not in ecs.task_definitions

    def test_task_definition_limit_does_not_starve_later_regions(self):
        describe_calls = []

        def counting_make_api_call(self, operation_name, kwarg):
            region = self.meta.region_name
            if operation_name == "ListTaskDefinitions":
                task_definition_revisions = {
                    AWS_REGION_EU_WEST_1: (3, 2, 1),
                    AWS_REGION_US_EAST_1: (9,),
                }[region]
                return {
                    "taskDefinitionArns": [
                        f"arn:aws:ecs:{region}:123456789012:task-definition/fam:{revision}"
                        for revision in task_definition_revisions
                    ]
                }
            if operation_name == "DescribeTaskDefinition":
                describe_calls.append(kwarg["taskDefinition"])
                return {
                    "taskDefinition": {
                        "containerDefinitions": [],
                        "networkMode": "bridge",
                        "pidMode": "",
                        "tags": [],
                    }
                }
            if operation_name == "ListClusters":
                return {"clusterArns": []}
            return mock_make_api_call(self, operation_name, kwarg)

        with (
            patch(
                "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
                new=mock_generate_multi_region_clients,
            ),
            patch(
                "botocore.client.BaseClient._make_api_call", new=counting_make_api_call
            ),
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                audit_config={"max_ecs_task_definitions": 2},
            )
            ecs = ECS(aws_provider)

            assert [td.region for td in ecs.task_definitions.values()] == [
                AWS_REGION_EU_WEST_1,
                AWS_REGION_US_EAST_1,
            ]
            assert set(describe_calls) == {
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:3",
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:2",
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/fam:1",
                "arn:aws:ecs:us-east-1:123456789012:task-definition/fam:9",
            }

    # Test list ECS clusters
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_clusters(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)

        cluster_arn1 = "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"

        assert len(ecs.clusters) == 1
        assert ecs.clusters[cluster_arn1].name == "test_cluster_1"
        assert ecs.clusters[cluster_arn1].arn == cluster_arn1
        assert ecs.clusters[cluster_arn1].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS clusters
    def test_describe_clusters(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)

        cluster_arn1 = "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"

        assert len(ecs.clusters) == 1
        assert ecs.clusters[cluster_arn1].name == "test_cluster_1"
        assert ecs.clusters[cluster_arn1].arn == cluster_arn1
        assert ecs.clusters[cluster_arn1].region == AWS_REGION_EU_WEST_1
        assert ecs.clusters[cluster_arn1].services
        assert ecs.clusters[cluster_arn1].tags == [
            {"key": "Name", "value": "test_cluster_1"}
        ]
        assert ecs.clusters[cluster_arn1].settings == [
            {"name": "containerInsights", "value": "enabled"}
        ]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS services
    def test_describe_services(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecs = ECS(aws_provider)

        service_arn = (
            "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service"
        )

        task_set_arn = "arn:aws:ecs:eu-west-1:123456789012:task-set/test_cluster_1/test_ecs_service/ecs-svc/task-set"

        assert len(ecs.services) == 1
        assert ecs.services[service_arn].name == "test_ecs_service"
        assert ecs.services[service_arn].arn == service_arn
        assert ecs.services[service_arn].region == AWS_REGION_EU_WEST_1
        assert ecs.services[service_arn].assign_public_ip
        assert ecs.services[service_arn].tags == []
        assert ecs.services[service_arn].launch_type == "FARGATE"
        assert ecs.services[service_arn].platform_version == "1.4.0"
        assert ecs.services[service_arn].platform_family == "Linux"
        assert len(ecs.task_sets) == 1
        assert ecs.task_sets[task_set_arn].id == "ecs-svc/task-set"
        assert ecs.task_sets[task_set_arn].arn == task_set_arn
        assert (
            ecs.task_sets[task_set_arn].cluster_arn
            == "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"
        )
        assert ecs.task_sets[task_set_arn].service_arn == service_arn
        assert ecs.task_sets[task_set_arn].assign_public_ip == "DISABLED"
        assert ecs.task_sets[task_set_arn].region == AWS_REGION_EU_WEST_1
        assert ecs.task_sets[task_set_arn].tags == []
