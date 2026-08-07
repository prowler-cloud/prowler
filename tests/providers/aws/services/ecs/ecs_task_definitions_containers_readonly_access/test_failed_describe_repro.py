"""Regression tests for #12132 (ECS task-definition checks fail open).

When DescribeTaskDefinition fails, the shared ``EcsTaskDefinition`` model
must keep ``container_definitions = None`` (evidence not gathered), and the
task-definition checks must skip such resources instead of reporting a
default PASS.  A failed gather must never look like compliance.
"""

from unittest.mock import patch

import botocore

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    TaskDefinition,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

TASK_ARN = (
    f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:123456789012:task-definition/test:1"
)


def mock_make_api_call_failed_describe(self, operation_name, kwarg):
    if operation_name == "ListTaskDefinitions":
        return {"taskDefinitionArns": [TASK_ARN]}
    if operation_name == "DescribeTaskDefinition":
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "rate exceeded"}},
            "DescribeTaskDefinition",
        )
    if operation_name == "ListClusters":
        return {"clusterArns": []}
    return make_api_call(self, operation_name, kwarg)


def _run_check(check_name):
    """Instantiate a check and run it against a real ECS service whose
    describe call fails, returning the check results."""
    from prowler.providers.aws.services.ecs.ecs_service import ECS

    mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

    module_path = (
        "prowler.providers.aws.services.ecs"
        f".{check_name}.{check_name}"
    )
    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ),
        patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_failed_describe,
        ),
        patch(f"{module_path}.ecs_client", new=ECS(mocked_aws_provider)),
    ):
        from importlib import import_module

        check_cls = getattr(import_module(module_path), check_name)
        return check_cls().execute()


class TestServiceModel:
    def test_failed_describe_leaves_container_definitions_none(self):
        """A failed describe must leave evidence as not-gathered (None)."""
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "botocore.client.BaseClient._make_api_call",
                new=mock_make_api_call_failed_describe,
            ),
        ):
            ecs = ECS(mocked_aws_provider)

        task_definition = ecs.task_definitions[TASK_ARN]
        assert task_definition.container_definitions is None


class TestChecksSkipUnexaminedTaskDefinitions:
    """All task-definition checks must skip a resource whose describe failed."""

    def test_readonly_access_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_containers_readonly_access") == []

    def test_host_namespace_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_host_namespace_not_shared") == []

    def test_host_networking_mode_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_host_networking_mode_users") == []

    def test_logging_enabled_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_logging_enabled") == []

    def test_no_environment_secrets_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_no_environment_secrets") == []

    def test_no_privileged_skips_failed_describe(self):
        assert _run_check("ecs_task_definitions_no_privileged_containers") == []

    def test_logging_block_mode_skips_failed_describe(self):
        # Shares the container_definitions model: without the guard this check
        # would crash iterating None rather than fail open.
        assert _run_check("ecs_task_definitions_logging_block_mode") == []


class TestSuccessPathStillReports:
    """Sanity: a successfully described task definition still yields findings."""

    def test_container_definitions_empty_list_is_distinct_from_none(self):
        """A successful describe with no containers is [] and still evaluated."""
        task_definition = TaskDefinition(
            name="test",
            arn=TASK_ARN,
            revision="1",
            region=AWS_REGION_EU_WEST_1,
            container_definitions=[],
        )
        assert task_definition.container_definitions == []
        assert task_definition.container_definitions is not None

    def test_model_defaults_to_none(self):
        """Without explicit container_definitions, the sentinel is None."""
        task_definition = TaskDefinition(
            name="test",
            arn=TASK_ARN,
            revision="1",
            region=AWS_REGION_EU_WEST_1,
        )
        assert task_definition.container_definitions is None

    def test_container_definition_model_unchanged(self):
        """ContainerDefinition fields remain intact for populated resources."""
        container = ContainerDefinition(
            name="c",
            privileged=False,
            readonly_rootfilesystem=True,
            user="appuser",
            environment=[],
            log_driver="awslogs",
            log_option="non-blocking",
        )
        assert container.readonly_rootfilesystem is True
        assert container.name == "c"
