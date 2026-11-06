import json
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import ClassVar, Optional

import pytest
from pydantic.v1 import BaseModel

from prowler.lib.check.models import Check_Report_AWS, CheckReportOpenStack
from prowler.lib.check.redact import REDACTED_VALUE, redact_sensitive_fields
from prowler.providers.aws.services.amplify.amplify_service import App, Branch
from prowler.providers.aws.services.apigateway.apigateway_service import Stage
from prowler.providers.aws.services.autoscaling.autoscaling_service import (
    LaunchConfiguration,
)
from prowler.providers.aws.services.awslambda.awslambda_service import Function
from prowler.providers.aws.services.batch.batch_service import (
    BatchContainerProperties,
)
from prowler.providers.aws.services.batch.batch_service import (
    ContainerEnvVariable as BatchContainerEnvVariable,
)
from prowler.providers.aws.services.cloudformation.cloudformation_service import Stack
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import LogGroup
from prowler.providers.aws.services.codebuild.codebuild_service import (
    EnvironmentVariable,
)
from prowler.providers.aws.services.datapipeline.datapipeline_service import Pipeline
from prowler.providers.aws.services.ec2.ec2_service import Instance, TemplateData
from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerEnvVariable as EcsContainerEnvVariable,
)
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_service import (
    Environment,
)
from prowler.providers.aws.services.glue.glue_service import Connection, Job
from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    NotebookInstance,
)
from prowler.providers.aws.services.ssm.ssm_service import Document
from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    StateMachine,
)
from prowler.providers.openstack.services.blockstorage.blockstorage_service import (
    SnapshotResource,
    VolumeResource,
)
from prowler.providers.openstack.services.compute.compute_service import (
    ComputeInstance,
)
from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)

SECRET = "AKIAIOSFODNN7EXAMPLE"
STACK_ARN = "arn:aws:cloudformation:eu-central-1:123456789012:stack/app/1"
CLOUDFORMATION_CHECKS = (
    Path(__file__).parents[3] / "prowler/providers/aws/services/cloudformation"
)

MODELS_WITH_SECRETS = [
    App,
    Branch,
    Stage,
    LaunchConfiguration,
    Function,
    BatchContainerProperties,
    BatchContainerEnvVariable,
    Stack,
    LogGroup,
    EnvironmentVariable,
    Pipeline,
    Instance,
    TemplateData,
    EcsContainerEnvVariable,
    Environment,
    Connection,
    Job,
    NotebookInstance,
    Document,
    StateMachine,
    SnapshotResource,
    VolumeResource,
    ComputeInstance,
    ObjectStorageContainer,
]


class Secret(BaseModel):
    sensitive_fields: ClassVar[tuple[str, ...]] = ("value",)
    name: str
    value: str


class Holder(BaseModel):
    sensitive_fields: ClassVar[tuple[str, ...]] = ("env", "script")
    name: str
    env: dict = {}
    script: Optional[str] = None
    secrets: list[Secret] = []
    by_name: dict[str, Secret] = {}


@dataclass
class DataclassHolder:
    sensitive_fields: ClassVar[tuple[str, ...]] = ("metadata",)
    name: str
    metadata: dict


def _check_metadata(check_id: str) -> str:
    return (CLOUDFORMATION_CHECKS / check_id / f"{check_id}.metadata.json").read_text()


class TestRedactSensitiveFields:
    def test_masks_values_and_keeps_dict_keys(self):
        holder = Holder(name="app", env={"DB_PASSWORD": SECRET, "nested": {"k": 1}})

        redacted = redact_sensitive_fields(holder, holder.dict())

        assert redacted["name"] == "app"
        assert redacted["env"] == {
            "DB_PASSWORD": REDACTED_VALUE,
            "nested": {"k": REDACTED_VALUE},
        }

    def test_keeps_empty_values(self):
        holder = Holder(name="app")

        redacted = redact_sensitive_fields(holder, holder.dict())

        assert redacted["env"] == {}
        assert redacted["script"] is None

    def test_redacts_nested_models_in_lists_and_dicts(self):
        holder = Holder(
            name="app",
            secrets=[Secret(name="TOKEN", value=SECRET)],
            by_name={"TOKEN": Secret(name="TOKEN", value=SECRET)},
        )

        redacted = redact_sensitive_fields(holder, holder.dict())

        assert redacted["secrets"] == [{"name": "TOKEN", "value": REDACTED_VALUE}]
        assert redacted["by_name"]["TOKEN"] == {
            "name": "TOKEN",
            "value": REDACTED_VALUE,
        }

    def test_redacts_dataclasses(self):
        holder = DataclassHolder(name="vm", metadata={"password": SECRET})

        redacted = redact_sensitive_fields(holder, {"name": "vm", **holder.__dict__})

        assert redacted["metadata"] == {"password": REDACTED_VALUE}

    def test_does_not_mutate_the_resource(self):
        holder = Holder(name="app", secrets=[Secret(name="TOKEN", value=SECRET)])
        data = holder.dict()

        redact_sensitive_fields(holder, data)

        assert holder.secrets[0].value == SECRET
        assert data["secrets"][0]["value"] == SECRET

    @pytest.mark.parametrize("model", MODELS_WITH_SECRETS, ids=lambda m: m.__name__)
    def test_declared_fields_exist_on_model(self, model):
        names = (
            {f.name for f in fields(model)}
            if is_dataclass(model)
            else set(model.__fields__)
        )

        assert model.sensitive_fields
        assert set(model.sensitive_fields) <= names
        assert "sensitive_fields" not in names


class TestCheckReportRedaction:
    def test_unrelated_check_on_same_stack_does_not_expose_outputs(self):
        stack = Stack(
            arn=STACK_ARN,
            name="app",
            outputs=[f"AccessKey:{SECRET}"],
            region="eu-central-1",
        )

        report = Check_Report_AWS(
            metadata=_check_metadata(
                "cloudformation_stacks_termination_protection_enabled"
            ),
            resource=stack,
        )

        assert report.resource["outputs"] == [REDACTED_VALUE]
        assert SECRET not in json.dumps(report.resource)
        assert report.resource_arn == STACK_ARN
        assert stack.outputs == [f"AccessKey:{SECRET}"]

    def test_lambda_environment_is_redacted(self):
        function = Function(
            name="fn",
            arn="arn:aws:lambda:eu-central-1:123456789012:function:fn",
            region="eu-central-1",
            environment={"API_TOKEN": SECRET},
            security_groups=[],
        )

        report = Check_Report_AWS(
            metadata=_check_metadata("cloudformation_stack_outputs_find_secrets"),
            resource=function,
        )

        assert report.resource["environment"] == {"API_TOKEN": REDACTED_VALUE}

    def test_dict_resource_without_model_is_left_untouched(self):
        resource = {"name": "x", "outputs": ["plain"]}

        report = CheckReportOpenStack(
            metadata=_check_metadata("cloudformation_stack_outputs_find_secrets"),
            resource=resource,
        )

        assert report.resource == resource
