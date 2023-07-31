from unittest.mock import patch

from boto3 import client, session
from moto import mock_ecs

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ecs.ecs_service import ECS
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ECS_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test ECS Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        ecs = ECS(audit_info)
        assert ecs.service == "ecs"

    # Test ECS client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        ecs = ECS(audit_info)
        for reg_client in ecs.regional_clients.values():
            assert reg_client.__class__.__name__ == "ECS"

    # Test ECS session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        ecs = ECS(audit_info)
        assert ecs.session.__class__.__name__ == "Session"

    # Test list ECS task definitions
    @mock_ecs
    def test__list_task_definitions__(self):
        ecs_client = client("ecs", region_name=AWS_REGION)

        definition = dict(
            family="test_ecs_task",
            containerDefinitions=[
                {
                    "name": "hello_world",
                    "image": "hello-world:latest",
                    "memory": 400,
                }
            ],
        )

        task_definition = ecs_client.register_task_definition(**definition)
        audit_info = self.set_mocked_audit_info()
        ecs = ECS(audit_info)

        assert len(ecs.task_definitions) == 1
        assert (
            ecs.task_definitions[0].name == task_definition["taskDefinition"]["family"]
        )
        assert (
            ecs.task_definitions[0].arn
            == task_definition["taskDefinition"]["taskDefinitionArn"]
        )
        assert ecs.task_definitions[0].environment_variables == []

    @mock_ecs
    # Test describe ECS task definitions
    def test__describe_task_definitions__(self):
        ecs_client = client("ecs", region_name=AWS_REGION)

        definition = dict(
            family="test_ecs_task",
            containerDefinitions=[
                {
                    "name": "hello_world",
                    "image": "hello-world:latest",
                    "memory": 400,
                    "environment": [
                        {"name": "test-env", "value": "test-env-value"},
                        {"name": "test-env2", "value": "test-env-value2"},
                    ],
                }
            ],
            tags=[
                {"key": "test", "value": "test"},
            ],
        )

        task_definition = ecs_client.register_task_definition(**definition)
        audit_info = self.set_mocked_audit_info()
        ecs = ECS(audit_info)

        assert len(ecs.task_definitions) == 1
        assert (
            ecs.task_definitions[0].name == task_definition["taskDefinition"]["family"]
        )
        assert ecs.task_definitions[0].tags == [
            {"key": "test", "value": "test"},
        ]
        assert (
            ecs.task_definitions[0].arn
            == task_definition["taskDefinition"]["taskDefinitionArn"]
        )
        assert (
            ecs.task_definitions[0].environment_variables[0].name
            == task_definition["taskDefinition"]["containerDefinitions"][0][
                "environment"
            ][0]["name"]
        )
        assert (
            ecs.task_definitions[0].environment_variables[0].value
            == task_definition["taskDefinition"]["containerDefinitions"][0][
                "environment"
            ][0]["value"]
        )
        assert (
            ecs.task_definitions[0].environment_variables[1].name
            == task_definition["taskDefinition"]["containerDefinitions"][0][
                "environment"
            ][1]["name"]
        )
        assert (
            ecs.task_definitions[0].environment_variables[1].value
            == task_definition["taskDefinition"]["containerDefinitions"][0][
                "environment"
            ][1]["value"]
        )
