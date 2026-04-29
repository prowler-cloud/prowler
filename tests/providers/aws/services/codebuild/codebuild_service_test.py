from datetime import datetime, timedelta
from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.codebuild.codebuild_service import (
    Build,
    CloudWatchLogs,
    Codebuild,
    ExportConfig,
    Project,
    ReportGroup,
    Webhook,
    WebhookFilter,
    WebhookFilterGroup,
    s3Logs,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

project_name = "test"
project_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
build_spec_project_arn = "arn:aws:s3:::my-codebuild-sample2/buildspec.yml"
source_type = "BITBUCKET"
build_id = "test:93f838a7-cd20-48ae-90e5-c10fbbc78ca6"
last_invoked_time = datetime.now() - timedelta(days=2)
bitbucket_url = "https://bitbucket.org/example/repo.git"
secondary_bitbucket_url = "https://bitbucket.org/example/secondary-repo.git"
project_visibility = "PRIVATE"

report_group_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:report-group/{project_name}"

# Mocking batch_get_projects
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListProjects":
        return {"projects": [project_name]}
    elif operation_name == "ListBuildsForProject":
        return {"ids": [build_id]}
    elif operation_name == "BatchGetBuilds":
        return {"builds": [{"id": build_id, "endTime": last_invoked_time}]}
    elif operation_name == "BatchGetProjects":
        return {
            "projects": [
                {
                    "arn": project_arn,
                    "source": {
                        "type": source_type,
                        "location": bitbucket_url,
                        "buildspec": build_spec_project_arn,
                    },
                    "secondarySources": [
                        {
                            "type": source_type,
                            "location": secondary_bitbucket_url,
                            "buildspec": "",
                        }
                    ],
                    "logsConfig": {
                        "cloudWatchLogs": {
                            "status": "ENABLED",
                            "groupName": project_name,
                            "streamName": project_name,
                        },
                        "s3Logs": {
                            "status": "ENABLED",
                            "location": "test-bucket",
                            "encryptionDisabled": False,
                        },
                    },
                    "tags": [{"key": "Name", "value": project_name}],
                    "projectVisibility": project_visibility,
                    "webhook": {
                        "filterGroups": [
                            [
                                {
                                    "type": "ACTOR_ACCOUNT_ID",
                                    "pattern": "^123456789$",
                                    "excludeMatchedPattern": False,
                                },
                                {
                                    "type": "EVENT",
                                    "pattern": "PUSH",
                                    "excludeMatchedPattern": False,
                                },
                            ]
                        ],
                        "branchFilter": "main",
                    },
                }
            ]
        }
    elif operation_name == "ListReportGroups":
        return {"reportGroups": [report_group_arn]}
    elif operation_name == "BatchGetReportGroups":
        return {
            "reportGroups": [
                {
                    "name": project_name,
                    "arn": report_group_arn,
                    "exportConfig": {
                        "exportConfigType": "S3",
                        "s3Destination": {
                            "bucket": "test-bucket",
                            "path": "test-path",
                            "encryptionKey": "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                            "encryptionDisabled": False,
                        },
                    },
                    "tags": [{"key": "Name", "value": project_name}],
                    "status": "ACTIVE",
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


class Test_Codebuild_Service:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_codebuild_service(self):
        codebuild = Codebuild(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert codebuild.session.__class__.__name__ == "Session"
        assert codebuild.service == "codebuild"
        # Asserttions related with projects
        assert len(codebuild.projects) == 1
        assert isinstance(codebuild.projects, dict)
        assert isinstance(codebuild.projects[project_arn], Project)
        assert codebuild.projects[project_arn].name == project_name
        assert codebuild.projects[project_arn].arn == project_arn
        assert codebuild.projects[project_arn].region == AWS_REGION_EU_WEST_1
        assert codebuild.projects[project_arn].last_invoked_time == last_invoked_time
        assert codebuild.projects[project_arn].last_build == Build(id=build_id)
        assert codebuild.projects[project_arn].buildspec == build_spec_project_arn
        assert bitbucket_url == codebuild.projects[project_arn].source.location
        assert (
            secondary_bitbucket_url
            in codebuild.projects[project_arn].secondary_sources[0].location
        )
        assert isinstance(codebuild.projects[project_arn].s3_logs, s3Logs)
        assert codebuild.projects[project_arn].s3_logs.enabled
        assert codebuild.projects[project_arn].s3_logs.bucket_location == "test-bucket"
        assert codebuild.projects[project_arn].s3_logs.encrypted
        assert isinstance(
            codebuild.projects[project_arn].cloudwatch_logs, CloudWatchLogs
        )
        assert codebuild.projects[project_arn].cloudwatch_logs.enabled
        assert (
            codebuild.projects[project_arn].cloudwatch_logs.group_name == project_name
        )
        assert (
            codebuild.projects[project_arn].cloudwatch_logs.stream_name == project_name
        )
        assert codebuild.projects[project_arn].tags[0]["key"] == "Name"
        assert codebuild.projects[project_arn].tags[0]["value"] == project_name
        assert codebuild.projects[project_arn].project_visibility == project_visibility
        # Assertions related with webhooks
        assert codebuild.projects[project_arn].webhook is not None
        assert isinstance(codebuild.projects[project_arn].webhook, Webhook)
        assert codebuild.projects[project_arn].webhook.branch_filter == "main"
        assert len(codebuild.projects[project_arn].webhook.filter_groups) == 1
        assert isinstance(
            codebuild.projects[project_arn].webhook.filter_groups[0], WebhookFilterGroup
        )
        assert (
            len(codebuild.projects[project_arn].webhook.filter_groups[0].filters) == 2
        )
        assert isinstance(
            codebuild.projects[project_arn].webhook.filter_groups[0].filters[0],
            WebhookFilter,
        )
        assert (
            codebuild.projects[project_arn].webhook.filter_groups[0].filters[0].type
            == "ACTOR_ACCOUNT_ID"
        )
        assert (
            codebuild.projects[project_arn].webhook.filter_groups[0].filters[0].pattern
            == "^123456789$"
        )
        assert (
            codebuild.projects[project_arn]
            .webhook.filter_groups[0]
            .filters[0]
            .exclude_matched_pattern
            is False
        )
        # Assertions related with report groups
        assert len(codebuild.report_groups) == 1
        assert isinstance(codebuild.report_groups, dict)
        assert isinstance(codebuild.report_groups[report_group_arn], ReportGroup)
        assert codebuild.report_groups[report_group_arn].name == project_name
        assert codebuild.report_groups[report_group_arn].arn == report_group_arn
        assert codebuild.report_groups[report_group_arn].region == AWS_REGION_EU_WEST_1
        assert codebuild.report_groups[report_group_arn].status == "ACTIVE"
        assert isinstance(
            codebuild.report_groups[report_group_arn].export_config, ExportConfig
        )
        assert codebuild.report_groups[report_group_arn].export_config.type == "S3"
        assert (
            codebuild.report_groups[report_group_arn].export_config.bucket_location
            == "s3://test-bucket/test-path"
        )
        assert (
            codebuild.report_groups[report_group_arn].export_config.encryption_key
            == "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        )
        assert codebuild.report_groups[report_group_arn].export_config.encrypted
        assert codebuild.report_groups[report_group_arn].tags[0]["key"] == "Name"
        assert (
            codebuild.report_groups[report_group_arn].tags[0]["value"] == project_name
        )

# Module-level state and helpers used by the chunking/out-of-order test below.
# Kept at module level so the API-call mock is a plain function rather than a
# closure defined inside the test method.
TOTAL_PROJECTS = 150
many_project_names = [f"project-{i}" for i in range(TOTAL_PROJECTS)]
many_project_arns = [
    f"arn:{AWS_COMMERCIAL_PARTITION}:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:project/{name}"
    for name in many_project_names
]
many_build_ids_for = {name: f"{name}:build-id" for name in many_project_names}
many_end_times_for = {
    name: datetime.now() - timedelta(days=i)
    for i, name in enumerate(many_project_names)
}
many_name_by_build_id = {v: k for k, v in many_build_ids_for.items()}
many_batch_call_sizes = {"BatchGetProjects": [], "BatchGetBuilds": []}


def mock_make_api_call_many_projects(self, operation_name, kwarg):
    if operation_name == "ListProjects":
        return {"projects": many_project_names}
    if operation_name == "ListBuildsForProject":
        return {"ids": [many_build_ids_for[kwarg["projectName"]]]}
    if operation_name == "BatchGetBuilds":
        ids = kwarg["ids"]
        many_batch_call_sizes["BatchGetBuilds"].append(len(ids))
        # Reverse the response order to verify id->project mapping does not
        # depend on response ordering.
        builds = [
            {"id": bid, "endTime": many_end_times_for[many_name_by_build_id[bid]]}
            for bid in reversed(ids)
        ]
        return {"builds": builds}
    if operation_name == "BatchGetProjects":
        names = kwarg["names"]
        many_batch_call_sizes["BatchGetProjects"].append(len(names))
        # Reverse the response order to verify arn->project mapping does not
        # depend on response ordering.
        projects = [
            {
                "arn": f"arn:{AWS_COMMERCIAL_PARTITION}:codebuild:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:project/{name}",
                "source": {"type": "NO_SOURCE"},
                "logsConfig": {},
                "tags": [],
                "projectVisibility": "PRIVATE",
            }
            for name in reversed(names)
        ]
        return {"projects": projects}
    if operation_name == "ListReportGroups":
        return {"reportGroups": []}
    return make_api_call(self, operation_name, kwarg)


class Test_Codebuild_Service_Batching:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_many_projects,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_codebuild_batches_chunks_over_100_projects_and_maps_out_of_order_responses(
        self,
    ):
        """Verify _batch_get_projects/_batch_get_builds chunk in groups of 100
        and correctly map out-of-order batch responses back to the right
        project using `arn`/`id`.
        """
        # Reset the per-test recorder (module-level state survives across runs).
        many_batch_call_sizes["BatchGetProjects"].clear()
        many_batch_call_sizes["BatchGetBuilds"].clear()

        codebuild = Codebuild(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        # Verify chunking: 150 items -> two batches of 100 and 50.
        assert sorted(many_batch_call_sizes["BatchGetProjects"]) == [50, 100]
        assert sorted(many_batch_call_sizes["BatchGetBuilds"]) == [50, 100]

        # Verify all projects were tracked.
        assert len(codebuild.projects) == TOTAL_PROJECTS

        # Verify out-of-order responses were correctly mapped back to the
        # right project by `arn` (projects) and `id` (builds).
        for name, arn in zip(many_project_names, many_project_arns):
            project = codebuild.projects[arn]
            assert project.name == name
            assert project.project_visibility == "PRIVATE"
            assert project.last_build == Build(id=many_build_ids_for[name])
            assert project.last_invoked_time == many_end_times_for[name]

