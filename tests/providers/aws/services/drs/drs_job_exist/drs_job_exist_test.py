from unittest import mock

from prowler.providers.aws.services.drs.drs_service import DRSservice, Job
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

JOB_ARN = "arn:aws:drs:eu-west-1:123456789012:job/12345678901234567890123456789012"


class Test_drs_job_exist:
    def test_drs_job_exist(self):
        drs_client = mock.MagicMock
        drs_client.audited_account = AWS_ACCOUNT_NUMBER
        drs_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        drs_client.region = AWS_REGION_EU_WEST_1
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
                jobs=[
                    Job(
                        arn=JOB_ARN,
                        id="12345678901234567890123456789012",
                        status="COMPLETED",
                        region=AWS_REGION_EU_WEST_1,
                        tags=[{"Key": "Name", "Value": "test"}],
                    )
                ],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_job_exist.drs_job_exist import (
                drs_job_exist,
            )

            check = drs_job_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "DRS is enabled for this region with jobs."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_drs_no_jobs(self):
        drs_client = mock.MagicMock
        drs_client.audited_account = AWS_ACCOUNT_NUMBER
        drs_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        drs_client.region = AWS_REGION_EU_WEST_1
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
                jobs=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_job_exist.drs_job_exist import (
                drs_job_exist,
            )

            check = drs_job_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DRS is enabled for this region without jobs."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_drs_disabled(self):
        drs_client = mock.MagicMock
        drs_client.audited_account = AWS_ACCOUNT_NUMBER
        drs_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        drs_client.region = AWS_REGION_EU_WEST_1
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
                jobs=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_job_exist.drs_job_exist import (
                drs_job_exist,
            )

            check = drs_job_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "DRS is not enabled for this region."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_drs_disabled_allowlisted(self):
        drs_client = mock.MagicMock
        drs_client.audit_config = {"allowlist_non_default_regions": True}
        drs_client.audited_account = AWS_ACCOUNT_NUMBER
        drs_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        drs_client.region = "eu-west-2"
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
                jobs=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_job_exist.drs_job_exist import (
                drs_job_exist,
            )

            check = drs_job_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "WARNING"
            assert result[0].status_extended == "DRS is not enabled for this region."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
