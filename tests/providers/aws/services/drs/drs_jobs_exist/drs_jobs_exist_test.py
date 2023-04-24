from unittest import mock

from prowler.providers.aws.services.drs.drs_service import Job, DRSservice

AWS_REGION = "eu-west-1"
JOB_ARN = "arn:aws:drs:eu-west-1:123456789012:job/12345678901234567890123456789012"


class Test_drs_jobs_exist:
    def test_drs_jobs_exist(self):
        drs_client = mock.MagicMock
        drs_client.region = AWS_REGION
        drs_client.drs_jobs = [
            Job(
                arn=JOB_ARN,
                id="12345678901234567890123456789012",
                status="COMPLETED",
                region=AWS_REGION,
                tags=[{"Key": "Name", "Value": "test"}],
            )
        ]
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="ENABLED",
                region=AWS_REGION,
                jobs=drs_client.drs_jobs,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_jobs_exist.drs_jobs_exist import (
                drs_jobs_exist,
            )

            check = drs_jobs_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "DRS is enabled for this region with jobs."
            )
            assert result[0].resource_id == "DRS"
            assert result[0].resource_arn == ""
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_drs_no_jobs(self):
        drs_client = mock.MagicMock
        drs_client.region = AWS_REGION
        drs_client.drs_jobs = []
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="ENABLED",
                region=AWS_REGION,
                jobs=drs_client.drs_jobs,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_jobs_exist.drs_jobs_exist import (
                drs_jobs_exist,
            )

            check = drs_jobs_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DRS is enabled for this region without jobs."
            )
            assert result[0].resource_id == "DRS"
            assert result[0].resource_arn == ""
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_drs_disabled(self):
        drs_client = mock.MagicMock
        drs_client.region = AWS_REGION
        drs_client.drs_jobs = []
        drs_client.drs_services = [
            DRSservice(
                id="DRS",
                status="DISABLED",
                region=AWS_REGION,
                jobs=drs_client.drs_jobs,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.drs.drs_service.DRS",
            new=drs_client,
        ):
            # Test Check
            from prowler.providers.aws.services.drs.drs_jobs_exist.drs_jobs_exist import (
                drs_jobs_exist,
            )

            check = drs_jobs_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "DRS is not enabled for this region."
            assert result[0].resource_id == "DRS"
            assert result[0].resource_arn == ""
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
