from unittest import mock

from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    ReplicationSet,
    ResponsePlan,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

REPLICATION_SET_ARN = "arn:aws:ssm-incidents::111122223333:replication-set/40bd98f0-4110-2dee-b35e-b87006f9e172"
RESPONSE_PLAN_ARN = "arn:aws:ssm-incidents::111122223333:response-plan/example-response"


class Test_ssmincidents_enabled_with_plans:
    def test_ssmincidents_no_replicationset(self):
        ssmincidents_client = mock.MagicMock
        ssmincidents_client.audited_account = AWS_ACCOUNT_NUMBER
        ssmincidents_client.audited_partition = "aws"
        ssmincidents_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        ssmincidents_client.region = AWS_REGION_US_EAST_1
        ssmincidents_client.replication_set_arn_template = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        ssmincidents_client.__get_replication_set_arn_template__ = mock.MagicMock(
            return_value=ssmincidents_client.replication_set_arn_template
        )
        ssmincidents_client.replication_set = []
        with mock.patch(
            "prowler.providers.aws.services.ssmincidents.ssmincidents_service.SSMIncidents",
            new=ssmincidents_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssmincidents.ssmincidents_enabled_with_plans.ssmincidents_enabled_with_plans import (
                ssmincidents_enabled_with_plans,
            )

            check = ssmincidents_enabled_with_plans()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "No SSM Incidents replication set exists."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_ssmincidents_replicationset_not_active(self):
        ssmincidents_client = mock.MagicMock
        ssmincidents_client.audited_account = AWS_ACCOUNT_NUMBER
        ssmincidents_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        ssmincidents_client.region = AWS_REGION_US_EAST_1
        ssmincidents_client.replication_set = [
            ReplicationSet(arn=REPLICATION_SET_ARN, status="CREATING")
        ]
        ssmincidents_client.audited_partition = "aws"
        ssmincidents_client.replication_set_arn_template = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        ssmincidents_client.__get_replication_set_arn_template__ = mock.MagicMock(
            return_value=ssmincidents_client.replication_set_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.ssmincidents.ssmincidents_service.SSMIncidents",
            new=ssmincidents_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssmincidents.ssmincidents_enabled_with_plans.ssmincidents_enabled_with_plans import (
                ssmincidents_enabled_with_plans,
            )

            check = ssmincidents_enabled_with_plans()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SSM Incidents replication set {REPLICATION_SET_ARN} exists but not ACTIVE."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == REPLICATION_SET_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_ssmincidents_replicationset_active_no_plans(self):
        ssmincidents_client = mock.MagicMock
        ssmincidents_client.audited_account = AWS_ACCOUNT_NUMBER
        ssmincidents_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        ssmincidents_client.region = AWS_REGION_US_EAST_1
        ssmincidents_client.replication_set = [
            ReplicationSet(arn=REPLICATION_SET_ARN, status="ACTIVE")
        ]
        ssmincidents_client.audited_partition = "aws"
        ssmincidents_client.replication_set_arn_template = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        ssmincidents_client.__get_replication_set_arn_template__ = mock.MagicMock(
            return_value=ssmincidents_client.replication_set_arn_template
        )
        ssmincidents_client.response_plans = []
        with mock.patch(
            "prowler.providers.aws.services.ssmincidents.ssmincidents_service.SSMIncidents",
            new=ssmincidents_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssmincidents.ssmincidents_enabled_with_plans.ssmincidents_enabled_with_plans import (
                ssmincidents_enabled_with_plans,
            )

            check = ssmincidents_enabled_with_plans()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SSM Incidents replication set {REPLICATION_SET_ARN} is ACTIVE but no response plans exist."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == REPLICATION_SET_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_ssmincidents_replicationset_active_with_plans(self):
        ssmincidents_client = mock.MagicMock
        ssmincidents_client.audited_account = AWS_ACCOUNT_NUMBER
        ssmincidents_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        ssmincidents_client.region = AWS_REGION_US_EAST_1
        ssmincidents_client.replication_set = [
            ReplicationSet(arn=REPLICATION_SET_ARN, status="ACTIVE")
        ]
        ssmincidents_client.response_plans = [
            ResponsePlan(
                arn=RESPONSE_PLAN_ARN, name="test", region=AWS_REGION_US_EAST_1
            )
        ]
        ssmincidents_client.audited_partition = "aws"
        ssmincidents_client.replication_set_arn_template = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        ssmincidents_client.__get_replication_set_arn_template__ = mock.MagicMock(
            return_value=ssmincidents_client.replication_set_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.ssmincidents.ssmincidents_service.SSMIncidents",
            new=ssmincidents_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssmincidents.ssmincidents_enabled_with_plans.ssmincidents_enabled_with_plans import (
                ssmincidents_enabled_with_plans,
            )

            check = ssmincidents_enabled_with_plans()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SSM Incidents replication set {REPLICATION_SET_ARN} is ACTIVE and has response plans."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == REPLICATION_SET_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_access_denied(self):
        ssmincidents_client = mock.MagicMock
        ssmincidents_client.audited_account = AWS_ACCOUNT_NUMBER
        ssmincidents_client.audited_partition = "aws"
        ssmincidents_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        ssmincidents_client.region = AWS_REGION_US_EAST_1
        ssmincidents_client.replication_set_arn_template = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        ssmincidents_client.__get_replication_set_arn_template__ = mock.MagicMock(
            return_value=ssmincidents_client.replication_set_arn_template
        )
        ssmincidents_client.replication_set = None
        with mock.patch(
            "prowler.providers.aws.services.ssmincidents.ssmincidents_service.SSMIncidents",
            new=ssmincidents_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssmincidents.ssmincidents_enabled_with_plans.ssmincidents_enabled_with_plans import (
                ssmincidents_enabled_with_plans,
            )

            check = ssmincidents_enabled_with_plans()
            result = check.execute()

            assert len(result) == 0
