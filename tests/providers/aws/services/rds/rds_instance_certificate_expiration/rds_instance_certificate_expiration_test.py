from datetime import datetime
from unittest import mock

import botocore
from dateutil import relativedelta
from pytz import utc

from prowler.providers.aws.services.rds.rds_service import Certificate, DBInstance

AWS_ACCOUNT_NUMBER_CON = "123456789012"
AWS_REGION = "us-east-1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_certificate_expiration:
    def test_rds_no_instances(self):
        rds_client = mock.MagicMock
        rds_client.db_instances = {}

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 0

    def test_rds_certificate_expired(self):

        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) - relativedelta.relativedelta(months=7)
        customer_override_valid = datetime.now(utc) - relativedelta.relativedelta(
            months=7
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=False,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "critical"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 certificate has expired."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_rds_certificate_not_expired(self):

        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=7)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=7
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=False,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == "informational"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 certificate has over 6 months of validity left."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_rds_certificate_less_than_one_month(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(weeks=2)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            weeks=2
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=False,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "high"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 certificate less than 1 month of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_rds_certificate_between_three_and_six_months(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=4)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=4
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=False,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == "low"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 certificate has between 3 and 6 months of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_rds_certificate_less_than_three_months(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=3)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=3
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=False,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "medium"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 certificate less than 3 months of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_custom_rds_certificate_over_six_months(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=7)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=7
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=True,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == "informational"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 custom certificate has over 6 months of validity left."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_custom_rds_certificate_between_three_and_six_months(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=4)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=4
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=True,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == "low"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 custom certificate has between 3 and 6 months of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_custom_rds_certificate_less_than_three_months(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(months=3)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            months=3
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=True,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "medium"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 custom certificate less than 3 months of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_custom_rds_certificate_less_than_one_month(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) + relativedelta.relativedelta(weeks=2)
        customer_override_valid = datetime.now(utc) + relativedelta.relativedelta(
            weeks=2
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=True,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "high"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 custom certificate less than 1 month of validity."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []

    def test_custom_rds_certificate_expired(self):
        valid_from = datetime.now(utc) - relativedelta.relativedelta(months=7)
        valid_till = datetime.now(utc) - relativedelta.relativedelta(months=7)
        customer_override_valid = datetime.now(utc) - relativedelta.relativedelta(
            months=7
        )

        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="aurora-postgresql",
                engine_version="aurora14",
                status="available",
                public=False,
                encrypted=True,
                deletion_protection=True,
                auto_minor_version_upgrade=False,
                multi_az=True,
                username="test",
                iam_auth=False,
                region=AWS_REGION,
                ca_cert="rds-ca-rsa2048-g1",
                endpoint={},
                cert=[
                    Certificate(
                        id="rds-ca-rsa2048-g1",
                        arn=f"arn:aws:rds:{AWS_REGION}::cert:rds-ca-2019",
                        type="CA",
                        valid_from=valid_from,
                        valid_till=valid_till,
                        customer_override=True,
                        customer_override_valid_till=customer_override_valid,
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_client.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_certificate_expiration.rds_instance_certificate_expiration import (
                rds_instance_certificate_expiration,
            )

            check = rds_instance_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == "critical"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 custom certificate has expired."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER_CON}:db:db-master-1"
            )
            assert result[0].resource_tags == []
