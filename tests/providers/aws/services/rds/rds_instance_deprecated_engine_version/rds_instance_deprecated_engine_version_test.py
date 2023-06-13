from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_rds

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
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


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_deprecated_engine_version:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_rds
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 0

    @mock_rds
    def test_rds_instance_no_deprecated_engine_version(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="mysql",
            EngineVersion="8.0.32",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS instance db-master-1 is not using a deprecated engine mysql with version 8.0.32."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_rds
    def test_rds_instance_deprecated_engine_version(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-2",
            AllocatedStorage=10,
            Engine="mysql",
            EngineVersion="8.0.23",
            DBName="staging-mysql",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version.rds_client",
                new=RDS(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_deprecated_engine_version.rds_instance_deprecated_engine_version import (
                    rds_instance_deprecated_engine_version,
                )

                check = rds_instance_deprecated_engine_version()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance db-master-2 is using a deprecated engine mysql with version 8.0.23."
                )
                assert result[0].resource_id == "db-master-2"
                assert result[0].region == AWS_REGION
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:db-master-2"
                )
                assert result[0].resource_tags == []
