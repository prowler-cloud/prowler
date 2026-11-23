from unittest import mock

from prowler.providers.gcp.services.cloudsql.cloudsql_service import Instance
from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)

CHECK = "cloudsql_instance_deletion_protection_enabled"
CHECK_PATH = f"prowler.providers.gcp.services.cloudsql.{CHECK}.{CHECK}"


def build_instance(
    name: str,
    deletion_protection_enabled: bool,
    instance_type: str = "CLOUD_SQL_INSTANCE",
) -> Instance:
    return Instance(
        name=name,
        version="POSTGRES_15",
        ip_addresses=[],
        region=GCP_EU1_LOCATION,
        public_ip=False,
        require_ssl=True,
        ssl_mode="ENCRYPTED_ONLY",
        automated_backups=True,
        authorized_networks=[],
        flags=[],
        instance_type=instance_type,
        deletion_protection_enabled=deletion_protection_enabled,
        project_id=GCP_PROJECT_ID,
    )


def run_check(instances):
    cloudsql_client = mock.MagicMock()
    cloudsql_client.instances = instances
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.cloudsql_client", new=cloudsql_client),
    ):
        from prowler.providers.gcp.services.cloudsql.cloudsql_instance_deletion_protection_enabled.cloudsql_instance_deletion_protection_enabled import (
            cloudsql_instance_deletion_protection_enabled,
        )

        return cloudsql_instance_deletion_protection_enabled().execute()


class Test_cloudsql_instance_deletion_protection_enabled:
    def test_no_instances(self):
        assert run_check([]) == []

    def test_deletion_protection_enabled(self):
        result = run_check([build_instance("db-protected", True)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Database instance db-protected has deletion protection enabled."
        )
        assert result[0].resource_id == "db-protected"
        assert result[0].resource_name == "db-protected"
        assert result[0].location == GCP_EU1_LOCATION
        assert result[0].project_id == GCP_PROJECT_ID

    def test_deletion_protection_disabled(self):
        result = run_check([build_instance("db-unprotected", False)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Database instance db-unprotected does not have deletion protection enabled."
        )
        assert result[0].resource_id == "db-unprotected"

    def test_primary_and_replica_evaluated_on_premises_skipped(self):
        result = run_check(
            [
                build_instance("db-primary", True),
                build_instance("db-replica", False, "READ_REPLICA_INSTANCE"),
                build_instance("db-source", False, "ON_PREMISES_INSTANCE"),
            ]
        )
        assert [(r.resource_id, r.status) for r in result] == [
            ("db-primary", "PASS"),
            ("db-replica", "FAIL"),
        ]
