from importlib import import_module
from types import SimpleNamespace

import pytest
from django.apps import apps

from api.models import ProviderSecret


@pytest.mark.django_db
class TestRemoveOraclecloudSecretRegionsMigration:
    def test_removes_region_fields_from_oraclecloud_secrets_only(
        self, providers_fixture
    ):
        oraclecloud_provider = providers_fixture[6]
        aws_provider = providers_fixture[0]
        oraclecloud_secret = ProviderSecret.objects.create(
            tenant_id=oraclecloud_provider.tenant_id,
            provider=oraclecloud_provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            secret={
                "user": "ocid1.user.oc1..fake",
                "fingerprint": "00:11:22:33:44:55:66:77",
                "key_content": "fake-base64-key-content",
                "tenancy": "ocid1.tenancy.oc1..fake",
                "region": "us-ashburn-1",
                "regions": ["us-phoenix-1"],
            },
        )
        aws_secret = ProviderSecret.objects.create(
            tenant_id=aws_provider.tenant_id,
            provider=aws_provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            secret={
                "aws_access_key_id": "fake-access-key-id",
                "aws_secret_access_key": "fake-secret-access-key",
                "region": "us-east-1",
            },
        )
        migration = import_module(
            "api.migrations.0096_remove_oraclecloud_secret_regions"
        )
        schema_editor = SimpleNamespace(connection=SimpleNamespace(alias="default"))

        migration.remove_oraclecloud_secret_regions(apps, schema_editor)

        oraclecloud_secret.refresh_from_db()
        aws_secret.refresh_from_db()
        assert "region" not in oraclecloud_secret.secret
        assert "regions" not in oraclecloud_secret.secret
        assert aws_secret.secret["region"] == "us-east-1"
