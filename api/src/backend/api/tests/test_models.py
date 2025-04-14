import pytest

from api.db_utils import SeverityEnumField
from api.models import Finding, Resource, ResourceTag, StatusChoices


@pytest.mark.django_db
class TestResourceModel:
    def test_setting_tags(self, providers_fixture):
        provider, *_ = providers_fixture
        tenant_id = provider.tenant_id

        resource = Resource.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            name="My Instance 1",
            region="us-east-1",
            service="ec2",
            type="prowler-test",
        )

        tags = [
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="key",
                value="value",
            ),
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="key2",
                value="value2",
            ),
        ]

        resource.upsert_or_delete_tags(tags)

        assert len(tags) == len(resource.tags.filter(tenant_id=tenant_id))

        tags_dict = resource.get_tags(tenant_id=tenant_id)

        for tag in tags:
            assert tag.key in tags_dict
            assert tag.value == tags_dict[tag.key]

    def test_adding_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)

        tags = [
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="env",
                value="test",
            ),
        ]
        before_count = len(resource.tags.filter(tenant_id=tenant_id))

        resource.upsert_or_delete_tags(tags)

        assert before_count + 1 == len(resource.tags.filter(tenant_id=tenant_id))

        tags_dict = resource.get_tags(tenant_id=tenant_id)

        assert "env" in tags_dict
        assert tags_dict["env"] == "test"

    def test_adding_duplicate_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)

        tags = resource.tags.filter(tenant_id=tenant_id)

        before_count = len(resource.tags.filter(tenant_id=tenant_id))

        resource.upsert_or_delete_tags(tags)

        # should be the same number of tags
        assert before_count == len(resource.tags.filter(tenant_id=tenant_id))

    def test_add_tags_none(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)
        resource.upsert_or_delete_tags(None)

        assert len(resource.tags.filter(tenant_id=tenant_id)) == 0
        assert resource.get_tags(tenant_id=tenant_id) == {}

    def test_clear_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)
        resource.clear_tags()

        assert len(resource.tags.filter(tenant_id=tenant_id)) == 0
        assert resource.get_tags(tenant_id=tenant_id) == {}


@pytest.mark.django_db
class TestFindingModel:
    def test_add_finding_with_long_uid(
        self, providers_fixture, scans_fixture, resources_fixture
    ):
        provider, *_ = providers_fixture
        tenant_id = provider.tenant_id

        long_uid = "1" * 500
        _ = Finding.objects.create(
            tenant_id=tenant_id,
            uid=long_uid,
            delta=Finding.DeltaChoices.NEW,
            check_metadata={},
            status=StatusChoices.PASS,
            status_extended="",
            severity=SeverityEnumField.HIGH,
            impact=SeverityEnumField.HIGH,
            raw_result={},
            check_id="test_check",
            scan=scans_fixture[0],
            first_seen_at=None,
            muted=False,
            compliance={},
        )
        assert Finding.objects.filter(uid=long_uid).exists()
