import pytest

from api.models import Resource, ResourceTag


@pytest.mark.django_db
class TestResourceModel:
    def test_setting_tags(self, providers_fixture):
        provider, *_ = providers_fixture

        resource = Resource.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            name="My Instance 1",
            region="us-east-1",
            service="ec2",
            type="prowler-test",
        )

        tags = [
            ResourceTag.objects.create(
                tenant_id=provider.tenant_id,
                key="key",
                value="value",
            ),
            ResourceTag.objects.create(
                tenant_id=provider.tenant_id,
                key="key2",
                value="value2",
            ),
        ]

        resource.upsert_or_delete_tags(tags)

        assert len(tags) == len(resource.tags.all())

        tags_dict = resource.get_tags()

        for tag in tags:
            assert tag.key in tags_dict
            assert tag.value == tags_dict[tag.key]

    def test_adding_tags(self, resources_fixture):
        resource, *_ = resources_fixture

        tags = [
            ResourceTag.objects.create(
                tenant_id=resource.tenant_id,
                key="env",
                value="test",
            ),
        ]
        before_count = len(resource.tags.all())

        resource.upsert_or_delete_tags(tags)

        assert before_count + 1 == len(resource.tags.all())

        tags_dict = resource.get_tags()

        assert "env" in tags_dict
        assert tags_dict["env"] == "test"

    def test_adding_duplicate_tags(self, resources_fixture):
        resource, *_ = resources_fixture

        tags = resource.tags.all()

        before_count = len(resource.tags.all())

        resource.upsert_or_delete_tags(tags)

        # should be the same number of tags
        assert before_count == len(resource.tags.all())

    def test_add_tags_none(self, resources_fixture):
        resource, *_ = resources_fixture
        resource.upsert_or_delete_tags(None)

        assert len(resource.tags.all()) == 0
        assert resource.get_tags() == {}

    def test_clear_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        resource.clear_tags()

        assert len(resource.tags.all()) == 0
        assert resource.get_tags() == {}
