from types import SimpleNamespace

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIdentityCenterService:
    def test_real_session_does_not_require_mock_flag(self):
        from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
            IdentityCenter,
        )

        provider = set_mocked_huaweicloud_provider(region="eu-west-101")
        del provider.session.is_mock
        provider.session.client.return_value.list_instances.return_value = (
            SimpleNamespace(
                instances=[],
                page_info=SimpleNamespace(next_marker=None),
            )
        )

        service = IdentityCenter(provider)

        assert service.instances == []
        assert service.error is None

    def test_preserves_instance_discovery_error(self):
        from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
            IdentityCenter,
        )

        provider = set_mocked_huaweicloud_provider(region="eu-west-101")
        provider.session.is_mock = False
        provider.session.client.return_value.list_instances.side_effect = RuntimeError(
            "access denied"
        )

        service = IdentityCenter(provider)

        assert service.instances == []
        assert service.error == "access denied"

    def test_lists_all_instances_and_permission_sets_pages(self):
        from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import (
            IdentityCenter,
        )

        provider = set_mocked_huaweicloud_provider(region="eu-west-101")
        provider.session.is_mock = False
        client = provider.session.client.return_value
        marker = "a" * 24
        client.list_instances.side_effect = [
            SimpleNamespace(
                instances=[
                    SimpleNamespace(instance_id="ins-1", instance_urn="urn:ins-1")
                ],
                page_info=SimpleNamespace(next_marker=marker),
            ),
            SimpleNamespace(
                instances=[
                    SimpleNamespace(instance_id="ins-2", instance_urn="urn:ins-2")
                ],
                page_info=SimpleNamespace(next_marker=None),
            ),
        ]
        client.list_permission_sets.side_effect = [
            SimpleNamespace(
                permission_sets=[SimpleNamespace(permission_set_id="ps-1")],
                page_info=SimpleNamespace(next_marker=marker),
            ),
            SimpleNamespace(
                permission_sets=[SimpleNamespace(permission_set_id="ps-2")],
                page_info=SimpleNamespace(next_marker=None),
            ),
            SimpleNamespace(
                permission_sets=[SimpleNamespace(permission_set_id="ps-3")],
                page_info=SimpleNamespace(next_marker=None),
            ),
        ]

        service = IdentityCenter(provider)

        assert [instance.instance_id for instance in service.instances] == [
            "ins-1",
            "ins-2",
        ]
        assert service.instances[0].instance_urn == "urn:ins-1"
        assert service.instances[0].permission_sets == ["ps-1", "ps-2"]
        assert service.instances[1].permission_sets == ["ps-3"]
        assert client.list_instances.call_args_list[1].args[0].marker == marker
        assert client.list_permission_sets.call_args_list[1].args[0].marker == marker
