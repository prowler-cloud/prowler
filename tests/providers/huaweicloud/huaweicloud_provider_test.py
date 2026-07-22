import os
from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.huaweicloud.exceptions.exceptions import (
    HuaweiCloudAssumeRoleError,
    HuaweiCloudAuthenticationError,
    HuaweiCloudBaseException,
    HuaweiCloudCredentialsError,
    HuaweiCloudIdentityError,
    HuaweiCloudInvalidProviderIdError,
    HuaweiCloudInvalidRegionError,
    HuaweiCloudServiceError,
    HuaweiCloudSetUpSessionError,
)
from prowler.providers.huaweicloud.huaweicloud_provider import HuaweicloudProvider
from prowler.providers.huaweicloud.models import (
    HuaweiCloudCallerIdentity,
    HuaweiCloudCredentials,
    HuaweiCloudSession,
)

ACCESS_KEY = "AKIAmockaccesskey"
SECRET_KEY = "mocksecretkey"


class TestHuaweiCloudProviderSetupSession:
    def test_missing_credentials_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(HuaweiCloudCredentialsError):
                HuaweicloudProvider.setup_session()

    def test_returns_session_with_explicit_credentials(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = HuaweicloudProvider.setup_session(
                access_key_id=ACCESS_KEY,
                secret_access_key=SECRET_KEY,
            )
            assert isinstance(session, HuaweiCloudSession)
            assert session.get_credentials().ak == ACCESS_KEY

    def test_reads_credentials_from_env(self):
        env = {
            "HUAWEICLOUD_ACCESS_KEY_ID": ACCESS_KEY,
            "HUAWEICLOUD_SECRET_ACCESS_KEY": SECRET_KEY,
        }
        with mock.patch.dict(os.environ, env, clear=True):
            session = HuaweicloudProvider.setup_session()
            assert session.get_credentials().ak == ACCESS_KEY


class TestHuaweiCloudProviderValidateCredentials:
    def test_resolves_caller_identity_from_iam(self):
        session = HuaweiCloudSession(
            HuaweiCloudCredentials(ak=ACCESS_KEY, sk=SECRET_KEY, domain_id="domain-1")
        )

        domain = mock.MagicMock(id="domain-1")
        domain.name = "my-account"
        user = mock.MagicMock(id="user-1")
        user.name = "admin"
        iam_client = mock.MagicMock()
        iam_client.keystone_list_auth_domains.return_value = mock.MagicMock(
            domains=[domain]
        )
        iam_client.show_user.return_value = mock.MagicMock(user=user)

        builder = mock.MagicMock()
        builder.with_credentials.return_value.with_region.return_value.build.return_value = (
            iam_client
        )

        with (
            mock.patch(
                "huaweicloudsdkiam.v3.IamClient.new_builder", return_value=builder
            ),
            mock.patch("huaweicloudsdkcore.auth.credentials.BasicCredentials"),
            mock.patch("huaweicloudsdkiam.v3.region.iam_region.IamRegion"),
        ):
            identity = HuaweicloudProvider.validate_credentials(session=session)

        assert isinstance(identity, HuaweiCloudCallerIdentity)
        assert identity.domain_id == "domain-1"
        assert identity.account_name == "my-account"
        assert identity.user_name == "admin"


class TestHuaweiCloudProviderGetRegionsToAudit:
    @staticmethod
    def _provider():
        # Bare instance is enough: get_regions_to_audit only reads the module-level
        # HUAWEICLOUD_REGIONS and guards access to self._identity with hasattr.
        return HuaweicloudProvider.__new__(HuaweicloudProvider)

    def test_valid_regions(self):
        regions = self._provider().get_regions_to_audit(["cn-north-4"])
        assert [r.region_id for r in regions] == ["cn-north-4"]

    def test_no_regions_returns_all(self):
        from prowler.providers.huaweicloud.config import HUAWEICLOUD_REGIONS

        regions = self._provider().get_regions_to_audit(None)
        assert len(regions) == len(HUAWEICLOUD_REGIONS)

    def test_all_invalid_regions_raises(self):
        with pytest.raises(HuaweiCloudInvalidRegionError):
            self._provider().get_regions_to_audit(["not-a-region"])

    def test_partial_invalid_regions_keeps_valid(self):
        regions = self._provider().get_regions_to_audit(["cn-north-4", "not-a-region"])
        assert [r.region_id for r in regions] == ["cn-north-4"]


class TestHuaweiCloudProviderResolveRegions:
    def test_flag_takes_precedence_over_env(self):
        with mock.patch.dict(
            os.environ, {"HUAWEICLOUD_REGION": "eu-west-101"}, clear=True
        ):
            assert HuaweicloudProvider._resolve_regions(["ap-southeast-1"]) == [
                "ap-southeast-1"
            ]

    def test_falls_back_to_env_region(self):
        with mock.patch.dict(
            os.environ, {"HUAWEICLOUD_REGION": "eu-west-101"}, clear=True
        ):
            assert HuaweicloudProvider._resolve_regions(None) == ["eu-west-101"]

    def test_env_region_supports_multiple(self):
        with mock.patch.dict(
            os.environ,
            {"HUAWEICLOUD_REGION": "eu-west-101, ap-southeast-1"},
            clear=True,
        ):
            assert HuaweicloudProvider._resolve_regions(None) == [
                "eu-west-101",
                "ap-southeast-1",
            ]

    def test_hw_region_alias(self):
        with mock.patch.dict(os.environ, {"HW_REGION": "eu-west-0"}, clear=True):
            assert HuaweicloudProvider._resolve_regions(None) == ["eu-west-0"]

    def test_no_flag_no_env_returns_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert HuaweicloudProvider._resolve_regions(None) is None

    def test_cloud_selector_expands_to_cloud_regions(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert HuaweicloudProvider._resolve_regions(None, "europe") == [
                "eu-west-101"
            ]

    def test_cloud_selector_from_env(self):
        with mock.patch.dict(os.environ, {"HUAWEICLOUD_CLOUD": "europe"}, clear=True):
            assert HuaweicloudProvider._resolve_regions(None) == ["eu-west-101"]

    def test_region_overrides_cloud_selector(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert HuaweicloudProvider._resolve_regions(
                ["ap-southeast-1"], "europe"
            ) == ["ap-southeast-1"]

    def test_env_region_overrides_cloud_env(self):
        with mock.patch.dict(
            os.environ,
            {"HUAWEICLOUD_REGION": "eu-west-101", "HUAWEICLOUD_CLOUD": "china"},
            clear=True,
        ):
            assert HuaweicloudProvider._resolve_regions(None) == ["eu-west-101"]

    def test_cloud_alias_and_case_insensitive(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert HuaweicloudProvider._resolve_regions(None, "EU") == ["eu-west-101"]


class TestHuaweiCloudProviderRegionsForCloud:
    def test_europe_is_only_eu_endpoint_regions(self):
        assert HuaweicloudProvider._regions_for_cloud("europe") == ["eu-west-101"]

    def test_china_is_cn_prefixed_regions(self):
        regions = HuaweicloudProvider._regions_for_cloud("china")
        assert regions
        assert all(region.startswith("cn-") for region in regions)

    def test_international_excludes_china_and_europe(self):
        regions = HuaweicloudProvider._regions_for_cloud("international")
        assert regions
        assert all(not region.startswith("cn-") for region in regions)
        assert "eu-west-101" not in regions
        # eu-west-0 is an International (.com) region despite the eu- prefix
        assert "eu-west-0" in regions

    def test_clouds_partition_all_regions_without_overlap(self):
        from prowler.providers.huaweicloud.config import HUAWEICLOUD_REGIONS

        europe = set(HuaweicloudProvider._regions_for_cloud("europe"))
        china = set(HuaweicloudProvider._regions_for_cloud("china"))
        international = set(HuaweicloudProvider._regions_for_cloud("international"))
        assert europe & china == set()
        assert europe & international == set()
        assert china & international == set()
        assert europe | china | international == set(HUAWEICLOUD_REGIONS)

    def test_alias_maps_to_canonical_cloud(self):
        assert HuaweicloudProvider._regions_for_cloud(
            "intl"
        ) == HuaweicloudProvider._regions_for_cloud("international")
        assert HuaweicloudProvider._regions_for_cloud(
            "com"
        ) == HuaweicloudProvider._regions_for_cloud("international")
        assert HuaweicloudProvider._regions_for_cloud(
            "cn"
        ) == HuaweicloudProvider._regions_for_cloud("china")

    def test_unknown_cloud_returns_empty(self):
        assert HuaweicloudProvider._regions_for_cloud("mars") == []


class TestHuaweiCloudProviderValidationRegion:
    def test_no_regions_uses_default(self):
        from prowler.providers.huaweicloud.config import HUAWEICLOUD_DEFAULT_REGION

        assert (
            HuaweicloudProvider._validation_region(None) == HUAWEICLOUD_DEFAULT_REGION
        )

    def test_picks_first_iam_capable_requested_region(self):
        assert (
            HuaweicloudProvider._validation_region(["ap-southeast-1", "af-south-1"])
            == "af-south-1"
        )

    def test_skips_non_iam_regions_when_iam_region_present(self):
        # af-north-1 has no IAM endpoint; ap-southeast-1 does and sorts after it,
        # so validation must skip the non-IAM region.
        assert (
            HuaweicloudProvider._validation_region(["af-north-1", "ap-southeast-1"])
            == "ap-southeast-1"
        )

    def test_falls_back_to_same_cloud_iam_region_international(self):
        # Only a non-IAM International region requested -> validate against an
        # IAM-capable International region.
        region = HuaweicloudProvider._validation_region(["af-north-1"])
        from prowler.providers.huaweicloud.models import _iam_endpoint_for_region

        assert _iam_endpoint_for_region(region)
        assert not region.startswith("cn-")

    def test_falls_back_to_same_cloud_iam_region_china(self):
        region = HuaweicloudProvider._validation_region(["cn-south-4"])
        from prowler.providers.huaweicloud.models import _iam_endpoint_for_region

        assert _iam_endpoint_for_region(region)
        assert region.startswith("cn-")


class TestHuaweiCloudProviderTestConnection:
    def test_successful_connection(self):
        fake_identity = HuaweiCloudCallerIdentity(
            domain_id="d",
            user_id="u",
            user_name="n",
            account_id="123456789012",
            account_name="acct",
            type="user",
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            with (
                mock.patch.object(
                    HuaweicloudProvider,
                    "setup_session",
                    return_value=mock.MagicMock(),
                ),
                mock.patch.object(
                    HuaweicloudProvider,
                    "validate_credentials",
                    return_value=fake_identity,
                ),
            ):
                connection = HuaweicloudProvider.test_connection(
                    access_key_id=ACCESS_KEY,
                    secret_access_key=SECRET_KEY,
                    provider_id="123456789012",
                )
                assert connection.is_connected
                assert connection.error is None

    def test_provider_id_mismatch_raises(self):
        fake_identity = HuaweiCloudCallerIdentity(
            domain_id="d",
            user_id="u",
            user_name="n",
            account_id="111111111111",
            account_name="acct",
            type="user",
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            with (
                mock.patch.object(
                    HuaweicloudProvider,
                    "setup_session",
                    return_value=mock.MagicMock(),
                ),
                mock.patch.object(
                    HuaweicloudProvider,
                    "validate_credentials",
                    return_value=fake_identity,
                ),
            ):
                with pytest.raises(HuaweiCloudInvalidProviderIdError):
                    HuaweicloudProvider.test_connection(
                        access_key_id=ACCESS_KEY,
                        secret_access_key=SECRET_KEY,
                        provider_id="999999999999",
                        raise_on_exception=True,
                    )

    def test_missing_credentials_returns_error_when_not_raising(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            connection = HuaweicloudProvider.test_connection(raise_on_exception=False)
            assert connection.is_connected is not True
            assert connection.error is not None


def _agency_builder(credential):
    """Return a mocked IamClient builder chain for agency assumption."""
    client = mock.MagicMock()
    client.create_temporary_access_key_by_agency.return_value = SimpleNamespace(
        credential=credential
    )
    builder = mock.MagicMock()
    builder.with_credentials.return_value.with_region.return_value.build.return_value = (
        client
    )
    return builder, client


class TestHuaweiCloudProviderAssumeAgency:
    def test_returns_temporary_credentials(self):
        credential = SimpleNamespace(
            access="tmp-ak",
            secret="tmp-sk",
            securitytoken="tmp-token",
            expires_at="2026-01-01T00:00:00Z",
        )
        builder, client = _agency_builder(credential)
        base = HuaweiCloudCredentials(
            ak="base-ak", sk="base-sk", domain_id="base-domain"
        )

        with (
            mock.patch(
                "huaweicloudsdkiam.v3.IamClient.new_builder", return_value=builder
            ),
            mock.patch("huaweicloudsdkiam.v3.region.iam_region.IamRegion"),
        ):
            result = HuaweicloudProvider.assume_agency(
                credentials=base,
                agency_name="prowler-agency",
                assume_domain_id="target-domain",
            )

        assert result.ak == "tmp-ak"
        assert result.sk == "tmp-sk"
        assert result.security_token == "tmp-token"
        assert result.domain_id == "target-domain"

        request = client.create_temporary_access_key_by_agency.call_args[0][0]
        assume_role = request.body.auth.identity.assume_role
        assert assume_role.agency_name == "prowler-agency"
        assert assume_role.domain_id == "target-domain"

    def test_requires_target_domain(self):
        base = HuaweiCloudCredentials(ak="a", sk="b")
        with pytest.raises(HuaweiCloudAssumeRoleError):
            HuaweicloudProvider.assume_agency(
                credentials=base, agency_name="prowler-agency"
            )

    def test_sdk_failure_raises_assume_role_error(self):
        builder, client = _agency_builder(None)
        client.create_temporary_access_key_by_agency.side_effect = Exception("denied")
        base = HuaweiCloudCredentials(ak="a", sk="b")

        with (
            mock.patch(
                "huaweicloudsdkiam.v3.IamClient.new_builder", return_value=builder
            ),
            mock.patch("huaweicloudsdkiam.v3.region.iam_region.IamRegion"),
        ):
            with pytest.raises(HuaweiCloudAssumeRoleError):
                HuaweicloudProvider.assume_agency(
                    credentials=base,
                    agency_name="prowler-agency",
                    assume_domain_name="target-account",
                )

    def test_setup_session_assumes_agency_from_env(self):
        credential = SimpleNamespace(
            access="tmp-ak",
            secret="tmp-sk",
            securitytoken="tmp-token",
            expires_at="",
        )
        builder, _ = _agency_builder(credential)
        env = {
            "HUAWEICLOUD_ACCESS_KEY_ID": ACCESS_KEY,
            "HUAWEICLOUD_SECRET_ACCESS_KEY": SECRET_KEY,
            "HUAWEICLOUD_AGENCY_NAME": "prowler-agency",
            "HUAWEICLOUD_ASSUME_DOMAIN_ID": "target-domain",
        }

        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch(
                "huaweicloudsdkiam.v3.IamClient.new_builder", return_value=builder
            ),
            mock.patch("huaweicloudsdkiam.v3.region.iam_region.IamRegion"),
        ):
            session = HuaweicloudProvider.setup_session()

        assert session.get_credentials().ak == "tmp-ak"
        assert session.get_credentials().security_token == "tmp-token"


class TestHuaweiCloudExceptions:
    def test_error_codes_are_unique_and_in_reserved_range(self):
        classes = [
            HuaweiCloudCredentialsError,
            HuaweiCloudAuthenticationError,
            HuaweiCloudSetUpSessionError,
            HuaweiCloudIdentityError,
            HuaweiCloudInvalidRegionError,
            HuaweiCloudInvalidProviderIdError,
            HuaweiCloudServiceError,
            HuaweiCloudAssumeRoleError,
        ]
        codes = set()
        for cls in classes:
            error = cls(file="huaweicloud_provider.py")
            assert isinstance(error, HuaweiCloudBaseException)
            assert 19000 <= error.code <= 19099
            assert error.message
            assert error.remediation
            codes.add(error.code)
        assert len(codes) == len(classes)

    def test_custom_message_override(self):
        error = HuaweiCloudServiceError(message="custom service failure")
        assert error.message == "custom service failure"
        assert error.code == 19006
