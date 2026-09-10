"""Tests for the credential-free provider metadata stub (PROWLER-2145).

Every provider object used here is a plain ``SimpleNamespace`` WITHOUT a
``secret`` attribute: any code path trying to read ``provider.secret`` (the
coupling these tests guard against) would raise ``AttributeError`` and fail
the test. No database is required.
"""

from types import SimpleNamespace

import pytest
from api.models import Provider
from prowler.lib.outputs.finding import Finding as FindingOutput
from prowler.providers.github.models import GithubIdentityInfo
from tasks.jobs.reports import build_provider_metadata

PROVIDER_UID = "provider-uid-123"
PROVIDER_ALIAS = "my-provider-alias"


def _provider_row(provider_type: str, alias: str | None = PROVIDER_ALIAS):
    """Mimic the Provider DB row attributes read by build_provider_metadata."""
    return SimpleNamespace(provider=provider_type, uid=PROVIDER_UID, alias=alias)


class TestBuildProviderMetadata:
    @pytest.mark.parametrize("provider_type", Provider.ProviderChoices.values)
    def test_every_provider_type_gets_safe_defaults(self, provider_type):
        stub = build_provider_metadata(_provider_row(provider_type))

        assert stub.type == provider_type
        assert isinstance(stub.auth_method, str)
        assert hasattr(stub, "identity")

    def test_aws_identity_account_is_uid(self):
        stub = build_provider_metadata(_provider_row("aws"))
        assert stub.identity.account == PROVIDER_UID

    def test_azure_identity_covers_generate_output_accesses(self):
        stub = build_provider_metadata(_provider_row("azure"))

        # generate_output indexes tenant_ids[0] and reads these directly.
        assert stub.identity.tenant_ids
        assert stub.identity.identity_type == ""
        assert stub.identity.identity_id == ""
        assert stub.identity.subscriptions == {PROVIDER_UID: PROVIDER_ALIAS}

    def test_gcp_projects_keyed_by_uid(self):
        stub = build_provider_metadata(_provider_row("gcp"))

        project = stub.projects[PROVIDER_UID]
        assert project.id == PROVIDER_UID
        assert project.name == PROVIDER_ALIAS
        assert project.labels == {}
        # generate_output calls getattr(project, "organization") without a
        # default, so the attribute must exist (None skips the org branch).
        assert project.organization is None

    def test_kubernetes_identity_context_and_cluster(self):
        stub = build_provider_metadata(_provider_row("kubernetes"))
        assert stub.identity.context == PROVIDER_UID
        assert stub.identity.cluster == PROVIDER_UID

    def test_github_identity_is_real_identity_info(self):
        # generate_output only assigns account fields inside
        # isinstance(identity, Github*IdentityInfo) branches.
        stub = build_provider_metadata(_provider_row("github"))
        assert isinstance(stub.identity, GithubIdentityInfo)
        assert stub.identity.account_id == PROVIDER_UID
        assert stub.identity.account_name == PROVIDER_ALIAS

    def test_iac_provider_uid(self):
        stub = build_provider_metadata(_provider_row("iac"))
        assert stub.provider_uid == PROVIDER_UID

    def test_alias_falls_back_to_uid(self):
        stub = build_provider_metadata(_provider_row("azure", alias=None))
        assert stub.identity.subscriptions == {PROVIDER_UID: PROVIDER_UID}


def _check_metadata_dict(provider_type: str, check_id: str) -> dict:
    return {
        "provider": provider_type,
        "checkid": check_id,
        "checktitle": "Test check title",
        "checktype": [],
        # CheckMetadata validates ServiceName == check_id.split("_")[0]
        "servicename": check_id.split("_")[0],
        "subservicename": "",
        "severity": "high",
        "resourcetype": "resource-type",
        "description": "",
        "risk": "",
        "relatedurl": "",
        "remediation": {
            "recommendation": {"text": "", "url": ""},
            "code": {"nativeiac": "", "terraform": "", "cli": "", "other": ""},
        },
        "resourceidtemplate": "",
        "categories": [],
        "dependson": [],
        "relatedto": [],
        "notes": "",
    }


class _FakeFinding:
    """Attribute-faithful Finding stand-in.

    A plain object instead of ``Mock``: only the attributes the Django model
    exposes exist, so any new provider-attribute read in generate_output
    (e.g. cloudflare's ``getattr(finding, "account_id", ...)``) hits the
    same missing-attribute path it would hit in production instead of being
    masked by Mock auto-created attributes.
    """


def _finding_model(provider_type: str, check_id: str, region: str):
    """Mimic the Django Finding row attributes read by transform_api_finding."""
    resource = SimpleNamespace(
        uid="resource-uid",
        name="resource-name",
        metadata="{}",
        details="",
        region=region,
        tags=SimpleNamespace(all=lambda: []),
    )
    finding = _FakeFinding()
    finding.resources = SimpleNamespace(first=lambda: resource)
    finding.check_metadata = _check_metadata_dict(provider_type, check_id)
    finding.status = "FAIL"
    finding.status_extended = "failed for testing"
    finding.muted = False
    return finding


_FINDING_REGION = "region-x"

# Expected (account_uid, region) of the transformed finding per provider
# type, with resource.region = _FINDING_REGION. Keyed by every
# Provider.ProviderChoices value so that adding a new provider type without
# extending build_provider_metadata (and this table) fails the test below
# instead of breaking PDF generation at runtime.
_EXPECTED_TRANSFORM = {
    "aws": (PROVIDER_UID, _FINDING_REGION),
    "azure": (PROVIDER_UID, _FINDING_REGION),
    "gcp": (PROVIDER_UID, _FINDING_REGION),
    # transform_api_finding strips the "namespace: " prefix and
    # generate_output re-adds it.
    "kubernetes": (PROVIDER_UID, f"namespace: {_FINDING_REGION}"),
    "m365": (PROVIDER_UID, _FINDING_REGION),
    # For GitHub the owner comes from resource.region.
    "github": (_FINDING_REGION, _FINDING_REGION),
    "mongodbatlas": (PROVIDER_UID, _FINDING_REGION),
    "iac": (PROVIDER_UID, _FINDING_REGION),
    "oraclecloud": (PROVIDER_UID, _FINDING_REGION),
    "alibabacloud": (PROVIDER_UID, _FINDING_REGION),
    # Cloudflare uses the zone name (falls back to resource.name) as region.
    "cloudflare": (PROVIDER_UID, "resource-name"),
    "openstack": (PROVIDER_UID, _FINDING_REGION),
    "image": ("image", _FINDING_REGION),
    "googleworkspace": (PROVIDER_UID, _FINDING_REGION),
    "vercel": (PROVIDER_UID, "global"),
    "okta": (PROVIDER_UID, "global"),
}


class TestTransformApiFindingWithMetadataStub:
    """transform_api_finding must work end-to-end with the stub — i.e.
    without a credentialed SDK provider — for EVERY API provider type."""

    @pytest.mark.parametrize("provider_type", Provider.ProviderChoices.values)
    def test_transform_with_stub(self, provider_type):
        assert provider_type in _EXPECTED_TRANSFORM, (
            f"New provider type {provider_type!r}: add a branch to "
            f"build_provider_metadata covering the attributes read by "
            f"FindingOutput.generate_output, then add its expected "
            f"(account_uid, region) here."
        )
        expected_account_uid, expected_region = _EXPECTED_TRANSFORM[provider_type]

        stub = build_provider_metadata(_provider_row(provider_type))
        check_id = f"{provider_type}_test_check"
        finding_model = _finding_model(provider_type, check_id, _FINDING_REGION)

        output = FindingOutput.transform_api_finding(finding_model, stub)

        assert output.check_id == check_id
        assert output.status == "FAIL"
        assert output.account_uid == expected_account_uid
        assert output.region == expected_region
        assert output.resource_name
        assert output.resource_uid
