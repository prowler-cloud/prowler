from types import SimpleNamespace

from prowler.providers.github.models import GithubIdentityInfo


def build_provider_metadata(provider) -> SimpleNamespace:
    """Build a credential-free stand-in for the Prowler SDK provider.

    ``FindingOutput.transform_api_finding`` only reads static attributes
    from the provider (``type`` plus a few identity/metadata fields used to
    label accounts), so compliance reports never need the decrypted
    ``ProviderSecret`` nor a live cloud SDK session. This builds an object
    exposing exactly those attributes from the ``Provider`` DB row, which
    keeps report generation working when the provider secret has been
    deleted or its credentials are no longer valid (PROWLER-2145).

    Args:
        provider: The API ``Provider`` model instance (only ``provider``,
            ``uid`` and ``alias`` are read).

    Returns:
        A ``SimpleNamespace`` mimicking the SDK provider attributes consumed
        by ``FindingOutput.transform_api_finding`` / ``generate_output``.
    """
    provider_type = provider.provider
    uid = provider.uid
    display_name = provider.alias or uid

    # Defaults cover every attribute read unconditionally in
    # FindingOutput.generate_output (``provider.auth_method`` is accessed
    # directly for several provider types); identity lookups go through
    # get_nested_attribute/getattr, which tolerate missing attributes.
    stub = SimpleNamespace(
        type=provider_type,
        auth_method="",
        identity=SimpleNamespace(),
    )

    if provider_type == "aws":
        stub.identity = SimpleNamespace(account=uid)
    elif provider_type == "azure":
        stub.identity = SimpleNamespace(
            identity_type="",
            identity_id="",
            tenant_ids=[""],
            tenant_domain="",
            subscriptions={uid: display_name},
        )
    elif provider_type == "gcp":
        stub.identity = SimpleNamespace(profile="")
        stub.projects = {
            uid: SimpleNamespace(
                id=uid,
                name=display_name,
                labels={},
                organization=None,
            )
        }
    elif provider_type == "kubernetes":
        stub.identity = SimpleNamespace(context=uid, cluster=uid)
    elif provider_type == "m365":
        stub.identity = SimpleNamespace(
            identity_type="",
            identity_id="",
            tenant_domain=uid,
            tenant_id="",
        )
    elif provider_type == "github":
        # generate_output assigns account fields only inside
        # isinstance(identity, Github*IdentityInfo) branches, so the stub
        # must carry a real GithubIdentityInfo instance.
        stub.identity = GithubIdentityInfo(
            account_id=uid,
            account_name=display_name,
            account_url="",
        )
    elif provider_type == "mongodbatlas":
        stub.identity = SimpleNamespace(
            organization_id=uid,
            organization_name=display_name,
        )
    elif provider_type == "iac":
        stub.provider_uid = uid
    elif provider_type == "oraclecloud":
        stub.identity = SimpleNamespace(
            tenancy_id=uid,
            tenancy_name=display_name,
        )
    elif provider_type == "alibabacloud":
        stub.identity = SimpleNamespace(
            identity_arn="",
            account_id=uid,
            account_name=display_name,
        )
    elif provider_type == "cloudflare":
        stub.identity = SimpleNamespace(
            audited_accounts=[uid],
            accounts=[],
        )
    elif provider_type == "openstack":
        stub.identity = SimpleNamespace(
            username="",
            project_id=uid,
            project_name=display_name,
        )
    elif provider_type == "googleworkspace":
        stub.identity = SimpleNamespace(
            delegated_user="",
            customer_id=uid,
            domain=display_name,
        )
    elif provider_type == "vercel":
        stub.identity = SimpleNamespace(
            team=None,
            user_id=uid,
            username=display_name,
        )
    elif provider_type == "okta":
        stub.identity = SimpleNamespace(
            org_domain=uid,
            client_id="",
        )

    return stub
