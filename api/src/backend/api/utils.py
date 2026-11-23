from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.exceptions import InvitationTokenExpiredException
from api.models import (
    Integration,
    Invitation,
    Membership,
    Processor,
    Provider,
    Role,
    UserRoleRelationship,
)
from api.v1.serializers import (
    FindingMetadataSerializer,
    KubernetesProviderSecret,
    declared_secret_fields,
)
from django.db import transaction
from prowler.lib.outputs.jira.jira import Jira, JiraBasicAuthError
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from prowler.providers.common.models import Connection
from rest_framework.exceptions import NotFound, ValidationError

logger = logging.getLogger(__name__)

STORED_SECRET_NOT_SUPPORTED_ERROR = (
    "The stored credentials do not match a supported credential type for this "
    "provider. Update the provider credentials."
)

if TYPE_CHECKING:
    from prowler.providers.alibabacloud.alibabacloud_provider import (
        AlibabacloudProvider,
    )
    from prowler.providers.aws.aws_provider import AwsProvider
    from prowler.providers.azure.azure_provider import AzureProvider
    from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
    from prowler.providers.gcp.gcp_provider import GcpProvider
    from prowler.providers.github.github_provider import GithubProvider
    from prowler.providers.googleworkspace.googleworkspace_provider import (
        GoogleworkspaceProvider,
    )
    from prowler.providers.iac.iac_provider import IacProvider
    from prowler.providers.image.image_provider import ImageProvider
    from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
    from prowler.providers.m365.m365_provider import M365Provider
    from prowler.providers.mongodbatlas.mongodbatlas_provider import (
        MongodbatlasProvider,
    )
    from prowler.providers.okta.okta_provider import OktaProvider
    from prowler.providers.openstack.openstack_provider import OpenstackProvider
    from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider
    from prowler.providers.vercel.vercel_provider import VercelProvider


class CustomOAuth2Client(OAuth2Client):
    def __init__(self, client_id, secret, *args, **kwargs):
        # Remove any duplicate "scope_delimiter" from kwargs
        # Bug present in dj-rest-auth after version v7.0.1
        # https://github.com/iMerica/dj-rest-auth/issues/673
        kwargs.pop("scope_delimiter", None)
        super().__init__(client_id, secret, *args, **kwargs)


def merge_dicts(default_dict: dict, replacement_dict: dict) -> dict:
    """
    Recursively merge two dictionaries, using `default_dict` as the base and `replacement_dict` for overriding values.

    Args:
        default_dict (dict): The base dictionary containing default key-value pairs.
        replacement_dict (dict): The dictionary containing values that should override those in `default_dict`.

    Returns:
        dict: A new dictionary containing all keys from `default_dict` with values from `replacement_dict` replacing
              any overlapping keys. If a key in both `default_dict` and `replacement_dict` contains dictionaries,
              this function will merge them recursively.
    """
    result = default_dict.copy()

    for key, value in replacement_dict.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            if value:
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value

    return result


def return_prowler_provider(
    provider: Provider,
) -> (
    AlibabacloudProvider
    | AwsProvider
    | AzureProvider
    | CloudflareProvider
    | GcpProvider
    | GithubProvider
    | GoogleworkspaceProvider
    | IacProvider
    | ImageProvider
    | KubernetesProvider
    | M365Provider
    | MongodbatlasProvider
    | OktaProvider
    | OpenstackProvider
    | OraclecloudProvider
    | VercelProvider
):
    """Return the Prowler provider class based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        AlibabacloudProvider | AwsProvider | AzureProvider | CloudflareProvider | GcpProvider | GithubProvider | GoogleworkspaceProvider | IacProvider | ImageProvider | KubernetesProvider | M365Provider | MongodbatlasProvider | OpenstackProvider | OraclecloudProvider: The corresponding provider class.

    Raises:
        ValueError: If the provider type specified in `provider.provider` is not supported.
    """
    match provider.provider:
        case Provider.ProviderChoices.AWS.value:
            from prowler.providers.aws.aws_provider import AwsProvider

            prowler_provider = AwsProvider
        case Provider.ProviderChoices.GCP.value:
            from prowler.providers.gcp.gcp_provider import GcpProvider

            prowler_provider = GcpProvider
        case Provider.ProviderChoices.GOOGLEWORKSPACE.value:
            from prowler.providers.googleworkspace.googleworkspace_provider import (
                GoogleworkspaceProvider,
            )

            prowler_provider = GoogleworkspaceProvider
        case Provider.ProviderChoices.AZURE.value:
            from prowler.providers.azure.azure_provider import AzureProvider

            prowler_provider = AzureProvider
        case Provider.ProviderChoices.KUBERNETES.value:
            from prowler.providers.kubernetes.kubernetes_provider import (
                KubernetesProvider,
            )

            prowler_provider = KubernetesProvider
        case Provider.ProviderChoices.M365.value:
            from prowler.providers.m365.m365_provider import M365Provider

            prowler_provider = M365Provider
        case Provider.ProviderChoices.GITHUB.value:
            from prowler.providers.github.github_provider import GithubProvider

            prowler_provider = GithubProvider
        case Provider.ProviderChoices.MONGODBATLAS.value:
            from prowler.providers.mongodbatlas.mongodbatlas_provider import (
                MongodbatlasProvider,
            )

            prowler_provider = MongodbatlasProvider
        case Provider.ProviderChoices.IAC.value:
            from prowler.providers.iac.iac_provider import IacProvider

            prowler_provider = IacProvider
        case Provider.ProviderChoices.ORACLECLOUD.value:
            from prowler.providers.oraclecloud.oraclecloud_provider import (
                OraclecloudProvider,
            )

            prowler_provider = OraclecloudProvider
        case Provider.ProviderChoices.ALIBABACLOUD.value:
            from prowler.providers.alibabacloud.alibabacloud_provider import (
                AlibabacloudProvider,
            )

            prowler_provider = AlibabacloudProvider
        case Provider.ProviderChoices.CLOUDFLARE.value:
            from prowler.providers.cloudflare.cloudflare_provider import (
                CloudflareProvider,
            )

            prowler_provider = CloudflareProvider
        case Provider.ProviderChoices.OPENSTACK.value:
            from prowler.providers.openstack.openstack_provider import OpenstackProvider

            prowler_provider = OpenstackProvider
        case Provider.ProviderChoices.IMAGE.value:
            from prowler.providers.image.image_provider import ImageProvider

            prowler_provider = ImageProvider
        case Provider.ProviderChoices.VERCEL.value:
            from prowler.providers.vercel.vercel_provider import VercelProvider

            prowler_provider = VercelProvider
        case Provider.ProviderChoices.OKTA.value:
            from prowler.providers.okta.okta_provider import OktaProvider

            prowler_provider = OktaProvider
        case _:
            raise ValueError(f"Provider type {provider.provider} not supported")
    return prowler_provider


def _validate_kubernetes_secret(secret: dict) -> None:
    """Re-validate a stored kubeconfig at use time; errors never echo its content."""
    KubernetesProviderSecret(
        data={"kubeconfig_content": secret.get("kubeconfig_content")}
    ).is_valid(raise_exception=True)


def _googleworkspace_credentials(secret: dict) -> dict:
    """Only the stored key and delegated user: the provider also reads file paths."""
    return {
        "credentials_content": secret.get("credentials_content"),
        "delegated_user": secret.get("delegated_user"),
    }


def declared_provider_secret(provider: Provider) -> dict:
    """The provider's stored secret without fields its serializer does not declare."""
    secret = provider.secret.secret
    declared = declared_secret_fields(
        provider.provider, provider.secret.secret_type, secret
    )
    # secrets stored before the write path dropped undeclared fields may still hold them
    ignored = sorted(set(secret) - set(declared))
    if ignored:
        logger.warning(
            f"Ignoring undeclared fields in the secret of provider {provider.id}: "
            + ", ".join(ignored)
        )
    return declared


def get_prowler_provider_kwargs(
    provider: Provider, mutelist_processor: Processor | None = None
) -> dict:
    """Get the Prowler provider kwargs based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secret.
        mutelist_processor (Processor): The mutelist processor object containing the mutelist configuration.

    Returns:
        dict: The provider kwargs for the corresponding provider class.
    """
    prowler_provider_kwargs = declared_provider_secret(provider)
    if provider.provider == Provider.ProviderChoices.AZURE.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "subscription_ids": [provider.uid],
        }
    elif provider.provider == Provider.ProviderChoices.GCP.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "project_ids": [provider.uid],
        }
    elif provider.provider == Provider.ProviderChoices.KUBERNETES.value:
        _validate_kubernetes_secret(prowler_provider_kwargs)
        prowler_provider_kwargs = {**prowler_provider_kwargs, "context": provider.uid}
    elif provider.provider == Provider.ProviderChoices.GITHUB.value:
        if provider.uid:
            prowler_provider_kwargs = {
                **prowler_provider_kwargs,
                "organizations": [provider.uid],
            }
    elif provider.provider == Provider.ProviderChoices.IAC.value:
        # For IaC provider, uid contains the repository URL
        # Extract the access token if present in the secret
        prowler_provider_kwargs = {
            "scan_repository_url": provider.uid,
        }
        secret = declared_provider_secret(provider)
        if "access_token" in secret:
            prowler_provider_kwargs["oauth_app_token"] = secret["access_token"]
    elif provider.provider == Provider.ProviderChoices.MONGODBATLAS.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "atlas_organization_id": provider.uid,
        }
    elif provider.provider == Provider.ProviderChoices.CLOUDFLARE.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "filter_accounts": [provider.uid],
        }
    elif provider.provider == Provider.ProviderChoices.OPENSTACK.value:
        # clouds_yaml_content, clouds_yaml_cloud and provider_id are validated
        # in the provider itself, so it's not needed here.
        pass
    elif provider.provider == Provider.ProviderChoices.VERCEL.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "team_id": provider.uid,
        }
    elif provider.provider == Provider.ProviderChoices.OKTA.value:
        prowler_provider_kwargs = {
            **prowler_provider_kwargs,
            "okta_org_domain": provider.uid,
        }
    elif provider.provider == Provider.ProviderChoices.GOOGLEWORKSPACE.value:
        prowler_provider_kwargs = _googleworkspace_credentials(prowler_provider_kwargs)
    elif provider.provider == Provider.ProviderChoices.IMAGE.value:
        # Detect whether uid is a registry URL (e.g. "docker.io/andoniaf") or
        # a concrete image reference (e.g. "docker.io/andoniaf/myimage:latest").
        from prowler.providers.image.image_provider import ImageProvider

        if ImageProvider._is_registry_url(provider.uid):
            prowler_provider_kwargs = {
                "registry": provider.uid,
                **{k: v for k, v in prowler_provider_kwargs.items() if v},
            }
        else:
            prowler_provider_kwargs = {
                "images": [provider.uid],
                **{k: v for k, v in prowler_provider_kwargs.items() if v},
            }

    elif provider.provider == Provider.ProviderChoices.ORACLECLOUD.value:
        prowler_provider_kwargs = _normalize_oraclecloud_provider_kwargs(
            prowler_provider_kwargs
        )

    if mutelist_processor:
        mutelist_content = mutelist_processor.configuration.get("Mutelist", {})
        # IaC and Image providers don't support mutelist (both use Trivy's built-in logic)
        if mutelist_content and provider.provider not in (
            Provider.ProviderChoices.IAC.value,
            Provider.ProviderChoices.IMAGE.value,
        ):
            prowler_provider_kwargs["mutelist_content"] = mutelist_content

    return prowler_provider_kwargs


def _without_oraclecloud_key_file(secret: dict) -> dict:
    """Copy of an OCI secret without key_file, a worker path stored before it was refused."""
    return {key: value for key, value in secret.items() if key != "key_file"}


def _normalize_oraclecloud_provider_kwargs(secret: dict) -> dict:
    """Normalize external OCI secret fields into SDK provider kwargs."""
    prowler_provider_kwargs = _without_oraclecloud_key_file(secret)
    home_region = _oraclecloud_home_region(prowler_provider_kwargs.pop("region", None))
    if home_region:
        prowler_provider_kwargs["home_region"] = home_region

    return prowler_provider_kwargs


def _oraclecloud_home_region(region) -> str | None:
    """Return the stored OCI region as a home region, ignoring blank or non-string legacy values."""
    if isinstance(region, str) and region.strip():
        return region.strip()
    return None


def _normalize_oraclecloud_connection_test_kwargs(secret: dict) -> dict:
    """Normalize external OCI secret fields into test_connection kwargs."""
    from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider

    prowler_provider_kwargs = _without_oraclecloud_key_file(secret)
    home_region = _oraclecloud_home_region(prowler_provider_kwargs.pop("region", None))

    if (
        prowler_provider_kwargs.get("user")
        and prowler_provider_kwargs.get("fingerprint")
        and prowler_provider_kwargs.get("tenancy")
        and prowler_provider_kwargs.get("key_content")
    ):
        # Identity calls only succeed in a region the tenancy is subscribed to.
        prowler_provider_kwargs["region"] = (
            home_region or OraclecloudProvider._bootstrap_region
        )

    return prowler_provider_kwargs


def initialize_prowler_provider(
    provider: Provider,
    mutelist_processor: Processor | None = None,
) -> (
    AlibabacloudProvider
    | AwsProvider
    | AzureProvider
    | CloudflareProvider
    | GcpProvider
    | GithubProvider
    | GoogleworkspaceProvider
    | IacProvider
    | ImageProvider
    | KubernetesProvider
    | M365Provider
    | MongodbatlasProvider
    | OktaProvider
    | OpenstackProvider
    | OraclecloudProvider
    | VercelProvider
):
    """Initialize a Prowler provider instance based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.
        mutelist_processor (Processor): The mutelist processor object containing the mutelist configuration.

    Returns:
        AlibabacloudProvider | AwsProvider | AzureProvider | CloudflareProvider | GcpProvider | GithubProvider | GoogleworkspaceProvider | IacProvider | ImageProvider | KubernetesProvider | M365Provider | MongodbatlasProvider | OpenstackProvider | OraclecloudProvider: An instance of the corresponding provider class
            initialized with the provider's secrets.
    """
    prowler_provider = return_prowler_provider(provider)
    prowler_provider_kwargs = get_prowler_provider_kwargs(provider, mutelist_processor)
    return prowler_provider(**prowler_provider_kwargs)


def prowler_provider_connection_test(provider: Provider) -> Connection:
    """Test the connection to a Prowler provider based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        Connection: A connection object representing the result of the connection test for the specified provider.
    """
    prowler_provider = return_prowler_provider(provider)

    try:
        prowler_provider_kwargs = declared_provider_secret(provider)
    except Provider.secret.RelatedObjectDoesNotExist as secret_error:
        return Connection(is_connected=False, error=secret_error)
    except ValidationError:
        # A stored secret no serializer accepts is a failed connection, not a task error.
        return Connection(
            is_connected=False,
            error=Exception(STORED_SECRET_NOT_SUPPORTED_ERROR),
        )

    if provider.provider == Provider.ProviderChoices.KUBERNETES.value:
        # A rejected stored kubeconfig is a failed connection, not a task error.
        try:
            _validate_kubernetes_secret(prowler_provider_kwargs)
        except ValidationError as validation_error:
            return Connection(
                is_connected=False,
                error=Exception(validation_error.detail["kubeconfig_content"][0]),
            )

    # For IaC provider, construct the kwargs properly for test_connection
    if provider.provider == Provider.ProviderChoices.IAC.value:
        # Don't pass repository_url from secret, use scan_repository_url with the UID
        iac_test_kwargs = {
            "scan_repository_url": provider.uid,
            "raise_on_exception": False,
        }
        # Add access_token if present in the secret
        if "access_token" in prowler_provider_kwargs:
            iac_test_kwargs["access_token"] = prowler_provider_kwargs["access_token"]
        return prowler_provider.test_connection(**iac_test_kwargs)
    elif provider.provider == Provider.ProviderChoices.OPENSTACK.value:
        openstack_kwargs = {
            "clouds_yaml_content": prowler_provider_kwargs["clouds_yaml_content"],
            "clouds_yaml_cloud": prowler_provider_kwargs["clouds_yaml_cloud"],
            "provider_id": provider.uid,
            "raise_on_exception": False,
        }
        return prowler_provider.test_connection(**openstack_kwargs)
    elif provider.provider == Provider.ProviderChoices.VERCEL.value:
        vercel_kwargs = {
            **prowler_provider_kwargs,
            "team_id": provider.uid,
            "raise_on_exception": False,
        }
        return prowler_provider.test_connection(**vercel_kwargs)
    elif provider.provider == Provider.ProviderChoices.OKTA.value:
        okta_kwargs = {
            **prowler_provider_kwargs,
            "okta_org_domain": provider.uid,
            "provider_id": provider.uid,
            "raise_on_exception": False,
        }
        return prowler_provider.test_connection(**okta_kwargs)
    elif provider.provider == Provider.ProviderChoices.IMAGE.value:
        image_kwargs = {
            "image": provider.uid,
            "raise_on_exception": False,
        }
        if prowler_provider_kwargs.get("registry_username"):
            image_kwargs["registry_username"] = prowler_provider_kwargs[
                "registry_username"
            ]
        if prowler_provider_kwargs.get("registry_password"):
            image_kwargs["registry_password"] = prowler_provider_kwargs[
                "registry_password"
            ]
        if prowler_provider_kwargs.get("registry_token"):
            image_kwargs["registry_token"] = prowler_provider_kwargs["registry_token"]
        return prowler_provider.test_connection(**image_kwargs)
    elif provider.provider == Provider.ProviderChoices.ORACLECLOUD.value:
        oraclecloud_kwargs = _normalize_oraclecloud_connection_test_kwargs(
            prowler_provider_kwargs
        )
        return prowler_provider.test_connection(
            **oraclecloud_kwargs,
            provider_id=provider.uid,
            raise_on_exception=False,
        )
    elif provider.provider == Provider.ProviderChoices.GOOGLEWORKSPACE.value:
        return prowler_provider.test_connection(
            **_googleworkspace_credentials(prowler_provider_kwargs),
            provider_id=provider.uid,
            raise_on_exception=False,
        )
    else:
        return prowler_provider.test_connection(
            **prowler_provider_kwargs,
            provider_id=provider.uid,
            raise_on_exception=False,
        )


def prowler_integration_connection_test(integration: Integration) -> Connection:
    """Test the connection to a Prowler integration based on the given integration type.

    Args:
        integration (Integration): The integration object containing the integration type and associated credentials.

    Returns:
        Connection: A connection object representing the result of the connection test for the specified integration.
    """
    if integration.integration_type == Integration.IntegrationChoices.AMAZON_S3:
        return S3.test_connection(
            **integration.credentials,
            bucket_name=integration.configuration["bucket_name"],
            raise_on_exception=False,
        )
    # TODO: It is possible that we can unify the connection test for all integrations, but need refactoring
    # to avoid code duplication. Actually the AWS integrations are similar, so SecurityHub and S3 can be unified
    # making some changes in the SDK.
    elif (
        integration.integration_type == Integration.IntegrationChoices.AWS_SECURITY_HUB
    ):
        # Get the provider associated with this integration
        provider_relationship = integration.integrationproviderrelationship_set.first()
        if not provider_relationship:
            return Connection(
                is_connected=False, error="No provider associated with this integration"
            )

        credentials = (
            integration.credentials
            if integration.credentials
            else declared_provider_secret(provider_relationship.provider)
        )
        connection = SecurityHub.test_connection(
            aws_account_id=provider_relationship.provider.uid,
            raise_on_exception=False,
            **credentials,
        )

        # Only save regions if connection is successful
        if connection.is_connected:
            regions_status = dict.fromkeys(connection.enabled_regions, True)
            regions_status.update(dict.fromkeys(connection.disabled_regions, False))

            # Save regions information in the integration configuration
            integration.configuration["regions"] = regions_status
            integration.save()
        else:
            # Reset regions information if connection fails
            integration.configuration["regions"] = {}
            integration.save()

        return connection
    elif integration.integration_type == Integration.IntegrationChoices.JIRA:
        jira_connection = Jira.test_connection(
            **integration.credentials,
            raise_on_exception=False,
        )
        project_keys = jira_connection.projects if jira_connection.is_connected else {}
        issue_types = (
            jira_connection.issue_types if jira_connection.is_connected else {}
        )
        with rls_transaction(str(integration.tenant_id)):
            integration.configuration["projects"] = project_keys
            integration.configuration["issue_types"] = issue_types
            integration.save()
        return jira_connection
    elif integration.integration_type == Integration.IntegrationChoices.SLACK:
        pass
    else:
        raise ValueError(
            f"Integration type {integration.integration_type} not supported"
        )


def validate_invitation(
    invitation_token: str, email: str, raise_not_found=False
) -> Invitation:
    """
    Validates an invitation based on the provided token and email.

    This function attempts to retrieve an Invitation object using the given
    `invitation_token` and `email`. It performs several checks to ensure that
    the invitation is valid, not expired, and in the correct state for acceptance.

    Args:
        invitation_token (str): The token associated with the invitation.
        email (str): The email address associated with the invitation.
        raise_not_found (bool, optional): If True, raises a `NotFound` exception
            when the invitation is not found. If False, raises a `ValidationError`.
            Defaults to False.

    Returns:
        Invitation: The validated Invitation object.

    Raises:
        NotFound: If `raise_not_found` is True and the invitation does not exist.
        ValidationError: If the invitation does not exist and `raise_not_found`
            is False, or if the invitation is invalid or in an incorrect state.
        InvitationTokenExpiredException: If the invitation has expired.

    Notes:
        - This function uses the admin database connector to bypass RLS protection
          since the invitation may belong to a tenant the user is not a member of yet.
        - If the invitation has expired, its state is updated to EXPIRED, and an
          `InvitationTokenExpiredException` is raised.
        - Only invitations in the PENDING state can be accepted.

    Examples:
        invitation = validate_invitation("TOKEN123", "user@example.com")
    """
    try:
        # Admin DB connector is used to bypass RLS protection since the invitation belongs to a tenant the user
        # is not a member of yet
        invitation = Invitation.objects.using(MainRouter.admin_db).get(
            token=invitation_token, email__iexact=email
        )
    except Invitation.DoesNotExist:
        if raise_not_found:
            raise NotFound(detail="Invitation is not valid.")
        else:
            raise ValidationError({"invitation_token": "Invalid invitation code."})

    # Check if the invitation has expired
    if invitation.expires_at < datetime.now(UTC):
        invitation.state = Invitation.State.EXPIRED
        invitation.save(using=MainRouter.admin_db)
        raise InvitationTokenExpiredException()

    # Check the state of the invitation
    if invitation.state != Invitation.State.PENDING:
        raise ValidationError(
            {"invitation_token": "This invitation is no longer valid."}
        )

    return invitation


def accept_invitation_for_user(
    *, user, invitation_token: str, raise_not_found: bool = False
):
    with transaction.atomic(using=MainRouter.admin_db):
        invitation = validate_invitation(
            invitation_token, user.email, raise_not_found=raise_not_found
        )
        with rls_transaction(str(invitation.tenant_id), using=MainRouter.admin_db):
            membership, _ = Membership.objects.using(MainRouter.admin_db).get_or_create(
                user=user,
                tenant=invitation.tenant,
                defaults={"role": Membership.RoleChoices.MEMBER},
            )
            invitation_roles = Role.objects.using(MainRouter.admin_db).filter(
                invitations=invitation
            )
            for role in invitation_roles:
                UserRoleRelationship.objects.using(MainRouter.admin_db).get_or_create(
                    user=user,
                    role=role,
                    defaults={"tenant": invitation.tenant},
                )

            invitation.state = Invitation.State.ACCEPTED
            invitation.save(using=MainRouter.admin_db)

    return invitation, membership


# ToRemove after removing the fallback mechanism in /findings/metadata
def get_findings_metadata_no_aggregations(filtered_queryset):
    """Build the findings metadata from the values each finding already carries."""
    services, regions, resource_types, categories, groups = (set() for _ in range(5))

    # One pass over the findings: the distinct combinations are few, the findings are not
    combinations = (
        filtered_queryset.order_by()
        .values_list(
            "resource_services",
            "resource_regions",
            "resource_types",
            "categories",
            "resource_groups",
        )
        .distinct()
    )
    for (
        finding_services,
        finding_regions,
        finding_types,
        finding_categories,
        finding_group,
    ) in combinations:
        services.update(filter(None, finding_services or ()))
        regions.update(filter(None, finding_regions or ()))
        resource_types.update(filter(None, finding_types or ()))
        categories.update(filter(None, finding_categories or ()))
        if finding_group:
            groups.add(finding_group)

    result = {
        "services": sorted(services),
        "regions": sorted(regions),
        "resource_types": sorted(resource_types),
        "categories": sorted(categories),
        "groups": sorted(groups, key=str.casefold),
    }

    serializer = FindingMetadataSerializer(data=result)
    serializer.is_valid(raise_exception=True)

    return serializer.data


def get_findings_categories(filtered_queryset) -> list[str]:
    """Sorted categories of the findings, for scans without a category summary."""
    category_lists = (
        filtered_queryset.order_by().values_list("categories", flat=True).distinct()
    )
    return sorted(
        {
            category
            for categories in category_lists
            for category in categories or ()
            if category
        }
    )


def initialize_prowler_integration(integration: Integration) -> Jira:
    # TODO Refactor other integrations to use this function
    if integration.integration_type == Integration.IntegrationChoices.JIRA:
        try:
            return Jira(**integration.credentials)
        except JiraBasicAuthError as jira_auth_error:
            with rls_transaction(str(integration.tenant_id)):
                integration.configuration["projects"] = {}
                integration.connected = False
                integration.connection_last_checked_at = datetime.now(tz=UTC)
                integration.save()
            raise jira_auth_error
