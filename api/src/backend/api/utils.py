from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Subquery
from rest_framework.exceptions import NotFound, ValidationError

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.exceptions import InvitationTokenExpiredException
from api.models import Integration, Invitation, Processor, Provider, Resource
from api.v1.serializers import FindingMetadataSerializer
from prowler.lib.outputs.jira.jira import Jira, JiraBasicAuthError
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from prowler.providers.common.models import Connection

if TYPE_CHECKING:
    from prowler.providers.alibabacloud.alibabacloud_provider import (
        AlibabacloudProvider,
    )
    from prowler.providers.aws.aws_provider import AwsProvider
    from prowler.providers.azure.azure_provider import AzureProvider
    from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
    from prowler.providers.gcp.gcp_provider import GcpProvider
    from prowler.providers.github.github_provider import GithubProvider
    from prowler.providers.iac.iac_provider import IacProvider
    from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
    from prowler.providers.m365.m365_provider import M365Provider
    from prowler.providers.mongodbatlas.mongodbatlas_provider import (
        MongodbatlasProvider,
    )
    from prowler.providers.openstack.openstack_provider import OpenstackProvider
    from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider


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
    | IacProvider
    | KubernetesProvider
    | M365Provider
    | MongodbatlasProvider
    | OpenstackProvider
    | OraclecloudProvider
):
    """Return the Prowler provider class based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.

    Returns:
        AlibabacloudProvider | AwsProvider | AzureProvider | CloudflareProvider | GcpProvider | GithubProvider | IacProvider | KubernetesProvider | M365Provider | MongodbatlasProvider | OpenstackProvider | OraclecloudProvider: The corresponding provider class.

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
        case _:
            raise ValueError(f"Provider type {provider.provider} not supported")
    return prowler_provider


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
    prowler_provider_kwargs = provider.secret.secret
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
        if "access_token" in provider.secret.secret:
            prowler_provider_kwargs["oauth_app_token"] = provider.secret.secret[
                "access_token"
            ]
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

    if mutelist_processor:
        mutelist_content = mutelist_processor.configuration.get("Mutelist", {})
        # IaC provider doesn't support mutelist (uses Trivy's built-in logic)
        if mutelist_content and provider.provider != Provider.ProviderChoices.IAC.value:
            prowler_provider_kwargs["mutelist_content"] = mutelist_content

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
    | IacProvider
    | KubernetesProvider
    | M365Provider
    | MongodbatlasProvider
    | OpenstackProvider
    | OraclecloudProvider
):
    """Initialize a Prowler provider instance based on the given provider type.

    Args:
        provider (Provider): The provider object containing the provider type and associated secrets.
        mutelist_processor (Processor): The mutelist processor object containing the mutelist configuration.

    Returns:
        AlibabacloudProvider | AwsProvider | AzureProvider | CloudflareProvider | GcpProvider | GithubProvider | IacProvider | KubernetesProvider | M365Provider | MongodbatlasProvider | OpenstackProvider | OraclecloudProvider: An instance of the corresponding provider class
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
        prowler_provider_kwargs = provider.secret.secret
    except Provider.secret.RelatedObjectDoesNotExist as secret_error:
        return Connection(is_connected=False, error=secret_error)

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
            else provider_relationship.provider.secret.secret
        )
        connection = SecurityHub.test_connection(
            aws_account_id=provider_relationship.provider.uid,
            raise_on_exception=False,
            **credentials,
        )

        # Only save regions if connection is successful
        if connection.is_connected:
            regions_status = {r: True for r in connection.enabled_regions}
            regions_status.update({r: False for r in connection.disabled_regions})

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
        with rls_transaction(str(integration.tenant_id)):
            integration.configuration["projects"] = project_keys
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
    if invitation.expires_at < datetime.now(timezone.utc):
        invitation.state = Invitation.State.EXPIRED
        invitation.save(using=MainRouter.admin_db)
        raise InvitationTokenExpiredException()

    # Check the state of the invitation
    if invitation.state != Invitation.State.PENDING:
        raise ValidationError(
            {"invitation_token": "This invitation is no longer valid."}
        )

    return invitation


# ToRemove after removing the fallback mechanism in /findings/metadata
def get_findings_metadata_no_aggregations(tenant_id: str, filtered_queryset):
    filtered_ids = filtered_queryset.order_by().values("id")

    relevant_resources = Resource.all_objects.filter(
        tenant_id=tenant_id, findings__id__in=Subquery(filtered_ids)
    ).only("service", "region", "type")

    aggregation = relevant_resources.aggregate(
        services=ArrayAgg("service", flat=True),
        regions=ArrayAgg("region", flat=True),
        resource_types=ArrayAgg("type", flat=True),
    )

    services = sorted(set(aggregation["services"] or []))
    regions = sorted({region for region in aggregation["regions"] or [] if region})
    resource_types = sorted(set(aggregation["resource_types"] or []))

    # Aggregate categories from findings
    categories_set = set()
    for categories_list in filtered_queryset.values_list("categories", flat=True):
        if categories_list:
            categories_set.update(categories_list)
    categories = sorted(categories_set)

    # Aggregate groups from findings
    groups = list(
        filtered_queryset.exclude(resource_groups__isnull=True)
        .exclude(resource_groups__exact="")
        .values_list("resource_groups", flat=True)
        .distinct()
        .order_by("resource_groups")
    )

    result = {
        "services": services,
        "regions": regions,
        "resource_types": resource_types,
        "categories": categories,
        "groups": groups,
    }

    serializer = FindingMetadataSerializer(data=result)
    serializer.is_valid(raise_exception=True)

    return serializer.data


def initialize_prowler_integration(integration: Integration) -> Jira:
    # TODO Refactor other integrations to use this function
    if integration.integration_type == Integration.IntegrationChoices.JIRA:
        try:
            return Jira(**integration.credentials)
        except JiraBasicAuthError as jira_auth_error:
            with rls_transaction(str(integration.tenant_id)):
                integration.configuration["projects"] = {}
                integration.connected = False
                integration.connection_last_checked_at = datetime.now(tz=timezone.utc)
                integration.save()
            raise jira_auth_error
