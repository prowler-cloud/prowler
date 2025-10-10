"""OCI Identity Service Module."""

from datetime import datetime
from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Identity(OCIService):
    """OCI Identity Service class to retrieve users, groups, policies, and authentication settings."""

    def __init__(self, provider):
        """
        Initialize the Identity service.

        Args:
            provider: The OCI provider instance
        """
        super().__init__("identity", provider)
        self.users = []
        self.groups = []
        self.policies = []
        self.dynamic_groups = []
        self.domains = []
        self.password_policy = None
        self.root_compartment_resources = []
        self.active_non_root_compartments = []
        self.__threading_call__(self.__list_users__)
        self.__threading_call__(self.__list_groups__)
        self.__threading_call__(self.__list_policies__)
        self.__threading_call__(self.__list_dynamic_groups__)
        self.__threading_call__(self.__list_domains__)
        self.__threading_call__(self.__list_domain_password_policies__)
        self.__get_password_policy__()
        self.__threading_call__(self.__search_root_compartment_resources__)
        self.__threading_call__(self.__search_active_non_root_compartments__)

    def __get_client__(self, region):
        """
        Get the Identity client for a region.

        Args:
            region: Region key

        Returns:
            Identity client instance
        """
        client_region = self.regional_clients.get(region)
        if client_region:
            return self._create_oci_client(oci.identity.IdentityClient)
        return None

    def __list_users__(self, regional_client):
        """
        List all IAM users in the tenancy.

        Args:
            regional_client: Regional OCI client
        """
        try:
            # Identity is a global service, use home region
            if regional_client.region not in self.provider.identity.region:
                return

            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Listing Users...")

            for compartment in self.audited_compartments:
                try:
                    users = oci.pagination.list_call_get_all_results(
                        identity_client.list_users, compartment_id=compartment.id
                    ).data

                    for user in users:
                        if user.lifecycle_state != "DELETED":
                            # Get user API keys
                            api_keys = self.__list_user_api_keys__(
                                identity_client, user.id
                            )

                            # Get user auth tokens
                            auth_tokens = self.__list_user_auth_tokens__(
                                identity_client, user.id
                            )

                            # Get user customer secret keys
                            customer_secret_keys = (
                                self.__list_user_customer_secret_keys__(
                                    identity_client, user.id
                                )
                            )

                            # Get user database passwords
                            db_passwords = self.__list_user_db_passwords__(
                                identity_client, user.id
                            )

                            # Get user groups
                            user_groups = self.__get_user_groups__(
                                identity_client, user.id, compartment.id
                            )

                            # Check if user can use API keys
                            can_use_api_keys = (
                                user.capabilities.can_use_api_keys
                                if hasattr(user, "capabilities")
                                else True
                            )

                            # Check if console password is enabled
                            can_use_console_password = (
                                user.capabilities.can_use_console_password
                                if hasattr(user, "capabilities")
                                else False
                            )

                            # Check MFA status
                            is_mfa_activated = (
                                user.is_mfa_activated
                                if hasattr(user, "is_mfa_activated")
                                else False
                            )

                            self.users.append(
                                User(
                                    id=user.id,
                                    name=user.name,
                                    description=(
                                        user.description or ""
                                        if hasattr(user, "description")
                                        else ""
                                    ),
                                    email=(
                                        user.email or ""
                                        if hasattr(user, "email")
                                        else ""
                                    ),
                                    email_verified=(
                                        user.email_verified
                                        if hasattr(user, "email_verified")
                                        else False
                                    ),
                                    compartment_id=compartment.id,
                                    time_created=user.time_created,
                                    lifecycle_state=user.lifecycle_state,
                                    can_use_api_keys=can_use_api_keys,
                                    can_use_console_password=can_use_console_password,
                                    is_mfa_activated=is_mfa_activated,
                                    api_keys=api_keys,
                                    auth_tokens=auth_tokens,
                                    customer_secret_keys=customer_secret_keys,
                                    db_passwords=db_passwords,
                                    groups=user_groups,
                                    region=regional_client.region,
                                )
                            )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_user_api_keys__(self, identity_client, user_id):
        """List API keys for a user."""
        try:
            api_keys = []
            api_keys_data = oci.pagination.list_call_get_all_results(
                identity_client.list_api_keys, user_id=user_id
            ).data

            for key in api_keys_data:
                api_keys.append(
                    ApiKey(
                        key_id=key.key_id,
                        fingerprint=key.fingerprint,
                        lifecycle_state=key.lifecycle_state,
                        time_created=key.time_created,
                        user_id=user_id,
                    )
                )
            return api_keys
        except Exception as error:
            logger.error(
                f"Identity - Error listing API keys for user {user_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def __list_user_auth_tokens__(self, identity_client, user_id):
        """List auth tokens for a user."""
        try:
            auth_tokens = []
            auth_tokens_data = oci.pagination.list_call_get_all_results(
                identity_client.list_auth_tokens, user_id=user_id
            ).data

            for token in auth_tokens_data:
                auth_tokens.append(
                    AuthToken(
                        id=token.id,
                        description=(
                            token.description if hasattr(token, "description") else ""
                        ),
                        lifecycle_state=token.lifecycle_state,
                        time_created=token.time_created,
                        time_expires=(
                            token.time_expires
                            if hasattr(token, "time_expires")
                            else None
                        ),
                        user_id=user_id,
                    )
                )
            return auth_tokens
        except Exception as error:
            logger.error(
                f"Identity - Error listing auth tokens for user {user_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def __list_user_customer_secret_keys__(self, identity_client, user_id):
        """List customer secret keys for a user."""
        try:
            customer_secret_keys = []
            keys_data = oci.pagination.list_call_get_all_results(
                identity_client.list_customer_secret_keys, user_id=user_id
            ).data

            for key in keys_data:
                customer_secret_keys.append(
                    CustomerSecretKey(
                        id=key.id,
                        display_name=(
                            key.display_name if hasattr(key, "display_name") else ""
                        ),
                        lifecycle_state=key.lifecycle_state,
                        time_created=key.time_created,
                        time_expires=(
                            key.time_expires if hasattr(key, "time_expires") else None
                        ),
                        user_id=user_id,
                    )
                )
            return customer_secret_keys
        except Exception as error:
            logger.error(
                f"Identity - Error listing customer secret keys for user {user_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def __list_user_db_passwords__(self, identity_client, user_id):
        """List database passwords for a user."""
        try:
            db_passwords = []
            passwords_data = oci.pagination.list_call_get_all_results(
                identity_client.list_db_credentials, user_id=user_id
            ).data

            for password in passwords_data:
                db_passwords.append(
                    DbPassword(
                        id=password.id,
                        description=(
                            password.description
                            if hasattr(password, "description") and password.description
                            else None
                        ),
                        lifecycle_state=password.lifecycle_state,
                        time_created=password.time_created,
                        time_expires=(
                            password.time_expires
                            if hasattr(password, "time_expires")
                            else None
                        ),
                        user_id=user_id,
                    )
                )
            return db_passwords
        except Exception as error:
            logger.error(
                f"Identity - Error listing database passwords for user {user_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def __get_user_groups__(self, identity_client, user_id, compartment_id):
        """Get groups for a user."""
        try:
            groups = []
            user_group_memberships = oci.pagination.list_call_get_all_results(
                identity_client.list_user_group_memberships,
                compartment_id=compartment_id,
                user_id=user_id,
            ).data

            for membership in user_group_memberships:
                if membership.lifecycle_state != "DELETED":
                    groups.append(membership.group_id)
            return groups
        except Exception as error:
            logger.error(
                f"Identity - Error getting groups for user {user_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def __list_groups__(self, regional_client):
        """List all IAM groups."""
        try:
            if regional_client.region not in self.provider.identity.region:
                return

            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Listing Groups...")

            for compartment in self.audited_compartments:
                try:
                    groups = oci.pagination.list_call_get_all_results(
                        identity_client.list_groups, compartment_id=compartment.id
                    ).data

                    for group in groups:
                        if group.lifecycle_state != "DELETED":
                            self.groups.append(
                                Group(
                                    id=group.id,
                                    name=group.name,
                                    description=(
                                        group.description
                                        if hasattr(group, "description")
                                        else ""
                                    ),
                                    compartment_id=compartment.id,
                                    time_created=group.time_created,
                                    lifecycle_state=group.lifecycle_state,
                                    region=regional_client.region,
                                )
                            )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_policies__(self, regional_client):
        """List all IAM policies."""
        try:
            if regional_client.region not in self.provider.identity.region:
                return

            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Listing Policies...")

            for compartment in self.audited_compartments:
                try:
                    policies = oci.pagination.list_call_get_all_results(
                        identity_client.list_policies, compartment_id=compartment.id
                    ).data

                    for policy in policies:
                        if policy.lifecycle_state != "DELETED":
                            self.policies.append(
                                Policy(
                                    id=policy.id,
                                    name=policy.name,
                                    description=(
                                        policy.description
                                        if hasattr(policy, "description")
                                        else ""
                                    ),
                                    compartment_id=compartment.id,
                                    statements=policy.statements,
                                    time_created=policy.time_created,
                                    lifecycle_state=policy.lifecycle_state,
                                    region=regional_client.region,
                                )
                            )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_dynamic_groups__(self, regional_client):
        """List all dynamic groups in the tenancy."""
        try:
            # Dynamic groups are only in the home region
            if regional_client.region not in self.provider.identity.region:
                return

            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Listing Dynamic Groups...")

            try:
                dynamic_groups = oci.pagination.list_call_get_all_results(
                    identity_client.list_dynamic_groups,
                    compartment_id=self.audited_tenancy,
                ).data

                for dynamic_group in dynamic_groups:
                    if dynamic_group.lifecycle_state != "DELETED":
                        self.dynamic_groups.append(
                            DynamicGroup(
                                id=dynamic_group.id,
                                name=dynamic_group.name,
                                description=(
                                    dynamic_group.description or ""
                                    if hasattr(dynamic_group, "description")
                                    else ""
                                ),
                                compartment_id=self.audited_tenancy,
                                matching_rule=(
                                    dynamic_group.matching_rule
                                    if hasattr(dynamic_group, "matching_rule")
                                    else ""
                                ),
                                time_created=dynamic_group.time_created,
                                lifecycle_state=dynamic_group.lifecycle_state,
                                region=regional_client.region,
                            )
                        )
            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_domains__(self, regional_client):
        """List all identity domains."""
        try:
            # Domains are only in the home region
            if regional_client.region not in self.provider.identity.region:
                return

            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Listing Identity Domains...")

            try:
                # List all domains in the tenancy
                for compartment in self.audited_compartments:
                    domains = oci.pagination.list_call_get_all_results(
                        identity_client.list_domains,
                        compartment_id=compartment.id,
                        lifecycle_state="ACTIVE",
                    ).data

                    for domain in domains:
                        self.domains.append(
                            IdentityDomain(
                                id=domain.id,
                                display_name=domain.display_name,
                                description=domain.description or "",
                                url=domain.url,
                                home_region=domain.home_region,
                                compartment_id=compartment.id,
                                lifecycle_state=domain.lifecycle_state,
                                time_created=domain.time_created,
                                region=regional_client.region,
                                password_policies=[],
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_domain_password_policies__(self, regional_client):
        """List password policies for all identity domains."""
        try:
            # Password policies are only in the home region
            if regional_client.region not in self.provider.identity.region:
                return

            logger.info("Identity - Listing Domain Password Policies...")

            for domain in self.domains:
                try:
                    # Create Identity Domains client for this domain
                    if self.session_signer:
                        domain_client = oci.identity_domains.IdentityDomainsClient(
                            config=self.session_config,
                            signer=self.session_signer,
                            service_endpoint=domain.url,
                        )
                    else:
                        domain_client = oci.identity_domains.IdentityDomainsClient(
                            config=self.session_config, service_endpoint=domain.url
                        )

                    # List password policies in the domain
                    policies_response = domain_client.list_password_policies()

                    for policy in policies_response.data.resources:
                        domain.password_policies.append(
                            DomainPasswordPolicy(
                                id=policy.id,
                                name=policy.name,
                                description=policy.description or "",
                                min_length=policy.min_length,
                                password_expires_after=policy.password_expires_after,
                                num_passwords_in_history=policy.num_passwords_in_history,
                                password_expire_warning=policy.password_expire_warning,
                                min_password_age=policy.min_password_age,
                            )
                        )

                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_password_policy__(self):
        """Get the password policy for the tenancy."""
        try:
            identity_client = self._create_oci_client(oci.identity.IdentityClient)

            logger.info("Identity - Getting Password Policy...")

            password_policy = identity_client.get_authentication_policy(
                compartment_id=self.audited_tenancy
            ).data.password_policy

            self.password_policy = PasswordPolicy(
                is_lowercase_characters_required=password_policy.is_lowercase_characters_required,
                is_uppercase_characters_required=password_policy.is_uppercase_characters_required,
                is_numeric_characters_required=password_policy.is_numeric_characters_required,
                is_special_characters_required=password_policy.is_special_characters_required,
                is_username_containment_allowed=password_policy.is_username_containment_allowed,
                minimum_password_length=password_policy.minimum_password_length,
            )
        except Exception as error:
            logger.error(
                f"Identity - Error getting password policy: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __search_root_compartment_resources__(self, regional_client):
        """Search for resources in the root compartment using OCI Resource Search."""
        try:
            # Search is a global service, use home region
            if regional_client.region not in self.provider.identity.region:
                return

            logger.info("Identity - Searching for resources in root compartment...")

            # Create search client using the helper method for proper authentication
            search_client = self._create_oci_client(
                oci.resource_search.ResourceSearchClient
            )

            # Query to search for resources in root compartment
            # This covers VCN, instances, boot volumes, volumes, file systems, buckets,
            # autonomous databases, databases, and DB systems
            query_text = f"query VCN, instance, bootvolume, volume, filesystem, bucket, autonomousdatabase, database, dbsystem resources where compartmentId = '{self.audited_tenancy}'"

            # Execute structured search
            search_response = search_client.search_resources(
                search_details=oci.resource_search.models.StructuredSearchDetails(
                    type="Structured", query=query_text
                )
            )

            if search_response.data and search_response.data.items:
                for resource in search_response.data.items:
                    self.root_compartment_resources.append(
                        RootCompartmentResource(
                            display_name=resource.display_name or "",
                            identifier=resource.identifier,
                            resource_type=resource.resource_type,
                            compartment_id=resource.compartment_id,
                            availability_domain=getattr(
                                resource, "availability_domain", None
                            ),
                            lifecycle_state=getattr(resource, "lifecycle_state", None),
                            time_created=getattr(resource, "time_created", None),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __search_active_non_root_compartments__(self, regional_client):
        """Search for active non-root compartments using OCI Resource Search."""
        try:
            # Search is a global service, use home region
            if regional_client.region not in self.provider.identity.region:
                return

            logger.info("Identity - Searching for active non-root compartments...")

            # Create search client using the helper method for proper authentication
            search_client = self._create_oci_client(
                oci.resource_search.ResourceSearchClient
            )

            # Query to search for active compartments in the tenancy (excluding root)
            query_text = f"query compartment resources where (compartmentId = '{self.audited_tenancy}' && lifecycleState = 'ACTIVE')"

            # Execute structured search
            search_response = search_client.search_resources(
                search_details=oci.resource_search.models.StructuredSearchDetails(
                    type="Structured", query=query_text
                )
            )

            if search_response.data and search_response.data.items:
                for compartment in search_response.data.items:
                    self.active_non_root_compartments.append(
                        ActiveCompartment(
                            display_name=compartment.display_name or "",
                            identifier=compartment.identifier,
                            compartment_id=compartment.compartment_id,
                            lifecycle_state=getattr(
                                compartment, "lifecycle_state", None
                            ),
                            time_created=getattr(compartment, "time_created", None),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class ApiKey(BaseModel):
    """OCI API Key model."""

    key_id: str
    fingerprint: str
    lifecycle_state: str
    time_created: datetime
    user_id: str


class AuthToken(BaseModel):
    """OCI Auth Token model."""

    id: str
    description: str
    lifecycle_state: str
    time_created: datetime
    time_expires: Optional[datetime]
    user_id: str


class CustomerSecretKey(BaseModel):
    """OCI Customer Secret Key model."""

    id: str
    display_name: str
    lifecycle_state: str
    time_created: datetime
    time_expires: Optional[datetime]
    user_id: str


class DbPassword(BaseModel):
    """OCI Database Password model."""

    id: str
    description: Optional[str]
    lifecycle_state: str
    time_created: datetime
    time_expires: Optional[datetime]
    user_id: str


class User(BaseModel):
    """OCI IAM User model."""

    id: str
    name: str
    description: str
    email: str
    email_verified: bool
    compartment_id: str
    time_created: datetime
    lifecycle_state: str
    can_use_api_keys: bool
    can_use_console_password: bool
    is_mfa_activated: bool
    api_keys: list[ApiKey] = []
    auth_tokens: list[AuthToken] = []
    customer_secret_keys: list[CustomerSecretKey] = []
    db_passwords: list[DbPassword] = []
    groups: list[str] = []
    region: str


class Group(BaseModel):
    """OCI IAM Group model."""

    id: str
    name: str
    description: str
    compartment_id: str
    time_created: datetime
    lifecycle_state: str
    region: str


class Policy(BaseModel):
    """OCI IAM Policy model."""

    id: str
    name: str
    description: str
    compartment_id: str
    statements: list[str]
    time_created: datetime
    lifecycle_state: str
    region: str


class PasswordPolicy(BaseModel):
    """OCI Password Policy model."""

    is_lowercase_characters_required: bool
    is_uppercase_characters_required: bool
    is_numeric_characters_required: bool
    is_special_characters_required: bool
    is_username_containment_allowed: bool
    minimum_password_length: int


class AuthenticationPolicy(BaseModel):
    """OCI Authentication Policy model."""

    compartment_id: str
    password_policy: Optional[PasswordPolicy]


class DynamicGroup(BaseModel):
    """OCI Dynamic Group model."""

    id: str
    name: str
    description: str
    compartment_id: str
    matching_rule: str
    time_created: datetime
    lifecycle_state: str
    region: str


class DomainPasswordPolicy(BaseModel):
    """OCI Identity Domain Password Policy model."""

    id: str
    name: str
    description: str
    min_length: Optional[int]
    password_expires_after: Optional[int]
    num_passwords_in_history: Optional[int]
    password_expire_warning: Optional[int]
    min_password_age: Optional[int]


class IdentityDomain(BaseModel):
    """OCI Identity Domain model."""

    id: str
    display_name: str
    description: str
    url: str
    home_region: str
    compartment_id: str
    lifecycle_state: str
    time_created: datetime
    region: str
    password_policies: list[DomainPasswordPolicy]


class RootCompartmentResource(BaseModel):
    """OCI Resource found in root compartment via search."""

    display_name: str
    identifier: str
    resource_type: str
    compartment_id: str
    availability_domain: Optional[str]
    lifecycle_state: Optional[str]
    time_created: Optional[datetime]


class ActiveCompartment(BaseModel):
    """OCI Active non-root compartment found via search."""

    display_name: str
    identifier: str
    compartment_id: str
    lifecycle_state: Optional[str]
    time_created: Optional[datetime]
