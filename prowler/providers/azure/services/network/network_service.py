import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network import models as network_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService

WAF_POLICY_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Network/ApplicationGatewayWebApplicationFirewallPolicies"
    r"/(?P<name>[^/]+)$",
    re.IGNORECASE,
)

# Whether a WAF policy in each state, matched without regard to case, is enabled.
WAF_POLICY_STATES = {"enabled": True, "disabled": False}


class Network(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(NetworkManagementClient, provider)
        self.security_groups = self._get_security_groups()
        self.bastion_hosts = self._get_bastion_hosts()
        self.network_watchers = self._get_network_watchers()
        self.public_ip_addresses = self._get_public_ip_addresses()
        self.virtual_networks = self._get_virtual_networks()
        # Subscriptions whose WAF policies could not be listed completely.
        self.waf_policies_lookup_failed: set[str] = set()
        self.waf_policies = self._get_waf_policies()
        # Casefolded IDs of WAF policies outside that listing that could not be read.
        self.waf_policy_reads_failed: set[str] = set()
        # Subscriptions whose Application Gateways could not be listed completely.
        self.application_gateways_lookup_failed: set[str] = set()
        self.application_gateways = self._get_application_gateways()

    def _get_security_groups(self):
        logger.info("Network - Getting Network Security Groups...")
        security_groups = {}
        for subscription, client in self.clients.items():
            try:
                security_groups_list = self.list_with_rg_scope(
                    subscription,
                    client.network_security_groups.list_all,
                    client.network_security_groups.list,
                )

                security_groups.update({subscription: []})
                for security_group in security_groups_list:
                    security_groups[subscription].append(
                        SecurityGroup(
                            id=security_group.id,
                            name=security_group.name,
                            location=security_group.location,
                            security_rules=[
                                SecurityRule(
                                    id=rule.id,
                                    name=rule.name,
                                    destination_port_range=getattr(
                                        rule, "destination_port_range", ""
                                    ),
                                    protocol=getattr(rule, "protocol", ""),
                                    source_address_prefix=getattr(
                                        rule, "source_address_prefix", ""
                                    ),
                                    access=getattr(rule, "access", "Allow"),
                                    direction=getattr(rule, "direction", "Inbound"),
                                )
                                for rule in getattr(
                                    security_group, "security_rules", []
                                )
                            ],
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_groups

    def _get_network_watchers(self):
        logger.info("Network - Getting Network Watchers...")
        network_watchers = {}
        for subscription, client in self.clients.items():
            try:
                network_watchers_list = client.network_watchers.list_all()
                network_watchers.update({subscription: []})
                for network_watcher in network_watchers_list:
                    flow_logs = self._get_flow_logs(
                        subscription, network_watcher.name, network_watcher.id
                    )
                    network_watchers[subscription].append(
                        NetworkWatcher(
                            id=network_watcher.id,
                            name=network_watcher.name,
                            location=network_watcher.location,
                            flow_logs=[
                                FlowLog(
                                    id=flow_log.id,
                                    name=flow_log.name,
                                    enabled=flow_log.enabled,
                                    target_resource_id=getattr(
                                        flow_log, "target_resource_id", None
                                    ),
                                    retention_policy=RetentionPolicy(
                                        enabled=(
                                            flow_log.retention_policy.enabled
                                            if flow_log.retention_policy
                                            else False
                                        ),
                                        days=(
                                            flow_log.retention_policy.days
                                            if flow_log.retention_policy
                                            else 0
                                        ),
                                    ),
                                    traffic_analytics_enabled=bool(
                                        getattr(
                                            getattr(
                                                getattr(
                                                    flow_log,
                                                    "flow_analytics_configuration",
                                                    None,
                                                ),
                                                "network_watcher_flow_analytics_configuration",
                                                None,
                                            ),
                                            "enabled",
                                            False,
                                        )
                                    ),
                                    workspace_resource_id=getattr(
                                        getattr(
                                            getattr(
                                                flow_log,
                                                "flow_analytics_configuration",
                                                None,
                                            ),
                                            "network_watcher_flow_analytics_configuration",
                                            None,
                                        ),
                                        "workspace_resource_id",
                                        None,
                                    ),
                                )
                                for flow_log in flow_logs
                            ],
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return network_watchers

    def _get_flow_logs(self, subscription, network_watcher_name, network_watcher_id):
        logger.info("Network - Getting Flow Logs...")
        client = self.clients[subscription]
        match = re.search(r"/resourceGroups/(?P<rg>[^/]+)/", network_watcher_id)
        if not match:
            logger.error(
                f"Could not extract resource group from ID: {network_watcher_id}"
            )
            return []
        resource_group = match.group("rg")
        try:
            flow_logs = client.flow_logs.list(resource_group, network_watcher_name)
            return flow_logs
        except ResourceNotFoundError as error:
            logger.warning(
                f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []
        except Exception as error:
            logger.error(
                f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def _get_bastion_hosts(self):
        logger.info("Network - Getting Bastion Hosts...")
        bastion_hosts = {}
        for subscription, client in self.clients.items():
            try:
                bastion_hosts_list = self.list_with_rg_scope(
                    subscription,
                    client.bastion_hosts.list,
                    client.bastion_hosts.list_by_resource_group,
                )

                bastion_hosts.update({subscription: []})
                for bastion_host in bastion_hosts_list:
                    bastion_hosts[subscription].append(
                        BastionHost(
                            id=bastion_host.id,
                            name=bastion_host.name,
                            location=bastion_host.location,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return bastion_hosts

    def _get_public_ip_addresses(self):
        logger.info("Network - Getting Public IP Addresses...")
        public_ip_addresses = {}
        for subscription, client in self.clients.items():
            try:
                public_ip_addresses_list = self.list_with_rg_scope(
                    subscription,
                    client.public_ip_addresses.list_all,
                    client.public_ip_addresses.list,
                )

                public_ip_addresses.update({subscription: []})
                for public_ip_address in public_ip_addresses_list:
                    public_ip_addresses[subscription].append(
                        PublicIp(
                            id=public_ip_address.id,
                            name=public_ip_address.name,
                            location=public_ip_address.location,
                            ip_address=public_ip_address.ip_address,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return public_ip_addresses

    def _get_virtual_networks(self):
        logger.info("Network - Getting Virtual Networks...")
        virtual_networks = {}
        for subscription_id, client in self.clients.items():
            try:
                virtual_networks[subscription_id] = []
                virtual_networks_list = self.list_with_rg_scope(
                    subscription_id,
                    client.virtual_networks.list_all,
                    client.virtual_networks.list,
                )
                for virtual_network in virtual_networks_list:
                    subnets = []
                    for subnet in getattr(virtual_network, "subnets", []) or []:
                        nsg = getattr(subnet, "network_security_group", None)
                        subnets.append(
                            VNetSubnet(
                                id=subnet.id,
                                name=subnet.name,
                                nsg_id=getattr(nsg, "id", None) if nsg else None,
                            )
                        )
                    virtual_networks[subscription_id].append(
                        VirtualNetwork(
                            id=virtual_network.id,
                            name=virtual_network.name,
                            location=virtual_network.location,
                            enable_ddos_protection=getattr(
                                virtual_network, "enable_ddos_protection", False
                            ),
                            subnets=subnets,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return virtual_networks

    def _get_waf_policies(self) -> dict:
        """Get the Application Gateway WAF policies of every subscription.

        A subscription whose WAF policies cannot be listed or mapped completely
        is added to waf_policies_lookup_failed. A policy that cannot be mapped
        is logged and skipped, so the others are still collected.

        Returns:
            A dictionary keyed by subscription ID whose values map each WAF
            policy ID to a WafPolicy model.
        """
        logger.info("Network - Getting Application Gateway WAF policies...")
        waf_policies = {}
        for subscription_id, client in self.clients.items():
            try:
                waf_policies[subscription_id] = {}
                waf_policies_list = self.list_with_rg_scope(
                    subscription_id,
                    client.web_application_firewall_policies.list_all,
                    mark_failed_lookups(
                        client.web_application_firewall_policies.list,
                        self.waf_policies_lookup_failed,
                        subscription_id,
                    ),
                )
                for waf_policy in waf_policies_list:
                    try:
                        policy = build_waf_policy(waf_policy)
                        waf_policies[subscription_id][policy.id] = policy
                    except Exception as error:
                        self.waf_policies_lookup_failed.add(subscription_id)
                        logger.error(
                            f"Subscription ID: {subscription_id} -- WAF policy: {getattr(waf_policy, 'id', None)} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
            except Exception as error:
                self.waf_policies_lookup_failed.add(subscription_id)
                logger.error(
                    f"Subscription ID: {subscription_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return waf_policies

    def _get_application_gateways(self) -> dict:
        """Get the Application Gateways of every subscription.

        The state of each gateway's WAF policy comes from the policies that
        _get_waf_policies collected, so that method must run first, and a
        policy that was not listed is read once by its ID. A subscription whose
        gateways cannot be listed or mapped completely is added to
        application_gateways_lookup_failed. A gateway that cannot be mapped is
        logged and skipped, so the others are still collected.

        Returns:
            A dictionary keyed by subscription ID whose values map each
            Application Gateway ID to an ApplicationGateway model.
        """
        logger.info("Network - Getting Application Gateways...")
        application_gateways = {}
        for subscription_id, client in self.clients.items():
            try:
                application_gateways[subscription_id] = {}
                application_gateways_list = self.list_with_rg_scope(
                    subscription_id,
                    client.application_gateways.list_all,
                    mark_failed_lookups(
                        client.application_gateways.list,
                        self.application_gateways_lookup_failed,
                        subscription_id,
                    ),
                )
                listed_policies = {
                    policy_id.casefold(): policy
                    for policy_id, policy in self.waf_policies.get(
                        subscription_id, {}
                    ).items()
                }
                policy_states = {}
                for application_gateway in application_gateways_list:
                    try:
                        gateway = build_application_gateway(application_gateway)
                        if gateway.firewall_policy_id:
                            key = gateway.firewall_policy_id.casefold()
                            if key not in policy_states:
                                policy_states[key] = get_waf_policy_enabled(
                                    client,
                                    subscription_id,
                                    gateway.firewall_policy_id,
                                    listed_policies,
                                    self.waf_policy_reads_failed,
                                )
                            gateway.firewall_policy_enabled = policy_states[key]
                        application_gateways[subscription_id][gateway.id] = gateway
                    except Exception as error:
                        self.application_gateways_lookup_failed.add(subscription_id)
                        logger.error(
                            f"Subscription ID: {subscription_id} -- Application Gateway: {getattr(application_gateway, 'id', None)} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
            except Exception as error:
                self.application_gateways_lookup_failed.add(subscription_id)
                logger.error(
                    f"Subscription ID: {subscription_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return application_gateways


@dataclass
class BastionHost:
    id: str
    name: str
    location: str


@dataclass
class RetentionPolicy:
    enabled: bool = False
    days: int = 0


@dataclass
class FlowLog:
    id: str
    name: str
    enabled: bool
    retention_policy: RetentionPolicy
    target_resource_id: Optional[str] = None
    traffic_analytics_enabled: bool = False
    workspace_resource_id: Optional[str] = None


@dataclass
class NetworkWatcher:
    id: str
    name: str
    location: str
    flow_logs: List[FlowLog]


@dataclass
class SecurityRule:
    id: str
    name: str
    destination_port_range: Optional[str]
    protocol: Optional[str]
    source_address_prefix: Optional[str]
    access: Optional[str]
    direction: Optional[str]


@dataclass
class SecurityGroup:
    id: str
    name: str
    location: str
    security_rules: List[SecurityRule]


@dataclass
class PublicIp:
    id: str
    name: str
    location: str
    ip_address: str


@dataclass
class VNetSubnet:
    id: str
    name: str
    nsg_id: Optional[str] = None


@dataclass
class VirtualNetwork:
    id: str
    name: str
    location: str
    enable_ddos_protection: bool = False
    subnets: List[VNetSubnet] = None

    def __post_init__(self):
        if self.subnets is None:
            self.subnets = []


class ApplicationGateway(BaseModel):
    """Application Gateway settings used by the network checks."""

    id: str
    name: str
    location: str
    firewall_policy_id: Optional[str] = None
    firewall_policy_enabled: Optional[bool] = None
    waf_configuration_enabled: bool = False
    http2_enabled: bool = False


class WafPolicy(BaseModel):
    """Application Gateway WAF policy settings used by the network checks."""

    id: str
    name: str
    location: str
    state: Optional[str] = None


def mark_failed_lookups(
    list_by_rg_fn: Callable[..., Iterable[object]],
    lookup_failed: set[str],
    subscription_id: str,
) -> Callable[..., List[object]]:
    """Wrap a per-resource-group list call so that a failure marks the subscription.

    list_with_rg_scope logs and skips a resource group whose list call fails,
    so the subscription is recorded here before the error reaches it. A
    resource group that no longer exists (not found) is not a failed lookup.

    Args:
        list_by_rg_fn: Azure SDK list operation for one resource group.
        lookup_failed: Set of subscriptions whose listing was incomplete.
        subscription_id: Subscription the list call belongs to.

    Returns:
        A callable with the same keyword arguments as list_by_rg_fn.
    """

    def list_by_resource_group(**kwargs) -> List[object]:
        try:
            return list(list_by_rg_fn(**kwargs))
        except ResourceNotFoundError:
            raise
        except Exception:
            lookup_failed.add(subscription_id)
            raise

    return list_by_resource_group


def build_application_gateway(
    application_gateway: network_models.ApplicationGateway,
) -> ApplicationGateway:
    """Convert an Azure SDK Application Gateway into an ApplicationGateway model.

    The state of the associated WAF policy is not part of the gateway, so
    firewall_policy_enabled is set afterwards from get_waf_policy_enabled.

    Args:
        application_gateway: ApplicationGateway from the Azure SDK.

    Returns:
        The ApplicationGateway model.
    """
    waf_configuration = getattr(
        application_gateway, "web_application_firewall_configuration", None
    )
    return ApplicationGateway(
        id=application_gateway.id,
        name=application_gateway.name,
        location=application_gateway.location,
        firewall_policy_id=getattr(
            getattr(application_gateway, "firewall_policy", None), "id", None
        ),
        waf_configuration_enabled=bool(getattr(waf_configuration, "enabled", False)),
        http2_enabled=bool(getattr(application_gateway, "enable_http2", False)),
    )


def build_waf_policy(
    waf_policy: network_models.WebApplicationFirewallPolicy,
) -> WafPolicy:
    """Convert an Azure SDK WAF policy into a WafPolicy model.

    Args:
        waf_policy: WebApplicationFirewallPolicy from the Azure SDK.

    Returns:
        The WafPolicy model.
    """
    settings = getattr(waf_policy, "policy_settings", None)
    return WafPolicy(
        id=waf_policy.id,
        name=waf_policy.name,
        location=waf_policy.location,
        state=getattr(settings, "state", None),
    )


def read_waf_policy(
    client: NetworkManagementClient,
    subscription_id: str,
    policy_id: str,
    reads_failed: set[str],
) -> Optional[WafPolicy]:
    """Read one Application Gateway WAF policy by its resource ID.

    A read that fails for any reason other than the policy not existing adds
    the casefolded policy ID to reads_failed. Every failure is logged.

    Args:
        client: NetworkManagementClient of the gateway's subscription.
        subscription_id: Subscription of the gateway.
        policy_id: Resource ID of the WAF policy.
        reads_failed: Casefolded IDs of WAF policies that could not be read.

    Returns:
        The WafPolicy model, or None when the ID is not a WAF policy ID in the
        subscription or the policy cannot be read.
    """
    match = WAF_POLICY_ID.match(policy_id)
    if (
        not match
        or match.group("subscription").casefold() != subscription_id.casefold()
    ):
        logger.warning(
            f"Subscription ID: {subscription_id} -- WAF policy: {policy_id} -- not an Application Gateway WAF policy ID in this subscription, so the policy was not read."
        )
        return None
    try:
        return build_waf_policy(
            client.web_application_firewall_policies.get(
                resource_group_name=match.group("resource_group"),
                policy_name=match.group("name"),
            )
        )
    except ResourceNotFoundError as error:
        logger.warning(
            f"Subscription ID: {subscription_id} -- WAF policy: {policy_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    except Exception as error:
        reads_failed.add(policy_id.casefold())
        logger.error(
            f"Subscription ID: {subscription_id} -- WAF policy: {policy_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return None


def get_waf_policy_enabled(
    client: NetworkManagementClient,
    subscription_id: str,
    policy_id: str,
    listed_policies: dict,
    reads_failed: set[str],
) -> Optional[bool]:
    """Return whether the WAF policy associated with a gateway is enabled.

    The policy is looked up among the WAF policies listed for the
    subscription, and read by its ID only when it was not listed, such as a
    policy outside the scanned resource groups.

    Args:
        client: NetworkManagementClient of the gateway's subscription.
        subscription_id: Subscription of the gateway.
        policy_id: Resource ID of the associated WAF policy.
        listed_policies: WafPolicy models listed for the subscription, keyed by
            casefolded policy ID.
        reads_failed: Casefolded IDs of WAF policies that could not be read.

    Returns:
        True when the policy is enabled, False when it is disabled, and None
        when its state cannot be determined.
    """
    policy = listed_policies.get(policy_id.casefold())
    if policy is None:
        policy = read_waf_policy(client, subscription_id, policy_id, reads_failed)
    if policy is None:
        return None
    enabled = WAF_POLICY_STATES.get((policy.state or "").casefold())
    if enabled is None:
        logger.warning(
            f"Subscription ID: {subscription_id} -- WAF policy: {policy_id} -- unrecognised policy state: {policy.state}"
        )
    return enabled
