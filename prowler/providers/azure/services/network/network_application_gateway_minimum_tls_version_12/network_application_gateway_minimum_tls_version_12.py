from typing import List, Optional, Tuple

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client
from prowler.providers.azure.services.network.network_service import (
    ApplicationGateway,
    SslPolicy,
)

# Lowest TLS version each predefined policy is configured for, from Microsoft's
# Application Gateway TLS policy overview.
PREDEFINED_POLICY_MIN_TLS = {
    "AppGwSslPolicy20150501": "TLSv1_0",
    "AppGwSslPolicy20170401": "TLSv1_1",
    "AppGwSslPolicy20170401S": "TLSv1_2",
    "AppGwSslPolicy20220101": "TLSv1_2",
    "AppGwSslPolicy20220101S": "TLSv1_2",
}
TLS_VERSIONS = ("TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3")
MINIMUM_SECURE_TLS = "TLSv1_2"
# Both tables keyed by the casefolded name, so Azure's casing does not matter.
PREDEFINED_MINIMUMS = {
    name.casefold(): version for name, version in PREDEFINED_POLICY_MIN_TLS.items()
}
CANONICAL_TLS_VERSIONS = {version.casefold(): version for version in TLS_VERSIONS}


def policy_is_set(ssl_policy: Optional[SslPolicy]) -> bool:
    """Return whether an SSL policy sets anything.

    Azure can report an empty policy object, which, like no policy at all,
    leaves the default policy in force.

    Args:
        ssl_policy: SslPolicy model, or None.

    Returns:
        True when the policy sets a type, a name, a minimum version or
        disabled protocols.
    """
    return ssl_policy is not None and bool(
        ssl_policy.policy_type
        or ssl_policy.policy_name
        or ssl_policy.min_protocol_version
        or ssl_policy.disabled_ssl_protocols
    )


def minimum_tls_version(ssl_policy: SslPolicy) -> Optional[str]:
    """Work out the lowest TLS version an SSL policy is configured for.

    Args:
        ssl_policy: SslPolicy model that sets at least one value.

    Returns:
        The lowest TLS version in Azure's spelling, such as "TLSv1_2", or None
        when it cannot be determined.
    """
    policy_type = (ssl_policy.policy_type or "").casefold()
    if policy_type == "predefined" or (ssl_policy.policy_name and not policy_type):
        return PREDEFINED_MINIMUMS.get((ssl_policy.policy_name or "").casefold())
    if ssl_policy.min_protocol_version:
        return CANONICAL_TLS_VERSIONS.get(ssl_policy.min_protocol_version.casefold())
    if ssl_policy.disabled_ssl_protocols:
        disabled = {
            (protocol or "").casefold()
            for protocol in ssl_policy.disabled_ssl_protocols
        }
        enabled = [
            version for version in TLS_VERSIONS if version.casefold() not in disabled
        ]
        return enabled[0] if enabled else None
    return None


def is_below_minimum(version: str) -> bool:
    """Return whether a TLS version from TLS_VERSIONS is older than TLS 1.2."""
    return TLS_VERSIONS.index(version) < TLS_VERSIONS.index(MINIMUM_SECURE_TLS)


def gateway_policies(
    gateway: ApplicationGateway,
) -> List[Tuple[str, Optional[str]]]:
    """List the SSL policies in force on a gateway with their minimum TLS version.

    The first entry is the gateway's own policy, or the default policy Azure
    reports when the gateway sets none. Each SSL profile a listener uses
    follows, unless it sets no policy and so uses the gateway's.

    Args:
        gateway: ApplicationGateway model.

    Returns:
        A list of (description, minimum TLS version) pairs. The version is None
        when it cannot be determined.
    """
    if policy_is_set(gateway.ssl_policy):
        name = gateway.ssl_policy.policy_name
        policies = [
            (
                f"gateway SSL policy {name}" if name else "gateway SSL policy",
                minimum_tls_version(gateway.ssl_policy),
            )
        ]
    elif gateway.default_ssl_policy_name:
        policies = [
            (
                f"default SSL policy {gateway.default_ssl_policy_name}",
                PREDEFINED_MINIMUMS.get(gateway.default_ssl_policy_name.casefold()),
            )
        ]
    else:
        policies = [("gateway SSL policy (none set and no default reported)", None)]
    for profile in gateway.listener_ssl_profiles:
        if policy_is_set(profile.ssl_policy):
            name = profile.ssl_policy.policy_name
            policies.append(
                (
                    f"SSL profile {profile.name}" + (f" with {name}" if name else ""),
                    minimum_tls_version(profile.ssl_policy),
                )
            )
    return policies


class network_application_gateway_minimum_tls_version_12(Check):
    """Application Gateway requires TLS 1.2 or higher on its SSL policies."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the SSL policies in force on every Application Gateway.

        Returns:
            One finding per Application Gateway, plus one MANUAL finding for
            each subscription whose gateways could not be listed completely.
            A gateway finding is MANUAL when the minimum TLS version of a
            policy cannot be determined.
        """
        findings = []
        for subscription_id, gateways in network_client.application_gateways.items():
            subscription_name = network_client.subscriptions.get(
                subscription_id, subscription_id
            )
            if subscription_id in network_client.application_gateways_lookup_failed:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_id
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate the minimum TLS version of the Application Gateways in subscription {subscription_name} ({subscription_id}): they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."
                findings.append(report)
            for gateway in gateways.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=gateway)
                report.subscription = subscription_id
                prefix = f"Application Gateway {gateway.name} in subscription {subscription_name} ({subscription_id})"
                policies = gateway_policies(gateway)
                weak = [
                    f"{name} ({version})"
                    for name, version in policies
                    if version and is_below_minimum(version)
                ]
                unknown = [name for name, version in policies if not version]
                no_policy_reported = not (
                    policy_is_set(gateway.ssl_policy) or gateway.default_ssl_policy_name
                )
                if weak:
                    report.status = "FAIL"
                    report.status_extended = f"{prefix} has a minimum TLS version below 1.2: {', '.join(weak)}."
                    if unknown:
                        report.status_extended += f" The minimum TLS version of {', '.join(unknown)} could not be determined."
                elif no_policy_reported and len(unknown) == 1:
                    report.status = "MANUAL"
                    report.status_extended = f"{prefix} sets no SSL policy and Azure reports no default policy for it, so its minimum TLS version could not be determined. Set an explicit SSL policy, such as AppGwSslPolicy20220101."
                elif unknown:
                    report.status = "MANUAL"
                    policy_noun = (
                        "an SSL policy" if len(unknown) == 1 else "SSL policies"
                    )
                    report.status_extended = f"{prefix} has {policy_noun} whose minimum TLS version could not be determined: {', '.join(unknown)}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"{prefix} requires TLS 1.2 or higher: {', '.join(f'{name} ({version})' for name, version in policies)}."
                findings.append(report)
        return findings
