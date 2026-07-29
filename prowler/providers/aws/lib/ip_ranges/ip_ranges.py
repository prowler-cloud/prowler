import json
import urllib.error
import urllib.request
from ipaddress import ip_network

from prowler.lib.logger import logger

AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AWS_IP_RANGES_TIMEOUT = 10


def get_public_ip_networks() -> list:
    """Fetch the AWS public IP prefixes as a list of ip_network objects.

    The request verifies the server certificate against the system trust store,
    matching urllib's default behaviour. This replaces the unmaintained
    awsipranges package, whose latest release (0.3.3) calls
    urllib.request.urlopen() with the cafile/capath arguments that Python 3.13
    removed.

    Returns an empty list when the feed cannot be fetched or parsed, and skips
    individual malformed prefixes, so a transient or corrupt feed never aborts
    the calling check.
    """
    try:
        with urllib.request.urlopen(
            AWS_IP_RANGES_URL, timeout=AWS_IP_RANGES_TIMEOUT
        ) as response:
            ranges = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return []

    networks = []
    for key, prefixes in (
        ("ip_prefix", ranges.get("prefixes", [])),
        ("ipv6_prefix", ranges.get("ipv6_prefixes", [])),
    ):
        for prefix in prefixes:
            cidr = prefix.get(key)
            if not cidr:
                continue
            try:
                networks.append(ip_network(cidr))
            except ValueError as error:
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
    return networks
