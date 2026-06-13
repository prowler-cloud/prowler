import json
import urllib.request
from ipaddress import ip_network

AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def get_public_ip_networks() -> list:
    """Fetch the AWS public IP prefixes as a list of ip_network objects.

    The request verifies the server certificate against the system trust store,
    matching urllib's default behaviour. This replaces the unmaintained
    awsipranges package, whose latest release (0.3.3) calls
    urllib.request.urlopen() with the cafile/capath arguments that Python 3.13
    removed.
    """
    with urllib.request.urlopen(AWS_IP_RANGES_URL) as response:
        ranges = json.loads(response.read())

    networks = []
    for prefix in ranges.get("prefixes", []):
        cidr = prefix.get("ip_prefix")
        if cidr:
            networks.append(ip_network(cidr))
    for prefix in ranges.get("ipv6_prefixes", []):
        cidr = prefix.get("ipv6_prefix")
        if cidr:
            networks.append(ip_network(cidr))
    return networks
