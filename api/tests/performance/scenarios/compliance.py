import random
from collections import defaultdict

import requests
from locust import events, task
from utils.helpers import APIUserBase, get_api_token, get_auth_headers

GLOBAL = {
    "token": None,
    "available_scans_info": {},
}
SUPPORTED_COMPLIANCE_IDS = {
    "aws": ["ens_rd2022", "cis_2.0", "prowler_threatscore", "soc2"],
    "gcp": ["ens_rd2022", "cis_2.0", "prowler_threatscore", "soc2"],
    "azure": ["ens_rd2022", "cis_2.0", "prowler_threatscore", "soc2"],
    "m365": ["cis_4.0", "iso27001_2022", "prowler_threatscore"],
}


def _get_random_scan() -> tuple:
    provider_type = random.choice(list(GLOBAL["available_scans_info"].keys()))
    scan_info = random.choice(GLOBAL["available_scans_info"][provider_type])
    return provider_type, scan_info


def _get_random_compliance_id(provider: str) -> str:
    return f"{random.choice(SUPPORTED_COMPLIANCE_IDS[provider])}_{provider}"


def _get_compliance_available_scans_by_provider_type(host: str, token: str) -> dict:
    excluded_providers = ["kubernetes"]

    response_dict = defaultdict(list)
    provider_response = requests.get(
        f"{host}/providers?fields[providers]=id,provider&filter[connected]=true",
        headers=get_auth_headers(token),
    )
    for provider in provider_response.json()["data"]:
        provider_id = provider["id"]
        provider_type = provider["attributes"]["provider"]
        if provider_type in excluded_providers:
            continue

        scan_response = requests.get(
            f"{host}/scans?fields[scans]=id&filter[provider]={provider_id}&filter[state]=completed",
            headers=get_auth_headers(token),
        )
        scan_data = scan_response.json()["data"]
        if not scan_data:
            continue
        scan_id = scan_data[0]["id"]
        response_dict[provider_type].append(scan_id)
    return response_dict


def _get_compliance_regions_from_scan(host: str, token: str, scan_id: str) -> list:
    response = requests.get(
        f"{host}/compliance-overviews/metadata?filter[scan_id]={scan_id}",
        headers=get_auth_headers(token),
    )
    assert response.status_code == 200, f"Failed to get scan: {response.text}"
    return response.json()["data"]["attributes"]["regions"]


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    GLOBAL["token"] = get_api_token(environment.host)
    scans_by_provider = _get_compliance_available_scans_by_provider_type(
        environment.host, GLOBAL["token"]
    )
    scan_info = defaultdict(list)
    for provider, scans in scans_by_provider.items():
        for scan in scans:
            scan_info[provider].append(
                {
                    "scan_id": scan,
                    "regions": _get_compliance_regions_from_scan(
                        environment.host, GLOBAL["token"], scan
                    ),
                }
            )
    GLOBAL["available_scans_info"] = scan_info


class APIUser(APIUserBase):
    def on_start(self):
        self.token = GLOBAL["token"]

    @task(3)
    def compliance_overviews_default(self):
        provider_type, scan_info = _get_random_scan()
        name = f"/compliance-overviews ({provider_type})"
        endpoint = f"/compliance-overviews?" f"filter[scan_id]={scan_info['scan_id']}"
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(2)
    def compliance_overviews_region(self):
        provider_type, scan_info = _get_random_scan()
        name = f"/compliance-overviews?filter[region] ({provider_type})"
        endpoint = (
            f"/compliance-overviews"
            f"?filter[scan_id]={scan_info['scan_id']}"
            f"&filter[region]={random.choice(scan_info['regions'])}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(2)
    def compliance_overviews_requirements(self):
        provider_type, scan_info = _get_random_scan()
        compliance_id = _get_random_compliance_id(provider_type)
        name = f"/compliance-overviews/requirements ({compliance_id})"
        endpoint = (
            f"/compliance-overviews/requirements"
            f"?filter[scan_id]={scan_info['scan_id']}"
            f"&filter[compliance_id]={compliance_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def compliance_overviews_attributes(self):
        provider_type, _ = _get_random_scan()
        compliance_id = _get_random_compliance_id(provider_type)
        name = f"/compliance-overviews/attributes ({compliance_id})"
        endpoint = (
            f"/compliance-overviews/attributes"
            f"?filter[compliance_id]={compliance_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)
