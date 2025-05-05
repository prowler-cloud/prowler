from locust import events, task
from utils.config import (
    FINDINGS_UI_SORT_VALUES,
    L_PROVIDER_NAME,
    M_PROVIDER_NAME,
    S_PROVIDER_NAME,
    TARGET_INSERTED_AT,
)
from utils.helpers import (
    APIUserBase,
    get_api_token,
    get_auth_headers,
    get_next_resource_filter,
    get_resource_filters_pairs,
    get_scan_id_from_provider_name,
    get_sort_value,
)

GLOBAL = {
    "token": None,
    "scan_ids": {},
    "resource_filters": None,
    "large_resource_filters": None,
}


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    GLOBAL["token"] = get_api_token(environment.host)

    GLOBAL["scan_ids"]["small"] = get_scan_id_from_provider_name(
        environment.host, GLOBAL["token"], S_PROVIDER_NAME
    )
    GLOBAL["scan_ids"]["medium"] = get_scan_id_from_provider_name(
        environment.host, GLOBAL["token"], M_PROVIDER_NAME
    )
    GLOBAL["scan_ids"]["large"] = get_scan_id_from_provider_name(
        environment.host, GLOBAL["token"], L_PROVIDER_NAME
    )

    GLOBAL["resource_filters"] = get_resource_filters_pairs(
        environment.host, GLOBAL["token"]
    )
    GLOBAL["large_resource_filters"] = get_resource_filters_pairs(
        environment.host, GLOBAL["token"], GLOBAL["scan_ids"]["large"]
    )


class APIUser(APIUserBase):
    def on_start(self):
        self.token = GLOBAL["token"]
        self.s_scan_id = GLOBAL["scan_ids"]["small"]
        self.m_scan_id = GLOBAL["scan_ids"]["medium"]
        self.l_scan_id = GLOBAL["scan_ids"]["large"]
        self.available_resource_filters = GLOBAL["resource_filters"]
        self.available_resource_filters_large_scan = GLOBAL["large_resource_filters"]

    @task
    def findings_default(self):
        name = "/findings"
        page_number = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page_number}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[inserted_at]={TARGET_INSERTED_AT}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def findings_default_include(self):
        name = "/findings?include"
        page = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[inserted_at]={TARGET_INSERTED_AT}"
            f"&include=scan.provider,resources"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def findings_metadata(self):
        endpoint = f"/findings/metadata?" f"filter[inserted_at]={TARGET_INSERTED_AT}"
        self.client.get(
            endpoint, headers=get_auth_headers(self.token), name="/findings/metadata"
        )

    @task
    def findings_scan_small(self):
        name = "/findings?filter[scan_id] - 50k"
        page_number = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page_number}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[scan]={self.s_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def findings_metadata_scan_small(self):
        endpoint = f"/findings/metadata?" f"&filter[scan]={self.s_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name="/findings/metadata?filter[scan_id] - 50k",
        )

    @task(2)
    def findings_scan_medium(self):
        name = "/findings?filter[scan_id] - 250k"
        page_number = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page_number}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[scan]={self.m_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def findings_metadata_scan_medium(self):
        endpoint = f"/findings/metadata?" f"&filter[scan]={self.m_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name="/findings/metadata?filter[scan_id] - 250k",
        )

    @task
    def findings_scan_large(self):
        name = "/findings?filter[scan_id] - 500k"
        page_number = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page_number}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[scan]={self.l_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def findings_scan_large_include(self):
        name = "/findings?filter[scan_id]&include - 500k"
        page_number = self._next_page(name)
        endpoint = (
            f"/findings?page[number]={page_number}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[scan]={self.l_scan_id}"
            f"&include=scan.provider,resources"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def findings_metadata_scan_large(self):
        endpoint = f"/findings/metadata?" f"&filter[scan]={self.l_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name="/findings/metadata?filter[scan_id] - 500k",
        )

    @task(2)
    def findings_resource_filter(self):
        name = "/findings?filter[resource_filter]&include"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/findings?filter[{filter_name}]={filter_value}"
            f"&filter[inserted_at]={TARGET_INSERTED_AT}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&include=scan.provider,resources"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def findings_metadata_resource_filter(self):
        name = "/findings/metadata?filter[resource_filter]"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/findings?filter[{filter_name}]={filter_value}"
            f"&filter[inserted_at]={TARGET_INSERTED_AT}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def findings_resource_filter_large_scan_include(self):
        name = "/findings?filter[resource_filter][scan]&include - 500k"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/findings?filter[{filter_name}]={filter_value}"
            f"&{get_sort_value(FINDINGS_UI_SORT_VALUES)}"
            f"&filter[scan]={self.l_scan_id}"
            f"&include=scan.provider,resources"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)
