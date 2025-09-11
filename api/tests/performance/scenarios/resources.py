from locust import events, task
from utils.config import (
    L_PROVIDER_NAME,
    M_PROVIDER_NAME,
    RESOURCES_UI_FIELDS,
    S_PROVIDER_NAME,
    TARGET_INSERTED_AT,
)
from utils.helpers import (
    APIUserBase,
    get_api_token,
    get_auth_headers,
    get_dynamic_filters_pairs,
    get_next_resource_filter,
    get_scan_id_from_provider_name,
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

    GLOBAL["resource_filters"] = get_dynamic_filters_pairs(
        environment.host, GLOBAL["token"], "resources"
    )
    GLOBAL["large_resource_filters"] = get_dynamic_filters_pairs(
        environment.host, GLOBAL["token"], "resources", GLOBAL["scan_ids"]["large"]
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
    def resources_default(self):
        name = "/resources"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}"
            f"&filter[updated_at]={TARGET_INSERTED_AT}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_default_ui_fields(self):
        name = "/resources?fields"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}"
            f"&fields[resources]={','.join(RESOURCES_UI_FIELDS)}"
            f"&filter[updated_at]={TARGET_INSERTED_AT}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_default_include(self):
        name = "/resources?include"
        page = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page}"
            f"&filter[updated_at]={TARGET_INSERTED_AT}"
            f"&include=provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_metadata(self):
        name = "/resources/metadata"
        endpoint = f"/resources/metadata?filter[updated_at]={TARGET_INSERTED_AT}"
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def resources_scan_small(self):
        name = "/resources?filter[scan_id] - 50k"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}" f"&filter[scan]={self.s_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def resources_metadata_scan_small(self):
        name = "/resources/metadata?filter[scan_id] - 50k"
        endpoint = f"/resources/metadata?&filter[scan]={self.s_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name=name,
        )

    @task(2)
    def resources_scan_medium(self):
        name = "/resources?filter[scan_id] - 250k"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}" f"&filter[scan]={self.m_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def resources_metadata_scan_medium(self):
        name = "/resources/metadata?filter[scan_id] - 250k"
        endpoint = f"/resources/metadata?&filter[scan]={self.m_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name=name,
        )

    @task
    def resources_scan_large(self):
        name = "/resources?filter[scan_id] - 500k"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}" f"&filter[scan]={self.l_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def resources_scan_large_include(self):
        name = "/resources?filter[scan_id]&include - 500k"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}"
            f"&filter[scan]={self.l_scan_id}"
            f"&include=provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task
    def resources_metadata_scan_large(self):
        endpoint = f"/resources/metadata?&filter[scan]={self.l_scan_id}"
        self.client.get(
            endpoint,
            headers=get_auth_headers(self.token),
            name="/resources/metadata?filter[scan_id] - 500k",
        )

    @task(2)
    def resources_filters(self):
        name = "/resources?filter[resource_filter]&include"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/resources?filter[{filter_name}]={filter_value}"
            f"&filter[updated_at]={TARGET_INSERTED_AT}"
            f"&include=provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_metadata_filters(self):
        name = "/resources/metadata?filter[resource_filter]"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/resources/metadata?filter[{filter_name}]={filter_value}"
            f"&filter[updated_at]={TARGET_INSERTED_AT}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_metadata_filters_scan_large(self):
        name = "/resources/metadata?filter[resource_filter]&filter[scan_id] - 500k"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/resources/metadata?filter[{filter_name}]={filter_value}"
            f"&filter[scan]={self.l_scan_id}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(2)
    def resourcess_filter_large_scan_include(self):
        name = "/resources?filter[resource_filter][scan]&include - 500k"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = (
            f"/resources?filter[{filter_name}]={filter_value}"
            f"&filter[scan]={self.l_scan_id}"
            f"&include=provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_latest_default_ui_fields(self):
        name = "/resources/latest?fields"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources/latest?page[number]={page_number}"
            f"&fields[resources]={','.join(RESOURCES_UI_FIELDS)}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resources_latest_metadata_filters(self):
        name = "/resources/metadata/latest?filter[resource_filter]"
        filter_name, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )

        endpoint = f"/resources/metadata/latest?filter[{filter_name}]={filter_value}"
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)
