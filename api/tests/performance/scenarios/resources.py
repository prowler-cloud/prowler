from locust import task, events
from utils.helpers import (
    APIUserBase,
    get_api_token,
    get_auth_headers,
    get_sort_value,
    get_available_resource_filters,
    get_next_resource_filter,
)
from utils.config import (
    RESOURCES_UI_SORT_VALUES,
)

GLOBAL = {"token": None, "resource_ids": [], "resource_filters": None}


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    GLOBAL["token"] = get_api_token(environment.host)
    GLOBAL["resource_filters"] = get_available_resource_filters(
        environment.host, GLOBAL["token"]
    )


class ResourceUser(APIUserBase):
    def on_start(self):
        self.token = GLOBAL["token"]
        self.headers = get_auth_headers(self.token)
        self.available_resource_filters = GLOBAL["resource_filters"]

    @task
    def resources_default(self):
        name = "GET /resources"
        page_number = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page_number}"
            f"&{get_sort_value(RESOURCES_UI_SORT_VALUES)}"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(3)
    def resource_with_include(self):
        name = "GET /resources (with include)"
        page = self._next_page(name)
        endpoint = (
            f"/resources?page[number]={page}"
            f"&{get_sort_value(RESOURCES_UI_SORT_VALUES)}"
            f"&include=findings,provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(2)
    def resource_filter(self):
        name = "GET /resources (random filter)"
        filter_type, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )
        endpoint = f"/resources?filter[{filter_type}]={filter_value}"
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)

    @task(2)
    def resource_filter_with_include(self):
        name = "GET /resources (random filter + include)"
        filter_type, filter_value = get_next_resource_filter(
            self.available_resource_filters
        )
        endpoint = (
            f"/resources?filter[{filter_type}]={filter_value}"
            f"&include=findings,provider"
        )
        self.client.get(endpoint, headers=get_auth_headers(self.token), name=name)
