from locust import HttpUser, task, events
from utils.helpers import get_api_token, get_auth_headers, get_random_resource_id

GLOBAL = {
    "token": None,
    "resource_ids": []
}

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    GLOBAL["token"] = get_api_token(environment.host)

class ResourceUser(HttpUser):
    def on_start(self):
        self.token = GLOBAL["token"]
        self.headers = get_auth_headers(self.token)

        with self.client.get("/resources", headers=self.headers, name="/resources", catch_response=True) as response:
            if response.status_code == 200:
                json_data = response.json()
                GLOBAL["resource_ids"] = [item["id"] for item in json_data.get("data", [])[:10]]
            else:
                response.failure("Failed to load /resources")

    @task(3)
    def list_resources(self):
        self.client.get("/resources", headers=self.headers, name="/resources")

    @task(2)
    def get_single_resource(self):
        if GLOBAL["resource_ids"]:
            resource_id = get_random_resource_id(GLOBAL["resource_ids"])
            self.client.get(f"/resources/{resource_id}", headers=self.headers, name="/resources/:id")
