import os
import threading

from locust import HttpUser, task

TARGET_INSERTED_AT_GTE = os.environ.get("TARGET_INSERTED_AT_GTE", "")
BASE_URL = os.environ.get("BASE_URL", "")
email = ""
password = ""

global_page_number = 0
page_lock = threading.Lock()


def get_next_page_number():
    global global_page_number
    with page_lock:
        global_page_number += 1
        return global_page_number


class APIUser(HttpUser):
    host = BASE_URL

    def on_start(self):
        login_payload = {
            "data": {
                "type": "tokens",
                "attributes": {"email": email, "password": password},
            }
        }
        headers = {"Content-Type": "application/vnd.api+json"}
        with self.client.post(
            "/tokens", json=login_payload, headers=headers, catch_response=True
        ) as response:
            self.token = response.json()["data"]["attributes"]["access"]

    @task
    def findings(self):
        page_number = get_next_page_number()
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/vnd.api+json",
        }
        endpoint = (
            f"/findings?page[number]={page_number}"
            "&sort=severity,status,-inserted_at"
            f"&filter[inserted_at__gte]={TARGET_INSERTED_AT_GTE}"
        )
        self.client.get(endpoint, headers=headers, name="/findings")

    @task
    def findings_metadata(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/vnd.api+json",
        }
        endpoint = (
            f"/findings/metadata?" f"filter[inserted_at__gte]={TARGET_INSERTED_AT_GTE}"
        )
        self.client.get(endpoint, headers=headers, name="/findings/metadata")
