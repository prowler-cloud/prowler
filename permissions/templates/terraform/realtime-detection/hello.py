"""Emits the Prowler real-time detection hello event.

Invoked once by Terraform when real-time detection is enabled, mirroring the
CloudFormation custom resource. It never raises: a failed verification must not
fail the apply that created the scan role.
"""

import json
import time

import boto3

ATTEMPTS = 3
BACKOFF_SECONDS = 2


def handler(_event, context):
    _, _, _, region, account = context.invoked_function_arn.split(":")[:5]
    entries = [
        {
            "Source": "prowler.simulation",
            "DetailType": "test_connection",
            "Detail": json.dumps(
                {"account_id": account, "region": region, "trigger": "terraform"}
            ),
            "EventBusName": "default",
        }
    ]

    client = boto3.client("events")
    error = "not attempted"
    # The role policy may not be in effect yet on the first apply
    for attempt in range(ATTEMPTS):
        try:
            entry = client.put_events(Entries=entries)["Entries"][0]
            if not entry.get("ErrorCode"):
                return {"status": "Sent", "event_id": entry["EventId"]}
            error = entry["ErrorCode"]
        except Exception as failure:  # noqa: BLE001
            error = str(failure)[:200]
        if attempt + 1 < ATTEMPTS:
            time.sleep(BACKOFF_SECONDS)

    print(f"hello event not sent: {error}")
    return {"status": "Failed", "error": error}
