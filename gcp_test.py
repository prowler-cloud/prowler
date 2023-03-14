#!/usr/bin/env python3
from pprint import pprint

from google import auth
from googleapiclient import discovery

# https://cloud.google.com/docs/authentication/application-default-credentials
# 1. GOOGLE_APPLICATION_CREDENTIALS with path of credentials file (--service-account)
# 2. gcloud auth application-default login (--user-account)
# 3. Gather automatically Compute Engine Credentials

credentials, project_id = auth.default()
print(type(credentials))

service = discovery.build(
    "iam", "v1", credentials=credentials
)  # IAM API has to be enabled https://console.developers.google.com/apis/api/iam.googleapis.com/overview?project=6896496431
print(type(service))
request = service.roles().list()
while True:
    response = request.execute()

    for role in response.get("roles", []):
        # TODO: Change code below to process each `role` resource:
        pprint(role["name"])

    request = service.roles().list_next(
        previous_request=request, previous_response=response
    )
    if request is None:
        break

# service = discovery.build(
#     "cloudresourcemanager", "v1", credentials=credentials
# )  # CloudResourceManager API has to be enabled https://console.developers.google.com/apis/api/iam.googleapis.com/overview?project=6896496431

# request = service.projects().list()

# while request is not None:
#     response = request.execute()

#     for project in response.get("projects", []):
#         pprint(project["projectId"])

#     request = service.projects().list_next(
#         previous_request=request, previous_response=response
#     )

compute = discovery.build(
    "compute", "v1", credentials=credentials
)  # Compute API has to be enabled https://console.developers.google.com/apis/api/iam.googleapis.com/overview?project=6896496431
zones = []
request = compute.zones().list(project=project_id)
while request is not None:
    response = request.execute()

    for zone in response["items"]:
        # TODO: Change code below to process each `instance` resource:
        zones.append(zone["name"])
        pprint(zone["name"])

    request = compute.zones().list_next(
        previous_request=request, previous_response=response
    )

for zone in zones:
    request = compute.instances().list(project=project_id, zone=zone)
    while request is not None:
        response = request.execute()

        for instance in response.get("items", []):
            # TODO: Change code below to process each `instance` resource:
            pprint(instance["name"])

        request = compute.instances().list_next(
            previous_request=request, previous_response=response
        )
