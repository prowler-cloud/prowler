import json

import requests

TOKEN = "token"
ENDPOINT = "https://api.github.com/graphql"

headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

query = """
{
  user(login: "HugoPBrito") {
    login
    twoFactorAuthentication {
      enabled
    }
  }
}
"""

response = requests.post(ENDPOINT, headers=headers, json={"query": query})

if response.status_code == 200:
    print(json.dumps(response.json(), indent=2))

    data = response.json()
    two_factor_authentication = data["data"]["user"]["twoFactorAuthentication"][
        "enabled"
    ]
    print(two_factor_authentication)
else:
    print(f"Error {response.status_code}: {response.text}")
