import json
import re
import subprocess

# Start PowerShell with NoExit so the session persists
ps = subprocess.Popen(
    ["pwsh", "-NoExit", "-Command", "-"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

# Run Azure PowerShell commands
ps.stdin.write("Connect-MicrosoftTeams\n")
ps.stdin.write("Get-CsTeamsClientConfiguration | ConvertTo-Json\n")
ps.stdin.flush()

# Read output
stdout, stderr = ps.communicate()

if stderr:
    print("Error:", stderr)
    exit(1)

# Extract only the JSON response
json_match = re.search(r"(\{.*\})", stdout, re.DOTALL)
if not json_match:
    print("Failed to extract JSON")
    exit(1)

try:
    response = json.loads(json_match.group(1))
except json.JSONDecodeError as e:
    print("JSON decoding error:", e)
    exit(1)

# Check conditions
if all(
    response.get(key, False) is False
    for key in [
        "AllowDropBox",
        "AllowBox",
        "AllowGoogleDrive",
        "AllowOneDrive",
        "AllowShareFile",
        "AllowEgnyte",
    ]
):
    print("PASS")
else:
    print("FAIL")
