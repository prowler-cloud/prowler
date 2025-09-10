# Jira Integration

Prowler App enables automatic export of security findings to Jira, providing seamless integration with Atlassian's work item tracking and project management platform. This comprehensive guide demonstrates how to configure and manage Jira integrations to streamline security incident management and enhance team collaboration across security workflows.

Integrating Prowler App with Jira provides:

* **Streamlined management:** Convert security findings directly into actionable Jira work items
* **Enhanced team collaboration:** Leverage existing project management workflows for security remediation
* **Automated ticket creation:** Reduce manual effort in tracking and assigning security work items

## How It Works

When enabled and configured:

1. Security findings can be manually sent to Jira from the Findings table.
2. Each finding creates a Jira work item with all the check's metadata, including guidance on how to remediate it.

## Configuration

To configure Jira integration in Prowler App:

1. Navigate to **Integrations** in the Prowler App interface
2. Locate the **Jira** card and click **Manage**, then select **Add integration**

    ![Integrations tab](./img/jira/integrations-tab.png)

3. Complete the integration settings:
    * **Jira domain:** Enter the Jira domain (e.g., from `https://your-domain.atlassian.net` -> `your-domain`)
    * **Email:** Your Jira account email
    * **API Token:** API token with the following scopes: `read:jira-user`, `read:jira-work`, `write:jira-work`
        ![Connection settings](./img/jira/connection-settings.png)

!!! note "Generate Jira API Token"
    To generate a Jira API token, visit: https://id.atlassian.com/manage-profile/security/api-tokens


Once configured successfully, the integration is ready to send findings to Jira.

## Sending Findings to Jira

### Manual Export

To manually send individual findings to Jira:

1. Navigate to the **Findings** section in Prowler App
2. Select one finding you want to export
3. Click the action button on the table row and select **Send to Jira**
4. Select the Jira integration and project
5. Click **Send to Jira**

    ![Send to Jira modal](./img/jira/send-to-jira-modal.png)

## Integration Status

Monitor and manage your Jira integrations through the management interface:

1. Review configured integrations in the integrations dashboard
2. Each integration displays:

    - **Connection Status:** Connected or Disconnected indicator
    - **Instance Information:** Jira domain and last checked timestamp

### Actions

Each Jira integration provides management actions through dedicated buttons:

| Button | Purpose | Available Actions | Notes |
|--------|---------|------------------|-------|
| **Test** | Verify integration connectivity | • Test Jira API access<br/>• Validate credentials<br/>• Check project permissions<br/>• Verify work item creation capability | Results displayed in notification message |
| **Credentials** | Update authentication settings | • Change API token<br/>• Update email<br/>• Update Jira domain | Click "Update Credentials" to save changes |
| **Enable/Disable** | Toggle integration status | • Enable or disable integration<br/>| Status change takes effect immediately |
| **Delete** | Remove integration permanently | • Permanently delete integration<br/>• Remove all configuration data | ⚠️ **Cannot be undone** - confirm before deleting |

## Troubleshooting

### Connection test fails

- Verify Jira instance domain is correct and accessible
- Confirm API token or credentials are valid
- Ensure API access is enabled in Jira settings and the needed scopes are granted

### Check task status (API)

If the Jira issue does not appear in your Jira project, follow these steps to verify the export task status via the API.

!!! note
    Replace `http://localhost:8080` with the base URL where your Prowler API is accessible (for example, `https://api.yourdomain.com`).

1) Get an access token (replace email and password):

```
curl --location 'http://localhost:8080/api/v1/tokens' \
  --header 'Content-Type: application/vnd.api+json' \
  --header 'Accept: application/vnd.api+json' \
  --data-raw '{
    "data": {
      "type": "tokens",
      "attributes": {
        "email": "YOUR_USER_EMAIL",
        "password": "YOUR_USER_PASSWORD"
      }
    }
  }'
```

2) List tasks filtered by the Jira task (`integration-jira`) using the access token:

```
curl --location --globoff 'http://localhost:8080/api/v1/tasks?filter[name]=integration-jira' \
  --header 'Accept: application/vnd.api+json' \
  --header 'Authorization: Bearer ACCESS_TOKEN' | jq
```

!!! note
    If you don’t have `jq` installed, run the command without `| jq`.

3) Share the output so we can help. A typical result will look like:

```
{
  "links": {
    "first": "https://api.dev.prowler.com/api/v1/tasks?page%5Bnumber%5D=1",
    "last": "https://api.dev.prowler.com/api/v1/tasks?page%5Bnumber%5D=122",
    "next": "https://api.dev.prowler.com/api/v1/tasks?page%5Bnumber%5D=2",
    "prev": null
  },
  "data": [
    {
      "type": "tasks",
      "id": "9a79ab21-39ae-4161-9f6e-2844eb0da0fb",
      "attributes": {
        "inserted_at": "2025-09-09T08:11:38.643620Z",
        "completed_at": "2025-09-09T08:11:41.264285Z",
        "name": "integration-jira",
        "state": "completed",
        "result": {
          "created_count": 0,
          "failed_count": 1
        },
        "task_args": {
          "integration_id": "a476c2c0-0a00-4720-bfb9-286e9eb5c7bd",
          "project_key": "PRWLR",
          "issue_type": "Task",
          "finding_ids": [
            "01992d53-3af7-7759-be48-68fc405391e6"
          ]
        },
        "metadata": {}
      }
    },
    {
      "type": "tasks",
      "id": "5f525135-9d37-4b01-9ac8-afeaf8793eac",
      "attributes": {
        "inserted_at": "2025-09-09T08:07:22.184164Z",
        "completed_at": "2025-09-09T08:07:24.909185Z",
        "name": "integration-jira",
        "state": "completed",
        "result": {
          "created_count": 1,
          "failed_count": 0
        },
        "task_args": {
          "integration_id": "a476c2c0-0a00-4720-bfb9-286e9eb5c7bd",
          "project_key": "JIRA",
          "issue_type": "Task",
          "finding_ids": [
            "0198f018-8b7b-7154-a509-1a2b1ffba02d"
          ]
        },
        "metadata": {}
      }
    }
  ],
  "meta": {
    "pagination": {
      "page": 1,
      "pages": 122,
      "count": 1214
    },
    "version": "v1"
  }
}
```

How to read it:

- "created_count": number of Jira issues successfully created.
- "failed_count": number of Jira issues that could not be created. If `failed_count > 0` or the issue does not appear in Jira, please contact us so we can assist while detailed logs are not available through the UI.
