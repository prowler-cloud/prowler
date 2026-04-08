# Slack Notification Action

A generic and flexible GitHub composite action for sending Slack notifications using JSON template files. Supports both standalone messages and message updates, with automatic status detection.

## Features

- **Template-based**: All messages use JSON template files for consistency
- **Automatic status detection**: Pass `step-outcome` to auto-calculate success/failure
- **Message updates**: Supports updating existing messages (using `chat.update`)
- **Simple API**: Clean and minimal interface
- **Reusable**: Use across all workflows and scenarios
- **Maintainable**: Centralized message templates

## Use Cases

1. **Container releases**: Track push start and completion with automatic status
2. **Deployments**: Track deployment progress with rich Block Kit formatting
3. **Custom notifications**: Any scenario where you need to notify Slack

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `slack-bot-token` | Slack bot token for authentication | Yes | - |
| `payload-file-path` | Path to JSON file with the Slack message payload | Yes | - |
| `update-ts` | Message timestamp to update (leave empty for new messages) | No | `''` |
| `step-outcome` | Step outcome for automatic status detection (sets STATUS_EMOJI and STATUS_TEXT env vars) | No | `''` |

## Outputs

| Output | Description |
|--------|-------------|
| `ts` | Timestamp of the Slack message (use for updates) |

## Usage Examples

### Example 1: Container Release with Automatic Status Detection

Using JSON template files with automatic status detection:

```yaml
# Send start notification
- name: Notify container push started
  if: github.event_name == 'release'
  uses: ./.github/actions/slack-notification
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    COMPONENT: API
    RELEASE_TAG: ${{ env.RELEASE_TAG }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/container-release-started.json"

# Do the work
- name: Build and push container
  if: github.event_name == 'release'
  id: container-push
  uses: docker/build-push-action@...
  with:
    push: true
    tags: ...

# Send completion notification with automatic status detection
- name: Notify container push completed
  if: github.event_name == 'release' && always()
  uses: ./.github/actions/slack-notification
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    COMPONENT: API
    RELEASE_TAG: ${{ env.RELEASE_TAG }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/container-release-completed.json"
    step-outcome: ${{ steps.container-push.outcome }}
```

**Benefits:**
- No status calculation needed in workflow
- Reusable template files
- Clean and concise
- Automatic `STATUS_EMOJI` and `STATUS_TEXT` env vars set by action
- Consistent message format across all workflows

### Example 2: Deployment with Message Update Pattern

```yaml
# Send initial deployment message
- name: Notify deployment started
  id: slack-start
  uses: ./.github/actions/slack-notification
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    COMPONENT: API
    ENVIRONMENT: PRODUCTION
    COMMIT_HASH: ${{ github.sha }}
    VERSION_DEPLOYED: latest
    GITHUB_ACTOR: ${{ github.actor }}
    GITHUB_WORKFLOW: ${{ github.workflow }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/deployment-started.json"

# Run deployment
- name: Deploy
  id: deploy
  run: terraform apply -auto-approve

# Determine additional status variables
- name: Determine deployment status
  if: always()
  id: deploy-status
  run: |
    if [[ "${{ steps.deploy.outcome }}" == "success" ]]; then
      echo "STATUS_COLOR=28a745" >> $GITHUB_ENV
      echo "STATUS=Completed" >> $GITHUB_ENV
    else
      echo "STATUS_COLOR=fc3434" >> $GITHUB_ENV
      echo "STATUS=Failed" >> $GITHUB_ENV
    fi

# Update the same message with final status
- name: Update deployment notification
  if: always()
  uses: ./.github/actions/slack-notification
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    MESSAGE_TS: ${{ steps.slack-start.outputs.ts }}
    COMPONENT: API
    ENVIRONMENT: PRODUCTION
    COMMIT_HASH: ${{ github.sha }}
    VERSION_DEPLOYED: latest
    GITHUB_ACTOR: ${{ github.actor }}
    GITHUB_WORKFLOW: ${{ github.workflow }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
    STATUS: ${{ env.STATUS }}
    STATUS_COLOR: ${{ env.STATUS_COLOR }}
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    update-ts: ${{ steps.slack-start.outputs.ts }}
    payload-file-path: "./.github/scripts/slack-messages/deployment-completed.json"
    step-outcome: ${{ steps.deploy.outcome }}
```

## Automatic Status Detection

When you provide `step-outcome` input, the action automatically sets these environment variables:

| Outcome | STATUS_EMOJI | STATUS_TEXT |
|---------|--------------|-------------|
| success | `[✓]` | `completed successfully!` |
| failure | `[✗]` | `failed` |

These variables are then available in your payload template files.

## Template File Format

All template files must be valid JSON and support environment variable substitution. Example:

```json
{
  "channel": "$SLACK_CHANNEL_ID",
  "text": "$STATUS_EMOJI $COMPONENT container release $RELEASE_TAG push $STATUS_TEXT <$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID|View run>"
}
```

See available templates in [`.github/scripts/slack-messages/`](../../scripts/slack-messages/).

## Requirements

- Slack Bot Token with scopes: `chat:write`, `chat:write.public`
- Slack Channel ID where messages will be posted
- JSON template files for your messages

## Benefits

- **Consistency**: All notifications use standardized templates
- **Automatic status handling**: No need to calculate success/failure in workflows
- **Clean workflows**: Minimal boilerplate code
- **Reusable templates**: One template for all components
- **Easy to maintain**: Change template once, applies everywhere
- **Version controlled**: All message formats in git

## Related Resources

- [Slack Block Kit Builder](https://app.slack.com/block-kit-builder)
- [Slack API Method Documentation](https://docs.slack.dev/tools/slack-github-action/sending-techniques/sending-data-slack-api-method/)
- [Message templates documentation](../../scripts/slack-messages/README.md)
