# Slack Message Templates

This directory contains reusable message templates for Slack notifications sent from GitHub Actions workflows.

## Usage

These JSON templates are used with the `slackapi/slack-github-action` using the Slack API method (`chat.postMessage` and `chat.update`). All templates support rich Block Kit formatting and message updates.

### Available Templates

**Container Releases**
- `container-release-started.json`: Simple one-line notification when container push starts
- `container-release-completed.json`: Simple one-line notification when container release completes

**Deployments**
- `deployment-started.json`: Deployment start notification with Block Kit formatting
- `deployment-completed.json`: Deployment completion notification (updates the start message)

All templates use the Slack API method and require a Slack Bot Token.

## Setup Requirements

1. Create a Slack App (or use existing)
2. Add Bot Token Scopes: `chat:write`, `chat:write.public`
3. Install the app to your workspace
4. Get the Bot Token from OAuth & Permissions page
5. Add secrets:
   - `SLACK_BOT_TOKEN`: Your bot token
   - `SLACK_CHANNEL_ID`: The channel ID where messages will be posted

Reference: [Sending data using a Slack API method](https://docs.slack.dev/tools/slack-github-action/sending-techniques/sending-data-slack-api-method/)

## Environment Variables

### Required Secrets (GitHub Secrets)
- `SLACK_BOT_TOKEN`: Passed as `token` parameter to the action (not as env variable)
- `SLACK_CHANNEL_ID`: Used in payload as env variable

### Container Release Variables (configured as env)
- `COMPONENT`: Component name (e.g., "API", "SDK", "UI", "MCP")
- `RELEASE_TAG` / `PROWLER_VERSION`: The release tag or version being deployed
- `GITHUB_SERVER_URL`: Provided by GitHub context
- `GITHUB_REPOSITORY`: Provided by GitHub context
- `GITHUB_RUN_ID`: Provided by GitHub context
- `STATUS_EMOJI`: Status symbol (calculated: `[✓]` for success, `[✗]` for failure)
- `STATUS_TEXT`: Status text (calculated: "completed successfully!" or "failed")

### Deployment Variables (configured as env)
- `COMPONENT`: Component name (e.g., "API", "SDK", "UI", "MCP")
- `ENVIRONMENT`: Environment name (e.g., "DEVELOPMENT", "PRODUCTION")
- `COMMIT_HASH`: Commit hash being deployed
- `VERSION_DEPLOYED`: Version being deployed
- `GITHUB_ACTOR`: User who triggered the workflow
- `GITHUB_WORKFLOW`: Workflow name
- `GITHUB_SERVER_URL`: Provided by GitHub context
- `GITHUB_REPOSITORY`: Provided by GitHub context
- `GITHUB_RUN_ID`: Provided by GitHub context

All other variables (MESSAGE_TS, STATUS, STATUS_COLOR, STATUS_EMOJI, etc.) are calculated internally within the workflow and should NOT be configured as environment variables.

## Example Workflow Usage

### Using the Generic Slack Notification Action (Recommended)

**Recommended approach**: Use the generic reusable action `.github/actions/slack-notification` which provides maximum flexibility:

#### Example 1: Container Release (Start + Completion)

```yaml
# Send start notification
- name: Notify container push started
  if: github.event_name == 'release'
  uses: ./.github/actions/slack-notification
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload: |
      {
        "channel": "${{ secrets.SLACK_CHANNEL_ID }}",
        "text": "API container release ${{ env.RELEASE_TAG }} push started... <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View run>"
      }

# Build and push container
- name: Build and push container
  if: github.event_name == 'release'
  id: container-push
  uses: docker/build-push-action@...
  with:
    push: true
    tags: ...

# Calculate status
- name: Determine push status
  if: github.event_name == 'release' && always()
  id: push-status
  run: |
    if [[ "${{ steps.container-push.outcome }}" == "success" ]]; then
      echo "emoji=[✓]" >> $GITHUB_OUTPUT
      echo "text=completed successfully!" >> $GITHUB_OUTPUT
    else
      echo "emoji=[✗]" >> $GITHUB_OUTPUT
      echo "text=failed" >> $GITHUB_OUTPUT
    fi

# Send completion notification
- name: Notify container push completed
  if: github.event_name == 'release' && always()
  uses: ./.github/actions/slack-notification
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload: |
      {
        "channel": "${{ secrets.SLACK_CHANNEL_ID }}",
        "text": "${{ steps.push-status.outputs.emoji }} API container release ${{ env.RELEASE_TAG }} push ${{ steps.push-status.outputs.text }} <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View run>"
      }
```

#### Example 2: Simple One-Time Message

```yaml
- name: Send notification
  uses: ./.github/actions/slack-notification
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload: |
      {
        "channel": "${{ secrets.SLACK_CHANNEL_ID }}",
        "text": "Deployment completed successfully!"
      }
```

#### Example 3: Deployment with Message Update Pattern

```yaml
# Send initial deployment message
- name: Notify deployment started
  id: slack-start
  uses: ./.github/actions/slack-notification
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload: |
      {
        "channel": "${{ secrets.SLACK_CHANNEL_ID }}",
        "text": "API deployment to PRODUCTION started",
        "attachments": [
          {
            "color": "dbab09",
            "blocks": [
              {
                "type": "header",
                "text": {
                  "type": "plain_text",
                  "text": "API | Deployment to PRODUCTION"
                }
              },
              {
                "type": "section",
                "fields": [
                  {
                    "type": "mrkdwn",
                    "text": "*Status:*\nIn Progress"
                  }
                ]
              }
            ]
          }
        ]
      }

# Run deployment
- name: Deploy
  id: deploy
  run: terraform apply -auto-approve

# Calculate status
- name: Determine status
  if: always()
  id: status
  run: |
    if [[ "${{ steps.deploy.outcome }}" == "success" ]]; then
      echo "color=28a745" >> $GITHUB_OUTPUT
      echo "emoji=[✓]" >> $GITHUB_OUTPUT
      echo "status=Completed" >> $GITHUB_OUTPUT
    else
      echo "color=fc3434" >> $GITHUB_OUTPUT
      echo "emoji=[✗]" >> $GITHUB_OUTPUT
      echo "status=Failed" >> $GITHUB_OUTPUT
    fi

# Update the same message with final status
- name: Update deployment notification
  if: always()
  uses: ./.github/actions/slack-notification
  with:
    slack-bot-token: ${{ secrets.SLACK_BOT_TOKEN }}
    update-ts: ${{ steps.slack-start.outputs.ts }}
    payload: |
      {
        "channel": "${{ secrets.SLACK_CHANNEL_ID }}",
        "ts": "${{ steps.slack-start.outputs.ts }}",
        "text": "${{ steps.status.outputs.emoji }} API deployment to PRODUCTION ${{ steps.status.outputs.status }}",
        "attachments": [
          {
            "color": "${{ steps.status.outputs.color }}",
            "blocks": [
              {
                "type": "header",
                "text": {
                  "type": "plain_text",
                  "text": "API | Deployment to PRODUCTION"
                }
              },
              {
                "type": "section",
                "fields": [
                  {
                    "type": "mrkdwn",
                    "text": "*Status:*\n${{ steps.status.outputs.emoji }} ${{ steps.status.outputs.status }}"
                  }
                ]
              }
            ]
          }
        ]
      }
```

**Benefits of using the generic action:**
- Maximum flexibility: Build any payload you need directly in the workflow
- No template files needed: Everything inline
- Supports all scenarios: one-time messages, start/update patterns, rich Block Kit
- Easy to customize per use case
- Generic: Works for containers, deployments, or any notification type

For more details, see [Slack Notification Action](../../actions/slack-notification/README.md).

### Using Message Templates (Alternative Approach)

Simple one-line notifications for container releases:

```yaml
# Step 1: Notify when push starts
- name: Notify container push started
  if: github.event_name == 'release'
  uses: slackapi/slack-github-action@91efab103c0de0a537f72a35f6b8cda0ee76bf0a # v2.1.1
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    COMPONENT: API
    RELEASE_TAG: ${{ env.RELEASE_TAG }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
  with:
    method: chat.postMessage
    token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/container-release-started.json"

# Step 2: Build and push container
- name: Build and push container
  id: container-push
  uses: docker/build-push-action@...
  with:
    push: true
    tags: ...

# Step 3: Determine push status
- name: Determine push status
  if: github.event_name == 'release' && always()
  id: push-status
  run: |
    if [[ "${{ steps.container-push.outcome }}" == "success" ]]; then
      echo "status-emoji=[✓]" >> $GITHUB_OUTPUT
      echo "status-text=completed successfully!" >> $GITHUB_OUTPUT
    else
      echo "status-emoji=[✗]" >> $GITHUB_OUTPUT
      echo "status-text=failed" >> $GITHUB_OUTPUT
    fi

# Step 4: Notify when push completes (success or failure)
- name: Notify container push completed
  if: github.event_name == 'release' && always()
  uses: slackapi/slack-github-action@91efab103c0de0a537f72a35f6b8cda0ee76bf0a # v2.1.1
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    COMPONENT: API
    RELEASE_TAG: ${{ env.RELEASE_TAG }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
    STATUS_EMOJI: ${{ steps.push-status.outputs.status-emoji }}
    STATUS_TEXT: ${{ steps.push-status.outputs.status-text }}
  with:
    method: chat.postMessage
    token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/container-release-completed.json"
```

### Deployment with Update Pattern

For deployments that start with one message and update it with the final status:

```yaml
# Step 1: Send deployment start notification
- name: Notify Deployment Start
  id: slack-notification-start
  uses: slackapi/slack-github-action@91efab103c0de0a537f72a35f6b8cda0ee76bf0a # v2.1.1
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
    method: chat.postMessage
    token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/deployment-started.json"

# Step 2: Run your deployment steps
- name: Terraform Plan
  id: terraform-plan
  run: terraform plan

- name: Terraform Apply
  id: terraform-apply
  run: terraform apply -auto-approve

# Step 3: Determine status (calculated internally, not configured)
- name: Determine Status
  if: always()
  id: determine-status
  run: |
    if [[ "${{ steps.terraform-apply.outcome }}" == "success" ]]; then
      echo "status=Completed" >> $GITHUB_OUTPUT
      echo "status-color=28a745" >> $GITHUB_OUTPUT
      echo "status-emoji=[✓]" >> $GITHUB_OUTPUT
      echo "plan-emoji=[✓]" >> $GITHUB_OUTPUT
      echo "apply-emoji=[✓]" >> $GITHUB_OUTPUT
    elif [[ "${{ steps.terraform-plan.outcome }}" == "failure" || "${{ steps.terraform-apply.outcome }}" == "failure" ]]; then
      echo "status=Failed" >> $GITHUB_OUTPUT
      echo "status-color=fc3434" >> $GITHUB_OUTPUT
      echo "status-emoji=[✗]" >> $GITHUB_OUTPUT
      if [[ "${{ steps.terraform-plan.outcome }}" == "failure" ]]; then
        echo "plan-emoji=[✗]" >> $GITHUB_OUTPUT
      else
        echo "plan-emoji=[✓]" >> $GITHUB_OUTPUT
      fi
      if [[ "${{ steps.terraform-apply.outcome }}" == "failure" ]]; then
        echo "apply-emoji=[✗]" >> $GITHUB_OUTPUT
      else
        echo "apply-emoji=[✓]" >> $GITHUB_OUTPUT
      fi
    else
      echo "status=Failed" >> $GITHUB_OUTPUT
      echo "status-color=fc3434" >> $GITHUB_OUTPUT
      echo "status-emoji=[✗]" >> $GITHUB_OUTPUT
      echo "plan-emoji=[?]" >> $GITHUB_OUTPUT
      echo "apply-emoji=[?]" >> $GITHUB_OUTPUT
    fi

# Step 4: Update the same Slack message (using calculated values)
- name: Notify Deployment Result
  if: always()
  uses: slackapi/slack-github-action@91efab103c0de0a537f72a35f6b8cda0ee76bf0a # v2.1.1
  env:
    SLACK_CHANNEL_ID: ${{ secrets.SLACK_CHANNEL_ID }}
    MESSAGE_TS: ${{ steps.slack-notification-start.outputs.ts }}
    COMPONENT: API
    ENVIRONMENT: PRODUCTION
    COMMIT_HASH: ${{ github.sha }}
    VERSION_DEPLOYED: latest
    GITHUB_ACTOR: ${{ github.actor }}
    GITHUB_WORKFLOW: ${{ github.workflow }}
    GITHUB_SERVER_URL: ${{ github.server_url }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    GITHUB_RUN_ID: ${{ github.run_id }}
    STATUS: ${{ steps.determine-status.outputs.status }}
    STATUS_COLOR: ${{ steps.determine-status.outputs.status-color }}
    STATUS_EMOJI: ${{ steps.determine-status.outputs.status-emoji }}
    PLAN_EMOJI: ${{ steps.determine-status.outputs.plan-emoji }}
    APPLY_EMOJI: ${{ steps.determine-status.outputs.apply-emoji }}
    TERRAFORM_PLAN_OUTCOME: ${{ steps.terraform-plan.outcome }}
    TERRAFORM_APPLY_OUTCOME: ${{ steps.terraform-apply.outcome }}
  with:
    method: chat.update
    token: ${{ secrets.SLACK_BOT_TOKEN }}
    payload-file-path: "./.github/scripts/slack-messages/deployment-completed.json"
```

**Note**: Variables like `STATUS`, `STATUS_COLOR`, `STATUS_EMOJI`, `PLAN_EMOJI`, `APPLY_EMOJI` are calculated by the `determine-status` step based on the outcomes of previous steps. They should NOT be manually configured.

## Key Features

### Benefits of Using Slack API Method

- **Rich Block Kit Formatting**: Full support for Slack's Block Kit including headers, sections, fields, colors, and attachments
- **Message Updates**: Update the same message instead of posting multiple messages (using `chat.update` with `ts`)
- **Consistent Experience**: Same look and feel as Prowler Cloud notifications
- **Flexible**: Easy to customize message appearance by editing JSON templates

### Differences from Webhook Method

| Feature | webhook-trigger | Slack API (chat.postMessage) |
|---------|-----------------|------------------------------|
| Setup | Workflow Builder webhook | Slack Bot Token + Channel ID |
| Formatting | Plain text/simple | Full Block Kit support |
| Message Update | No | Yes (with chat.update) |
| Authentication | Webhook URL | Bot Token |
| Scopes Required | None | chat:write, chat:write.public |

## Message Appearance

### Container Release (Simple One-Line)

**Start message:**
```
API container release 4.5.0 push started... View run
```

**Completion message (success):**
```
[✓] API container release 4.5.0 push completed successfully! View run
```

**Completion message (failure):**
```
[✗] API container release 4.5.0 push failed View run
```

All messages are simple one-liners with a clickable "View run" link. The completion message adapts to show success `[✓]` or failure `[✗]` based on the outcome of the container push.

### Deployment Start
- Header: Component and environment
- Yellow bar (color: `dbab09`)
- Status: In Progress
- Details: Commit, version, actor, workflow
- Link: Direct link to deployment run

### Deployment Completion
- Header: Component and environment
- Green bar for success (color: `28a745`) / Red bar for failure (color: `fc3434`)
- Status: [✓] Completed or [✗] Failed
- Details: All deployment info plus terraform outcomes
- Link: Direct link to deployment run

## Adding New Templates

1. Create a new JSON file with Block Kit structure
2. Use environment variable placeholders (e.g., `$VAR_NAME`)
3. Include `channel` and `text` fields (required)
4. Add `blocks` or `attachments` for rich formatting
5. For update templates, include `ts` field as `$MESSAGE_TS`
6. Document the template in this README
7. Reference it in your workflow using `payload-file-path`

## Reference

- [Slack Block Kit Builder](https://app.slack.com/block-kit-builder)
- [Slack API Method Documentation](https://docs.slack.dev/tools/slack-github-action/sending-techniques/sending-data-slack-api-method/)
