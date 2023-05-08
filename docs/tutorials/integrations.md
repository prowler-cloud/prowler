# Integrations

## Slack

Prowler can be integrated with Slack to send a summary of the execution with a Slack APP in your channel:

![Prowler Slack Message](img/slack-prowler-message.png)

### Configuration

To configure the Slack Integration, follow the next steps:

1. Create a Slack Application:
    - Go to [Slack API page](https://api.slack.com/tutorials/tracks/getting-a-token), scroll down to the *Create app* button and select your workspace:
    ![Create Slack App](img/create-slack-app.png)

    - Install the application in your selected workspaces:
    ![Install Slack App in Workspace](img/install-in-slack-workspace.png)

    - Get the *Slack App OAuth Token* that Prowler needs to send the message:
    ![Slack App OAuth Token](img/slack-app-token.png)

2. Optionally, create a Slack Channel (you can use an existing one)

3. Integrate the created Slack App to your Slack channel:
    - Click on the channel, go to the Integrations tab, and Add an App.
    ![Slack App Channel Integration](img/integrate-slack-app.png)

4. Set the following environment variables that Prowler will read:
    - `SLACK_API_TOKEN`: the *Slack App OAuth Token* that was previously get.
    - `SLACK_CHANNEL_ID`: the name of your Slack Channel where Prowler will send the message.
