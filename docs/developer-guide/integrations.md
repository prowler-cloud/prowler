# Creating a New Integration

## Introduction

Integrating Prowler with external tools enhances its functionality and seamlessly embeds it into your workflows. Prowler supports a wide range of integrations to streamline security assessments and reporting. Common integration targets include messaging platforms like Slack, project management tools like Jira, and cloud services such as AWS Security Hub.

## Steps to Create a General Integration

### Identify the Integration Purpose

* Clearly define the objective of the integration. For example:
    * Sending Prowler findings to a platform for alerts, tracking, or further analysis.
    * Review existing integrations in the `/lib/outputs` folder for inspiration and implementation examples.

### Review Prowler’s Integration Capabilities

* Consult the [Prowler Developer Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/) to understand available integration points.
* Identify the best approach for the specific platform you’re targeting.

### Develop the Integration

* Script Development:
    * Write a script to process Prowler’s output and interact with the target platform’s API.
    * For example, to send findings, parse Prowler’s results and use the platform’s API to create entries or notifications.
* Configuration:
    * Ensure your script includes configurable options for environment-specific settings, such as API endpoints and authentication tokens.

### Fundamental Structure

* Integration Class:
    * Create a class that encapsulates attributes and methods for the integration.
* Test Connection Method:
    * Implement a method to validate credentials or tokens, ensuring the connection to the target platform is successful.
* Send Findings Method:
    * Add a method to send Prowler findings to the target platform, adhering to its API specifications.

### Testing

* Test the integration in a controlled environment to confirm it behaves as expected.
* Verify that Prowler’s findings are accurately transmitted and correctly processed by the target platform.
* Simulate edge cases to ensure robust error handling.

### Documentation

* Provide clear, detailed documentation for your integration:
    * Setup instructions, including any required dependencies.
    * Configuration details, such as environment variables or authentication steps.
    * Example use cases and troubleshooting tips.
* Good documentation ensures maintainability and simplifies onboarding for team members.
