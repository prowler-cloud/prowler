# AWS SSO to Prowler Automation Script

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Script Overview](#script-overview)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Customization](#customization)
- [Security Considerations](#security-considerations)
- [License](#license)

## Introduction

This repository provides a Bash script that automates the process of logging into AWS Single Sign-On (SSO), extracting temporary AWS credentials, and running **Prowler**—a security tool that performs AWS security best practices assessments—inside a Docker container using those credentials.

By following this guide, you can streamline your AWS security assessments, ensuring that you consistently apply best practices across your AWS accounts.

## Prerequisites

Before you begin, ensure that you have the following tools installed and properly configured on your system:

1. **AWS CLI v2**
   - AWS SSO support is available from AWS CLI version 2 onwards.
   - [Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

2. **jq**
   - A lightweight and flexible command-line JSON processor.
   - **macOS (Homebrew):**
     ```bash
     brew install jq
     ```
   - **Ubuntu/Debian:**
     ```bash
     sudo apt-get update
     sudo apt-get install -y jq
     ```
   - **Windows:**
     - [Download jq](https://stedolan.github.io/jq/download/)

3. **Docker**
   - Ensure Docker is installed and running on your system.
   - [Docker Installation Guide](https://docs.docker.com/get-docker/)

4. **AWS SSO Profile Configuration**
   - Ensure that you have configured an AWS CLI profile with SSO.
   - [Configuring AWS CLI with SSO](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)

## Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/aws-sso-prowler-automation.git
   cd aws-sso-prowler-automation
   ```

2. **Create the Automation Script**
   Create a new Bash script named `run_prowler_sso.sh` and make it executable.

   ```bash
   nano run_prowler_sso.sh
   chmod +x run_prowler_sso.sh
   ```

3. **Add the Script Content**
   Paste the following content into `run_prowler_sso.sh`:

4. **Configure AWS SSO Profile**
   Ensure that your AWS CLI profile (`twodragon` in this case) is correctly configured for SSO.

   ```bash
   aws configure sso --profile twodragon
   ```

   **Example Configuration Prompts:**
   ```
   SSO session name (Recommended): [twodragon]
   SSO start URL [None]: https://twodragon.awsapps.com/start
   SSO region [None]: ap-northeast-2
   SSO account ID [None]: 123456789012
   SSO role name [None]: ReadOnlyAccess
   CLI default client region [None]: ap-northeast-2
   CLI default output format [None]: json
   CLI profile name [twodragon]: twodragon
   ```

## Script Overview

The `run_prowler_sso.sh` script performs the following actions:

1. **AWS SSO Login:**
   - Initiates AWS SSO login for the specified profile.
   - Opens the SSO authorization page in the default browser for user authentication.

2. **Extract Temporary Credentials:**
   - Locates the most recent SSO cache file containing the `accessToken`.
   - Uses `jq` to parse and extract the `accessToken` from the cache file.
   - Retrieves the `sso_role_name` and `sso_account_id` from the AWS CLI configuration.
   - Obtains temporary AWS credentials (`AccessKeyId`, `SecretAccessKey`, `SessionToken`) using the extracted `accessToken`.

3. **Set Environment Variables:**
   - Exports the extracted AWS credentials as environment variables to be used by the Docker container.

4. **Run Prowler:**
   - Executes the **Prowler** Docker container, passing the AWS credentials as environment variables for security assessments.

## Usage

1. **Make the Script Executable**
   Ensure the script has execute permissions.

   ```bash
   chmod +x run_prowler_sso.sh
   ```

2. **Run the Script**
   Execute the script to start the AWS SSO login process and run Prowler.

   ```bash
   ./run_prowler_sso.sh
   ```

3. **Follow the Prompts**
   - A browser window will open prompting you to authenticate via AWS SSO.
   - Complete the authentication process in the browser.
   - Upon successful login, the script will extract temporary credentials and run Prowler.

4. **Review Prowler Output**
   - Prowler will analyze your AWS environment based on the specified checks and output the results directly in the terminal.

## Troubleshooting

If you encounter issues during the script execution, follow these steps to diagnose and resolve them.

### 1. Verify AWS CLI Version

Ensure you are using AWS CLI version 2 or later.

```bash
aws --version
```

**Expected Output:**
```
aws-cli/2.11.10 Python/3.9.12 Darwin/20.3.0 exe/x86_64 prompt/off
```

If you are not using version 2, [install or update AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).

### 2. Confirm AWS SSO Profile Configuration

Check that the `twodragon` profile is correctly configured.

```bash
aws configure list-profiles
```

**Expected Output:**
```
default
twodragon
```

Review the profile details:

```bash
aws configure get sso_start_url --profile twodragon
aws configure get sso_region --profile twodragon
aws configure get sso_account_id --profile twodragon
aws configure get sso_role_name --profile twodragon
```

Ensure all fields return the correct values.

### 3. Check SSO Cache File

Ensure that the SSO cache file contains a valid `accessToken`.

```bash
cat ~/.aws/sso/cache/*.json
```

**Example Content:**
```json
{
  "accessToken": "eyJz93a...k4laUWw",
  "expiresAt": "2024-12-22T14:07:55Z",
  "clientId": "example-client-id",
  "clientSecret": "example-client-secret",
  "startUrl": "https://twodragon.awsapps.com/start#"
}
```

If `accessToken` is `null` or missing, retry the AWS SSO login:

```bash
aws sso login --profile twodragon
```

### 4. Validate `jq` Installation

Ensure that `jq` is installed and functioning correctly.

```bash
jq --version
```

**Expected Output:**
```
jq-1.6
```

If `jq` is not installed, install it using the instructions in the [Prerequisites](#prerequisites) section.

### 5. Test Docker Environment Variables

Verify that the Docker container receives the AWS credentials correctly.

```bash
docker run --platform linux/amd64 \
    -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
    -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
    toniblyx/prowler /bin/bash -c 'echo $AWS_ACCESS_KEY_ID; echo $AWS_SECRET_ACCESS_KEY; echo $AWS_SESSION_TOKEN'
```

**Expected Output:**
```
ASIA...
wJalrFEMI/K7MDENG/bPxRfiCY...
IQoJb3JpZ2luX2VjEHwaCXVz...
```

Ensure that none of the environment variables are empty.

### 6. Review Script Output

Run the script with debugging enabled to get detailed output.

1. **Enable Debugging in Script**
   Add `set -x` for verbose output.

   ```bash
   #!/bin/bash
   set -e
   set -x
   # ... rest of the script ...
   ```

2. **Run the Script**

   ```bash
   ./run_prowler_sso.sh
   ```

3. **Analyze Output**
   Look for any errors or unexpected values in the output to identify where the script is failing.

## Customization

You can modify the script to suit your specific needs, such as:

- **Changing the AWS Profile Name:**
  Update the `PROFILE` variable at the top of the script.

  ```bash
  PROFILE="your-profile-name"
  ```

- **Adding Prowler Options:**
  Pass additional options to Prowler for customized checks or output formats.

  ```bash
  docker run --platform linux/amd64 \
      -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
      -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
      -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
      toniblyx/prowler -c check123 -M json
  ```

## Security Considerations

- **Handle Credentials Securely:**
  - Avoid sharing or exposing your AWS credentials.
  - Do not include sensitive information in logs or version control.

- **Script Permissions:**
  - Ensure the script file has appropriate permissions to prevent unauthorized access.

    ```bash
    chmod 700 run_prowler_sso.sh
    ```

- **Environment Variables:**
  - Be cautious when exporting credentials as environment variables.
  - Consider using more secure methods for credential management if necessary.

## License

This project is licensed under the [MIT License](LICENSE).
