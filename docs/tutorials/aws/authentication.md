# AWS Authentication in Prowler

Prowler requires AWS credentials to function properly. Authentication is available through the following methods:

- Static Credentials
- Assumed Role

## Required Permissions

To ensure full functionality, attach the following AWS managed policies to the designated user or role:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

### Additional Permissions

For certain checks, additional read-only permissions are required. Attach the following custom policy to your role: [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json)


## 🔐 Assume Role (Recommended)

This method grants permanent access and is the recommended setup for production environments.

=== "CloudFormation"

    1. Download the [Prowler Scan Role Template](https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/permissions/templates/cloudformation/prowler-scan-role.yml)

        ![Prowler Scan Role Template](./img/prowler-scan-role-template.png)

        ![Download Role Template](./img/download-role-template.png)

    2. Open the [AWS Console](https://console.aws.amazon.com), search for **CloudFormation**

        ![CloudFormation Search](./img/cloudformation-nav.png)

    3. Go to **Stacks** and click "Create stack" > "With new resources (standard)"

        ![Create Stack](./img/create-stack.png)

    4. In **Specify Template**, choose "Upload a template file" and select the downloaded file

        ![Upload a template file](./img/upload-template-file.png)
        ![Upload file from downloads](./img/upload-template-from-downloads.png)

    5. Click "Next", provide a stack name and the **External ID** shown in the Prowler Cloud setup screen

        ![External ID](./img/prowler-cloud-external-id.png)
        ![Stack Data](./img/fill-stack-data.png)

        !!! info
            An **External ID** is required when assuming the *ProwlerScan* role to comply with AWS [confused deputy prevention](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

    6. Acknowledge the IAM resource creation warning and proceed

        ![Stack Creation Second Step](./img/stack-creation-second-step.png)

    7. Click "Submit" to deploy the stack

        ![Click on submit](./img/submit-third-page.png)

=== "Terraform"

    To provision the scan role using Terraform:

    1. Run the following commands:

        ```bash
        terraform init
        terraform plan
        terraform apply
        ```

    2. During `plan` and `apply`, provide the **External ID** when prompted, which is available in the Prowler Cloud or Prowler App UI:

        ![Get External ID](./img/get-external-id-prowler-cloud.png)

    > 💡 Note: Terraform will use the AWS credentials of the default profile.

---

## 🔑 Credentials
=== "Long term credentials"

    1. Go to the [AWS Console](https://console.aws.amazon.com), open **CloudShell**

        ![AWS CloudShell](./img/aws-cloudshell.png)

    2. Run:

        ```bash
        aws iam create-access-key
        ```

    3. Copy the output containing:

        - `AccessKeyId`
        - `SecretAccessKey`

        ![CloudShell Output](./img/cloudshell-output.png)

=== "Short term credentials (Recommended)"

    Use the [AWS Access Portal](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtogetcredentials.html) or the CLI:

    1. Retrieve short-term credentials for the IAM identity using this command:

        ```bash
        aws sts get-session-token --duration-seconds 900
        ```

        ???+ note
            Check the aws documentation [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/sts_example_sts_GetSessionToken_section.html)

    2. Copy the output containing:

        - `AccessKeyId`
        - `SecretAccessKey`
        - `SessionToken`

        > Sample output:
            ```json
            {
                "Credentials": {
                    "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
                    "SessionToken": "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE",
                    "Expiration": "2020-05-19T18:06:10+00:00"
                }
            }
            ```
