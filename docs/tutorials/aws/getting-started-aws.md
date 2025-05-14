# Getting Started with AWS on Prowler Cloud/App

<iframe width="560" height="380" src="https://www.youtube-nocookie.com/embed/RPgIWOCERzY" title="Prowler Cloud Onboarding AWS" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="1"></iframe>

Set up your AWS account to enable security scanning using Prowler Cloud/App.

## Requirements

To configure your AWS account, you’ll need:

1. Access to Prowler Cloud/App
2. Properly configured AWS credentials (either static or via an assumed IAM role)

---

## Step 1: Get Your AWS Account ID

1. Log in to the [AWS Console](https://console.aws.amazon.com)
2. Locate your AWS account ID in the top-right dropdown menu

![Account ID detail](./img/aws-account-id.png)

---

## Step 2: Access Prowler Cloud/App

1. Navigate to [Prowler Cloud](https://cloud.prowler.com/) or launch [Prowler App](../prowler-app.md)
2. Go to `Configuration` > `Cloud Providers`

    ![Cloud Providers Page](../img/cloud-providers-page.png)

3. Click `Add Cloud Provider`

    ![Add a Cloud Provider](../img/add-cloud-provider.png)

4. Select `Amazon Web Services`

    ![Select AWS Provider](./img/select-aws.png)

5. Enter your AWS Account ID and optionally provide a friendly alias

    ![Add account ID](./img/add-account-id.png)

6. Choose your preferred authentication method (next step)

    ![Select auth method](./img/select-auth-method.png)

---

## Step 3: Set Up AWS Authentication

Before proceeding, choose your preferred authentication mode:

Credentials

* Quick scan as current user ✅
* No extra setup ✅
* Credentials time out ❌

Assumed Role

* Preferred Setup ✅
* Permanent Credentials ✅
* Requires access to create role ❌

---

### 🔐 Assume Role (Recommended)

![Assume Role Overview](./img/assume-role-overview.png)

This method grants permanent access and is the recommended setup for production environments.

=== "CloudFormation"

    1. Download the [Prowler Scan Role Template](https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/permissions/templates/cloudformation/prowler-scan-role.yml)

        ![Prowler Scan Role Template](./img/prowler-scan-role-template.png)

        ![Download Role Template](./img/download-role-template.png)

    2. Open the [AWS Console](https://console.aws.amazon.com), search for **CloudFormation**

        ![CloudFormation Search](./img/cloudformation-nav.png)

    3. Go to **Stacks** and click `Create stack` > `With new resources (standard)`

        ![Create Stack](./img/create-stack.png)

    4. In **Specify Template**, choose `Upload a template file` and select the downloaded file

        ![Upload a template file](./img/upload-template-file.png)
        ![Upload file from downloads](./img/upload-template-from-downloads.png)

    5. Click `Next`, provide a stack name and the **External ID** shown in the Prowler Cloud setup screen

        ![External ID](./img/prowler-cloud-external-id.png)
        ![Stack Data](./img/fill-stack-data.png)

    6. Acknowledge the IAM resource creation warning and proceed

        ![Stack Creation Second Step](./img/stack-creation-second-step.png)

    7. Click `Submit` to deploy the stack

        ![Click on submit](./img/submit-third-page.png)

=== "Terraform"

    To provision the scan role using Terraform:

    1. Run the following commands:

        ```bash
        terraform init
        terraform plan
        terraform apply
        ```

    2. During `plan` and `apply`, you will be prompted for the **External ID**, which is available in the Prowler Cloud/App UI:

        ![Get External ID](./img/get-external-id-prowler-cloud.png)

    > 💡 Note: Terraform will use the AWS credentials of your default profile.

---

### Finish Setup with Assume Role

8. Once the role is created, go to the **IAM Console**, click on the `ProwlerScan` role to open its details:

    ![ProwlerScan role info](./img/prowler-scan-pre-info.png)

9. Copy the **Role ARN**

    ![New Role Info](./img/get-role-arn.png)

10. Paste the ARN into the corresponding field in Prowler Cloud/App

    ![Input the Role ARN](./img/paste-role-arn-prowler.png)

11. Click `Next`, then `Launch Scan`

    ![Next button in Prowler Cloud](./img/next-button-prowler-cloud.png)
    ![Launch Scan](./img/launch-scan-button-prowler-cloud.png)

---

### 🔑 Credentials (Static Access Keys)

You can also configure your AWS account using static credentials (not recommended for long-term use):

![Connect via credentials](./img/connect-via-credentials.png)

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

    > ⚠️ Save these credentials securely and paste them into the Prowler Cloud/App setup screen.

=== "Short term credentials (Recommended)"

    You can use your [AWS Access Portal](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtogetcredentials.html) or the CLI:

    1. Retrieve short-term credentials for the IAM identity using this command:

        ```bash
        aws sts get-session-token --duration-seconds 900
        ```

        ???+ note
            Check the aws documentation [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/sts_example_sts_GetSessionToken_section.html)

    2. Copy the output containing:

        - `AccessKeyId`
        - `SecretAccessKey`

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

    > ⚠️ Save these credentials securely and paste them into the Prowler Cloud/App setup screen.

Complete the form in Prowler Cloud/App and click `Next`

![Filled credentials page](./img/prowler-cloud-credentials-next.png)

Click `Launch Scan`

![Launch Scan](./img/launch-scan-button-prowler-cloud.png)
