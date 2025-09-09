# Getting Started with AWS on Prowler

## Prowler App

<iframe width="560" height="380" src="https://www.youtube-nocookie.com/embed/RPgIWOCERzY" title="Prowler Cloud Onboarding AWS" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="1"></iframe>

> Walkthrough video onboarding a AWS Account using Assumed Role.

### Step 1: Get Your AWS Account ID

1. Log in to the [AWS Console](https://console.aws.amazon.com)
2. Locate your AWS account ID in the top-right dropdown menu

![Account ID detail](./img/aws-account-id.png)


### Step 2: Access Prowler Cloud/App

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


### Step 3: Set Up AWS Authentication

Before proceeding, choose your preferred authentication mode:

**Credentials**

* Quick scan as current user ✅
* No extra setup ✅
* Credentials time out ❌

**Assumed Role**

* Preferred Setup ✅
* Permanent Credentials ✅
* Requires access to create role ❌


---

#### 🔐 Assume Role (Recommended)

This method grants permanent access and is the recommended setup for production environments.

![Assume Role Overview](img/assume-role-overview.png)

For detailed instructions on how to create the role, see [Authentication > Assume Role](./authentication.md#assume-role-recommended).

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

#### 🔑 Credentials (Static Access Keys)

You can also configure your AWS account using static credentials (not recommended for long-term use):

![Connect via credentials](./img/connect-via-credentials.png)

For detailed instructions on how to create the credentials, see [Authentication > Credentials](./authentication.md#credentials).

1. Complete the form in Prowler Cloud/App and click `Next`

    ![Filled credentials page](./img/prowler-cloud-credentials-next.png)

2. Click `Launch Scan`

    ![Launch Scan](./img/launch-scan-button-prowler-cloud.png)

---

## Prowler CLI

### Configure AWS Credentials

Use one of the following methods to authenticate:

```console
aws configure
```

or

```console
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
```

These credentials must be associated with a user or role with the necessary permissions to perform security checks.



### AWS Profiles

Specify a custom AWS profile using the following command:

```console
prowler aws -p/--profile <profile_name>
```

### Multi-Factor Authentication (MFA)

For IAM entities requiring Multi-Factor Authentication (MFA), use the `--mfa` flag. Prowler prompts for the following values to initiate a new session:

- **ARN of your MFA device**
- **TOTP (Time-Based One-Time Password)**
