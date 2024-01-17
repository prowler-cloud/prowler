# Security

## Software Security

As an **AWS Partner** and we have passed the [AWS Foundation Technical Review (FTR)](https://aws.amazon.com/partners/foundational-technical-review/) and we use the following tools and automation to make sure our code is secure and dependencies up-to-dated:

- `bandit` for code security review.
- `safety` and `dependabot` for dependencies.
- `hadolint` and `dockle` for our containers security.
- `snyk` in Docker Hub.
- `clair` in Amazon ECR.
- `vulture`, `flake8`, `black` and `pylint` for formatting and best practices.

## Reporting Vulnerabilities

If you would like to report a vulnerability or have a security concern regarding Prowler Open Source or ProwlerPro service, please submit the information by contacting to help@prowler.pro.

The information you share with ProwlerPro as part of this process is kept confidential within ProwlerPro. We will only share this information with a third party if the vulnerability you report is found to affect a third-party product, in which case we will share this information with the third-party product's author or manufacturer. Otherwise, we will only share this information as permitted by you.

We will review the submitted report, and assign it a tracking number. We will then respond to you, acknowledging receipt of the report, and outline the next steps in the process.

You will receive a non-automated response to your initial contact within 24 hours, confirming receipt of your reported vulnerability.

We will coordinate public notification of any validated vulnerability with you. Where possible, we prefer that our respective public disclosures be posted simultaneously.
