# Troubleshooting

- **Running `prowler` I get `[File: utils.py:15] [Module: utils]	CRITICAL: path/redacted: OSError[13]`**:

    That is an error related to file descriptors or opened files allowed by your operating system.

    In macOS Ventura, the default value for the `file descriptors` is `256`. With the following command `ulimit -n 1000` you'll increase that value and solve the issue.

    If you have a different OS and you are experiencing the same, please increase the value of your `file descriptors`. You can check it running `ulimit -a | grep "file descriptors"`.

    This error is also related with a lack of system requirements. To improve performance, Prowler stores information in memory so it may need to be run in a system with more than 1GB of memory.


See section [Logging](./tutorials/logging.md) for further information or [contact us](./contact.md).

## Common Issues with Docker Pull Installation

???+ warning
    Docker pull is not officially supported.

- **Problem adding AWS Provider using "Connect assuming IAM Role" in Docker (see [GitHub Issue #7745](https://github.com/prowler-cloud/prowler/issues/7745))**:

    When running Prowler App via Docker, you may encounter errors such as `Provider not set`, `AWS assume role error - Unable to locate credentials`, or `Provider has no secret` when trying to add an AWS Provider using the "Connect assuming IAM Role" option. This typically happens because the container does not have access to the necessary AWS credentials or profiles.

    **Workaround:**
    - Ensure your AWS credentials and configuration are available to the Docker container. You can do this by mounting your local `.aws` directory into the container. For example, in your `docker-compose.yaml`, add the following volume to the relevant services:

      ```yaml
      volumes:
        - "${HOME}/.aws:/home/prowler/.aws:ro"
      ```
      This should be added to the `api`, `worker`, and `worker-beat` services.

    - Create or update your `~/.aws/config` and `~/.aws/credentials` files with the appropriate profiles and roles. For example:

      ```ini
      [profile prowler-profile]
      role_arn = arn:aws:iam::<account-id>:role/ProwlerScan
      source_profile = default
      ```
      And set the environment variable in your `.env` file:

      ```env
      AWS_PROFILE=prowler-profile
      ```
    - If you are scanning multiple AWS accounts, you may need to add multiple profiles to your AWS config. Note that this workaround is mainly for local testing; for production or multi-account setups, follow the [CloudFormation Template guide](https://github.com/prowler-cloud/prowler/issues/7745) and ensure the correct IAM roles and permissions are set up in each account.
