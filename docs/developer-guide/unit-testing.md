# Unit Tests for Prowler Checks

Unit tests for Prowler checks vary based on the provider being evaluated.

Below are key resources and insights gained throughout the testing process.

**Python Testing**

- https://docs.python-guide.org/writing/tests/

**Where to Patch**

- https://docs.python.org/3/library/unittest.mock.html#where-to-patch
- https://stackoverflow.com/questions/893333/multiple-variables-in-a-with-statement
- ​https://docs.python.org/3/reference/compound_stmts.html#the-with-statement

**Utilities for Tracing Mocking and Test Execution**

- https://news.ycombinator.com/item?id=36054868
- https://docs.python.org/3/library/sys.html#sys.settrace
- https://github.com/kunalb/panopticon

## General Recommendations

When writing tests for Prowler provider checks, follow these guidelines to maximize coverage across test scenarios:

1. Zero Findings Scenario:
Develop tests where no resources exist. Prowler returns zero findings if the audited service lacks the required resources.

2. Positive and Negative Outcomes:
Create tests that generate both a passing (`PASS`) and a failing (`FAIL`) result.

3. Multi-Resource Evaluations:
Design tests with multiple resources to verify check behavior and ensure the correct number of findings.

## Running Prowler Tests

To execute the Prowler test suite, install the necessary dependencies listed in the `pyproject.toml` file.

### Prerequisites

If you have not installed Prowler yet, refer to the [developer guide introduction](./introduction.md#get-the-code-and-install-all-dependencies).

### Executing Tests

Navigate to the project's root directory and execute: `pytest -n auto -vvv -s -x`

Alternatively, use:
`Makefile` with `make test`.

Other Commands for Running Tests

- Running tests for a provider:
`pytest -n auto -vvv -s -x tests/providers/<provider>/services`
- Running tests for a provider service:
`pytest -n auto -vvv -s -x tests/providers/<provider>/services/<service>`
- Running tests for a provider check:
`pytest -n auto -vvv -s -x tests/providers/<provider>/services/<service>/<check>`

???+ note
    Refer to the [pytest documentation](https://docs.pytest.org/en/7.1.x/getting-started.html) for more details.

## AWS Testing Approaches

For AWS provider, different testing approaches apply based on API coverage based on several criteria.

???+ note
    Prowler leverages and contributes to the[Moto](https://github.com/getmoto/moto) library for mocking AWS infrastructure in tests.

- AWS API Calls Covered by [Moto](https://github.com/getmoto/moto):
    - Service Tests: `@mock_aws`
    - Checks Tests: `@mock_aws`

- AWS API Calls Not Covered by Moto:
    - Service Tests: `mock_make_api_call`
    - Checks Tests: [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock)

- AWS API Calls Partially Covered by Moto:
    - Service Tests: `@mock_aws` and `mock_make_api_call`
    - Check Tests: `@mock_aws` and `mock_make_api_call`

#### AWS Check Testing Scenarios

The following section provides examples for each testing scenario. The primary distinction between these scenarios depends on whether the [Moto](https://github.com/getmoto/moto) library covers the AWS API calls made by the service. You can review the supported API calls [here](https://github.com/getmoto/moto/blob/master/IMPLEMENTATION_COVERAGE.md).

### AWS Check Testing Approach

For AWS test examples, we reference tests for the `iam_password_policy_uppercase` check.

This section is categorized based on [Moto](https://github.com/getmoto/moto) API coverage.

#### API Calls Covered by Moto

When the [Moto](https://github.com/getmoto/moto) library supports the API calls required for testing, use the `@mock_aws` decorator. This ensures that all AWS API calls within the decorated function are properly mocked while maintaining state within the test.

```python
# Import unittest.mock to enable object patching
# This prevents shared objects between tests, ensuring test isolation
from unittest import mock

# Import Boto3 client and session for AWS API calls
from boto3 import client, session

# Import Moto decorator for mocking AWS services
from moto import mock_aws

# Define constants for test execution
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


# Test class naming convention: Test_<check_name>
class Test_iam_password_policy_uppercase:

  # Apply the Moto decorator for AWS service mocking
  @mock_aws
  # Test naming convention: test_<service>_<check_name>_<test_action>
  def test_iam_password_policy_no_uppercase_flag(self):
    Steps

    # Step 1: Create an IAM client for API calls in the specified region
    iam_client = client("iam", region_name=AWS_REGION)

    # Step 2: Modify the account password policy to disable uppercase character enforcement

    # Action: Setting RequireUppercaseCharacters to False

    iam_client.update_account_password_policy(RequireUppercaseCharacters=False)

    # Step 3: Mock the AWS provider to ensure isolated testing

    # Using 'set_mocked_aws_provider' allows overriding the provider response
    # This mocked provider is defined in test fixtures

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    # Step 4: Ensure Prowler service imports occur within the decorated function
    # This prevents accidental real API calls to AWS during test execution

    from prowler.providers.aws.services.iam.iam_service import IAM

    # Mocking AWS Provider and IAM Client for Prowler Tests

    #Prowler for AWS relies on a shared object, aws_provider, which stores provider-related information.

    # To ensure proper test isolation and prevent shared objects between tests, we apply mocking techniques.

    # Mocking Global AWS Provider

    #To mock the global provider, we use mock.patch() to override the get_global_provider() method, ensuring aws_provider is the return value.

    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ),

    # Mocking IAM Client for Test Isolation

    #In addition to mocking the provider, we must also mock the iam_client from the check. This ensures that the IAM client used in the test is the one explicitly created within the test.

    # ⚠️ Important:

    # patch != import—simply importing does not ensure proper isolation.

    # Running tests in parallel may cause unintended object initialization, impacting test integrity.

      with mock.patch(
        "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
        new=IAM(aws_provider),
    ):
        # Importing the IAM Check

    # To prevent initialization issues, import the check inside the two-mock context.

        # This ensures the IAM client does not retain shared data from aws_provider or the IAM service.

        from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
            iam_password_policy_uppercase,
        )

        # Executing the IAM Check

        # Once imported, instantiate the check’s class.

        check = iam_password_policy_uppercase()

        # Then run the execute function()
        # against the set up IAM client.

        result = check.execute()

        # Validating the Check Results
        # Finally, assert all fields to verify expected results.

        assert len(results) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == "IAM password policy does not srequire at least one uppercase letter."
        assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_tags == []
        assert result[0].region == AWS_REGION
```

#### Handling API Calls Not Covered by Moto

If the IAM service required for testing is not supported by the Moto library, use [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock) to inject objects into the service client.

???+ warning
    As stated above, direct service instantiation must be avoided to prevent actual AWS API calls.

???+ note
    The example below demonstrates the IAM GetAccountPasswordPolicy API, which is covered by Moto, but is used for instructional purposes only.

#### Mocking Service Objects Using MagicMock

The following code demonstrates how to use MagicMock to create service objects.

```python
# Import unittest.mock to enable object patching
# This prevents shared objects between tests, ensuring test isolation

from unittest import mock

# Define constants for test execution

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


# Test class naming convention: Test_<check_name>

class Test_iam_password_policy_uppercase:

  # Test naming convention: test_<service>_<check_name>_<test_action>

  def test_iam_password_policy_no_uppercase_flag(self):

    # Mock IAM client with MagicMock

    mocked_iam_client = mock.MagicMock

    # Import IAM PasswordPolicy model, as it has its own model

    from prowler.providers.aws.services.iam.iam_service import PasswordPolicy

    # Create a mock PasswordPolicy object with predefined attributes

    mocked_iam_client.password_policy = PasswordPolicy(
        length=5,
        symbols=True,
        numbers=True,
        # The value must be set to False to trigger a failure scenario
        uppercase=False,
        lowercase=True,
        allow_change=False,
        expiration=True,
    )

    # In this scenario, both the IAM service and the iam_client from the check must be mocked to ensure test isolation. This guarantees that the iam_client used in the test is the one explicitly instantiated within the test itself.

    # Note: Simply applying a patch does not modify imports (patch != import).

    # If tests are executed in parallel, objects may already be initialized,
    # leading to unintended shared state and breaking test isolation.

    # Unlike other cases, we do not use the Moto decorator here.

    # Instead, we mock the IAM client for both objects to prevent real AWS API interactions.

    with mock.patch(
        "prowler.providers.aws.services.iam.iam_service.IAM",
        new=mocked_iam_client,
    ), mock.patch(
        "prowler.providers.aws.services.iam.iam_client.iam_client",
        new=mocked_iam_client,
    ):
        # Importing the IAM Check

        # To prevent initialization issues, import the check inside the two-mock context.

        # This ensures the IAM client does not retain shared data from aws_provider or the IAM service.

        from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
            iam_password_policy_uppercase,
        )

        # Executing the IAM Check

        # Once imported, instantiate the check’s class.

        check = iam_password_policy_uppercase()

        # Then run the execute function()
        # against the set up IAM client.

        result = check.execute()

        # Validating the Check Results

        # Finally, assert all fields to verify expected results.

        assert len(results) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == "IAM password policy does not require at least one uppercase letter."
        assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_tags == []
        assert result[0].region == AWS_REGION
```

#### Ensuring Test Isolation with Mocked/Patched Objects

In all above scenarios, check execution must occur within the context of mocked or patched objects. This guarantees that the test only evaluates objects explicitly created within its scope, preventing interference from shared state or external dependencies.

#### Handling Partially Covered API Calls

When a service requires API calls that are partially covered by the Moto decorator, additional mocking is necessary. In such cases, custom mocked API calls must be implemented alongside Moto to ensure full coverage.

To achieve this, mock the `botocore.client.BaseClient._make_api_call` function—the method responsible for making actual API requests to AWS—using `mock.patch <https://docs.python.org/3/library/unittest.mock.html#patch>`:

```python

import boto3
import botocore
from unittest.mock import patch
from moto import mock_aws

# Original botocore _make_api_call function

orig = botocore.client.BaseClient._make_api_call

# Mocked botocore _make_api_call function

def mock_make_api_call(self, operation_name, kwarg):

    # The 'operation_name' follows the snake_case format (get_account_password_policy),
    # but we use the PascalCase form (GetAccountPasswordPolicy) for consistency with Boto3 conventions.

    # Reference: https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    if operation_name == 'GetAccountPasswordPolicy':
        return {
            'PasswordPolicy': {
                'MinimumPasswordLength': 123,
                'RequireSymbols': True|False,
                'RequireNumbers': True|False,
                'RequireUppercaseCharacters': True|False,
                'RequireLowercaseCharacters': True|False,
                'AllowUsersToChangePassword': True|False,
                'ExpirePasswords': True|False,
                'MaxPasswordAge': 123,
                'PasswordReusePrevention': 123,
                'HardExpiry': True|False
            }
        }

    # If API call patching is not required, return the original method execution.

    return orig(self, operation_name, kwarg)

# Test class naming convention: Test_<check_name>

class Test_iam_password_policy_uppercase:

  # Apply custom API call mock decorator for the required service

  @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)

  # Also include IAM Moto decorator for supported API calls

  @mock_iam

  # Test naming convention: test_<service>_<check_name>_<test_action>

  def test_iam_password_policy_no_uppercase_flag(self):

    # Refer to the previous section for the check test, as the implementation remains unchanged.
```

???+ note
    This example does not use Moto to simplify the setup.
    However, if additional `moto` decorators are applied alongside the patch, Moto will automatically intercept the call to `orig(self, operation_name, kwarg)`.

???+ note
    The source of the above implementation can be found here:[Patch Other Services with Moto](https://docs.getmoto.org/en/latest/docs/services/patching\_other\_services.html)

#### Mocking Several Services

Since the provider is being mocked, multiple attributes can be configured to customize its behavior:

```python
def set_mocked_aws_provider(
    audited_regions: list[str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
    audited_partition: str = AWS_COMMERCIAL_PARTITION,
    expected_checks: list[str] = [],
    profile_region: str = None,
    audit_config: dict = {},
    fixer_config: dict = {},
    scan_unused_services: bool = True,
    audit_session: session.Session = session.Session(
        profile_name=None,
        botocore_session=None,
    ),
    original_session: session.Session = None,
    enabled_regions: set = None,
    arguments: Namespace = Namespace(),
    create_default_organization: bool = True,
) -> AwsProvider:
```

If a test is designed for a check that interacts with multiple provider services, each service used must be individually mocked. For instance, if the check `cloudtrail_logs_s3_bucket_access_logging_enabled` relies on both the CloudTrail and S3 clients, the test's service mocking section should be structured as follows:

```python
with mock.patch(
    "prowler.providers.common.provider.Provider.get_global_provider",
    return_value=set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
    ),
), mock.patch(
    "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
    new=Cloudtrail(
        set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
    ),
), mock.patch(
    "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
    new=S3(
        set_mocked_aws_provider([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
    ),
):
```

As demonstrated in the code above, mocking both the AWS audit information and all utilized services is mandatory for proper test execution.

#### Patching vs. Importing

Properly understanding patching versus importing is critical for unit testing with Prowler checks. Given the dynamic nature of the check-loading mechanism, the process for importing a service client within a check follows this structured approach:

1. `<check>.py`:

    ```python
    from prowler.providers.<provider>.services.<service>.<service>_client import <service>_client
    ```

2. `<service>_client.py`:

    ```python
    from prowler.providers.common.provider import Provider
    from prowler.providers.<provider>.services.<service>.<service>_service import <SERVICE>

    <service>_client = <SERVICE>(Provider.get_global_provider())
    ```

Due to the import path structure, patching certain objects does not always ensure full isolation. If multiple tests—executed sequentially or in parallel—reuse service clients, some instances may already be initialized by another check. This can lead to unintended shared state, affecting test accuracy:

- `<service>_client` imported at `<check>.py`
- `<service>_client` initialised at `<service>_client.py`
- `<SERVICE>` imported at `<service>_client.py`

#### Additional Resources on Mocking Imports

For a deeper understanding of mocking imports in Python, refer to the following article: https://stackoverflow.com/questions/8658043/how-to-mock-an-import

#### Approaches to Mocking a Service Client

1\. Mocking the Service Client at the Service Client Level

2\. Mocking a Service Client via Below Code Implementation

Once all required attributes are configured for the mocked provider, it can be used as the service client for test execution:

```python title="Mocking the service_client"
with mock.patch(
    "prowler.providers.common.provider.Provider.get_global_provider",
    new=set_mocked_aws_provider([<region>]),
), mock.patch(
    "prowler.providers.<provider>.services.<service>.<check>.<check>.<service>_client",
    new=<SERVICE>(set_mocked_aws_provider([<region>])),
):
```

will cause that the service will be initialised twice:

1. When `<SERVICE>(set_mocked_aws_provider([<region>]))` is mocked out using `mock.patch`, it must be properly prepared before patching to ensure test consistency.

2. At the point of patching, in `<service>_client.py`, and since `mock.patch` needs to access said object and initialise it, `<SERVICE>(set_mocked_aws_provider([<region>]))` will be called again.

Later, when importing `<service>_client.py` at `<check>.py`, Python uses the mocked instance since the patch was applied at the correct reference point.

In the [next section](./unit-testing.md#mocking-the-service-and-the-service-client-at-the-service-client-level) we will explore an improved approach to mock objects.

##### Mocking the Service and the Service Client at the Service Client Level

##### Mocking a Service Client via Below Code Implementation

```python title="Mocking the service and the service_client"
with mock.patch(
    "prowler.providers.common.provider.Provider.get_global_provider",
    new=set_mocked_aws_provider([<region>]),
), mock.patch(
    "prowler.providers.<provider>.services.<service>.<SERVICE>",
    new=<SERVICE>(set_mocked_aws_provider([<region>])),
) as service_client, mock.patch(
    "prowler.providers.<provider>.services.<service>.<service>_client.<service>_client",
    new=service_client,
):
```

will cause that the service is initialized only once—at the moment of mocking out `set_mocked_aws_provider([<region>])` using `mock.patch`.

Later, when Python attempts to import the client at the check level, the execution continues using`from prowler.providers.<provider>.services.<service>.<service>_client`. As a result of it being already mocked out, the execution will continue using `service_client` without getting into `<service>_client.py`.

### Testing AWS Services

AWS service testing follows the same methodology as AWS checks:
Verify whether the AWS API calls made by the service are covered by Moto.

Execute tests on the service `__init__` to ensure correct information retrieval.

While service tests resemble *Integration Tests*, as they assess how the service interacts with the provider, they ultimately fall under *Unit Tests*, due to the use of Moto or custom mock objects.

For detailed guidance on test creation and existing service tests, refer to the [AWS checks test](./unit-testing.md#checks) [documentation](https://github.com/prowler-cloud/prowler/tree/master/tests/providers/aws/services).

## GCP

### GCP Check Testing Approach

Currently the GCP Provider does not have a dedicated library for mocking API calls. To ensure proper test isolation, objects must be manually injected into the service client using [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock).

Mocking Service Objects Using MagicMock

The following code demonstrates how to use MagicMock to create service objects for a GCP check test. This is a real-world implementation, adapted for instructional clarity.

```python
from re import search
from unittest import mock

# Import constant values needed in every check

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

# Create a test for the compute_project_os_login_enabled check

class Test_compute_project_os_login_enabled:

    def test_one_compliant_project(self):
        # Import the service resource model to create the mocked object
        from prowler.providers.gcp.services.compute.compute_service import Project
        # Create the custom Project object to be tested
        project = Project(
            id=GCP_PROJECT_ID,
            enable_oslogin=True,
        )
        # Mock IAM client with MagicMock
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = [project]

        # In this scenario, the app_client from the check must be mocked to ensure that the compute_client used in the test is the explicitly created instance.

        # Additionally, the return value of the get_global_provider function is mocked to return the predefined GCP mocked provider from the test fixtures.

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            # Import the check within the two mocks

            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )

            # Executing the IAM Check
            # Once imported, instantiate the check’s class.

            check = compute_project_os_login_enabled()

            # Then run the execute function()
            # against the set up Compute client.

            result = check.execute()

            # Assert the expected results

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Project {project.id} has OS Login enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == project.id
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    # Complementary Test

    # The following is an additional test for a wider scenario coverage

    def test_one_non_compliant_project(self):
        from prowler.providers.gcp.services.compute.compute_service import Project

        project = Project(
            id=GCP_PROJECT_ID,
            enable_oslogin=False,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = [project]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )

            check = compute_project_os_login_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Project {project.id} does not have OS Login enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == project.id
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

```

### Testing GCP Services

The testing of Google Cloud Services follows the same principles as the one of Google Cloud checks. While all API calls must be mocked, attribute setup for API calls in this scenario is defined in the fixtures file, specifically within the [fixtures file](https://github.com/prowler-cloud/prowler/blob/master/tests/providers/gcp/gcp_fixtures.py) in the `mock_api_client` function.

???+ important
    Every method within a service must be tested to ensure full coverage and accurate validation.

The following example presents a real testing class, but includes additional comments for educational purposes, explaining key concepts and implementation details.

```python title="BigQuery Service Test"

# Import unittest.mock.patch to enable object patching
# This prevents shared objects between tests, ensuring test isolation

from unittest.mock import patch

# Import the class needed from the service file

from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery

# Use necessary constants and functions from fixtures file

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestBigQueryService:
    # The only method needed to test full service
    def test_service(self):
        # Mocking '__is_api_active__' ensures that the test utilizes the predefined mocked project instead of a real instance.
        # Additionally, all client interactions are patched to use the mocked API calls.
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            # Instantiate an object of class with the mocked provider
            bigquery_client = BigQuery(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            # Verify that all attributes of the tested class are correctly initialized based on the API calls mocked from the GCP fixture file.
            assert bigquery_client.service == "bigquery"
            assert bigquery_client.project_ids == [GCP_PROJECT_ID]

            assert len(bigquery_client.datasets) == 2

            assert bigquery_client.datasets[0].name == "unique_dataset1_name"
            assert bigquery_client.datasets[0].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[0].region == "US"
            assert bigquery_client.datasets[0].cmk_encryption
            assert bigquery_client.datasets[0].public
            assert bigquery_client.datasets[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.datasets[1].name == "unique_dataset2_name"
            assert bigquery_client.datasets[1].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[1].region == "EU"
            assert not bigquery_client.datasets[1].cmk_encryption
            assert not bigquery_client.datasets[1].public
            assert bigquery_client.datasets[1].project_id == GCP_PROJECT_ID

            assert len(bigquery_client.tables) == 2

            assert bigquery_client.tables[0].name == "unique_table1_name"
            assert bigquery_client.tables[0].id.__class__.__name__ == "str"
            assert bigquery_client.tables[0].region == "US"
            assert bigquery_client.tables[0].cmk_encryption
            assert bigquery_client.tables[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.tables[1].name == "unique_table2_name"
            assert bigquery_client.tables[1].id.__class__.__name__ == "str"
            assert bigquery_client.tables[1].region == "US"
            assert not bigquery_client.tables[1].cmk_encryption
            assert bigquery_client.tables[1].project_id == GCP_PROJECT_ID
```

Clarifying Value Origins with an Example

Understanding where specific values originate can be challenging, so the following example provides clarity.

- Step 1: Identify the API Call for Dataset Retrieval

    To determine how datasets are obtained, examine the API call used by the service. In this case, the relevant service call is: `self.client.datasets().list(projectId=project_id)`.

- Step 2: Mocking the API Call in the Fixture File

    In the fixture file, mock this call in the `MagicMock` client, in the function `mock_api_client`.

- Step 3: Structuring the Mock Function

    The best approach for mocking is to adhere to the service’s existing format:

Define a dedicated function that modifies the client.

Follow the naming convention: `mock_api_<endpoint>_calls` (*endpoint* refers to the first attribute pointed after *client*).

For BigQuery, the mock function is called `mock_api_dataset_calls`. Within this function, an assignment is made for use in the `_get_datasets` method of the BigQuery class:

```python
# Mocking datasets
dataset1_id = str(uuid4())
dataset2_id = str(uuid4())

client.datasets().list().execute.return_value = {
    "datasets": [
        {
            "datasetReference": {
                "datasetId": "unique_dataset1_name",
                "projectId": GCP_PROJECT_ID,
            },
            "id": dataset1_id,
            "location": "US",
        },
        {
            "datasetReference": {
                "datasetId": "unique_dataset2_name",
                "projectId": GCP_PROJECT_ID,
            },
            "id": dataset2_id,
            "location": "EU",
        },
    ]
}
```

## Azure

### Azure Check Testing Approach

Currently the Azure Provider does not have a dedicated library for mocking API calls. To ensure proper test isolation, objects must be manually injected into the service client using [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock).

Mocking Service Objects Using MagicMock

The following code demonstrates how to use MagicMock to create service objects for an Azure check test. This is a real-world implementation, adapted for instructional clarity.

```python title="app_ensure_http_is_redirected_to_https_test.py"

# Import unittest.mock to enable object patching
# This prevents shared objects between tests, ensuring test isolation

from unittest import mock

from uuid import uuid4

# Import some constans values needed in almost every check

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

# Create a test for the app_ensure_http_is_redirected_to_https check

class Test_app_ensure_http_is_redirected_to_https:

    # Test naming convention: test_<service>_<check_name>_<test_action>
    def test_app_http_to_https_disabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        # Mock IAM client with MagicMock
        app_client = mock.MagicMock

        # In this scenario, the app_client from the check must be mocked to ensure that the app_client used in the test is the explicitly created instance.

        # Additionally, the return value of the get_global_provider function is mocked to return the predefined Azure mocked provider from the test fixtures.

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            # Import the check within the two mocks
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )
            # Import the service resource model to create the mocked object
            from prowler.providers.azure.services.app.app_service import WebApp

            # Create the custom App object to be tested
            app_client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    resource_id: WebApp(
                        resource_id=resource_id,
                        name="app_id-1",
                        auth_enabled=True,
                        configurations=mock.MagicMock(),
                        client_cert_mode="Ignore",
                        https_only=False,
                        identity=None,
                        location="West Europe",
                    )
                }
            }
            # Executing the IAM Check
            # Once imported, instantiate the check’s class.
            check = app_ensure_http_is_redirected_to_https()
            # Then run the execute function()
            # against the set up App client.
            result = check.execute()
            # Assert the expected results
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"HTTP is not redirected to HTTPS for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION_ID}'."
            )
            assert result[0].resource_name == "app_id-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

    # Complementary Test
    # The following is an additional test for a wider scenario coverage

    def test_app_http_to_https_enabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )
            from prowler.providers.azure.services.app.app_service import WebApp

            app_client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    resource_id: WebApp(
                        resource_id=resource_id,
                        name="app_id-1",
                        auth_enabled=True,
                        configurations=mock.MagicMock(),
                        client_cert_mode="Ignore",
                        https_only=True,
                        identity=None,
                        location="West Europe",
                    )
                }
            }
            check = app_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"HTTP is redirected to HTTPS for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION_ID}'."
            )
            assert result[0].resource_name == "app_id-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

```

### Testing Azure Services

The testing of Azure Services follows the same principles as the one of Google Cloud checks. All API calls are still mocked, but for methods that initialize attributes via an API call, use the [patch](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.patch) decorator at the beginning of the class to ensure proper mocking.

???+ important "Remember"
    Every method within a service must be tested to ensure full coverage and accurate validation.

The following example presents a real testing class, but includes additional comments for educational purposes, explaining key concepts and implementation details.

```python title="AppInsights Service Test"

# Import unittest.mock.patch to enable object patching
# This prevents shared objects between tests, ensuring test isolation

from unittest.mock import patch

# Import the models needed from the service file

from prowler.providers.azure.services.appinsights.appinsights_service import (
    AppInsights,
    Component,
)

# Import some constans values needed in almost every check

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

# Function to mock the service function _get_components; the aim of this function is to return a possible value that a real function could return.

def mock_appinsights_get_components(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "app_id-1": Component(
                resource_id="/subscriptions/resource_id",
                resource_name="AppInsightsTest",
                location="westeurope",
            )
        }
    }

# Patch decorator to use the mocked function instead of the function with the real API call

@patch(
    "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
    new=mock_appinsights_get_components,
)
class Test_AppInsights_Service:
    # Mandatory test for every service; this method tests if the instance of the client is correct.
    def test_get_client(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "ApplicationInsightsManagementClient"
        )
    # Second typical method that tests if subscriptions are defined inside the client object.
    def test__get_subscriptions__(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert app_insights.subscriptions.__class__.__name__ == "dict"
    # Test for the function _get_components; the mocked function is used within this client.
    def test_get_components(self):
        appinsights = AppInsights(set_mocked_azure_provider())
        assert len(appinsights.components) == 1
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].resource_name
            == "AppInsightsTest"
        )
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].location
            == "westeurope"
        )
```
