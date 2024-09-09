# Unit Tests

The unit tests for the Prowler checks varies between each provider supported.

Here we left some good reads about unit testing and things we've learnt through all the process.

**Python Testing**

- https://docs.python-guide.org/writing/tests/

**Where to patch**

- https://docs.python.org/3/library/unittest.mock.html#where-to-patch
- https://stackoverflow.com/questions/893333/multiple-variables-in-a-with-statement
- ​https://docs.python.org/3/reference/compound_stmts.html#the-with-statement

**Utils to trace mocking and test execution**

- https://news.ycombinator.com/item?id=36054868
- https://docs.python.org/3/library/sys.html#sys.settrace
- https://github.com/kunalb/panopticon

## General Recommendations

When creating tests for some provider's checks we follow these guidelines trying to cover as much test scenarios as possible:

1. Create a test without resource to generate 0 findings, because Prowler will generate 0 findings if a service does not contain the resources the check is looking for audit.
2. Create test to generate both a `PASS` and a `FAIL` result.
3. Create tests with more than 1 resource to evaluate how the check behaves and if the number of findings is right.

## How to run Prowler tests

To run the Prowler test suite you need to install the testing dependencies already included in the `pyproject.toml` file. If you didn't install it yet please read the developer guide introduction [here](./introduction.md#get-the-code-and-install-all-dependencies).

Then in the project's root path execute `pytest -n auto -vvv -s -x` or use the `Makefile` with `make test`.

Other commands to run tests:

- Run tests for a provider: `pytest -n auto -vvv -s -x tests/providers/<provider>/services`
- Run tests for a provider service: `pytest -n auto -vvv -s -x tests/providers/<provider>/services/<service>`
- Run tests for a provider check: `pytest -n auto -vvv -s -x tests/providers/<provider>/services/<service>/<check>`

???+ note
    Refer to the [pytest documentation](https://docs.pytest.org/en/7.1.x/getting-started.html) documentation for more information.

## AWS

For the AWS provider we have ways to test a Prowler check based on the following criteria:

???+ note
    We use and contribute to the [Moto](https://github.com/getmoto/moto) library which allows us to easily mock out tests based on AWS infrastructure. **It's awesome!**

- AWS API calls covered by [Moto](https://github.com/getmoto/moto):
    - Service tests with `@mock_<service>`
    - Checks tests with `@mock_<service>`
- AWS API calls not covered by Moto:
    - Service test with `mock_make_api_call`
    - Checks tests with [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock)
- AWS API calls partially covered by Moto:
    - Service test with `@mock_<service>` and `mock_make_api_call`
    - Checks tests with `@mock_<service>` and `mock_make_api_call`

In the following section we are going to explain all of the above scenarios with examples. The main difference between those scenarios comes from if the [Moto](https://github.com/getmoto/moto) library covers the AWS API calls made by the service. You can check the covered API calls [here](https://github.com/getmoto/moto/blob/master/IMPLEMENTATION_COVERAGE.md).

### Checks

For the AWS tests examples we are going to use the tests for the `iam_password_policy_uppercase` check.

This section is going to be divided based on the API coverage of the [Moto](https://github.com/getmoto/moto) library.

#### API calls covered

If the [Moto](https://github.com/getmoto/moto) library covers the API calls we want to test, we can use the `@mock_<service>` decorator. This will mocked out all the API calls made to AWS keeping the state within the code decorated, in this case the test function.

```python
# We need to import the unittest.mock to allow us to patch some objects
# not to use shared ones between test, hence to isolate the test
from unittest import mock

# Boto3 client and session to call the AWS APIs
from boto3 import client, session

# Moto decorator for the IAM service we want to mock
from moto import mock_iam

# Constants used
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


# We always name the test classes like Test_<check_name>
class Test_iam_password_policy_uppercase:

  # We include the Moto decorator for the service we want to use
  # You can include more than one if two or more services are
  # involved in test
  @mock_iam
  # We name the tests with test_<service>_<check_name>_<test_action>
  def test_iam_password_policy_no_uppercase_flag(self):
    # First, we have to create an IAM client
    iam_client = client("iam", region_name=AWS_REGION)

    # Then, since all the AWS accounts have a password
    # policy we want to set to False the RequireUppercaseCharacters
    iam_client.update_account_password_policy(RequireUppercaseCharacters=False)

    # The aws_provider is mocked using set_mocked_aws_provider to use it as the return of the get_global_provider method.
    # this mocked provider is defined in fixtures
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    # The Prowler service import MUST be made within the decorated
    # code not to make real API calls to the AWS service.
    from prowler.providers.aws.services.iam.iam_service import IAM

    # Prowler for AWS uses a shared object called aws_provider where it stores
    # the info related with the provider
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ),
    # We have to mock also the iam_client from the check to enforce that the iam_client used is the one
    # created within this check because patch != import, and if you execute tests in parallel some objects
    # can be already initialised hence the check won't be isolated
      mock.patch(
        "prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase.iam_client",
        new=IAM(aws_provider),
    ):
        # We import the check within the two mocks not to initialise the iam_client with some shared information from
        # the aws_provider or the IAM service.
        from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
            iam_password_policy_uppercase,
        )

        # Once imported, we only need to instantiate the check's class
        check = iam_password_policy_uppercase()

        # And then, call the execute() function to run the check
        # against the IAM client we've set up.
        result = check.execute()

        # Last but not least, we need to assert all the fields
        # from the check's results
        assert len(results) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == "IAM password policy does not require at least one uppercase letter."
        assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_tags == []
        assert result[0].region == AWS_REGION
```

#### API calls not covered

If the IAM service for the check's we want to test is not covered by Moto, we have to inject the objects in the service client using [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock). As we have pointed above, we cannot instantiate the service since it will make real calls to the AWS APIs.

???+ note
    The following example uses the IAM GetAccountPasswordPolicy which is covered by Moto but this is only for demonstration purposes.

The following code shows how to use MagicMock to create the service objects.

```python
# We need to import the unittest.mock to allow us to patch some objects
# not to use shared ones between test, hence to isolate the test
from unittest import mock

# Constants used
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


# We always name the test classes like Test_<check_name>
class Test_iam_password_policy_uppercase:

  # We name the tests with test_<service>_<check_name>_<test_action>
  def test_iam_password_policy_no_uppercase_flag(self):
    # Mocked client with MagicMock
    mocked_iam_client = mock.MagicMock

    # Since the IAM Password Policy has their own model we have to import it
    from prowler.providers.aws.services.iam.iam_service import PasswordPolicy

    # Create the mock PasswordPolicy object
    mocked_iam_client.password_policy = PasswordPolicy(
        length=5,
        symbols=True,
        numbers=True,
        # We set the value to False to test the check
        uppercase=False,
        lowercase=True,
        allow_change=False,
        expiration=True,
    )

    # In this scenario we have to mock also the IAM service and the iam_client from the check to enforce    # that the iam_client used is the one created within this check because patch != import, and if you     # execute tests in parallel some objects can be already initialised hence the check won't be isolated.
    # In this case we don't use the Moto decorator, we use the mocked IAM client for both objects
    with mock.patch(
        "prowler.providers.aws.services.iam.iam_service.IAM",
        new=mocked_iam_client,
    ), mock.patch(
        "prowler.providers.aws.services.iam.iam_client.iam_client",
        new=mocked_iam_client,
    ):
        # We import the check within the two mocks not to initialise the iam_client with some shared information from
        # the aws_provider or the IAM service.
        from prowler.providers.aws.services.iam.iam_password_policy_uppercase.iam_password_policy_uppercase import (
            iam_password_policy_uppercase,
        )

        # Once imported, we only need to instantiate the check's class
        check = iam_password_policy_uppercase()

        # And then, call the execute() function to run the check
        # against the IAM client we've set up.
        result = check.execute()

        # Last but not least, we need to assert all the fields
        # from the check's results
        assert len(results) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == "IAM password policy does not require at least one uppercase letter."
        assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_tags == []
        assert result[0].region == AWS_REGION
```

As it can be seen in the above scenarios, the check execution should always be into the context of mocked/patched objects. This way we ensure it reviews only the objects created under the scope the test.

#### API calls partially covered

If the API calls we want to use in the service are partially covered by the Moto decorator we have to create our own mocked API calls to use it in combination.

To do so, you need to mock the `botocore.client.BaseClient._make_api_call` function, which is the Boto3 function in charge of making the real API call to the AWS APIs, using `mock.patch <https://docs.python.org/3/library/unittest.mock.html#patch>`:


```python

import boto3
import botocore
from unittest.mock import patch
from moto import mock_iam

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    # As you can see the operation_name has the get_account_password_policy snake_case form but
    # we are using the GetAccountPasswordPolicy form.
    # Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
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
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)

# We always name the test classes like Test_<check_name>
class Test_iam_password_policy_uppercase:

  # We include the custom API call mock decorator for the service we want to use
  @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
  # We include also the IAM Moto decorator for the API calls supported
  @mock_iam
  # We name the tests with test_<service>_<check_name>_<test_action>
  def test_iam_password_policy_no_uppercase_flag(self):
    # Check the previous section to see the check test since is the same
```

Note that this does not use Moto, to keep it simple, but if you use any `moto`-decorators in addition to the patch, the call to `orig(self, operation_name, kwarg)` will be intercepted by Moto.

???+ note
    The above code comes from here https://docs.getmoto.org/en/latest/docs/services/patching_other_services.html

#### Mocking more than one service

Since we are mocking the provider, it can be customized setting multiple attributes to the provider:
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

If the test your are creating belongs to a check that uses more than one provider service, you should mock each of the services used. For example, the check `cloudtrail_logs_s3_bucket_access_logging_enabled` requires the CloudTrail and the S3 client, hence the service's mock part of the test will be as follows:


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


As you can see in the above code, it is required to mock the AWS audit info and both services used.


#### Patching vs. Importing

This is an important topic within the Prowler check's unit testing. Due to the dynamic nature of the check's load, the process of importing the service client from a check is the following:

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

Due to the above import path it's not the same to patch the following objects because if you run a bunch of tests, either in parallel or not, some clients can be already instantiated by another check, hence your test execution will be using another test's service instance:

- `<service>_client` imported at `<check>.py`
- `<service>_client` initialised at `<service>_client.py`
- `<SERVICE>` imported at `<service>_client.py`

A useful read about this topic can be found in the following article: https://stackoverflow.com/questions/8658043/how-to-mock-an-import


#### Different ways to mock the service client

##### Mocking the service client at the service client level

Mocking a service client using the following code ...

Once the needed attributes are set for the mocked provider, you can use the mocked provider:
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

1. When the `<SERVICE>(set_mocked_aws_provider([<region>]))` is mocked out using `mock.patch` to have the object ready for the patching.
2. At the `<service>_client.py` when we are patching it since the `mock.patch` needs to go to that object an initialise it, hence the `<SERVICE>(set_mocked_aws_provider([<region>]))` will be called again.

Then, when we import the `<service>_client.py` at `<check>.py`, since we are mocking where the object is used, Python will use the mocked one.

In the [next section](./unit-testing.md#mocking-the-service-and-the-service-client-at-the-service-client-level) you will see an improved version to mock objects.


##### Mocking the service and the service client at the service client level
Mocking a service client using the following code ...

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
will cause that the service will be initialised once, just when the `set_mocked_aws_provider([<region>])` is mocked out using `mock.patch`.

Then, at the check_level when Python tries to import the client with `from prowler.providers.<provider>.services.<service>.<service>_client`, since it is already mocked out, the execution will continue using the `service_client` without getting into the `<service>_client.py`.


### Services

For testing the AWS services we have to follow the same logic as with the AWS checks, we have to check if the AWS API calls made by the service are covered by Moto and we have to test the service `__init__` to verify that the information is being correctly retrieved.

The service tests could act as *Integration Tests* since we test how the service retrieves the information from the provider, but since Moto or the custom mock objects mocks that calls this test will fall into *Unit Tests*.

Please refer to the [AWS checks tests](./unit-testing.md#checks) for more information on how to create tests and check the existing services tests [here](https://github.com/prowler-cloud/prowler/tree/master/tests/providers/aws/services).

## GCP

### Checks

For the GCP Provider we don't have any library to mock out the API calls we use. So in this scenario we inject the objects in the service client using [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock).

The following code shows how to use MagicMock to create the service objects for a GCP check test. It is a real example adapted for informative purposes.

```python
from re import search
from unittest import mock

# Import some constant values needed in every check
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

# We are going to create a test for the compute_project_os_login_enabled check
class Test_compute_project_os_login_enabled:

    def test_one_compliant_project(self):
        # Import the service resource model to create the mocked object
        from prowler.providers.gcp.services.compute.compute_service import Project
        # Create the custom Project object to be tested
        project = Project(
            id=GCP_PROJECT_ID,
            enable_oslogin=True,
        )
        # Mocked client with MagicMock
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = [project]

        # In this scenario we have to mock the app_client from the check to enforce that the compute_client used is the one created above
        # And also is mocked the return value of get_global_provider function to return our GCP mocked provider defined in fixtures
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            # We import the check within the two mocks
            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )
            # Once imported, we only need to instantiate the check's class
            check = compute_project_os_login_enabled()
            # And then, call the execute() function to run the check
            # against the Compute client we've set up.
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

    # Complementary test to make more coverage for different scenarios
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

### Services

For testing Google Cloud Services, we have to follow the same logic as with the Google Cloud checks. We still mocking all API calls, but in this case, every API call to set up an attribute is defined in [fixtures file](https://github.com/prowler-cloud/prowler/blob/master/tests/providers/gcp/gcp_fixtures.py) in `mock_api_client` function. Remember that EVERY method of a service must be tested.

The following code shows a real example of a testing class, but it has more comments than usual for educational purposes.

```python title="BigQuery Service Test"
# We need to import the unittest.mock.patch to allow us to patch some objects
# not to use shared ones between test, hence to isolate the test
from unittest.mock import patch
# Import the class needed from the service file
from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery
# Necessary constans and functions from fixtures file
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestBigQueryService:
    # Only method needed to test full service
    def test_service(self):
        # In this case we are mocking the __is_api_active__ to ensure our mocked project is used
        # And all the client to use our mocked API calls
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
            # Check all attributes of the tested class is well set up according API calls mocked from GCP fixture file
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
As it can be confusing where all these values come from, I'll give an example to make this clearer. First we need to check
what is the API call used to obtain the datasets. In this case if we check the service the call is
`self.client.datasets().list(projectId=project_id)`.

Now in the fixture file we have to mock this call in our `MagicMock` client in the function `mock_api_client`. The best way to mock
is following the actual format, add one function where the client is passed to be changed, the format of this function name must be
`mock_api_<endpoint>_calls` (*endpoint* refers to the first attribute pointed after *client*).

In the example of BigQuery the function is called `mock_api_dataset_calls`. And inside of this function we found an assignation to
be used in the `_get_datasets` method in BigQuery class:

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

### Checks

For the Azure Provider we don't have any library to mock out the API calls we use. So in this scenario we inject the objects in the service client using [MagicMock](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.MagicMock).

The following code shows how to use MagicMock to create the service objects for a Azure check test. It is a real example adapted for informative purposes.

```python title="app_ensure_http_is_redirected_to_https_test.py"
# We need to import the unittest.mock to allow us to patch some objects
# not to use shared ones between test, hence to isolate the test
from unittest import mock

from uuid import uuid4

# Import some constans values needed in almost every check
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

# We are going to create a test for the app_ensure_http_is_redirected_to_https check
class Test_app_ensure_http_is_redirected_to_https:

    # We name the tests with test_<service>_<check_name>_<test_action>
    def test_app_http_to_https_disabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        # Mocked client with MagicMock
        app_client = mock.MagicMock

        # In this scenario we have to mock the app_client from the check to enforce that the app_client used is the one created above
        # And also is mocked the return value of get_global_provider function to return our Azure mocked provider defined in fixtures
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            # We import the check within the two mocks
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )
            # Import the service resource model to create the mocked object
            from prowler.providers.azure.services.app.app_service import WebApp

            # Create the custom App object to be tested
            app_client.apps = {
                AZURE_SUBSCRIPTION_ID: {
                    "app_id-1": WebApp(
                        resource_id=resource_id,
                        auth_enabled=True,
                        configurations=mock.MagicMock(),
                        client_cert_mode="Ignore",
                        https_only=False,
                        identity=None,
                        location="West Europe",
                    )
                }
            }
            # Once imported, we only need to instantiate the check's class
            check = app_ensure_http_is_redirected_to_https()
            # And then, call the execute() function to run the check
            # against the App client we've set up.
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

    # Complementary test to make more coverage for different scenarios
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
                    "app_id-1": WebApp(
                        resource_id=resource_id,
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

### Services

For testing Azure services, we have to follow the same logic as with the Azure checks. We still mock all the API calls, but in this case, every method that uses an API call to set up an attribute is mocked with the [patch](https://docs.python.org/3/library/unittest.mock.html#unittest.mock.patch) decorator at the beginning of the class. Remember that every method of a service MUST be tested.

The following code shows a real example of a testing class, but it has more comments than usual for educational purposes.

```python title="AppInsights Service Test"
# We need to import the unittest.mock.patch to allow us to patch some objects
# not to use shared ones between test, hence to isolate the test
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

# Function to mock the service function _get_components, this function task is to return a possible value that real function could returns
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

# Patch decorator to use the mocked function instead the function with the real API call
@patch(
    "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
    new=mock_appinsights_get_components,
)
class Test_AppInsights_Service:
    # Mandatory test for every service, this method test the instance of the client is correct
    def test_get_client(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "ApplicationInsightsManagementClient"
        )
    # Second typical method that test if subscriptions is defined inside the client object
    def test__get_subscriptions__(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert app_insights.subscriptions.__class__.__name__ == "dict"
    # Test for the function _get_components, inside this client is used the mocked function
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
