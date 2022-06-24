from moto import mock_sts, mock_iam
import boto3
from providers.aws.aws_provider import validate_credentials, assume_role
from providers.aws.models import AWS_Audit_Info, AWS_Assume_Role
from providers.aws.aws_provider import AWS_Provider
import sure

ACCOUNT_ID = 123456789012

@mock_sts
@mock_iam
def test_validate_credentials():
    # Create a mock IAM user
    iam_client = boto3.client("iam", region_name="us-east-1")
    iam_user = iam_client.create_user(UserName="test-user")["User"]
    # Create a mock IAM access keys
    access_key = iam_client.create_access_key(UserName=iam_user["UserName"])["AccessKey"]
    access_key_id = access_key["AccessKeyId"]
    secret_access_key = access_key["SecretAccessKey"]
    # Create AWS session to validate
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name="us-east-1")
    # Validate AWS session
    get_caller_identity = validate_credentials(session)

    get_caller_identity["Arn"].should.equal(iam_user["Arn"])
    get_caller_identity["UserId"].should.equal(iam_user["UserId"])
    # assert get_caller_identity["UserId"] == str(ACCOUNT_ID)


@mock_iam
@mock_sts
def test_assume_role():
    # Variables
    role_name = "test-role"
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
    session_duration_seconds = 900
    audited_regions = "eu-west-1"
    sessionName = "ProwlerProAsessmentSession"
    # Boto 3 client to create our user
    iam_client = boto3.client("iam", region_name="us-east-1")
    # IAM user
    iam_user = iam_client.create_user(UserName="test-user")["User"]
    access_key = iam_client.create_access_key(UserName=iam_user["UserName"])["AccessKey"]
    access_key_id = access_key["AccessKeyId"]
    secret_access_key = access_key["SecretAccessKey"]
    # New Boto3 session with the previously create user
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name="us-east-1")

    # Fulfil the input session object for Prowler
    audit_info = AWS_Audit_Info(
        original_session=session,
        audit_session=None,
        audited_account=None,
        audited_partition=None,
        profile=None,
        credentials=None,
        assumed_role_info=AWS_Assume_Role(
            role_arn=role_arn,
            session_duration=session_duration_seconds,
            external_id=None
        ),
        audited_regions=audited_regions,
    )
    # Do we need this to test assume role?
    # audit_info.original_session = AWS_Provider(audit_info).get_session()

    # Call assume_role
    assume_role_response = assume_role(audit_info)
    # Recover credentials for the assume role operation
    credentials = assume_role_response["Credentials"]
    # Test the response
    ## SessionToken
    credentials["SessionToken"].should.have.length_of(356)
    credentials["SessionToken"].startswith("FQoGZXIvYXdzE")
    ## AccessKeyId
    credentials["AccessKeyId"].should.have.length_of(20)
    credentials["AccessKeyId"].startswith("ASIA")
    ## SecretAccessKey
    credentials["SecretAccessKey"].should.have.length_of(40)
    ## Assumed Role
    assume_role_response["AssumedRoleUser"]["Arn"].should.equal(
        f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role_name}/{sessionName}"
    )
    ## AssumedRoleUser
    assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].startswith("AROA")
    assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].endswith(
        ":" + sessionName
    )
    assume_role_response["AssumedRoleUser"]["AssumedRoleId"].should.have.length_of(
        21 + 1 + len(sessionName)
    )



# @mock_iam
# def create_iam_user(user_name: str):
#     iam_client = boto3.client("iam", region_name="us-east-1")
#     return iam_client.create_user(UserName="test-user")["User"]

# @mock_iam
# def create_iam_access_keys(iam_user: str):
#     iam_client = boto3.client("iam", region_name="us-east-1")
#     return iam_client.create_access_key(UserName="test-user")["AccessKey"]

# @mock_iam
# def create_session(access_key_id:str, secret_access_key: str, region: str):
#     return boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)
