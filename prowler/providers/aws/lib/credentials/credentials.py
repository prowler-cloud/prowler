import sys

from boto3 import session

from prowler.lib.logger import logger

AWS_STS_GLOBAL_ENDPOINT_REGION = "us-east-1"


def validate_aws_credentials(validate_session: session, input_regions: list) -> dict:
    try:
        # For a valid STS GetCallerIdentity we have to use the right AWS Region
        if input_regions is None or len(input_regions) == 0:
            if validate_session.region_name is not None:
                aws_region = validate_session.region_name
            else:
                # If there is no region set passed with -f/--region
                # we use the Global STS Endpoint Region, us-east-1
                aws_region = AWS_STS_GLOBAL_ENDPOINT_REGION
        else:
            # Get the first region passed to the -f/--region
            aws_region = input_regions[0]
        validate_credentials_client = validate_session.client("sts", aws_region)
        caller_identity = validate_credentials_client.get_caller_identity()
        # Include the region where the caller_identity has validated the credentials
        caller_identity["region"] = aws_region
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit(1)
    else:
        return caller_identity
