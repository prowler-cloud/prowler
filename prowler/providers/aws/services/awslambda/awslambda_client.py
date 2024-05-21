from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
from prowler.providers.common.provider import Provider

awslambda_client = Lambda(Provider.get_global_provider())
