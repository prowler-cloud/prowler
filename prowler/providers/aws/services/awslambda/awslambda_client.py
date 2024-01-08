from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
from prowler.providers.common.common import get_global_provider

awslambda_client = Lambda(get_global_provider())
