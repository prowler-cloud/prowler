import json
from enum import Enum
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.service.service import AWSService


class OAM(AWSService):
    """AWS Observability Access Manager service class for monitoring account sinks.

    A sink is the resource a monitoring account exposes so that source accounts can link
    their observability data into it. This class lists the sinks in the audited account
    and, for each one, collects the resource policy that decides which accounts may link
    to it, plus its tags.

    Attributes:
        sinks: Dictionary mapping sink ARNs to Sink objects.
    """

    def __init__(self, provider: AwsProvider) -> None:
        """Initializes the OAM service class.

        Args:
            provider: AWS provider instance for making API calls.
        """
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.sinks = {}
        self.__threading_call__(self._list_sinks)
        self.__threading_call__(self._get_sink_policy)
        self.__threading_call__(self._list_tags_for_resource)

    def _list_sinks(self, regional_client):
        """Lists all OAM sinks in the specified region.

        Retrieves every sink using pagination and creates a Sink object for each one
        that passes the audit resource filter.

        Args:
            regional_client: AWS regional client for the OAM service.

        Note:
            AWS API errors are caught and logged internally; this method does not
            raise them to the caller.
        """
        logger.info("OAM - Listing sinks...")
        try:
            list_sinks_paginator = regional_client.get_paginator("list_sinks")
            for page in list_sinks_paginator.paginate():
                for sink in page["Items"]:
                    sink_arn = sink["Arn"]
                    if not self.audit_resources or (
                        is_resource_filtered(sink_arn, self.audit_resources)
                    ):
                        self.sinks[sink_arn] = Sink(
                            arn=sink_arn,
                            id=sink["Id"],
                            name=sink["Name"],
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_sink_policy(self, regional_client):
        """Retrieves the resource policy of every sink in the specified region.

        A policy is stored on the sink only when it decodes to a populated JSON object,
        so ``Sink.policy`` is a readable policy document or None and never a shape a
        consumer cannot evaluate.

        Args:
            regional_client: AWS regional client for the OAM service.

        Note:
            AWS API errors are caught and logged internally; this method does not
            raise them to the caller.
        """
        logger.info("OAM - Getting sink policies...")
        for sink in self.sinks.values():
            if sink.region != regional_client.region:
                continue
            try:
                policy = regional_client.get_sink_policy(SinkIdentifier=sink.arn).get(
                    "Policy"
                )
                document = json.loads(policy) if policy else None
                if isinstance(document, dict) and document:
                    sink.policy = document
                    sink.policy_state = SinkPolicyState.AVAILABLE
                else:
                    # GetSinkPolicy SUCCEEDED but returned nothing usable -- an absent
                    # Policy member, an empty string, or a document that does not decode
                    # to a populated JSON object. Absence of a policy is reported by
                    # ResourceNotFoundException below, not by a successful empty response,
                    # so this is a response we do not understand rather than a determined
                    # ABSENT. Calling it ABSENT would PASS the sink as unlinkable.
                    #
                    # The isinstance guard is what keeps a non-object out of Sink.policy:
                    # pydantic.v1 does not validate assignment, so a document decoding to
                    # a string or a list would be stored despite the dict annotation, read
                    # as truthy, marked AVAILABLE, and then abort the consuming check on
                    # the first .get() -- discarding the findings for every other sink too.
                    sink.policy_state = SinkPolicyState.UNKNOWN
            except ClientError as error:
                if error.response["Error"]["Code"] == "ResourceNotFoundException":
                    # No policy is attached to the sink, so no account can link to it.
                    # This is a determined state, unlike an unreadable policy below.
                    sink.policy_state = SinkPolicyState.ABSENT
                else:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_tags_for_resource(self, regional_client):
        """Lists the tags of every sink in the specified region.

        Args:
            regional_client: AWS regional client for the OAM service.

        Note:
            AWS API errors are caught and logged internally; this method does not
            raise them to the caller.
        """
        logger.info("OAM - Listing tags for sinks...")
        for sink in self.sinks.values():
            if sink.region != regional_client.region:
                continue
            try:
                sink.tags = [
                    regional_client.list_tags_for_resource(ResourceArn=sink.arn)["Tags"]
                ]
            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class SinkPolicyState(Enum):
    """Whether the sink's resource policy could be determined.

    ABSENT and UNKNOWN are distinct: the first means the service answered that no policy is
    attached, the second means the policy was never read. A check must not treat the second as
    compliant.
    """

    AVAILABLE = "AVAILABLE"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class Sink(BaseModel):
    """Model representing an AWS Observability Access Manager sink.

    Attributes:
        arn: The ARN (Amazon Resource Name) of the sink.
        id: The random ID string that AWS generated as part of the sink ARN.
        name: The name of the sink.
        region: The AWS region where the sink exists.
        policy: The decoded sink resource policy, or None when policy_state is not
            AVAILABLE.
        policy_state: Whether the resource policy could be determined.
        tags: Optional list of sink tags.
    """

    arn: str
    id: str
    name: str
    region: str
    policy: Optional[dict] = None
    policy_state: SinkPolicyState = SinkPolicyState.UNKNOWN
    tags: Optional[list] = []
