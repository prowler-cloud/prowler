from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.service.service import AWSService
from prowler.providers.aws.services.opensearchserverless.lib.network_policy import (
    NetworkPolicyRule,
    parse_network_policy,
    resource_pattern_matches,
)


class OpenSearchServerless(AWSService):
    """Collects OpenSearch Serverless collections and their network exposure.

    For each region with collections, the service reads every network
    security policy, flattens it into rules and attaches to each collection
    the rules whose patterns cover it. A region is only marked as complete
    when all its network policies were listed and read; any failure leaves
    it incomplete so that checks never assume the absence of public access.
    Regions whose collections could not be fully listed are recorded too,
    so that checks can report them instead of treating them as empty.
    """

    def __init__(self, provider: AwsProvider) -> None:
        """Initialize the service and collect all the data it needs.

        Args:
            provider: The AWS provider used to create the regional clients.
        """
        super().__init__("opensearchserverless", provider)
        self.collections = {}
        self.collections_listing_failed_regions = set()
        self.network_rules = {}
        self.network_policies_complete_regions = set()
        self.__threading_call__(self._list_collections)
        regions_with_collections = {
            collection.region for collection in self.collections.values()
        }
        self.__threading_call__(
            self._list_network_rules,
            [
                regional_client
                for region, regional_client in self.regional_clients.items()
                if region in regions_with_collections
            ],
        )
        self._map_network_rules_to_collections()
        self.__threading_call__(self._list_tags_for_resource, self.collections.values())

    def _list_collections(self, regional_client):
        """List the collections of a region, following pagination.

        If any page fails, the collections already listed are kept and the
        region is recorded as incompletely listed.

        Args:
            regional_client: The OpenSearch Serverless client of the region.
        """
        logger.info("OpenSearchServerless - Listing collections...")
        try:
            next_token = None
            while True:
                kwargs = {"nextToken": next_token} if next_token else {}
                response = regional_client.list_collections(**kwargs)
                for summary in response.get("collectionSummaries", []):
                    arn = summary["arn"]
                    if not self.audit_resources or is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        self.collections[arn] = Collection(
                            id=summary["id"],
                            name=summary["name"],
                            arn=arn,
                            status=summary.get("status"),
                            region=regional_client.region,
                        )
                next_token = response.get("nextToken")
                if not next_token:
                    break
        except Exception as error:
            self.collections_listing_failed_regions.add(regional_client.region)
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_network_policy_names(self, regional_client) -> list[str]:
        """Return the names of all network policies of a region.

        Args:
            regional_client: The OpenSearch Serverless client of the region.

        Returns:
            The names of every network policy, across all pages.
        """
        policy_names = []
        next_token = None
        while True:
            kwargs = {"type": "network"}
            if next_token:
                kwargs["nextToken"] = next_token
            response = regional_client.list_security_policies(**kwargs)
            for summary in response.get("securityPolicySummaries", []):
                policy_names.append(summary["name"])
            next_token = response.get("nextToken")
            if not next_token:
                return policy_names

    def _list_network_rules(self, regional_client):
        """Read and flatten every network policy of a region.

        Readable rules are always stored, even when another policy fails, so
        that a readable public rule can still be reported. The region is
        marked as complete only as the last step, after every policy was
        listed, read and parsed without errors.

        Args:
            regional_client: The OpenSearch Serverless client of the region.
        """
        logger.info("OpenSearchServerless - Getting network policies...")
        region = regional_client.region
        rules = []
        all_policies_read = True
        try:
            for policy_name in self._list_network_policy_names(regional_client):
                try:
                    response = regional_client.get_security_policy(
                        type="network", name=policy_name
                    )
                    parsed_rules = parse_network_policy(
                        policy_name,
                        response.get("securityPolicyDetail", {}).get("policy"),
                    )
                except Exception as error:
                    all_policies_read = False
                    logger.error(
                        f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
                if parsed_rules is None:
                    all_policies_read = False
                    logger.warning(
                        f"{region} -- OpenSearch Serverless network policy {policy_name} has an unexpected format and could not be evaluated."
                    )
                    continue
                rules.extend(parsed_rules)
            if all_policies_read:
                self.network_policies_complete_regions.add(region)
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        finally:
            self.network_rules[region] = rules

    def _map_network_rules_to_collections(self):
        """Attach to each collection the network rules that cover it.

        A rule covers a collection for sure when any of its patterns matches
        it; it is doubtful when no pattern matches for sure but at least one
        cannot be interpreted. Rules that do not cover the collection are not
        stored, so checks cannot mistake them for coverage.
        """
        for collection in self.collections.values():
            collection.network_policies_complete = (
                collection.region in self.network_policies_complete_regions
            )
            for rule in self.network_rules.get(collection.region, []):
                matches = [
                    resource_pattern_matches(pattern, collection.name)
                    for pattern in rule.patterns
                ]
                if True in matches:
                    collection.network_rules.append(rule)
                elif None in matches:
                    collection.doubtful_network_rules.append(rule)

    def _list_tags_for_resource(self, collection):
        """Get the tags of a collection.

        Args:
            collection: The collection whose tags are retrieved.
        """
        logger.info("OpenSearchServerless - Listing tags...")
        try:
            regional_client = self.regional_clients[collection.region]
            response = regional_client.list_tags_for_resource(
                resourceArn=collection.arn
            )
            collection.tags = response.get("tags", [])
        except Exception as error:
            logger.error(
                f"{collection.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Collection(BaseModel):
    """An OpenSearch Serverless collection and the network rules that cover it.

    Attributes:
        id: Collection ID.
        name: Collection name.
        arn: Collection ARN, as returned by AWS (built from the ID).
        status: Collection status (for example ACTIVE or CREATING).
        region: Region of the collection.
        network_rules: Network rules whose patterns cover the collection for
            sure, for its API ("collection") or Dashboards ("dashboard")
            endpoint.
        doubtful_network_rules: Network rules with at least one pattern whose
            coverage cannot be determined and no pattern that covers the
            collection for sure.
        network_policies_complete: True only if every network policy of the
            collection's region was listed and read successfully.
        tags: Collection tags.
    """

    id: str
    name: str
    arn: str
    status: Optional[str]
    region: str
    network_rules: list[NetworkPolicyRule] = []
    doubtful_network_rules: list[NetworkPolicyRule] = []
    network_policies_complete: bool = False
    tags: Optional[list] = []
