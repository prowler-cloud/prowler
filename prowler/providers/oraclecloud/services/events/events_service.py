"""OCI Events Service Module."""

from typing import List

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Events(OCIService):
    """OCI Events Service class to retrieve event rules and notification topics."""

    def __init__(self, provider):
        """Initialize the Events service."""
        super().__init__("events", provider)
        self.rules = []
        self.topics = []
        self.__threading_call__(self.__list_rules__)
        self.__threading_call__(self.__list_topics__)

    def __get_client__(self, region):
        """Get the Events client for a region."""
        return self._create_oci_client(
            oci.events.EventsClient, config_overrides={"region": region}
        )

    def __list_rules__(self, regional_client):
        """List all event rules."""
        try:
            # Create events client for this region
            events_client = self.__get_client__(regional_client.region)
            if not events_client:
                return

            logger.info(f"Events - Listing Rules in {regional_client.region}...")

            for compartment in self.audited_compartments:
                try:
                    logger.info(
                        f"Events - Checking compartment {compartment.name} ({compartment.id})..."
                    )
                    rules = oci.pagination.list_call_get_all_results(
                        events_client.list_rules, compartment_id=compartment.id
                    ).data

                    logger.info(
                        f"Events - Found {len(rules)} rules in compartment {compartment.name}"
                    )

                    for rule in rules:
                        if rule.lifecycle_state != "DELETED":
                            # Get full rule details including actions
                            try:
                                full_rule = events_client.get_rule(rule_id=rule.id).data

                                # Extract actions from the full rule details
                                actions_list = []
                                if hasattr(full_rule, "actions") and full_rule.actions:
                                    if hasattr(full_rule.actions, "actions"):
                                        # Convert action objects to dictionaries for JSON serialization
                                        for action in full_rule.actions.actions:
                                            action_dict = {
                                                "action_type": (
                                                    action.action_type
                                                    if hasattr(action, "action_type")
                                                    else None
                                                ),
                                                "is_enabled": (
                                                    action.is_enabled
                                                    if hasattr(action, "is_enabled")
                                                    else False
                                                ),
                                                "id": (
                                                    action.id
                                                    if hasattr(action, "id")
                                                    else None
                                                ),
                                            }
                                            actions_list.append(action_dict)

                                self.rules.append(
                                    Rule(
                                        id=full_rule.id,
                                        name=(
                                            full_rule.display_name
                                            if hasattr(full_rule, "display_name")
                                            else full_rule.id
                                        ),
                                        compartment_id=compartment.id,
                                        region=regional_client.region,
                                        lifecycle_state=full_rule.lifecycle_state,
                                        condition=(
                                            full_rule.condition
                                            if hasattr(full_rule, "condition")
                                            else ""
                                        ),
                                        is_enabled=(
                                            full_rule.is_enabled
                                            if hasattr(full_rule, "is_enabled")
                                            else False
                                        ),
                                        actions=actions_list,
                                    )
                                )
                            except Exception as error:
                                logger.error(
                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_topics__(self, regional_client):
        """List all notification topics."""
        try:
            # Control plane client for listing topics
            ons_control_client = self._create_oci_client(
                oci.ons.NotificationControlPlaneClient,
                config_overrides={"region": regional_client.region},
            )

            # Data plane client for listing subscriptions
            ons_data_client = self._create_oci_client(
                oci.ons.NotificationDataPlaneClient,
                config_overrides={"region": regional_client.region},
            )

            logger.info(f"Events - Listing Topics in {regional_client.region}...")

            # First, get all subscriptions in this compartment for later matching
            all_subscriptions = {}
            for compartment in self.audited_compartments:
                try:
                    subs = oci.pagination.list_call_get_all_results(
                        ons_data_client.list_subscriptions,
                        compartment_id=compartment.id,
                    ).data

                    # Group subscriptions by topic_id
                    for sub in subs:
                        topic_id = sub.topic_id
                        if topic_id not in all_subscriptions:
                            all_subscriptions[topic_id] = []
                        if sub.lifecycle_state == "ACTIVE":
                            all_subscriptions[topic_id].append(sub.id)
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

            # Now list all topics and attach their subscriptions
            for compartment in self.audited_compartments:
                try:
                    topics = oci.pagination.list_call_get_all_results(
                        ons_control_client.list_topics, compartment_id=compartment.id
                    ).data

                    for topic in topics:
                        if topic.lifecycle_state != "DELETED":
                            # Get subscriptions for this topic from our pre-fetched map
                            subscriptions = all_subscriptions.get(topic.topic_id, [])

                            self.topics.append(
                                Topic(
                                    id=topic.topic_id,
                                    name=topic.name,
                                    compartment_id=compartment.id,
                                    region=regional_client.region,
                                    lifecycle_state=topic.lifecycle_state,
                                    subscriptions=subscriptions,
                                )
                            )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class Rule(BaseModel):
    """OCI Events Rule model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    condition: str
    is_enabled: bool
    actions: List = []


class Topic(BaseModel):
    """OCI Notification Topic model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    subscriptions: List[str] = []
