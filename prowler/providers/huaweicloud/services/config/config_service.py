from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class Config(HuaweiCloudService):
    """
    Config (Resource Management Service) class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud RMS/Config service
    to retrieve tracker configuration and policy assignments.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.tracker_config = TrackerConfig()
        self.policy_assignments: List[PolicyAssignment] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._get_tracker_config()
        self._list_policy_assignments()

    def _load_mock_data(self):
        """Load mock data for testing."""
        self.tracker_config = TrackerConfig(
            agency_name="rms_agency",
            tracker_enabled=True,
        )
        self.policy_assignments = [
            PolicyAssignment(
                id="assignment-001",
                name="check-encryption",
                state="Enabled",
                policy_definition_id="definition-001",
            ),
            PolicyAssignment(
                id="assignment-002",
                name="check-public-access",
                state="Enabled",
                policy_definition_id="definition-002",
            ),
        ]

    def _get_tracker_config(self):
        """Get the RMS tracker configuration."""
        if not self.client:
            return

        region = self.region
        client = self.client
        logger.info(f"Config - Getting Tracker Config from {region}...")

        try:
            from huaweicloudsdkrms.v1 import ShowTrackerConfigRequest

            request = ShowTrackerConfigRequest()
            response = self._call_with_retries(client.show_tracker_config, request)

            if response:
                self.tracker_config = TrackerConfig(
                    agency_name=getattr(response, "agency_name", "") or "",
                    tracker_enabled=True,
                )
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_policy_assignments(self):
        """List all policy assignments (compliance rules)."""
        if not self.client:
            return

        region = self.region
        client = self.client
        logger.info(f"Config - Listing Policy Assignments in {region}...")

        try:
            from huaweicloudsdkrms.v1 import ListPolicyAssignmentsRequest

            request = ListPolicyAssignmentsRequest()
            response = self._call_with_retries(client.list_policy_assignments, request)

            if response and response.value:
                for assignment_data in response.value:
                    self.policy_assignments.append(
                        PolicyAssignment(
                            id=assignment_data.id,
                            name=getattr(assignment_data, "name", assignment_data.id),
                            state=getattr(assignment_data, "state", ""),
                            policy_definition_id=getattr(
                                assignment_data, "policy_definition_id", ""
                            ),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class TrackerConfig(BaseModel):
    """RMS Tracker Configuration model."""

    agency_name: str = ""
    tracker_enabled: bool = False


class PolicyAssignment(BaseModel):
    """RMS Policy Assignment model."""

    id: str
    name: str = ""
    state: str = ""
    policy_definition_id: str = ""
