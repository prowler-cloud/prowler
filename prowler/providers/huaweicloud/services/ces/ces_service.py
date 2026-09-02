from typing import Any, List

from huaweicloudsdkces.v2 import ListAlarmRulesRequest
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class CES(HuaweiCloudService):
    """
    CES (Cloud Eye) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud CES service
    to retrieve alarm rules.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.alarms: List[CESAlarm] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_alarms()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.alarms = [
            CESAlarm(
                alarm_id="alarm-001",
                alarm_name="cpu-alarm",
                alarm_enabled=True,
                region=region,
            ),
            CESAlarm(
                alarm_id="alarm-002",
                alarm_name="disk-alarm",
                alarm_enabled=False,
                region=region,
            ),
        ]

    def _list_alarms(self):
        """List all CES alarm rules across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"CES - Listing Alarms in {region}...")

            offset = 0
            limit = 100
            while True:
                request = ListAlarmRulesRequest(offset=offset, limit=limit)
                response = self._call_with_retries(client.list_alarm_rules, request)
                alarms = getattr(response, "alarms", None) or []

                for alarm in alarms:
                    self.alarms.append(
                        CESAlarm(
                            alarm_id=getattr(alarm, "alarm_id", "") or "",
                            alarm_name=getattr(alarm, "name", "") or "",
                            alarm_enabled=getattr(alarm, "enabled", False) is True,
                            region=region,
                            policies=[
                                self._model_to_dict(policy)
                                for policy in (getattr(alarm, "policies", None) or [])
                            ],
                            resources=[
                                self._model_to_dict(resource)
                                for resource in (
                                    getattr(alarm, "resources", None) or []
                                )
                            ],
                        )
                    )

                offset += len(alarms)
                count = getattr(response, "count", None)
                if not alarms or (count is not None and offset >= count):
                    break
                if count is None and len(alarms) < limit:
                    break

    @staticmethod
    def _model_to_dict(model: Any) -> Any:
        """Convert an SDK response model into a serializable dictionary."""
        if hasattr(model, "to_dict"):
            return model.to_dict()
        if isinstance(model, list):
            return [CES._model_to_dict(item) for item in model]
        if isinstance(model, dict):
            return {key: CES._model_to_dict(value) for key, value in model.items()}
        if hasattr(model, "__dict__"):
            return {
                key: CES._model_to_dict(value) for key, value in vars(model).items()
            }
        return model


class CESAlarm(BaseModel):
    """CES alarm rule model."""

    alarm_id: str
    alarm_name: str = ""
    alarm_enabled: bool = True
    region: str = ""
    policies: List[dict] = Field(default_factory=list)
    resources: List[dict] = Field(default_factory=list)
