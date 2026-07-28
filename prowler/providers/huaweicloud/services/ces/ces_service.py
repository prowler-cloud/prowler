from typing import List

from pydantic.v1 import BaseModel

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

            try:
                from huaweicloudsdkces.v1 import ListAlarmsRequest

                request = ListAlarmsRequest()
                response = self._call_with_retries(client.list_alarms, request)

                if response and response.metric_alarms:
                    for alarm in response.metric_alarms:
                        alarm_id = getattr(alarm, "alarm_id", "") or ""
                        alarm_name = getattr(alarm, "alarm_name", "") or ""
                        alarm_enabled = getattr(alarm, "alarm_enabled", True)

                        self.alarms.append(
                            CESAlarm(
                                alarm_id=alarm_id,
                                alarm_name=alarm_name,
                                alarm_enabled=alarm_enabled,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class CESAlarm(BaseModel):
    """CES alarm rule model."""

    alarm_id: str
    alarm_name: str = ""
    alarm_enabled: bool = True
    region: str = ""
