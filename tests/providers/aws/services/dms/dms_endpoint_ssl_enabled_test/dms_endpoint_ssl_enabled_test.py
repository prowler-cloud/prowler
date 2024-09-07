from unittest import mock

from prowler.providers.aws.services.dms.dms_service import Endpoint

class Test_dms_ssl_enabled:

    def test_dms_no_endpoint(self):
         dms_client = mock.MagicMock
         dms_client.endpoints = {}

         with mock.patch(
            "prowler.providers.aws.services.dms.dms_service.DMS",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled import (
                dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute()
            assert len(result) == 0