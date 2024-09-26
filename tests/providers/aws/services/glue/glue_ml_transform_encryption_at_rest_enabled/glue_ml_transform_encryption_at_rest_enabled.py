from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import Transforms
from tests.providers.aws.utils import AWS_REGION_US_EAST_1


class Test_glue_ml_transform_encryption_at_rest_enabled:

    def test_no_ml_transfroms(self):
        glue_client = mock.MagicMock
        glue_client.transforms = []

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            glue_client,
        ):
            from prowler.providers.aws.services.glue.glue_ml_transform_encryption_at_rest_enabled.glue_ml_transform_encryption_at_rest_enabled import (
                glue_ml_transform_encryption_at_rest_enabled,
            )
            check = glue_ml_transform_encryption_at_rest_enabled()
            result = check.execute()

            assert len(result) == 0
    
    def test_no_ml_transfroms_ssl_mode_disabled(self):
        pass


    