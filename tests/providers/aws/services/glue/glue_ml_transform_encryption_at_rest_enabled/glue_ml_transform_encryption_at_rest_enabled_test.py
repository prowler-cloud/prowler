from re import search
from unittest import mock

from prowler.providers.aws.services.glue.glue_service import Transforms
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, AWS_COMMERCIAL_PARTITION,AWS_ACCOUNT_NUMBER


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
    

    def test_ml_transforms_disabled(self):
        glue_client = mock.MagicMock
        glue_client.ml_transforms = {
            "arn:aws:glue:us-east-1:123456789012:mlTransform/ml-transform1": Transforms(
                id="transform1",
                name="ml-transform1",
                user_data_encryption="DISABLED",
                region="us-east-1",
                
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ):
            from prowler.providers.aws.services.glue.glue_ml_transform_encryption_at_rest_enabled.glue_ml_transform_encryption_at_rest_enabled import (
                glue_ml_transform_encryption_at_rest_enabled,
            )

            check = glue_ml_transform_encryption_at_rest_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "transform1"
            assert result[0].resource_arn == "arn:aws:glue:us-east-1:123456789012:mlTransform/ml-transform1"
            assert result[0].region == "us-east-1"
            assert result[0].status_extended == "Glue ML Transform ml-transform1 has encryption DISABLED at rest."