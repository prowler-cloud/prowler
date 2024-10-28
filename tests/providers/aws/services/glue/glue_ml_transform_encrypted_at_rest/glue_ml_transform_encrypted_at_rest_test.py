from unittest.mock import MagicMock, patch

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class Test_glue_ml_transform_encrypted_at_rest:
    def test_no_ml_transfroms(self):
        glue_client = MagicMock
        glue_client.ml_transforms = {}

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            from prowler.providers.aws.services.glue.glue_ml_transform_encrypted_at_rest.glue_ml_transform_encrypted_at_rest import (
                glue_ml_transform_encrypted_at_rest,
            )

            check = glue_ml_transform_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 0

    def test_ml_transform_encryption_disabled(self):
        glue_client = MagicMock
        ml_transform_id = "transform1"
        ml_transform_arn = f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:mlTransform/{ml_transform_id}"

        from prowler.providers.aws.services.glue.glue_service import MLTransform

        glue_client.ml_transforms = {
            ml_transform_arn: MLTransform(
                arn=ml_transform_arn,
                id=ml_transform_id,
                name="ml-transform1",
                user_data_encryption="DISABLED",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        }

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            from prowler.providers.aws.services.glue.glue_ml_transform_encrypted_at_rest.glue_ml_transform_encrypted_at_rest import (
                glue_ml_transform_encrypted_at_rest,
            )

            check = glue_ml_transform_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == ml_transform_id
            assert result[0].resource_arn == ml_transform_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == "Glue ML Transform ml-transform1 is not encrypted at rest."
            )

    def test_ml_transform_encryption_enabled(self):
        glue_client = MagicMock
        ml_transform_id = "transform2"
        ml_transform_arn = f"arn:aws:glue:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:mlTransform/{ml_transform_id}"

        from prowler.providers.aws.services.glue.glue_service import MLTransform

        glue_client.ml_transforms = {
            ml_transform_arn: MLTransform(
                arn=ml_transform_arn,
                id=ml_transform_id,
                name="ml-transform2",
                user_data_encryption="SSE-KMS",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        }

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            from prowler.providers.aws.services.glue.glue_ml_transform_encrypted_at_rest.glue_ml_transform_encrypted_at_rest import (
                glue_ml_transform_encrypted_at_rest,
            )

            check = glue_ml_transform_encrypted_at_rest()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == ml_transform_id
            assert result[0].resource_arn == ml_transform_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == "Glue ML Transform ml-transform2 is encrypted at rest."
            )
