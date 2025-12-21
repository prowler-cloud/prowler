"""
Tests for SageMaker Service Tag Parallelization.

This module validates that the SageMaker service correctly implements parallel execution
for tag retrieval across different resource types (Models, Notebooks, Training Jobs, Endpoints).
"""
from unittest.mock import MagicMock, call, patch
from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    SageMaker,
    Model,
    NotebookInstance,
    TrainingJob,
    EndpointConfig,
)

class TestSageMakerTags:
    """Test suite for SageMaker tag listing logic."""

    def test_list_tags_for_resource_calls_client(self):
        """Test that _list_tags_for_resource calls the correct AWS client and updates the resource."""
        # Mock audit info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        regional_client.list_tags.return_value = {"Tags": [{"Key": "foo", "Value": "bar"}]}

        # Create service instance (mocking init to avoid full setup)
        with patch.object(SageMaker, "__init__", return_value=None):
            sagemaker_service = SageMaker(audit_info)
            sagemaker_service.regional_clients = {"us-east-1": regional_client}
            sagemaker_service.audit_info = audit_info

        # Create a mock resource
        resource = Model(
            name="test-model",
            region="us-east-1",
            arn="arn:aws:sagemaker:us-east-1:123456789012:model/test-model"
        )

        # Execute method under test
        sagemaker_service._list_tags_for_resource(resource)

        # Verification
        regional_client.list_tags.assert_called_once_with(ResourceArn=resource.arn)
        assert len(resource.tags) == 1
        assert resource.tags[0]["Key"] == "foo"
        assert resource.tags[0]["Value"] == "bar"

    def test_init_calls_threading_for_tags(self):
        """
        Test that __init__ calls __threading_call__ for tag listing for each resource type.
        This confirms that parallel execution is requested.
        """
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"

        # We mock __threading_call__ to verify it is called with the right arguments
        with patch("prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker.__threading_call__") as mock_threading_call:
             # We also need to mock the other methods called in init to avoid errors
            with patch("prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_notebook_instances"), \
                 patch("prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_models"), \
                 patch("prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_training_jobs"), \
                 patch("prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker._list_endpoint_configs"):
                
                sagemaker_service = SageMaker(audit_info)
                
                # Check for calls to __threading_call__ with _list_tags_for_resource
                # We expect 4 calls, one for each resource list
                calls = [
                    call(sagemaker_service._list_tags_for_resource, sagemaker_service.sagemaker_models),
                    call(sagemaker_service._list_tags_for_resource, sagemaker_service.sagemaker_notebook_instances),
                    call(sagemaker_service._list_tags_for_resource, sagemaker_service.sagemaker_training_jobs),
                    call(sagemaker_service._list_tags_for_resource, list(sagemaker_service.endpoint_configs.values()))
                ]
                mock_threading_call.assert_has_calls(calls, any_order=True)
