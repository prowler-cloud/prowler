from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled import dms_endpoint_ssl_enabled



class Test_dms_endpoint_ssl_enabled:
    
    def test_no_endpoints(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {}

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute()  
            assert len(result) == 0



    def test_endpoint_without_ssl(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP": mock.MagicMock(
                endpoint_arn="arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP",
                ssl_mode="none",
                region="us-west-2"
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )

            check = dms_endpoint_ssl_enabled()
            result = check.execute() 
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "FAIL")
            self.assertEqual(result[0].resource_id, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertIn("is not using SSL", result[0].status_extended) 
            

    def test_dms_endpoint_ssl_enabled_ssl_disabled(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP": mock.MagicMock(
                endpoint_arn="arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP",
                ssl_mode="none",
                region="us-west-2"
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute() 
            finding = result[0]
            self.assertEqual(finding.status, "FAIL")
            self.assertEqual(finding.resource_id, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.resource_arn, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.region, "us-west-2")
            self.assertIn("is not using SSL", finding.status_extended)



    def test_dms_endpoint_ssl_enabled_ssl_required(self):
   
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP": mock.MagicMock(
                endpoint_arn="arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP",
                ssl_mode="require",
                region="us-west-2"
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute() 
            finding = result[0]
            self.assertEqual(len(result), 1)
            finding = result[0]
            self.assertEqual(finding.status, "PASS")  
            self.assertEqual(finding.resource_id, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.resource_arn, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.region, "us-west-2")
            self.assertIn("is using SSL with mode: require", finding.status_extended)  
        

    def test_dms_endpoint_ssl_enabled_ssl_verify_ca(self):

        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP": mock.MagicMock(
                endpoint_arn="arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP",
                ssl_mode="verify-ca",
                region="us-west-2"
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute() 
            finding = result[0]
            self.assertEqual(len(result), 1)
            self.assertEqual(finding.status, "PASS")  
            self.assertEqual(finding.resource_id, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.resource_arn, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.region, "us-west-2")
            self.assertIn("is using SSL with mode: verify-ca", finding.status_extended)  

    
    def test_dms_ssl_enabled_ssl_verify_full(self):
        dms_client = mock.MagicMock
        dms_client.endpoints = {
            "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP": mock.MagicMock(
                endpoint_arn="arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP",
                ssl_mode="verify-full",
                region="us-west-2"
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.dms.dms_client.dms_client",
            new=dms_client,
        ):
            from prowler.providers.aws.services.dms.dms_endpoint_ssl_enabled.dms_endpoint_ssl_enabled import (
            dms_endpoint_ssl_enabled,
            )
            check = dms_endpoint_ssl_enabled()
            result = check.execute() 
            finding = result[0]
            self.assertEqual(len(result), 1)
            self.assertEqual(finding.status, "PASS")  
            self.assertEqual(finding.resource_id, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.resource_arn, "arn:aws:dms:us-west-2:123456789012:endpoint:ABCDEFGHIJKLMNOP")
            self.assertEqual(finding.region, "us-west-2")
            self.assertIn("is using SSL with mode: verify-full", finding.status_extended)  