from prowler.lib.scan.scan import Scan
from prowler.providers.aws.aws_provider import AwsProvider

providers = AwsProvider(profile="dev", regions=["eu-west-1"])
check_to_execute = ["accessanalyzer_enabled"]


def new_api_scan(providers, check_to_execute):
    scan = Scan(providers, check_to_execute)

    for audit_metadata, findings in scan.scan():
        print("Audit Metadata: ", audit_metadata)
        print("Findings: ", len(findings))
        print("##################")


new_api_scan(providers, check_to_execute)
