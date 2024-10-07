from prowler.lib.scan.scan import Scan
from prowler.providers.aws.aws_provider import AwsProvider

provider = AwsProvider(profile="dev", regions=["eu-west-1"])


def new_api_scan(provider):
    scan = Scan(provider)
    for progress, findings in scan.scan():
        print("Progress: ", progress)
        print("Findings: ", len(findings))
        print("###########3")


new_api_scan(provider)
