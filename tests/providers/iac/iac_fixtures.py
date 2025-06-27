from checkov.common.models.enums import CheckResult
from checkov.common.output.record import Record
from checkov.common.output.report import Report

# IAC Provider Constants
DEFAULT_SCAN_PATH = "."

# Sample Finding Data
SAMPLE_FINDING = Report(check_type="terraform")
SAMPLE_FAILED_CHECK = Record(
    check_id="CKV_AWS_1",
    check_name="Ensure S3 bucket has encryption enabled",
    severity="low",
    file_path="test.tf",
    file_line_range=[1, 2],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_FAILED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_1-s3-bucket-has-encryption-enabled"
)

SAMPLE_PASSED_CHECK = Record(
    check_id="CKV_AWS_3",
    check_name="Ensure S3 bucket has versioning enabled",
    severity="low",
    file_path="test.tf",
    file_line_range=[1, 2],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.PASSED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_PASSED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_3-s3-bucket-has-versioning-enabled"
)

# Additional test fixtures for comprehensive testing
SAMPLE_SKIPPED_CHECK = Record(
    check_id="CKV_AWS_2",
    check_name="Ensure S3 bucket has public access blocked",
    severity="high",
    file_path="test.tf",
    file_line_range=[3, 4],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.SKIPPED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_SKIPPED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_2-s3-bucket-has-public-access-blocked"
)

SAMPLE_HIGH_SEVERITY_CHECK = Record(
    check_id="CKV_AWS_4",
    check_name="Ensure S3 bucket has logging enabled",
    severity="HIGH",
    file_path="test.tf",
    file_line_range=[5, 6],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_HIGH_SEVERITY_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_4-s3-bucket-has-logging-enabled"
)

SAMPLE_KUBERNETES_CHECK = Record(
    check_id="CKV_K8S_1",
    check_name="Ensure API server has audit logging enabled",
    severity="medium",
    file_path="deployment.yaml",
    file_line_range=[1, 10],
    resource="kubernetes_deployment.test_deployment",
    evaluations=[],
    check_class="kubernetes",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="deployment.yaml",
)
SAMPLE_KUBERNETES_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/k8s_1-api-server-has-audit-logging-enabled"
)

SAMPLE_CLOUDFORMATION_CHECK = Record(
    check_id="CKV_AWS_5",
    check_name="Ensure CloudFormation stacks are not publicly accessible",
    severity="critical",
    file_path="template.yaml",
    file_line_range=[1, 20],
    resource="AWS::CloudFormation::Stack",
    evaluations=[],
    check_class="cloudformation",
    check_result=CheckResult.PASSED,
    code_block=[],
    file_abs_path="template.yaml",
)
SAMPLE_CLOUDFORMATION_CHECK.guideline = "https://docs.bridgecrew.io/docs/cfn_1-cloudformation-stacks-are-not-publicly-accessible"

# Sample findings for different frameworks
SAMPLE_KUBERNETES_FINDING = Report(check_type="kubernetes")
SAMPLE_CLOUDFORMATION_FINDING = Report(check_type="cloudformation")

# Additional fixtures for different test scenarios
SAMPLE_CHECK_WITHOUT_GUIDELINE = Record(
    check_id="CKV_AWS_6",
    check_name="Test check without guideline",
    severity="low",
    file_path="test.tf",
    file_line_range=[1, 2],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
# Note: No guideline attribute set

SAMPLE_MEDIUM_SEVERITY_CHECK = Record(
    check_id="CKV_AWS_7",
    check_name="Ensure S3 bucket has proper access controls",
    severity="MEDIUM",
    file_path="test.tf",
    file_line_range=[7, 8],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_MEDIUM_SEVERITY_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_7-s3-bucket-has-proper-access-controls"
)

SAMPLE_CRITICAL_SEVERITY_CHECK = Record(
    check_id="CKV_AWS_8",
    check_name="Ensure S3 bucket has encryption at rest",
    severity="CRITICAL",
    file_path="test.tf",
    file_line_range=[9, 10],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_CRITICAL_SEVERITY_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_8-s3-bucket-has-encryption-at-rest"
)

# Sample reports for different frameworks
SAMPLE_TERRAFORM_REPORT = Report(check_type="terraform")
SAMPLE_KUBERNETES_REPORT = Report(check_type="kubernetes")
SAMPLE_CLOUDFORMATION_REPORT = Report(check_type="cloudformation")
SAMPLE_DOCKERFILE_REPORT = Report(check_type="dockerfile")
SAMPLE_YAML_REPORT = Report(check_type="yaml")

# Sample checks for different frameworks
SAMPLE_DOCKERFILE_CHECK = Record(
    check_id="CKV_DOCKER_1",
    check_name="Ensure base image is not using latest tag",
    severity="high",
    file_path="Dockerfile",
    file_line_range=[1, 1],
    resource="Dockerfile",
    evaluations=[],
    check_class="dockerfile",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="Dockerfile",
)
SAMPLE_DOCKERFILE_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/docker_1-base-image-not-using-latest-tag"
)

SAMPLE_YAML_CHECK = Record(
    check_id="CKV_YAML_1",
    check_name="Ensure YAML file has proper indentation",
    severity="low",
    file_path="config.yaml",
    file_line_range=[1, 5],
    resource="config.yaml",
    evaluations=[],
    check_class="yaml",
    check_result=CheckResult.PASSED,
    code_block=[],
    file_abs_path="config.yaml",
)
SAMPLE_YAML_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/yaml_1-proper-indentation"
)

# Sample checks with different statuses for comprehensive testing
SAMPLE_ANOTHER_FAILED_CHECK = Record(
    check_id="CKV_AWS_9",
    check_name="Ensure S3 bucket has lifecycle policy",
    severity="medium",
    file_path="test.tf",
    file_line_range=[11, 12],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.FAILED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_ANOTHER_FAILED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_9-s3-bucket-has-lifecycle-policy"
)

SAMPLE_ANOTHER_PASSED_CHECK = Record(
    check_id="CKV_AWS_10",
    check_name="Ensure S3 bucket has proper tags",
    severity="low",
    file_path="test.tf",
    file_line_range=[13, 14],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.PASSED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_ANOTHER_PASSED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_10-s3-bucket-has-proper-tags"
)

SAMPLE_ANOTHER_SKIPPED_CHECK = Record(
    check_id="CKV_AWS_11",
    check_name="Ensure S3 bucket has cross-region replication",
    severity="high",
    file_path="test.tf",
    file_line_range=[15, 16],
    resource="aws_s3_bucket.test_bucket",
    evaluations=[],
    check_class="terraform",
    check_result=CheckResult.SKIPPED,
    code_block=[],
    file_abs_path="test.tf",
)
SAMPLE_ANOTHER_SKIPPED_CHECK.guideline = (
    "https://docs.bridgecrew.io/docs/s3_11-s3-bucket-has-cross-region-replication"
)
