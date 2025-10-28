import os
import re
import zipfile

import boto3
import config.django.base as base
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from celery.utils.log import get_task_logger
from django.conf import settings

from api.db_utils import rls_transaction
from api.models import Scan
from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.aws_well_architected.aws_well_architected import (
    AWSWellArchitected,
)
from prowler.lib.outputs.compliance.c5.c5_aws import AWSC5
from prowler.lib.outputs.compliance.ccc.ccc_aws import CCC_AWS
from prowler.lib.outputs.compliance.ccc.ccc_azure import CCC_Azure
from prowler.lib.outputs.compliance.ccc.ccc_gcp import CCC_GCP
from prowler.lib.outputs.compliance.cis.cis_aws import AWSCIS
from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS
from prowler.lib.outputs.compliance.cis.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.cis.cis_github import GithubCIS
from prowler.lib.outputs.compliance.cis.cis_kubernetes import KubernetesCIS
from prowler.lib.outputs.compliance.cis.cis_m365 import M365CIS
from prowler.lib.outputs.compliance.cis.cis_oci import OCICIS
from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS
from prowler.lib.outputs.compliance.ens.ens_azure import AzureENS
from prowler.lib.outputs.compliance.ens.ens_gcp import GCPENS
from prowler.lib.outputs.compliance.iso27001.iso27001_aws import AWSISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_azure import AzureISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_gcp import GCPISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_kubernetes import (
    KubernetesISO27001,
)
from prowler.lib.outputs.compliance.iso27001.iso27001_m365 import M365ISO27001
from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_aws import AWSKISAISMSP
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_aws import AWSMitreAttack
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_azure import (
    AzureMitreAttack,
)
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_gcp import GCPMitreAttack
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_aws import (
    ProwlerThreatScoreAWS,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_azure import (
    ProwlerThreatScoreAzure,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_gcp import (
    ProwlerThreatScoreGCP,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_m365 import (
    ProwlerThreatScoreM365,
)
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF

logger = get_task_logger(__name__)


COMPLIANCE_CLASS_MAP = {
    "aws": [
        (lambda name: name.startswith("cis_"), AWSCIS),
        (lambda name: name == "mitre_attack_aws", AWSMitreAttack),
        (lambda name: name.startswith("ens_"), AWSENS),
        (
            lambda name: name.startswith("aws_well_architected_framework"),
            AWSWellArchitected,
        ),
        (lambda name: name.startswith("iso27001_"), AWSISO27001),
        (lambda name: name.startswith("kisa"), AWSKISAISMSP),
        (lambda name: name == "prowler_threatscore_aws", ProwlerThreatScoreAWS),
        (lambda name: name == "ccc_aws", CCC_AWS),
        (lambda name: name.startswith("c5_"), AWSC5),
    ],
    "azure": [
        (lambda name: name.startswith("cis_"), AzureCIS),
        (lambda name: name == "mitre_attack_azure", AzureMitreAttack),
        (lambda name: name.startswith("ens_"), AzureENS),
        (lambda name: name.startswith("iso27001_"), AzureISO27001),
        (lambda name: name == "ccc_azure", CCC_Azure),
        (lambda name: name == "prowler_threatscore_azure", ProwlerThreatScoreAzure),
    ],
    "gcp": [
        (lambda name: name.startswith("cis_"), GCPCIS),
        (lambda name: name == "mitre_attack_gcp", GCPMitreAttack),
        (lambda name: name.startswith("ens_"), GCPENS),
        (lambda name: name.startswith("iso27001_"), GCPISO27001),
        (lambda name: name == "prowler_threatscore_gcp", ProwlerThreatScoreGCP),
        (lambda name: name == "ccc_gcp", CCC_GCP),
    ],
    "kubernetes": [
        (lambda name: name.startswith("cis_"), KubernetesCIS),
        (lambda name: name.startswith("iso27001_"), KubernetesISO27001),
    ],
    "m365": [
        (lambda name: name.startswith("cis_"), M365CIS),
        (lambda name: name == "prowler_threatscore_m365", ProwlerThreatScoreM365),
        (lambda name: name.startswith("iso27001_"), M365ISO27001),
    ],
    "github": [
        (lambda name: name.startswith("cis_"), GithubCIS),
    ],
    "oci": [
        (lambda name: name.startswith("cis_"), OCICIS),
    ],
}


# Predefined mapping for output formats and their configurations
OUTPUT_FORMATS_MAPPING = {
    "csv": {
        "class": CSV,
        "suffix": csv_file_suffix,
        "kwargs": {},
    },
    "json-ocsf": {"class": OCSF, "suffix": json_ocsf_file_suffix, "kwargs": {}},
    "json-asff": {"class": ASFF, "suffix": json_asff_file_suffix, "kwargs": {}},
    "html": {"class": HTML, "suffix": html_file_suffix, "kwargs": {"stats": {}}},
}


def _compress_output_files(output_directory: str) -> str:
    """
    Compress output files from all configured output formats into a ZIP archive.
    Args:
        output_directory (str): The directory where the output files are located.
            The function looks up all known suffixes in OUTPUT_FORMATS_MAPPING
            and compresses those files into a single ZIP.
    Returns:
        str: The full path to the newly created ZIP archive.
    """
    zip_path = f"{output_directory}.zip"
    parent_dir = os.path.dirname(output_directory)
    zip_path_abs = os.path.abspath(zip_path)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for foldername, _, filenames in os.walk(parent_dir):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                if os.path.abspath(file_path) == zip_path_abs:
                    continue
                arcname = os.path.relpath(file_path, start=parent_dir)
                zipf.write(file_path, arcname)

    return zip_path


def get_s3_client():
    """
    Create and return a boto3 S3 client using AWS credentials from environment variables.

    This function attempts to initialize an S3 client by reading the AWS access key, secret key,
    session token, and region from environment variables. It then validates the client by listing
    available S3 buckets. If an error occurs during this process (for example, due to missing or
    invalid credentials), it falls back to creating an S3 client without explicitly provided credentials,
    which may rely on other configuration sources (e.g., IAM roles).

    Returns:
        boto3.client: A configured S3 client instance.

    Raises:
        ClientError, NoCredentialsError, or ParamValidationError if both attempts to create a client fail.
    """
    s3_client = None
    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=settings.DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN,
            region_name=settings.DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION,
        )
        s3_client.list_buckets()
    except (ClientError, NoCredentialsError, ParamValidationError, ValueError):
        s3_client = boto3.client("s3")
        s3_client.list_buckets()

    return s3_client


def _upload_to_s3(
    tenant_id: str, scan_id: str, local_path: str, relative_key: str
) -> str | None:
    """
    Upload a local artifact to an S3 bucket under the tenant/scan prefix.

    Args:
        tenant_id (str): The tenant identifier used as the first segment of the S3 key.
        scan_id (str): The scan identifier used as the second segment of the S3 key.
        local_path (str): Filesystem path to the artifact to upload.
        relative_key (str): Object key relative to `<tenant_id>/<scan_id>/`.

    Returns:
        str | None: S3 URI of the uploaded artifact, or None if the upload is skipped.

    Raises:
        botocore.exceptions.ClientError: If the upload attempt to S3 fails for any reason.
    """
    bucket = base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET
    if not bucket:
        return

    if not relative_key:
        return

    if not os.path.isfile(local_path):
        return

    try:
        s3 = get_s3_client()

        s3_key = f"{tenant_id}/{scan_id}/{relative_key}"
        s3.upload_file(Filename=local_path, Bucket=bucket, Key=s3_key)

        return f"s3://{base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET}/{s3_key}"
    except (ClientError, NoCredentialsError, ParamValidationError, ValueError) as e:
        logger.error(f"S3 upload failed: {str(e)}")


def _generate_output_directory(
    output_directory, prowler_provider: object, tenant_id: str, scan_id: str
) -> tuple[str, str, str]:
    """
    Generate a file system path for the output directory of a prowler scan.

    This function constructs the output directory path by combining a base
    temporary output directory, the tenant ID, the scan ID, and details about
    the prowler provider along with a timestamp. The resulting path is used to
    store the output files of a prowler scan.

    Note:
        This function depends on one external variable:
          - `output_file_timestamp`: A timestamp (as a string) used to uniquely identify the output.

    Args:
        output_directory (str): The base output directory.
        prowler_provider (object): An identifier or descriptor for the prowler provider.
                                   Typically, this is a string indicating the provider (e.g., "aws").
        tenant_id (str): The unique identifier for the tenant.
        scan_id (str): The unique identifier for the scan.

    Returns:
        str: The constructed file system path for the prowler scan output directory.

    Example:
        >>> _generate_output_directory("/tmp", "aws", "tenant-1234", "scan-5678")
        '/tmp/tenant-1234/aws/scan-5678/prowler-output-2023-02-15T12:34:56',
        '/tmp/tenant-1234/aws/scan-5678/compliance/prowler-output-2023-02-15T12:34:56'
        '/tmp/tenant-1234/aws/scan-5678/threatscore/prowler-output-2023-02-15T12:34:56'
    """
    # Sanitize the prowler provider name to ensure it is a valid directory name
    prowler_provider_sanitized = re.sub(r"[^\w\-]", "-", prowler_provider)

    with rls_transaction(tenant_id):
        started_at = Scan.objects.get(id=scan_id).started_at

    timestamp = started_at.strftime("%Y%m%d%H%M%S")
    path = (
        f"{output_directory}/{tenant_id}/{scan_id}/prowler-output-"
        f"{prowler_provider_sanitized}-{timestamp}"
    )
    os.makedirs("/".join(path.split("/")[:-1]), exist_ok=True)

    compliance_path = (
        f"{output_directory}/{tenant_id}/{scan_id}/compliance/prowler-output-"
        f"{prowler_provider_sanitized}-{timestamp}"
    )
    os.makedirs("/".join(compliance_path.split("/")[:-1]), exist_ok=True)

    threatscore_path = (
        f"{output_directory}/{tenant_id}/{scan_id}/threatscore/prowler-output-"
        f"{prowler_provider_sanitized}-{timestamp}"
    )
    os.makedirs("/".join(threatscore_path.split("/")[:-1]), exist_ok=True)

    return path, compliance_path, threatscore_path
