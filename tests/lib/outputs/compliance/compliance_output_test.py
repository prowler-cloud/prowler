"""Guard that a compliance formatter emits the manual requirements once per writer.

Every formatter appends the manual requirements of its framework, the ones that map
no checks, after the rows of the findings it transforms. The CLI transforms all the
findings in one call, but the API streams them in batches and calls ``transform`` once
per batch on the same writer, so each manual requirement was written once per batch.

``ComplianceOutput`` guards ``transform`` for all its subclasses. These tests run every
formatter the way the API does and check that only the first batch carries the manual
requirements, while the rows of the findings stay the same. A caller can still decide
per call with ``include_manual``, the flag the universal exporters use.
"""

import importlib
import pkgutil
from csv import DictReader

import pytest

import prowler.lib.outputs.compliance as compliance_outputs
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS
from tests.lib.outputs.compliance.fixtures import (
    ASD_ESSENTIAL_EIGHT_AWS,
    AWS_WELL_ARCHITECTED,
    C5_AWS,
    CCC_AWS_FIXTURE,
    CIS_2_0_AZURE,
    ENS_RD2022_AWS,
    ISO27001_2013_AWS,
    KISA_ISMSP_AWS,
    MITRE_ATTACK_AWS,
    MITRE_ATTACK_AZURE,
    MITRE_ATTACK_GCP,
    NIST_800_53_REVISION_4_AWS,
    OKTA_IDAAS_STIG_OKTA,
    PROWLER_THREATSCORE_AWS,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

_MANUAL_RESOURCE_ID = "manual_check"

# A formatter only reads the requirement attributes of its family, so one framework per
# family drives all of its formatters. MITRE ATT&CK attributes differ per provider.
_FAMILY_FRAMEWORKS = {
    "asd_essential_eight": ASD_ESSENTIAL_EIGHT_AWS,
    "aws_well_architected": AWS_WELL_ARCHITECTED,
    "c5": C5_AWS,
    "ccc": CCC_AWS_FIXTURE,
    "cis": CIS_2_0_AZURE,
    "cisa_scuba": NIST_800_53_REVISION_4_AWS,
    "ens": ENS_RD2022_AWS,
    "generic": NIST_800_53_REVISION_4_AWS,
    "iso27001": ISO27001_2013_AWS,
    "kisa_ismsp": KISA_ISMSP_AWS,
    "okta_idaas_stig": OKTA_IDAAS_STIG_OKTA,
    "prowler_threatscore": PROWLER_THREATSCORE_AWS,
}
_FORMATTER_FRAMEWORKS = {
    "AWSMitreAttack": MITRE_ATTACK_AWS,
    "AzureMitreAttack": MITRE_ATTACK_AZURE,
    "GCPMitreAttack": MITRE_ATTACK_GCP,
}


def _formatters():
    package = compliance_outputs.__name__
    for module in pkgutil.walk_packages(compliance_outputs.__path__, f"{package}."):
        importlib.import_module(module.name)
    return sorted(
        (
            formatter
            for formatter in ComplianceOutput.__subclasses__()
            if formatter.__module__.startswith(f"{package}.")
        ),
        key=lambda formatter: formatter.__name__,
    )


def _framework_for(formatter):
    family = formatter.__module__.split(".")[-2]
    return _FORMATTER_FRAMEWORKS.get(formatter.__name__) or _FAMILY_FRAMEWORKS.get(
        family
    )


def _finding_for(compliance):
    """A finding of the first check the framework maps, so transform emits a row for it."""
    check_id = next(
        requirement.Checks[0]
        for requirement in compliance.Requirements
        if requirement.Checks
    )
    return generate_finding_output(
        provider=compliance.Provider.lower(),
        check_id=check_id,
        service_name=check_id.split("_")[0],
    )


def _manual_rows(rows):
    return [row for row in rows if row.ResourceId == _MANUAL_RESOURCE_ID]


def _finding_rows(rows):
    return [row for row in rows if row.ResourceId != _MANUAL_RESOURCE_ID]


@pytest.mark.parametrize(
    "formatter",
    [pytest.param(formatter, id=formatter.__name__) for formatter in _formatters()],
)
def test_formatter_emits_manual_requirements_once_across_batches(formatter):
    compliance = _framework_for(formatter)
    if compliance is None:
        # The guard lives in the base class, so it still covers this formatter.
        pytest.skip("no framework fixture for this formatter family")
    requirements = list(compliance.Requirements)
    finding = _finding_for(compliance)

    single_batch = formatter([finding], compliance)
    manual_rows = _manual_rows(single_batch.data)
    finding_rows = _finding_rows(single_batch.data)
    # The framework drives both kinds of row, or the assertions below prove nothing.
    assert manual_rows
    assert finding_rows

    batched = formatter([finding], compliance)
    batched.transform([finding], compliance, compliance.Framework)
    batched.transform([finding], compliance, compliance.Framework)

    assert _manual_rows(batched.data) == manual_rows
    # Each batch still gets the same rows for its findings.
    assert _finding_rows(batched.data) == finding_rows * 3
    # Later batches must not change the framework the caller keeps using.
    assert compliance.Requirements == requirements


def test_writer_without_initial_findings_emits_manual_requirements_once():
    finding = _finding_for(ENS_RD2022_AWS)

    writer = AWSENS([], ENS_RD2022_AWS)
    assert writer.data == []

    writer.transform([finding], ENS_RD2022_AWS, ENS_RD2022_AWS.Framework)
    writer.transform([finding], ENS_RD2022_AWS, ENS_RD2022_AWS.Framework)

    assert len(_manual_rows(writer.data)) == 1
    assert len(writer.data) == 3


def test_include_manual_lets_the_caller_decide_for_a_batch():
    finding = _finding_for(ENS_RD2022_AWS)
    writer = AWSENS([], ENS_RD2022_AWS)

    # Left out on request: the writer has still not emitted them.
    writer.transform(
        [finding], ENS_RD2022_AWS, ENS_RD2022_AWS.Framework, include_manual=False
    )
    assert _manual_rows(writer.data) == []

    writer.transform([finding], ENS_RD2022_AWS, ENS_RD2022_AWS.Framework)
    assert len(_manual_rows(writer.data)) == 1

    # Asked for explicitly: emitted again, whatever the writer did before.
    writer.transform(
        [finding], ENS_RD2022_AWS, ENS_RD2022_AWS.Framework, include_manual=True
    )
    assert len(_manual_rows(writer.data)) == 2
    assert len(_finding_rows(writer.data)) == 3


def test_streamed_csv_holds_each_manual_requirement_once(tmp_path):
    finding = _finding_for(ENS_RD2022_AWS)
    file_path = tmp_path / "ens_rd2022_aws.csv"

    # The API creates the writer with the first batch and reuses it for the rest.
    writer = AWSENS(
        findings=[finding],
        compliance=ENS_RD2022_AWS,
        file_path=str(file_path),
        from_cli=False,
    )
    writer.batch_write_data_to_file()
    writer._data.clear()
    for is_last in (False, True):
        writer.transform([finding], ENS_RD2022_AWS, "ens_rd2022_aws")
        writer.close_file = is_last
        writer.batch_write_data_to_file()
        writer._data.clear()

    with open(file_path, newline="") as csv_file:
        rows = list(DictReader(csv_file, delimiter=";"))

    assert [row["STATUS"] for row in rows].count("MANUAL") == 1
    assert [row["RESOURCEID"] for row in rows].count(_MANUAL_RESOURCE_ID) == 1
    assert len(rows) == 4
