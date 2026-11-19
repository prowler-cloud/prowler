from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ens.ens_m365 import M365ENS
from prowler.lib.outputs.compliance.ens.models import M365ENSModel
from tests.lib.outputs.compliance.fixtures import ENS_RD2022_M365
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.m365.m365_fixtures import LOCATION, TENANT_ID


class TestM365ENS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                compliance={"ENS-RD2022": "op.exp.8.m365.purview.1"},
                provider="m365",
                account_uid=TENANT_ID,
                region=LOCATION,
            ),
        ]

        output = M365ENS(findings, ENS_RD2022_M365)
        output_data = output.data[0]
        assert isinstance(output_data, M365ENSModel)
        assert output_data.Provider == "m365"
        assert output_data.Framework == ENS_RD2022_M365.Framework
        assert output_data.Name == ENS_RD2022_M365.Name
        assert output_data.TenantId == TENANT_ID
        assert output_data.Location == LOCATION
        assert output_data.Description == ENS_RD2022_M365.Description
        assert output_data.Requirements_Id == ENS_RD2022_M365.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == ENS_RD2022_M365.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_M365.Requirements[0].Attributes[0].IdGrupoControl
        )
        assert (
            output_data.Requirements_Attributes_Marco
            == ENS_RD2022_M365.Requirements[0].Attributes[0].Marco
        )
        assert (
            output_data.Requirements_Attributes_Categoria
            == ENS_RD2022_M365.Requirements[0].Attributes[0].Categoria
        )
        assert (
            output_data.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_M365.Requirements[0].Attributes[0].DescripcionControl
        )
        assert (
            output_data.Requirements_Attributes_Nivel
            == ENS_RD2022_M365.Requirements[0].Attributes[0].Nivel
        )
        assert (
            output_data.Requirements_Attributes_Tipo
            == ENS_RD2022_M365.Requirements[0].Attributes[0].Tipo
        )
        assert [
            output_data.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_M365.Requirements[0].Attributes[0].Dimensiones
        assert (
            output_data.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_M365.Requirements[0].Attributes[0].ModoEjecucion
        )
        assert output_data.Requirements_Attributes_Dependencias == ""
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "m365"
        assert output_data_manual.Framework == ENS_RD2022_M365.Framework
        assert output_data_manual.Name == ENS_RD2022_M365.Name
        assert output_data_manual.TenantId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Requirements_Id == ENS_RD2022_M365.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == ENS_RD2022_M365.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_M365.Requirements[1].Attributes[0].IdGrupoControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Marco
            == ENS_RD2022_M365.Requirements[1].Attributes[0].Marco
        )
        assert (
            output_data_manual.Requirements_Attributes_Categoria
            == ENS_RD2022_M365.Requirements[1].Attributes[0].Categoria
        )
        assert (
            output_data_manual.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_M365.Requirements[1].Attributes[0].DescripcionControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Nivel
            == ENS_RD2022_M365.Requirements[1].Attributes[0].Nivel
        )
        assert (
            output_data_manual.Requirements_Attributes_Tipo
            == ENS_RD2022_M365.Requirements[1].Attributes[0].Tipo
        )
        assert [
            output_data_manual.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_M365.Requirements[1].Attributes[0].Dimensiones
        assert (
            output_data_manual.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_M365.Requirements[1].Attributes[0].ModoEjecucion
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    def test_output_transform_keeps_a_failed_finding_failed(self):
        findings = [
            generate_finding_output(
                status="FAIL",
                status_extended="Unified audit log search is disabled.",
                compliance={"ENS-RD2022": "op.exp.8.m365.purview.1"},
                provider="m365",
                account_uid=TENANT_ID,
                region=LOCATION,
            ),
        ]
        output = M365ENS(findings, ENS_RD2022_M365)
        row = output.data[0]
        assert row.Requirements_Id == "op.exp.8.m365.purview.1"
        assert row.Status == "FAIL"
        assert row.StatusExtended == "Unified audit log search is disabled."

    def test_output_transform_applies_the_requirement_config_override(self):
        findings = [
            generate_finding_output(
                status="PASS",
                status_extended="Unified audit log search is enabled.",
                compliance={"ENS-RD2022": "op.exp.8.m365.purview.1"},
                provider="m365",
                account_uid=TENANT_ID,
                region=LOCATION,
            ),
        ]
        with patch(
            "prowler.lib.outputs.compliance.ens.ens_m365.build_requirement_config_status",
            return_value={
                "op.exp.8.m365.purview.1": (False, "audit retention is too short")
            },
        ):
            output = M365ENS(findings, ENS_RD2022_M365)
        row = output.data[0]
        assert row.Requirements_Id == "op.exp.8.m365.purview.1"
        assert row.Status == "FAIL"
        assert "audit retention is too short" in row.StatusExtended
        assert "Unified audit log search is enabled." in row.StatusExtended

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.ens.ens_m365.timestamp", "2025-01-01 00:00:00"
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                compliance={"ENS-RD2022": "op.exp.8.m365.purview.1"},
                provider="m365",
                account_uid=TENANT_ID,
                region=LOCATION,
            ),
        ]
        output = M365ENS(findings, ENS_RD2022_M365)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;TENANTID;LOCATION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL;REQUIREMENTS_ATTRIBUTES_MARCO;REQUIREMENTS_ATTRIBUTES_CATEGORIA;REQUIREMENTS_ATTRIBUTES_DESCRIPCIONCONTROL;REQUIREMENTS_ATTRIBUTES_NIVEL;REQUIREMENTS_ATTRIBUTES_TIPO;REQUIREMENTS_ATTRIBUTES_DIMENSIONES;REQUIREMENTS_ATTRIBUTES_MODOEJECUCION;REQUIREMENTS_ATTRIBUTES_DEPENDENCIAS;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME;FRAMEWORK;NAME\r\nm365;The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.;{TENANT_ID};{LOCATION};{datetime.now()};op.exp.8.m365.purview.1;Registro de actividad;op.exp.8;operacional;explotación;Habilitar el registro de auditoría unificado para que quede constancia de la actividad de usuarios y administradores.;alto;requisito;trazabilidad;automático;;PASS;;;service_test_check_id;False;;ENS;ENS RD 311/2022 - Categoría Alta\r\nm365;The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.;;;{datetime.now()};op.exp.8.m365.purview.2;Registro de actividad;op.exp.8;operacional;explotación;Habilitar el registro de auditoría unificado para que quede constancia de la actividad de usuarios y administradores.;alto;requisito;trazabilidad;automático;;MANUAL;Manual check;manual_check;manual;False;Manual check;ENS;ENS RD 311/2022 - Categoría Alta\r\n"

        assert content == expected_csv
