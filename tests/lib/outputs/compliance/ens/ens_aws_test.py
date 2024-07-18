from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS
from prowler.lib.outputs.compliance.ens.models import AWSENSModel
from tests.lib.outputs.compliance.fixtures import ENS_RD2022_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSENS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(compliance={"ENS-RD2022": "op.exp.8.aws.ct.3"})
        ]

        output = AWSENS(findings, ENS_RD2022_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, AWSENSModel)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == ENS_RD2022_AWS.Description
        assert output_data.Requirements_Id == ENS_RD2022_AWS.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == ENS_RD2022_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].IdGrupoControl
        )
        assert (
            output_data.Requirements_Attributes_Marco
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].Marco
        )
        assert (
            output_data.Requirements_Attributes_Categoria
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].Categoria
        )
        assert (
            output_data.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].DescripcionControl
        )
        assert (
            output_data.Requirements_Attributes_Nivel
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].Nivel
        )
        assert (
            output_data.Requirements_Attributes_Tipo
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].Tipo
        )
        assert [
            output_data.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_AWS.Requirements[0].Attributes[0].Dimensiones
        assert (
            output_data.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_AWS.Requirements[0].Attributes[0].ModoEjecucion
        )
        assert output_data.Requirements_Attributes_Dependencias == ""
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "aws"
        assert output_data_manual.AccountId == ""
        assert output_data_manual.Region == ""
        assert output_data_manual.Requirements_Id == ENS_RD2022_AWS.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == ENS_RD2022_AWS.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].IdGrupoControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Marco
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].Marco
        )
        assert (
            output_data_manual.Requirements_Attributes_Categoria
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].Categoria
        )
        assert (
            output_data_manual.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].DescripcionControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Nivel
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].Nivel
        )
        assert (
            output_data_manual.Requirements_Attributes_Tipo
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].Tipo
        )
        assert [
            output_data_manual.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_AWS.Requirements[1].Attributes[0].Dimensiones
        assert (
            output_data_manual.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_AWS.Requirements[1].Attributes[0].ModoEjecucion
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time(datetime.now())
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(compliance={"ENS-RD2022": "op.exp.8.aws.ct.3"})
        ]
        output = AWSENS(findings, ENS_RD2022_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_IDGRUPOCONTROL;REQUIREMENTS_ATTRIBUTES_MARCO;REQUIREMENTS_ATTRIBUTES_CATEGORIA;REQUIREMENTS_ATTRIBUTES_DESCRIPCIONCONTROL;REQUIREMENTS_ATTRIBUTES_NIVEL;REQUIREMENTS_ATTRIBUTES_TIPO;REQUIREMENTS_ATTRIBUTES_DIMENSIONES;REQUIREMENTS_ATTRIBUTES_MODOEJECUCION;REQUIREMENTS_ATTRIBUTES_DEPENDENCIAS;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME\r\naws;The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.;123456789012;eu-west-1;{datetime.now()};op.exp.8.aws.ct.3;Registro de actividad;op.exp.8;operacional;explotación;Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.;alto;requisito;trazabilidad;automático;;PASS;;;test-check-id;False;\r\naws;The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.;;;{datetime.now()};op.exp.8.aws.ct.4;Registro de actividad;op.exp.8;operacional;explotación;Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.;alto;requisito;trazabilidad;automático;;MANUAL;Manual check;manual_check;manual;False;Manual check\r\n"
        assert content == expected_csv
