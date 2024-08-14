import { FilterControls } from "@/components/filters";
import {
  AmazonEC2Icon,
  AmazonEMRIcon,
  AmazonGuardDutyIcon,
  AmazonInspectorIcon,
  AmazonMacieIcon,
  AmazonRDSIcon,
  AmazonRoute53Icon,
  AmazonS3Icon,
  AmazonSNSIcon,
  AmazonVPCIcon,
  AWSAccountIcon,
  AWSAthenaIcon,
  AWSCertificateManagerIcon,
  AWSCloudFormationIcon,
  AWSCloudTrailIcon,
  AWSCloudWatchIcon,
  AWSConfigIcon,
  AWSDatabaseMigrationServiceIcon,
  AWSGlueIcon,
  AWSIAMIcon,
  AWSLambdaIcon,
  AWSNetworkFirewallIcon,
  AWSOrganizationsIcon,
  AWSResourceExplorerIcon,
  AWSSecurityHubIcon,
  AWSSystemsManagerIncidentManagerIcon,
  AWSTrustedAdvisorIcon,
  IAMAccessAnalyzerIcon,
} from "@/components/icons";
import { Header } from "@/components/ui";

export default function Services() {
  return (
    <>
      <Header
        title="Services"
        icon="material-symbols:linked-services-outline"
      />
      <FilterControls />

      <IAMAccessAnalyzerIcon />
      <AWSAccountIcon />
      <AWSCertificateManagerIcon />
      <AWSAthenaIcon />
      <AWSLambdaIcon />
      <AWSCloudFormationIcon />
      <AWSCloudTrailIcon />
      <AWSCloudWatchIcon />
      <AWSConfigIcon />
      <AWSDatabaseMigrationServiceIcon />
      <AmazonEC2Icon />
      <AmazonEMRIcon />
      <AWSGlueIcon />
      <AmazonGuardDutyIcon />
      <AmazonInspectorIcon />
      <AWSIAMIcon />
      <AmazonMacieIcon />
      <AWSNetworkFirewallIcon />
      <AWSOrganizationsIcon />
      <AmazonRDSIcon />
      <AWSResourceExplorerIcon />
      <AmazonRoute53Icon />
      <AmazonS3Icon />
      <AWSSecurityHubIcon />
      <AmazonSNSIcon />
      <AWSSystemsManagerIncidentManagerIcon />
      <AWSTrustedAdvisorIcon />
      <AmazonVPCIcon />
    </>
  );
}
