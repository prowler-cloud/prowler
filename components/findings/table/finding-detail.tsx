"use client";

import { Card, CardBody, CardHeader, Divider } from "@nextui-org/react";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { FindingProps } from "@/types";
import {Table, TableHeader, TableColumn, TableBody, TableRow, TableCell} from "@nextui-org/react";

export const FindingDetail = ({ findingDetails }: { findingDetails: FindingProps }) => {
  const finding = findingDetails;
  console.log(finding)
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">

        <Table aria-label="Example static collection table">
      <TableHeader>
        <TableColumn>Name </TableColumn>
        <TableColumn>Value</TableColumn>
      </TableHeader>
      <TableBody>
        <TableRow key="1">
          <TableCell>Resource ID</TableCell>
          <TableCell>{finding.relationships.resource.id}</TableCell>
        </TableRow>
        <TableRow key="2">
          <TableCell>Resource ARN</TableCell>
          <TableCell>{finding.relationships.resource.attributes.uid}</TableCell>
        </TableRow>
        <TableRow key="3">
          <TableCell>Check ID</TableCell>
          <TableCell>{finding.attributes.check_id}</TableCell>
        </TableRow>
        <TableRow key="4">
          <TableCell>Types</TableCell>
          <TableCell>{finding.attributes.check_metadata.checktype}</TableCell>
        </TableRow>
        <TableRow key="5">
          <TableCell>Scan time</TableCell>
          <TableCell>{finding.attributes.inserted_at}</TableCell>
        </TableRow>
        <TableRow key="6">
          <TableCell>Prowler Finding ID</TableCell>
          <TableCell>{finding.relationships.resource.attributes.uid}</TableCell>
        </TableRow>
        <TableRow key="7">
          <TableCell>Severity</TableCell>
          <TableCell>{finding.id}</TableCell>
        </TableRow>
        <TableRow key="8">
          <TableCell>Status</TableCell>
          <TableCell>{finding.attributes.status}</TableCell>
        </TableRow>
        <TableRow key="9">
          <TableCell>Region</TableCell>
          <TableCell>{finding.relationships.resource.attributes.region}</TableCell>
        </TableRow>
        <TableRow key="10">
          <TableCell>Service</TableCell>
          <TableCell>{finding.relationships.resource.attributes.service}</TableCell>
        </TableRow>
        <TableRow key="11">
          <TableCell>Account</TableCell>
          <TableCell>{finding.relationships.provider.attributes.uid}</TableCell>
        </TableRow>
        <TableRow key="12">
          <TableCell>Details</TableCell>
          <TableCell>{finding.attributes.status_extended}</TableCell>
        </TableRow>
        <TableRow key="13">
          <TableCell>Risk</TableCell>
          <TableCell>{finding.attributes.check_metadata.risk}</TableCell>
        </TableRow>
        <TableRow key="14">
          <TableCell>Recommendation</TableCell>
          <TableCell>{finding.attributes.check_metadata.remediation.recommendation.text}</TableCell>
        </TableRow>
        <TableRow key="15">
          <TableCell>CLI</TableCell>
          <TableCell>{finding.attributes.check_metadata.remediation.code.cli}</TableCell>
        </TableRow>
        <TableRow key="16">
          <TableCell>Other</TableCell>
          <TableCell>{finding.attributes.check_metadata.remediation.code.other}</TableCell>
        </TableRow>
        <TableRow key="17">
          <TableCell>Terraform</TableCell>
          <TableCell>{finding.attributes.check_metadata.remediation.code.terraform}</TableCell>
        </TableRow>
      </TableBody>
    </Table>
       
    </div>
    </div>
  );
};
