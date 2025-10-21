import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import { getLatestFindings } from "@/actions/findings/findings";
import {
  getFindingsBySeverity,
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import { FilterControls } from "@/components/filters";
import {
  DonutChart,
  HorizontalBarChart,
  LineChart,
  RadarChart,
  RadialChart,
  SankeyChart,
  ScatterPlot,
  ThreatMap,
} from "@/components/graphs";
import { LighthouseBanner } from "@/components/lighthouse";
import {
  FindingsBySeverityChart,
  FindingsByStatusChart,
  LinkToFindings,
  ProvidersOverview,
  RadarChartWithSelection,
  ScatterPlotWithSelection,
  SkeletonFindingsBySeverityChart,
  SkeletonFindingsByStatusChart,
  SkeletonProvidersOverview,
} from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { SkeletonTableNewFindings } from "@/components/overview/new-findings-table/table/skeleton-table-new-findings";
import { ContentLayout } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib/helper";
import { FindingProps, SearchParamsProps } from "@/types";

const FILTER_PREFIX = "filter[";

// Sample data for ThreatMap component
const RISK_LEVELS = {
  LOW_HIGH: "low-high",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

const sampleThreatMapData = {
  regions: ["US East", "US West", "Europe", "Asia Pacific", "South America"],
  locations: [
    {
      id: "us-east-1",
      name: "US East-1",
      region: "US East",
      coordinates: [-77.4875, 39.0438] as [number, number],
      totalFindings: 455,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      change: 21,
      severityData: [
        { name: "Info", value: 10, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 543,
          percentage: 25,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 221,
          percentage: 18,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 1232,
          percentage: 32,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 432,
          percentage: 22,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "us-west-2",
      name: "US West-2",
      region: "US West",
      coordinates: [-121.7269, 45.6387] as [number, number],
      totalFindings: 324,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 8, percentage: 2, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 89,
          percentage: 15,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 156,
          percentage: 28,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 187,
          percentage: 35,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 124,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "eu-west-1",
      name: "EU West-1",
      region: "Europe",
      coordinates: [-6.2603, 53.3498] as [number, number],
      totalFindings: 567,
      riskLevel: RISK_LEVELS.CRITICAL,
      change: 15,
      severityData: [
        { name: "Info", value: 12, percentage: 2, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 98,
          percentage: 10,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 203,
          percentage: 22,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 354,
          percentage: 38,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 267,
          percentage: 28,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "eu-central-1",
      name: "EU Central-1",
      region: "Europe",
      coordinates: [8.6821, 50.1109] as [number, number],
      totalFindings: 289,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      severityData: [
        { name: "Info", value: 15, percentage: 5, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 134,
          percentage: 32,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 87,
          percentage: 22,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 103,
          percentage: 28,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 43,
          percentage: 13,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "ap-northeast-1",
      name: "AP Northeast-1",
      region: "Asia Pacific",
      coordinates: [139.6917, 35.6895] as [number, number],
      totalFindings: 412,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 9, percentage: 2, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 87,
          percentage: 18,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 145,
          percentage: 26,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 198,
          percentage: 34,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 112,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "ap-southeast-1",
      name: "AP Southeast-1",
      region: "Asia Pacific",
      coordinates: [103.8198, 1.3521] as [number, number],
      totalFindings: 378,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 11, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 76,
          percentage: 16,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 132,
          percentage: 25,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 187,
          percentage: 36,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 94,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "ap-south-1",
      name: "AP South-1",
      region: "Asia Pacific",
      coordinates: [72.8777, 19.076] as [number, number],
      totalFindings: 234,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      change: -8,
      severityData: [
        { name: "Info", value: 7, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 98,
          percentage: 28,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 76,
          percentage: 24,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 89,
          percentage: 30,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 43,
          percentage: 15,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "sa-east-1",
      name: "SA East-1",
      region: "South America",
      coordinates: [-46.6333, -23.5505] as [number, number],
      totalFindings: 189,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      severityData: [
        { name: "Info", value: 6, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 87,
          percentage: 30,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 54,
          percentage: 22,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 67,
          percentage: 28,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 32,
          percentage: 17,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "ca-central-1",
      name: "CA Central-1",
      region: "US East",
      coordinates: [-73.5673, 45.5017] as [number, number],
      totalFindings: 267,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      severityData: [
        { name: "Info", value: 8, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 112,
          percentage: 27,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 87,
          percentage: 23,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 98,
          percentage: 30,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 54,
          percentage: 17,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "ap-southeast-2",
      name: "AP Southeast-2",
      region: "Asia Pacific",
      coordinates: [151.2093, -33.8688] as [number, number],
      totalFindings: 345,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 10, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 78,
          percentage: 17,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 121,
          percentage: 25,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 167,
          percentage: 35,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 89,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "eu-west-2",
      name: "EU West-2",
      region: "Europe",
      coordinates: [-0.1278, 51.5074] as [number, number],
      totalFindings: 423,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 11, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 98,
          percentage: 19,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 154,
          percentage: 26,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 189,
          percentage: 32,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 112,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "us-east-2",
      name: "US East-2",
      region: "US East",
      coordinates: [-82.9988, 39.9612] as [number, number],
      totalFindings: 298,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      severityData: [
        { name: "Info", value: 9, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 123,
          percentage: 28,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 89,
          percentage: 23,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 101,
          percentage: 29,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 54,
          percentage: 17,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "us-west-1",
      name: "US West-1",
      region: "US West",
      coordinates: [-121.8863, 37.3382] as [number, number],
      totalFindings: 389,
      riskLevel: RISK_LEVELS.HIGH,
      severityData: [
        { name: "Info", value: 10, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 87,
          percentage: 18,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 143,
          percentage: 26,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 176,
          percentage: 33,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 98,
          percentage: 20,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
    {
      id: "eu-north-1",
      name: "EU North-1",
      region: "Europe",
      coordinates: [18.0686, 59.3293] as [number, number],
      totalFindings: 213,
      riskLevel: RISK_LEVELS.LOW_HIGH,
      severityData: [
        { name: "Info", value: 7, percentage: 3, color: "var(--chart-info)" },
        {
          name: "Low",
          value: 89,
          percentage: 29,
          color: "var(--chart-warning)",
        },
        {
          name: "Medium",
          value: 67,
          percentage: 23,
          color: "var(--chart-warning-emphasis)",
        },
        {
          name: "High",
          value: 76,
          percentage: 28,
          color: "var(--chart-danger)",
        },
        {
          name: "Critical",
          value: 43,
          percentage: 17,
          color: "var(--chart-danger-emphasis)",
        },
      ],
    },
  ],
};

// Sample data for DonutChart
const sampleDonutChartData = [
  {
    name: "AWS",
    value: 1840,
    percentage: 45,
    color: "var(--chart-provider-aws)",
    change: 5,
  },
  {
    name: "Azure",
    value: 1280,
    percentage: 32,
    color: "var(--chart-provider-azure)",
    change: -2,
  },
  {
    name: "Google",
    value: 920,
    percentage: 23,
    color: "var(--chart-provider-google)",
    change: 8,
  },
];

// Sample data for LineChart
const sampleLineChartData = [
  { date: "Jan", critical: 385, high: 1100, medium: 820, low: 450 },
  { date: "Feb", critical: 398, high: 1150, medium: 870, low: 480 },
  { date: "Mar", critical: 410, high: 1180, medium: 890, low: 510 },
  { date: "Apr", critical: 425, high: 1210, medium: 915, low: 530 },
  { date: "May", critical: 418, high: 1195, medium: 905, low: 520 },
  { date: "Jun", critical: 432, high: 1232, medium: 925, low: 543 },
];

const sampleLineConfig = [
  {
    dataKey: "critical",
    color: "var(--chart-danger-emphasis)",
    label: "Critical",
  },
  { dataKey: "high", color: "var(--chart-danger)", label: "High" },
  {
    dataKey: "medium",
    color: "var(--chart-warning-emphasis)",
    label: "Medium",
  },
  { dataKey: "low", color: "var(--chart-warning)", label: "Low" },
];

// Sample data for HorizontalBarChart (Severity Distribution)
const sampleHorizontalBarData = [
  {
    name: "Critical",
    value: 432,
    percentage: 22,
    newFindings: 15,
    change: 5,
  },
  { name: "High", value: 1232, percentage: 32, newFindings: 45, change: 8 },
  {
    name: "Medium",
    value: 925,
    percentage: 28,
    newFindings: 32,
    change: -3,
  },
  { name: "Low", value: 543, percentage: 15, newFindings: 18, change: -2 },
  { name: "Info", value: 108, percentage: 3, newFindings: 5, change: 0 },
];

// Sample data for SankeyChart
const sampleSankeyData = {
  nodes: [
    { name: "Success" },
    { name: "Fail" },
    { name: "AWS" },
    { name: "Azure" },
    { name: "Google" },
    { name: "Critical", newFindings: 5, change: 15 },
    { name: "High", newFindings: 12, change: 8 },
    { name: "Medium", newFindings: 28, change: -3 },
    { name: "Low", newFindings: 45, change: -8 },
    { name: "Info", newFindings: 18, change: 2 },
  ],
  links: [
    // Success to Providers
    { source: 0, target: 2, value: 300 }, // Success -> AWS
    { source: 0, target: 3, value: 283 }, // Success -> Azure
    { source: 0, target: 4, value: 300 }, // Success -> Google

    // Fail to Providers
    { source: 1, target: 2, value: 200 }, // Fail -> AWS
    { source: 1, target: 3, value: 300 }, // Fail -> Azure
    { source: 1, target: 4, value: 500 }, // Fail -> Google

    // AWS to Severities (Critical to Info order)
    { source: 2, target: 5, value: 8 }, // AWS -> Critical
    { source: 2, target: 6, value: 25 }, // AWS -> High
    { source: 2, target: 7, value: 67 }, // AWS -> Medium
    { source: 2, target: 8, value: 80 }, // AWS -> Low
    { source: 2, target: 9, value: 20 }, // AWS -> Info

    // Azure to Severities
    { source: 3, target: 5, value: 10 }, // Azure -> Critical
    { source: 3, target: 6, value: 35 }, // Azure -> High
    { source: 3, target: 7, value: 95 }, // Azure -> Medium
    { source: 3, target: 8, value: 130 }, // Azure -> Low
    { source: 3, target: 9, value: 30 }, // Azure -> Info

    // Google to Severities
    { source: 4, target: 5, value: 7 }, // Google -> Critical
    { source: 4, target: 6, value: 40 }, // Google -> High
    { source: 4, target: 7, value: 163 }, // Google -> Medium
    { source: 4, target: 8, value: 190 }, // Google -> Low
    { source: 4, target: 9, value: 100 }, // Google -> Info
  ],
};

// Sample data for ScatterPlot
const sampleScatterPlotData = [
  { x: 8.2, y: 45, provider: "AWS", name: "S3 Buckets", size: 120 },
  { x: 7.5, y: 62, provider: "AWS", name: "EC2 Instances", size: 95 },
  { x: 6.8, y: 78, provider: "Azure", name: "Storage Accounts", size: 85 },
  { x: 9.1, y: 32, provider: "AWS", name: "RDS Databases", size: 110 },
  { x: 5.4, y: 88, provider: "Google", name: "Cloud Storage", size: 75 },
  { x: 7.9, y: 55, provider: "Azure", name: "Virtual Machines", size: 90 },
  { x: 8.5, y: 48, provider: "AWS", name: "Lambda Functions", size: 105 },
  { x: 6.2, y: 82, provider: "Google", name: "Compute Engine", size: 80 },
  { x: 7.2, y: 68, provider: "Azure", name: "SQL Databases", size: 88 },
  { x: 8.8, y: 41, provider: "AWS", name: "IAM Users", size: 115 },
];

// Extract only query params that start with "filter[" for API calls
function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});
  return (
    <ContentLayout title="Overview" icon="lucide:square-chart-gantt">
      <FilterControls providers mutedFindings showClearButton={false} />

      <div className="grid grid-cols-12 gap-12 lg:gap-6">
        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonProvidersOverview />}>
            <SSRProvidersOverview />
          </Suspense>
        </div>

        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonFindingsBySeverityChart />}>
            <SSRFindingsBySeverity searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonFindingsByStatusChart />}>
            <SSRFindingsByStatus searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <div className="col-span-12">
          <Spacer y={16} />
          <Suspense
            key={searchParamsKey}
            fallback={<SkeletonTableNewFindings />}
          >
            <SSRDataNewFindingsTable searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <div className="col-span-12 lg:col-span-6">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Security Categories
          </h3>
          <RadarChartWithSelection />
        </div>

        <div className="col-span-12 lg:col-span-6">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">Threat Map</h3>
          <ThreatMap data={sampleThreatMapData} height={400} />
        </div>

        <div className="col-span-12 lg:col-span-6">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Findings by Severity
          </h3>
          <HorizontalBarChart data={sampleHorizontalBarData} />
        </div>

        <div className="col-span-12 lg:col-span-6">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Provider Distribution
          </h3>
          <DonutChart
            data={sampleDonutChartData}
            height={350}
            showLegend
            centerLabel={{
              value: "4,040",
              label: "Total Findings",
            }}
          />
        </div>

        <div className="col-span-12">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Findings Trend Over Time
          </h3>
          <LineChart
            data={sampleLineChartData}
            lines={sampleLineConfig}
            height={350}
            xLabel="Month"
            yLabel="Findings"
          />
        </div>

        <div className="col-span-12">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Provider to Severity Flow
          </h3>
          <SankeyChart data={sampleSankeyData} height={400} />
        </div>

        <div className="col-span-12 lg:col-span-6">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">Compliance Score</h3>
          <RadialChart
            percentage={78}
            label="Overall Compliance"
            color="var(--chart-success-color)"
            height={350}
          />
        </div>

        <div className="col-span-12">
          <Spacer y={16} />
          <h3 className="mb-4 text-sm font-bold uppercase">
            Risk Score vs Compliance by Service
          </h3>
          <ScatterPlotWithSelection
            data={sampleScatterPlotData}
            height={400}
            xLabel="Risk Score"
            yLabel="Compliance %"
          />
        </div>
      </div>
    </ContentLayout>
  );
}

const SSRProvidersOverview = async () => {
  const providersOverview = await getProvidersOverview({});

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">Providers Overview</h3>
      <ProvidersOverview providersOverview={providersOverview} />
    </>
  );
};

const SSRFindingsByStatus = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">Findings by Status</h3>
      <FindingsByStatusChart findingsByStatus={findingsByStatus} />
    </>
  );
};

const SSRFindingsBySeverity = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const defaultFilters = {
    "filter[status]": "FAIL",
  } as const;

  const filters = pickFilterParams(searchParams);

  const combinedFilters = { ...defaultFilters, ...filters };

  const findingsBySeverity = await getFindingsBySeverity({
    filters: combinedFilters,
  });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">
        Failed Findings by Severity
      </h3>
      <FindingsBySeverityChart findingsBySeverity={findingsBySeverity} />
    </>
  );
};

const SSRDataNewFindingsTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const page = 1;
  const sort = "severity,-inserted_at";

  const defaultFilters = {
    "filter[status]": "FAIL",
    "filter[delta]": "new",
  };

  const filters = pickFilterParams(searchParams);

  const combinedFilters = { ...defaultFilters, ...filters };

  const findingsData = await getLatestFindings({
    query: undefined,
    page,
    sort,
    filters: combinedFilters,
  });

  // Create dictionaries for resources, scans, and providers
  const resourceDict = createDict("resources", findingsData);
  const scanDict = createDict("scans", findingsData);
  const providerDict = createDict("providers", findingsData);

  // Expand each finding with its corresponding resource, scan, and provider
  const expandedFindings = findingsData?.data
    ? findingsData.data.map((finding: FindingProps) => {
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

        return {
          ...finding,
          relationships: { scan, resource, provider },
        };
      })
    : [];

  // Create the new object while maintaining the original structure
  const expandedResponse = {
    ...findingsData,
    data: expandedFindings,
  };

  return (
    <>
      <div className="relative flex w-full">
        <div className="flex w-full items-center gap-2">
          <h3 className="text-sm font-bold uppercase">
            Latest new failing findings
          </h3>
          <p className="text-xs text-gray-500">
            Showing the latest 10 new failing findings by severity.
          </p>
        </div>
        <div className="absolute -top-6 right-0">
          <LinkToFindings />
        </div>
      </div>
      <Spacer y={4} />

      <LighthouseBanner />

      <DataTable
        key={`dashboard-${Date.now()}`}
        columns={ColumnNewFindingsToDate}
        data={expandedResponse?.data || []}
        // metadata={findingsData?.meta}
      />
    </>
  );
};
