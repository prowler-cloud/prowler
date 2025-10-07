"use client";

import { useState } from "react";

import {
  DonutChart,
  HorizontalBarChart,
  LineChart,
  RadarChart,
  RadialChart,
  SankeyChart,
  ScatterPlot,
} from "@/components/graphs";

export default function ChartsDemoPage() {
  const [selectedRadarPoint, setSelectedRadarPoint] = useState<any>(null);
  const [selectedScatterPoint, setSelectedScatterPoint] = useState<any>(null);
  // Fake data for demonstrations
  const barChartData = [
    {
      name: "Critical",
      value: 432,
      percentage: 22,
      color: "#971348",
      newFindings: 5,
      change: 18,
    },
    {
      name: "High",
      value: 1232,
      percentage: 32,
      color: "#FF3077",
      newFindings: 21,
      change: -12,
    },
    {
      name: "Medium",
      value: 221,
      percentage: 18,
      color: "#FF7D19",
      newFindings: 8,
      change: 5,
    },
    {
      name: "Low",
      value: 543,
      percentage: 25,
      color: "#FDD34F",
      newFindings: 15,
      change: -8,
    },
    {
      name: "Info",
      value: 10,
      percentage: 3,
      color: "#2E51B2",
      newFindings: 2,
      change: 22,
    },
  ];

  const donutChartData = [
    {
      name: "Fail Findings",
      value: 327,
      percentage: 62,
      color: "#DB2B49",
      new: 11,
      muted: 12,
    },
    {
      name: "Pass Findings",
      value: 1483,
      percentage: 38,
      color: "#20B853",
      new: 31,
      muted: 332,
    },
  ];

  const lineChartData = [
    {
      date: "12/1",
      info: 800,
      low: 1200,
      medium: 900,
      high: 1300,
      critical: 1100,
      info_newFindings: 2,
      info_change: 5,
      low_newFindings: 4,
      low_change: 8,
      medium_newFindings: 6,
      medium_change: 12,
      high_newFindings: 8,
      high_change: 15,
      critical_newFindings: 5,
      critical_change: 10,
    },
    {
      date: "12/2",
      info: 700,
      low: 1000,
      medium: 800,
      high: 1100,
      critical: 1000,
      info_newFindings: 1,
      info_change: -13,
      low_newFindings: 3,
      low_change: -17,
      medium_newFindings: 2,
      medium_change: -11,
      high_newFindings: 4,
      high_change: -15,
      critical_newFindings: 3,
      critical_change: -9,
    },
    {
      date: "12/3",
      info: 600,
      low: 1400,
      medium: 900,
      high: 2000,
      critical: 2100,
      info_newFindings: 3,
      info_change: -14,
      low_newFindings: 8,
      low_change: 40,
      medium_newFindings: 5,
      medium_change: 13,
      high_newFindings: 15,
      high_change: 82,
      critical_newFindings: 12,
      critical_change: 110,
    },
    {
      date: "12/4",
      info: 500,
      low: 1200,
      medium: 800,
      high: 1500,
      critical: 1300,
      info_newFindings: 1,
      info_change: -17,
      low_newFindings: 5,
      low_change: -14,
      medium_newFindings: 4,
      medium_change: -11,
      high_newFindings: 7,
      high_change: -25,
      critical_newFindings: 6,
      critical_change: -38,
    },
    {
      date: "12/5",
      info: 900,
      low: 2000,
      medium: 1000,
      high: 2500,
      critical: 2400,
      info_newFindings: 5,
      info_change: 80,
      low_newFindings: 10,
      low_change: 67,
      medium_newFindings: 8,
      medium_change: 25,
      high_newFindings: 12,
      high_change: 67,
      critical_newFindings: 10,
      critical_change: 85,
    },
  ];

  const lineChartLines = [
    { dataKey: "critical", color: "#971348", label: "Critical" },
    { dataKey: "high", color: "#FF3077", label: "High" },
    { dataKey: "medium", color: "#FF7D19", label: "Medium" },
    { dataKey: "low", color: "#FDD34F", label: "Low" },
    { dataKey: "info", color: "#2E51B2", label: "Info" },
  ];

  const radarChartData = [
    { category: "Trust Boundaries", value: 455, change: 12 },
    { category: "Internet Exposed", value: 320, change: -8 },
    { category: "Forensics-ready", value: 180, change: 15 },
    { category: "Secrets", value: 250, change: -5 },
    { category: "Cluster Security", value: 200, change: 22 },
    { category: "Container Security", value: 290, change: -3 },
    { category: "Logging", value: 280, change: 7 },
    { category: "Encryption", value: 340, change: -10 },
  ];

  const sankeyData = {
    nodes: [
      { name: "Total Findings" },
      { name: "Success" },
      { name: "Fail" },
      { name: "AWS" },
      { name: "Azure" },
      { name: "Google" },
      { name: "Critical" },
      { name: "High" },
      { name: "Medium" },
      { name: "Low" },
      { name: "Info" },
    ],
    links: [
      { source: 0, target: 1, value: 883 },
      { source: 0, target: 2, value: 1000 },
      { source: 2, target: 3, value: 200 },
      { source: 2, target: 4, value: 300 },
      { source: 2, target: 5, value: 500 },
      { source: 3, target: 6, value: 25 },
      { source: 3, target: 7, value: 50 },
      { source: 3, target: 8, value: 75 },
      { source: 3, target: 9, value: 50 },
      { source: 4, target: 6, value: 50 },
      { source: 4, target: 7, value: 100 },
      { source: 4, target: 8, value: 100 },
      { source: 4, target: 9, value: 50 },
      { source: 5, target: 7, value: 75 },
      { source: 5, target: 8, value: 50 },
      { source: 5, target: 9, value: 75 },
      { source: 5, target: 10, value: 300 },
    ],
  };

  const scatterPlotData = [
    { x: 2.1, y: 185, provider: "AWS", name: "Prod-AWS-1", size: 10 },
    { x: 2.5, y: 100, provider: "AWS", name: "Dev-AWS-1", size: 8 },
    { x: 2.8, y: 200, provider: "AWS", name: "Staging-AWS-1", size: 12 },
    { x: 4.2, y: 340, provider: "AWS", name: "Test-AWS-1", size: 15 },
    { x: 4.0, y: 280, provider: "Azure", name: "Prowler-Dev-2", size: 14 },
    { x: 4.5, y: 225, provider: "Azure", name: "Azure-Prod-1", size: 11 },
    { x: 4.3, y: 280, provider: "Azure", name: "Azure-Test-1", size: 14 },
    { x: 4.7, y: 235, provider: "Azure", name: "Azure-Dev-1", size: 12 },
    { x: 4.8, y: 185, provider: "Azure", name: "Azure-Staging-1", size: 9 },
    { x: 2.7, y: 20, provider: "Google", name: "GCP-Prod-1", size: 6 },
    { x: 2.9, y: 145, provider: "Google", name: "GCP-Dev-1", size: 8 },
    { x: 3.2, y: 90, provider: "Google", name: "GCP-Test-1", size: 7 },
    { x: 6.2, y: 270, provider: "AWS", name: "Critical-AWS-1", size: 16 },
    { x: 6.0, y: 210, provider: "Azure", name: "Critical-Azure-1", size: 13 },
    { x: 6.3, y: 155, provider: "Google", name: "Critical-GCP-1", size: 10 },
    { x: 6.5, y: 215, provider: "Google", name: "High-Risk-GCP", size: 13 },
    { x: 9.2, y: 265, provider: "AWS", name: "Very-High-AWS", size: 20 },
  ];

  return (
    <div className="min-h-screen bg-slate-900 p-8">
      <div className="mx-auto max-w-7xl space-y-12">
        <div className="space-y-2">
          <h1 className="text-4xl font-bold text-white">
            Graph Components Demo
          </h1>
          <p className="text-slate-400">
            Testing reusable chart components for the Prowler Dashboard
          </p>
        </div>

        {/* Radial Chart - Threat Score */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Radial Chart</h2>
            <p className="text-sm text-slate-400">
              Used for: Threat Score (Story 1)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <div className="mx-auto max-w-sm">
              <RadialChart
                percentage={52}
                label="Moderately Secure"
                color="#86DA26"
                height={250}
              />
            </div>
          </div>
        </section>

        {/* Donut Chart - Check Findings */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Donut Chart</h2>
            <p className="text-sm text-slate-400">
              Used for: Check Findings (Story 2), Resource Inventory (Story 5)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <DonutChart
              data={donutChartData}
              centerLabel={{ value: "1,883", label: "Total Findings" }}
              height={350}
            />
          </div>
        </section>

        {/* Horizontal Bar Chart - Risk Severity */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">
              Horizontal Bar Chart (Risk Severity)
            </h2>
            <p className="text-sm text-slate-400">
              Used for: Risk Severity (Story 3)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <HorizontalBarChart
              data={barChartData}
              title="Risk Severity"
              showSortDropdown={true}
            />
          </div>
        </section>

        {/* Line Chart - Severity Over Time */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Line Chart</h2>
            <p className="text-sm text-slate-400">
              Used for: Finding Severity Over Time (Story 7)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <LineChart
              data={lineChartData}
              lines={lineChartLines}
              height={400}
            />
          </div>
        </section>

        {/* Radar Chart - Risk Radar */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Radar Chart</h2>
            <p className="text-sm text-slate-400">
              Used for: Risk Radar (Story 8)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <RadarChart
              data={radarChartData}
              height={450}
              selectedPoint={selectedRadarPoint}
              onSelectPoint={setSelectedRadarPoint}
            />
            {selectedRadarPoint && (
              <div className="mt-4 rounded-lg bg-slate-700 p-3">
                <p className="text-sm text-white">
                  Selected: {selectedRadarPoint.category} -{" "}
                  {selectedRadarPoint.value} findings
                </p>
              </div>
            )}
          </div>
        </section>

        {/* Sankey Chart - Risk Pipeline */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Sankey Chart</h2>
            <p className="text-sm text-slate-400">
              Used for: Risk Pipeline (Story 9)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <SankeyChart data={sankeyData} height={450} />
          </div>
        </section>

        {/* Scatter Plot - Risk Plot */}
        <section className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Scatter Plot</h2>
            <p className="text-sm text-slate-400">
              Used for: Risk Plot (Story 10)
            </p>
          </div>
          <div className="rounded-lg bg-slate-800 p-6">
            <ScatterPlot
              data={scatterPlotData}
              xLabel="Risk Score"
              yLabel="Failed Findings"
              height={450}
              selectedPoint={selectedScatterPoint}
              onSelectPoint={(point) => {
                setSelectedScatterPoint(point);
              }}
            />
            {selectedScatterPoint && (
              <div className="mt-4 rounded-lg bg-slate-700 p-3">
                <p className="text-sm text-white">
                  Selected: {selectedScatterPoint.name} (
                  {selectedScatterPoint.provider})
                </p>
                <p className="text-xs text-slate-400">
                  Risk Score: {selectedScatterPoint.x} | Failed Findings:{" "}
                  {selectedScatterPoint.y}
                </p>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
