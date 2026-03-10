"use client";

import * as d3 from "d3";
import type {
  Feature,
  FeatureCollection,
  GeoJsonProperties,
  Geometry,
} from "geojson";
import { AlertTriangle, Info, MapPin } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { feature } from "topojson-client";
import type {
  GeometryCollection,
  Objects,
  Topology,
} from "topojson-specification";

import { HorizontalBarChart } from "./horizontal-bar-chart";
import { BarDataPoint } from "./types";

// Constants
const MAP_CONFIG = {
  defaultWidth: 688,
  defaultHeight: 400,
  pointRadius: 6,
  selectedPointRadius: 8,
  transitionDuration: 300,
} as const;

const MAP_COLORS = {
  landFill: "var(--border-neutral-tertiary)",
  landStroke: "var(--border-neutral-secondary)",
  pointDefault: "var(--bg-fail)",
  pointSelected: "var(--bg-pass)",
  pointHover: "var(--bg-fail)",
} as const;

export const RISK_LEVELS = {
  LOW_HIGH: "low-high",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

type RiskLevel = (typeof RISK_LEVELS)[keyof typeof RISK_LEVELS];

interface LocationPoint {
  id: string;
  name: string;
  region: string;
  coordinates: [number, number];
  totalFindings: number;
  riskLevel: RiskLevel;
  severityData: BarDataPoint[];
  change?: number;
}

export interface MapChartData {
  locations: LocationPoint[];
  regions: string[];
}

export interface MapChartProps {
  data: MapChartData;
  height?: number;
  onLocationSelect?: (location: LocationPoint | null) => void;
}

// Utility functions
function createProjection(width: number, height: number) {
  return d3
    .geoNaturalEarth1()
    .fitExtent(
      [
        [1, 1],
        [width - 1, height - 1],
      ],
      { type: "Sphere" },
    )
    .precision(0.2);
}

async function fetchWorldData(): Promise<FeatureCollection | null> {
  try {
    const worldAtlasModule = await import("world-atlas/countries-110m.json");
    const worldData = worldAtlasModule.default || worldAtlasModule;
    const topology = worldData as unknown as Topology<Objects>;
    return feature(
      topology,
      topology.objects.countries as GeometryCollection,
    ) as FeatureCollection;
  } catch (error) {
    console.error("Error loading world map data:", error);
    return null;
  }
}

// Helper: Create SVG element
function createSVGElement<T extends SVGElement>(
  type: string,
  attributes: Record<string, string>,
): T {
  const element = document.createElementNS(
    "http://www.w3.org/2000/svg",
    type,
  ) as T;
  Object.entries(attributes).forEach(([key, value]) => {
    element.setAttribute(key, value);
  });
  return element;
}

// Components
function MapTooltip({
  location,
  position,
}: {
  location: LocationPoint;
  position: { x: number; y: number };
}) {
  const CHART_COLORS = {
    tooltipBorder: "var(--border-neutral-tertiary)",
    tooltipBackground: "var(--bg-neutral-secondary)",
    textPrimary: "var(--text-neutral-primary)",
    textSecondary: "var(--text-neutral-secondary)",
  };

  return (
    <div
      className="pointer-events-none absolute z-50 min-w-[200px] rounded-lg border p-3 shadow-lg"
      style={{
        left: `${position.x + 15}px`,
        top: `${position.y + 15}px`,
        transform: "translate(0, -50%)",
        borderColor: CHART_COLORS.tooltipBorder,
        backgroundColor: CHART_COLORS.tooltipBackground,
      }}
    >
      <div className="flex items-center gap-2">
        <MapPin size={14} style={{ color: CHART_COLORS.textSecondary }} />
        <span
          className="text-sm font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          {location.name}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <AlertTriangle size={14} className="text-[#DB2B49]" />
        <span className="text-sm" style={{ color: CHART_COLORS.textPrimary }}>
          {location.totalFindings.toLocaleString()} Fail Findings
        </span>
      </div>
      {location.change !== undefined && (
        <p
          className="mt-1 text-xs"
          style={{ color: CHART_COLORS.textSecondary }}
        >
          <span className="font-bold">
            {location.change > 0 ? "+" : ""}
            {location.change}%
          </span>{" "}
          since last scan
        </p>
      )}
    </div>
  );
}

function EmptyState() {
  const CHART_COLORS = {
    tooltipBorder: "var(--border-neutral-tertiary)",
    tooltipBackground: "var(--bg-neutral-secondary)",
    textSecondary: "var(--text-neutral-secondary)",
  };

  return (
    <div
      className="flex h-full min-h-[400px] w-full items-center justify-center rounded-lg border p-6"
      style={{
        borderColor: CHART_COLORS.tooltipBorder,
        backgroundColor: CHART_COLORS.tooltipBackground,
      }}
    >
      <div className="text-center">
        <Info
          size={48}
          className="mx-auto mb-2"
          style={{ color: CHART_COLORS.textSecondary }}
        />
        <p className="text-sm" style={{ color: CHART_COLORS.textSecondary }}>
          Select a location on the map to view details
        </p>
      </div>
    </div>
  );
}

function LoadingState({ height }: { height: number }) {
  const CHART_COLORS = {
    textSecondary: "var(--text-neutral-secondary)",
  };

  return (
    <div className="flex items-center justify-center" style={{ height }}>
      <div className="text-center">
        <div className="mb-2" style={{ color: CHART_COLORS.textSecondary }}>
          Loading map...
        </div>
      </div>
    </div>
  );
}

export function MapChart({
  data,
  height = MAP_CONFIG.defaultHeight,
}: MapChartProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedLocation, setSelectedLocation] =
    useState<LocationPoint | null>(null);
  const [hoveredLocation, setHoveredLocation] = useState<LocationPoint | null>(
    null,
  );
  const [tooltipPosition, setTooltipPosition] = useState<{
    x: number;
    y: number;
  } | null>(null);
  const [worldData, setWorldData] = useState<FeatureCollection | null>(null);
  const [isLoadingMap, setIsLoadingMap] = useState(true);
  const [dimensions, setDimensions] = useState<{
    width: number;
    height: number;
  }>({
    width: MAP_CONFIG.defaultWidth,
    height,
  });

  // Fetch world data once on mount
  useEffect(() => {
    let isMounted = true;
    fetchWorldData()
      .then((data) => {
        if (isMounted && data) setWorldData(data);
      })
      .catch(console.error)
      .finally(() => {
        if (isMounted) setIsLoadingMap(false);
      });
    return () => {
      isMounted = false;
    };
  }, []);

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({ width: containerRef.current.clientWidth, height });
      }
    };
    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, [height]);

  // Render the map
  useEffect(() => {
    if (!svgRef.current || !worldData || isLoadingMap) return;

    const svg = svgRef.current;
    const { width, height } = dimensions;
    svg.innerHTML = "";

    const projection = createProjection(width, height);
    const path = d3.geoPath().projection(projection);

    // Render countries
    const mapGroup = createSVGElement<SVGGElement>("g", {
      class: "map-countries",
    });
    worldData.features?.forEach(
      (feature: Feature<Geometry, GeoJsonProperties>) => {
        const pathData = path(feature);
        if (pathData) {
          const pathElement = createSVGElement<SVGPathElement>("path", {
            d: pathData,
            fill: MAP_COLORS.landFill,
            stroke: MAP_COLORS.landStroke,
            "stroke-width": "0.5",
          });
          mapGroup.appendChild(pathElement);
        }
      },
    );
    svg.appendChild(mapGroup);

    // Helper to update tooltip position
    const updateTooltip = (e: MouseEvent) => {
      const rect = svg.getBoundingClientRect();
      setTooltipPosition({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    };

    // Helper to create circle
    const createCircle = (location: LocationPoint) => {
      const projected = projection(location.coordinates);
      if (!projected) return null;

      const [x, y] = projected;
      if (x < 0 || x > width || y < 0 || y > height) return null;

      const isSelected = selectedLocation?.id === location.id;
      const isHovered = hoveredLocation?.id === location.id;
      const classes = ["cursor-pointer"];

      if (isSelected) classes.push("drop-shadow-[0_0_8px_#86da26]");
      if (isHovered && !isSelected) classes.push("opacity-70");

      const circle = createSVGElement<SVGCircleElement>("circle", {
        cx: x.toString(),
        cy: y.toString(),
        r: (isSelected
          ? MAP_CONFIG.selectedPointRadius
          : MAP_CONFIG.pointRadius
        ).toString(),
        fill: isSelected ? MAP_COLORS.pointSelected : MAP_COLORS.pointDefault,
        class: classes.join(" "),
      });

      circle.addEventListener("click", () =>
        setSelectedLocation(isSelected ? null : location),
      );
      circle.addEventListener("mouseenter", (e) => {
        setHoveredLocation(location);
        updateTooltip(e);
      });
      circle.addEventListener("mousemove", updateTooltip);
      circle.addEventListener("mouseleave", () => {
        setHoveredLocation(null);
        setTooltipPosition(null);
      });

      return circle;
    };

    // Render points
    const pointsGroup = createSVGElement<SVGGElement>("g", {
      class: "threat-points",
    });

    // Unselected points first
    data.locations.forEach((location) => {
      if (selectedLocation?.id !== location.id) {
        const circle = createCircle(location);
        if (circle) pointsGroup.appendChild(circle);
      }
    });

    // Selected point last (on top)
    if (selectedLocation) {
      const selectedData = data.locations.find(
        (loc) => loc.id === selectedLocation.id,
      );
      if (selectedData) {
        const circle = createCircle(selectedData);
        if (circle) pointsGroup.appendChild(circle);
      }
    }

    svg.appendChild(pointsGroup);
  }, [
    data.locations,
    dimensions,
    selectedLocation,
    hoveredLocation,
    worldData,
    isLoadingMap,
  ]);

  const CHART_COLORS = {
    tooltipBorder: "var(--border-neutral-tertiary)",
    tooltipBackground: "var(--bg-neutral-secondary)",
    textPrimary: "var(--text-neutral-primary)",
    textSecondary: "var(--text-neutral-secondary)",
  };

  return (
    <div className="flex w-full flex-col gap-6 lg:flex-row lg:items-start">
      {/* Map Section */}
      <div className="flex-1">
        <h3
          className="mb-4 text-lg font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          Threat Map
        </h3>

        <div
          ref={containerRef}
          className="rounded-lg border p-4"
          style={{
            borderColor: CHART_COLORS.tooltipBorder,
            backgroundColor: CHART_COLORS.tooltipBackground,
          }}
        >
          {isLoadingMap ? (
            <LoadingState height={dimensions.height} />
          ) : (
            <>
              <div className="relative">
                <svg
                  ref={svgRef}
                  width={dimensions.width}
                  height={dimensions.height}
                  className="w-full"
                  style={{ maxWidth: "100%" }}
                />
                {hoveredLocation && tooltipPosition && (
                  <MapTooltip
                    location={hoveredLocation}
                    position={tooltipPosition}
                  />
                )}
              </div>
              <div className="mt-4 flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-[#DB2B49]" />
                <span
                  className="text-sm"
                  style={{ color: CHART_COLORS.textSecondary }}
                >
                  {data.locations.length} Locations
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Details Section */}
      <div className="w-full lg:w-[400px]">
        <div className="mb-4 h-10" />
        {selectedLocation ? (
          <div
            className="rounded-lg border p-6"
            style={{
              borderColor: CHART_COLORS.tooltipBorder,
              backgroundColor: CHART_COLORS.tooltipBackground,
            }}
          >
            <div className="mb-6">
              <div className="mb-1 flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-[#86DA26]" />
                <h4
                  className="text-base font-semibold"
                  style={{ color: CHART_COLORS.textPrimary }}
                >
                  {selectedLocation.name}
                </h4>
              </div>
              <p
                className="text-sm"
                style={{ color: CHART_COLORS.textSecondary }}
              >
                {selectedLocation.totalFindings.toLocaleString()} Total Findings
              </p>
            </div>
            <HorizontalBarChart data={selectedLocation.severityData} />
          </div>
        ) : (
          <EmptyState />
        )}
      </div>
    </div>
  );
}
