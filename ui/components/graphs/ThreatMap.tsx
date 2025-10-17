"use client";

import * as d3 from "d3";
import type {
  Feature,
  FeatureCollection,
  GeoJsonProperties,
  Geometry,
} from "geojson";
import { AlertTriangle, ChevronDown, Info, MapPin } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { feature } from "topojson-client";
import type {
  GeometryCollection,
  Objects,
  Topology,
} from "topojson-specification";

import { HorizontalBarChart } from "./HorizontalBarChart";
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
  landFill: "var(--chart-border-emphasis)",
  landStroke: "var(--chart-border)",
  pointDefault: "#DB2B49",
  pointSelected: "#86DA26",
  pointHover: "#DB2B49",
} as const;

const RISK_LEVELS = {
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

interface ThreatMapData {
  locations: LocationPoint[];
  regions: string[];
}

interface ThreatMapProps {
  data: ThreatMapData;
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
  return (
    <div
      className="pointer-events-none absolute z-50 min-w-[200px] rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg"
      style={{
        left: `${position.x + 15}px`,
        top: `${position.y + 15}px`,
        transform: "translate(0, -50%)",
      }}
    >
      <div className="flex items-center gap-2">
        <MapPin size={14} className="text-slate-400" />
        <span className="text-sm font-semibold text-white">
          {location.name}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <AlertTriangle size={14} className="text-[#DB2B49]" />
        <span className="text-sm text-white">
          {location.totalFindings.toLocaleString()} Fail Findings
        </span>
      </div>
      {location.change !== undefined && (
        <p className="mt-1 text-xs text-slate-400">
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
  return (
    <div className="flex h-full min-h-[400px] items-center justify-center rounded-lg border border-slate-700 bg-slate-800 p-6">
      <div className="text-center">
        <Info size={48} className="mx-auto mb-2 text-slate-500" />
        <p className="text-sm text-slate-400">
          Select a location on the map to view details
        </p>
      </div>
    </div>
  );
}

function LoadingState({ height }: { height: number }) {
  return (
    <div className="flex items-center justify-center" style={{ height }}>
      <div className="text-center">
        <div className="mb-2 text-slate-400">Loading map...</div>
      </div>
    </div>
  );
}

export function ThreatMap({
  data,
  height = MAP_CONFIG.defaultHeight,
}: ThreatMapProps) {
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
  const [selectedRegion, setSelectedRegion] = useState<string>("All Regions");
  const [worldData, setWorldData] = useState<FeatureCollection | null>(null);
  const [isLoadingMap, setIsLoadingMap] = useState(true);
  const [dimensions, setDimensions] = useState<{
    width: number;
    height: number;
  }>({
    width: MAP_CONFIG.defaultWidth,
    height,
  });

  const filteredLocations =
    selectedRegion === "All Regions"
      ? data.locations
      : data.locations.filter((loc) => loc.region === selectedRegion);

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
    filteredLocations.forEach((location) => {
      if (selectedLocation?.id !== location.id) {
        const circle = createCircle(location);
        if (circle) pointsGroup.appendChild(circle);
      }
    });

    // Selected point last (on top)
    if (selectedLocation) {
      const selectedData = filteredLocations.find(
        (loc) => loc.id === selectedLocation.id,
      );
      if (selectedData) {
        const circle = createCircle(selectedData);
        if (circle) pointsGroup.appendChild(circle);
      }
    }

    svg.appendChild(pointsGroup);
  }, [
    dimensions,
    filteredLocations,
    selectedLocation,
    hoveredLocation,
    worldData,
    isLoadingMap,
  ]);

  return (
    <div className="flex w-full flex-col gap-6 lg:flex-row lg:items-start">
      {/* Map Section */}
      <div className="flex-1">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Threat Map</h3>
          <div className="relative">
            <select
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="appearance-none rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 pr-10 text-sm text-white focus:border-slate-600 focus:outline-none"
            >
              <option value="All Regions">All Regions</option>
              {data.regions.map((region) => (
                <option key={region} value={region}>
                  {region}
                </option>
              ))}
            </select>
            <ChevronDown
              size={16}
              className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-slate-400"
            />
          </div>
        </div>

        <div
          ref={containerRef}
          className="rounded-lg border border-slate-700 bg-slate-800/50 p-4"
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
                <span className="text-sm text-slate-400">
                  {filteredLocations.length} Locations
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
          <div className="rounded-lg border border-slate-700 bg-slate-800 p-6">
            <div className="mb-6">
              <div className="mb-1 flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-[#86DA26]" />
                <h4 className="text-base font-semibold text-white">
                  {selectedLocation.name}
                </h4>
              </div>
              <p className="text-sm text-slate-400">
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

