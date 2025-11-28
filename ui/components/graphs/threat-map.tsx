"use client";

import * as d3 from "d3";
import type {
  Feature,
  FeatureCollection,
  GeoJsonProperties,
  Geometry,
} from "geojson";
import { AlertTriangle, ChevronDown, Info, MapPin } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { feature } from "topojson-client";
import type {
  GeometryCollection,
  Objects,
  Topology,
} from "topojson-specification";

import { Card } from "@/components/shadcn/card/card";
import { mapProviderFiltersForFindings } from "@/lib/provider-helpers";

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

// SVG-specific colors: must use actual color values, not Tailwind classes
// as SVG fill/stroke attributes don't support class-based styling
// Retrieves computed CSS variable values from globals.css theme variables at runtime
// Fallback hex colors are used only when CSS variables cannot be computed (SSR context)
interface MapColorsConfig {
  landFill: string;
  landStroke: string;
  pointDefault: string;
  pointSelected: string;
  pointHover: string;
}

const DEFAULT_MAP_COLORS: MapColorsConfig = {
  // Fallback: gray-300 (neutral-300) - used for map land fill in light theme
  landFill: "#d1d5db",
  // Fallback: slate-300 - used for map borders
  landStroke: "#cbd5e1",
  // Fallback: red-600 - error color for points
  pointDefault: "#dc2626",
  // Fallback: emerald-500 - success color for selected points
  pointSelected: "#10b981",
  // Fallback: red-600 - error color for hover points
  pointHover: "#dc2626",
};

function getMapColors(): MapColorsConfig {
  if (typeof document === "undefined") return DEFAULT_MAP_COLORS;

  const root = document.documentElement;
  const style = getComputedStyle(root);
  const getVar = (varName: string): string => {
    const value = style.getPropertyValue(varName).trim();
    return value && value.length > 0 ? value : "";
  };

  const colors: MapColorsConfig = {
    landFill: getVar("--bg-neutral-map") || DEFAULT_MAP_COLORS.landFill,
    landStroke:
      getVar("--border-neutral-tertiary") || DEFAULT_MAP_COLORS.landStroke,
    pointDefault:
      getVar("--text-text-error") || DEFAULT_MAP_COLORS.pointDefault,
    pointSelected:
      getVar("--bg-button-primary") || DEFAULT_MAP_COLORS.pointSelected,
    pointHover: getVar("--text-text-error") || DEFAULT_MAP_COLORS.pointHover,
  };

  return colors;
}

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
  regionCode: string;
  providerType: string;
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
      className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none absolute z-50 min-w-[200px] rounded-xl border p-3 shadow-lg"
      style={{
        left: `${position.x + 15}px`,
        top: `${position.y + 15}px`,
        transform: "translate(0, -50%)",
      }}
    >
      <div className="flex items-center gap-2">
        <MapPin size={14} className="text-text-neutral-secondary" />
        <span className="text-text-neutral-primary text-sm font-semibold">
          {location.name}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <AlertTriangle size={14} className="text-bg-data-critical" />
        <span className="text-text-neutral-secondary text-sm font-medium">
          {location.totalFindings.toLocaleString()} Fail Findings
        </span>
      </div>
      {location.change !== undefined && (
        <p className="text-text-neutral-secondary mt-1 text-sm font-medium">
          <span
            className="font-bold"
            style={{
              color:
                location.change > 0
                  ? "var(--bg-pass-primary)"
                  : "var(--bg-fail-primary)",
            }}
          >
            {location.change > 0 ? "+" : ""}
            {location.change}%{" "}
          </span>
          since last scan
        </p>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex h-full min-h-[400px] w-full items-center justify-center">
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

const STATUS_FILTER_MAP: Record<string, string> = {
  Fail: "FAIL",
  Pass: "PASS",
};

export function ThreatMap({
  data,
  height = MAP_CONFIG.defaultHeight,
}: ThreatMapProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
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
  const [mapColors, setMapColors] =
    useState<MapColorsConfig>(DEFAULT_MAP_COLORS);

  const filteredLocations =
    selectedRegion === "All Regions"
      ? data.locations
      : data.locations.filter((loc) => loc.region === selectedRegion);

  // Monitor theme changes and update colors
  useEffect(() => {
    const updateColors = () => {
      setMapColors(getMapColors());
    };

    // Update colors immediately
    updateColors();

    // Watch for theme changes (dark class on document)
    const observer = new MutationObserver(() => {
      updateColors();
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });

    return () => observer.disconnect();
  }, []);

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
    const colors = mapColors;

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
            fill: colors.landFill,
            stroke: colors.landStroke,
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

    // Helper to create glow rings
    const createGlowRing = (
      cx: string,
      cy: string,
      radiusOffset: number,
      color: string,
      opacity: string,
    ): SVGCircleElement => {
      return createSVGElement<SVGCircleElement>("circle", {
        cx,
        cy,
        r: radiusOffset.toString(),
        fill: "none",
        stroke: color,
        "stroke-width": "1",
        opacity,
      });
    };

    // Helper to create circle with glow
    const createCircle = (location: LocationPoint) => {
      const projected = projection(location.coordinates);
      if (!projected) return null;

      const [x, y] = projected;
      if (x < 0 || x > width || y < 0 || y > height) return null;

      const isSelected = selectedLocation?.id === location.id;
      const isHovered = hoveredLocation?.id === location.id;

      const group = createSVGElement<SVGGElement>("g", {
        class: "cursor-pointer",
      });

      const radius = isSelected
        ? MAP_CONFIG.selectedPointRadius
        : MAP_CONFIG.pointRadius;
      const color = isSelected ? colors.pointSelected : colors.pointDefault;

      // Add glow rings for all points (unselected and selected)
      group.appendChild(
        createGlowRing(x.toString(), y.toString(), radius + 4, color, "0.4"),
      );
      group.appendChild(
        createGlowRing(x.toString(), y.toString(), radius + 8, color, "0.2"),
      );

      const circle = createSVGElement<SVGCircleElement>("circle", {
        cx: x.toString(),
        cy: y.toString(),
        r: radius.toString(),
        fill: color,
        class: isHovered && !isSelected ? "opacity-70" : "",
      });
      group.appendChild(circle);

      group.addEventListener("click", () =>
        setSelectedLocation(isSelected ? null : location),
      );
      group.addEventListener("mouseenter", (e) => {
        setHoveredLocation(location);
        updateTooltip(e);
      });
      group.addEventListener("mousemove", updateTooltip);
      group.addEventListener("mouseleave", () => {
        setHoveredLocation(null);
        setTooltipPosition(null);
      });

      return group;
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
    mapColors,
  ]);

  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex flex-1 gap-12 overflow-hidden">
        {/* Map Section - in Card */}
        <div className="flex basis-[70%] flex-col overflow-hidden">
          <Card
            ref={containerRef}
            variant="base"
            className="flex flex-1 flex-col overflow-hidden"
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-text-neutral-primary text-lg font-semibold">
                Threat Map
              </h3>
              <div className="relative">
                <select
                  aria-label="Filter threat map by region"
                  value={selectedRegion}
                  onChange={(e) => setSelectedRegion(e.target.value)}
                  className="border-border-neutral-primary bg-bg-neutral-secondary text-text-neutral-primary appearance-none rounded-lg border px-4 py-2 pr-10 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2"
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
                  className="text-text-neutral-tertiary pointer-events-none absolute top-1/2 right-3 -translate-y-1/2"
                />
              </div>
            </div>

            <div className="relative w-full flex-1">
              {isLoadingMap ? (
                <LoadingState height={dimensions.height} />
              ) : (
                <>
                  <div className="relative h-full w-full">
                    <svg
                      ref={svgRef}
                      width={dimensions.width}
                      height={dimensions.height}
                      className="h-full w-full"
                      style={{ maxWidth: "100%", maxHeight: "100%" }}
                      preserveAspectRatio="xMidYMid meet"
                    />
                    {hoveredLocation && tooltipPosition && (
                      <MapTooltip
                        location={hoveredLocation}
                        position={tooltipPosition}
                      />
                    )}
                    <div
                      className="border-border-neutral-primary bg-bg-neutral-secondary absolute bottom-4 left-4 flex items-center gap-2 rounded-full border px-3 py-1.5"
                      role="status"
                      aria-label={`${filteredLocations.length} threat locations on map`}
                    >
                      <div
                        aria-hidden="true"
                        className="h-3 w-3 rounded"
                        style={{ backgroundColor: "var(--bg-data-critical)" }}
                      />
                      <span className="text-text-neutral-primary text-sm font-medium">
                        {filteredLocations.length} Locations
                      </span>
                    </div>
                  </div>
                </>
              )}
            </div>
          </Card>
        </div>

        {/* Details Section - No Card */}
        <div className="flex basis-[30%] items-center overflow-hidden">
          {selectedLocation ? (
            <div className="flex w-full flex-col">
              <div className="mb-4">
                <div
                  className="mb-1 flex items-center"
                  aria-label={`Selected location: ${selectedLocation.name}`}
                >
                  <MapPin
                    size={21}
                    style={{ color: "var(--color-text-text-error)" }}
                  />
                  <div
                    aria-hidden="true"
                    className="bg-pass-primary h-2 w-2 rounded-full"
                  />
                  <h4 className="text-neutral-primary text-base font-semibold">
                    {selectedLocation.name}
                  </h4>
                </div>
                <p className="text-neutral-tertiary text-xs">
                  {selectedLocation.totalFindings.toLocaleString()} Total
                  Findings
                </p>
              </div>
              <HorizontalBarChart
                data={selectedLocation.severityData}
                onBarClick={(dataPoint) => {
                  const status = STATUS_FILTER_MAP[dataPoint.name];
                  if (status && selectedLocation.providerType) {
                    const params = new URLSearchParams(searchParams.toString());

                    mapProviderFiltersForFindings(params);

                    params.set(
                      "filter[provider_type__in]",
                      selectedLocation.providerType,
                    );
                    params.set(
                      "filter[region__in]",
                      selectedLocation.regionCode,
                    );
                    params.set("filter[status__in]", status);
                    router.push(`/findings?${params.toString()}`);
                  }
                }}
              />
            </div>
          ) : (
            <EmptyState />
          )}
        </div>
      </div>
    </div>
  );
}
