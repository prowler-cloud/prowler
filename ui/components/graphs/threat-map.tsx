"use client";

import { geoPath } from "d3";
import type {
  Feature,
  FeatureCollection,
  GeoJsonProperties,
  Geometry,
} from "geojson";
import { AlertTriangle, ChevronDown, Info, MapPin } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { Card } from "@/components/shadcn/card/card";

import { HorizontalBarChart } from "./horizontal-bar-chart";
import {
  DEFAULT_MAP_COLORS,
  LocationPoint,
  MAP_CONFIG,
  MapColorsConfig,
  STATUS_FILTER_MAP,
  ThreatMapProps,
} from "./threat-map.types";
import {
  createProjection,
  createSVGElement,
  fetchWorldData,
  getMapColors,
} from "./threat-map.utils";
import { BarDataPoint } from "./types";

// Sub-components
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
          {location.failFindings.toLocaleString()} Fail Findings
        </span>
      </div>
      {location.change !== undefined && (
        <p className="text-text-neutral-secondary mt-1 text-sm font-medium">
          <span
            className={`font-bold ${location.change > 0 ? "text-pass-primary" : "text-fail-primary"}`}
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

function LocationDetails({
  location,
  onBarClick,
}: {
  location: Pick<LocationPoint, "name" | "totalFindings" | "severityData">;
  onBarClick: (dataPoint: BarDataPoint) => void;
}) {
  return (
    <div className="flex w-full flex-col">
      <div className="mb-4">
        <div className="mb-1 flex items-center">
          <MapPin size={21} className="text-text-error" />
          <div
            aria-hidden="true"
            className="bg-pass-primary h-2 w-2 rounded-full"
          />
          <h4 className="text-neutral-primary text-base font-semibold">
            {location.name}
          </h4>
        </div>
        <p className="text-neutral-tertiary text-xs">
          {location.totalFindings.toLocaleString()} Total Findings
        </p>
      </div>
      <HorizontalBarChart
        data={location.severityData}
        onBarClick={onBarClick}
      />
    </div>
  );
}

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
  const [selectedRegion, setSelectedRegion] = useState("All Regions");
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

  const isGlobalSelected = selectedRegion.toLowerCase() === "global";
  const isAllRegions = selectedRegion === "All Regions";

  // For display count only (not used in useEffect to avoid infinite loop)
  const locationCount = data.locations.filter((loc) => {
    if (loc.region.toLowerCase() === "global") return false;
    if (isAllRegions) return true;
    if (isGlobalSelected) return false;
    return loc.region === selectedRegion;
  }).length;

  const sortedRegions = [...data.regions].sort((a, b) => {
    if (a.toLowerCase() === "global") return -1;
    if (b.toLowerCase() === "global") return 1;
    return a.localeCompare(b);
  });

  // Compute global aggregated data
  const globalLocations = data.locations.filter(
    (loc) => loc.region.toLowerCase() === "global",
  );

  const globalAggregatedData =
    globalLocations.length > 0
      ? (() => {
          const aggregate = (name: string) =>
            globalLocations.reduce(
              (sum, loc) =>
                sum +
                (loc.severityData.find((d) => d.name === name)?.value || 0),
              0,
            );
          const failValue = aggregate("Fail");
          const passValue = aggregate("Pass");
          const total = failValue + passValue;
          return {
            name: "Global Regions",
            regionCode: "global",
            providerType: "global",
            totalFindings: total,
            failFindings: failValue,
            severityData: [
              {
                name: "Fail",
                value: failValue,
                percentage:
                  total > 0 ? Math.round((failValue / total) * 100) : 0,
                color: "var(--color-bg-fail)",
              },
              {
                name: "Pass",
                value: passValue,
                percentage:
                  total > 0 ? Math.round((passValue / total) * 100) : 0,
                color: "var(--color-bg-pass)",
              },
            ],
          };
        })()
      : null;

  // Reset selected location when region changes
  useEffect(() => {
    setSelectedLocation(null);
  }, [selectedRegion]);

  // Theme colors
  useEffect(() => {
    setMapColors(getMapColors());
    const observer = new MutationObserver(() => setMapColors(getMapColors()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    return () => observer.disconnect();
  }, []);

  // Fetch world data
  useEffect(() => {
    let mounted = true;
    fetchWorldData()
      .then((d) => mounted && d && setWorldData(d))
      .finally(() => mounted && setIsLoadingMap(false));
    return () => {
      mounted = false;
    };
  }, []);

  // Resize handler
  useEffect(() => {
    const update = () =>
      containerRef.current &&
      setDimensions({ width: containerRef.current.clientWidth, height });
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [height]);

  // Render map
  useEffect(() => {
    if (!svgRef.current || !worldData || isLoadingMap) return;

    const svg = svgRef.current;
    svg.innerHTML = "";

    // Compute filtered locations inside useEffect to avoid infinite loop
    const isGlobal = selectedRegion.toLowerCase() === "global";
    const isAll = selectedRegion === "All Regions";
    const locationsToRender = data.locations.filter((loc) => {
      if (loc.region.toLowerCase() === "global") return false;
      if (isAll) return true;
      if (isGlobal) return false;
      return loc.region === selectedRegion;
    });

    const projection = createProjection(dimensions.width, dimensions.height);
    const path = geoPath().projection(projection);

    // Countries
    const mapGroup = createSVGElement<SVGGElement>("g", {
      class: "map-countries",
    });
    const fillColor = isGlobal ? mapColors.pointDefault : mapColors.landFill;

    worldData.features?.forEach(
      (feat: Feature<Geometry, GeoJsonProperties>) => {
        const pathData = path(feat);
        if (pathData) {
          const el = createSVGElement<SVGPathElement>("path", {
            d: pathData,
            fill: fillColor,
            stroke: mapColors.landStroke,
            "stroke-width": "0.5",
          });
          mapGroup.appendChild(el);
        }
      },
    );
    svg.appendChild(mapGroup);

    // Helper to create glow rings
    const createGlowRing = (
      cx: string,
      cy: string,
      r: number,
      color: string,
      opacity: string,
    ) =>
      createSVGElement<SVGCircleElement>("circle", {
        cx,
        cy,
        r: r.toString(),
        fill: "none",
        stroke: color,
        "stroke-width": "1",
        opacity,
      });

    // Points
    const pointsGroup = createSVGElement<SVGGElement>("g", {
      class: "threat-points",
    });

    const createPoint = (loc: LocationPoint) => {
      const proj = projection(loc.coordinates);
      if (
        !proj ||
        proj[0] < 0 ||
        proj[0] > dimensions.width ||
        proj[1] < 0 ||
        proj[1] > dimensions.height
      ) {
        return null;
      }

      const [x, y] = proj;
      const isSelected = selectedLocation?.id === loc.id;
      const radius = isSelected
        ? MAP_CONFIG.selectedPointRadius
        : MAP_CONFIG.pointRadius;
      const color = isSelected
        ? mapColors.pointSelected
        : mapColors.pointDefault;

      const group = createSVGElement<SVGGElement>("g", {
        class: "cursor-pointer",
      });
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
      });
      group.appendChild(circle);

      group.addEventListener("click", () =>
        setSelectedLocation(isSelected ? null : loc),
      );
      group.addEventListener("mouseenter", (e) => {
        setHoveredLocation(loc);
        const rect = svg.getBoundingClientRect();
        setTooltipPosition({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        });
      });
      group.addEventListener("mousemove", (e) => {
        const rect = svg.getBoundingClientRect();
        setTooltipPosition({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        });
      });
      group.addEventListener("mouseleave", () => {
        setHoveredLocation(null);
        setTooltipPosition(null);
      });

      return group;
    };

    locationsToRender.forEach((loc) => {
      if (selectedLocation?.id !== loc.id) {
        const point = createPoint(loc);
        if (point) pointsGroup.appendChild(point);
      }
    });

    if (selectedLocation) {
      const loc = locationsToRender.find((l) => l.id === selectedLocation.id);
      if (loc) {
        const point = createPoint(loc);
        if (point) pointsGroup.appendChild(point);
      }
    }

    svg.appendChild(pointsGroup);
  }, [
    dimensions,
    data.locations,
    selectedRegion,
    selectedLocation,
    worldData,
    isLoadingMap,
    mapColors,
  ]);

  const navigateToFindings = (
    status: string,
    regionCode: string,
    providerType?: string,
  ) => {
    const params = new URLSearchParams(searchParams.toString());
    if (providerType) params.set("filter[provider_type__in]", providerType);
    params.set("filter[region__in]", regionCode);
    params.set("filter[status__in]", status);
    params.set("filter[muted]", "false");
    router.push(`/findings?${params.toString()}`);
  };

  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex flex-1 gap-12 overflow-hidden">
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
                  {sortedRegions.map((region) => (
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
                <div
                  className="flex items-center justify-center"
                  style={{ height: dimensions.height }}
                >
                  <div className="text-text-neutral-tertiary mb-2">
                    Loading map...
                  </div>
                </div>
              ) : (
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
                  <div className="border-border-neutral-primary bg-bg-neutral-secondary absolute bottom-4 left-4 flex items-center gap-2 rounded-full border px-3 py-1.5">
                    <div
                      aria-hidden="true"
                      className="bg-data-critical h-3 w-3 rounded"
                    />
                    <span className="text-text-neutral-primary text-sm font-medium">
                      {locationCount} Locations
                    </span>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </div>

        <div className="flex basis-[30%] items-center overflow-hidden">
          {selectedLocation ? (
            <LocationDetails
              location={selectedLocation}
              onBarClick={(dp) => {
                const status = STATUS_FILTER_MAP[dp.name];
                if (status && selectedLocation.providerType) {
                  navigateToFindings(
                    status,
                    selectedLocation.regionCode,
                    selectedLocation.providerType,
                  );
                }
              }}
            />
          ) : isGlobalSelected && globalAggregatedData ? (
            <LocationDetails
              location={globalAggregatedData}
              onBarClick={(dp) => {
                const status = STATUS_FILTER_MAP[dp.name];
                if (status) {
                  navigateToFindings(status, "global");
                }
              }}
            />
          ) : (
            <div className="flex h-full min-h-[400px] w-full items-center justify-center">
              <div className="text-center">
                <Info
                  size={48}
                  className="text-text-neutral-secondary mx-auto mb-2"
                />
                <p className="text-text-neutral-tertiary text-sm">
                  Select a location on the map to view details
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
