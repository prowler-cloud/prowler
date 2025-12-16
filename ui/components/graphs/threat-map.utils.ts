import { geoNaturalEarth1 } from "d3";
import type { FeatureCollection } from "geojson";
import { feature } from "topojson-client";
import type {
  GeometryCollection,
  Objects,
  Topology,
} from "topojson-specification";

import { DEFAULT_MAP_COLORS, MapColorsConfig } from "./threat-map.types";

export function createProjection(width: number, height: number) {
  return geoNaturalEarth1()
    .fitExtent(
      [
        [1, 1],
        [width - 1, height - 1],
      ],
      { type: "Sphere" },
    )
    .precision(0.2);
}

export async function fetchWorldData(): Promise<FeatureCollection | null> {
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

export function createSVGElement<T extends SVGElement>(
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

export function getMapColors(): MapColorsConfig {
  if (typeof document === "undefined") return DEFAULT_MAP_COLORS;

  const root = document.documentElement;
  const style = getComputedStyle(root);
  const getVar = (varName: string): string => {
    const value = style.getPropertyValue(varName).trim();
    return value && value.length > 0 ? value : "";
  };

  return {
    landFill: getVar("--bg-neutral-map") || DEFAULT_MAP_COLORS.landFill,
    landStroke:
      getVar("--border-neutral-tertiary") || DEFAULT_MAP_COLORS.landStroke,
    pointDefault:
      getVar("--text-text-error") || DEFAULT_MAP_COLORS.pointDefault,
    pointSelected:
      getVar("--bg-button-primary") || DEFAULT_MAP_COLORS.pointSelected,
    pointHover: getVar("--text-text-error") || DEFAULT_MAP_COLORS.pointHover,
  };
}
