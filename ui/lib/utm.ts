export const UTM_PARAM_PREFIX = "utm_";
const UTM_SOURCE_KEY = "utm_source";
export const PROMO_CODE_KEY = "promo_code";

export type UtmParams = Record<string, string>;

type SearchParamSource = {
  forEach(callback: (value: string, key: string) => void): void;
};

type RecordParamSource = Record<string, string | string[] | undefined>;

type UtmSource = SearchParamSource | RecordParamSource;

const isSearchParamSource = (source: UtmSource): source is SearchParamSource =>
  "forEach" in source && typeof source.forEach === "function";

const toEntries = (source: UtmSource): [string, string][] => {
  if (isSearchParamSource(source)) {
    const entries: [string, string][] = [];
    source.forEach((value, key) => {
      entries.push([key, value]);
    });
    return entries;
  }

  return Object.entries(source).flatMap(([key, value]) => {
    if (typeof value === "string") {
      return [[key, value]];
    }
    if (Array.isArray(value) && typeof value[0] === "string") {
      return [[key, value[0]]];
    }
    return [];
  });
};

export const extractUtmParams = (source: UtmSource): UtmParams => {
  const utm: UtmParams = {};
  let hasAttribution = false;

  for (const [key, value] of toEntries(source)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey === PROMO_CODE_KEY) {
      utm[PROMO_CODE_KEY] = value;
      hasAttribution = true;
    } else if (lowerKey.startsWith(UTM_PARAM_PREFIX)) {
      utm[key] = value;
      if (lowerKey === UTM_SOURCE_KEY) {
        hasAttribution = true;
      }
    }
  }

  return hasAttribution ? utm : {};
};

export const copyAttributionParams = (
  from: URLSearchParams,
  to: URLSearchParams,
): void => {
  for (const [key, value] of Object.entries(extractUtmParams(from))) {
    to.set(key, value);
  }
};
