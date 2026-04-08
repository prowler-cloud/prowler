/**
 * Maps cloud region strings to flag emojis.
 *
 * Supports AWS (us-east-1), Azure (eastus), GCP (us-central1),
 * and other providers with common region naming patterns.
 */

const REGION_FLAG_RULES: [RegExp, string][] = [
  // United States
  [
    /\bus[-_]?|useast|uswest|usgov|uscentral|northamerica|virginia|ohio|oregon|california/i,
    "🇺🇸",
  ],
  // European Union / general Europe
  [
    /\beu[-_]?|europe|euwest|eucentral|eunorth|eusouth|frankfurt|ireland|paris|stockholm|milan|spain|zurich/i,
    "🇪🇺",
  ],
  // United Kingdom
  [/\buk[-_]?|uksouth|ukwest|london/i, "🇬🇧"],
  // Germany
  [/germany|germanycentral/i, "🇩🇪"],
  // France
  [/france|francecentral/i, "🇫🇷"],
  // Ireland
  [/\bireland\b/i, "🇮🇪"],
  // Sweden
  [/sweden/i, "🇸🇪"],
  // Switzerland
  [/switzerland|switz/i, "🇨🇭"],
  // Italy
  [/italy|italynorth/i, "🇮🇹"],
  // Spain
  [/\bspain\b/i, "🇪🇸"],
  // Norway
  [/norway/i, "🇳🇴"],
  // Poland
  [/poland/i, "🇵🇱"],
  // Canada
  [/\bca[-_]?|canada|canadacentral|canadaeast/i, "🇨🇦"],
  // Brazil
  [/\bsa[-_]?|brazil|southamerica|saeast|brazilsouth/i, "🇧🇷"],
  // Japan
  [/\bap[-_]?northeast[-_]?1|japan|japaneast|japanwest|tokyo|osaka/i, "🇯🇵"],
  // South Korea
  [/\bap[-_]?northeast[-_]?[23]|korea|koreacentral|koreasouth|seoul/i, "🇰🇷"],
  // Australia
  [
    /\bap[-_]?southeast[-_]?2|australia|australiaeast|australiacentral|sydney|melbourne/i,
    "🇦🇺",
  ],
  // Singapore
  [/\bap[-_]?southeast[-_]?1|singapore/i, "🇸🇬"],
  // India
  [
    /\bap[-_]?south[-_]?1|india|centralindia|southindia|westindia|mumbai|hyderabad/i,
    "🇮🇳",
  ],
  // Taiwan — GCP asia-east1 (must come BEFORE Hong Kong rule)
  [/\basia[-_]east[-_]?1\b/i, "🇹🇼"],
  // Hong Kong — GCP asia-east2 (ap-east-1 is AWS HK)
  [/\bap[-_]?east[-_]?1|\basia[-_]east[-_]?2\b|hongkong/i, "🇭🇰"],
  // Indonesia
  [/\bap[-_]?southeast[-_]?3|indonesia|jakarta/i, "🇮🇩"],
  // China
  [/\bcn[-_]?|china|chinaeast|chinanorth|beijing|shanghai|ningxia/i, "🇨🇳"],
  // Middle East / UAE
  [/\bme[-_]?|middleeast|uaecentral|uaenorth|dubai|bahrain/i, "🇦🇪"],
  // Israel
  [/israel|israelcentral/i, "🇮🇱"],
  // South Africa
  [/\baf[-_]?|africa|southafrica|capetown|johannesburg/i, "🇿🇦"],
  // Asia Pacific (generic fallback)
  [/\bap[-_]?|asia/i, "🌏"],
  // Global / multi-region
  [/global|multi/i, "🌐"],
];

export function getRegionFlag(region: string): string {
  if (!region || region === "-") return "";

  const normalized = region.toLowerCase().replace(/\s+/g, "");

  for (const [pattern, flag] of REGION_FLAG_RULES) {
    if (pattern.test(normalized)) {
      return flag;
    }
  }

  return "🌐";
}
