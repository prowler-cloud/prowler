import { IBM_Plex_Mono as FontMono, IBM_Plex_Sans as FontSans } from "next/font/google";

// Cloudy type system (Taste "framed sheet"): IBM Plex Sans for everything,
// IBM Plex Mono for one job only — resource IDs, ARNs, keys and check IDs.
export const fontSans = FontSans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-sans",
  preload: false,
  display: "swap",
});

export const fontMono = FontMono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
  preload: false,
  display: "swap",
});
