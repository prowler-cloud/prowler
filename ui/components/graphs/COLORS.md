# Graph Component Colors

This document defines the standardized color palette used across all graph components.

## Severity Colors

Based on the Prowler design system:

| Severity Level | Hex Code | Usage |
|----------------|----------|-------|
| **Critical** | `#971348` | Highest severity findings, critical issues |
| **High** | `#FF3077` | High severity findings |
| **Medium** | `#FF7D19` | Medium severity findings |
| **Low** | `#FDD34F` | Low severity findings |
| **Informational** | `#2E51B2` | Informational findings, no risk |

## Provider Colors

| Provider | Hex Code | Usage |
|----------|----------|-------|
| **AWS** | `#FF9800` | Amazon Web Services |
| **Azure** | `#06B6D4` | Microsoft Azure |
| **Google** | `#EF4444` | Google Cloud Platform |

## Status Colors

| Status | Hex Code | Usage |
|--------|----------|-------|
| **Pass (Donut)** | `#20B853` | Passing findings in donut charts |
| **Pass (Radial)** | `#86DA26` | Success in radial/gauge charts |
| **Fail** | `#DB2B49` | Failed checks |
| **Success** | `#86DA26` | General success states |

## UI Colors

| Element | Hex Code | Tailwind Class |
|---------|----------|----------------|
| **Background** | `#1E293B` | `slate-800` |
| **Secondary Background** | `#0F172A` | `slate-900` |
| **Border** | `#334155` | `slate-700` |
| **Text Primary** | `#FFFFFF` | `white` |
| **Text Secondary** | `#94A3B8` | `slate-400` |
| **Text Tertiary** | `#64748B` | `slate-500` |
| **Muted** | `#64748B` | `slate-500` |

## Component Usage

### BarChart
- Uses `SEVERITY_COLORS` map for automatic color assignment
- Can override with custom colors via `data[].color` property

### DonutChart
- Requires explicit colors in `data[].color`
- Typically uses Pass/Fail colors

### LineChart
- Colors defined via `lines[].color` property
- Typically uses severity colors for multi-line severity trends

### RadarChart
- Default: Green (`#86DA26`) for fill/stroke
- Active dot: Critical (`#971348`)

### RadialChart
- Default: Green (`#86DA26`)
- Customizable via `color` prop

### SankeyChart
- Uses comprehensive `COLORS` map including:
  - Status colors (Success, Fail)
  - Provider colors (AWS, Azure, Google)
  - Severity colors (Critical to Info)

### ScatterPlot
- Uses `PROVIDER_COLORS` map
- Colors determined by `data[].provider` property

## Implementation Notes

1. All severity colors follow the official Prowler design system
2. Colors are defined as hex codes for consistency across libraries
3. Each component exports its color constants for reference
4. Dark theme optimized - all colors provide sufficient contrast on dark backgrounds
5. Accessible color combinations meet WCAG AA standards

## Migration from Old Colors

| Old Color | New Color | Change |
|-----------|-----------|--------|
| `#3B82F6` (Blue 500) | `#2E51B2` | Info/Informational |
| `#FBBF24` (Yellow 400) | `#FDD34F` | Low severity |
| `#F97316` (Orange 500) | `#FF7D19` | Medium severity |
| `#EC4899` (Pink 500) | `#FF3077` | High severity |
| `#DC2626` (Red 600) | `#971348` | Critical severity |
| `#F59E0B` (Amber 500) | `#FF9800` | AWS provider |
