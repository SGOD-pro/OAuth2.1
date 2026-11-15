# UI.md — M Auth Design System (Precision BMW M-Series Craftsmanship)

## 1. Design Philosophy: "Disciplined Precision & Engineered Contrast"
M Auth delivers a focused, high-assurance authentication experience under the **SWYRA** brand. Inspired by the disciplined instrumentation, graphite surfaces, and purposeful material contrast of a BMW M-series cockpit, the interface is calm, responsive, and stripped of theatrical decoration.

- **Golden-Ratio Typography & Structure**: Uses **Space Grotesk** for display titles, **Geist Sans** for interface text, and **Geist Mono** for technical identifiers. The typographic hierarchy follows golden-ratio steps (φ ≈ 1.618) to organize information naturally.
- **60–30–10 Color Balance**: 
  - **60% Dominant**: Neutral canvas (`#101114` dark / `#F5F6F8` light).
  - **30% Secondary**: Opaque graphite panels, elevated cards, and structural sidebars (`#191C21` dark / `#FFFFFF` light) separated by crisp 1px borders.
  - **10% Accent**: Controlled interaction blue (`#245DCF` / `#70AAFF`) and deliberate **BMW M-series motorsport signatures** (Light Blue `#0066B1`, Dark Blue `#1C69D4`, Red `#E22718`).
- **Selective Motorsport Accent**: The iconic three-color motorsport detail appears only in deliberate contexts: the product identity lockup, an accent slash on the authentication split-panel, and opt-in top-edge accents on featured cards (`accent="motorsport"`). Standard cards and dialogs remain clean, neutral graphite.
- **Natural Language**: Clear authentication terminology ("sign-in", "applications", "audit logs", "security"). No contrived jargon ("telemetry", "pilot", "engine", "terminal").

---

## 2. Color Palette & 60–30–10 Theme Architecture

Implemented with OKLCH variables and Tailwind v4:

### Dark Theme (Carbon & Graphite)
- **60% Canvas**: `oklch(0.12 0.005 250)` (`#101114`)
- **30% Surfaces**:
  - Sidebar: `oklch(0.14 0.006 250)` (`#131519`)
  - Panels / Cards: `oklch(0.16 0.006 250)` (`#191C21`)
  - Elevated / Inputs: `oklch(0.20 0.008 250)` (`#21252C`)
  - Hairline Dividers: `oklch(0.26 0.008 250)` (`#2C313A`)
  - Primary Text: `oklch(0.96 0.005 250)` (`#F2F4F7`)
  - Secondary Text: `oklch(0.72 0.010 250)` (`#A8B0BD`)
- **10% Accent**:
  - Interaction Blue: `oklch(0.52 0.20 256)` (`#245DCF` button fill) / `oklch(0.72 0.16 256)` (`#70AAFF` highlights)
  - Motorsport Light Blue: `#0066B1`
  - Motorsport Dark Blue: `#1C69D4`
  - Motorsport Red: `#E22718`
  - Status Success: `oklch(0.68 0.17 155)` (Emerald)
  - Status Warning: `oklch(0.75 0.15 75)` (Amber)
  - Status Danger: `oklch(0.63 0.22 25)` (Crimson)

### Light Theme (Precision Stone & Crisp White)
- **60% Canvas**: `oklch(0.97 0.003 250)` (`#F5F6F8`)
- **30% Surfaces**:
  - Sidebar & Panels: `#FFFFFF`
  - Elevated / Inputs: `oklch(0.94 0.004 250)` (`#EEF1F5`)
  - Hairline Dividers: `oklch(0.88 0.005 250)` (`#D8DEE7`)
  - Primary Text: `oklch(0.18 0.008 250)` (`#171B22`)
  - Secondary Text: `oklch(0.46 0.012 250)` (`#566171`)
- **10% Accent**:
  - Interaction Blue: `#245DCF`
  - Status Success, Warning, Danger as semantic tokens

---

## 3. Typography & Golden-Ratio Scale

- **Display Headings**: Space Grotesk (`font-heading`)
- **Interface & Content**: Geist Sans (`font-sans`)
- **Technical & Identifiers**: Geist Mono (`font-mono`)

Scale organized by approximate Golden Ratio steps (φ ≈ 1.618):
- **13px**: Small metadata, status tags, table headers (`font-mono` or `font-sans text-xs`)
- **14–16px**: Body text, form labels, controls, table cell content (`font-sans text-sm` / `text-base`)
- **16–18px**: Compact panel headings (`font-heading text-base` / `text-lg font-semibold`)
- **21px**: Major section titles and prominent card headers (`font-heading text-[21px] font-medium`)
- **34px**: Desktop page titles (`font-heading text-[34px] leading-tight font-normal`), responsive to `28px` on mobile; primary metric values
- **55px**: Authentication brand panel headline (`font-heading text-[55px] leading-none font-normal`), responsive to `34px` on mobile

---

## 4. Component Primitives & Geometry

### 4.1 Buttons
- **Radius**: `8px` (`rounded-md` / `rounded-lg`).
- **Primary**: Solid `#245DCF` with white text, subtle hover shade `#1E4FB5`. No animated gradient sweeps or pill shapes.
- **Outline / Ghost**: 1px border with neutral hover background.
- **Sizes**: `h-9 px-4` (default), `h-8 px-3 text-xs` (sm), `h-11 px-6` (auth primary).

### 4.2 Form Inputs
- Full-boundary inputs with opaque surface.
- `h-9` (`h-11` on auth), `rounded-md` (`8px`), `border border-border bg-secondary/30 dark:bg-[#191C21] px-3 text-sm`.
- Focus state: `focus:border-accent focus:ring-1 focus:ring-accent/40`. Full accessibility and password reveal toggles.

### 4.3 Cards & Panels
- Opaque surface: `bg-card border border-border rounded-[12px] shadow-xs`.
- `accent="motorsport"`: Optional prop that renders 3 distinct color segments (light blue, dark blue, red) across a 3px top edge. Default is clean neutral.
- No SWYRA watermarks. No hover lift (`hover:-translate-y-1`) on static cards.

### 4.4 Dialogs & Sheets
- `rounded-[14px]`, opaque panel background, clean 1px border, backdrop blur overlay.

### 4.5 Status Badges
- Pill geometry (`rounded-full`), clear semantic labels: `Active`, `Suspended`, `Development`, `Production`.

---

## 5. Brand Identity & Hierarchy

- **Product Identity**: **M Auth**
- **Parent Brand Endorsement**: **by SWYRA**
- **Browser Title**: `[Page Name] · M Auth`
- **Motorsport Signature**: A small 3-segment slanting geometric mark:
  ```tsx
  <div className="flex h-3.5 gap-0.5 items-center">
    <div className="w-[3px] h-3.5 bg-[#0066B1] -skew-x-12" />
    <div className="w-[3px] h-3.5 bg-[#1C69D4] -skew-x-12" />
    <div className="w-[3px] h-3.5 bg-[#E22718] -skew-x-12" />
  </div>
  ```