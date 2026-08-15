# UI.md — BMW M-Series Auth Service Design System (Premium $50k Vibe)

## 1. Design Philosophy: "Digital Telemetry & Precision Engineering"
The frontend must feel like the interface of a $200k BMW M-Series super-car: **raw, precise, high-performance, and devoid of decorative noise.** It uses monumental tight-tracking typography, flat premium surfaces, and reserves the **M Tricolor** strictly as a high-voltage telemetry signal (stripes, borders, focus rings)—never as a cheap button fill. 

Layouts, typography scales, and spacing systems strictly adhere to the **Golden Ratio (1.618)** to create a natural, premium visual hierarchy. Animations are mechanical, snappy, and purposeful.

## 2. Tailwind v4 Theme Configuration (`index.css`)
Update your `index.css` to define the Light/Dark premium themes using OKLCH and CSS variables. Tailwind v4 will automatically pick these up via `@theme inline`.

```css
@import "tailwindcss";
@import "tw-animate-css";
@import "shadcn/tailwind.css";
@import "@fontsource-variable/figtree";
@import "@fontsource-variable/space-grotesk";
@import "@fontsource-variable/geist";

@custom-variant dark (&:where(.dark, .dark *));

@theme inline {
  --font-sans: "Geist Variable", Inter, system-ui, sans-serif;
  --font-heading: "Space Grotesk Variable", sans-serif;
  --font-mono: "Geist Mono Variable", ui-monospace, monospace;

  /* Golden Ratio Scale (Base 8px) */
  --spacing-xs: 8px;
  --spacing-sm: 13px;   /* 8 * 1.618 */
  --spacing-md: 21px;   /* 13 * 1.618 */
  --spacing-lg: 34px;   /* 21 * 1.618 */
  --spacing-xl: 55px;   /* 34 * 1.618 */
  --spacing-2xl: 89px;  /* 55 * 1.618 */

  /* Radius Scale */
  --radius-sm: 4px;
  --radius-md: 16px;
  --radius-lg: 26px; /* 16 * 1.618 */
  --radius-pill: 9999px;
}

:root {
  /* Light Theme: Soft Stone & Ink */
  --background: oklch(0.98 0.002 240); /* Soft stone canvas */
  --foreground: oklch(0.15 0.005 240); /* Deep ink */
  --card: oklch(1 0 0 / 0.6); /* Premium glass */
  --card-foreground: oklch(0.15 0.005 240);
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.15 0.005 240);
  --primary: oklch(0.15 0.005 240); /* Ink buttons */
  --primary-foreground: oklch(0.98 0 0);
  --secondary: oklch(0.92 0.004 240);
  --secondary-foreground: oklch(0.20 0.005 240);
  --muted: oklch(0.92 0.004 240);
  --muted-foreground: oklch(0.45 0.01 240);
  --accent: oklch(0.55 0.22 256); /* Electric Blue */
  --accent-foreground: oklch(0.98 0 0);
  --destructive: oklch(0.58 0.24 27);
  --destructive-foreground: #ffffff;
  --border: oklch(0.85 0.004 240);
  --input: oklch(0.85 0.004 240);
  --ring: oklch(0.55 0.22 256);
}

.dark {
  /* Dark Theme: Carbon Fiber & M-Series Telemetry */
  --background: oklch(0.12 0 0); /* Deep Carbon Black */
  --foreground: oklch(0.98 0 0); /* Pure White */
  --card: oklch(0.16 0 0 / 0.6); /* Brushed aluminum dark glass */
  --card-foreground: oklch(0.98 0 0);
  --popover: oklch(0.16 0 0);
  --popover-foreground: oklch(0.98 0 0);
  --primary: oklch(0.98 0 0); /* White buttons */
  --primary-foreground: oklch(0.12 0 0);
  --secondary: oklch(0.22 0 0); /* Muted Carbon */
  --secondary-foreground: oklch(0.98 0 0);
  --muted: oklch(0.22 0 0);
  --muted-foreground: oklch(0.65 0 0);
  --accent: oklch(0.65 0.22 256); /* Electric Blue */
  --accent-foreground: oklch(0.98 0 0);
  --destructive: oklch(0.70 0.24 25);
  --destructive-foreground: #ffffff;
  --border: oklch(1 0 0 / 10%); /* Hairline borders */
  --input: oklch(1 0 0 / 15%);
  --ring: oklch(0.65 0.22 256);
}
```

## 3. Typography & Golden Ratio Scale
Fonts: `Space Grotesk` (Display), `Geist` (UI), `Geist Mono` (Labels).
Use Tailwind arbitrary values for precise Golden Ratio scaling.

*   **Hero Display:** `font-heading text-[90px] leading-[1] tracking-[-0.04em] font-normal`
*   **Admin Display:** `font-heading text-[55px] leading-[1] tracking-[-0.03em] font-normal`
*   **Section Heading:** `font-heading text-[34px] leading-[1.2] tracking-[-0.02em] font-normal`
*   **Card Heading:** `font-sans text-[21px] leading-[1.3] font-medium`
*   **Body:** `font-sans text-sm leading-[1.5] font-normal`
*   **Mono Label/Telemetry:** `font-mono text-xs tracking-[0.02em] uppercase text-muted-foreground`

## 4. Premium Tailwind Component Recipes
*Do not write custom CSS classes. Apply these Tailwind utilities directly to shadcn components.*

### Theme Toggle Component
A premium, mechanical switch with a smooth transition.
```tsx
<button onClick={toggleTheme} className="relative h-8 w-14 rounded-full bg-secondary transition-colors duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background">
  <span className="absolute left-1 top-1 flex h-6 w-6 items-center justify-center rounded-full bg-background shadow-sm transition-transform duration-300 ease-in-out dark:translate-x-6">
    {/* Sun / Moon Icons */}
  </span>
</button>
```

### Button (Primary & Outline)
*Pill-shaped, smooth scaling micro-interactions.*
```tsx
// Primary (M-Series White/Ink)
<Button className="group relative h-12 w-full rounded-pill bg-primary text-primary-foreground font-sans text-sm font-medium tracking-wide overflow-hidden transition-all duration-300 hover:scale-[1.02] active:scale-[0.98]">
  <span className="relative z-10 flex items-center justify-center gap-2">Authenticate</span>
  {/* M-Tricolor hover sweep */}
  <span className="absolute inset-0 z-0 h-full w-0 bg-[linear-gradient(to_right,#0066B1_0%,#1C69D4_50%,#E22718_100%)] opacity-0 transition-all duration-500 group-hover:w-full group-hover:opacity-100"></span>
</Button>

// Outline (Ghost)
<Button variant="outline" className="rounded-pill border-border bg-transparent text-foreground hover:bg-secondary/50 transition-all duration-300 active:scale-[0.98]">
  Secondary Action
</Button>
```

### Input & Label
*Bottom-border only, mechanical focus ring.*
```tsx
<div className="flex flex-col gap-2">
  <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Email Address</label>
  <Input 
    className="h-12 rounded-none border-0 border-b-2 border-border bg-transparent px-1 font-sans text-base text-foreground caret-accent transition-colors duration-300 placeholder:text-muted-foreground/50 focus:border-accent focus:ring-0 focus:ring-offset-0 focus-visible:ring-0" 
  />
</div>
```

### Card (Auth & Admin Panels)
*Glassmorphism, premium border, and M-Tricolor top telemetry.*
```tsx
<Card className="relative overflow-hidden rounded-[26px] border border-border bg-card/60 backdrop-blur-2xl shadow-[0_8px_32px_0_rgba(0,0,0,0.3)] transition-transform duration-500 hover:-translate-y-1">
  {/* M Tricolor Top Stripe */}
  <div className="absolute left-0 right-0 top-0 h-[3px] w-full bg-[linear-gradient(to_right,#0066B1_0%,#0066B1_33.3%,#1C69D4_33.3%,#1C69D4_66.6%,#E22718_66.6%,#E22718_100%)]"></div>
  
  <CardContent className="p-[34px]">
    {/* Content */}
  </CardContent>
</Card>
```

### Alerts & Toasts
*Premium glass alerts with left telemetry stripe and staggered entrance.*
```tsx
// Destructive Alert
<div className="relative flex items-start gap-4 overflow-hidden rounded-[16px] border border-destructive/30 bg-destructive/5 p-[21px] backdrop-blur-md animate-in fade-in slide-in-from-right-full duration-500">
  <div className="absolute left-0 top-0 h-full w-1 bg-destructive"></div>
  <AlertCircle className="mt-1 h-5 w-5 text-destructive" />
  <div className="flex-1">
    <h5 className="font-sans text-sm font-medium text-foreground">Access Denied</h5>
    <p className="font-sans text-sm text-muted-foreground mt-1">Invalid credentials. Session terminated.</p>
  </div>
</div>

// Success Alert (Electric Blue)
<div className="relative flex items-start gap-4 overflow-hidden rounded-[16px] border border-accent/30 bg-accent/5 p-[21px] backdrop-blur-md animate-in fade-in slide-in-from-right-full duration-500">
  <div className="absolute left-0 top-0 h-full w-1 bg-accent"></div>
  {/* ... */}
</div>
```

## 5. Layout & Route Architecture

### `Layout` Component (Global)
*   Remove all mesh gradients. Use a stark, flat canvas.
*   **Background:** Add an incredibly subtle CSS noise texture or carbon-fiber grid at `opacity: 0.02` for a $50k tactile feel.
*   **Animations:** Wrap lazy-loaded routes in `RouteLoader` (a mechanical tricolor telemetry loader).

### `RouteLoader` (Suspense Fallback)
```tsx
<div className="flex h-screen w-screen flex-col items-center justify-center gap-[34px] bg-background">
  <div className="font-heading text-[34px] tracking-tighter text-foreground">M Auth</div>
  <div className="flex w-64 flex-col gap-2">
    {/* 3 bars animating width sequentially */}
    <div className="h-[2px] w-full origin-left animate-pulse bg-[#0066B1]"></div>
    <div className="h-[2px] w-3/4 origin-left animate-pulse bg-[#1C69D4] [animation-delay:150ms]"></div>
    <div className="h-[2px] w-1/2 origin-left animate-pulse bg-[#E22718] [animation-delay:300ms]"></div>
  </div>
</div>
```

### `/auth` (SignIn, Forgot Password, Reset Password)
*   **Layout:** Split screen using Golden Ratio. `grid grid-cols-1 lg:grid-cols-[38.2fr_61.8fr]`.
*   **Left (38.2%):** Pure premium dark `bg-background` (or soft stone in light mode). Massive `90px` Space Grotesk headline: "Digital Telemetry." Mono telemetry labels underneath ("Securing M-Series Session..."). 
*   **Right (61.8%):** Centered premium `Card` (with glassmorphism and tricolor top stripe). Social login buttons rendered as stark outline pills. Email/password inputs use bottom-border-only styling.

### `/admin/*` (AdminDashboard, Clients, Logs, Security)
*   **Layout:** Full screen dark dashboard. 
*   **Sidebar:** Fixed left, `w-[260px]`. `bg-background`. 1px right border. 
    *   Active route gets a 2px left border using the M-Tricolor gradient: `border-l-[3px] border-[#0066B1]` (or full gradient).
    *   Hover states: `bg-secondary/50 transition-colors duration-200`.
*   **Data Tables (Clients/Logs):** Flat, no card boxing. Use 1px bottom hairlines `border-b border-border/50` for row separation. 
*   **Staggered Animations:** Table rows and admin cards should use `tw-animate-css` (already installed) to stagger their entrance: `animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:100ms]`.

### `/consent` (OAuth Consent Screen)
*   Centered Modal Card with `backdrop-blur-2xl`.
*   Display the application requesting access using a `34px` Space Grotesk headline.
*   Scope permissions listed as `Geist Mono` 14px text with thin-line geometric checkmarks.