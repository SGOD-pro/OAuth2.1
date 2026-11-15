---
name: pro-animation-skill
version: 1.0.0
type: universal-dashboard-design-and-motion-system
description: A model-friendly, framework-agnostic design and animation contract for premium dashboards.
---

# PRO ANIMATION SKILL

## 0. PURPOSE

Use this file whenever designing, implementing, reviewing, or refactoring a dashboard UI.
It applies to:

- SaaS dashboards
- analytics dashboards
- admin panels
- CRMs
- project management tools
- Kanban/task boards
- internal tools
- finance dashboards
- developer dashboards
- monitoring/observability UIs
- CMS/back-office products

The goal is not to make the UI "animated". The goal is to make the interface feel:

```text
instant + responsive + spatially continuous + weighted + calm + premium
```

The premium feeling comes from the combination of:

```text
layout hierarchy
+ typography
+ spacing
+ surfaces
+ color
+ depth
+ micro-interaction
+ directional reveal
+ shared-element movement
+ intelligent page transitions
+ physical drag behavior
+ performance discipline
```

---

# 1. AI AGENT EXECUTION CONTRACT

When this skill is loaded, follow these rules before writing UI code.

### MUST

1. Inspect the existing framework, component system, CSS system, and animation dependencies.
2. Reuse existing design/motion tokens before creating new ones.
3. Prefer the smallest implementation that produces the desired effect.
4. Use CSS for simple hover/focus/pressed/color transitions.
5. Use the project's existing motion library for React/Vue/Svelte layout transitions when available.
6. Use GSAP only when the interaction needs timelines, FLIP, magnetic motion, complex drag, SVG choreography, or scroll choreography.
7. Keep the application shell persistent across route changes.
8. Prefer transform/opacity for movement and fades.
9. Make pointer and keyboard interactions visually equivalent.
10. Support `prefers-reduced-motion`.
11. Clean up every animation, listener, observer, ticker, and timeline.
12. Keep input feedback immediate; never wait for an API response before showing local feedback.
13. Animate the changed region instead of the entire page whenever possible.
14. Keep durations/easing in shared tokens.
15. Verify no layout shift, animation leak, or pointermove render storm is introduced.

### MUST NOT

```text
Do not use transition: all.
Do not animate every element just because it exists.
Do not animate every icon.
Do not make every card magnetic.
Do not use huge hover scale.
Do not use long cinematic route transitions.
Do not make the sidebar/header replay on every route.
Do not drive frame-level pointer motion through React state.
Do not animate width/height when transform/layout animation can do the job.
Do not add GSAP just because a premium site might use it.
Do not add multiple animation libraries without a clear architectural reason.
Do not claim a reference site's exact timing/easing unless it was actually measured.
```

---

# 2. CORE MOTION PHILOSOPHY

## 2.1 Spatial continuity is the #1 rule

Whenever possible, keep the user's mental model continuous.

Prefer:

```text
A → B by moving the object
```

over:

```text
A disappears → B appears
```

Highest-value examples:

```text
sidebar active indicator moves
segmented selection pill slides
active tab underline travels
sortable cards reflow
modal enters from nearby space
route content transitions without shell reset
```

## 2.2 Motion must explain something

Every motion should explain at least one of:

```text
where it came from
where it went
what changed
what is active
what can be interacted with
what operation is happening
```

If it explains none of these, remove it.

## 2.3 Motion intensity

Use four levels:

```text
0 = static
1 = subtle: color/opacity/1px lift
2 = responsive: translate/scale/shared indicator/reveal
3 = expressive: magnetic/FLIP/complex drag/ambient motion
```

Most dashboard UI should stay in levels 0–2.
Level 3 is reserved for selected high-value interactions.

---

# 3. UNIVERSAL MOTION TOKENS

Start with a small vocabulary. Tune it to the product rather than inventing values per component.

```css
:root {
  --motion-instant: 80ms;
  --motion-fast: 120ms;
  --motion-hover: 140ms;
  --motion-normal: 180ms;
  --motion-medium: 240ms;
  --motion-slow: 320ms;
  --motion-emphasis: 450ms;
  --motion-data: 500ms;

  --ease-standard: cubic-bezier(0.2, 0, 0, 1);
  --ease-enter: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-exit: cubic-bezier(0.4, 0, 1, 1);
  --ease-emphasis: cubic-bezier(0.22, 1, 0.36, 1);

  --motion-distance-xs: 4px;
  --motion-distance-sm: 8px;
  --motion-distance-md: 16px;
  --motion-distance-lg: 24px;
}
```

### Default timing reference

| Interaction | Default |
|---|---:|
| hover | 140ms |
| press | 90ms |
| focus | 120ms |
| tooltip enter | 140ms |
| dropdown enter | 170ms |
| tab/active indicator | 200–240ms |
| card hover | 160ms |
| modal enter | 220ms |
| modal exit | 150ms |
| drawer | 260ms |
| page enter | 220–300ms |
| page exit | 120–180ms |
| drag lift | 100ms |
| drag settle | 220–280ms |
| FLIP reflow | 220–280ms |
| progress | 350–500ms |
| KPI number | 400–600ms |
| chart | 350–600ms |
| theme change | 180–260ms |
| toast enter | 180–220ms |
| toast exit | 120–160ms |

These are implementation defaults, not universal laws.

---

# 4. EASING RULES

Use a small family.

### Standard

For ordinary state change:

```text
cubic-bezier(0.2, 0, 0, 1)
```

### Enter

For content arriving:

```text
cubic-bezier(0.16, 1, 0.3, 1)
```

### Exit

For content leaving:

```text
cubic-bezier(0.4, 0, 1, 1)
```

### Emphasis

For drag settle/shared geometry:

```text
cubic-bezier(0.22, 1, 0.36, 1)
```

Avoid using bounce/elastic everywhere. Productivity UI normally benefits from controlled acceleration and deceleration.

---

# 5. DESIGN FOUNDATION

Motion comes after the visual foundation.

Define tokens for:

```text
background
surface
surface-muted
text-primary
text-secondary
text-muted
border
accent
success
warning
error
info
spacing
radius
shadow
typography
motion
```

A premium dashboard generally benefits from:

```text
soft neutral background
clean white/light surfaces
strong primary text
quieter secondary text
subtle borders
restrained shadows
one dominant accent
semantic colors used sparingly
```

Do not copy a reference site's literal colors into every project. Copy the hierarchy and token strategy, then adapt the brand.

---

# 6. TYPOGRAPHY RULES

Use one primary UI typeface unless the brand requires more.

Hierarchy:

```text
page title
→ section heading
→ card heading
→ body
→ secondary/meta
→ caption
```

Recommended dashboard scale:

```css
--text-xs: 0.6875rem;
--text-sm: 0.8125rem;
--text-md: 0.9375rem;
--text-lg: 1.125rem;
--text-xl: 1.5rem;
--text-2xl: 2rem;
--text-3xl: 2.75rem;
```

Prefer:

```css
.page-title {
  font-weight: 500–650;
  letter-spacing: -0.03em;
  line-height: 1.05;
}

.numeric {
  font-variant-numeric: tabular-nums;
}
```

Do not animate font-size, font-weight, or letter-spacing for ordinary UI state changes.

---

# 7. SURFACE / RADIUS / DEPTH SYSTEM

Use a consistent radius hierarchy.

```css
--radius-xs: 8px;
--radius-sm: 12px;
--radius-md: 16px;
--radius-lg: 20px;
--radius-xl: 24px;
--radius-pill: 999px;
```

Use depth hierarchically:

```text
app background
→ panel
→ card
→ interactive surface
→ floating surface
→ drag preview
→ modal
```

Do not put a large shadow on every card. Increase depth only when an object becomes interactive/floating.

---

# 8. COMPONENT STATE MATRIX

Every interactive component should be considered in these states:

```text
default
hover
focus-visible
pressed
selected
disabled
loading
success
error
open
closed
dragging
drop-target
```

Use this table as the default behavior contract:

| State | Typical visual | Typical motion |
|---|---|---|
| default | neutral | none |
| hover | surface/color/shadow | 100–160ms |
| focus | ring/border | 100–150ms |
| pressed | compressed | 80–120ms |
| selected | accent surface/indicator | 160–240ms |
| disabled | muted | none |
| loading | localized spinner/skeleton | localized |
| success | semantic state | short morph/fade |
| error | visible error state | optional tiny shake |
| dragging | elevated | lift + pointer motion |
| drop-target | highlighted | tint/border |

---

# 9. BUTTONS

## Primary button

Use:

```text
strong accent surface
clear contrast
large hit target
small radius/pill depending on brand
```

Hover:

```text
translateY(-1px)
+ subtle shadow/border/gradient change
```

Pressed:

```text
translateY(0)
scale(0.985–0.99)
```

Example:

```css
.button {
  transition:
    transform 140ms var(--ease-standard),
    box-shadow 140ms var(--ease-standard),
    background-color 160ms var(--ease-standard);
}

.button:hover { transform: translateY(-1px); }
.button:active { transform: translateY(0) scale(.99); }
```

Never make normal dashboard buttons bounce or scale 1.08.

---

# 10. MAGNETIC CTA

Magnetic motion is a premium micro-interaction for selected primary actions.

Use only when:

```text
button is important
pointer/hover device exists
interaction is not dense
```

Recommended:

```text
radius: 60–100px
max offset: 4–10px
strength: 0.10–0.18
```

Formula:

```text
buttonX = pointerOffsetX × strength
buttonY = pointerOffsetY × strength
```

GSAP example:

```ts
gsap.to(button, {
  x: dx * strength,
  y: dy * strength,
  duration: 0.35,
  ease: "power3.out",
  overwrite: true,
});
```

Pointer leave:

```text
x → 0
y → 0
```

Use a 250–450ms reset.

Never:

```text
20px+ attraction
10%+ scale
large rotation
magnetize every button
magnetize touch controls
```

---

# 11. CARD MOTION

Dashboard cards should feel stable, not floaty.

Hover:

```text
translateY(-1px to -2px)
shadow + small
border + small
```

Press, when clickable:

```text
scale(.995)
```

Do not separately animate every child when the whole card can move as one unit.

---

# 12. NAVIGATION

## Sidebar item

Typical structure:

```text
icon + label + optional badge
```

Hover:

```text
surface/color only
```

Active:

```text
stronger label
accent icon
persistent indicator or active surface
```

## Shared active indicator

Treat the active indicator as one moving object.

Preferred:

```text
layoutId / FLIP / shared element
```

Avoid:

```text
old indicator removed
new indicator created
```

The perceived behavior should be:

```text
old item
  ↓
indicator travels
  ↓
new item
```

Typical:

```text
180–260ms
```

This is one of the highest-value premium dashboard details.

---

# 13. BADGES

Count changes should affect the count, not the entire navigation item.

Example:

```text
10 → 11
```

Optional pattern:

```text
old number exits upward
new number enters upward
```

Typical:

```text
160–220ms
```

Keep the badge geometry stable when possible.

---

# 14. TABS / SEGMENTED CONTROLS

Use a shared active surface whenever practical.

Concept:

```text
[ active pill ]
```

moves between options.

Recommended:

```text
180–240ms
```

Do not fade the whole control when the user changes a filter.

---

# 15. FILTERED CONTENT

When a filter changes:

Bad:

```text
entire page disappears
→ spinner
→ entire page appears
```

Good:

```text
preserve page structure
→ update local region
→ animate changed content only
```

Suggested:

```text
old: opacity 1, y 0
new: opacity 0, y 6–10px
new: opacity 1, y 0
```

Use 25–60ms card stagger, capped so the user never waits for a long list.

---

# 16. DIRECTIONAL REVEALS

Four reusable directions are enough.

### Up

```text
opacity: 0 → 1
y: 16px → 0
```

Use for cards/KPIs/lower sections.

### Down

```text
opacity: 0 → 1
y: -16px → 0
```

Use for top surfaces/menus when appropriate.

### Left

```text
opacity: 0 → 1
x: -16px → 0
```

### Right

```text
opacity: 0 → 1
x: 16px → 0
```

Recommended reveal distance:

```text
4px = subtle
8px = small
16px = normal
24px = strong
```

For most dashboards use 8–16px.

---

# 17. STAGGERED REVEAL

Stagger should create choreography, not delay the user.

Typical order:

```text
page title
→ description
→ primary action
→ KPI group
→ main visualization
→ secondary content
```

Typical stagger:

```text
30–70ms
```

Example:

```ts
const delay = Math.min(index * 0.05, 0.30);
```

Never use long serial delays for large lists.

---

# 18. INITIAL PAGE LOAD

Only the initial viewport needs a deliberate boot sequence.

Example:

```text
0ms   shell
50ms  header/sidebar
100ms title
140ms description
180ms actions
220ms KPI group
300ms primary chart
360ms secondary content
```

After initial boot, do not replay the entire sequence on every interaction.

---

# 19. ROUTE / PAGE TRANSITIONS

Keep this persistent:

```text
App shell
├─ sidebar
├─ header
└─ global UI
```

Animate:

```text
route content only
```

Same-level dashboard pages can use:

```text
exit:
opacity 1 → 0
y 0 → -4px

enter:
opacity 0 → 1
y 4px → 0
```

Typical:

```text
exit 120–180ms
enter 180–300ms
```

The old view should leave quickly; the new view can settle slightly more slowly.

---

# 20. HIERARCHICAL PAGE DIRECTION

For true parent/child navigation:

```text
parent → child = new content enters from right
child → parent = new content enters from left
```

For peer sections of an admin dashboard, subtle vertical motion is usually safer than large horizontal slides.

---

# 21. MODAL

Use a two-layer choreography:

```text
backdrop
+
dialog
```

Backdrop:

```text
opacity 0 → 1
```

Dialog:

```text
opacity 0 → 1
y 10–14px → 0
scale .985 → 1
```

Typical:

```text
enter 180–260ms
exit 120–180ms
```

Open the backdrop and dialog almost together.

Do not use `scale(0) → scale(1)`.

Accessibility requirements:

```text
focus trap
Escape close
body scroll lock
restore focus to trigger
```

---

# 22. DRAWER

Right drawer:

```text
translateX(100%) → 0
```

Left drawer:

```text
translateX(-100%) → 0
```

Backdrop:

```text
opacity 0 → 1
```

Typical:

```text
220–300ms
```

---

# 23. DROPDOWN / POPOVER

Enter:

```text
opacity 0 → 1
scale .98 → 1
y -4px → 0
```

Exit:

```text
opacity 1 → 0
scale 1 → .98
```

Typical:

```text
enter 150–190ms
exit 100–140ms
```

Menus should feel fast.

---

# 24. TOOLTIP

Use a small hover delay:

```text
delay 300–500ms
```

Enter:

```text
opacity 0 → 1
y 3px → 0
```

Typical:

```text
120–160ms
```

Exit faster.

Never let a tooltip reflow the page.

---

# 25. TOGGLE / CHECKBOX

Toggle:

```text
track color
+
thumb translation
```

Typical:

```text
160–220ms
```

Checkbox:

```text
checkmark path draw
```

Typical:

```text
120–180ms
```

Use motion to reinforce state; never require it to understand state.

---

# 26. TOAST

Enter:

```text
opacity 0 → 1
y 8px → 0
```

Exit:

```text
opacity 1 → 0
y 0 → 4px
```

Typical:

```text
enter 180–220ms
exit 120–160ms
```

---

# 27. DRAG AND DROP — STATE MACHINE

For any Kanban/sortable dashboard, implement explicit states:

```text
IDLE
↓
GRAB
↓
DRAGGING
↓
VALID_TARGET / INVALID_TARGET
↓
DROP / RETURN
↓
SETTLE
↓
IDLE
```

Do not scatter drag behavior across unrelated callbacks without state semantics.

---

# 28. DRAG LIFT

On grab:

```text
scale 1 → 1.01–1.02
shadow normal → elevated
optional y 0 → -2px
```

Typical:

```text
80–120ms
```

The user should feel that the object has been lifted from the surface.

---

# 29. DRAG PREVIEW

Preferred model:

```text
original:
opacity .3–.5

preview:
full opacity
higher z-index
slightly larger scale
elevated shadow
```

This preserves board readability.

---

# 30. DRAG POINTER PERFORMANCE

Do NOT do frame-level drag through React state like:

```tsx
setPosition({ x, y });
```

on every pointer event.

Prefer:

```text
transform
requestAnimationFrame
native pointer capture
drag library
gsap ticker
```

depending on the stack.

The pointer should control the target; the animation system should handle visual interpolation.

---

# 31. DROP TARGET

When a draggable enters a valid zone:

```text
border → accent
background → accent-soft
```

Typical:

```text
120–180ms
```

Use a stable highlight.

Do not continuously pulse the target.

---

# 32. DROP SETTLE

After release:

```text
drag preview
→ destination geometry
→ scale 1
→ shadow normal
```

Typical:

```text
180–280ms
```

Use emphasized easing.

---

# 33. SORTABLE REFLOW / FLIP

When surrounding cards move, animate their geometry.

Use FLIP or the equivalent layout-animation mechanism:

```text
First
Last
Invert
Play
```

GSAP example:

```ts
const state = Flip.getState(items);
commitNewOrder();
Flip.from(state, {
  duration: 0.24,
  ease: "power3.out",
  absolute: true,
});
```

Use the API version installed in the project.

---

# 34. INVALID DROP

Do not snap the item violently.

Return to origin:

```text
180–300ms
```

Optional subtle error shake:

```text
0 → -3px → 3px → -2px → 0
```

Typical:

```text
120–180ms
```

Always also show a meaningful error/state message when required.

---

# 35. KEYBOARD DRAG

Keyboard movement should produce the same visible reflow as pointer drag.

Do not give keyboard users:

```text
instant teleport
```

while pointer users receive:

```text
lift + FLIP + settle
```

Visual behavior should be consistent even when the input modality differs.

---

# 36. TABLE MOTION

Tables need stability more than theatrical motion.

Recommended:

```text
row hover background
small action reveal
subtle border change
```

Typical:

```text
100–150ms
```

Avoid row scale/rotation.

---

# 37. KPI / NUMBER ANIMATION

Animate a number when actual data changes.

Good:

```text
128 → 134
```

Bad:

```text
0 → 134 on every render
```

Typical:

```text
400–600ms
```

Keep width stable with tabular numerals/min-width when necessary.

---

# 38. PROGRESS BARS

Initial:

```text
scaleX(0) → scaleX(value)
transform-origin: left
```

Typical:

```text
350–500ms
```

Updates:

```text
old → new
```

Do not reset to zero unless the product semantics require an actual reset.

---

# 39. CHART MOTION

For line charts:

```text
stroke dash/path reveal
```

For bar charts:

```text
scaleY(0) → scaleY(1)
transform-origin: bottom
```

Typical:

```text
350–600ms
```

When changing periods:

```text
7D → 30D → 90D
```

prefer data interpolation or controlled crossfade.

Do not blank the chart first.

---

# 40. CHART TOOLTIP

On data-point hover:

```text
point scale 1 → 1.1–1.15
tooltip opacity 0 → 1
tooltip y +2–4px → 0
```

Typical:

```text
100–140ms
```

Tooltip must not change chart layout.

---

# 41. LOADING / SKELETON

Use localized loading states.

Prefer:

```text
existing UI
+
localized pending state
```

over:

```text
entire dashboard → spinner
```

Optional skeleton delay:

```text
~120–180ms before displaying a skeleton
```

This avoids flicker on fast requests.

Skeleton animation should be subtle and stop immediately when content arrives.

---

# 42. ASYNC ACTIONS

Correct:

```text
click
→ immediate press
→ request
→ success/error
```

Incorrect:

```text
click
→ 500ms visual animation
→ request
```

Animation must never become an artificial wait.

For safe local operations, optimistic UI is preferred:

```text
local visual update
→ server request
→ rollback only on failure
```

---

# 43. THEME / ACCENT SWITCHING

Treat theme colors as tokens:

```css
--accent
--accent-strong
--accent-soft
--accent-contrast
--accent-border
```

Theme changes should retint coherently:

```text
buttons
active states
focus
progress
charts
selection
status accents
```

Typical:

```text
180–260ms
```

Do not fade the whole application to white between themes.

---

# 44. GRADIENTS

Use gradients as subtle lighting/hierarchy.

Good:

```css
background:
  linear-gradient(135deg,
    var(--accent-strong),
    var(--accent));
```

Optional hover shift:

```css
background-size: 120% 120%;
transition: background-position 500ms var(--ease-standard);
```

Do not use animated gradients on every card.

---

# 45. AMBIENT DECORATION

Optional ambient motion can live in:

```text
background graphics
promotional cards
decorative SVGs
empty space
```

Typical cycle:

```text
8–20 seconds
```

It should be low contrast and never communicate core product state.

---

# 46. SCROLL REVEAL

Use when content genuinely enters the viewport.

Recommended:

```text
opacity 0 → 1
y 16px → 0
350–500ms
```

Prefer:

```text
IntersectionObserver
```

or:

```text
ScrollTrigger
```

Use `once` for most dashboard sections.

Do not replay all card animations continuously while scrolling.

---

# 47. MOBILE / TOUCH RULES

Magnetic mouse effects should normally be disabled when hover capability is unavailable.

Touch UI should prioritize:

```text
large hit targets
instant press feedback
clear selected state
```

Mobile sidebar:

```text
translateX(-100%) → 0
```

with backdrop:

```text
opacity 0 → 1
```

Typical:

```text
220–300ms
```

---

# 48. PERFORMANCE RULES

Premium motion must remain responsive.

## Prefer

```text
transform
opacity
```

## Use carefully

```text
box-shadow
filter
backdrop-filter
blur
```

## Avoid for frequent motion

```text
width
height
top
left
margin
padding
```

Do not create forced synchronous layout loops:

```text
read layout
→ write
→ read
→ write
```

Batch measurements and writes.

---

# 49. REACT PERFORMANCE RULE

For React-like frameworks:

```text
application state
= React/Vue/Svelte state

frame-level motion
= DOM / animation engine
```

Do not put every pointer position into application state.

For GSAP in React:

```tsx
useLayoutEffect(() => {
  const ctx = gsap.context(() => {
    // timeline / tween setup
  }, root);

  return () => ctx.revert();
}, []);
```

Always clean up.

---

# 50. `will-change`

Good:

```css
.dragging {
  will-change: transform;
}
```

Bad:

```css
* {
  will-change: transform;
}
```

Use it only around real performance-sensitive motion.

---

# 51. LIBRARY DECISION TABLE

| Requirement | Default choice |
|---|---|
| hover | CSS |
| focus | CSS |
| pressed | CSS |
| color/border | CSS |
| simple fade | CSS |
| simple drawer | CSS or existing framework motion |
| modal in React | existing Motion system |
| tabs | existing layout/motion system |
| active indicator | shared layout / FLIP |
| sortable cards | drag library + FLIP/layout motion |
| magnetic CTA | GSAP or direct transform+rAF |
| complex timeline | GSAP |
| complex scroll | GSAP ScrollTrigger or existing equivalent |
| SVG drawing | GSAP/CSS depending on complexity |
| charts | chart library native animation first |

**Rule:** the visual behavior matters more than the library name.

---

# 52. EXISTING STACK DETECTION

Before adding dependencies, inspect:

```text
package.json
lockfile
animation/motion folders
existing hooks
shared components
CSS tokens
chart library
drag library
```

Look for:

```text
gsap
motion
framer-motion
react-spring
anime
web animations
```

Then select one coherent approach.

Do not introduce a second animation engine when the existing one can solve the problem cleanly.

---

# 53. RECOMMENDED ARCHITECTURE

A reusable motion system can look like:

```text
src/
├── design/
│   ├── colors.ts
│   ├── typography.ts
│   ├── spacing.ts
│   ├── radii.ts
│   ├── shadows.ts
│   └── motion.ts
│
├── motion/
│   ├── tokens.ts
│   ├── easings.ts
│   ├── reveal.ts
│   ├── magnetic.ts
│   ├── flip.ts
│   ├── page-transition.ts
│   ├── reduced-motion.ts
│   └── cleanup.ts
│
└── components/
    ├── navigation/
    ├── buttons/
    ├── cards/
    ├── dialogs/
    ├── dropdowns/
    ├── tabs/
    ├── charts/
    └── drag-drop/
```

Adapt this to the project's actual architecture.

---

# 54. MOTION PRIMITIVES

Useful reusable primitives:

```text
RevealUp
RevealDown
RevealLeft
RevealRight
Stagger
AnimatedNumber
MagneticButton
ActiveIndicator
AnimatedTabs
AnimatedDialog
AnimatedDropdown
AnimatedToast
PageTransition
SortableBoard
```

Do not create wrappers for trivial one-line CSS.

Abstract repeated behavior, not every element.

---

# 55. MOTION STATE MACHINES

Complex interactions should have explicit state.

## Modal

```text
CLOSED → OPENING → OPEN → CLOSING → CLOSED
```

## Drag

```text
IDLE → GRABBED → DRAGGING → VALID/INVALID → DROPPING/RETURNING → SETTLING → IDLE
```

## Async button

```text
IDLE → PENDING → SUCCESS
             ↘ ERROR
```

State-driven motion is easier to reason about than scattered animations.

---

# 56. MOTION BUDGET

At one moment, aim for:

```text
1 primary motion
+
1–2 supporting motions
+
optional ambient motion
```

Example filter change:

```text
primary = chart/data
supporting = selected filter
supporting = changed KPI
ambient = none
```

If everything moves at once, the interface becomes noisy.

---

# 57. PRIORITY ORDER

When time is limited, implement in this order.

## P0 — foundation

```text
1. motion tokens
2. focus state
3. button hover/press
4. card hover
5. reduced motion
```

## P1 — high-value structure

```text
6. shared sidebar indicator
7. tabs/filter indicator
8. route transition
9. modal
10. dropdown/drawer
```

## P2 — advanced polish

```text
11. directional reveals
12. stagger
13. drag lift
14. FLIP reflow
15. magnetic CTA
16. animated numbers
17. chart transitions
```

## P3 — optional

```text
18. icon micro-motion
19. subtle gradient movement
20. ambient decorative motion
21. scroll reveal
```

Do not start with P3.

---

# 58. AI AGENT IMPLEMENTATION WORKFLOW

When asked to "make this dashboard premium/smooth":

### Step 1 — Audit

Inspect:

```text
framework
routes
component system
animation dependencies
design tokens
charts
drag/drop
existing motion
```

### Step 2 — Build a motion matrix

```text
component | state | motion | duration | easing | implementation
```

### Step 3 — Tokenize

Create/reuse:

```text
durations
easings
distances
```

### Step 4 — Foundation

Implement:

```text
hover
focus
pressed
selected
loading
error
success
```

### Step 5 — Spatial continuity

Implement:

```text
active indicator
tab/filter movement
layout reflow
```

### Step 6 — Structure

Implement:

```text
modal
drawer
dropdown
page transitions
```

### Step 7 — Advanced

Only then add:

```text
magnetic
drag/FLIP
charts
scroll choreography
ambient motion
```

### Step 8 — Verify

Check:

```text
performance
keyboard
reduced motion
mobile
cleanup
layout stability
```

---

# 59. MODEL-FRIENDLY DECISION TREE

Use this when deciding how to animate something:

```text
Does it only change color/border/opacity/tiny scale?
    YES → CSS
    NO ↓

Does the project already use a motion/layout library?
    YES → reuse it
    NO ↓

Does it need shared geometry, FLIP, complex timeline, magnetic pointer,
complex drag, SVG choreography, or scroll choreography?
    YES → GSAP is appropriate
    NO ↓

Can CSS/Web Animations express it cleanly?
    YES → CSS/Web Animations
    NO → smallest suitable library
```

---

# 60. AGENT OUTPUT FORMAT FOR LARGE TASKS

Before implementing a large motion pass, produce this compact plan:

```md
# Motion Plan

## Existing stack
- Framework:
- Motion library:
- Drag library:
- Chart library:

## Tokens
- Micro:
- Component:
- Structure:
- Easings:

## Motion matrix
| Component | State | Motion | Duration | Implementation |
|---|---|---|---:|---|

## Advanced
- Magnetic:
- FLIP:
- Drag:
- Route transitions:

## Accessibility
- Reduced motion:
- Keyboard:
- Focus:

## Performance risks
- ...
```

Then implement.

---

# 61. ACCESSIBILITY CONTRACT

Animation is subordinate to accessibility.

Must support:

```text
focus-visible
keyboard navigation
Escape for dismissible overlays
reduced motion
touch interaction
```

Never communicate critical information only through:

```text
color
movement
shake
animation
```

---

# 62. REDUCED MOTION

Minimum CSS fallback:

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

For complex motion, additionally:

```text
remove magnetic movement
remove large translations
remove parallax
reduce stagger
stop ambient loops
preserve meaningful state change
```

---

# 63. QA — VISUAL

Before shipping:

```text
[ ] hierarchy is clear
[ ] spacing is consistent
[ ] active state is obvious
[ ] hover is subtle
[ ] press is immediate
[ ] focus is visible
[ ] sidebar indicator moves
[ ] tabs/filters preserve continuity
[ ] route transition does not flash
[ ] cards do not jump
[ ] modal is coherent
[ ] dropdown is fast
[ ] drag feels lifted
[ ] drop reflows smoothly
[ ] KPI numbers do not shift layout
[ ] charts do not reset unnecessarily
```

---

# 64. QA — PERFORMANCE

```text
[ ] no transition: all
[ ] no React setState per pointermove
[ ] no unnecessary layout properties animated
[ ] no leaked GSAP timelines
[ ] no leaked observers/listeners
[ ] no excessive will-change
[ ] no large blur animation storms
[ ] no hundreds of simultaneous tweens
[ ] no shell replay on every route
[ ] no animation blocks user input
[ ] reduced-motion path works
```

---

# 65. ANTI-PATTERNS

Never default to:

```text
❌ scale(1.05+) on dashboard cards
❌ rotation on normal buttons
❌ infinite floating cards
❌ infinite pulse on notification dots
❌ whole-page fades for filters
❌ 500–1000ms hover effects
❌ giant slide distances
❌ gradient animation on everything
❌ large blur transitions
❌ full-screen loading for local actions
❌ serial 200ms stagger for long lists
❌ reanimating sidebar/header on every route
❌ resetting charts to zero before updates
❌ teleporting sortable cards
❌ adding GSAP for a simple hover
❌ adding 3 animation libraries for one dashboard
```

---

# 66. PREMIUM PATTERN LIBRARY

Keep these as the core reusable patterns:

```text
01. shared active sidebar indicator
02. sliding segmented selection
03. sliding tab underline
04. subtle card lift
05. tactile button press
06. magnetic primary CTA
07. directional reveal
08. staggered section reveal
09. route content transition
10. modal backdrop + content choreography
11. dropdown fade/scale
12. drawer slide
13. progress fill
14. animated KPI number
15. chart draw/update
16. physical drag lift
17. drag preview
18. drop target highlight
19. FLIP reflow
20. invalid-drop return
21. toast enter/exit
22. toggle motion
23. checkbox draw
24. theme retint
25. optional ambient decoration
```

---

# 67. MINIMUM PREMIUM PRESET

If implementation time is limited, do exactly this:

```text
motion tokens
+
button hover/press
+
card hover
+
focus states
+
shared sidebar active indicator
+
shared tab/filter indicator
+
subtle route transition
+
modal transition
+
dropdown transition
+
reduced motion
```

This gives most of the perceived improvement without over-engineering.

---

# 68. FULL PREMIUM PRESET

For products where motion is part of the brand:

```text
foundation
→ state matrix
→ shared indicators
→ directional reveals
→ stagger
→ route motion
→ modal/drawer/dropdown
→ drag lift
→ FLIP
→ magnetic CTA
→ KPI/chart motion
→ theme transition
→ optional ambient motion
```

Still keep the motion budget under control.

---

# 69. ONE-PASS COMPONENT RECIPE

When adding a new interactive dashboard component, answer:

```text
1. What is its default state?
2. What changes on hover?
3. What changes on focus?
4. What changes on press?
5. What does selected mean?
6. Does it need enter/exit motion?
7. What object should visually move between states?
8. What is the smallest useful duration?
9. Which shared easing applies?
10. Can CSS do it?
11. If not, can the existing motion library do it?
12. Is GSAP actually justified?
13. What happens with reduced motion?
14. What happens on keyboard/touch?
15. How is the animation cleaned up?
```

---

# 70. FINAL ACCEPTANCE STANDARD

A premium dashboard should feel like this:

```text
HOVER
→ immediate
→ subtle

PRESS
→ tactile
→ short

NAVIGATION
→ active state moves
→ shell remains stable

PAGE CHANGE
→ old content exits quickly
→ new content enters softly
→ no flash

FILTER
→ selection slides
→ changed region updates locally

CARD
→ lifts slightly
→ never jumps

DRAG
→ lifts
→ follows smoothly
→ target highlights
→ siblings reflow
→ object settles

MODAL
→ backdrop + surface arrive together
→ focus is correct

DATA
→ values interpolate
→ charts update without unnecessary reset
→ no layout shift

THEME
→ interface retints coherently

PERFORMANCE
→ no stutter
→ no animation leaks
→ no input lag

ACCESSIBILITY
→ keyboard works
→ focus visible
→ reduced motion works
```

---

# 71. FINAL RULE

> **Build the dashboard as if every interaction has weight, direction, and a reason to move — but never let the animation become more important than the user's task.**

The best premium dashboard animation is usually:

```text
small
fast
consistent
spatially meaningful
performance-safe
```

not:

```text
large
slow
constant
random
```
