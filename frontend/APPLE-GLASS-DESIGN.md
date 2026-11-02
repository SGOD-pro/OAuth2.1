# Apple-Inspired Glass Design

A reusable design and implementation guide for web and native interfaces. Use it alongside the product's existing design system, not as permission to turn every surface into glass.

**Status:** Design guidance and starting values, not an Apple specification. Apple's native Liquid Glass is a system material. CSS, SVG and WebGL versions are approximations with different capabilities.

## 1. Start with the task

Before applying a material, identify:

1. The user, primary task, platform and input method.
2. Which content must remain easy to read, select or edit.
3. Which controls float over changing content and benefit from spatial context.
4. Existing colors, typography, shapes, spacing and component APIs to preserve.
5. The least capable supported device and the required accessibility settings.

Make a small material map for the screen. Give glass a purpose: it can distinguish floating navigation or controls while allowing context underneath to remain visible. If it does not improve hierarchy or spatial understanding, use an ordinary surface.

## 2. Choose where glass belongs

| Surface | Recommendation | Why / constraint |
| --- | --- | --- |
| Floating tab bar, toolbar or navigation rail | Good candidate | Separates navigation from scrolling content. Keep labels readable. |
| Compact floating action group | Good candidate | Supports a small, distinct control layer. Keep primary actions obvious. |
| Search overlay or short popover | Conditional | Works for a short task when the background is controlled. Use an opaque surface if content competes. |
| Modal or bottom sheet | Conditional | Favor a stable, readable surface and scrim for a focused task. A subtle material is optional. |
| Media controls above imagery | Conditional | Test against bright, dark and moving frames. Use a local scrim when needed. |
| Dashboard card or list row | Usually no | Repetition, dense data and changing backgrounds make blur distracting and expensive. |
| Forms, tables, code, long articles and charts | No for the reading surface | Precision and sustained legibility matter more than decorative transparency. |
| Alerts, destructive actions, errors and security decisions | Prefer solid | Meaning and state must stay unambiguous on every background. |
| Full-page background, every container, nested glass | Avoid | Removes hierarchy, adds visual noise and raises rendering cost. |

Do not make a material the only way to identify a selected, disabled, focused, warning or error state. Use labels, shape, color and/or iconography with adequate contrast.

## 3. Visual rules

- **Content first:** A person's information is the main surface. Keep glass for a small number of functional layers.
- **One material family:** Use shared tokens across components. Match the product's existing palette and geometry.
- **Prefer restraint:** Soft surface tint, moderate blur, a fine edge and a restrained shadow. Decorative color fringes are optional and usually nearly invisible.
- **Edges describe form:** Use a smooth continuous edge, not a thick fixed white line. Highlights should follow the shape and fade gradually. Eliminate rectangular canvas or filter corners.
- **Frost is smooth:** Blur softens detail without visible pixel blocks, repeated bands or obvious noise. Frost at zero must not secretly blur the content.
- **Refraction is local:** If used, keep it near the boundary and preserve a clear center. Avoid dragging the whole background or navbar out of shape.
- **Dispersion is a hint:** Separate colors only subtly at an edge. Avoid colored halos around text and icons.
- **Adapt to the surface below:** Use a stronger tint or scrim when background detail harms contrast. Do not rely on `mix-blend-mode` as the only legibility strategy.
- **Avoid stacking glass:** An overlay over a glass toolbar should generally have a more stable surface. Do not apply the same effect twice to the same region.
- **Tint follows meaning:** Use brand color for selected or important controls when it stays readable. Never assume white text works everywhere.

## 4. Suggested starting tokens

These are **project defaults to tune**, not Apple's values. Derive light and dark variants from the existing theme and test on real backdrops.

```css
:root {
  --glass-surface: rgb(255 255 255 / 0.68);
  --glass-border: rgb(255 255 255 / 0.45);
  --glass-shadow: 0 8px 24px rgb(0 0 0 / 0.12);
  --glass-ink: #17202d;
  --glass-blur: 16px;
  --glass-saturation: 1.15;
  --glass-radius: 18px;
  --glass-focus: #005fcc;
}

[data-theme='dark'] {
  --glass-surface: rgb(22 27 35 / 0.76);
  --glass-border: rgb(255 255 255 / 0.17);
  --glass-shadow: 0 8px 24px rgb(0 0 0 / 0.28);
  --glass-ink: #fff;
  --glass-focus: #9ac6ff;
}
```

Treat opacity, blur, radius, shadow and color as independent controls. A stronger bevel should change a smooth edge profile, not create a fixed thick band. A zero value for refraction, dispersion, frost or shine should genuinely disable that property. Provide ranges with documented units; do not expose controls that have no visible effect across their advertised range.

## 5. A safe web baseline

Start opaque. Enhance with backdrop blur only where supported. This example is **translucency and blur**, not true refraction.

```css
.glass-surface {
  color: var(--glass-ink, #17202d);
  background: #f4f6f9;
  border: 1px solid rgb(15 23 42 / 0.18);
  border-radius: var(--glass-radius, 18px);
  box-shadow: var(--glass-shadow, 0 8px 24px rgb(0 0 0 / 0.12));
}

[data-theme='dark'] .glass-surface {
  color: #fff;
  background: #252b35;
  border-color: rgb(255 255 255 / 0.24);
}

@supports ((-webkit-backdrop-filter: blur(1px)) or (backdrop-filter: blur(1px))) {
  .glass-surface {
    background: var(--glass-surface);
    border-color: var(--glass-border);
    -webkit-backdrop-filter: blur(var(--glass-blur)) saturate(var(--glass-saturation));
    backdrop-filter: blur(var(--glass-blur)) saturate(var(--glass-saturation));
  }
}

.glass-surface :focus-visible {
  outline: 2px solid var(--glass-focus);
  outline-offset: 3px;
}

@media (prefers-reduced-transparency: reduce), (prefers-contrast: more) {
  .glass-surface {
    background: #f4f6f9;
    color: #17202d;
    border-color: #48566a;
    -webkit-backdrop-filter: none;
    backdrop-filter: none;
  }
  [data-theme='dark'] .glass-surface {
    background: #252b35;
    color: #fff;
    border-color: #bbc6d5;
  }
}

@media (forced-colors: active) {
  .glass-surface {
    color: CanvasText;
    background: Canvas;
    border: 1px solid CanvasText;
    box-shadow: none;
    -webkit-backdrop-filter: none;
    backdrop-filter: none;
  }
  .glass-surface :focus-visible { outline-color: Highlight; }
}
```

Also provide an app-level solid-material option: not all browsers expose or honor reduced-transparency preferences. Check the rendered contrast of the actual foreground against real background combinations. Feature detection does not establish visual correctness.

**Use semantic controls:** `<button>` for actions and `<a href>` for navigation. Keep foreground text and controls as real, selectable, accessible DOM. Decorative layers use `aria-hidden="true"` and `pointer-events: none`. Do not disable scrolling or selection to achieve the effect.

## 6. Choose the rendering path deliberately

| Approach | What it can do | Important limits |
| --- | --- | --- |
| Native system material | System-integrated adaptive material on supported Apple OS versions | Native platform only. Prefer standard system controls. Respect availability and system accessibility settings. |
| CSS backdrop blur | Blur and tint actual rendered backdrop in supporting browsers | Not optical refraction. Clipping, nesting and compositing vary by browser. Provide opaque fallback. |
| SVG displacement | Distort an explicit SVG image or source image; may be usable as a filter in supported combinations | Do not assume SVG URL filters applied to a backdrop work consistently on iOS. `@supports` alone cannot prove correct pixels. Test actual devices. |
| WebGL / canvas shader | Controlled displacement, edge effects and chromatic separation of a texture | A canvas cannot automatically sample arbitrary live HTML behind it. Requires a supplied or reconstructed scene, performance budget and recovery on context loss. |

A reusable `<GlassSurface>` can wrap arbitrary content for tint and blur. A **physically refracting wrapper around arbitrary live DOM**, including cross-origin images, video and animation, cannot be assumed from a generic WebGL canvas. Requesting it requires an explicit scene-capture/compositing strategy and a tested fallback. Cross-origin image rules may prevent reading a canvas.

### If a refracted scene is required

1. Decide what the scene contains and how it stays in sync. Do not claim to capture content that is not included.
2. Use the DOM itself as the single source of labels and icons. Any off-screen snapshot must not create a second accessible or visibly misaligned copy.
3. Preserve SVG `fill="none"`, `stroke`, `currentColor`, line caps, stroke width and transforms. Never force-fill all paths: Lucide and other outline icons will break.
4. Render the lens with real geometry and a rounded alpha mask. Handle device pixel ratio, resize, page scroll, transforms and zoom in a single coordinate space.
5. Avoid reading layout and reallocating canvases repeatedly during drag. Cap resolution based on measurement, not an unverified device guess. Stop work when hidden, idle or offscreen; recover from context loss and clean up observers and animation frames.
6. Avoid duplicate live and refracted text. Distortion must remain deliberate, legible and confined to the actual lens. Test the handoff when motion ends.
7. Give the fallback a clear label in developer documentation: opaque or blurred material, not equivalent refraction.

## 7. Interaction and motion

Motion communicates state and direct manipulation. It is not a permanent decoration.

- Provide immediate press feedback. Keep target geometry and hit areas stable.
- During drag, preserve the pointer's grab offset. Track the input without a CSS transition restarting on every frame. Support pointer capture, cancellation and interruption.
- Use one source of truth for position. A new gesture starts from the current displayed position. For release, hand off velocity where the chosen motion system supports it.
- Use bounded spring motion for physical interactions. Keep positional and shape springs independent. Add modest squash/stretch for momentum, not constant wobble.
- At an edge, use a soft, bounded response and mirror left/right behavior. Avoid repeated impulses while the pointer stays at a boundary. If the design calls for a wall impact, detect a single crossing and apply a damped response, not an unbounded or magnetic pull.
- Return from active to idle smoothly. Do not snap position, resize the wrong wrapper, shift the icon layer, reveal an old pill or swap in misaligned text.
- Do not animate icons or labels just because the glass moves. If the product intentionally shows refracted text under the lens, keep it legible and ensure there is no visible duplicate.
- For button taps, subtle scale or color can be enough. Reserve elastic motion for a drag, release or meaningful boundary. Avoid looping animation and unsolicited parallax.
- Disable or simplify elastic deformation and parallax for reduced motion. Keep instant, clear state feedback and preserve the ability to navigate.

**Starting points, not standards:** short press feedback around 100–160 ms; modest open/close transitions around 180–300 ms; spring settling depends on stiffness, damping and initial velocity, not a fixed CSS duration. Tune using device recordings and interaction testing. Do not apply arbitrary timing changes to fix layout or clipping bugs.

## 8. Accessibility and usable states

- Target WCAG 2.2 AA where applicable: ordinary text generally needs **4.5:1**, large text **3:1**, and relevant UI boundaries or icons generally **3:1** against adjacent colors. Follow the standard's exceptions. Check every representative background, including bright, dark, patterned and moving content.
- WCAG 2.2 target size minimum is generally **24 × 24 CSS px or sufficient spacing**, subject to its exceptions. Larger touch targets improve usability; native platform conventions may recommend different sizes.
- Support keyboard navigation, visible focus, screen readers, zoom, larger text and RTL layouts. Announce selected and disabled states semantically, not through color alone.
- Respect reduced motion, reduced transparency and increased contrast where detectable. Provide an explicit appearance setting when detection is unavailable. Test forced colors on web.
- Ensure focus rings and text are not clipped by the decorative mask. Do not use a decorative duplicate as the accessible control.
- Check loading, empty, error, selected, unselected, focus, hover, pressed, disabled and open/closed states. Verify both pointer and keyboard operation.

## 9. Platform guidance

### Native Apple platforms

Prefer standard navigation, toolbar, tab and sheet controls before applying custom effects. Follow OS availability and use system-provided Liquid Glass APIs when appropriate. SwiftUI offers `glassEffect(_:in:)` and `GlassEffectContainer` on supported platform versions; consult current Apple documentation for deployment targets. Let system materials adapt to appearance, contrast, transparency and other accessibility settings. Avoid layering custom simulated glass over system glass.

### Web

Use semantic HTML and CSS for the baseline. Prefer existing design-system controls and avoid taking over pointer or scroll behavior. Use the lightest effect that meets the brief. Verify actual iOS Safari on a physical device when iPhone support is a requirement. Chrome on iOS is also subject to platform browser constraints, but do not assume identical results across versions or browsers. A desktop responsive viewport is not an iPhone rendering test.

### Other platforms

Use the platform's established materials and interaction conventions. Keep the visual language compatible with the product instead of copying iOS navigation patterns into Android, desktop or enterprise workflows blindly.

## 10. Review and verification checklist

Record the environment and evidence for each result. Distinguish source review, unit tests, browser emulation, visual review and physical-device testing.

### Design

- [ ] Each glass surface has a clear functional reason and does not compete with content.
- [ ] Surface density, tint and typography match the existing UI.
- [ ] Glass does not cover dense reading, data entry or critical messaging.
- [ ] Text, icons and focus indicators stay clear over all relevant backdrops.

### Interaction

- [ ] Drag slowly and quickly through the middle; stop without releasing; reverse; release; interrupt the return.
- [ ] Test first and last positions, mirrored wall behavior, taps, pointer cancellation, resize and orientation change.
- [ ] The intended glass lens moves and deforms; labels and navigation geometry do not shift unexpectedly.
- [ ] No duplicate icon, text, old pill, rectangular canvas edge, flicker or sudden release jump.
- [ ] Reduced-motion interaction still responds and reaches the correct state.

### Rendering and performance

- [ ] Test light, dark, solid, high-detail and moving backdrops; both theme modes; settings at zero and at their maximum.
- [ ] Check the actual chosen renderer and fallback on supported versions of Safari/iOS, Android Chrome and desktop browsers. Test SVG and WebGL separately when offered.
- [ ] Check for clipped corners, white rectangles, hard bands, noisy gradients, pixelated frost and unreadable refracted content.
- [ ] Check console errors and a real-device performance trace while dragging and scrolling. Watch dropped frames, GPU/memory load and battery behavior. Compare before and after; do not claim a frame rate without measurement.
- [ ] Verify resize/visibility cleanup, reduced transparency, forced colors, keyboard, screen reader and zoom.
- [ ] Record browser/OS/device, actual settings, observed issues and remaining gaps. If no physical iPhone was tested, say so explicitly.

## 11. Handoff for an implementation agent

1. Inspect the existing app, design tokens, components, states and supported platforms before editing.
2. Identify suitable candidate surfaces and explain any surface that should remain solid.
3. Choose a native, CSS or scene-based rendering path. Document what content it can and cannot refract.
4. Add the smallest reusable material API that fits existing architecture. Keep material parameters separate from interaction and semantic content.
5. Preserve existing functionality, routes, keyboard behavior and theme controls.
6. Implement opaque and accessibility fallbacks first, then the enhancement.
7. Run appropriate checks. Render and interact at relevant sizes; compare real visual states. Report actual evidence and untested devices.
8. Tune based on the product and user feedback. Do not present approximation as a pixel-perfect recreation of Apple's private implementation.

## Sources and further reading

- Apple, [Liquid Glass technology overview](https://developer.apple.com/documentation/technologyoverviews/liquid-glass).
- Apple, [Materials in the Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/materials).
- Apple, [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass).
- Apple, [Meet Liquid Glass, WWDC25](https://developer.apple.com/videos/play/wwdc2025/219/).
- Apple, [SwiftUI glassEffect](https://developer.apple.com/documentation/swiftui/view/glasseffect(_:in:)).
- W3C, [WCAG 2.2](https://www.w3.org/TR/WCAG22/).
- Emil Kowalski, [Apple Design skill](https://github.com/emilkowalski/skills/blob/main/skills/apple-design/SKILL.md), a third-party interpretation for the web, not official Apple guidance.
- Uizze, [UI Taste](https://uizze.sh/), applied for design judgment, preserving product identity and evidence-based visual review.
