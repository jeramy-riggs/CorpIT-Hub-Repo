---
name: CorpIT Control Registry
description: A calm operational registry that turns live evidence into the next responsible action.
colors:
  workspace: "#f6f7f8"
  surface: "#ffffff"
  surface-muted: "#f0f3f7"
  surface-raised: "#f8fafc"
  ink: "#081728"
  ink-secondary: "#46546c"
  ink-muted: "#59677b"
  rule: "#dbe2eb"
  rule-soft: "#e8edf3"
  cobalt: "#0858f8"
  cobalt-deep: "#0648ca"
  cobalt-wash: "#eaf1ff"
  healthy: "#16834e"
  healthy-wash: "#e6f5ed"
  warning: "#a66b00"
  warning-wash: "#fff4d6"
  critical: "#ca2932"
  critical-wash: "#fee9ea"
  midnight: "#081728"
  midnight-raised: "#10243c"
  shell-text: "#f7f9fc"
  dark-workspace: "#0b1320"
  dark-surface: "#101b2a"
  dark-ink: "#f1f5fa"
  dark-cobalt: "#6e9cff"
typography:
  headline:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "29px"
    fontWeight: 600
    lineHeight: 1.08
    letterSpacing: "-0.025em"
  title:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "19px"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.018em"
  body:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "IBM Plex Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "10.5px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "0.06em"
rounded:
  status: "5px"
  compact: "7px"
  control: "7px"
  panel: "10px"
  round: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  xl: "28px"
components:
  button-primary:
    backgroundColor: "{colors.cobalt}"
    textColor: "{colors.surface}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "7px 13px"
  button-primary-hover:
    backgroundColor: "{colors.cobalt-deep}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "7px 13px"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "7px 13px"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.compact}"
    padding: "8px 11px"
  status-warning:
    backgroundColor: "{colors.warning-wash}"
    textColor: "{colors.warning}"
    typography: "{typography.label}"
    rounded: "{rounded.status}"
    padding: "3px 6px"
  registry-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
---

# Design System: CorpIT Control Registry

## Overview

**Creative North Star: "The Control Registry"**

CorpIT is a live operational ledger, not a decorative dashboard. A midnight navigation rail anchors a cool-frost workspace where precise rules, compact records, and restrained status color make the current condition easy to scan. The interface feels calm, factual, and densely useful without becoming visually heavy.

The system moves from verdict to evidence to responsible action. Cobalt marks selection and action; amber and red are reserved for conditions that require attention; mono metadata provides timestamps, counts, and machine evidence. Surfaces remain mostly flat so hierarchy comes from placement, tonal shifts, and etched dividers.

**Key Characteristics:**

- Midnight shell against a bright, cool workspace.
- Flat, rule-defined panels with restrained corners.
- Practical sans hierarchy paired with compact mono metadata.
- Ordered records that preserve context while revealing evidence and next steps.
- Status is always expressed with text or structure as well as color.

## Colors

The palette is a cool neutral field with one cobalt action ink and a narrow semantic set for healthy, warning, and critical states. A complete dark mode preserves those role relationships with lighter foreground and accent values.

### Primary

- **Cobalt Action Ink:** Selection rails, active navigation, primary buttons, links, focus outlines, and informational status.
- **Cobalt Wash:** Selected records and next-action containers; use it as a local state field, not a page background.

### Secondary

- **Healthy Green:** Verified healthy states, live indicators, and metric bars.
- **Warning Amber:** Conditions that need review but are not destructive or failed.
- **Critical Red:** Failed or high-risk conditions and destructive action emphasis.

### Neutral

- **Cool Frost:** The workspace field behind operational surfaces.
- **Registry White:** The default panel and control surface.
- **Midnight Navy:** The persistent navigation shell and its raised states.
- **Etched Rules:** Cool gray borders divide records, facts, and metrics instead of relying on shadow.
- **Operational Ink:** Near-navy primary text with slate secondary and metadata levels.

### Named Rules

**The One Action Ink Rule.** Cobalt owns navigation selection, primary action, links, and focus; do not introduce a competing accent.

**The Status Has Words Rule.** Healthy, warning, critical, and unknown conditions always carry a label, symbol, or explanatory copy in addition to color.

**The Honest Unknown Rule.** Missing or stale evidence uses muted or explicit unavailable language; it never inherits healthy green.

## Typography

**Display Font:** IBM Plex Sans (with system-ui and Segoe UI fallback)
**Body Font:** IBM Plex Sans (with system-ui and Segoe UI fallback)
**Label/Mono Font:** IBM Plex Mono (with platform monospace fallbacks)

**Character:** IBM Plex Sans keeps the console professional and direct, while IBM Plex Mono separates machine facts from explanatory prose. The scale is compact, with weight and spacing doing more work than oversized type.

### Hierarchy

- **Headline** (600, 29px, 1.08): Primary operational page statements; reduce to 26px on narrow screens.
- **Title** (600, 19px, 1.25): Selected-record headings and the highest local hierarchy inside panels.
- **Section title** (600, 13–16px): Panel headings, record names, and evidence sections.
- **Body** (400, 14px, 1.5): Explanations and operator guidance; action-oriented paragraphs generally stay within 70–75ch.
- **Label** (400–600, 9.5–11px, tracked): Timestamps, counts, field labels, environment facts, and table metadata. Uppercase is limited to short machine-oriented labels.

### Named Rules

**The Evidence Face Rule.** Use mono for values an operator may compare, copy, or audit; use sans for interpretation and action.

**The Compact Hierarchy Rule.** Establish importance with weight, contrast, and grouping before increasing size.

## Layout

Desktop uses a two-column application shell: a fixed 224px navigation rail and a fluid workspace. The top environment strip is 64px high, and the content canvas uses 28px page padding. The signature operations board is a 42% queue and 58% detail split, bounded as one panel so selection and evidence read as a single workflow.

Spacing follows a compact 4/8/12/18/28px rhythm. Dividers align related facts into registers: four estate cells, three record facts, and a horizontal health strip. At 1180px the master pane tightens; at 900px the shell collapses to a 76px icon rail and the board stacks; at 620px the rail becomes 68px, page gutters become 12px, facts become single-column, and actions become full-width. Information may reflow, but no operational state or action disappears solely because of viewport size.

**The Preserved Context Rule.** Selection, evidence, and the next action remain visually connected; do not send routine triage into a detached card grid.

## Elevation & Depth

The working surface is flat by default. Borders, pale tonal fields, and the midnight shell create depth; cards and stat groups carry no resting shadow. The only substantial elevation is reserved for transient overlays such as command search and modal sheets.

### Shadow Vocabulary

- **Overlay:** A broad, low-opacity navy shadow lifts command search and modal sheets above the registry.
- **Status halo:** A small tonal ring around the environment dot makes live state legible without turning it into decoration.

### Named Rules

**The Flat Registry Rule.** Persistent operational surfaces use rules and tonal layers, never floating card shadows.

## Shapes

The form language is precise and restrained: panels use 10px corners, controls and evidence wells use 7px corners, compact status slips use 4–6px corners, and only avatars or dot indicators are fully round. One-pixel borders define the system. Selected records add a 2px cobalt edge rather than changing their silhouette.

**The Restrained Corner Rule.** Radius indicates component scale; do not soften the console into oversized pills or bubbly cards.

## Components

### Buttons

- **Shape:** Compact rectangular controls with restrained corners (7px) and 7px × 13px padding.
- **Primary:** Cobalt fill, white text, and matching border; reserve it for the next responsible action.
- **Secondary:** White surface with an etched border and operational ink.
- **Hover / Focus:** Hover strengthens fill or border. Focus uses a visible 2px cobalt outline with offset. Active controls compress slightly; reduced-motion users receive state change without motion.

### Chips

- **Style:** Compact mono status slips use semantic wash, semantic text, and a modest 5px radius.
- **State:** Labels such as Open, Warning, Critical, and blocked remain readable without color and do not replace explanatory copy.

### Cards / Containers

- **Corner Style:** Restrained panel corners (10px).
- **Background:** Registry white over cool frost; raised headers use the palest cool surface.
- **Shadow Strategy:** None at rest.
- **Border:** One-pixel etched rules define the outer panel and every structural division.
- **Internal Padding:** Dense 12–18px spacing, with larger 28px page gutters on desktop.

### Inputs / Fields

- **Style:** White field, one-pixel cool rule, compact corners (7px), and 8px × 11px padding.
- **Focus:** Border shifts to cobalt with a three-pixel translucent cobalt ring.
- **Disabled:** Retains shape and label while dropping to half opacity; the cursor and active compression are removed.

### Navigation

The left rail is midnight navy with low-contrast labels and 40px navigation rows. The active item uses a cobalt-navy fill plus an inset light-cobalt edge. At tablet and mobile widths labels collapse while icons, selected state, focus, and section order remain intact.

### Attention Registry

The ordered queue is the signature component. Each record combines a numbered severity marker, factual title and detail, recency, and a written severity. Selection uses cobalt wash and a 2px leading rail, while the adjoining detail pane holds estate facts, evidence, cause, impact, and a highlighted next-action block. The record and detail pane are one interaction, not independent cards.

### Health Strip

Live host metrics sit in a thin ruled register. Labels and values use mono, compact green/amber/red bars reinforce the reading, and an explicit system-health label carries the overall condition.

## Do's and Don'ts

### Do:

- **Do** lead with the most consequential verified condition and keep its evidence and next safe action adjacent.
- **Do** use one-pixel rules and tonal fields to create structure in persistent surfaces.
- **Do** preserve the sans/mono division between explanation and auditable facts.
- **Do** show stale, failed, loading, and unavailable states explicitly.
- **Do** keep desktop density high while reflowing all controls and facts for narrow viewports.

### Don't:

- **Don't** introduce gradients, glass effects, neon color, illustrations, or promotional imagery into the operational shell.
- **Don't** turn the registry into a generic mosaic of independently floating cards.
- **Don't** use shadow as routine separation or introduce hard offset shadows.
- **Don't** use color alone to communicate status or render unavailable evidence as a healthy zero.
- **Don't** add a second accent color or use cobalt as broad decoration.
