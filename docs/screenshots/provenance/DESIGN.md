---
name: Security Detection Lab evidence viewer
description: Static bilingual evidence documentation extending the Network Access Auditor report pattern.
colors:
  navy: "#203d50"
  ink: "#172c3c"
  paper: "#fff"
  canvas: "#edf1f3"
  muted: "#476174"
  label-accent: "#8b371f"
  divider: "#d8e0e5"
  table-head: "#eaf0f4"
  code-surface: "#f1f5f7"
  note-surface: "#fff5e8"
  source-text: "#425d6d"
  link: "#245771"
  selection: "#d4e6ef"
  footer-divider: "#c4d0d8"
  footer-text: "#465d6d"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "36px"
    lineHeight: 1.12
    letterSpacing: "-.025em"
  headline:
    fontSize: "20px"
    lineHeight: 1.3
  translation:
    fontSize: "22px"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "17px"
    lineHeight: 1.45
  table:
    fontSize: "16px"
  label:
    fontSize: "14px"
    fontWeight: 700
  code:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "15px"
    lineHeight: 1.45
  sources:
    fontFamily: "ui-monospace, SFMono-Regular, monospace"
    fontSize: "12px"
    lineHeight: 1.6
spacing:
  table-cell: "9px 12px"
  code-inset: "15px 18px"
  note-inset: "13px 17px"
  page-inset: "30px 42px 26px"
  section-margin: "24px 0 17px"
components:
  evidence-label:
    textColor: "{colors.label-accent}"
    typography: "{typography.label}"
    padding: "9px 0"
  evidence-table:
    typography: "{typography.table}"
    width: "100%"
  literal-output:
    backgroundColor: "{colors.code-surface}"
    typography: "{typography.code}"
    padding: "{spacing.code-inset}"
  explanatory-note:
    backgroundColor: "{colors.note-surface}"
    padding: "{spacing.note-inset}"
  source-link:
    textColor: "{colors.link}"
  source-link-hover:
    textColor: "{colors.label-accent}"
---

# Design System: Security Detection Lab evidence viewer

## Overview

**Creative North Star: "The Evidence Report"**

A navy-on-white evidence report extending the established Network Access Auditor documentation pattern. Compact tables, literal outputs and source links support calm, factual review in Spanish and English. This system describes a read-only desktop evidence viewer, not product UI or a new product identity.

**Key Characteristics:**
- Compact tables with tabular numerals.
- Bilingual hierarchy and explicit evidence-viewer labels.
- Flat paper surfaces, restrained amber notes and traceable outputs.

Scope: actual implementation in `../viewer/style.css`, the index and five evidence pages, with five JPEG captures in `../images/`. Product context: `PRODUCT.md`. This is a source-led extension; no generated imagery or design comp was used. The Impeccable context launcher failed with permission denied, so no automated style detector ran. Tokens were extracted directly from CSS. Capture review is desktop-specific; mobile behavior below is documented from source, not claimed as visually verified.

## Colors

Primary navy anchors the header rule and footer emphasis. Ink carries report content; muted blue-gray distinguishes English titles and introductions. White paper sits over the pale canvas. Cool table headers and code surfaces organize dense content, while light dividers separate rows. The warm label accent marks scope and interactive focus; amber note surfaces carry explanatory context. Source and footer text use their own subdued blue-gray values. Palette values in frontmatter are normative.

## Typography

System sans-serif supports headings, prose and tables; system monospace distinguishes literal outputs and sources. Spanish titles lead, English translations follow. Table numerals are tabular. Headings retain native bold styling; no custom webfont or calculated type scale is present. Long source strings and output wrap without ellipsis.

## Layout

A single paper column is centered at a maximum width of 1440px. Page insets, cell padding, note padding and section rhythm use the extracted spacing values above. Tables occupy the full column. The header has a 5px navy rule and 18px top padding; source blocks start after 24px. Footer metadata uses a spaced horizontal flex row with a 15px gap.

At widths of 600px or less, page padding becomes 22px 16px, the main title 29px, translation 19px, and table, header-cell, output and label text 12px. Cells become 7px 5px and footer metadata stacks with a 4px gap. This is fallback source behavior for a desktop-oriented artifact.

## Elevation & Depth

No shadows, gradients, animation or lifted surfaces. Flat background changes and separator rules carry hierarchy. Link hover changes color; keyboard focus uses a 2px warm outline with a 3px offset. Selection uses the dedicated pale-blue surface and ink.

## Shapes

Square document surfaces, table cells, notes and output blocks. No border-radius declarations or rounded component tokens. Row and label separators are 1px; the footer divider is 2px. No decorative icon system.

## Components

- **Evidence heading and label:** Spanish title, English subtitle and a bold scope label between thin rules.
- **Evidence table:** tinted header, left-aligned columns, compact cells and tabular figures; long values wrap anywhere.
- **Literal output:** pale monospace block preserving whitespace while wrapping; exit status remains adjacent text.
- **Explanatory note:** restrained amber rectangle with ordinary body text and no alert icon.
- **Sources and footer:** small monospace source links, abbreviated hashes and visible offline / synthetic / Not product UI context. Native links have hover and keyboard-focus treatments.
- **Index:** an ordinary ordered list of evidence-page links; no app navigation shell, form fields or buttons are implemented.

## Do's and Don'ts

- Do keep ES/EN headings and the evidence-viewer / Not product UI labels visible.
- Do preserve literal logs, JSON and source links as factual evidence.
- Do retain the compact table rhythm and wrapping for long values.
- Don't present these screenshots as a functioning product interface.
- Don't add simulated terminals, generated evidence imagery or decorative dashboard controls.
- Don't imply automated visual validation that did not run.
