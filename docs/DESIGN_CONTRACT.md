# Design contract: Policy Forge

The transferable design rules for this site. Graders and repair workers read this file; it
contains no private preferences or credentials.

## Character

A **structured policy and evidence desk**. A review is a case file on a desk: ivory sheets on an
oat surface, a folder with tabs for findings, inventory, policies, rule tests, exceptions and
remediation, and every claim carrying a citation to the exact file and line it came from.

The one bold element is the **coverage tally**, borrowed from the tick marks auditors put on
working papers. It opens every run: one mark per evaluated check, grouped by rule pack, with a
plain sentence above it. A passed check is a tick, a failed check a cross in a filled box, a check
that could not be evaluated a hatched box with a question mark, an excepted check a dashed stamp,
and every resource no rule evaluated an empty dashed box at the end of the row. What was not
evaluated is drawn as visibly as what failed, so partial coverage can never be read as a clean
result. Everything else is quiet paper.

Distinct from the siblings: Quant Foundry is a serif research note with red-pen strikes on a light
masthead; Data Refinery is a gridded workbench with a wide grotesk, a monospace for every value and a
dark housing band. Policy Forge has no grid, no dark band and no serif: a darker oat desk, raised ivory
sheets, folder tabs, a humanist sans built for legibility and a matching monospace used only for
configuration text.

## Process record

| Directive stage | Playbook steps | Done here |
|---|---|---|
| 1 Discovery | 1 brief, 3 direction | Character given by the brief; direction delegated and chosen above |
| 2 Content | 2 audience and content | Audience: cloud security and platform engineers, technical reviewers. Their questions: what failed and where exactly, what could not be evaluated, is a patch safe, which exceptions are still valid, how good are the rules' own tests. Primary action: open a finding and read its evidence at the cited line |
| 3 Staging | 4 references, 5 design plan, 6 assets | No external visual references adopted (the named motion reference could not be verified). Tokens below. No imagery: configuration is the material |
| 4 Component adaptation | 7 architecture | Hand-built tally, evidence viewer and diff, no chart or UI library; the engineering kit (data loading, states, routing, embedding, e2e harness) is shared with the siblings, the visual layer is not |
| (build) | 8 build and debug | Verified in a browser before any fix is claimed |
| 5 Batch polish | 9, 10 | One coordinated batch after first review; one restrained treatment per flat section |
| 6 Mobile pass | 11 | Deliberate 390 px composition below |
| 7 Browser evidence | 12 | Playwright at 390 / 768 / 1440 in CI and on the live site; screenshots read by a person |
| 8 Deployment | 13 | GitHub Pages from Actions; live URL verified |

Skills invoked for this design: `website-playbook`, `frontend-design:frontend-design`, `ui-ux-pro-max`
(design system "Accessible & Ethical" kept for its rules: 4.5:1 text, visible 3 px focus, 44 px touch
targets, reduced motion; its security-blue palette and IBM Plex Sans rejected, the first because the
brief sets a warm palette, the second because it is the generic enterprise default and too close to a
sibling's Plex Condensed).

## Tokens

| Token | Light | Dark | Role |
|---|---|---|---|
| desk | #E8D7BF | #1E1814 | page canvas |
| paper | #FFF6E8 | #2A221D | sheets, panels, tabs |
| paper-2 | #F6EAD7 | #231C18 | code gutters, table heads, inputs |
| ink | #29201B | #FFF6E8 | primary text |
| ink-2 | #5E5248 | #CDBBA6 | secondary text (5.4:1 on desk, 7.1:1 on paper) |
| rule | #D8C6AC | #3A2F28 | hairlines, decorative only |
| edge | #826F57 | #7D6A59 | control and tab boundaries (3.4:1 on desk, 4.5:1 on paper) |
| action | #5A171B, ivory text | #E8D7BF, charcoal text | primary buttons, active tab marker |
| fail | #8E3520 text, #A6422A fill | #E58C73 | failed checks |
| pass | #545537 text, #646548 fill | #B9BC8C | passed checks |
| unknown | #6F520F text, hatch #7A5A12 | #E0B862 | checks that could not be evaluated |
| excepted | #5A171B dashed outline | #E8D7BF dashed outline | checks covered by a valid exception |
| uncovered | edge-coloured dashed empty box | same | resources no rule evaluated |
| focus | 3 px ink outline + 2 px paper offset | same | keyboard focus |

Status always pairs a mark (tick, cross, question mark, E, empty box) or a word with colour, never
colour alone. Text pairs are >= 4.5:1 and boundaries >= 3:1 on both desk and paper (checked with a
contrast script).

## Type

- **Atkinson Hyperlegible Next** (variable weight): wordmark 800, headings 700 with -0.01em
  tracking, UI and body 400/500 at 16 px / 1.55. Chosen for unambiguous letterforms (1 l I, 0 O),
  which matter when people read resource names, CIDRs and rule ids.
- **Atkinson Hyperlegible Mono**: configuration excerpts, file paths, line numbers, resource and rule
  ids. Never used for labels or counts; counts use the sans with tabular figures.
- Scale (px): 13, 14, 16, 19, 24, 32, 44. Sentence case; no all-caps labels, no eyebrows, no
  middle-dot meta strings, no arrows on links.

## Layout

- Desktop 1440: the desk header (wordmark, run picker showing snapshot and as-of date, links to Runs,
  Request a run, About); the coverage sheet (statement, tally, legend); then the folder: a row of six
  tabs with counts, attached to one sheet. Findings is a two-column sheet: resources with their
  failed checks on the left, the evidence viewer (rule, cited source excerpt with line numbers and the
  cited line marked, exception, patch) sticky on the right.
- Tablet 768: tabs stay in one row with shorter labels; the evidence viewer becomes a sheet that
  slides up from the bottom.
- Mobile 390: the run picker drops below the wordmark at full width; the tally wraps into rows per
  pack; the six tabs form a 3 x 2 grid; tables become cards; the evidence viewer is a full-height sheet
  with a close button; diffs switch from side-by-side to unified.
- Left aligned. Radius 4 px on controls, 8 px on sheets, tabs rounded on top only. Sheets have a 1 px
  edge and one soft desk shadow; nothing else has a shadow.

## Motion (durations in ms)

| Moment | Treatment | Duration |
|---|---|---|
| Run load (once) | tally marks are set in order, pack by pack (scale from 0.6 and fade) | 12 per mark, 600 max total |
| Tab change | the active tab rises 2 px and joins the sheet; sheet content slides 16 px in the tab direction and fades | 220 in, 140 out |
| Evidence open / close | viewer slides from the right (desktop) or bottom (sheet); the cited line band fades in after the excerpt | 220 / 160; band 180 |
| Before / after toggle | changed lines cross-fade; added and removed lines keep +/- markers | 200 |
| Run change | tally marks re-set; counts update without animation | as run load |
| Expand / collapse | rule details and rejected-patch reasons open with a height transition | 200 open, 140 close |
| Controls | press scale 0.98; tab and chip state changes 120 | 120 |

Easing: decelerate on arrival, accelerate on exit. Reduced motion: all durations 0, tally rendered
complete. Nothing essential waits for animation; no scroll hijacking, no intro, no perpetual motion,
no hover-only controls (each tally mark carries a text label for assistive technology, each pack's counts are
written beside its marks, and every result is listed in the Findings tab, so nothing depends on pointing at a mark).

## Language rules

The site never says "compliant", "compliance achieved", "secure" or "all clear". The headline is a
count-only sentence (checks failed, checks that could not be evaluated, resources no rule evaluated),
always naming what was not evaluated alongside what failed; the engine's own coverage statement from
`summary.json` follows it verbatim. The site computes no verdict of its own.

## States

loading (skeleton shaped like the sheet), empty (no runs yet + how to request one), error (which file
failed, Retry), stale (snapshot older than 14 days: banner with age + Refresh), fixture notice,
success; per tab: no findings for this filter, no exceptions, remediation not requested for this run,
patch rejected (with its reason).
