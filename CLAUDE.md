# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Nature of this repository

This is a **planning and research repository**, not a software project. It currently
contains no source code, no build system, no tests, and no dependency manifests —
only prose and reference PDFs. There are no build, lint, or test commands to run.

Contents:
- `README.md` — the primary artifact: the project charter, outline, task list, and
  notes from the founding Twitter Space discussion.
- `FlowRepositoryAPI.pdf` — reference material on the FlowRepository API, relevant to
  the "Data Integrity" workstream (see below). Scanned/image-based; not machine-readable text.
- `CostOfAcademicFraud.pdf` — supporting reference on the motivation for the project.

When asked to "implement" something here, expect to be **scaffolding a new codebase
from scratch** (a proof-of-concept per the outline below) rather than editing existing
code. Confirm the intended language/stack with the user before creating one, since none
is established yet.

## Project scope (the two workstreams)

The project — "Scientific Data Integrity" — pursues on-chain (Cardano) integrity
guarantees for science along two independent tracks described in `README.md`:

1. **Data Integrity** — hash scientific data at the point of acquisition and anchor the
   hashes on-chain (envisioned as NFTs), so published results can be verified without
   trusting the publisher. The concrete near-term target is **flow cytometry data via
   FlowRepository** (hence `FlowRepositoryAPI.pdf`) and FlowJo/BD as partners. The
   first requested deliverable is a **proof-of-concept for data hashing**.

2. **Reagent Integrity** — establish chain-of-custody and QC provenance for lab
   reagents, starting with the highest-stakes domain (medical testing). Involves
   aggregating QC documents into a common structure, integrating with manufacturing
   step-verification, and using PRISM identities for reagent tracking.

Keep changes aligned to whichever workstream the task names; they do not share
infrastructure yet.

## Working conventions

- The README is authored in a specific Markdown style: nested ordered lists using
  `1.`/`2.` sub-numbering and GitHub task-list checkboxes (`* [ ]`). Match this style
  when editing it, and update the `### Tasks` checklist when a task's status changes.
- Do not fabricate technical detail about FlowRepository's API or the referenced PDFs;
  they are scanned images and cannot be read as text here. Ask the user or fetch the
  live FlowRepository API docs if API specifics are needed.
