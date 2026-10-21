# PhantomGate-AI FYP report - revision 3.0

Prepared 22 October 2026. This revision keeps the reverse proxy central and replaces the old next-action agent with an embedded, observational diagnostic assistant.

## Read in this order

1. `PhantomGate-Project-Report.pdf`: complete 43-page FYP design and handover.
2. `docs/AI_HANDOVER.md`: implementation scope, code mapping, contracts and milestones.
3. `PROJECT_SPEC.json`: machine-readable labels, interfaces, defaults and acceptance criteria.
4. Actual code snapshot and repository instructions: verify existing behavior before editing.

The PDF includes abstract, problem statement, proposed solution, literature review, candidate gap, architecture and data-flow diagrams, use/misuse cases, technical implementation, model training, evaluation, market-value hypothesis, conclusion, future work and AI implementation handover. There are 14 diagrams, 18 tables and 9 references. New runtime modules, model training and experiments remain proposed.

## Regenerate

From the repository/package root:

```bash
python -m pip install -r reports/requirements.txt
python reports/build_report.py --output-dir .
```

The generator writes the PDF, Markdown and `diagrams/*.svg`. Edit its content blocks to keep the PDF and Markdown in sync. It does not generate the handover or JSON specification; update those when changing the design.

## Checks performed for this revision

- Reopened the PDF, checked page count and bookmarks.
- Rendered all pages with Poppler and visually inspected layout, diagrams and tables.
- Checked Markdown figure targets, XML validity of SVGs, JSON syntax and handover consistency.
- Rechecked source symbols at the pinned code baseline and reviewed primary literature records.
- No proxy runtime, training, penetration-testing or robustness experiments were run in this documentation revision.

## Submission requirements

University template, team/registration details, supervisor, session, real approval signatures and acknowledgements were not supplied. Complete these before submission. The market section is qualitative and contains no invented market-size or revenue figures. Novelty is a candidate to validate, not a guaranteed claim. Replace unmeasured-result wording only with actual experimental evidence.
