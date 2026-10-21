# PhantomGate-Lab report source

This package revises the original PhantomGate technical handover into a final-year-project design proposal for **AI-Assisted Penetration Testing for Controlled Authentication Assessment**.

The report contains 39 pages, 14 vector diagrams, 15 tables, a focused literature review, requirements, AI training and evaluation plans, reliability criteria, and appendices. It does not claim implementation of the proposed agent, trained models, completed experiments, institutional approval, or production readiness.

## Regenerate

With Python 3 and the packages in `requirements.txt`:

```bash
python -m pip install -r requirements.txt
python build_report.py --output-dir ..
```

In the repository, where this directory is stored as `reports/`:

```bash
python -m pip install -r reports/requirements.txt
python reports/build_report.py --output-dir .
```

The generator writes `PhantomGate-Project-Report.pdf`, `PhantomGate-Project-Report.md`, and `diagrams/*.svg`. Edit the generator's content blocks to change both the formatted PDF and Markdown consistently. Editing the generated Markdown alone does not update the PDF.

## Before academic submission

- Insert actual team, registration, university, department, degree, supervisor, and session details.
- Apply the institution's required template, approval text, and reference style.
- Add acknowledgements and obtain actual signatures.
- Replace the unmeasured-results section only after executing and documenting experiments.
- Extend the focused related-work review before asserting publication-level novelty.
- Attribute the original framework and identify student contributions accurately.

## Verification performed for this revision

- Reopened the generated PDF and confirmed 39 pages.
- Rendered every page with Poppler and inspected the page layouts.
- Checked figures, tables, page numbering, references, and SVG assets.
- No application, model, penetration-testing, or robustness acceptance tests were run as part of this documentation change.

Prepared: 21 October 2026. Original source baseline: `8ae8437a4900b03fbaf187ac98bbde6127687efa`.
