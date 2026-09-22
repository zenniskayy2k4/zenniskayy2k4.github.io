# Adding vulnerability research

Research records are Markdown documents in `_research/`. The Portfolio and Research pages read this collection automatically, so adding a CVE does not require editing HTML or Liquid templates.

## Add a zero-day discovery

Create a file such as `_research/cve-2026-12345-product.md`:

```markdown
---
order: 4
cve: CVE-2026-12345
product: Product name
kind: 0-day
classification: 0-day research
severity: High · CVSS 8.8
severity_level: high
featured: false
impact: Concise vulnerability class or demonstrated impact
summary: One recruiter-readable sentence describing the security boundary and impact.
evidence_url: https://example.com/public-advisory
link_label: Read advisory
---

Add the technical detail shown on the Research page here. Markdown such as `code identifiers` and links is supported.
```

## Add a reproduction or technical analysis

Use `kind: reproduction`, `classification: Reproduction & technical analysis`, and wording that clearly avoids claiming a zero-day discovery.

## Field reference

- `order`: display order within its group.
- `cve`: CVE identifier shown in the interface.
- `kind`: `0-day` or `reproduction`. The Portfolio and Research templates use this value to group records.
- `severity_level`: `critical`, `high`, `moderate`, `low`, or `analysis`; this controls the restrained badge treatment.
- `featured`: optional; use only for the most important zero-day finding.
- `impact`: short heading for the finding.
- `summary`: one concise sentence shown on both Portfolio and Research.
- Markdown body: supporting detail shown on Research.
- `evidence_url` and `link_label`: public evidence destination and accessible action text. Use `evidence_url` because Jekyll reserves `url` for the collection document path.

Run `bundle exec jekyll build` after adding a record. The build validates front matter and renders the entry into both pages.
