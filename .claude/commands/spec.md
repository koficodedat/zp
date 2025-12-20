---
description: Look up zp specification sections by number or search term
argument-hint: <section-number or search-term>
---

Search docs/zp_specification_v1.0.md for the given input.

If input looks like a section number (e.g., "3.3.5", "4.2"):
- Find and return that exact section with full content
- Include subsections if the section has them

If input is a search term (e.g., "flow control", "KeyUpdate"):
- Search the entire spec for occurrences
- Return all matching sections with context
- Show section numbers for each match

Always include the section number and header in output.