---
description: Create a Design Authority escalation request
---

Interactively gather escalation details:

1. Ask: "Which component/crate is this about?"
2. Ask: "Which spec section is relevant?"
3. Ask: "What is the specific question or ambiguity?"
4. Ask: "What options have you considered?"
5. Ask: "Is this blocking your work? (yes/no)"

Then create file `docs/decisions/pending/DA-XXXX.md` with:
```markdown
# DA-XXXX: Pending Escalation

**Date:** [today]
**Status:** PENDING
**Component:** [answer 1]
**Spec Section:** [answer 2]
**Blocking:** [answer 5]

## Question

[answer 3]

## Options Considered

[answer 4, formatted as numbered list]

## DA Decision

*Awaiting DA response*
```

Output: "Created docs/decisions/pending/DA-XXXX.md - Copy contents to DA project for resolution."