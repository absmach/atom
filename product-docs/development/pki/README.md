# PKI Development Guide

This directory is the implementation source of truth for Atom-native multi-tenant PKI.

## Required reading order

1. `../../14-atom-native-multitenant-pki.md` — architecture and trust model
2. `../../15-pki-implementation-roadmap.md` — sequence and milestone gates
3. `AI-GUIDELINES.md` — rules for human and AI-assisted development
4. the selected `pr-XXX-*.md` specification
5. `TEST-PLAN.md`
6. `DEFINITION-OF-DONE.md`

## Working method

Implement one PR specification at a time. Do not combine adjacent delivery PRs merely because an AI agent can generate a larger diff. Small security-sensitive changes are easier to review, test, revert, and audit.

For every implementation:

1. confirm dependencies are merged;
2. inspect current code rather than relying on the roadmap's expected file list;
3. write or update tests before relaxing an invariant;
4. preserve legacy behavior until the relevant cutover PR;
5. update the PR specification when implementation discovers a necessary architectural correction;
6. run the complete Definition of Done.

## PR specification format

Each document defines:

- objective;
- dependencies;
- scope;
- non-goals;
- expected design;
- acceptance criteria;
- mandatory tests;
- rollback and compatibility expectations;
- an AI-agent execution prompt.

Acceptance criteria are contractual. A PR is incomplete when one criterion is deferred without updating the roadmap and obtaining review.

## Numbering

- PR-000 fixes defects in the live v1 certificate runtime and has no dependencies. It may land before or alongside PR-001.
- PR-001 is the authority registry foundation contained in PR #44. It carries outstanding required corrections; read its specification before building on it.
- PR-002 through PR-013 are follow-up delivery units.
- PR-014 and PR-015 cover subject enrollment and lifecycle automation. They are numbered after PR-013 but are **not** optional extras: the short-lifetime revocation strategy in the PRD does not work without them.
- PR-014b is specified but deliberately unscheduled. It is built on its stated trigger condition, not as a matter of course.
- Additional work discovered later must receive a new numbered specification; do not silently expand an existing PR beyond its security boundary.

## Security escalation

Stop implementation and request architectural review when a change would:

- make the root key available to Atom runtime;
- expose CA private material through an API;
- permit caller-selected issuers;
- weaken tenant isolation;
- change certificate identity semantics before resolver v2;
- delete issuer artifacts before dependent certificates expire, or delete an authority in a way that removes the certificates it issued;
- issue a certificate for a subject that is not an Atom entity;
- introduce a downstream product's concept into Atom's model;
- move Atom toward general secret management, arbitrary PKI-as-a-service, or public/WebPKI issuance;
- introduce a new cryptographic algorithm or ASN.1 implementation;
- bypass transactional event or audit behavior.