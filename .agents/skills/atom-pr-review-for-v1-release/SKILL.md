---
name: atom-pr-review-for-v1-release
description: Review or re-review absmach/atom pull requests for unresolved prior findings and verified v1.0 API, architecture, and domain/data-model release blockers, approve an explicitly authorized ready head, and report the result to a specified uvconsult.slack.com channel. Use for Atom v1.0 release PR reviews; do not use for style reviews, feature design, optimization, or broad codebase audits.
---

# ATOM PR Review For V1.0 Release

Review only the selected PR changes. Protect the existing v1.0 API, architecture, and domain/data-model contracts and release-blocking correctness and security without expanding the PR's scope.

## Inputs

- `prs`: one PR URL/number, a list, or `all`; default to all open, non-draft `absmach/atom` PRs.
- `channel`: required Slack channel in `uvconsult.slack.com` before sending a notification.
- `attention_person`: optional Slack person to mention when a blocker needs attention.
- `ready_person`: optional Slack person to mention when an approved PR is ready to merge.
- `approve_when_ready`: submit a GitHub approval only when the current request explicitly asks for it.

Infer a re-review when the request says `re-review`, asks to check previous comments, or the current head already has review activity. Names supplied in natural language, such as "mention Ian" and "if ready mention Dusan", map to `attention_person` and `ready_person` respectively; resolve both unambiguously and never guess.

## Review

- Confirm the repository is `absmach/atom`; read `AGENTS.md` and guidance relevant to changed areas.
- Inspect the PR description, full diff, tests, checks, review state, mergeability, and exact head commit.
- Review only defects introduced by the PR and their direct effects.
- Make v1.0 compatibility the primary question. Check GraphQL, gRPC/protobuf, HTTP, broker, configuration, persistence, and authentication/authorization behavior exposed by the changed path.
- Report a finding only when the changed code verifies a concrete:
  - correctness bug, data loss/corruption risk, build failure, or material regression;
  - authentication, authorization, tenant-isolation, injection, or secret-exposure defect;
  - break in an existing v1.0 GraphQL, gRPC/protobuf, HTTP, broker, configuration, or persistence contract; or
  - architecture or domain/data-model change that breaks existing v1.0 behavior, violates a documented boundary or invariant, corrupts data, or creates a security or tenant-isolation failure; or
  - violation of an invariant documented in `AGENTS.md`.
- Treat any incompatible removal, rename, type/nullability change, protobuf field-number reuse, route/status/response change, or changed authentication/authorization behavior as blocking unless compatibility is preserved.
- Verify the failing call path or scenario. Do not post uncertain, duplicate, pre-existing, or unrelated findings.
- Do not report nits, formatting, naming, style preferences, optional refactors, new features, speculative concerns, or performance optimizations.
- Do not request scope expansion or extra tests unless a verified bug or API break needs a regression test for the proposed fix.

## Architecture and model review

- Review architectural and domain/data-model changes only where the PR touches them; do not turn the review into a repository-wide redesign.
- Check that changed handler, service, repository, transaction, and dependency boundaries still follow the documented ownership and layering rules.
- Check migrations and model changes for compatible types, nullability, relationships, cardinality, lifecycle behavior, and safe handling of existing data.
- Check that changed authorization paths preserve the canonical grant expansion, scope and deny behavior, tenant isolation, and API-to-model semantics documented in `AGENTS.md`.
- Check that changed mutations preserve transaction, audit, outbox, connection-usage, and commit guarantees documented in `AGENTS.md`.
- Block only on a verified v1.0 compatibility failure, security/correctness defect, data risk, or documented invariant violation. Do not report architectural taste, optional consolidation, speculative future-proofing, or a preferred alternative design.

## Re-review prior activity

- Record the current head commit and inspect every existing review, inline thread, issue comment, and author reply before looking for new findings. Identify the head commit covered by the previous review when possible.
- Re-verify each prior actionable finding against the current code; an author's statement that it is fixed is not sufficient by itself.
- Classify each prior finding as `fixed`, `still blocking`, `obsolete`, or `needs user attention`.
- Resolve a review thread only when its exact finding is verified fixed or made obsolete by the current head. Never resolve an unfixed thread, a question or disagreement that needs human judgment, or a discussion unrelated to a verified finding.
- Do not create a duplicate comment for a still-open finding. Refer to the existing thread and add a reply only when new evidence materially changes the review.
- Surface every human reply, question, disagreement, or request that needs the user's judgment in the final response with its author, a short summary, and a direct link. Do not silently answer or dismiss it on the user's behalf.
- If a human comment could affect the approval decision, stop short of approval and bring it to the user's attention even when the code otherwise looks clean.

## Report blockers

- Leave a concise GitHub review comment on the narrowest relevant changed lines. State the failure scenario, user/API impact, and required compatibility behavior.
- Do not modify code or merge the PR unless the user's current request separately authorizes it.
- Send one short Slack message per PR that has unresolved verified blockers:
  - first line: optional resolved `attention_person` mention, PR link, and reviewed head commit;
  - one bullet per finding: severity, location, failure, and impact;
  - final line: `_Sent by ChatGPT using the atom-pr-review-for-v1-release skill._`
- Keep bullets direct and readable. Include only verified bugs, security defects, API breaks, and qualifying architecture or model breaks.
- Resolve the channel and supplied people in `uvconsult.slack.com`. If the workspace, channel, or person cannot be resolved, do not use another destination or omit a requested mention; report the notification failure.
- Read the sent Slack message back, verify its content and mention, and return its link.

## Approval and ready-for-merge notification

- A PR is ready only when every prior verified blocker is fixed or obsolete, there are no new qualifying findings, no human comment needs judgment, the reviewed head is unchanged, required checks pass, required review state and branch protection are satisfied, and the PR is conflict-free and mergeable.
- If `approve_when_ready` is authorized and the PR is ready, submit a GitHub `APPROVE` review on the exact reviewed head. Re-read the review state and verify the approval was recorded for that head.
- After verified approval, send one short message to `channel` mentioning `ready_person`: PR link, reviewed head commit, and "ready for merge". Read it back, verify the mention and content, and return its link.
- Do not announce readiness before the approval is verified. Do not approve when a prior blocker remains open merely because its thread was marked resolved.
- If approval was not explicitly authorized, report the PR as clean but do not approve it or send a ready-for-merge message.
- If checks, mergeability, permissions, repository access, or notification delivery prevent completion, report the exact blocker without inventing a code finding.
- Never merge the PR unless the current request separately authorizes merging. Before any authorized merge, repeat the ready checks against the unchanged reviewed head; never bypass protections or merge an unreviewed head.

## Return to the user

For each PR, report the reviewed head, prior-finding statuses, new blockers, human comments needing attention, GitHub approval status, and Slack message link. Put items needing the user's judgment first. Keep clean results concise.
