-- Resources were never made applicable to the read/write/delete actions in the
-- initial seed (001), only to manage/role.manage/policy.manage. As a result the
-- authorization-filtered resource listing (action = read) matched no rows and the
-- admin UI showed "No resources found" even when resources existed.
--
-- Backfill the missing applicability so read/write/delete apply to resources.
INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'resource', NULL
FROM actions
WHERE name IN ('read', 'write', 'delete')
ON CONFLICT DO NOTHING;
