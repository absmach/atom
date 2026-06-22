-- The initial seed (001) declared the publish/subscribe/execute actions but
-- never their applicability, so:
--   * permission blocks / roles granting publish or subscribe on
--     resource:channel were rejected at write time, and
--   * execute on a rule resource was rejected, and
--   * none of these actions could ever be authorized at runtime
--     (the PDP resolves action ids through action_applicability).
--
-- publish/subscribe apply to channels; execute applies to rules.
INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'resource', 'resource:channel'
FROM actions
WHERE name IN ('publish', 'subscribe')
ON CONFLICT DO NOTHING;

INSERT INTO action_applicability (action_id, object_kind, object_type)
SELECT id, 'resource', 'resource:rule'
FROM actions
WHERE name = 'execute'
ON CONFLICT DO NOTHING;
