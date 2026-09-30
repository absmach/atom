(WITH RECURSIVE subject_groups(group_id, path) AS (
    SELECT gm.group_id, g.name
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.status = 'active' AND g.deleted_at IS NULL
    WHERE gm.entity_id = {subject}
    UNION ALL
    SELECT gh.parent_id, parent.name || ' -> ' || sg.path
    FROM group_hierarchy gh
    JOIN subject_groups sg ON sg.group_id = gh.child_id
    JOIN groups parent ON parent.id = gh.parent_id AND parent.status = 'active' AND parent.deleted_at IS NULL
)
SELECT dp.id AS assignment_id,
       pb.id AS block_id,
       NULL AS role_id,
       NULL AS role_name,
       CASE WHEN dp.subject_kind = 'entity' THEN 'direct' ELSE 'group:' || sg.path END AS via,
       dp.tenant_id AS tenant_boundary,
       pbs.scope_kind AS scope_kind,
       pbs.scope_ref AS scope_ref,
       pba.action_id AS capability_id,
       pb.effect AS effect,
       pb.conditions AS conditions
FROM direct_policies dp
JOIN permission_blocks pb ON pb.id = dp.permission_block_id
JOIN permission_block_scopes pbs ON pbs.permission_block_id = pb.id
JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
LEFT JOIN subject_groups sg ON dp.subject_kind = 'group' AND sg.group_id = dp.subject_id
WHERE (dp.subject_kind = 'entity' AND dp.subject_id = {subject})
   OR (dp.subject_kind = 'group' AND sg.group_id IS NOT NULL)
UNION ALL
SELECT ra.id,
       pb.id,
       ra.role_id,
       r.name,
       CASE WHEN ra.subject_kind = 'entity' THEN 'direct' ELSE 'group:' || sg.path END,
       ra.tenant_id,
       pbs.scope_kind,
       pbs.scope_ref,
       pba.action_id,
       pb.effect,
       pb.conditions
FROM role_assignments ra
JOIN roles r ON r.id = ra.role_id AND r.deleted_at IS NULL
JOIN role_permission_blocks rpb ON rpb.role_id = ra.role_id
JOIN permission_blocks pb ON pb.id = rpb.permission_block_id
JOIN permission_block_scopes pbs ON pbs.permission_block_id = pb.id
JOIN permission_block_actions pba ON pba.permission_block_id = pb.id
LEFT JOIN subject_groups sg ON ra.subject_kind = 'group' AND sg.group_id = ra.subject_id
WHERE (ra.subject_kind = 'entity' AND ra.subject_id = {subject})
   OR (ra.subject_kind = 'group' AND sg.group_id IS NOT NULL)
UNION ALL
SELECT unhex(md5('tenant_membership_assignment:' || atom_text(tm.tenant_id) || ':' || atom_text(tm.entity_id))),
       unhex(md5('tenant_membership_block:' || atom_text(tm.tenant_id) || ':' || atom_text(tm.entity_id))),
       NULL,
       NULL,
       'tenant_membership',
       tm.tenant_id,
       'object',
       atom_text(tm.tenant_id),
       a.id,
       'allow',
       '{}'
FROM tenant_memberships tm
JOIN entities e ON e.id = tm.entity_id
JOIN tenants t ON t.id = tm.tenant_id
JOIN actions a ON a.name = 'read'
WHERE tm.entity_id = {subject}
  AND tm.status = 'active'
  AND e.kind = 'human'
  AND e.status = 'active'
  AND e.deleted_at IS NULL
  AND t.status = 'active'
  AND t.deleted_at IS NULL)