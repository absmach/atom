//! Storage snapshots used by shared bootstrap reconciliation.
mod postgres;
mod sqlite;
use super::*;

pub(super) async fn stamp_direct_policy(
    tx: &mut DbTransaction<'_>,
    policy_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_direct_policy(conn, policy_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_direct_policy(conn, policy_id, managed_by_config).await
        }
    }
}

pub(super) async fn direct_policy(
    tx: &mut DbTransaction<'_>,
    policy_id: Uuid,
) -> Result<DirectPolicyState, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::direct_policy(conn, policy_id).await,
        DbTransaction::Sqlite(conn) => sqlite::direct_policy(conn, policy_id).await,
    }
}

pub(super) async fn insert_direct_policy(
    tx: &mut DbTransaction<'_>,
    policy_id: Uuid,
    policy_tenant_id: Option<Uuid>,
    policy_subject_kind: &SubjectKind,
    policy_subject_id: Uuid,
    policy_permission_block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_direct_policy(
                conn,
                policy_id,
                policy_tenant_id,
                policy_subject_kind,
                policy_subject_id,
                policy_permission_block_id,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_direct_policy(
                conn,
                policy_id,
                policy_tenant_id,
                policy_subject_kind,
                policy_subject_id,
                policy_permission_block_id,
            )
            .await
        }
    }
}

pub(super) async fn stamp_assignment_rule(
    tx: &mut DbTransaction<'_>,
    id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_assignment_rule(conn, id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_assignment_rule(conn, id, managed_by_config).await
        }
    }
}

pub(super) async fn assignment_rule(
    tx: &mut DbTransaction<'_>,
    normalized_tenant_id: Option<Uuid>,
    normalized_entity_kind: &EntityKind,
    normalized_action_name: &str,
    normalized_object_kind: ObjectKind,
    normalized_object_type: &Option<String>,
) -> Result<Option<AssignmentRuleState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::assignment_rule(
                conn,
                normalized_tenant_id,
                normalized_entity_kind,
                normalized_action_name,
                normalized_object_kind,
                normalized_object_type,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::assignment_rule(
                conn,
                normalized_tenant_id,
                normalized_entity_kind,
                normalized_action_name,
                normalized_object_kind,
                normalized_object_type,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_assignment_rule(
    tx: &mut DbTransaction<'_>,
    normalized_tenant_id: Option<Uuid>,
    normalized_entity_kind: &EntityKind,
    normalized_action_name: &str,
    normalized_object_kind: ObjectKind,
    normalized_object_type: &Option<String>,
    normalized_decision: ActionAssignmentDecision,
    normalized_is_absolute: bool,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_assignment_rule(
                conn,
                normalized_tenant_id,
                normalized_entity_kind,
                normalized_action_name,
                normalized_object_kind,
                normalized_object_type,
                normalized_decision,
                normalized_is_absolute,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_assignment_rule(
                conn,
                normalized_tenant_id,
                normalized_entity_kind,
                normalized_action_name,
                normalized_object_kind,
                normalized_object_type,
                normalized_decision,
                normalized_is_absolute,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn stamp_applicability(
    tx: &mut DbTransaction<'_>,
    action_id: Uuid,
    app_object_kind_as_str__: &str,
    app_object_type: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_applicability(
                conn,
                action_id,
                app_object_kind_as_str__,
                app_object_type,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_applicability(
                conn,
                action_id,
                app_object_kind_as_str__,
                app_object_type,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn insert_applicability(
    tx: &mut DbTransaction<'_>,
    action_id: Uuid,
    app_object_kind_as_str__: &str,
    app_object_type: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_applicability(
                conn,
                action_id,
                app_object_kind_as_str__,
                app_object_type,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_applicability(
                conn,
                action_id,
                app_object_kind_as_str__,
                app_object_type,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn final_action_applicability(
    tx: &mut DbTransaction<'_>,
    action_id: Uuid,
) -> Result<Vec<ApplicabilityState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::final_action_applicability(conn, action_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::final_action_applicability(conn, action_id).await,
    }
}

pub(super) async fn action_applicability(
    tx: &mut DbTransaction<'_>,
    action_id: Uuid,
) -> Result<Vec<ApplicabilityState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::action_applicability(conn, action_id).await,
        DbTransaction::Sqlite(conn) => sqlite::action_applicability(conn, action_id).await,
    }
}

pub(super) async fn stamp_action(
    tx: &mut DbTransaction<'_>,
    action_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_action(conn, action_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_action(conn, action_id, managed_by_config).await
        }
    }
}

pub(super) async fn action(
    tx: &mut DbTransaction<'_>,
    name: &str,
) -> Result<ActionState, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::action(conn, name).await,
        DbTransaction::Sqlite(conn) => sqlite::action(conn, name).await,
    }
}

pub(super) async fn insert_action(
    tx: &mut DbTransaction<'_>,
    name: &str,
    capability_description: &Option<String>,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_action(conn, name, capability_description, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_action(conn, name, capability_description, managed_by_config).await
        }
    }
}

pub(super) async fn stamp_role_assignment(
    tx: &mut DbTransaction<'_>,
    assignment_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_role_assignment(conn, assignment_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_role_assignment(conn, assignment_id, managed_by_config).await
        }
    }
}

pub(super) async fn role_assignment(
    tx: &mut DbTransaction<'_>,
    assignment_id: Uuid,
) -> Result<RoleAssignmentState, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::role_assignment(conn, assignment_id).await,
        DbTransaction::Sqlite(conn) => sqlite::role_assignment(conn, assignment_id).await,
    }
}

pub(super) async fn insert_role_assignment(
    tx: &mut DbTransaction<'_>,
    assignment_id: Uuid,
    assignment_tenant_id: Option<Uuid>,
    assignment_subject_kind: &SubjectKind,
    assignment_subject_id: Uuid,
    assignment_role_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_role_assignment(
                conn,
                assignment_id,
                assignment_tenant_id,
                assignment_subject_kind,
                assignment_subject_id,
                assignment_role_id,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_role_assignment(
                conn,
                assignment_id,
                assignment_tenant_id,
                assignment_subject_kind,
                assignment_subject_id,
                assignment_role_id,
            )
            .await
        }
    }
}

pub(super) async fn stamp_role(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_role(conn, role_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => sqlite::stamp_role(conn, role_id, managed_by_config).await,
    }
}

pub(super) async fn link_role_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    block_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::link_role_block(conn, role_id, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::link_role_block(conn, role_id, block_id).await,
    }
}

pub(super) async fn block_tenant(
    tx: &mut DbTransaction<'_>,
    block_id: &Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::block_tenant(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::block_tenant(conn, block_id).await,
    }
}

pub(super) async fn persisted_role_tenant(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::persisted_role_tenant(conn, role_id).await,
        DbTransaction::Sqlite(conn) => sqlite::persisted_role_tenant(conn, role_id).await,
    }
}

pub(super) async fn role_blocks(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::role_blocks(conn, role_id).await,
        DbTransaction::Sqlite(conn) => sqlite::role_blocks(conn, role_id).await,
    }
}

pub(super) async fn role_matches(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    role_name: &str,
    role_tenant_id: Option<Uuid>,
    role_description: &Option<String>,
) -> Result<bool, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::role_matches(conn, role_id, role_name, role_tenant_id, role_description).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::role_matches(conn, role_id, role_name, role_tenant_id, role_description).await
        }
    }
}

pub(super) async fn insert_role(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    role_name: &str,
    role_tenant_id: Option<Uuid>,
    role_description: &Option<String>,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_role(conn, role_id, role_name, role_tenant_id, role_description).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_role(conn, role_id, role_name, role_tenant_id, role_description).await
        }
    }
}

pub(super) async fn role_tenant(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::role_tenant(conn, role_id).await,
        DbTransaction::Sqlite(conn) => sqlite::role_tenant(conn, role_id).await,
    }
}

pub(super) async fn stamp_permission_block(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_permission_block(conn, block_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_permission_block(conn, block_id, managed_by_config).await
        }
    }
}

pub(super) async fn link_block_action(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
    action_id: &Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::link_block_action(conn, block_id, action_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::link_block_action(conn, block_id, action_id).await,
    }
}

pub(super) async fn stored_block_actions(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::stored_block_actions(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::stored_block_actions(conn, block_id).await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn permission_block_matches(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
    scope_tenant_id: Option<Uuid>,
    scope_mode_as_str__: &str,
    scope_object_kind: &Option<String>,
    scope_object_type: &Option<String>,
    scope_object_id: Option<Uuid>,
    scope_group_id: Option<Uuid>,
    block_effect: &Effect,
    conditions: &Value,
) -> Result<bool, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::permission_block_matches(
                conn,
                block_id,
                scope_tenant_id,
                scope_mode_as_str__,
                scope_object_kind,
                scope_object_type,
                scope_object_id,
                scope_group_id,
                block_effect,
                conditions,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::permission_block_matches(
                conn,
                block_id,
                scope_tenant_id,
                scope_mode_as_str__,
                scope_object_kind,
                scope_object_type,
                scope_object_id,
                scope_group_id,
                block_effect,
                conditions,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_permission_block(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
    scope_tenant_id: Option<Uuid>,
    scope_mode_as_str__: &str,
    scope_object_kind: &Option<String>,
    scope_object_type: &Option<String>,
    scope_object_id: Option<Uuid>,
    scope_group_id: Option<Uuid>,
    block_effect: &Effect,
    conditions: &Value,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_permission_block(
                conn,
                block_id,
                scope_tenant_id,
                scope_mode_as_str__,
                scope_object_kind,
                scope_object_type,
                scope_object_id,
                scope_group_id,
                block_effect,
                conditions,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_permission_block(
                conn,
                block_id,
                scope_tenant_id,
                scope_mode_as_str__,
                scope_object_kind,
                scope_object_type,
                scope_object_id,
                scope_group_id,
                block_effect,
                conditions,
            )
            .await
        }
    }
}

pub(super) async fn block_actions(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::block_actions(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::block_actions(conn, block_id).await,
    }
}

pub(super) async fn permission_block(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
) -> Result<Option<PermissionBlockState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::permission_block(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::permission_block(conn, block_id).await,
    }
}

pub(super) async fn action_id(
    tx: &mut DbTransaction<'_>,
    action_name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::action_id(conn, action_name).await,
        DbTransaction::Sqlite(conn) => sqlite::action_id(conn, action_name).await,
    }
}

pub(super) async fn hierarchy_has_cycle(
    tx: &mut DbTransaction<'_>,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::hierarchy_has_cycle(conn, parent_id, child_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::hierarchy_has_cycle(conn, parent_id, child_id).await,
    }
}

pub(super) async fn lock_parent_groups(
    tx: &mut DbTransaction<'_>,
    group_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_parent_groups(conn, group_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_parent_groups(conn, group_ids).await,
    }
}

pub(super) async fn parent_relation(
    tx: &mut DbTransaction<'_>,
    child_id: Uuid,
    parent_id: Uuid,
) -> Result<Option<ParentRelation>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::parent_relation(conn, child_id, parent_id).await,
        DbTransaction::Sqlite(conn) => sqlite::parent_relation(conn, child_id, parent_id).await,
    }
}

pub(super) async fn stamp_object_group(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_object_group(conn, group_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_object_group(conn, group_id, managed_by_config).await
        }
    }
}

pub(super) async fn object_group_parent(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::object_group_parent(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::object_group_parent(conn, group_id).await,
    }
}

pub(super) async fn object_group_resources(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::object_group_resources(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::object_group_resources(conn, group_id).await,
    }
}

pub(super) async fn object_group_entities(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::object_group_entities(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::object_group_entities(conn, group_id).await,
    }
}

pub(super) async fn object_group_matches(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::object_group_matches(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::object_group_matches(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
    }
}

pub(super) async fn insert_object_group(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_object_group(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_object_group(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
    }
}

pub(super) async fn object_resource_tenants(
    tx: &mut DbTransaction<'_>,
    resource_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::object_resource_tenants(conn, resource_ids).await
        }
        DbTransaction::Sqlite(conn) => sqlite::object_resource_tenants(conn, resource_ids).await,
    }
}

pub(super) async fn object_entity_tenants(
    tx: &mut DbTransaction<'_>,
    entity_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::object_entity_tenants(conn, entity_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::object_entity_tenants(conn, entity_ids).await,
    }
}

pub(super) async fn object_group_tenants(
    tx: &mut DbTransaction<'_>,
    group_ids: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::object_group_tenants(conn, group_ids).await,
        DbTransaction::Sqlite(conn) => sqlite::object_group_tenants(conn, group_ids).await,
    }
}

pub(super) async fn stamp_resource(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_resource(conn, resource_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_resource(conn, resource_id, managed_by_config).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn resource_matches(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    resource_kind: &str,
    resource_name: &Option<String>,
    alias: &Option<String>,
    resource_tenant_id: Option<Uuid>,
    resource_owner_id: Option<Uuid>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::resource_matches(
                conn,
                resource_id,
                resource_kind,
                resource_name,
                alias,
                resource_tenant_id,
                resource_owner_id,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::resource_matches(
                conn,
                resource_id,
                resource_kind,
                resource_name,
                alias,
                resource_tenant_id,
                resource_owner_id,
                attributes,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_resource(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
    resource_kind: &str,
    resource_name: &Option<String>,
    alias: &Option<String>,
    resource_tenant_id: Option<Uuid>,
    resource_owner_id: Option<Uuid>,
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_resource(
                conn,
                resource_id,
                resource_kind,
                resource_name,
                alias,
                resource_tenant_id,
                resource_owner_id,
                attributes,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_resource(
                conn,
                resource_id,
                resource_kind,
                resource_name,
                alias,
                resource_tenant_id,
                resource_owner_id,
                attributes,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn resource_tenant(
    tx: &mut DbTransaction<'_>,
    resource_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::resource_tenant(conn, resource_id).await,
        DbTransaction::Sqlite(conn) => sqlite::resource_tenant(conn, resource_id).await,
    }
}

pub(super) async fn member_entity_tenants(
    tx: &mut DbTransaction<'_>,
    group_members: &[Uuid],
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::member_entity_tenants(conn, group_members).await,
        DbTransaction::Sqlite(conn) => sqlite::member_entity_tenants(conn, group_members).await,
    }
}

pub(super) async fn principal_group_tenants(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Vec<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::principal_group_tenants(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::principal_group_tenants(conn, group_id).await,
    }
}

pub(super) async fn stamp_group(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_group(conn, group_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => sqlite::stamp_group(conn, group_id, managed_by_config).await,
    }
}

pub(super) async fn group_members(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::group_members(conn, group_id).await,
        DbTransaction::Sqlite(conn) => sqlite::group_members(conn, group_id).await,
    }
}

pub(super) async fn group_matches(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::group_matches(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::group_matches(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
    }
}

pub(super) async fn insert_group(
    tx: &mut DbTransaction<'_>,
    group_id: Uuid,
    group_name: &str,
    group_tenant_id: Option<Uuid>,
    group_description: &Option<String>,
    attributes: &Value,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_group(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_group(
                conn,
                group_id,
                group_name,
                group_tenant_id,
                group_description,
                attributes,
            )
            .await
        }
    }
}

pub(super) async fn stamp_access_token(
    tx: &mut DbTransaction<'_>,
    cred_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_access_token(conn, cred_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_access_token(conn, cred_id, managed_by_config).await
        }
    }
}

pub(super) async fn access_token_state(
    tx: &mut DbTransaction<'_>,
    cred_id: Uuid,
) -> Result<AccessTokenState, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::access_token_state(conn, cred_id).await,
        DbTransaction::Sqlite(conn) => sqlite::access_token_state(conn, cred_id).await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_access_token(
    tx: &mut DbTransaction<'_>,
    cred_id: Uuid,
    entity_id: Uuid,
    credential_kind: CredentialKind,
    identifier: &str,
    secret_hash: Option<String>,
    secret_lookup_hash: Option<Vec<u8>>,
    metadata: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_access_token(
                conn,
                cred_id,
                entity_id,
                credential_kind,
                identifier,
                secret_hash,
                secret_lookup_hash,
                metadata,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_access_token(
                conn,
                cred_id,
                entity_id,
                credential_kind,
                identifier,
                secret_hash,
                secret_lookup_hash,
                metadata,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn stamp_credential(
    tx: &mut DbTransaction<'_>,
    credential_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_credential(conn, credential_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_credential(conn, credential_id, managed_by_config).await
        }
    }
}

pub(super) async fn shared_key_credentials(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    credential_kind: CredentialKind,
) -> Result<Vec<SharedKeyState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::shared_key_credentials(conn, entity_id, credential_kind).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::shared_key_credentials(conn, entity_id, credential_kind).await
        }
    }
}

pub(super) async fn password_credentials(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    credential_kind: CredentialKind,
) -> Result<Vec<PasswordState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::password_credentials(conn, entity_id, credential_kind).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::password_credentials(conn, entity_id, credential_kind).await
        }
    }
}

pub(super) async fn stamp_entity(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_entity(conn, entity_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_entity(conn, entity_id, managed_by_config).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn entity_state(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    entity_kind: &EntityKind,
    entity_name: &str,
    alias: &Option<String>,
    entity_tenant_id: Option<Uuid>,
    entity_status: &EntityStatus,
    attributes: &Value,
) -> Result<Option<EntityState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::entity_state(
                conn,
                entity_id,
                entity_kind,
                entity_name,
                alias,
                entity_tenant_id,
                entity_status,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::entity_state(
                conn,
                entity_id,
                entity_kind,
                entity_name,
                alias,
                entity_tenant_id,
                entity_status,
                attributes,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_entity(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
    entity_kind: &EntityKind,
    entity_name: &str,
    alias: &Option<String>,
    entity_tenant_id: Option<Uuid>,
    entity_status: &EntityStatus,
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_entity(
                conn,
                entity_id,
                entity_kind,
                entity_name,
                alias,
                entity_tenant_id,
                entity_status,
                attributes,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_entity(
                conn,
                entity_id,
                entity_kind,
                entity_name,
                alias,
                entity_tenant_id,
                entity_status,
                attributes,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn entity_tenant(
    tx: &mut DbTransaction<'_>,
    entity_id: Uuid,
) -> Result<Option<Option<Uuid>>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::entity_tenant(conn, entity_id).await,
        DbTransaction::Sqlite(conn) => sqlite::entity_tenant(conn, entity_id).await,
    }
}

pub(super) async fn stamp_tenant(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::stamp_tenant(conn, tenant_id, managed_by_config).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::stamp_tenant(conn, tenant_id, managed_by_config).await
        }
    }
}

pub(super) async fn tenant_matches(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    tenant_name: &str,
    alias: &Option<String>,
    tenant_status: &TenantStatus,
    tenant_tags: &[String],
    attributes: &Value,
) -> Result<Option<bool>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::tenant_matches(
                conn,
                tenant_id,
                tenant_name,
                alias,
                tenant_status,
                tenant_tags,
                attributes,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::tenant_matches(
                conn,
                tenant_id,
                tenant_name,
                alias,
                tenant_status,
                tenant_tags,
                attributes,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn insert_tenant(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
    tenant_name: &str,
    alias: &Option<String>,
    tenant_status: &TenantStatus,
    tenant_tags: &[String],
    attributes: &Value,
    managed_by_config: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::insert_tenant(
                conn,
                tenant_id,
                tenant_name,
                alias,
                tenant_status,
                tenant_tags,
                attributes,
                managed_by_config,
            )
            .await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::insert_tenant(
                conn,
                tenant_id,
                tenant_name,
                alias,
                tenant_status,
                tenant_tags,
                attributes,
                managed_by_config,
            )
            .await
        }
    }
}

pub(super) async fn purge_orphan_admin_block(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::purge_orphan_admin_block(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::purge_orphan_admin_block(conn, block_id).await,
    }
}

pub(super) async fn unlink_admin_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    block_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::unlink_admin_block(conn, role_id, block_id).await
        }
        DbTransaction::Sqlite(conn) => sqlite::unlink_admin_block(conn, role_id, block_id).await,
    }
}

pub(super) async fn link_admin_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
    replacement_id: Uuid,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::link_admin_block(conn, role_id, replacement_id).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::link_admin_block(conn, role_id, replacement_id).await
        }
    }
}

pub(super) async fn link_admin_actions(
    tx: &mut DbTransaction<'_>,
    replacement_id: Uuid,
    desired_capabilities: &[String],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::link_admin_actions(conn, replacement_id, desired_capabilities).await
        }
        DbTransaction::Sqlite(conn) => {
            sqlite::link_admin_actions(conn, replacement_id, desired_capabilities).await
        }
    }
}

pub(super) async fn insert_admin_block(
    tx: &mut DbTransaction<'_>,
    tenant_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_admin_block(conn, tenant_id).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_admin_block(conn, tenant_id).await,
    }
}

pub(super) async fn block_action_names(
    tx: &mut DbTransaction<'_>,
    block_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::block_action_names(conn, block_id).await,
        DbTransaction::Sqlite(conn) => sqlite::block_action_names(conn, block_id).await,
    }
}

pub(super) async fn admin_block(
    tx: &mut DbTransaction<'_>,
    role_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::admin_block(conn, role_id).await,
        DbTransaction::Sqlite(conn) => sqlite::admin_block(conn, role_id).await,
    }
}

pub(super) async fn admin_roles(
    tx: &mut DbTransaction<'_>,
) -> Result<Vec<AdminRoleState>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::admin_roles(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::admin_roles(conn).await,
    }
}

pub(super) async fn insert_default_actions(
    tx: &mut DbTransaction<'_>,
    capabilities: &[String],
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::insert_default_actions(conn, capabilities).await,
        DbTransaction::Sqlite(conn) => sqlite::insert_default_actions(conn, capabilities).await,
    }
}

pub(super) async fn clear_default_actions(tx: &mut DbTransaction<'_>) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::clear_default_actions(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::clear_default_actions(conn).await,
    }
}

pub(super) async fn missing_default_actions(
    tx: &mut DbTransaction<'_>,
    capabilities: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => {
            postgres::missing_default_actions(conn, capabilities).await
        }
        DbTransaction::Sqlite(conn) => sqlite::missing_default_actions(conn, capabilities).await,
    }
}

pub(super) async fn entity_ids(tx: &mut DbTransaction<'_>) -> Result<Vec<Uuid>, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::entity_ids(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::entity_ids(conn).await,
    }
}

pub(super) async fn lock_configuration_tables(
    tx: &mut DbTransaction<'_>,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_configuration_tables(conn).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_configuration_tables(conn).await,
    }
}

pub(super) async fn lock_bootstrap(
    tx: &mut DbTransaction<'_>,
    lock_key: &str,
) -> Result<u64, sqlx::Error> {
    match tx {
        DbTransaction::Postgres(conn) => postgres::lock_bootstrap(conn, lock_key).await,
        DbTransaction::Sqlite(conn) => sqlite::lock_bootstrap(conn, lock_key).await,
    }
}
