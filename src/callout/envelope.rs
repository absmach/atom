//! Wire-shape envelope shared by HTTP and gRPC transports.
//!
//! Field selection ("include") walks the envelope JSON with dot-paths rooted
//! at `actor.*`, `args.*`, `extra.*`, etc., and produces a new JSON tree
//! containing only the whitelisted subtrees. A hard denylist strips keys named
//! `secret`, `password`, or `key` at any depth, as a safety net independent of
//! the config file.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::config::OperationConfig;
use super::Surface;

/// Hard denylist — these key names are stripped from the payload after
/// include-filtering, regardless of whether the config asked for them. Applied
/// at any depth (deep matching), so a nested `credentials.secret` is also
/// removed. Match is case-insensitive.
///
/// Deliberately conservative: the goal is "impossible to accidentally leak the
/// obvious secret fields", not "a general redaction policy".
pub const DENYLIST_KEYS: &[&str] = &["secret", "password", "key"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub entity_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub tenant_id: String,
    /// "session" for JWT/cookie auth, "access_token" for API-key auth, "" otherwise.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub scope: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source_ip: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub user_agent: String,
}

impl Actor {
    pub fn from_auth(auth: &crate::auth::AuthContext) -> Self {
        Self {
            entity_id: auth.entity_id.to_string(),
            tenant_id: auth.tenant_id.map(|t| t.to_string()).unwrap_or_default(),
            scope: if auth.credential_id.is_some() {
                "access_token".to_string()
            } else if auth.session_id.is_some() {
                "session".to_string()
            } else {
                String::new()
            },
            credential_id: auth
                .credential_id
                .map(|c| c.to_string())
                .unwrap_or_default(),
            source_ip: String::new(),
            user_agent: String::new(),
        }
    }
}

/// Canonical callout envelope — the shape sent to HTTP as JSON and translated
/// to `atom.v1.CalloutRequest` for gRPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalloutRequest {
    pub operation: String,
    pub surface: String,
    pub request_id: String,
    /// RFC-3339 UTC.
    pub time: String,
    pub actor: Actor,
    /// Filtered args (per operation `include:`).
    #[serde(default)]
    pub args: Value,
    /// Static extras merged from operation config.
    #[serde(default)]
    pub extra: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalloutResponse {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl CalloutResponse {
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            reason: String::new(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
        }
    }
}

/// Build the envelope for a given operation invocation.
///
/// `raw_args` is the resolver/method args serialized to JSON (an Object).
/// `actor` is the authenticated caller. The include-list from `op` selects
/// which of `actor.*` / `args.*` / `extra.*` subtrees are kept.
pub fn build(
    op: &OperationConfig,
    surface: Surface,
    actor: Actor,
    raw_args: Value,
    now: chrono::DateTime<chrono::Utc>,
) -> CalloutRequest {
    let extra_val = if op.extra.is_empty() {
        Value::Null
    } else {
        let mut m = Map::new();
        for (k, v) in &op.extra {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    };

    // Build the full envelope, then filter.
    let full_actor = serde_json::to_value(&actor).unwrap_or(Value::Null);
    let full = Value::Object({
        let mut m = Map::new();
        m.insert("actor".into(), full_actor);
        m.insert("args".into(), raw_args);
        m.insert("extra".into(), extra_val);
        m
    });

    let filtered = if op.include.is_empty() {
        // Empty include => omit actor/args entirely. `extra` is always included
        // (it's a static config-controlled payload).
        let mut m = Map::new();
        m.insert("extra".into(), full["extra"].clone());
        Value::Object(m)
    } else {
        // `extra` is a static config-controlled payload — always included,
        // independent of the whitelist. The whitelist selects from
        // `actor.*` / `args.*`.
        let mut selected = select_paths(&full, &op.include);
        if let Value::Object(m) = &mut selected {
            m.insert("extra".into(), full["extra"].clone());
        }
        selected
    };

    let redacted = strip_denylisted(filtered);

    // Extract back out into typed fields for the envelope.
    let (actor_out, args_out, extra_out) = split_envelope(redacted, &actor);

    CalloutRequest {
        operation: op.name.clone(),
        surface: surface.as_str().to_string(),
        request_id: Uuid::new_v4().to_string(),
        time: now.to_rfc3339(),
        actor: actor_out,
        args: args_out,
        extra: extra_out,
    }
}

fn split_envelope(mut v: Value, default_actor: &Actor) -> (Actor, Value, Value) {
    let actor = v
        .as_object_mut()
        .and_then(|m| m.remove("actor"))
        .and_then(|a| serde_json::from_value::<Actor>(a).ok())
        .unwrap_or_else(|| {
            // If the include-list excluded actor entirely, propagate an empty
            // Actor rather than the un-filtered caller. That mirrors "you get
            // what you asked for and nothing else."
            let _ = default_actor;
            Actor::default()
        });
    let args = v
        .as_object_mut()
        .and_then(|m| m.remove("args"))
        .unwrap_or(Value::Null);
    let extra = v
        .as_object_mut()
        .and_then(|m| m.remove("extra"))
        .unwrap_or(Value::Null);
    (actor, args, extra)
}

/// Recursively strip denylisted key names (case-insensitive) at any depth.
pub fn strip_denylisted(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            m.retain(|k, _| {
                let lower = k.to_ascii_lowercase();
                !DENYLIST_KEYS.iter().any(|d| *d == lower)
            });
            for (_k, v) in m.iter_mut() {
                let taken = std::mem::replace(v, Value::Null);
                *v = strip_denylisted(taken);
            }
            Value::Object(m)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(strip_denylisted).collect()),
        other => other,
    }
}

/// Select a subset of `source` matching any of the dot-paths. Missing paths
/// are silently skipped (they simply don't appear in the output).
pub fn select_paths(source: &Value, paths: &[String]) -> Value {
    let mut out = Value::Object(Map::new());
    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        if let Some(val) = walk(source, &segments) {
            insert_at(&mut out, &segments, val.clone());
        }
    }
    out
}

fn walk<'a>(v: &'a Value, segments: &[&str]) -> Option<&'a Value> {
    let mut current = v;
    for seg in segments {
        match current {
            Value::Object(m) => {
                current = m.get(*seg)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn insert_at(target: &mut Value, segments: &[&str], value: Value) {
    if segments.is_empty() {
        return;
    }
    let (last, prefix) = segments.split_last().expect("non-empty");
    let mut current = target;
    for seg in prefix {
        let obj = current
            .as_object_mut()
            .expect("select target must be object");
        let entry = obj
            .entry((*seg).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            // A conflict between a leaf and a deeper path — the deeper path
            // wins (overwrites the earlier leaf). Keeps the include list
            // order-independent for realistic inputs.
            *entry = Value::Object(Map::new());
        }
        current = entry;
    }
    if let Some(obj) = current.as_object_mut() {
        obj.insert((*last).to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callout::config::{OperationConfig, SurfaceKind};
    use serde_json::json;

    fn op(include: &[&str], extra: serde_json::Value) -> OperationConfig {
        let extra_map = extra
            .as_object()
            .map(|m| m.clone().into_iter().collect())
            .unwrap_or_default();
        OperationConfig {
            name: "createEntity".to_string(),
            surface: SurfaceKind::Graphql,
            endpoints: vec![],
            include: include.iter().map(|s| s.to_string()).collect(),
            extra: extra_map,
        }
    }

    #[test]
    fn empty_include_omits_actor_and_args() {
        let cfg = op(&[], json!({}));
        let actor = Actor {
            entity_id: "abc".into(),
            ..Default::default()
        };
        let req = build(
            &cfg,
            Surface::GraphQL,
            actor,
            json!({"input": {"name": "x"}}),
            chrono::Utc::now(),
        );
        assert_eq!(req.actor, Actor::default());
        assert!(req.args.is_null() || req.args.as_object().is_some_and(|m| m.is_empty()));
    }

    #[test]
    fn include_selects_subtree_only() {
        let cfg = op(&["actor.entity_id", "args.input.name"], json!({}));
        let actor = Actor {
            entity_id: "abc".into(),
            tenant_id: "tenant-1".into(),
            ..Default::default()
        };
        let req = build(
            &cfg,
            Surface::GraphQL,
            actor,
            json!({"input": {"name": "gadget", "kind": "device"}}),
            chrono::Utc::now(),
        );
        assert_eq!(req.actor.entity_id, "abc");
        // Tenant not in include list.
        assert!(req.actor.tenant_id.is_empty());
        assert_eq!(req.args, json!({"input": {"name": "gadget"}}));
    }

    #[test]
    fn denylist_strips_secret_at_any_depth() {
        let cfg = op(&["args.input.name", "args.input.credentials"], json!({}));
        let req = build(
            &cfg,
            Surface::GraphQL,
            Actor::default(),
            json!({
                "input": {
                    "name": "gadget",
                    "credentials": [
                        {"kind": "password", "secret": "hunter2"},
                        {"kind": "shared_key", "key": "abcd"}
                    ]
                }
            }),
            chrono::Utc::now(),
        );
        // Secret and key removed, kind kept.
        let creds = &req.args["input"]["credentials"];
        assert_eq!(creds[0]["kind"], "password");
        assert!(creds[0].get("secret").is_none());
        assert_eq!(creds[1]["kind"], "shared_key");
        assert!(creds[1].get("key").is_none());
    }

    #[test]
    fn extra_is_merged_and_static() {
        let cfg = op(
            &["actor.entity_id"],
            json!({"entity_type": "entity", "v": 1}),
        );
        let req = build(
            &cfg,
            Surface::GraphQL,
            Actor {
                entity_id: "abc".into(),
                ..Default::default()
            },
            json!({}),
            chrono::Utc::now(),
        );
        assert_eq!(req.extra["entity_type"], "entity");
        assert_eq!(req.extra["v"], 1);
    }

    #[test]
    fn missing_include_path_is_silently_skipped() {
        let cfg = op(&["actor.entity_id", "args.does.not.exist"], json!({}));
        let req = build(
            &cfg,
            Surface::GraphQL,
            Actor {
                entity_id: "abc".into(),
                ..Default::default()
            },
            json!({}),
            chrono::Utc::now(),
        );
        assert_eq!(req.actor.entity_id, "abc");
        assert!(req.args.is_null() || req.args.as_object().is_some_and(|m| m.is_empty()));
    }
}
