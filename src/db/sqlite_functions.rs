//! SQL functions registered on every SQLite connection.
//!
//! PostgreSQL provides these as built-ins or as functions in the baseline
//! schema; SQLite has neither, so the same semantics are implemented here in
//! Rust and installed through the SQLite C API (sqlx has no scalar-function
//! hook). Deterministic functions are flagged so they are legal in `CHECK`
//! constraints and indexes.

use std::{
    ffi::{c_int, c_void, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
};

use chrono::{DateTime, SecondsFormat, Utc};
use libsqlite3_sys as ffi;
use md5::{Digest as _, Md5};
use serde_json::Value;
use sqlx::SqliteConnection;
use uuid::Uuid;

/// An argument as SQLite hands it to a function.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    Null,
    Int(i64),
    Real(f64),
    Text(&'a str),
    Blob(&'a [u8]),
}

/// A function result.
#[derive(Debug)]
pub enum Ret {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<bool> for Ret {
    fn from(b: bool) -> Self {
        Ret::Int(i64::from(b))
    }
}

impl From<Option<bool>> for Ret {
    fn from(b: Option<bool>) -> Self {
        b.map_or(Ret::Null, Ret::from)
    }
}

type ScalarFn = fn(&[Arg<'_>]) -> Result<Ret, String>;

struct Spec {
    name: &'static str,
    args: c_int,
    deterministic: bool,
    func: ScalarFn,
}

const FUNCTIONS: &[Spec] = &[
    Spec {
        name: "now",
        args: 0,
        deterministic: false,
        func: f_now,
    },
    Spec {
        name: "gen_random_uuid",
        args: 0,
        deterministic: false,
        func: f_gen_random_uuid,
    },
    Spec {
        name: "atom_text",
        args: 1,
        deterministic: true,
        func: f_text,
    },
    Spec {
        name: "atom_ts_diff",
        args: 2,
        deterministic: true,
        func: f_ts_diff,
    },
    Spec {
        name: "atom_ts_epoch",
        args: 1,
        deterministic: true,
        func: f_ts_epoch,
    },
    Spec {
        name: "atom_ts_floor",
        args: 2,
        deterministic: true,
        func: f_ts_floor,
    },
    Spec {
        name: "atom_interval_secs",
        args: 1,
        deterministic: true,
        func: f_interval_secs,
    },
    Spec {
        name: "repeat",
        args: 2,
        deterministic: true,
        func: f_repeat,
    },
    Spec {
        name: "atom_uuid",
        args: 1,
        deterministic: true,
        func: f_uuid,
    },
    Spec {
        name: "atom_timestamp",
        args: 1,
        deterministic: true,
        func: f_timestamp,
    },
    Spec {
        name: "atom_ts_add",
        args: 2,
        deterministic: true,
        func: f_ts_add,
    },
    Spec {
        name: "atom_json_merge",
        args: 2,
        deterministic: true,
        func: f_json_merge,
    },
    Spec {
        name: "atom_json_remove",
        args: 2,
        deterministic: true,
        func: f_json_remove,
    },
    Spec {
        name: "atom_json_eq",
        args: 2,
        deterministic: true,
        func: f_json_eq,
    },
    Spec {
        name: "atom_json_subset",
        args: 2,
        deterministic: true,
        func: f_json_subset,
    },
    Spec {
        name: "atom_json_contains",
        args: 2,
        deterministic: true,
        func: f_json_contains,
    },
    Spec {
        name: "atom_pki_valid_san_policy",
        args: 1,
        deterministic: true,
        func: f_valid_san_policy,
    },
    Spec {
        name: "atom_pki_san_rule_is_subset",
        args: 2,
        deterministic: true,
        func: f_san_rule_is_subset,
    },
    Spec {
        name: "atom_sha256_hex",
        args: 1,
        deterministic: true,
        func: f_sha256_hex,
    },
    Spec {
        name: "md5",
        args: 1,
        deterministic: true,
        func: f_md5,
    },
    Spec {
        name: "atom_uuid_list",
        args: 1,
        deterministic: true,
        func: f_uuid_list,
    },
    Spec {
        name: "grant_scope_matches",
        args: 8,
        deterministic: true,
        func: f_grant_scope_matches,
    },
];

/// Installs every function on `conn`.
pub async fn register(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let mut handle = conn.lock_handle().await?;
    let db = handle.as_raw_handle().as_ptr();
    for spec in FUNCTIONS {
        let name = CString::new(spec.name).expect("function names have no NUL");
        let mut flags = ffi::SQLITE_UTF8 | ffi::SQLITE_INNOCUOUS;
        if spec.deterministic {
            flags |= ffi::SQLITE_DETERMINISTIC;
        }
        let user_data = Box::into_raw(Box::new(spec.func)).cast::<c_void>();
        // SAFETY: `db` is a live connection guarded by the locked handle; the
        // boxed function pointer is owned by SQLite and freed by `destroy`.
        let rc = unsafe {
            ffi::sqlite3_create_function_v2(
                db,
                name.as_ptr(),
                spec.args,
                flags,
                user_data,
                Some(trampoline),
                None,
                None,
                Some(destroy),
            )
        };
        if rc != ffi::SQLITE_OK {
            return Err(sqlx::Error::Protocol(format!(
                "failed to register SQLite function {} (code {rc})",
                spec.name
            )));
        }
    }
    Ok(())
}

unsafe extern "C" fn destroy(user_data: *mut c_void) {
    drop(Box::from_raw(user_data.cast::<ScalarFn>()));
}

unsafe extern "C" fn trampoline(
    ctx: *mut ffi::sqlite3_context,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    let func = *ffi::sqlite3_user_data(ctx).cast::<ScalarFn>();
    let raw = if argc > 0 {
        slice::from_raw_parts(argv, argc as usize)
    } else {
        &[]
    };
    let args: Vec<Arg<'_>> = raw.iter().map(|v| read_arg(*v)).collect();
    match catch_unwind(AssertUnwindSafe(|| func(&args))) {
        Ok(Ok(ret)) => set_result(ctx, ret),
        Ok(Err(message)) => set_error(ctx, &message),
        Err(_) => set_error(ctx, "internal error in SQL function"),
    }
}

unsafe fn read_arg<'a>(value: *mut ffi::sqlite3_value) -> Arg<'a> {
    match ffi::sqlite3_value_type(value) {
        ffi::SQLITE_INTEGER => Arg::Int(ffi::sqlite3_value_int64(value)),
        ffi::SQLITE_FLOAT => Arg::Real(ffi::sqlite3_value_double(value)),
        ffi::SQLITE_TEXT => {
            let ptr = ffi::sqlite3_value_text(value);
            let len = ffi::sqlite3_value_bytes(value) as usize;
            if ptr.is_null() {
                return Arg::Null;
            }
            match std::str::from_utf8(slice::from_raw_parts(ptr, len)) {
                Ok(s) => Arg::Text(s),
                Err(_) => Arg::Null,
            }
        }
        ffi::SQLITE_BLOB => {
            let ptr = ffi::sqlite3_value_blob(value);
            let len = ffi::sqlite3_value_bytes(value) as usize;
            if ptr.is_null() {
                Arg::Blob(&[])
            } else {
                Arg::Blob(slice::from_raw_parts(ptr.cast::<u8>(), len))
            }
        }
        _ => Arg::Null,
    }
}

unsafe fn set_result(ctx: *mut ffi::sqlite3_context, ret: Ret) {
    match ret {
        Ret::Null => ffi::sqlite3_result_null(ctx),
        Ret::Int(i) => ffi::sqlite3_result_int64(ctx, i),
        Ret::Real(r) => ffi::sqlite3_result_double(ctx, r),
        Ret::Text(s) => ffi::sqlite3_result_text(
            ctx,
            s.as_ptr().cast(),
            s.len() as c_int,
            ffi::SQLITE_TRANSIENT(),
        ),
        Ret::Blob(b) => ffi::sqlite3_result_blob(
            ctx,
            b.as_ptr().cast(),
            b.len() as c_int,
            ffi::SQLITE_TRANSIENT(),
        ),
    }
}

unsafe fn set_error(ctx: *mut ffi::sqlite3_context, message: &str) {
    ffi::sqlite3_result_error(ctx, message.as_ptr().cast(), message.len() as c_int);
}

// ---------------------------------------------------------------- helpers

/// Fixed-width timestamp text used for every stored timestamp.
pub fn format_timestamp(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Canonical text of a value that may be a UUID blob.
fn text_of(arg: &Arg<'_>) -> Option<String> {
    match arg {
        Arg::Null => None,
        Arg::Text(s) => Some((*s).to_owned()),
        Arg::Blob(b) => match Uuid::from_slice(b) {
            Ok(u) => Some(u.hyphenated().to_string()),
            Err(_) => Some(String::from_utf8_lossy(b).into_owned()),
        },
        Arg::Int(i) => Some(i.to_string()),
        Arg::Real(r) => Some(r.to_string()),
    }
}

fn json_of(arg: &Arg<'_>) -> Option<Value> {
    match arg {
        Arg::Text(s) => serde_json::from_str(s).ok(),
        _ => None,
    }
}

/// A list of UUIDs from JSON text (`["…"]`, hyphenated or simple) or the
/// PostgreSQL empty-array literal `{}`.
fn uuid_list_of(arg: &Arg<'_>) -> Option<Vec<Uuid>> {
    match arg {
        Arg::Null => None,
        Arg::Text(s) if s.trim() == "{}" || s.trim().is_empty() => Some(Vec::new()),
        Arg::Text(s) => match serde_json::from_str::<Value>(s).ok()? {
            Value::Array(items) => items
                .iter()
                .map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect(),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------- functions

fn f_now(_: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(Ret::Text(format_timestamp(Utc::now())))
}

fn f_gen_random_uuid(_: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(Ret::Blob(Uuid::new_v4().as_bytes().to_vec()))
}

fn f_text(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(text_of(&args[0]).map_or(Ret::Null, Ret::Text))
}

/// `text::uuid`: hyphenated or simple text becomes the 16-byte form; a value
/// that already is one passes through.
fn f_uuid(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match &args[0] {
        Arg::Blob(b) if b.len() == 16 => Ret::Blob(b.to_vec()),
        Arg::Text(s) => {
            Uuid::parse_str(s.trim()).map_or(Ret::Null, |u| Ret::Blob(u.as_bytes().to_vec()))
        }
        _ => Ret::Null,
    })
}

fn f_timestamp(args: &[Arg<'_>]) -> Result<Ret, String> {
    let Arg::Text(s) = args[0] else {
        return Ok(Ret::Null);
    };
    Ok(parse_timestamp(s).map_or(Ret::Null, |t| Ret::Text(format_timestamp(t))))
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .or_else(|_| DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%#z"))
        .map(|t| t.with_timezone(&Utc))
        .ok()
}

/// `EXTRACT(epoch FROM (a - b))`: the seconds between two timestamps.
fn f_ts_diff(args: &[Arg<'_>]) -> Result<Ret, String> {
    let (Arg::Text(a), Arg::Text(b)) = (args[0], args[1]) else {
        return Ok(Ret::Null);
    };
    Ok(match (parse_timestamp(a), parse_timestamp(b)) {
        (Some(a), Some(b)) => Ret::Real(
            (a - b)
                .num_microseconds()
                .map_or(f64::NAN, |us| us as f64 / 1e6),
        ),
        _ => Ret::Null,
    })
}

/// `EXTRACT(epoch FROM ts)`.
fn f_ts_epoch(args: &[Arg<'_>]) -> Result<Ret, String> {
    let Arg::Text(ts) = args[0] else {
        return Ok(Ret::Null);
    };
    Ok(parse_timestamp(ts).map_or(Ret::Null, |t| Ret::Real(t.timestamp_micros() as f64 / 1e6)))
}

/// The start of the `seconds`-wide window containing `ts` (epoch-aligned).
fn f_ts_floor(args: &[Arg<'_>]) -> Result<Ret, String> {
    let (Arg::Text(ts), Some(width)) = (
        args[0],
        match args[1] {
            Arg::Int(i) => Some(i as f64),
            Arg::Real(r) => Some(r),
            _ => None,
        },
    ) else {
        return Ok(Ret::Null);
    };
    let Some(t) = parse_timestamp(ts) else {
        return Ok(Ret::Null);
    };
    if width <= 0.0 {
        return Ok(Ret::Null);
    }
    let epoch = t.timestamp() as f64;
    let floored = (epoch / width).floor() * width;
    Ok(DateTime::<Utc>::from_timestamp(floored as i64, 0)
        .map_or(Ret::Null, |t| Ret::Text(format_timestamp(t))))
}

/// Seconds in a PostgreSQL interval literal such as `'3 days'` or
/// `'1 hour 30 minutes'`.
fn f_interval_secs(args: &[Arg<'_>]) -> Result<Ret, String> {
    let Arg::Text(text) = args[0] else {
        return Ok(Ret::Null);
    };
    let mut total = 0.0;
    let mut words = text.split_whitespace();
    while let Some(amount) = words.next() {
        let amount: f64 = amount
            .parse()
            .map_err(|_| format!("invalid interval: {text}"))?;
        let unit = words
            .next()
            .ok_or_else(|| format!("invalid interval: {text}"))?
            .to_ascii_lowercase();
        let per = match unit.trim_end_matches('s') {
            "second" | "sec" => 1.0,
            "minute" | "min" => 60.0,
            "hour" => 3600.0,
            "day" => 86_400.0,
            "week" => 604_800.0,
            _ => return Err(format!("unsupported interval unit: {unit}")),
        };
        total += amount * per;
    }
    Ok(Ret::Real(total))
}

/// `repeat(text, n)`.
fn f_repeat(args: &[Arg<'_>]) -> Result<Ret, String> {
    match (args[0], args[1]) {
        (Arg::Text(s), Arg::Int(n)) if n >= 0 => Ok(Ret::Text(s.repeat(n as usize))),
        _ => Ok(Ret::Null),
    }
}

/// `timestamp ± interval`, with the interval given as seconds.
fn f_ts_add(args: &[Arg<'_>]) -> Result<Ret, String> {
    let Arg::Text(ts) = args[0] else {
        return Ok(Ret::Null);
    };
    let seconds = match args[1] {
        Arg::Int(i) => i as f64,
        Arg::Real(r) => r,
        Arg::Text(t) => t.parse::<f64>().map_err(|e| e.to_string())?,
        _ => return Ok(Ret::Null),
    };
    let Some(base) = parse_timestamp(ts) else {
        return Ok(Ret::Null);
    };
    let delta = chrono::Duration::microseconds((seconds * 1_000_000.0).round() as i64);
    Ok(base
        .checked_add_signed(delta)
        .map_or(Ret::Null, |t| Ret::Text(format_timestamp(t))))
}

/// jsonb `a || b`: the top-level keys of `b` replace those of `a` (nulls kept).
fn f_json_merge(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match (json_of(&args[0]), json_of(&args[1])) {
        (Some(Value::Object(mut a)), Some(Value::Object(b))) => {
            a.extend(b);
            Ret::Text(Value::Object(a).to_string())
        }
        _ => Ret::Null,
    })
}

/// jsonb `a - 'key'`.
fn f_json_remove(args: &[Arg<'_>]) -> Result<Ret, String> {
    let (Some(Value::Object(mut a)), Arg::Text(key)) = (json_of(&args[0]), args[1]) else {
        return Ok(Ret::Null);
    };
    a.remove(key);
    Ok(Ret::Text(Value::Object(a).to_string()))
}

fn f_json_eq(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match (json_of(&args[0]), json_of(&args[1])) {
        (Some(a), Some(b)) => Ret::from(a == b),
        _ => Ret::Null,
    })
}

/// `a <@ b` for arrays of scalars.
fn f_json_subset(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match (json_of(&args[0]), json_of(&args[1])) {
        (Some(Value::Array(a)), Some(Value::Array(b))) => {
            Ret::from(a.iter().all(|x| b.contains(x)))
        }
        _ => Ret::Null,
    })
}

/// jsonb `a @> b`.
fn f_json_contains(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match (json_of(&args[0]), json_of(&args[1])) {
        (Some(a), Some(b)) => Ret::from(json_contains(&a, &b)),
        _ => Ret::Null,
    })
}

pub fn json_contains(container: &Value, contained: &Value) -> bool {
    match (container, contained) {
        (Value::Object(a), Value::Object(b)) => b
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|av| json_contains(av, v))),
        (Value::Array(a), Value::Array(b)) => {
            b.iter().all(|bv| a.iter().any(|av| json_contains(av, bv)))
        }
        // A primitive on the right is contained by an array holding it.
        (Value::Array(a), primitive) if !primitive.is_object() && !primitive.is_array() => {
            a.contains(primitive)
        }
        (a, b) => a == b,
    }
}

fn mode_of(rule: &Value) -> Option<&str> {
    rule.get("mode").and_then(Value::as_str)
}

fn san_rule_is_subset(child: &Value, ceiling: &Value) -> bool {
    let (child_mode, ceiling_mode) = (mode_of(child), mode_of(ceiling));
    match ceiling_mode {
        Some("deny") => child_mode == Some("deny"),
        Some("identity") => child_mode == Some("identity"),
        Some(mode @ ("allowlist" | "entity_template")) => {
            child_mode == Some("deny")
                || (child_mode == Some(mode)
                    && match (ceiling.get("values"), child.get("values")) {
                        (Some(c), Some(v)) => json_contains(c, v),
                        _ => false,
                    })
        }
        _ => false,
    }
}

fn f_san_rule_is_subset(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(Ret::from(match (json_of(&args[0]), json_of(&args[1])) {
        (Some(child), Some(ceiling)) => san_rule_is_subset(&child, &ceiling),
        _ => false,
    }))
}

fn valid_san_policy(policy: &Value) -> bool {
    const TYPES: [&str; 4] = ["dns", "ip", "email", "uri"];
    let Some(obj) = policy.as_object() else {
        return false;
    };
    if obj.len() != TYPES.len() || !TYPES.iter().all(|t| obj.contains_key(*t)) {
        return false;
    }
    TYPES.iter().all(|san_type| {
        let rule = &obj[*san_type];
        let Some(rule_obj) = rule.as_object() else {
            return false;
        };
        if rule_obj.len() != 2 || !rule_obj.contains_key("mode") || !rule_obj.contains_key("values")
        {
            return false;
        }
        let Some(values) = rule_obj["values"].as_array() else {
            return false;
        };
        let Some(mode) = rule_obj["mode"].as_str() else {
            return false;
        };
        match *san_type {
            "dns" => matches!(mode, "deny" | "allowlist" | "entity_template"),
            "ip" | "email" => matches!(mode, "deny" | "allowlist"),
            _ => mode == "identity" && values.is_empty(),
        }
    })
}

fn f_valid_san_policy(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(Ret::from(
        json_of(&args[0]).is_some_and(|p| valid_san_policy(&p)),
    ))
}

fn f_sha256_hex(args: &[Arg<'_>]) -> Result<Ret, String> {
    let bytes: &[u8] = match &args[0] {
        Arg::Blob(b) => b,
        Arg::Text(s) => s.as_bytes(),
        _ => return Ok(Ret::Null),
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    Ok(Ret::Text(hex::encode(digest.as_ref())))
}

fn f_md5(args: &[Arg<'_>]) -> Result<Ret, String> {
    let owned;
    let bytes: &[u8] = match &args[0] {
        Arg::Blob(b) => b,
        Arg::Text(s) => s.as_bytes(),
        Arg::Null => return Ok(Ret::Null),
        other => {
            owned = text_of(other).unwrap_or_default();
            owned.as_bytes()
        }
    };
    Ok(Ret::Text(hex::encode(Md5::digest(bytes))))
}

/// Normalises a UUID array argument to a JSON array of 32-hex simple strings.
fn f_uuid_list(args: &[Arg<'_>]) -> Result<Ret, String> {
    Ok(match uuid_list_of(&args[0]) {
        Some(list) => Ret::Text(
            serde_json::to_string(
                &list
                    .iter()
                    .map(|u| u.simple().to_string())
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| e.to_string())?,
        ),
        None => Ret::Null,
    })
}

// Three-valued logic so NULL inputs behave exactly as the PostgreSQL
// `grant_scope_matches` SQL function does.
fn and3(a: Option<bool>, b: impl FnOnce() -> Option<bool>) -> Option<bool> {
    match a {
        Some(false) => Some(false),
        Some(true) => b(),
        None => match b() {
            Some(false) => Some(false),
            _ => None,
        },
    }
}

fn or3(a: Option<bool>, b: impl FnOnce() -> Option<bool>) -> Option<bool> {
    match a {
        Some(true) => Some(true),
        Some(false) => b(),
        None => match b() {
            Some(true) => Some(true),
            _ => None,
        },
    }
}

fn eq3(a: Option<&str>, b: Option<&str>) -> Option<bool> {
    Some(a? == b?)
}

fn in3(needle: Option<Uuid>, haystack: &Option<Vec<Uuid>>) -> Option<bool> {
    let list = haystack.as_ref()?;
    let needle = needle?;
    Some(list.contains(&needle))
}

fn split_part(s: &str, n: usize) -> &str {
    s.split(':').nth(n - 1).unwrap_or("")
}

fn f_grant_scope_matches(args: &[Arg<'_>]) -> Result<Ret, String> {
    let scope_kind = text_of(&args[0]);
    let scope_ref = text_of(&args[1]);
    let coarse = text_of(&args[2]);
    let sub = text_of(&args[3]);
    let object_id = text_of(&args[4]);
    let object_tenant = text_of(&args[5]);
    let parents = uuid_list_of(&args[6]);
    let ancestors = uuid_list_of(&args[7]);

    let sr = scope_ref.as_deref();
    let object_type = match (coarse.as_deref(), sub.as_deref()) {
        (Some(c), Some(s)) => Some(format!("{c}:{s}")),
        _ => None,
    };
    let tail = sr.map(|r| r.split_once(':').map_or(r, |(_, rest)| rest));
    let head_uuid = sr.and_then(|r| Uuid::parse_str(split_part(r, 1)).ok());
    let second_is_group = sr.map(|r| split_part(r, 2) == "group");

    let result: Option<bool> = match scope_kind.as_deref() {
        Some("platform") => Some(true),
        Some("tenant") => match object_tenant.as_deref() {
            None => Some(false),
            Some(tenant) => eq3(sr, Some(tenant)),
        },
        Some("object_kind") => eq3(sr, coarse.as_deref()),
        Some("object_type") => eq3(sr, object_type.as_deref()),
        Some("object") => eq3(sr, object_id.as_deref()),
        Some("group_object_type") => and3(eq3(tail, object_type.as_deref()), || {
            in3(head_uuid, &parents)
        }),
        Some("group_tree_object_type") => and3(eq3(tail, object_type.as_deref()), || {
            in3(head_uuid, &ancestors)
        }),
        Some("group_child_kind") => and3(coarse.as_deref().map(|c| c == "group"), || {
            and3(second_is_group, || in3(head_uuid, &parents))
        }),
        Some("group_descendant_kind") => and3(coarse.as_deref().map(|c| c == "group"), || {
            and3(second_is_group, || {
                or3(in3(head_uuid, &parents), || in3(head_uuid, &ancestors))
            })
        }),
        _ => Some(false),
    };
    Ok(Ret::from(result))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sqlx::Row;

    use super::*;
    use crate::db::sqlite;

    async fn scalar(sql: &str) -> Option<String> {
        let cfg = crate::config::DbPoolConfig::default();
        let db = sqlite::connect("sqlite::memory:", &cfg).await.unwrap();
        let row = sqlx::query(sql).fetch_one(&db.pool).await.unwrap();
        row.try_get::<Option<String>, _>(0).unwrap()
    }

    #[test]
    fn json_containment_matches_jsonb_semantics() {
        assert!(json_contains(&json!(["a", "b"]), &json!(["a"])));
        assert!(!json_contains(&json!(["a"]), &json!(["a", "b"])));
        assert!(json_contains(&json!({"a": 1, "b": 2}), &json!({"a": 1})));
        assert!(json_contains(&json!(["a"]), &json!("a")));
        assert!(!json_contains(&json!({"a": 1}), &json!({"a": 2})));
    }

    #[test]
    fn san_policy_validation() {
        let ok = json!({
            "dns": {"mode": "deny", "values": []},
            "ip": {"mode": "deny", "values": []},
            "email": {"mode": "allowlist", "values": ["a@example.com"]},
            "uri": {"mode": "identity", "values": []},
        });
        assert!(valid_san_policy(&ok));
        let mut bad = ok.clone();
        bad["uri"] = json!({"mode": "allowlist", "values": []});
        assert!(!valid_san_policy(&bad));
        let mut extra = ok.clone();
        extra["other"] = json!({});
        assert!(!valid_san_policy(&extra));
    }

    #[test]
    fn json_merge_and_remove_follow_jsonb_operators() {
        let merged = f_json_merge(&[
            Arg::Text(r#"{"a":1,"b":2}"#),
            Arg::Text(r#"{"b":null,"c":3}"#),
        ])
        .unwrap();
        let Ret::Text(text) = merged else {
            panic!("expected text")
        };
        assert_eq!(text, r#"{"a":1,"b":null,"c":3}"#);
        let removed = f_json_remove(&[Arg::Text(r#"{"a":1,"b":2}"#), Arg::Text("a")]).unwrap();
        let Ret::Text(text) = removed else {
            panic!("expected text")
        };
        assert_eq!(text, r#"{"b":2}"#);
    }

    #[test]
    fn san_rule_subset() {
        let deny = json!({"mode": "deny", "values": []});
        let allow = json!({"mode": "allowlist", "values": ["a", "b"]});
        let narrower = json!({"mode": "allowlist", "values": ["a"]});
        assert!(san_rule_is_subset(&deny, &allow));
        assert!(san_rule_is_subset(&narrower, &allow));
        assert!(!san_rule_is_subset(&allow, &narrower));
        assert!(!san_rule_is_subset(&allow, &deny));
    }

    #[tokio::test]
    async fn sql_surface_behaves_like_postgres() {
        assert_eq!(
            scalar("SELECT atom_text(x'00000000000000000000000000000001')")
                .await
                .as_deref(),
            Some("00000000-0000-0000-0000-000000000001")
        );
        assert_eq!(
            scalar("SELECT md5('abc')").await.as_deref(),
            Some("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            scalar("SELECT atom_sha256_hex(x'616263')").await.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            scalar("SELECT atom_ts_add('2026-01-02T03:04:05.000000Z', -3600)")
                .await
                .as_deref(),
            Some("2026-01-02T02:04:05.000000Z")
        );
        assert_eq!(
            scalar("SELECT atom_timestamp('2026-01-02T03:04:05+00:00')")
                .await
                .as_deref(),
            Some("2026-01-02T03:04:05.000000Z")
        );
        assert_eq!(
            scalar("SELECT typeof(gen_random_uuid()) || length(gen_random_uuid())")
                .await
                .as_deref(),
            Some("blob16")
        );
        assert_eq!(
            scalar("SELECT CAST(length(now()) AS TEXT)")
                .await
                .as_deref(),
            Some("27")
        );
    }

    #[tokio::test]
    async fn grant_scope_matches_follows_the_sql_contract() {
        let g = "00000000-0000-0000-0000-0000000000aa";
        let query = |kind: &str, scope_ref: &str, parents: &str, ancestors: &str| {
            format!(
                "SELECT CAST(grant_scope_matches('{kind}', '{scope_ref}', 'resource', 'sensor', \
                 x'00000000000000000000000000000001', NULL, '{parents}', '{ancestors}') AS TEXT)"
            )
        };
        assert_eq!(
            scalar(&query("platform", "", "{}", "{}")).await.as_deref(),
            Some("1")
        );
        assert_eq!(
            scalar(&query("object_type", "resource:sensor", "{}", "{}"))
                .await
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            scalar(&query(
                "group_object_type",
                &format!("{g}:resource:sensor"),
                &format!("[\"{g}\"]"),
                "{}"
            ))
            .await
            .as_deref(),
            Some("1")
        );
        assert_eq!(
            scalar(&query(
                "group_tree_object_type",
                &format!("{g}:resource:sensor"),
                "{}",
                "{}"
            ))
            .await
            .as_deref(),
            Some("0")
        );
        assert_eq!(
            scalar(&query("tenant", "x", "{}", "{}")).await.as_deref(),
            Some("0")
        );
    }
}
