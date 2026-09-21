//! PostgreSQL → SQLite statement translation.
//!
//! Application SQL is written once in the PostgreSQL dialect. This module
//! rewrites the constructs that differ in ways that can be handled mechanically,
//! and leaves everything both engines share (joins, CTEs, `RETURNING`,
//! `ON CONFLICT`, `COALESCE`, `IS NOT DISTINCT FROM`, `FILTER`, …) untouched.
//!
//! Anything that cannot be rewritten mechanically must not rely on this pass:
//! give the statement an explicit [`crate::db::Query::sqlite`] override instead.
//! Translation is a pure function of the SQL text and the kinds of its bound
//! arguments, so results are cached.

use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
};

use regex::{Captures, Regex};

use super::arg::ArgKind;

type Cache = RwLock<HashMap<(String, Vec<ArgKind>), String>>;
static CACHE: LazyLock<Cache> = LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn to_sqlite(sql: &str, kinds: &[ArgKind]) -> String {
    let key = (sql.to_owned(), kinds.to_vec());
    if let Ok(cache) = CACHE.read() {
        if let Some(hit) = cache.get(&key) {
            return hit.clone();
        }
    }
    let translated = translate(sql, kinds);
    if let Ok(mut cache) = CACHE.write() {
        cache.insert(key, translated.clone());
    }
    translated
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static translation pattern is valid")
}

// Advisory locks and row locks have no SQLite counterpart: the single write
// transaction (`BEGIN IMMEDIATE`) already serialises every mutation.
static ADVISORY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?is)\bpg_(?:try_)?advisory_(?:xact_)?lock(?:_shared)?\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)",
    )
});
static ROW_LOCK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\s+FOR\s+(?:NO\s+KEY\s+UPDATE|KEY\s+SHARE|UPDATE|SHARE)(?:\s+OF\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*)*)?(?:\s+(?:SKIP\s+LOCKED|NOWAIT))?",
    )
});
static LOCK_TABLE: LazyLock<Regex> = LazyLock::new(|| re(r"(?is)^\s*LOCK\s+TABLE\b.*$"));
static TRUNCATE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?is)^\s*TRUNCATE\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+RESTART\s+IDENTITY)?(?:\s+CASCADE)?\s*$",
    )
});

// `x::text` on an identifier may be a UUID blob; render it in canonical form.
static TEXT_CAST_IDENT: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)::text\b"));
static CAST: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)::\s*(?:uuid|text|jsonb|json|integer|int4|int8|int|bigint|smallint|boolean|bool|timestamptz|timestamp|date|numeric|varchar|float8|real|double\s+precision)(?:\s*\[\s*\])?",
    )
});
static ANY_ARRAY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(=|<>|!=)\s*(ANY|ALL)\s*\(\s*\$(\d+)\s*\)"));
static ILIKE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bILIKE\b"));
static NOW_LIKE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:CURRENT_TIMESTAMP|clock_timestamp\s*\(\s*\)|statement_timestamp\s*\(\s*\)|transaction_timestamp\s*\(\s*\))",
    )
});
static JSONB_FUNCS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bjsonb?_(build_object|build_array|typeof|array_length|array_elements_text|array_elements|each_text|each|object_keys|agg)\b",
    )
});
static ARRAY_AGG: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\barray_agg\s*\("));
static INTERVAL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)interval\s+'\s*(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week)s?\s*'")
});

pub fn translate(sql: &str, kinds: &[ArgKind]) -> String {
    let mut out = sql.to_owned();

    if let Some(c) = TRUNCATE.captures(&out) {
        return format!("DELETE FROM {}", &c[1]);
    }
    if LOCK_TABLE.is_match(&out) {
        return "SELECT 1".to_owned();
    }

    out = ADVISORY.replace_all(&out, "1").into_owned();
    out = ROW_LOCK.replace_all(&out, "").into_owned();

    out = TEXT_CAST_IDENT
        .replace_all(&out, "atom_text($1)")
        .into_owned();
    out = CAST.replace_all(&out, "").into_owned();

    out = ANY_ARRAY
        .replace_all(&out, |c: &Captures<'_>| {
            let op = &c[1];
            let n: usize = c[3].parse().unwrap_or(0);
            let element = match n.checked_sub(1).and_then(|i| kinds.get(i)) {
                Some(ArgKind::UuidArray) => "unhex(value)",
                _ => "value",
            };
            let negated = op != "=";
            format!(
                "{} (SELECT {element} FROM json_each(${n}))",
                if negated { "NOT IN" } else { "IN" }
            )
        })
        .into_owned();

    out = ILIKE.replace_all(&out, "LIKE").into_owned();
    out = NOW_LIKE.replace_all(&out, "now()").into_owned();
    out = ARRAY_AGG
        .replace_all(&out, "json_group_array(")
        .into_owned();
    out = JSONB_FUNCS
        .replace_all(&out, |c: &Captures<'_>| {
            match c[1].to_ascii_lowercase().as_str() {
                "build_object" => "json_object".to_owned(),
                "build_array" => "json_array".to_owned(),
                "typeof" => "json_type".to_owned(),
                "array_length" => "json_array_length".to_owned(),
                "array_elements" | "array_elements_text" | "each" | "each_text" => {
                    "json_each".to_owned()
                }
                "agg" => "json_group_array".to_owned(),
                other => format!("json_{other}"),
            }
        })
        .into_owned();
    out = INTERVAL
        .replace_all(&out, |c: &Captures<'_>| {
            let n: f64 = c[1].parse().unwrap_or(0.0);
            let secs = match c[2].to_ascii_lowercase().as_str() {
                "second" => 1.0,
                "minute" => 60.0,
                "hour" => 3600.0,
                "day" => 86_400.0,
                _ => 604_800.0,
            };
            format!("{}", n * secs)
        })
        .into_owned();

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(sql: &str, kinds: &[ArgKind]) -> String {
        translate(sql, kinds)
    }

    #[test]
    fn strips_casts_and_row_locks() {
        assert_eq!(
            t(
                "SELECT id FROM entities WHERE id = $1::uuid FOR UPDATE",
                &[ArgKind::Uuid]
            ),
            "SELECT id FROM entities WHERE id = $1"
        );
        assert_eq!(
            t(
                "SELECT 1 FROM t WHERE a = $1 FOR UPDATE OF t SKIP LOCKED",
                &[ArgKind::Text]
            ),
            "SELECT 1 FROM t WHERE a = $1"
        );
    }

    #[test]
    fn rewrites_any_over_bound_arrays_by_element_kind() {
        assert_eq!(
            t("DELETE FROM x WHERE id = ANY($1)", &[ArgKind::UuidArray]),
            "DELETE FROM x WHERE id IN (SELECT unhex(value) FROM json_each($1))"
        );
        assert_eq!(
            t(
                "SELECT 1 FROM x WHERE name = ANY($2::text[])",
                &[ArgKind::Uuid, ArgKind::TextArray]
            ),
            "SELECT 1 FROM x WHERE name IN (SELECT value FROM json_each($2))"
        );
        assert_eq!(
            t("SELECT 1 FROM x WHERE id <> ALL($1)", &[ArgKind::UuidArray]),
            "SELECT 1 FROM x WHERE id NOT IN (SELECT unhex(value) FROM json_each($1))"
        );
    }

    #[test]
    fn advisory_locks_become_constants() {
        assert_eq!(
            t("SELECT pg_try_advisory_xact_lock($1)", &[ArgKind::I64]),
            "SELECT 1"
        );
        assert_eq!(
            t(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[ArgKind::Text]
            ),
            "SELECT 1"
        );
    }

    #[test]
    fn text_casts_of_identifiers_render_uuids_canonically() {
        assert_eq!(
            t("WHERE e.id::text ILIKE $1", &[ArgKind::Text]),
            "WHERE atom_text(e.id) LIKE $1"
        );
    }

    #[test]
    fn intervals_become_second_counts() {
        assert_eq!(t("interval '2 seconds'", &[]), "2");
        assert_eq!(t("interval '30 days'", &[]), "2592000");
    }
}
