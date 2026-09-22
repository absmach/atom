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

type Cache = RwLock<HashMap<(String, Vec<ArgKind>, Vec<bool>), String>>;
static CACHE: LazyLock<Cache> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// True when `sql` asks PostgreSQL for row locks (`FOR UPDATE`, `FOR SHARE`, …).
pub fn takes_row_locks(sql: &str) -> bool {
    ROW_LOCK.is_match(sql)
}

/// Translates `sql` for SQLite. `nulls[i]` says whether bound argument `$i+1` is
/// NULL: the optional-filter idiom `($n IS NULL OR cond)` is resolved with it,
/// which lets SQLite plan the filter that is actually present (an `OR` over a
/// parameter otherwise defeats index use).
pub fn to_sqlite(sql: &str, kinds: &[ArgKind], nulls: &[bool]) -> String {
    let key = (sql.to_owned(), kinds.to_vec(), nulls.to_vec());
    if let Ok(cache) = CACHE.read() {
        if let Some(hit) = cache.get(&key) {
            return hit.clone();
        }
    }
    let translated = translate_with_nulls(sql, kinds, nulls);
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

// Table-valued functions of the PostgreSQL schema. The two without arguments
// are views on SQLite; `subject_effective_grants` takes the subject as a
// parameter, so it is expanded in place with that parameter substituted.
static SCHEMA_VIEW_FN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(effective_access_edges|effective_role_actions)\s*\(\s*\)"));
static SUBJECT_GRANTS_FN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\bsubject_effective_grants\s*\(\s*(\$\d+)(?:\s*::\s*uuid)?\s*\)"));

const SUBJECT_EFFECTIVE_GRANTS: &str = include_str!("subject_effective_grants.sql");

static NULL_CAST: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bNULL\s*::\s*(?:uuid|text|jsonb|json|integer|int4|int8|int|bigint|smallint|boolean|bool|timestamptz|timestamp|date|numeric|varchar|float8|real|double\s+precision)(?:\s*\[\s*\])?",
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
static INTERVAL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)interval\s+'\s*(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week)s?\s*'")
});

// ----------------------------------------------------------------------------
// Structural rewrites (need balanced-parenthesis parsing)

/// Index just past the parenthesis matching the `(` at `open`, skipping string
/// literals.
fn matching_paren(s: &str, open: usize, open_ch: u8, close_ch: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            c if c == open_ch => depth += 1,
            c if c == close_ch => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Splits `s` on commas that are not nested in brackets or string literals.
fn split_top_level(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let (mut parts, mut depth, mut start, mut i) = (Vec::new(), 0i32, 0usize, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&s[start..]);
    parts
}

/// Rewrites every call `name( … )` matched by `head` (a regex ending in `\(`),
/// handing the raw argument text to `f`.
fn rewrite_calls(sql: &str, head: &Regex, f: impl Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(m) = head.find(rest) {
        let open = m.end() - 1;
        let Some(end) = matching_paren(rest, open, b'(', b')') else {
            break;
        };
        out.push_str(&rest[..m.start()]);
        out.push_str(&f(&rest[open + 1..end - 1]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

static ARRAY_LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bARRAY\s*\["));
static ARRAY_AGG_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\barray_agg\s*\("));
static ARRAY_TO_STRING: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\barray_to_string\s*\("));
static EMPTY_ARRAY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)'\{\}'\s*::\s*(?:uuid|text|integer|bigint|int4|int8)\s*\[\s*\]"));
static UUID_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)'([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})'\s*::\s*uuid\b",
    )
});
static JSON_CONTAINS: LazyLock<Regex> =
    LazyLock::new(|| re(r"([A-Za-z_][\w.]*|\$\d+)\s*@>\s*(\$\d+|[A-Za-z_][\w.]*)"));
static INFORMATION_SCHEMA_COLUMNS: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\binformation_schema\.columns\b"));
static JSON_OBJECT_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bjson_object\s*\("));
static JSON_ARRAY_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bjson_array\s*\("));
static BARE_PARAM: LazyLock<Regex> = LazyLock::new(|| re(r"^\$(\d+)$"));
// SQLite requires `AS` before the alias of an UPDATE/DELETE target.
static DML_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(UPDATE|DELETE\s+FROM)\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s+(SET|WHERE|USING)\b")
});
static ARRAY_POSITION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\barray_position\s*\(\s*(\$\d+)\s*(?:::\s*\w+\s*\[\s*\])?\s*,\s*([A-Za-z_][\w.]*)\s*\)",
    )
});
static BOOL_AGG: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bbool_(or|and)\s*\("));
static BTRIM: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bbtrim\s*\("));
// jsonb `x - 'k' … || json_object(…)` and `x || $n` (a JSON parameter).
static JSON_MERGE_HEAD: LazyLock<Regex> =
    LazyLock::new(|| re(r"([A-Za-z_][\w.]*)((?:\s*-\s*'[^']*')*)\s*\|\|\s*json_object\s*\("));
static JSON_MERGE_PARAM: LazyLock<Regex> =
    LazyLock::new(|| re(r"([A-Za-z_][\w.]*)\s*\|\|\s*(\$(\d+))"));
static JSON_KEY_REMOVE: LazyLock<Regex> =
    LazyLock::new(|| re(r"([A-Za-z_][\w.]*)((?:\s*-\s*'[^']*')+)"));
static JSON_KEY_LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r"-\s*('[^']*')"));
static GREATEST_LEAST: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(greatest|least)\s*\("));
static DIGITS_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(\(?[A-Za-z_][\w.]*(?:\s*(?:->>|->)\s*'[^']*')?\)?)\s*~\s*'\^\[0-9\]\+\$'")
});
static UNNEST: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\bunnest\s*\(\s*(\$\d+)\s*(?:::\s*\w+\s*\[\s*\])?\s*\)\s+AS\s+(\w+)\s*\(\s*(\w+)\s*\)")
});
static ANY_EXPR: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(=|<>|!=)\s*(ANY|ALL)\s*\(\s*([A-Za-z_][\w.]*)\s*\)"));
static LATERAL_JOIN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(LEFT\s+)?JOIN\s+LATERAL\s*\("));

const OPERAND: &str = r"(?:[A-Za-z_][\w.]*\(\)|[A-Za-z_][\w.]*|\$\d+)(?:\s*::\s*\w+)?";

fn unit_seconds(unit: &str) -> f64 {
    match unit.to_ascii_lowercase().trim_end_matches('s') {
        "second" => 1.0,
        "minute" => 60.0,
        "hour" => 3600.0,
        "day" => 86_400.0,
        _ => 604_800.0,
    }
}

static TS_PLUS_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?i)({OPERAND})\s*([+-])\s*interval\s+'\s*(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week)s?\s*'"
    ))
});
static TS_PLUS_SCALED: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?i)({OPERAND})\s*([+-])\s*\(\s*(\$\d+(?:\s*::\s*\w+)?|[A-Za-z_][\w.]*)\s*\*\s*interval\s+'\s*(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week)s?\s*'\s*\)"
    ))
});
static SCALED_INTERVAL_CLOSE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\*\s*interval\s+'\s*(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week)s?\s*'\s*\)")
});
static OPERAND_AND_SIGN: LazyLock<Regex> =
    LazyLock::new(|| re(&format!(r"(?i)({OPERAND})\s*([+-])\s*$")));
static TS_PLUS_TEXT_INTERVAL: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?i)({OPERAND})\s*([+-])\s*\(\s*(\$\d+)\s*(?:::\s*text)?\s*\|\|\s*'\s*(second|minute|hour|day|week)s?'\s*\)\s*::\s*interval"
    ))
});

fn ts_add(operand: &str, sign: &str, seconds: &str) -> String {
    let sign = if sign == "-" { "-" } else { "" };
    format!("atom_ts_add({operand}, {sign}({seconds}))")
}

/// `operand ± (<any expression> * interval 'K unit')`.
fn rewrite_scaled_intervals(sql: &str) -> String {
    let mut out = sql.to_owned();
    let mut from = 0;
    while let Some(c) = SCALED_INTERVAL_CLOSE.captures_at(&out, from) {
        let whole = c.get(0).expect("group 0");
        let close = whole.end() - 1;
        let factor: f64 = c[1].parse().unwrap_or(1.0) * unit_seconds(&c[2]);
        // Matching '(' of the closing parenthesis.
        let bytes = out.as_bytes();
        let (mut depth, mut i, mut open) = (0i32, close, None);
        loop {
            match bytes[i] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(i);
                        break;
                    }
                }
                _ => {}
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let Some(open) = open else {
            from = whole.end();
            continue;
        };
        let Some(prefix) = OPERAND_AND_SIGN.captures(&out[..open]) else {
            from = whole.end();
            continue;
        };
        let start = prefix.get(0).expect("group 0").start();
        let scale = out[open + 1..whole.start()].trim().to_owned();
        let replacement = ts_add(&prefix[1], &prefix[2], &format!("({scale}) * {factor}"));
        out.replace_range(start..close + 1, &replacement);
        from = start + replacement.len();
    }
    out
}

fn rewrite_intervals(sql: &str) -> String {
    let sql = rewrite_scaled_intervals(sql);
    let sql = TS_PLUS_PARAM_INTERVAL.replace_all(&sql, |c: &Captures<'_>| {
        ts_add(&c[1], &c[2], &format!("atom_interval_secs({})", &c[3]))
    });
    let out = TS_PLUS_SCALED.replace_all(&sql, |c: &Captures<'_>| {
        let factor: f64 = c[4].parse().unwrap_or(1.0) * unit_seconds(&c[5]);
        ts_add(&c[1], &c[2], &format!("{} * {factor}", &c[3]))
    });
    let out = TS_PLUS_TEXT_INTERVAL.replace_all(&out, |c: &Captures<'_>| {
        ts_add(
            &c[1],
            &c[2],
            &format!("CAST({} AS REAL) * {}", &c[3], unit_seconds(&c[4])),
        )
    });
    TS_PLUS_LITERAL
        .replace_all(&out, |c: &Captures<'_>| {
            let n: f64 = c[3].parse().unwrap_or(0.0);
            ts_add(&c[1], &c[2], &format!("{}", n * unit_seconds(&c[4])))
        })
        .into_owned()
}

/// `ARRAY[a, b]` → JSON array text (elements rendered through `atom_text`, so
/// UUID blobs become their canonical string form).
fn rewrite_array_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(m) = ARRAY_LITERAL.find(rest) {
        let open = m.end() - 1;
        let Some(end) = matching_paren(rest, open, b'[', b']') else {
            break;
        };
        out.push_str(&rest[..m.start()]);
        let inner = rest[open + 1..end - 1].trim();
        if inner.is_empty() {
            out.push_str("'[]'");
        } else {
            let items: Vec<String> = split_top_level(inner)
                .into_iter()
                .map(|e| format!("atom_text({})", e.trim()))
                .collect();
            out.push_str(&format!("json_array({})", items.join(", ")));
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn rewrite_array_agg(args: &str) -> String {
    let trimmed = args.trim_start();
    let (distinct, args) = match trimmed.get(..9) {
        Some(head) if head.eq_ignore_ascii_case("DISTINCT ") => ("DISTINCT ", &trimmed[9..]),
        _ => ("", args),
    };
    let upper = args.to_ascii_uppercase();
    match upper.find(" ORDER BY ") {
        Some(i) => format!(
            "json_group_array({distinct}atom_text({}){})",
            args[..i].trim(),
            &args[i..]
        ),
        None => format!("json_group_array({distinct}atom_text({args}))"),
    }
}

fn rewrite_json_merges(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(c) = JSON_MERGE_HEAD.captures(rest) {
        let whole = c.get(0).expect("group 0");
        let open = whole.end() - 1;
        let Some(end) = matching_paren(rest, open, b'(', b')') else {
            break;
        };
        let mut lhs = c[1].to_owned();
        for key in JSON_KEY_LITERAL.captures_iter(&c[2]) {
            lhs = format!("atom_json_remove({lhs}, {})", &key[1]);
        }
        out.push_str(&rest[..whole.start()]);
        out.push_str(&format!(
            "atom_json_merge({lhs}, json_object({}))",
            &rest[open + 1..end - 1]
        ));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

static EXPR_CAST: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\)\s*::\s*(uuid|timestamptz|timestamp|float8|double\s+precision|real)\b")
});

/// `(expr)::uuid` / `fn(expr)::timestamptz`: a cast of a computed value (a JSON
/// field, a NULLIF, …) parses its text, unlike a cast of a column or parameter,
/// which is already the right type and is simply dropped.
fn rewrite_expression_casts(sql: &str) -> String {
    let mut out = sql.to_owned();
    let mut from = 0;
    while let Some(c) = EXPR_CAST.captures_at(&out, from) {
        let whole = c.get(0).expect("group 0");
        let close = whole.start();
        let kind = c[1].to_ascii_lowercase();
        let function = match kind.as_str() {
            "uuid" => "atom_uuid",
            "timestamptz" | "timestamp" => "atom_timestamp",
            _ => "CAST_REAL",
        };
        // Walk back to the matching '('.
        let bytes = out.as_bytes();
        let mut depth = 0i32;
        let mut i = close;
        let mut open = None;
        loop {
            match bytes[i] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(i);
                        break;
                    }
                }
                _ => {}
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let Some(mut start) = open else {
            from = whole.end();
            continue;
        };
        // Include a function name in front of the parenthesis.
        while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            start -= 1;
        }
        let expr = out[start..close + 1].to_owned();
        let replacement = if function == "CAST_REAL" {
            format!("CAST({expr} AS REAL)")
        } else {
            format!("{function}({expr})")
        };
        out.replace_range(start..whole.end(), &replacement);
        from = start + replacement.len();
    }
    out
}

static DELETE_USING: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?is)^(\s*DELETE\s+FROM\s+[A-Za-z_]\w*(?:\s+(?:AS\s+)?[A-Za-z_]\w*)?)\s+USING\s+([A-Za-z_]\w*(?:\s+(?:AS\s+)?[A-Za-z_]\w*)?)\s+WHERE\s+(.*?)(\s+RETURNING\b.*)?\s*$",
    )
});

/// `DELETE … USING u WHERE c` → `DELETE … WHERE EXISTS (SELECT 1 FROM u WHERE c)`.
fn rewrite_delete_using(sql: &str) -> String {
    match DELETE_USING.captures(sql) {
        Some(c) => format!(
            "{} WHERE EXISTS (SELECT 1 FROM {} WHERE {}){}",
            &c[1],
            &c[2],
            &c[3],
            c.get(4).map_or("", |m| m.as_str())
        ),
        None => sql.to_owned(),
    }
}

static JSON_TYPE_IS: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\bjson_type\(([^()]*)\)\s*=\s*'(string|number|boolean)'"));
static EXTRACT_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bextract\s*\("));
static EPOCH_FROM: LazyLock<Regex> = LazyLock::new(|| re(r"(?is)^\s*epoch\s+FROM\s+(.*)$"));

/// `EXTRACT(epoch FROM x)` / `EXTRACT(epoch FROM (a - b))` → seconds as a float.
fn rewrite_extract_epoch(args: &str) -> String {
    let Some(c) = EPOCH_FROM.captures(args) else {
        return format!("extract({args})");
    };
    let operand = c[1].trim();
    let inner = operand
        .strip_prefix('(')
        .and_then(|o| o.strip_suffix(')'))
        .unwrap_or(operand);
    if let Some((left, right)) = split_once_top_level(inner, " - ") {
        return format!("atom_ts_diff({}, {})", left.trim(), right.trim());
    }
    format!("atom_ts_epoch({inner})")
}

/// Splits at the first occurrence of `needle` outside brackets and quotes.
fn split_once_top_level<'a>(s: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
    let bytes = s.as_bytes();
    let (mut depth, mut i) = (0i32, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if depth == 0 && s[i..].starts_with(needle) => {
                return Some((&s[..i], &s[i + needle.len()..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

static ENCODE_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bencode\s*\("));
static DECODE_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bdecode\s*\("));
static DIGEST_SHA256: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?is)^\s*digest\s*\((.*),\s*'sha256'\s*\)\s*$"));

/// `encode(x, 'hex')` → hex text; `encode(digest(x, 'sha256'), 'hex')` → SHA-256 hex.
fn rewrite_encode(args: &str) -> String {
    let parts = split_top_level(args);
    match parts.as_slice() {
        [value, format] if format.trim().eq_ignore_ascii_case("'hex'") => {
            match DIGEST_SHA256.captures(value) {
                Some(c) => format!("atom_sha256_hex({})", c[1].trim()),
                None => format!("lower(hex({}))", value.trim()),
            }
        }
        _ => format!("encode({args})"),
    }
}

/// `decode(text, 'hex')` → blob.
fn rewrite_decode(args: &str) -> String {
    let parts = split_top_level(args);
    match parts.as_slice() {
        [value, format] if format.trim().eq_ignore_ascii_case("'hex'") => {
            format!("unhex({})", value.trim())
        }
        _ => format!("decode({args})"),
    }
}

static EPOCH_FLOOR: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)to_timestamp\s*\(\s*floor\s*\(\s*extract\s*\(\s*epoch\s+FROM\s+now\(\)\s*\)\s*/\s*(\$\d+)\s*\)\s*\*\s*(\$\d+)\s*\)",
    )
});
static GENERATE_SERIES: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bgenerate_series\s*\(\s*(\d+|\$\d+)\s*,\s*(\d+|\$\d+)\s*\)\s+(?:AS\s+)?([A-Za-z_]\w*)(?:\s*\(\s*([A-Za-z_]\w*)\s*\))?",
    )
});
static TS_PLUS_PARAM_INTERVAL: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"(?i)({OPERAND})\s*([+-])\s*\(\s*(\$\d+)\s*(?:::\s*text)?\s*::\s*interval\s*\)"
    ))
});
static JSONB_SET_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bjsonb?_set\s*\("));
static TO_JSON_CALL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bto_jsonb?\s*\("));
static JSON_PATH_LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*'\{([^}']*)\}'\s*$"));

/// `jsonb_set(target, '{a,b}', value)` → `json_set(target, '$.a.b', json(value))`.
fn rewrite_jsonb_set(args: &str) -> String {
    let parts = split_top_level(args);
    if parts.len() < 3 {
        return format!("jsonb_set({args})");
    }
    let target = rewrite_calls(parts[0].trim(), &JSONB_SET_CALL, rewrite_jsonb_set);
    let path = match JSON_PATH_LITERAL.captures(parts[1]) {
        Some(c) => format!("'$.{}'", c[1].replace(',', ".")),
        None => return format!("jsonb_set({args})"),
    };
    let value = rewrite_calls(parts[2].trim(), &JSONB_SET_CALL, rewrite_jsonb_set);
    format!("json_set({target}, {path}, json({value}))")
}

static DML_TARGET_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(?:UPDATE|DELETE\s+FROM)\s+[A-Za-z_]\w*\s+AS\s+([A-Za-z_]\w*)\b"));
static RETURNING_KW: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bRETURNING\b"));

/// SQLite does not accept the target's alias inside `RETURNING`; the bare column
/// names mean the same thing there.
fn strip_returning_alias(sql: &str) -> String {
    let (Some(alias), Some(ret)) = (DML_TARGET_ALIAS.captures(sql), RETURNING_KW.find(sql)) else {
        return sql.to_owned();
    };
    let qualified = re(&format!(r"\b{}\.", regex::escape(&alias[1])));
    let (head, tail) = sql.split_at(ret.end());
    format!("{head}{}", qualified.replace_all(tail, ""))
}

/// True when `inner` reads a column from a table that is not part of its own
/// FROM/JOIN list, i.e. it is correlated with the enclosing query.
fn is_correlated(inner: &str) -> bool {
    static QUALIFIED: LazyLock<Regex> = LazyLock::new(|| re(r"\b([A-Za-z_]\w*)\.[A-Za-z_]\w*"));
    static SOURCE: LazyLock<Regex> = LazyLock::new(|| {
        re(r"(?i)\b(?:FROM|JOIN)\s+([A-Za-z_]\w*)(?:\s+(?:AS\s+)?([A-Za-z_]\w*))?")
    });
    let mut declared: Vec<String> = Vec::new();
    for c in SOURCE.captures_iter(inner) {
        declared.push(c[1].to_ascii_lowercase());
        if let Some(alias) = c.get(2) {
            let alias = alias.as_str().to_ascii_lowercase();
            if !matches!(
                alias.as_str(),
                "on" | "where"
                    | "join"
                    | "left"
                    | "inner"
                    | "cross"
                    | "order"
                    | "group"
                    | "limit"
                    | "union"
            ) {
                declared.push(alias);
            }
        }
    }
    QUALIFIED
        .captures_iter(inner)
        .any(|c| !declared.contains(&c[1].to_ascii_lowercase()))
}

/// `LEFT JOIN LATERAL (SELECT expr AS col …) alias ON TRUE` with a single
/// output column becomes a correlated scalar subquery at each `alias.col`;
/// an uncorrelated one simply loses `LATERAL`. Multi-column and inner LATERAL
/// joins have no mechanical form and need an explicit SQLite override.
fn rewrite_lateral(sql: &str) -> String {
    static TAIL: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?is)^\s*([A-Za-z_]\w*)\s+ON\s+(?:TRUE|1\s*=\s*1)"));
    static SELECT_LIST: LazyLock<Regex> = LazyLock::new(|| re(r"(?is)^\s*SELECT\s+(.*?)\s+FROM\b"));
    let mut out = sql.to_owned();
    let mut from = 0;
    while let Some(m) = LATERAL_JOIN.find_at(&out, from) {
        let left = m.as_str().to_ascii_uppercase().starts_with("LEFT");
        let open = m.end() - 1;
        let Some(end) = matching_paren(&out, open, b'(', b')') else {
            break;
        };
        let inner = out[open + 1..end - 1].to_owned();
        let Some(tail) = TAIL.captures(&out[end..]) else {
            from = end;
            continue;
        };
        let alias = tail[1].to_owned();
        let tail_len = tail.get(0).map_or(0, |t| t.end());
        let join_start = m.start();
        let join_end = end + tail_len;

        if !is_correlated(&inner) {
            out.replace_range(
                join_start..join_end,
                &format!(
                    "{}JOIN ({inner}) {alias} ON TRUE",
                    if left { "LEFT " } else { "" }
                ),
            );
            from = join_start + 1;
            continue;
        }
        let single_column = SELECT_LIST
            .captures(&inner)
            .filter(|c| split_top_level(&c[1]).len() == 1);
        let Some(list) = single_column else {
            from = join_end;
            continue;
        };
        if !left {
            from = join_end;
            continue;
        }
        let item = list[1].trim();
        let column = match item.to_ascii_uppercase().rfind(" AS ") {
            Some(i) => item[i + 4..].trim().to_owned(),
            None => item.rsplit('.').next().unwrap_or(item).trim().to_owned(),
        };
        out.replace_range(join_start..join_end, "");
        let reference = format!("{alias}.{column}");
        out = out.replace(&reference, &format!("({inner})"));
        from = join_start;
    }
    out
}

pub fn translate(sql: &str, kinds: &[ArgKind]) -> String {
    translate_with_nulls(sql, kinds, &[])
}

static OPTIONAL_FILTER: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\(\s*\$(\d+)(?:\s*::\s*\w+)?\s+IS\s+(NOT\s+)?NULL\s+(OR|AND)\s+"));

/// `($n IS NULL OR cond)` → `(1)` when `$n` is NULL, else `(cond)`; and
/// `($n IS NOT NULL AND cond)` → `(0)` / `(cond)`.
fn specialize_optional_filters(sql: &str, nulls: &[bool]) -> String {
    let mut out = sql.to_owned();
    let mut from = 0;
    loop {
        let found = OPTIONAL_FILTER.captures_at(&out, from).map(|c| {
            let whole = c.get(0).expect("group 0");
            (
                whole.start(),
                whole.end(),
                c[1].parse::<usize>().unwrap_or(0),
                c.get(2).is_some(),
                c[3].eq_ignore_ascii_case("OR"),
            )
        });
        let Some((start, prefix_end, n, negated, is_or)) = found else {
            break;
        };
        let Some(&is_null) = n.checked_sub(1).and_then(|i| nulls.get(i)) else {
            from = prefix_end;
            continue;
        };
        // Only the two idioms whose value is fixed by the argument's nullness.
        if negated == is_or {
            from = prefix_end;
            continue;
        }
        let Some(end) = matching_paren(&out, start, b'(', b')') else {
            from = prefix_end;
            continue;
        };
        let replacement = if is_null {
            if is_or {
                "(1)".to_owned()
            } else {
                "(0)".to_owned()
            }
        } else {
            format!("({})", &out[prefix_end..end - 1])
        };
        out.replace_range(start..end, &replacement);
        from = start + 1;
    }
    out
}

pub fn translate_with_nulls(sql: &str, kinds: &[ArgKind], nulls: &[bool]) -> String {
    let mut out = NULL_CAST.replace_all(sql, "NULL").into_owned();
    out = specialize_optional_filters(&out, nulls);

    if let Some(c) = TRUNCATE.captures(&out) {
        return format!("DELETE FROM {}", &c[1]);
    }
    if LOCK_TABLE.is_match(&out) {
        return "SELECT 1".to_owned();
    }

    out = SCHEMA_VIEW_FN.replace_all(&out, "$1").into_owned();
    out = SUBJECT_GRANTS_FN
        .replace_all(&out, |c: &Captures<'_>| {
            SUBJECT_EFFECTIVE_GRANTS.replace("{subject}", &c[1])
        })
        .into_owned();
    out = ADVISORY.replace_all(&out, "1").into_owned();
    out = ROW_LOCK.replace_all(&out, "").into_owned();

    // Literals and containers first, while the PostgreSQL casts that give them
    // their type are still present.
    out = UUID_LITERAL
        .replace_all(&out, |c: &Captures<'_>| {
            format!("x'{}{}{}{}{}'", &c[1], &c[2], &c[3], &c[4], &c[5])
        })
        .into_owned();
    out = EMPTY_ARRAY.replace_all(&out, "'[]'").into_owned();
    out = rewrite_array_literals(&out);
    out = rewrite_intervals(&out);
    out = JSON_CONTAINS
        .replace_all(&out, "atom_json_contains($1, $2)")
        .into_owned();
    out = rewrite_calls(&out, &ARRAY_TO_STRING, |args| {
        let parts = split_top_level(args);
        match parts.as_slice() {
            [column, sep] => format!(
                "COALESCE((SELECT group_concat(value, {}) FROM json_each({})), '')",
                sep.trim(),
                column.trim()
            ),
            _ => format!("array_to_string({args})"),
        }
    });
    out = UNNEST
        .replace_all(&out, |c: &Captures<'_>| {
            let n: usize = c[1][1..].parse().unwrap_or(0);
            let element = match n.checked_sub(1).and_then(|i| kinds.get(i)) {
                Some(ArgKind::UuidArray) => "unhex(value)",
                _ => "value",
            };
            format!(
                "(SELECT {element} AS {} FROM json_each({})) AS {}",
                &c[3], &c[1], &c[2]
            )
        })
        .into_owned();
    out = DML_ALIAS
        .replace_all(&out, |c: &Captures<'_>| {
            if c[3].eq_ignore_ascii_case("AS") || c[3].eq_ignore_ascii_case("SET") {
                return c[0].to_owned();
            }
            format!("{} {} AS {} {}", &c[1], &c[2], &c[3], &c[4])
        })
        .into_owned();
    // Deliberately not a `json_each` correlated subquery: `json_each` exposes
    // fixed columns named key/value/type/atom/id/parent/fullkey/path, and
    // every real call site here compares against a bare `id` — which a WHERE
    // clause inside json_each's own scope resolves to json_each's *own* `id`
    // column, silently shadowing the correlated outer row and matching
    // nothing. `instr` finds the substring within the parameter's JSON array
    // text directly, in the outer scope, so there is no name to shadow. Every
    // element is a fixed-width token (32-hex UUID, or any other JSON scalar
    // wrapped in its own quotes), so an element's substring position is
    // strictly increasing in element order — safe to sort by.
    out = ARRAY_POSITION
        .replace_all(&out, |c: &Captures<'_>| {
            let n: usize = c[1][1..].parse().unwrap_or(0);
            let needle = match n.checked_sub(1).and_then(|i| kinds.get(i)) {
                Some(ArgKind::UuidArray) => format!("lower(hex({}))", &c[2]),
                _ => format!("'\"' || {} || '\"'", &c[2]),
            };
            format!("NULLIF(instr({}, {needle}), 0)", &c[1])
        })
        .into_owned();
    out = BOOL_AGG
        .replace_all(&out, |c: &Captures<'_>| {
            if c[1].eq_ignore_ascii_case("or") {
                "max("
            } else {
                "min("
            }
        })
        .into_owned();
    out = BTRIM.replace_all(&out, "trim(").into_owned();
    out = EPOCH_FLOOR
        .replace_all(&out, "atom_ts_floor(now(), $1)")
        .into_owned();
    out = rewrite_calls(&out, &EXTRACT_CALL, rewrite_extract_epoch);
    out = rewrite_calls(&out, &DECODE_CALL, rewrite_decode);
    out = rewrite_calls(&out, &ENCODE_CALL, rewrite_encode);
    out = GENERATE_SERIES
        .replace_all(&out, |c: &Captures<'_>| {
            let column = c.get(4).map_or(&c[3], |m| m.as_str());
            format!(
                "(WITH RECURSIVE series(i) AS (SELECT {lo} UNION ALL SELECT i + 1 FROM series WHERE i < {hi}) \
                 SELECT i AS {column} FROM series) AS {alias}",
                lo = &c[1],
                hi = &c[2],
                alias = &c[3]
            )
        })
        .into_owned();
    out = rewrite_calls(&out, &JSONB_SET_CALL, rewrite_jsonb_set);
    out = TO_JSON_CALL.replace_all(&out, "json_quote(").into_owned();
    out = rewrite_delete_using(&out);
    out = strip_returning_alias(&out);
    out = rewrite_lateral(&out);
    out = INFORMATION_SCHEMA_COLUMNS
        .replace_all(
            &out,
            "(SELECT m.name AS table_name, p.name AS column_name \
             FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type = 'table')",
        )
        .into_owned();

    out = rewrite_expression_casts(&out);
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
    // `x = ANY(column)` over a JSON-array column.
    out = ANY_EXPR
        .replace_all(&out, |c: &Captures<'_>| {
            let negated = &c[1] != "=";
            // Elements are stored as text; a UUID column holds them in
            // canonical string form, so offer the value both ways.
            format!(
                "{} (SELECT value FROM json_each({col}) \
                 UNION ALL SELECT atom_uuid(value) FROM json_each({col}) \
                 WHERE atom_uuid(value) IS NOT NULL)",
                if negated { "NOT IN" } else { "IN" },
                col = &c[3]
            )
        })
        .into_owned();

    out = ILIKE.replace_all(&out, "LIKE").into_owned();
    out = NOW_LIKE.replace_all(&out, "now()").into_owned();
    out = rewrite_calls(&out, &ARRAY_AGG_CALL, rewrite_array_agg);
    out = GREATEST_LEAST
        .replace_all(&out, |c: &Captures<'_>| {
            if c[1].eq_ignore_ascii_case("greatest") {
                "max("
            } else {
                "min("
            }
        })
        .into_owned();
    out = DIGITS_ONLY
        .replace_all(&out, |c: &Captures<'_>| {
            let x = &c[1];
            format!("({x} <> '' AND {x} NOT GLOB '*[^0-9]*')")
        })
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
    // json_type() names JSON scalars differently from jsonb_typeof().
    out = JSON_TYPE_IS
        .replace_all(&out, |c: &Captures<'_>| {
            let call = format!("json_type({})", &c[1]);
            match &c[2] {
                "string" => format!("{call} = 'text'"),
                "number" => format!("{call} IN ('integer', 'real')"),
                _ => format!("{call} IN ('true', 'false')"),
            }
        })
        .into_owned();
    out = INTERVAL
        .replace_all(&out, |c: &Captures<'_>| {
            let n: f64 = c[1].parse().unwrap_or(0.0);
            format!("{}", n * unit_seconds(&c[2]))
        })
        .into_owned();
    out = rewrite_json_merges(&out);
    // Remaining `jsonb - 'key'` (not followed by a merge).
    out = JSON_KEY_REMOVE
        .replace_all(&out, |c: &Captures<'_>| {
            let mut lhs = c[1].to_owned();
            for key in JSON_KEY_LITERAL.captures_iter(&c[2]) {
                lhs = format!("atom_json_remove({lhs}, {})", &key[1]);
            }
            lhs
        })
        .into_owned();
    out = JSON_MERGE_PARAM
        .replace_all(&out, |c: &Captures<'_>| {
            let n: usize = c[3].parse().unwrap_or(0);
            match n.checked_sub(1).and_then(|i| kinds.get(i)) {
                Some(ArgKind::Json) => format!("atom_json_merge({}, {})", &c[1], &c[2]),
                _ => c[0].to_owned(),
            }
        })
        .into_owned();
    // A UUID parameter is a 16-byte BLOB, which JSON constructors reject; render
    // it as its canonical string first.
    for (head, name) in [
        (&JSON_OBJECT_CALL, "json_object"),
        (&JSON_ARRAY_CALL, "json_array"),
    ] {
        out = rewrite_calls(&out, head, |args| {
            let items: Vec<String> = split_top_level(args)
                .into_iter()
                .map(|item| {
                    let trimmed = item.trim();
                    let uuid_param = BARE_PARAM.captures(trimmed).is_some_and(|c| {
                        let n: usize = c[1].parse().unwrap_or(0);
                        n.checked_sub(1).and_then(|i| kinds.get(i)) == Some(&ArgKind::Uuid)
                    });
                    if uuid_param {
                        format!("atom_text({trimmed})")
                    } else {
                        item.to_owned()
                    }
                })
                .collect();
            format!("{name}({})", items.join(","))
        });
    }

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
    fn grant_expansion_functions_become_views_and_inline_queries() {
        assert_eq!(
            t("SELECT * FROM effective_access_edges() WHERE id = $1", &[]),
            "SELECT * FROM effective_access_edges WHERE id = $1"
        );
        let sql = t(
            "WITH g AS (SELECT * FROM subject_effective_grants($1)) SELECT * FROM g",
            &[ArgKind::Uuid],
        );
        assert!(sql.contains("WITH RECURSIVE subject_groups"));
        assert!(sql.contains("gm.entity_id = $1"));
        assert!(!sql.contains("{subject}"));
    }

    #[test]
    fn typed_nulls_lose_their_cast_without_swallowing_aliases() {
        assert_eq!(
            t("SELECT NULL::text AS object_type, NULL::uuid[] AS ids", &[]),
            "SELECT NULL AS object_type, NULL AS ids"
        );
    }

    #[test]
    fn interval_arithmetic_becomes_timestamp_function_calls() {
        assert_eq!(
            t("last_used_at < now() - interval '5 minutes'", &[]),
            "last_used_at < atom_ts_add(now(), -(300))"
        );
        assert_eq!(
            t(
                "window_start < now() - ($3 * interval '2 seconds')",
                &[ArgKind::I64]
            ),
            "window_start < atom_ts_add(now(), -(($3) * 2))"
        );
        assert_eq!(
            t(
                "c.expires_at <= now() + ($1::text || ' days')::interval",
                &[ArgKind::Text]
            ),
            "c.expires_at <= atom_ts_add(now(), (CAST($1 AS REAL) * 86400))"
        );
        assert_eq!(
            t("x <= $1 + interval '24 hours'", &[ArgKind::Timestamp]),
            "x <= atom_ts_add($1, (86400))"
        );
    }

    #[test]
    fn array_constructs_become_json() {
        assert_eq!(t("SELECT ARRAY[]::text[]", &[]), "SELECT '[]'");
        assert_eq!(
            t("SELECT ARRAY[gh.parent_id]", &[]),
            "SELECT json_array(atom_text(gh.parent_id))"
        );
        assert_eq!(t("COALESCE(x, '{}'::uuid[])", &[]), "COALESCE(x, '[]')");
        assert_eq!(
            t("SELECT array_agg(g.group_id) FROM g", &[]),
            "SELECT json_group_array(atom_text(g.group_id)) FROM g"
        );
        assert_eq!(
            t(
                "SELECT 1 FROM unnest($1::text[]) AS requested(name)",
                &[ArgKind::TextArray]
            ),
            "SELECT 1 FROM (SELECT value AS name FROM json_each($1)) AS requested"
        );
        assert_eq!(
            t("array_to_string(tags, ',') ILIKE $5", &[ArgKind::Text]),
            "COALESCE((SELECT group_concat(value, ',') FROM json_each(tags)), '') LIKE $5"
        );
        assert_eq!(
            t("WHERE name = ANY(aliases)", &[]),
            "WHERE name IN (SELECT value FROM json_each(aliases) UNION ALL SELECT atom_uuid(value) FROM json_each(aliases) WHERE atom_uuid(value) IS NOT NULL)"
        );
    }

    #[test]
    fn json_containment_and_uuid_literals() {
        assert_eq!(
            t(
                "($9::jsonb IS NULL OR r.attributes @> $9::jsonb)",
                &[ArgKind::Json]
            ),
            "($9 IS NULL OR atom_json_contains(r.attributes, $9))"
        );
        assert_eq!(
            t("id = '00000000-0000-0000-0000-000000000001'::uuid", &[]),
            "id = x'00000000000000000000000000000001'"
        );
    }

    #[test]
    fn lateral_joins_become_scalar_subqueries_when_correlated() {
        let sql = "SELECT t.id, x.kind FROM t LEFT JOIN LATERAL (SELECT 'a' || k AS kind FROM u WHERE u.id = t.uid) x ON TRUE";
        assert_eq!(
            t(sql, &[]),
            "SELECT t.id, (SELECT 'a' || k AS kind FROM u WHERE u.id = t.uid) FROM t "
        );
        assert_eq!(
            t(
                "FROM totals LEFT JOIN LATERAL (SELECT id FROM page) page ON TRUE",
                &[]
            ),
            "FROM totals LEFT JOIN (SELECT id FROM page) page ON TRUE"
        );
    }

    #[test]
    fn postgres_functions_without_a_sqlite_namesake_are_rewritten() {
        assert_eq!(
            t(
                "ORDER BY array_position($1::uuid[], id)",
                &[ArgKind::UuidArray]
            ),
            "ORDER BY NULLIF(instr($1, lower(hex(id))), 0)"
        );
        assert_eq!(
            t("COALESCE(bool_or(verified_at IS NOT NULL), false)", &[]),
            "COALESCE(max(verified_at IS NOT NULL), false)"
        );
        assert_eq!(t("lower(btrim(x))", &[]), "lower(trim(x))");
    }

    /// `array_position`'s old translation used a `json_each` correlated
    /// subquery that compared against a bare `id` — `json_each` itself
    /// exposes a fixed `id` column, which silently shadowed the outer row and
    /// matched nothing, reversing (rather than applying) the requested order.
    /// `instr` deliberately avoids introducing any new scope, so there is no
    /// name left to shadow.
    #[test]
    fn array_position_does_not_shadow_a_same_named_outer_column() {
        assert_eq!(
            t("array_position($1::uuid[], id)", &[ArgKind::UuidArray]),
            "NULLIF(instr($1, lower(hex(id))), 0)"
        );
        assert_eq!(
            t(
                "array_position($2::uuid[], g.id)",
                &[ArgKind::Uuid, ArgKind::UuidArray]
            ),
            "NULLIF(instr($2, lower(hex(g.id))), 0)"
        );
        assert_eq!(
            t("array_position($1::text[], name)", &[ArgKind::TextArray]),
            "NULLIF(instr($1, '\"' || name || '\"'), 0)"
        );
    }

    #[test]
    fn jsonb_merge_and_key_removal_use_json_functions() {
        assert_eq!(
            t(
                "metadata = metadata - 'revoked_at' - 'why' || jsonb_build_object('a', 1)",
                &[]
            ),
            "metadata = atom_json_merge(atom_json_remove(atom_json_remove(metadata, 'revoked_at'), 'why'), json_object('a', 1))"
        );
        assert_eq!(
            t(
                "SET attributes = attributes || $2",
                &[ArgKind::Uuid, ArgKind::Json]
            ),
            "SET attributes = atom_json_merge(attributes, $2)"
        );
    }

    #[test]
    fn casts_of_computed_values_parse_their_text() {
        assert_eq!(
            t(
                "(payload->>'target_id')::uuid = $2",
                &[ArgKind::Text, ArgKind::Uuid]
            ),
            "atom_uuid((payload->>'target_id')) = $2"
        );
        assert_eq!(
            t("NULLIF($5->>'tenant_id', '')::uuid IS NULL", &[]),
            "atom_uuid(NULLIF($5->>'tenant_id', '')) IS NULL"
        );
        assert_eq!(
            t("(c.metadata->>'revoked_at')::timestamptz", &[]),
            "atom_timestamp((c.metadata->>'revoked_at'))"
        );
        assert_eq!(t("id = $1::uuid", &[ArgKind::Uuid]), "id = $1");
    }

    #[test]
    fn set_returning_and_encoding_helpers() {
        assert_eq!(
            t("SELECT g FROM generate_series(1, 5000) g", &[]),
            "SELECT g FROM (WITH RECURSIVE series(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM series WHERE i < 5000) SELECT i AS g FROM series) AS g"
        );
        assert_eq!(t("decode($1, 'hex')", &[ArgKind::Text]), "unhex($1)");
        assert_eq!(t("encode(secret, 'hex')", &[]), "lower(hex(secret))");
        assert_eq!(
            t(
                "to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)",
                &[]
            ),
            "atom_ts_floor(now(), $3)"
        );
        assert_eq!(
            t(
                "now() - ($2::text::interval)",
                &[ArgKind::Uuid, ArgKind::Text]
            ),
            "atom_ts_add(now(), -(atom_interval_secs($2)))"
        );
        assert_eq!(
            t("array_agg(DISTINCT key_backend ORDER BY key_backend)", &[]),
            "json_group_array(DISTINCT atom_text(key_backend) ORDER BY key_backend)"
        );
    }

    #[test]
    fn epoch_extraction_uses_timestamp_functions() {
        assert_eq!(
            t(
                "GREATEST(MIN(EXTRACT(epoch FROM (not_after - $1))), 0)::float8",
                &[]
            ),
            "CAST(max(MIN(atom_ts_diff(not_after, $1)), 0) AS REAL)"
        );
        assert_eq!(t("extract(epoch FROM now())", &[]), "atom_ts_epoch(now())");
    }

    #[test]
    fn json_type_names_and_multiline_scaled_intervals() {
        assert_eq!(
            t("jsonb_typeof(c.metadata -> 'k') = 'string'", &[]),
            "json_type(c.metadata -> 'k') = 'text'"
        );
        assert_eq!(
            t(
                "c.expires_at - (\n COALESCE(a, b) * interval '1 second'\n)",
                &[]
            ),
            "atom_ts_add(c.expires_at, -((COALESCE(a, b)) * 1))"
        );
    }

    #[test]
    fn nested_encoding_and_float_casts() {
        assert_eq!(
            t("decode(md5(random()::text), 'hex')", &[]),
            "unhex(md5(random()))"
        );
        assert_eq!(
            t(
                "crl_sha256 = encode(digest(decode('010203', 'hex'), 'sha256'), 'hex')",
                &[]
            ),
            "crl_sha256 = atom_sha256_hex(unhex('010203'))"
        );
        assert_eq!(
            t("GREATEST(MIN(x), 0)::float8 AS seconds", &[]),
            "CAST(max(MIN(x), 0) AS REAL) AS seconds"
        );
    }

    #[test]
    fn optional_filters_are_resolved_by_argument_nullness() {
        let sql = "WHERE ($1::uuid IS NULL OR e.tenant_id = $1) AND ($2::text IS NULL OR e.external_id = $2)";
        assert_eq!(
            translate_with_nulls(sql, &[ArgKind::Uuid, ArgKind::Text], &[true, false]),
            "WHERE (1) AND (e.external_id = $2)"
        );
        assert_eq!(
            translate_with_nulls(sql, &[ArgKind::Uuid, ArgKind::Text], &[false, true]),
            "WHERE (e.tenant_id = $1) AND (1)"
        );
        assert_eq!(
            translate_with_nulls(
                "($2 IS NOT NULL AND invitee_user_id = $2)",
                &[ArgKind::Uuid, ArgKind::Uuid],
                &[false, true]
            ),
            "(0)"
        );
    }

    #[test]
    fn json_key_removal_outside_a_merge() {
        assert_eq!(
            t("jsonb_set(metadata - 'a' - 'b', '{k}', '1')", &[]),
            "json_set(atom_json_remove(atom_json_remove(metadata, 'a'), 'b'), '$.k', json('1'))"
        );
    }

    #[test]
    fn digest_encoding_uses_the_sha256_function() {
        assert_eq!(
            t("crl_sha256 = encode(digest(crl_der, 'sha256'), 'hex')", &[]),
            "crl_sha256 = atom_sha256_hex(crl_der)"
        );
    }

    #[test]
    fn jsonb_set_becomes_json_set() {
        assert_eq!(
            t(
                "jsonb_set(jsonb_set(metadata, '{revoked_at}', to_jsonb(now())), '{reason}', '\"x\"')",
                &[]
            ),
            "json_set(json_set(metadata, '$.revoked_at', json(json_quote(now()))), '$.reason', json('\"x\"'))"
        );
    }

    #[test]
    fn delete_using_becomes_exists() {
        assert_eq!(
            t(
                "DELETE FROM principal_group_members gm USING principal_groups g WHERE gm.group_id = g.id AND g.tenant_id = $1",
                &[]
            ),
            "DELETE FROM principal_group_members AS gm WHERE EXISTS (SELECT 1 FROM principal_groups g WHERE gm.group_id = g.id AND g.tenant_id = $1)"
        );
    }

    #[test]
    fn returning_drops_the_update_alias() {
        assert_eq!(
            t(
                "UPDATE credentials c SET a = 1 FROM e WHERE c.id = e.id RETURNING c.id, c.kind",
                &[]
            ),
            "UPDATE credentials AS c SET a = 1 FROM e WHERE c.id = e.id RETURNING id, kind"
        );
    }

    #[test]
    fn dml_target_aliases_gain_as() {
        assert_eq!(
            t(
                "UPDATE credentials c SET status = 'x' FROM entities e WHERE c.entity_id = e.id",
                &[]
            ),
            "UPDATE credentials AS c SET status = 'x' FROM entities e WHERE c.entity_id = e.id"
        );
        assert_eq!(
            t("UPDATE credentials SET status = 'x'", &[]),
            "UPDATE credentials SET status = 'x'"
        );
    }

    #[test]
    fn intervals_become_second_counts() {
        assert_eq!(t("interval '2 seconds'", &[]), "2");
        assert_eq!(t("interval '30 days'", &[]), "2592000");
    }
}
