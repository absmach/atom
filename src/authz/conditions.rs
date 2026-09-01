use chrono::{DateTime, Utc};
use serde_json::Value;

pub const ABAC_CONTEXT_ROOTS: [&str; 5] = ["entity", "resource", "object", "tenant", "context"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionOperator {
    Eq,
    Neq,
    In,
    Contains,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl ConditionOperator {
    const ALL: [Self; 8] = [
        Self::Eq,
        Self::Neq,
        Self::In,
        Self::Contains,
        Self::Gt,
        Self::Gte,
        Self::Lt,
        Self::Lte,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::In => "in",
            Self::Contains => "contains",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operator| operator.as_str() == value)
    }
}

pub fn abac_operator_names() -> impl Iterator<Item = &'static str> {
    ConditionOperator::ALL
        .into_iter()
        .map(ConditionOperator::as_str)
}

/// Evaluate flat-map ABAC conditions against the evaluation context.
/// Keys are dot-paths; all entries must match (AND logic).
pub fn conditions_match(conditions: &Value, ctx: &Value) -> bool {
    // Fail closed on malformed policy: a non-object `conditions` value is not a
    // valid condition set and must never match every request. An empty object
    // means "no conditions" and matches unconditionally.
    let Some(map) = conditions.as_object() else {
        return false;
    };

    if map.is_empty() {
        return true;
    }

    map.iter().all(|(path, expected)| {
        let Some(actual) = resolve_path(ctx, path) else {
            return false;
        };
        condition_value_matches(actual, expected)
    })
}

fn condition_value_matches(actual: &Value, expected: &Value) -> bool {
    let Some(ops) = expected.as_object() else {
        return actual == expected;
    };

    if ops.is_empty() {
        return actual == expected;
    }

    ops.iter()
        .all(|(op, operand)| match ConditionOperator::parse(op) {
            Some(ConditionOperator::Eq) => actual == operand,
            Some(ConditionOperator::Neq) => actual != operand,
            Some(ConditionOperator::Contains) => contains(actual, operand),
            Some(ConditionOperator::In) => operand
                .as_array()
                .map(|items| items.iter().any(|item| item == actual))
                .unwrap_or(false),
            Some(ConditionOperator::Gt) => {
                compare(actual, operand).map(|o| o.is_gt()).unwrap_or(false)
            }
            Some(ConditionOperator::Gte) => compare(actual, operand)
                .map(|o| o.is_gt() || o.is_eq())
                .unwrap_or(false),
            Some(ConditionOperator::Lt) => {
                compare(actual, operand).map(|o| o.is_lt()).unwrap_or(false)
            }
            Some(ConditionOperator::Lte) => compare(actual, operand)
                .map(|o| o.is_lt() || o.is_eq())
                .unwrap_or(false),
            None => false,
        })
}

fn contains(actual: &Value, operand: &Value) -> bool {
    match (actual, operand) {
        (Value::String(haystack), Value::String(needle)) => haystack.contains(needle),
        (Value::Array(items), needle) => items.iter().any(|item| item == needle),
        (Value::Object(map), Value::String(key)) => map.contains_key(key),
        (Value::Object(map), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| map.get(key) == Some(value)),
        _ => false,
    }
}

fn compare(actual: &Value, operand: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(left), Some(right)) = (actual.as_f64(), operand.as_f64()) {
        return left.partial_cmp(&right);
    }

    let left = actual.as_str().and_then(parse_time)?;
    let right = operand.as_str().and_then(parse_time)?;
    Some(left.cmp(&right))
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn literal_values_match_by_equality() {
        let ctx = json!({"entity": {"attributes": {"env": "prod"}}});
        assert!(conditions_match(
            &json!({"entity.attributes.env": "prod"}),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({"entity.attributes.env": "staging"}),
            &ctx
        ));
    }

    #[test]
    fn neq_operator_matches_when_values_differ() {
        let ctx = json!({"entity": {"kind": "human"}});
        assert!(conditions_match(
            &json!({"entity.kind": {"neq": "device"}}),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({"entity.kind": {"neq": "human"}}),
            &ctx
        ));
    }

    #[test]
    fn contains_operator_supports_strings_and_arrays() {
        let ctx = json!({
            "object": {
                "attributes": {
                    "path": "factory-a/line-1",
                    "tags": ["production", "critical"]
                }
            }
        });
        assert!(conditions_match(
            &json!({"object.attributes.path": {"contains": "line-1"}}),
            &ctx
        ));
        assert!(conditions_match(
            &json!({"object.attributes.tags": {"contains": "critical"}}),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({"object.attributes.tags": {"contains": "staging"}}),
            &ctx
        ));
    }

    #[test]
    fn in_operator_requires_actual_value_in_operand_array() {
        let ctx = json!({"entity": {"attributes": {"team": "ops"}}});
        assert!(conditions_match(
            &json!({"entity.attributes.team": {"in": ["ops", "security"]}}),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({"entity.attributes.team": {"in": ["finance"]}}),
            &ctx
        ));
    }

    #[test]
    fn numeric_comparison_operators_work() {
        let ctx = json!({"context": {"risk": 7}});
        assert!(conditions_match(&json!({"context.risk": {"gt": 5}}), &ctx));
        assert!(conditions_match(&json!({"context.risk": {"gte": 7}}), &ctx));
        assert!(conditions_match(&json!({"context.risk": {"lt": 9}}), &ctx));
        assert!(conditions_match(&json!({"context.risk": {"lte": 7}}), &ctx));
        assert!(!conditions_match(&json!({"context.risk": {"lt": 7}}), &ctx));
    }

    #[test]
    fn timestamp_comparison_operators_work() {
        let ctx = json!({"context": {"time": "2026-04-29T12:00:00Z"}});
        assert!(conditions_match(
            &json!({"context.time": {"gte": "2026-04-29T00:00:00Z"}}),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({"context.time": {"lt": "2026-04-29T00:00:00Z"}}),
            &ctx
        ));
    }

    #[test]
    fn empty_object_conditions_match_unconditionally() {
        let ctx = json!({"entity": {"kind": "human"}});
        assert!(conditions_match(&json!({}), &ctx));
    }

    #[test]
    fn non_object_conditions_fail_closed() {
        let ctx = json!({"entity": {"kind": "human"}});
        // Malformed policy: a string/array/number/bool/null is not a condition
        // set and must never match every request.
        assert!(!conditions_match(&json!("oops"), &ctx));
        assert!(!conditions_match(&json!(["a", "b"]), &ctx));
        assert!(!conditions_match(&json!(42), &ctx));
        assert!(!conditions_match(&json!(true), &ctx));
        assert!(!conditions_match(&Value::Null, &ctx));
    }

    #[test]
    fn mixed_conditions_are_and_logic_and_missing_fields_fail_closed() {
        let ctx = json!({
            "entity": {"kind": "human"},
            "object": {"kind": "resource"},
        });
        assert!(conditions_match(
            &json!({
                "entity.kind": "human",
                "object.kind": {"eq": "resource"}
            }),
            &ctx
        ));
        assert!(!conditions_match(
            &json!({
                "entity.kind": "human",
                "tenant.status": "active"
            }),
            &ctx
        ));
    }

    #[test]
    fn v1_abac_contract_matches_runtime() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../api/v1/persisted-semantics.json"))
                .expect("persisted-semantics contract");
        let strings = |field: &str| {
            contract["abac"][field]
                .as_array()
                .unwrap_or_else(|| panic!("missing ABAC contract {field}"))
                .iter()
                .map(|value| value.as_str().expect("ABAC string"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            abac_operator_names().collect::<Vec<_>>(),
            strings("operators")
        );
        assert_eq!(ABAC_CONTEXT_ROOTS, strings("pathRoots").as_slice());
        assert_eq!(contract["abac"]["conditionEntriesCombine"], "and");
        assert_eq!(contract["abac"]["operatorEntriesCombine"], "and");
        assert_eq!(contract["abac"]["emptyObjectMatches"], true);
        assert_eq!(contract["abac"]["missingPathMatches"], false);
        assert_eq!(contract["abac"]["unknownOperatorMatches"], false);
        assert_eq!(contract["abac"]["nonObjectConditionsMatch"], false);
    }
}
