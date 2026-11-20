use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::AppError;

use super::enums::{DeletedFilter, ResourceOrderField, SortDir};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Resource {
    pub id: Uuid,
    /// Revision from the same database snapshot as the object attributes.
    pub revision: i64,
    pub kind: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub attributes: Value,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    /// `Some("config")` when provisioned from the bootstrap YAML.
    #[sqlx(default)]
    pub managed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateResource {
    pub id: Option<Uuid>,
    pub kind: String,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateResource {
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::models::alias::deserialize_alias_update"
    )]
    pub alias: Option<Option<String>>,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListResources {
    pub q: Option<String>,
    pub kind: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub attributes_contains: Option<Value>,
    pub parent_group_id: Option<Uuid>,
    pub include_descendants: bool,
    #[serde(default)]
    pub deleted: DeletedFilter,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub order: ResourceOrderField,
    #[serde(default)]
    pub dir: SortDir,
    /// Ordering by, and filtering on, values inside `attributes`. Built only
    /// through `ResourceAttributeQuery::new`, never deserialized.
    #[serde(skip)]
    pub attrs: ResourceAttributeQuery,
}

fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct ResourceList {
    pub items: Vec<Resource>,
    pub total: i64,
}

/// How an attribute value is compared when ordering by it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeValueType {
    /// Compare `attributes->>key` as text (binary collation on both backends).
    #[default]
    Text,
    /// Compare numerically; a non-numeric or missing value counts as null.
    Number,
}

const MAX_ATTRIBUTE_KEY_LEN: usize = 64;
const MAX_ATTRIBUTES_IN_KEYS: usize = 20;
const MAX_ATTRIBUTES_IN_VALUES: usize = 200;
const MAX_ATTRIBUTES_IN_STRING_LEN: usize = 256;

/// Validated attribute-aware listing options for resources: an optional
/// ordering by one top-level attribute and an optional any-of filter.
///
/// Built only through [`ResourceAttributeQuery::new`], so every key reaching a
/// SQL adapter is a plain identifier. Adapters still bind keys as parameters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourceAttributeQuery {
    order_attribute: Option<String>,
    order_type: AttributeValueType,
    attributes_in: Option<Value>,
}

fn valid_attribute_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && key.len() <= MAX_ATTRIBUTE_KEY_LEN
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl ResourceAttributeQuery {
    pub fn new(
        order_attribute: Option<String>,
        order_type: Option<AttributeValueType>,
        attributes_in: Option<Value>,
    ) -> Result<Self, AppError> {
        if let Some(key) = &order_attribute {
            if !valid_attribute_key(key) {
                return Err(AppError::bad_request(
                    "orderAttribute must be a plain key: letters, digits and underscores, \
                     starting with a letter or underscore, at most 64 characters",
                ));
            }
        } else if order_type.is_some() {
            return Err(AppError::bad_request(
                "orderAttributeType requires orderAttribute",
            ));
        }

        let attributes_in = match attributes_in {
            None | Some(Value::Null) => None,
            Some(value) => Self::validate_attributes_in(&value)?,
        };

        Ok(Self {
            order_attribute,
            order_type: order_type.unwrap_or_default(),
            attributes_in,
        })
    }

    /// `Ok(None)` for an empty object: nothing to filter on.
    fn validate_attributes_in(value: &Value) -> Result<Option<Value>, AppError> {
        let Value::Object(map) = value else {
            return Err(AppError::bad_request(
                "attributesIn must be an object mapping attribute keys to arrays of values",
            ));
        };
        if map.is_empty() {
            return Ok(None);
        }
        if map.len() > MAX_ATTRIBUTES_IN_KEYS {
            return Err(AppError::bad_request(format!(
                "attributesIn accepts at most {MAX_ATTRIBUTES_IN_KEYS} keys"
            )));
        }
        let mut total = 0usize;
        for (key, values) in map {
            if !valid_attribute_key(key) {
                return Err(AppError::bad_request(
                    "attributesIn keys must be plain keys: letters, digits and underscores, \
                     starting with a letter or underscore, at most 64 characters",
                ));
            }
            let Value::Array(values) = values else {
                return Err(AppError::bad_request(
                    "every attributesIn value must be an array of values",
                ));
            };
            if values.is_empty() {
                return Err(AppError::bad_request(
                    "attributesIn arrays must not be empty",
                ));
            }
            if values
                .iter()
                .any(|v| matches!(v, Value::Array(_) | Value::Object(_)))
            {
                return Err(AppError::bad_request(
                    "attributesIn arrays may only contain strings, numbers, booleans or null",
                ));
            }
            if values.iter().any(
                |v| matches!(v, Value::String(s) if s.chars().count() > MAX_ATTRIBUTES_IN_STRING_LEN),
            ) {
                return Err(AppError::bad_request(format!(
                    "attributesIn strings may be at most {MAX_ATTRIBUTES_IN_STRING_LEN} characters"
                )));
            }
            total += values.len();
            if total > MAX_ATTRIBUTES_IN_VALUES {
                return Err(AppError::bad_request(format!(
                    "attributesIn accepts at most {MAX_ATTRIBUTES_IN_VALUES} values in total"
                )));
            }
        }
        Ok(Some(value.clone()))
    }

    pub fn order_attribute(&self) -> Option<&str> {
        self.order_attribute.as_deref()
    }

    pub fn order_type(&self) -> AttributeValueType {
        self.order_type
    }

    pub fn attributes_in(&self) -> Option<&Value> {
        self.attributes_in.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attrs_in(v: Value) -> Result<ResourceAttributeQuery, AppError> {
        ResourceAttributeQuery::new(None, None, Some(v))
    }

    #[test]
    fn defaults_are_inert() {
        let q = ResourceAttributeQuery::new(None, None, None).unwrap();
        assert_eq!(q, ResourceAttributeQuery::default());
        assert!(q.order_attribute().is_none() && q.attributes_in().is_none());
        assert!(attrs_in(json!({})).unwrap().attributes_in().is_none());
        assert!(attrs_in(Value::Null).unwrap().attributes_in().is_none());
    }

    #[test]
    fn order_attribute_must_be_a_plain_identifier() {
        for ok in ["relevance_score", "_x", "A1", &"a".repeat(64)] {
            assert!(ResourceAttributeQuery::new(Some(ok.into()), None, None).is_ok());
        }
        for bad in [
            "",
            "1a",
            "a-b",
            "a.b",
            "a b",
            "a'b",
            "a\"b",
            "é",
            &"a".repeat(65),
        ] {
            assert!(
                ResourceAttributeQuery::new(Some(bad.into()), None, None).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn order_type_requires_order_attribute() {
        assert!(ResourceAttributeQuery::new(None, Some(AttributeValueType::Number), None).is_err());
        let q = ResourceAttributeQuery::new(
            Some("score".into()),
            Some(AttributeValueType::Number),
            None,
        )
        .unwrap();
        assert_eq!(q.order_type(), AttributeValueType::Number);
        let q = ResourceAttributeQuery::new(Some("score".into()), None, None).unwrap();
        assert_eq!(q.order_type(), AttributeValueType::Text);
    }

    #[test]
    fn attributes_in_accepts_scalar_arrays() {
        let v = json!({"product_slug": ["a", "b", ""], "n": [1, 2.5], "f": [true, null]});
        assert_eq!(attrs_in(v.clone()).unwrap().attributes_in(), Some(&v));
    }

    #[test]
    fn attributes_in_rejects_bad_shapes() {
        for bad in [
            json!([]),
            json!("x"),
            json!({"k": "a"}),
            json!({"k": []}),
            json!({"k": [["a"]]}),
            json!({"k": [{"a": 1}]}),
            json!({"bad-key": ["a"]}),
            json!({"": ["a"]}),
        ] {
            assert!(attrs_in(bad.clone()).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn attributes_in_caps_string_length() {
        assert!(attrs_in(json!({"k": ["a".repeat(256)]})).is_ok());
        assert!(attrs_in(json!({"k": ["a".repeat(257)]})).is_err());
    }

    #[test]
    fn attributes_in_enforces_size_limits() {
        let keys: serde_json::Map<String, Value> =
            (0..20).map(|i| (format!("k{i}"), json!(["a"]))).collect();
        assert!(attrs_in(Value::Object(keys)).is_ok());
        let keys: serde_json::Map<String, Value> =
            (0..21).map(|i| (format!("k{i}"), json!(["a"]))).collect();
        assert!(attrs_in(Value::Object(keys)).is_err());

        let values: Vec<Value> = (0..200).map(|i| json!(i)).collect();
        assert!(attrs_in(json!({"k": values})).is_ok());
        let values: Vec<Value> = (0..201).map(|i| json!(i)).collect();
        assert!(attrs_in(json!({"k": values})).is_err());
        let a: Vec<Value> = (0..100).map(|i| json!(i)).collect();
        let b: Vec<Value> = (0..101).map(|i| json!(i)).collect();
        assert!(attrs_in(json!({"a": a, "b": b})).is_err());
    }
}
