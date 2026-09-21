//! Backend-neutral bound query parameters.
//!
//! A query is built once and executed against whichever backend the caller's
//! [`crate::db::Database`] holds, so its parameters cannot be typed to one
//! driver. [`Arg`] keeps each value in a neutral form and encodes it per
//! backend at execution time: natively for PostgreSQL, and in the SQLite
//! storage encodings documented in `product-docs/development/database-backends/`
//! (UUID as a 16-byte blob, timestamps as fixed-width UTC text, JSON and arrays
//! as JSON text).

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{postgres::PgArguments, sqlite::SqliteArguments, Arguments};
use uuid::Uuid;

/// The kind of a bound value. SQLite translation needs it (an `ANY($1)` over a
/// UUID array must decode blobs, over a text array must not), and a typed NULL
/// needs it on PostgreSQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgKind {
    Bool,
    I16,
    I32,
    I64,
    F64,
    Text,
    Uuid,
    Timestamp,
    Json,
    Bytes,
    UuidArray,
    TextArray,
    I64Array,
}

#[derive(Debug, Clone)]
pub enum Arg {
    Null(ArgKind),
    Bool(bool),
    I16(i16),
    I32(i32),
    I64(i64),
    F64(f64),
    Text(String),
    Uuid(Uuid),
    Timestamp(DateTime<Utc>),
    Json(Value),
    Bytes(Vec<u8>),
    UuidArray(Vec<Uuid>),
    TextArray(Vec<String>),
    I64Array(Vec<i64>),
}

impl Arg {
    pub fn is_null(&self) -> bool {
        matches!(self, Arg::Null(_))
    }

    pub fn kind(&self) -> ArgKind {
        match self {
            Arg::Null(kind) => *kind,
            Arg::Bool(_) => ArgKind::Bool,
            Arg::I16(_) => ArgKind::I16,
            Arg::I32(_) => ArgKind::I32,
            Arg::I64(_) => ArgKind::I64,
            Arg::F64(_) => ArgKind::F64,
            Arg::Text(_) => ArgKind::Text,
            Arg::Uuid(_) => ArgKind::Uuid,
            Arg::Timestamp(_) => ArgKind::Timestamp,
            Arg::Json(_) => ArgKind::Json,
            Arg::Bytes(_) => ArgKind::Bytes,
            Arg::UuidArray(_) => ArgKind::UuidArray,
            Arg::TextArray(_) => ArgKind::TextArray,
            Arg::I64Array(_) => ArgKind::I64Array,
        }
    }

    pub(crate) fn add_pg(&self, args: &mut PgArguments) -> Result<(), sqlx::error::BoxDynError> {
        match self {
            Arg::Null(kind) => match kind {
                ArgKind::Bool => args.add(None::<bool>),
                ArgKind::I16 => args.add(None::<i16>),
                ArgKind::I32 => args.add(None::<i32>),
                ArgKind::I64 => args.add(None::<i64>),
                ArgKind::F64 => args.add(None::<f64>),
                ArgKind::Text => args.add(None::<String>),
                ArgKind::Uuid => args.add(None::<Uuid>),
                ArgKind::Timestamp => args.add(None::<DateTime<Utc>>),
                ArgKind::Json => args.add(None::<Value>),
                ArgKind::Bytes => args.add(None::<Vec<u8>>),
                ArgKind::UuidArray => args.add(None::<Vec<Uuid>>),
                ArgKind::TextArray => args.add(None::<Vec<String>>),
                ArgKind::I64Array => args.add(None::<Vec<i64>>),
            },
            Arg::Bool(v) => args.add(*v),
            Arg::I16(v) => args.add(*v),
            Arg::I32(v) => args.add(*v),
            Arg::I64(v) => args.add(*v),
            Arg::F64(v) => args.add(*v),
            Arg::Text(v) => args.add(v.clone()),
            Arg::Uuid(v) => args.add(*v),
            Arg::Timestamp(v) => args.add(*v),
            Arg::Json(v) => args.add(v.clone()),
            Arg::Bytes(v) => args.add(v.clone()),
            Arg::UuidArray(v) => args.add(v.clone()),
            Arg::TextArray(v) => args.add(v.clone()),
            Arg::I64Array(v) => args.add(v.clone()),
        }
    }

    pub(crate) fn add_sqlite(
        &self,
        args: &mut SqliteArguments<'_>,
    ) -> Result<(), sqlx::error::BoxDynError> {
        match self {
            Arg::Null(_) => args.add(None::<String>),
            Arg::Bool(v) => args.add(*v),
            Arg::I16(v) => args.add(*v),
            Arg::I32(v) => args.add(*v),
            Arg::I64(v) => args.add(*v),
            Arg::F64(v) => args.add(*v),
            Arg::Text(v) => args.add(v.clone()),
            // sqlx encodes `Uuid` as a 16-byte blob on SQLite.
            Arg::Uuid(v) => args.add(*v),
            Arg::Timestamp(v) => args.add(sqlite_timestamp(v)),
            Arg::Json(v) => args.add(v.to_string()),
            Arg::Bytes(v) => args.add(v.clone()),
            Arg::UuidArray(v) => args.add(
                serde_json::to_string(
                    &v.iter().map(|u| u.simple().to_string()).collect::<Vec<_>>(),
                )
                .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?,
            ),
            Arg::TextArray(v) => args.add(
                serde_json::to_string(v).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?,
            ),
            Arg::I64Array(v) => args.add(
                serde_json::to_string(v).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?,
            ),
        }
    }
}

/// The one SQLite timestamp representation: fixed-width UTC RFC 3339 with
/// microseconds. Fixed width is what makes text comparison equal time
/// comparison, so `created_at < $1` needs no date functions.
pub fn sqlite_timestamp(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// A Rust value that can be bound as a query parameter on either backend.
pub trait DbArg {
    const KIND: ArgKind;
    fn into_arg(self) -> Arg;
}

macro_rules! impl_db_arg {
    ($ty:ty, $kind:ident, |$v:ident| $conv:expr) => {
        impl DbArg for $ty {
            const KIND: ArgKind = ArgKind::$kind;
            fn into_arg(self) -> Arg {
                let $v = self;
                $conv
            }
        }
    };
}

impl_db_arg!(bool, Bool, |v| Arg::Bool(v));
impl_db_arg!(i16, I16, |v| Arg::I16(v));
impl_db_arg!(i32, I32, |v| Arg::I32(v));
impl_db_arg!(i64, I64, |v| Arg::I64(v));
impl_db_arg!(f64, F64, |v| Arg::F64(v));
impl_db_arg!(String, Text, |v| Arg::Text(v));
impl_db_arg!(&str, Text, |v| Arg::Text(v.to_owned()));
impl_db_arg!(&String, Text, |v| Arg::Text(v.clone()));
impl_db_arg!(Uuid, Uuid, |v| Arg::Uuid(v));
impl_db_arg!(&Uuid, Uuid, |v| Arg::Uuid(*v));
impl_db_arg!(DateTime<Utc>, Timestamp, |v| Arg::Timestamp(v));
impl_db_arg!(&DateTime<Utc>, Timestamp, |v| Arg::Timestamp(*v));
impl_db_arg!(Value, Json, |v| Arg::Json(v));
impl_db_arg!(&Value, Json, |v| Arg::Json(v.clone()));
impl_db_arg!(Vec<u8>, Bytes, |v| Arg::Bytes(v));
impl_db_arg!(&[u8], Bytes, |v| Arg::Bytes(v.to_vec()));
impl_db_arg!(Vec<Uuid>, UuidArray, |v| Arg::UuidArray(v));
impl_db_arg!(&Vec<Uuid>, UuidArray, |v| Arg::UuidArray(v.clone()));
impl_db_arg!(&[Uuid], UuidArray, |v| Arg::UuidArray(v.to_vec()));
impl_db_arg!(Vec<String>, TextArray, |v| Arg::TextArray(v));
impl_db_arg!(&Vec<String>, TextArray, |v| Arg::TextArray(v.clone()));
impl_db_arg!(&[String], TextArray, |v| Arg::TextArray(v.to_vec()));
impl_db_arg!(Vec<&str>, TextArray, |v| Arg::TextArray(
    v.into_iter().map(str::to_owned).collect()
));
impl_db_arg!(&[&str], TextArray, |v| Arg::TextArray(
    v.iter().map(|s| (*s).to_owned()).collect()
));
impl_db_arg!(&Vec<&str>, TextArray, |v| Arg::TextArray(
    v.iter().map(|s| (*s).to_owned()).collect()
));
impl_db_arg!(Vec<i64>, I64Array, |v| Arg::I64Array(v));
impl_db_arg!(&[i64], I64Array, |v| Arg::I64Array(v.to_vec()));

impl<T: DbArg> DbArg for Option<T> {
    const KIND: ArgKind = T::KIND;
    fn into_arg(self) -> Arg {
        match self {
            Some(v) => v.into_arg(),
            None => Arg::Null(T::KIND),
        }
    }
}

impl<T: DbArg + Clone> DbArg for &Option<T> {
    const KIND: ArgKind = T::KIND;
    fn into_arg(self) -> Arg {
        self.clone().into_arg()
    }
}

/// Text form of a serde-serialised string enum, which is how every database
/// enum column stores its value (`#[serde(rename_all = ...)]` matches the
/// `CHECK` constraints; a contract test pins the two together).
pub fn enum_text<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(s)) => s,
        // A unit-variant enum always serialises to a string; anything else is a
        // programming error that the CHECK constraint would reject anyway.
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

/// Implements [`DbArg`] (by value and by reference) for string enums.
#[macro_export]
macro_rules! impl_db_enum_arg {
    ($($ty:ty),+ $(,)?) => {$(
        impl $crate::db::DbArg for $ty {
            const KIND: $crate::db::ArgKind = $crate::db::ArgKind::Text;
            fn into_arg(self) -> $crate::db::Arg {
                $crate::db::Arg::Text($crate::db::enum_text(&self))
            }
        }
        impl $crate::db::DbArg for &$ty {
            const KIND: $crate::db::ArgKind = $crate::db::ArgKind::Text;
            fn into_arg(self) -> $crate::db::Arg {
                $crate::db::Arg::Text($crate::db::enum_text(self))
            }
        }
    )+};
}

/// A `uuid[]` result column. PostgreSQL returns a native array; SQLite returns
/// the JSON array text that `array_agg` translates to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UuidList(pub Vec<Uuid>);

impl sqlx::Type<sqlx::Postgres> for UuidList {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<Uuid> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<Uuid> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for UuidList {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Self(<Vec<Uuid> as sqlx::Decode<sqlx::Postgres>>::decode(
            value,
        )?))
    }
}
impl sqlx::Type<sqlx::Sqlite> for UuidList {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <str as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        <str as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
    }
}
impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for UuidList {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let text = <&str as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let items: Vec<String> = serde_json::from_str(text)?;
        items
            .iter()
            .map(|s| Uuid::parse_str(s).map_err(Into::into))
            .collect::<Result<Vec<_>, sqlx::error::BoxDynError>>()
            .map(Self)
    }
}
impl std::ops::Deref for UuidList {
    type Target = Vec<Uuid>;
    fn deref(&self) -> &Vec<Uuid> {
        &self.0
    }
}
impl From<UuidList> for Vec<Uuid> {
    fn from(list: UuidList) -> Self {
        list.0
    }
}

/// A `text[]` result column, with the same two encodings as [`UuidList`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextList(pub Vec<String>);

impl sqlx::Type<sqlx::Postgres> for TextList {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for TextList {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Self(<Vec<String> as sqlx::Decode<sqlx::Postgres>>::decode(
            value,
        )?))
    }
}
impl sqlx::Type<sqlx::Sqlite> for TextList {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <str as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        <str as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
    }
}
impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for TextList {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let text = <&str as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        Ok(Self(serde_json::from_str(text)?))
    }
}
impl std::ops::Deref for TextList {
    type Target = Vec<String>;
    fn deref(&self) -> &Vec<String> {
        &self.0
    }
}
impl From<TextList> for Vec<String> {
    fn from(list: TextList) -> Self {
        list.0
    }
}
