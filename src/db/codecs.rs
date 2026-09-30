//! Native result codecs shared by domain adapters.
use uuid::Uuid;

/// A `uuid[]` result column. PostgreSQL returns a native array; SQLite returns
/// a JSON array of UUID strings from its native aggregation query.
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
