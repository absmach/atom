//! Test-only runner for paired, explicit PostgreSQL/SQLite fixture SQL.
//! This does not translate SQL and is never linked into the Atom service.
#![allow(dead_code)]
#[path = "db/arg.rs"]
mod arg;
use std::marker::PhantomData;

use sqlx::{
    postgres::{PgArguments, PgRow},
    sqlite::{SqliteArguments, SqliteRow},
    ColumnIndex, Decode, FromRow, Postgres, Sqlite, Type,
};

use self::arg::{Arg, DbArg};
use atom::db::{IntoTarget, Target};

/// Runs `$body` once per concrete executor type, binding the executor to `$e`.
/// The body is type-checked separately for each backend, which is what lets one
/// generic expression serve both drivers.
macro_rules! on_target {
    ($target:expr, locks = $locks:expr, pg($pe:ident) => $pg:expr, sqlite($se:ident) => $sq:expr $(,)?) => {
        match $target {
            Target::PoolPostgres($pe) => $pg,
            Target::ConnectionPostgres($pe) => {
                let $pe = &mut *$pe;
                $pg
            }
            Target::PoolSqlite(pool) => {
                if $locks {
                    // A PostgreSQL row lock (`FOR UPDATE`/`FOR SHARE`) makes the
                    // statement wait for concurrent writers. SQLite's equivalent
                    // is the single write lock, so run the statement inside
                    // `BEGIN IMMEDIATE`; an early `return` in the body leaves
                    // only this block, and the transaction always commits.
                    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                    let out: Result<_, sqlx::Error> = {
                        let $se = &mut *tx;
                        async { $sq }.await
                    };
                    tx.commit().await?;
                    out
                } else {
                    let mut pooled = pool.acquire().await?;
                    let $se = &mut *pooled;
                    $sq
                }
            }
            Target::ConnectionSqlite($se) => {
                let $se = &mut *$se;
                $sq
            }
        }
    };
}

/// Result of a statement that returns no rows.
#[derive(Debug, Clone, Copy)]
pub struct ExecResult {
    rows_affected: u64,
}

impl ExecResult {
    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }
}

/// A backend-neutral result row, for the few callers that read columns by name.
pub enum Row {
    Pg(PgRow),
    Sqlite(SqliteRow),
}

impl Row {
    /// Panicking variant of [`Row::try_get`], for tests and assertions.
    pub fn get<'r, T, I>(&'r self, index: I) -> T
    where
        I: ColumnIndex<PgRow> + ColumnIndex<SqliteRow> + std::fmt::Display + Copy,
        T: Decode<'r, Postgres> + Type<Postgres> + Decode<'r, Sqlite> + Type<Sqlite>,
    {
        self.try_get(index)
            .unwrap_or_else(|e| panic!("column {index}: {e}"))
    }

    pub fn try_get<'r, T, I>(&'r self, index: I) -> Result<T, sqlx::Error>
    where
        I: ColumnIndex<PgRow> + ColumnIndex<SqliteRow>,
        T: Decode<'r, Postgres> + Type<Postgres> + Decode<'r, Sqlite> + Type<Sqlite>,
    {
        use sqlx::Row as _;
        match self {
            Row::Pg(row) => row.try_get(index),
            Row::Sqlite(row) => row.try_get(index),
        }
    }
}

/// Rows a struct can be decoded from on both backends.
pub trait DbRow:
    for<'r> FromRow<'r, PgRow> + for<'r> FromRow<'r, SqliteRow> + Send + Unpin
{
}
impl<T> DbRow for T where
    T: for<'r> FromRow<'r, PgRow> + for<'r> FromRow<'r, SqliteRow> + Send + Unpin
{
}

/// A single column decodable on both backends.
pub trait DbScalar:
    for<'r> Decode<'r, Postgres>
    + Type<Postgres>
    + for<'r> Decode<'r, Sqlite>
    + Type<Sqlite>
    + Send
    + Unpin
{
}
impl<T> DbScalar for T where
    T: for<'r> Decode<'r, Postgres>
        + Type<Postgres>
        + for<'r> Decode<'r, Sqlite>
        + Type<Sqlite>
        + Send
        + Unpin
{
}

/// Diagnostics for a failing explicit SQLite fixture statement.
fn trace<T>(sql: &str, result: Result<T, sqlx::Error>) -> Result<T, sqlx::Error> {
    if let Err(e) = &result {
        tracing::debug!(target: "atom::db::sqlite", error = %e, sql = %sql, "SQLite statement failed");
    }
    result
}

#[derive(Default)]
struct Body {
    sql: String,
    args: Vec<Arg>,
    sqlite_sql: Vec<String>,
    locks_rows: bool,
}

impl Body {
    /// Explicit lock intent supplied by the fixture.
    fn locks_rows(&self) -> bool {
        self.locks_rows
    }

    fn pg_arguments(&self) -> Result<PgArguments, sqlx::Error> {
        let mut out = PgArguments::default();
        for arg in &self.args {
            arg.add_pg(&mut out).map_err(sqlx::Error::Encode)?;
        }
        Ok(out)
    }

    /// Bind the explicitly supplied native SQLite fixture statement.
    fn sqlite_prepared(&self) -> Result<Vec<(String, SqliteArguments<'static>)>, sqlx::Error> {
        let statements = self.sqlite_sql.clone();
        statements
            .into_iter()
            .map(|sql| {
                let mut out = SqliteArguments::default();
                for arg in &self.args {
                    arg.add_sqlite(&mut out).map_err(sqlx::Error::Encode)?;
                }
                Ok((sql, out))
            })
            .collect()
    }

    async fn execute(&self, target: Target<'_>) -> Result<ExecResult, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                let res = sqlx::query_with(&self.sql, args).execute(e).await?;
                Ok(ExecResult { rows_affected: res.rows_affected() })
            },
            sqlite(e) => {
                let mut rows_affected = 0;
                for (sql, args) in self.sqlite_prepared()? {
                    let res = trace(&sql, sqlx::query_with(&sql, args).execute(&mut *e).await)?;
                    rows_affected += res.rows_affected();
                }
                Ok(ExecResult { rows_affected })
            },
        )
    }

    async fn fetch_all(&self, target: Target<'_>) -> Result<Vec<Row>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                let rows = sqlx::query_with(&self.sql, args).fetch_all(e).await?;
                Ok(rows.into_iter().map(Row::Pg).collect())
            },
            sqlite(e) => {
                let mut out = Vec::new();
                for (sql, args) in self.sqlite_prepared()? {
                    let rows = trace(&sql, sqlx::query_with(&sql, args).fetch_all(&mut *e).await)?;
                    out.extend(rows.into_iter().map(Row::Sqlite));
                }
                Ok(out)
            },
        )
    }

    async fn fetch_optional(&self, target: Target<'_>) -> Result<Option<Row>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                let row = sqlx::query_with(&self.sql, args).fetch_optional(e).await?;
                Ok(row.map(Row::Pg))
            },
            sqlite(e) => {
                for (sql, args) in self.sqlite_prepared()? {
                    let row = trace(&sql, sqlx::query_with(&sql, args).fetch_optional(&mut *e).await)?;
                    if let Some(row) = row {
                        return Ok(Some(Row::Sqlite(row)));
                    }
                }
                Ok(None)
            },
        )
    }

    async fn fetch_all_as<O: DbRow>(&self, target: Target<'_>) -> Result<Vec<O>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                sqlx::query_as_with::<Postgres, O, _>(&self.sql, args).fetch_all(e).await
            },
            sqlite(e) => {
                let mut out = Vec::new();
                for (sql, args) in self.sqlite_prepared()? {
                    out.extend(trace(&sql, sqlx::query_as_with::<Sqlite, O, _>(&sql, args).fetch_all(&mut *e).await)?);
                }
                Ok(out)
            },
        )
    }

    async fn fetch_optional_as<O: DbRow>(
        &self,
        target: Target<'_>,
    ) -> Result<Option<O>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                sqlx::query_as_with::<Postgres, O, _>(&self.sql, args).fetch_optional(e).await
            },
            sqlite(e) => {
                for (sql, args) in self.sqlite_prepared()? {
                    if let Some(row) = trace(&sql, sqlx::query_as_with::<Sqlite, O, _>(&sql, args).fetch_optional(&mut *e).await)? {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            },
        )
    }

    async fn fetch_all_scalar<O: DbScalar>(
        &self,
        target: Target<'_>,
    ) -> Result<Vec<O>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                sqlx::query_scalar_with::<Postgres, O, _>(&self.sql, args).fetch_all(e).await
            },
            sqlite(e) => {
                let mut out = Vec::new();
                for (sql, args) in self.sqlite_prepared()? {
                    out.extend(trace(&sql, sqlx::query_scalar_with::<Sqlite, O, _>(&sql, args).fetch_all(&mut *e).await)?);
                }
                Ok(out)
            },
        )
    }

    async fn fetch_optional_scalar<O: DbScalar>(
        &self,
        target: Target<'_>,
    ) -> Result<Option<O>, sqlx::Error> {
        on_target!(target,
            locks = self.locks_rows(),
            pg(e) => {
                let args = self.pg_arguments()?;
                sqlx::query_scalar_with::<Postgres, O, _>(&self.sql, args).fetch_optional(e).await
            },
            sqlite(e) => {
                for (sql, args) in self.sqlite_prepared()? {
                    if let Some(row) = trace(&sql, sqlx::query_scalar_with::<Sqlite, O, _>(&sql, args).fetch_optional(&mut *e).await)? {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            },
        )
    }
}

macro_rules! builder_methods {
    () => {
        pub fn bind<V: DbArg>(mut self, value: V) -> Self {
            self.body.args.push(value.into_arg());
            self
        }

        /// Reserve SQLite's single writer for a row-lock fixture.
        pub fn locked(mut self) -> Self {
            self.body.locks_rows = true;
            self
        }
    };
}

/// `sqlx::query` equivalent: a statement whose rows are read by column name.
pub struct Query {
    body: Body,
}

pub fn query(sql: &str, sqlite: &str) -> Query {
    Query {
        body: Body {
            sql: sql.to_owned(),
            sqlite_sql: vec![sqlite.to_owned()],
            ..Body::default()
        },
    }
}

impl Query {
    builder_methods!();

    pub async fn execute<'a>(self, target: impl IntoTarget<'a>) -> Result<ExecResult, sqlx::Error> {
        self.body.execute(target.into_target()).await
    }

    pub async fn fetch_all<'a>(self, target: impl IntoTarget<'a>) -> Result<Vec<Row>, sqlx::Error> {
        self.body.fetch_all(target.into_target()).await
    }

    pub async fn fetch_optional<'a>(
        self,
        target: impl IntoTarget<'a>,
    ) -> Result<Option<Row>, sqlx::Error> {
        self.body.fetch_optional(target.into_target()).await
    }

    pub async fn fetch_one<'a>(self, target: impl IntoTarget<'a>) -> Result<Row, sqlx::Error> {
        self.fetch_optional(target)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }
}

/// `sqlx::query_as` equivalent: rows decoded into `T`.
pub struct QueryAs<T> {
    body: Body,
    _row: PhantomData<fn() -> T>,
}

pub fn query_as<T: DbRow>(sql: &str, sqlite: &str) -> QueryAs<T> {
    QueryAs {
        body: Body {
            sql: sql.to_owned(),
            sqlite_sql: vec![sqlite.to_owned()],
            ..Body::default()
        },
        _row: PhantomData,
    }
}

impl<T: DbRow> QueryAs<T> {
    builder_methods!();

    pub async fn fetch_all<'a>(self, target: impl IntoTarget<'a>) -> Result<Vec<T>, sqlx::Error> {
        self.body.fetch_all_as(target.into_target()).await
    }

    pub async fn fetch_optional<'a>(
        self,
        target: impl IntoTarget<'a>,
    ) -> Result<Option<T>, sqlx::Error> {
        self.body.fetch_optional_as(target.into_target()).await
    }

    pub async fn fetch_one<'a>(self, target: impl IntoTarget<'a>) -> Result<T, sqlx::Error> {
        self.fetch_optional(target)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }
}

/// `sqlx::query_scalar` equivalent: the first column of each row.
pub struct QueryScalar<T> {
    body: Body,
    _row: PhantomData<fn() -> T>,
}

pub fn query_scalar<T: DbScalar>(sql: &str, sqlite: &str) -> QueryScalar<T> {
    QueryScalar {
        body: Body {
            sql: sql.to_owned(),
            sqlite_sql: vec![sqlite.to_owned()],
            ..Body::default()
        },
        _row: PhantomData,
    }
}

impl<T: DbScalar> QueryScalar<T> {
    builder_methods!();

    pub async fn fetch_all<'a>(self, target: impl IntoTarget<'a>) -> Result<Vec<T>, sqlx::Error> {
        self.body.fetch_all_scalar(target.into_target()).await
    }

    pub async fn fetch_optional<'a>(
        self,
        target: impl IntoTarget<'a>,
    ) -> Result<Option<T>, sqlx::Error> {
        self.body.fetch_optional_scalar(target.into_target()).await
    }

    pub async fn fetch_one<'a>(self, target: impl IntoTarget<'a>) -> Result<T, sqlx::Error> {
        self.fetch_optional(target)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }
}
