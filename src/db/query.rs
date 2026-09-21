//! The single query layer every repository and service goes through.
//!
//! `query`, `query_as` and `query_scalar` mirror their `sqlx` namesakes, but
//! execute against a [`Target`] (a [`crate::db::Database`], a
//! [`crate::db::DbTransaction`], or a pooled [`crate::db::DbConn`]) and so run on
//! PostgreSQL or SQLite without the caller naming a driver.
//!
//! SQL text is written once, in the PostgreSQL dialect. PostgreSQL executes it
//! unchanged; SQLite executes a translation of it (see [`super::translate`]),
//! or the query's explicit [`Query::sqlite`] override when the construct has no
//! mechanical translation (recursive array walks, `LATERAL`, and the like).

use std::marker::PhantomData;

use sqlx::{
    postgres::{PgArguments, PgRow},
    sqlite::{SqliteArguments, SqliteRow},
    ColumnIndex, Decode, FromRow, PgConnection, PgPool, Postgres, Sqlite, SqliteConnection,
    SqlitePool, Type,
};

use super::{
    arg::{Arg, DbArg},
    Database, DbConn, DbTransaction,
};

/// Where a query runs.
pub enum Target<'a> {
    PgPool(&'a PgPool),
    PgConn(&'a mut PgConnection),
    SqlitePool(&'a SqlitePool),
    SqliteConn(&'a mut SqliteConnection),
}

/// Anything a query can run against.
pub trait IntoTarget<'a> {
    fn into_target(self) -> Target<'a>;
}

impl<'a> IntoTarget<'a> for &'a Database {
    fn into_target(self) -> Target<'a> {
        match self {
            Database::Postgres(pool) => Target::PgPool(pool),
            Database::Sqlite(db) => Target::SqlitePool(&db.pool),
        }
    }
}

impl<'a, 'b: 'a> IntoTarget<'a> for &'a &'b Database {
    fn into_target(self) -> Target<'a> {
        (*self).into_target()
    }
}

/// A connection-like handle a query can run on: an open transaction or a pooled
/// connection. Functions that must work inside either take
/// `&mut impl DbExecutor`.
pub trait DbExecutor {
    fn executor(&mut self) -> Target<'_>;
}

impl DbExecutor for DbTransaction<'_> {
    fn executor(&mut self) -> Target<'_> {
        match self {
            DbTransaction::Postgres(tx) => Target::PgConn(tx),
            DbTransaction::Sqlite(tx) => Target::SqliteConn(tx),
        }
    }
}

impl DbExecutor for DbConn {
    fn executor(&mut self) -> Target<'_> {
        match self {
            DbConn::Postgres(conn) => Target::PgConn(conn),
            DbConn::Sqlite(conn) => Target::SqliteConn(conn),
        }
    }
}

impl<T: DbExecutor + ?Sized> DbExecutor for &mut T {
    fn executor(&mut self) -> Target<'_> {
        (**self).executor()
    }
}

impl<'a, E: DbExecutor + ?Sized> IntoTarget<'a> for &'a mut E {
    fn into_target(self) -> Target<'a> {
        self.executor()
    }
}

impl<'a> IntoTarget<'a> for &'a PgPool {
    fn into_target(self) -> Target<'a> {
        Target::PgPool(self)
    }
}

impl<'a> IntoTarget<'a> for &'a mut PgConnection {
    fn into_target(self) -> Target<'a> {
        Target::PgConn(self)
    }
}

/// Runs `$body` once per concrete executor type, binding the executor to `$e`.
/// The body is type-checked separately for each backend, which is what lets one
/// generic expression serve both drivers.
macro_rules! on_target {
    ($target:expr, locks = $locks:expr, pg($pe:ident) => $pg:expr, sqlite($se:ident) => $sq:expr $(,)?) => {
        match $target {
            Target::PgPool($pe) => $pg,
            Target::PgConn($pe) => {
                let $pe = &mut *$pe;
                $pg
            }
            Target::SqlitePool(pool) => {
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
            Target::SqliteConn($se) => {
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

/// Logs the statement SQLite rejected (the translation, not the source text) so
/// a parity gap can be located from a bare "near X: syntax error".
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
}

impl Body {
    /// True when the PostgreSQL text takes row locks.
    fn locks_rows(&self) -> bool {
        super::translate::takes_row_locks(&self.sql)
    }

    fn pg_arguments(&self) -> Result<PgArguments, sqlx::Error> {
        let mut out = PgArguments::default();
        for arg in &self.args {
            arg.add_pg(&mut out).map_err(sqlx::Error::Encode)?;
        }
        Ok(out)
    }

    /// The SQLite statements to run, each with its own copy of the arguments:
    /// the explicit override(s) when given, else the translation of `sql`.
    fn sqlite_prepared(&self) -> Result<Vec<(String, SqliteArguments<'static>)>, sqlx::Error> {
        let statements = if self.sqlite_sql.is_empty() {
            let kinds: Vec<_> = self.args.iter().map(Arg::kind).collect();
            let nulls: Vec<_> = self.args.iter().map(Arg::is_null).collect();
            vec![super::translate::to_sqlite(&self.sql, &kinds, &nulls)]
        } else {
            self.sqlite_sql.clone()
        };
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

        /// The SQLite form of this statement, for constructs the mechanical
        /// PostgreSQL→SQLite translation cannot express. Placeholders keep their
        /// `$N` numbering and bind the same arguments.
        pub fn sqlite(mut self, sql: &str) -> Self {
            self.body.sqlite_sql = vec![sql.to_owned()];
            self
        }

        /// SQLite has no data-modifying CTEs (`WITH x AS (UPDATE …)`). A
        /// statement built from independent branches is instead run as these
        /// statements in order, all bound to the same arguments: `fetch_all`
        /// concatenates their rows, `fetch_optional` takes the first row any of
        /// them returns, and `execute` sums the rows affected.
        pub fn sqlite_all(mut self, statements: &[&str]) -> Self {
            self.body.sqlite_sql = statements.iter().map(|s| (*s).to_owned()).collect();
            self
        }
    };
}

/// `sqlx::query` equivalent: a statement whose rows are read by column name.
pub struct Query {
    body: Body,
}

pub fn query(sql: &str) -> Query {
    Query {
        body: Body {
            sql: sql.to_owned(),
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

pub fn query_as<T: DbRow>(sql: &str) -> QueryAs<T> {
    QueryAs {
        body: Body {
            sql: sql.to_owned(),
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

pub fn query_scalar<T: DbScalar>(sql: &str) -> QueryScalar<T> {
    QueryScalar {
        body: Body {
            sql: sql.to_owned(),
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

/// `sqlx::QueryBuilder` equivalent for statements assembled at runtime.
#[derive(Default)]
pub struct QueryBuilder {
    body: Body,
}

impl QueryBuilder {
    pub fn new(sql: &str) -> Self {
        Self {
            body: Body {
                sql: sql.to_owned(),
                ..Body::default()
            },
        }
    }

    pub fn push(&mut self, sql: &str) -> &mut Self {
        self.body.sql.push_str(sql);
        self
    }

    /// Appends the next `$N` placeholder and records its value.
    pub fn push_bind<T: DbArg>(&mut self, value: T) -> &mut Self {
        self.body.args.push(value.into_arg());
        self.body.sql.push('$');
        self.body.sql.push_str(&self.body.args.len().to_string());
        self
    }

    pub fn build(self) -> Query {
        Query { body: self.body }
    }

    pub fn build_query_as<T: DbRow>(self) -> QueryAs<T> {
        QueryAs {
            body: self.body,
            _row: PhantomData,
        }
    }

    pub fn build_query_scalar<T: DbScalar>(self) -> QueryScalar<T> {
        QueryScalar {
            body: self.body,
            _row: PhantomData,
        }
    }
}
