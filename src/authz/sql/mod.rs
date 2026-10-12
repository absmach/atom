//! Native authorization SQL fragments shared exclusively by backend adapters.
//! PostgreSQL owns its canonical expansion in the migrated SQL function;
//! SQLite expands the same grant relation with this single recursive query.
pub(crate) mod postgres;
pub(crate) mod sqlite;
