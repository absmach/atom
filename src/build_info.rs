//! Build identity embedded by `build.rs`.
//!
//! `make latest` and `make release` supply these values from Git. Direct
//! `cargo` builds fall back to the package version and an unknown revision.

pub const VERSION: &str = env!("ATOM_VERSION");
pub const REVISION: &str = env!("ATOM_REVISION");

#[cfg(test)]
mod tests {
    use super::{REVISION, VERSION};

    #[test]
    fn build_identity_is_always_present() {
        assert!(!VERSION.is_empty());
        assert!(!REVISION.is_empty());
    }
}
