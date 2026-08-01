fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=ATOM_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=ATOM_BUILD_REVISION");

    let version = build_value("ATOM_BUILD_VERSION", env!("CARGO_PKG_VERSION"))?;
    let revision = build_value("ATOM_BUILD_REVISION", "unknown")?;
    println!("cargo:rustc-env=ATOM_VERSION={version}");
    println!("cargo:rustc-env=ATOM_REVISION={revision}");

    tonic_build::compile_protos("proto/atom/v1/atom.proto")?;
    Ok(())
}

fn build_value(name: &str, fallback: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::env::var(name).unwrap_or_else(|_| fallback.to_string());
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
    {
        return Err(format!("{name} must be non-empty and contain no newlines").into());
    }
    Ok(value)
}
