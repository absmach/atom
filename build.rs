fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=ATOM_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=ATOM_BUILD_REVISION");

    let version = build_value("ATOM_BUILD_VERSION", env!("CARGO_PKG_VERSION"))?;
    let revision = build_value("ATOM_BUILD_REVISION", "unknown")?;
    println!("cargo:rustc-env=ATOM_VERSION={version}");
    println!("cargo:rustc-env=ATOM_REVISION={revision}");

    // Callout service — atom is the *client* here (talks out to an external
    // policy service), but tonic-build generates the client and server sides
    // together and only the client is wired into main. Uses well-known Struct
    // for the free-form args/extra payload.
    // Client + server: server is unused in production (atom is only ever the
    // client here), but tests implement a mock server against this proto.
    tonic_build::configure().compile_protos(
        &[
            "proto/atom/v1/atom.proto",
            "proto/broker/v1/auth.proto",
            "proto/atom/v1/callout.proto",
        ],
        &["proto"],
    )?;
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
